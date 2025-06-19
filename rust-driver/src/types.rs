use bincode::{Decode, Encode};
use ibverbs_sys::{
    ibv_send_wr,
    ibv_wr_opcode::{
        IBV_WR_RDMA_READ, IBV_WR_RDMA_WRITE, IBV_WR_RDMA_WRITE_WITH_IMM, IBV_WR_SEND,
        IBV_WR_SEND_WITH_IMM,
    },
};
use serde::{Deserialize, Serialize};

use crate::{send::WorkReqOpCode, RdmaError};

#[derive(Debug, Clone, Copy)]
pub(crate) enum SendWr {
    Rdma(SendWrRdma),
    Send(SendWrBase),
}

impl SendWr {
    #[allow(unsafe_code)]
    /// Creates a new `SendWr`
    pub(crate) fn new(wr: ibv_send_wr) -> crate::error::Result<Self> {
        let num_sge = usize::try_from(wr.num_sge)
            .map_err(|e| RdmaError::InvalidInput(format!("Invalid SGE count: {e}")))?;
        if num_sge != 1 {
            return Err(RdmaError::Unimplemented(
                "Only support for single SGE".into(),
            ));
        }
        // SAFETY: sg_list is valid when num_sge > 0, which we've verified above
        let sge = unsafe { *wr.sg_list };
        let opcode = match wr.opcode {
            IBV_WR_RDMA_WRITE => WorkReqOpCode::RdmaWrite,
            IBV_WR_RDMA_WRITE_WITH_IMM => WorkReqOpCode::RdmaWriteWithImm,
            IBV_WR_RDMA_READ => WorkReqOpCode::RdmaRead,
            IBV_WR_SEND => WorkReqOpCode::Send,
            IBV_WR_SEND_WITH_IMM => WorkReqOpCode::SendWithImm,
            _ => {
                return Err(RdmaError::Unimplemented(format!(
                    "Opcode {} not supported",
                    wr.opcode
                )))
            }
        };

        let base = SendWrBase {
            wr_id: wr.wr_id,
            send_flags: wr.send_flags,
            laddr: sge.addr,
            length: sge.length,
            lkey: sge.lkey,
            // SAFETY: imm_data is valid for operations with immediate data
            imm_data: unsafe { wr.__bindgen_anon_1.imm_data },
            opcode,
        };

        match wr.opcode {
            IBV_WR_RDMA_WRITE | IBV_WR_RDMA_WRITE_WITH_IMM | IBV_WR_RDMA_READ => {
                let wr = SendWrRdma {
                    base,
                    // SAFETY: rdma field is valid for RDMA operations
                    raddr: unsafe { wr.wr.rdma.remote_addr },
                    rkey: unsafe { wr.wr.rdma.rkey },
                };
                Ok(Self::Rdma(wr))
            }
            IBV_WR_SEND | IBV_WR_SEND_WITH_IMM => Ok(Self::Send(base)),
            _ => Err(RdmaError::Unimplemented("opcode not supported".into())),
        }
    }

    pub(crate) fn wr_id(&self) -> u64 {
        match *self {
            SendWr::Rdma(wr) => wr.base.wr_id,
            SendWr::Send(wr) => wr.wr_id,
        }
    }
    pub(crate) fn send_flags(&self) -> u32 {
        match *self {
            SendWr::Rdma(wr) => wr.base.send_flags,
            SendWr::Send(wr) => wr.send_flags,
        }
    }

    pub(crate) fn laddr(&self) -> u64 {
        match *self {
            SendWr::Rdma(wr) => wr.base.laddr,
            SendWr::Send(wr) => wr.laddr,
        }
    }

    pub(crate) fn length(&self) -> u32 {
        match *self {
            SendWr::Rdma(wr) => wr.base.length,
            SendWr::Send(wr) => wr.length,
        }
    }

    pub(crate) fn lkey(&self) -> u32 {
        match *self {
            SendWr::Rdma(wr) => wr.base.lkey,
            SendWr::Send(wr) => wr.lkey,
        }
    }

    pub(crate) fn imm_data(&self) -> u32 {
        match *self {
            SendWr::Rdma(wr) => wr.base.imm_data,
            SendWr::Send(wr) => wr.imm_data,
        }
    }
}

impl From<SendWrRdma> for SendWr {
    fn from(wr: SendWrRdma) -> Self {
        SendWr::Rdma(wr)
    }
}

impl From<SendWrBase> for SendWr {
    fn from(wr: SendWrBase) -> Self {
        SendWr::Send(wr)
    }
}

/// A resolver and validator for send work requests
#[derive(Clone, Copy)]
pub(crate) struct SendWrRdma {
    base: SendWrBase,
    pub(crate) raddr: u64,
    pub(crate) rkey: u32,
}

impl std::fmt::Debug for SendWrRdma {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendWrRdma")
            .field("base", &self.base)
            .field("raddr", &format_args!("{:x}", self.raddr))
            .field("rkey", &self.rkey)
            .finish()
    }
}

impl SendWrRdma {
    #[allow(unsafe_code)]
    /// Creates a new resolver from the given work request.
    /// Returns None if the input is invalid
    pub(crate) fn new(wr: ibv_send_wr) -> crate::error::Result<Self> {
        match wr.opcode {
            IBV_WR_RDMA_WRITE | IBV_WR_RDMA_WRITE_WITH_IMM => {}
            _ => {
                return Err(RdmaError::Unimplemented(format!(
                    "Opcode {} not supported for RDMA operations",
                    wr.opcode
                )))
            }
        }

        let num_sge = usize::try_from(wr.num_sge)
            .map_err(|e| RdmaError::InvalidInput(format!("Invalid SGE count: {e}")))?;

        if num_sge != 1 {
            return Err(RdmaError::Unimplemented(
                "Only support for single SGE in RDMA operations".into(),
            ));
        }

        // SAFETY: sg_list is valid when num_sge > 0, which we've verified above
        let sge = unsafe { *wr.sg_list };

        let opcode = match wr.opcode {
            IBV_WR_RDMA_WRITE => WorkReqOpCode::RdmaWrite,
            IBV_WR_RDMA_WRITE_WITH_IMM => WorkReqOpCode::RdmaWriteWithImm,
            IBV_WR_RDMA_READ => WorkReqOpCode::RdmaRead,
            IBV_WR_SEND => WorkReqOpCode::Send,
            IBV_WR_SEND_WITH_IMM => WorkReqOpCode::SendWithImm,
            _ => return Err(RdmaError::Unimplemented("opcode not supported".into())),
        };

        Ok(Self {
            base: SendWrBase {
                wr_id: wr.wr_id,
                send_flags: wr.send_flags,
                laddr: sge.addr,
                length: sge.length,
                lkey: sge.lkey,
                // SAFETY: imm_data is valid for operations with immediate data
                imm_data: unsafe { wr.__bindgen_anon_1.imm_data },
                opcode,
            },
            // SAFETY: rdma field is valid for RDMA operations
            raddr: unsafe { wr.wr.rdma.remote_addr },
            rkey: unsafe { wr.wr.rdma.rkey },
        })
    }

    pub(crate) fn new_from_base(base: SendWrBase, raddr: u64, rkey: u32) -> SendWrRdma {
        Self { base, raddr, rkey }
    }

    /// Returns the local address of the SGE buffer
    #[inline]
    pub(crate) fn laddr(&self) -> u64 {
        self.base.laddr
    }

    /// Returns the length of the SGE buffer in bytes
    #[inline]
    pub(crate) fn length(&self) -> u32 {
        self.base.length
    }

    /// Returns the local key associated with the SGE buffer
    #[inline]
    pub(crate) fn lkey(&self) -> u32 {
        self.base.lkey
    }

    /// Returns the remote memory address for RDMA operations
    #[inline]
    pub(crate) fn raddr(&self) -> u64 {
        self.raddr
    }

    /// Returns the remote key for RDMA operations
    #[inline]
    pub(crate) fn rkey(&self) -> u32 {
        self.rkey
    }

    /// Returns the immediate data value
    #[inline]
    pub(crate) fn imm(&self) -> u32 {
        self.base.imm_data
    }

    /// Returns the send flags
    #[inline]
    pub(crate) fn send_flags(&self) -> u32 {
        self.base.send_flags
    }

    /// Returns the ID associated with this WR
    #[inline]
    pub(crate) fn wr_id(&self) -> u64 {
        self.base.wr_id
    }

    pub(crate) fn opcode(&self) -> WorkReqOpCode {
        self.base.opcode
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SendWrBase {
    pub(crate) wr_id: u64,
    pub(crate) send_flags: u32,
    pub(crate) laddr: u64,
    pub(crate) length: u32,
    pub(crate) lkey: u32,
    pub(crate) imm_data: u32,
    pub(crate) opcode: WorkReqOpCode,
}

impl std::fmt::Debug for SendWrBase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendWrBase")
            .field("wr_id", &self.wr_id)
            .field("send_flags", &self.send_flags)
            .field("laddr", &format_args!("{:x}", self.laddr))
            .field("length", &self.length)
            .field("lkey", &self.lkey)
            .field("imm_data", &self.imm_data)
            .field("opcode", &self.opcode)
            .finish()
    }
}

impl SendWrBase {
    pub(crate) fn new(
        wr_id: u64,
        send_flags: u32,
        laddr: u64,
        length: u32,
        lkey: u32,
        imm_data: u32,
        opcode: WorkReqOpCode,
    ) -> Self {
        Self {
            wr_id,
            send_flags,
            laddr,
            length,
            lkey,
            imm_data,
            opcode,
        }
    }
}

// ValidationError has been moved to the error module

#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode)]
pub(crate) struct RecvWr {
    pub(crate) wr_id: u64,
    pub(crate) addr: u64,
    pub(crate) length: u32,
    pub(crate) lkey: u32,
}

impl RecvWr {
    #[allow(unsafe_code)]
    pub(crate) fn new(wr: ibverbs_sys::ibv_recv_wr) -> Option<Self> {
        let num_sge = usize::try_from(wr.num_sge).ok()?;
        if num_sge != 1 {
            return None;
        }
        // SAFETY: sg_list is valid when num_sge > 0, which we've verified above
        let sge = unsafe { *wr.sg_list };

        Some(Self {
            wr_id: wr.wr_id,
            addr: sge.addr,
            length: sge.length,
            lkey: sge.lkey,
        })
    }

    pub(crate) fn to_bytes(self) -> [u8; size_of::<RecvWr>()] {
        let mut bytes = [0u8; 24];
        bytes[0..8].copy_from_slice(&self.wr_id.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.addr.to_be_bytes());
        bytes[16..20].copy_from_slice(&self.length.to_be_bytes());
        bytes[20..24].copy_from_slice(&self.lkey.to_be_bytes());
        bytes
    }

    #[allow(clippy::unwrap_used)]
    pub(crate) fn from_bytes(bytes: &[u8; size_of::<RecvWr>()]) -> Self {
        Self {
            wr_id: u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
            addr: u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
            length: u32::from_be_bytes(bytes[16..20].try_into().unwrap()),
            lkey: u32::from_be_bytes(bytes[20..24].try_into().unwrap()),
        }
    }
}
