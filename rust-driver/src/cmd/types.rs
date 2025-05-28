use std::io;

use crate::{
    descriptors::{
        CmdQueueReqDescQpManagement, CmdQueueReqDescSetNetworkParam,
        CmdQueueReqDescSetRawPacketReceiveMeta, CmdQueueReqDescUpdateMrTable,
        CmdQueueReqDescUpdatePGT, CmdQueueRespDescOnlyCommonHeader, RingBufDescUntyped,
    },
    device::{
        proxy::{CmdQueueCsrProxy, CmdRespQueueCsrProxy},
        CsrReaderAdaptor, CsrWriterAdaptor, DeviceAdaptor,
    },
    mem::page::ContiguousPages,
    net::config::NetworkConfig,
    ringbuf_desc::DescRingBuffer,
};

/// Command queue for submitting commands to the device
pub(crate) struct CmdQueue {
    /// Inner ring buffer
    inner: DescRingBuffer,
}

/// Command queue descriptor types that can be submitted
#[derive(Debug, Clone, Copy)]
pub(crate) enum CmdQueueDesc {
    /// Update first stage table command
    UpdateMrTable(CmdQueueReqDescUpdateMrTable),
    /// Update second stage table command
    UpdatePGT(CmdQueueReqDescUpdatePGT),
    /// Manage Queue Pair operations
    ManageQP(CmdQueueReqDescQpManagement),
    /// Set network parameters
    SetNetworkParam(CmdQueueReqDescSetNetworkParam),
    /// Set metadata for raw packet receive operations
    SetRawPacketReceiveMeta(CmdQueueReqDescSetRawPacketReceiveMeta),
}

impl CmdQueue {
    /// Creates a new `CmdQueue`
    pub(crate) fn new(ring_buffer: DescRingBuffer) -> Self {
        Self { inner: ring_buffer }
    }

    /// Produces command descriptors to the queue
    pub(crate) fn push(&mut self, desc: CmdQueueDesc) -> bool {
        match desc {
            CmdQueueDesc::UpdateMrTable(d) => self.inner.push(d.into()),
            CmdQueueDesc::UpdatePGT(d) => self.inner.push(d.into()),
            CmdQueueDesc::ManageQP(d) => self.inner.push(d.into()),
            CmdQueueDesc::SetNetworkParam(d) => self.inner.push(d.into()),
            CmdQueueDesc::SetRawPacketReceiveMeta(d) => self.inner.push(d.into()),
        }
    }

    /// Returns the head pointer
    pub(crate) fn head(&self) -> u32 {
        self.inner.head() as u32
    }

    pub(crate) fn set_tail(&mut self, tail: u32) {
        self.inner.set_tail(tail);
    }
}

/// Command queue response descriptor type
#[derive(Debug, Clone, Copy)]
pub(crate) struct CmdRespQueueDesc(CmdQueueRespDescOnlyCommonHeader);

impl std::ops::Deref for CmdRespQueueDesc {
    type Target = CmdQueueRespDescOnlyCommonHeader;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Queue for receiving command responses from the device
pub(crate) struct CmdRespQueue {
    /// Inner ring buffer
    inner: DescRingBuffer,
}

impl CmdRespQueue {
    /// Creates a new `CmdRespQueue`
    pub(crate) fn new(ring_buffer: DescRingBuffer) -> Self {
        Self { inner: ring_buffer }
    }

    /// Tries to poll next valid entry from the queue
    pub(crate) fn try_pop(&mut self) -> Option<CmdRespQueueDesc> {
        self.inner.pop().map(Into::into).map(CmdRespQueueDesc)
    }

    /// Return tail pointer
    pub(crate) fn tail(&self) -> u32 {
        self.inner.tail() as u32
    }

    pub(crate) fn set_head(&mut self, head: u32) {
        self.inner.set_head(head);
    }
}

#[allow(clippy::missing_docs_in_private_items)]
/// Memory Translation Table entry
pub(crate) struct MttUpdate {
    pub(crate) mr_base_va: u64,
    pub(crate) mr_length: u32,
    pub(crate) mr_key: u32,
    pub(crate) pd_handler: u32,
    pub(crate) acc_flags: u8,
    pub(crate) base_pgt_offset: u32,
}

impl MttUpdate {
    pub(crate) fn new(
        mr_base_va: u64,
        mr_length: u32,
        mr_key: u32,
        pd_handler: u32,
        acc_flags: u8,
        base_pgt_offset: u32,
    ) -> Self {
        Self {
            mr_base_va,
            mr_length,
            mr_key,
            pd_handler,
            acc_flags,
            base_pgt_offset,
        }
    }
}

pub(crate) struct PgtUpdate {
    pub(crate) dma_addr: u64,
    pub(crate) pgt_offset: u32,
    pub(crate) zero_based_entry_count: u32,
}

impl PgtUpdate {
    pub(crate) fn new(dma_addr: u64, pgt_offset: u32, zero_based_entry_count: u32) -> Self {
        Self {
            dma_addr,
            pgt_offset,
            zero_based_entry_count,
        }
    }
}

/// Queue Pair entry
#[allow(clippy::missing_docs_in_private_items)]
#[derive(Default)]
pub(crate) struct UpdateQp {
    pub(crate) ip_addr: u32,
    pub(crate) qpn: u32,
    pub(crate) peer_qpn: u32,
    pub(crate) rq_access_flags: u8,
    pub(crate) qp_type: u8,
    pub(crate) pmtu: u8,
    pub(crate) local_udp_port: u16,
    pub(crate) peer_mac_addr: u64,
}

/// Receive buffer
pub(crate) struct RecvBuffer {
    /// One page
    inner: ContiguousPages<1>,
}

/// Metadata about a receive buffer
pub(crate) struct RecvBufferMeta {
    /// Physical address of the receive buffer
    pub(crate) phys_addr: u64,
}

impl RecvBufferMeta {
    /// Creates a new `RecvBufferMeta`
    pub(crate) fn new(phys_addr: u64) -> Self {
        Self { phys_addr }
    }
}

impl RecvBuffer {
    /// Creates a new receive buffer from contiguous pages
    pub(crate) fn new(inner: ContiguousPages<1>) -> Self {
        Self { inner }
    }

    /// Gets start address about this receive buffer
    pub(crate) fn addr(&self) -> u64 {
        self.inner.addr()
    }
}
