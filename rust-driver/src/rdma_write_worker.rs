use std::io;

use parking_lot::Mutex;

use crate::{
    ack_timeout::AckTimeoutTask,
    completion::{Completion, CompletionTask, Event, MessageMeta, SendEvent, SendEventOp},
    constants::PSN_MASK,
    device_protocol::{ChunkPos, QpParams, WorkReqOpCode, WorkReqSend, WrChunkBuilder},
    fragmenter::{WrChunkFragmenter, WrPacketFragmenter},
    packet_retransmit::{PacketRetransmitTask, SendQueueElem},
    protocol_impl::SendQueueScheduler,
    qp::{num_psn, QueuePairAttrTable, SqContext},
    send::SendWrRdma,
    utils::{Psn, QpTable},
};

#[derive(Debug)]
pub(crate) enum RdmaWriteTask {
    Write {
        qpn: u32,
        wr: SendWrRdma,
        resp_tx: oneshot::Sender<io::Result<()>>,
    },
    Ack {
        qpn: u32,
        base_psn: Psn,
    },
}

impl RdmaWriteTask {
    pub(crate) fn new_write(qpn: u32, wr: SendWrRdma) -> (Self, oneshot::Receiver<io::Result<()>>) {
        let (resp_tx, resp_rx) = oneshot::channel();
        (Self::Write { qpn, wr, resp_tx }, resp_rx)
    }

    pub(crate) fn new_ack(qpn: u32, base_psn: Psn) -> Self {
        Self::Ack { qpn, base_psn }
    }
}

pub(crate) struct RdmaWriteWorker {
    sq_ctx_table: QpTable<SqContext>,
    qp_attr_table: QueuePairAttrTable,
    send_scheduler: SendQueueScheduler,
    rdma_write_rx: flume::Receiver<RdmaWriteTask>,
    retransmit_tx: flume::Sender<AckTimeoutTask>,
    packet_retransmit_tx: flume::Sender<PacketRetransmitTask>,
    completion_tx: flume::Sender<CompletionTask>,
}

impl RdmaWriteWorker {
    pub(crate) fn new(
        rdma_write_rx: flume::Receiver<RdmaWriteTask>,
        qp_attr_table: QueuePairAttrTable,
        send_scheduler: SendQueueScheduler,
        retransmit_tx: flume::Sender<AckTimeoutTask>,
        packet_retransmit_tx: flume::Sender<PacketRetransmitTask>,
        completion_tx: flume::Sender<CompletionTask>,
    ) -> Self {
        Self {
            rdma_write_rx,
            sq_ctx_table: QpTable::new(),
            qp_attr_table,
            send_scheduler,
            retransmit_tx,
            packet_retransmit_tx,
            completion_tx,
        }
    }

    pub(crate) fn spawn(self) {
        let _handle = std::thread::Builder::new()
            .name("rdma-write-worker".into())
            .spawn(move || self.run())
            .unwrap_or_else(|err| unreachable!("Failed to spawn rx thread: {err}"));
    }

    fn run(mut self) {
        while let Ok(task) = self.rdma_write_rx.recv() {
            match task {
                RdmaWriteTask::Write { qpn, wr, resp_tx } => {
                    #[allow(clippy::wildcard_enum_match_arm)]
                    let resp = match wr.opcode() {
                        WorkReqOpCode::RdmaWrite
                        | WorkReqOpCode::RdmaWriteWithImm
                        | WorkReqOpCode::Send
                        | WorkReqOpCode::SendWithImm
                        | WorkReqOpCode::RdmaReadResp => self.write(qpn, wr),
                        WorkReqOpCode::RdmaRead => self.rdma_read(qpn, wr),
                        _ => unreachable!("opcode unsupported"),
                    };
                    resp_tx.send(resp);
                }
                RdmaWriteTask::Ack { qpn, base_psn } => {
                    if let Some(ctx) = self.sq_ctx_table.get_qp_mut(qpn) {
                        ctx.update_psn_acked(base_psn);
                    }
                }
            }
        }
    }

    fn rdma_read(&mut self, qpn: u32, wr: SendWrRdma) -> io::Result<()> {
        let qp = self
            .qp_attr_table
            .get(qpn)
            .ok_or(io::Error::from(io::ErrorKind::InvalidInput))?;

        let addr = wr.raddr();
        let length = wr.length();
        let num_psn = 1;
        let (msn, psn) = self
            .sq_ctx_table
            .get_qp_mut(qpn)
            .and_then(|ctx| ctx.next_wr(num_psn))
            .ok_or(io::Error::from(io::ErrorKind::InvalidInput))?;
        let end_psn = psn + num_psn;
        let qp_params = QpParams::new(
            msn,
            qp.qp_type,
            qp.qpn,
            qp.mac_addr,
            qp.dqpn,
            qp.dqp_ip,
            qp.pmtu,
        );
        let opcode = WorkReqOpCode::RdmaRead;
        let chunk = WrChunkBuilder::new_with_opcode(opcode)
            .set_qp_params(qp_params)
            .set_ibv_params(
                wr.send_flags() as u8,
                wr.rkey(),
                wr.length(),
                wr.lkey(),
                wr.imm(),
            )
            .set_chunk_meta(psn, wr.laddr(), wr.raddr(), wr.length(), ChunkPos::Only)
            .build();
        let flags = wr.send_flags();
        let mut ack_req = false;
        if flags & ibverbs_sys::ibv_send_flags::IBV_SEND_SIGNALED.0 != 0 {
            ack_req = true;
            let wr_id = wr.wr_id();
            let send_cq_handle = qp
                .send_cq
                .ok_or(io::Error::from(io::ErrorKind::InvalidInput))?;
            let event = Event::Send(SendEvent::new(
                qpn,
                SendEventOp::ReadSignaled,
                MessageMeta::new(msn, end_psn),
                wr_id,
            ));
            self.completion_tx
                .send(CompletionTask::Register { qpn, event });
        }

        if ack_req {
            let _ignore = self.retransmit_tx.send(AckTimeoutTask::new_ack_req(qpn));
        }

        let _ignore = self.packet_retransmit_tx.send(PacketRetransmitTask::NewWr {
            qpn,
            wr: SendQueueElem::new(wr, psn, qp_params),
        });

        self.send_scheduler.send(chunk)?;

        Ok(())
    }

    fn write(&mut self, qpn: u32, wr: SendWrRdma) -> io::Result<()> {
        let qp = self
            .qp_attr_table
            .get(qpn)
            .ok_or(io::Error::from(io::ErrorKind::InvalidInput))?;
        let addr = wr.raddr();
        let length = wr.length();
        let num_psn =
            num_psn(qp.pmtu, addr, length).ok_or(io::Error::from(io::ErrorKind::InvalidInput))?;
        let (msn, psn) = self
            .sq_ctx_table
            .get_qp_mut(qpn)
            .and_then(|ctx| ctx.next_wr(num_psn))
            .ok_or(io::Error::from(io::ErrorKind::InvalidInput))?;
        let end_psn = psn + num_psn;
        let flags = wr.send_flags();
        let mut ack_req = false;
        if flags & ibverbs_sys::ibv_send_flags::IBV_SEND_SIGNALED.0 != 0 {
            ack_req = true;
            let wr_id = wr.wr_id();
            let send_cq_handle = qp
                .send_cq
                .ok_or(io::Error::from(io::ErrorKind::InvalidInput))?;
            #[allow(clippy::wildcard_enum_match_arm)]
            let op = match wr.opcode() {
                WorkReqOpCode::RdmaWrite | WorkReqOpCode::RdmaWriteWithImm => {
                    SendEventOp::WriteSignaled
                }
                WorkReqOpCode::Send | WorkReqOpCode::SendWithImm => SendEventOp::SendSignaled,
                WorkReqOpCode::RdmaRead => SendEventOp::ReadSignaled,
                _ => return Err(io::ErrorKind::Unsupported.into()),
            };
            let event = Event::Send(SendEvent::new(
                qpn,
                op,
                MessageMeta::new(msn, end_psn),
                wr_id,
            ));
            self.completion_tx
                .send(CompletionTask::Register { qpn, event });
        }
        let qp_params = QpParams::new(
            msn,
            qp.qp_type,
            qp.qpn,
            qp.mac_addr,
            qp.dqpn,
            qp.dqp_ip,
            qp.pmtu,
        );

        if ack_req {
            let fragmenter = WrPacketFragmenter::new(wr, qp_params, psn);
            let Some(last_packet_chunk) = fragmenter.into_iter().last() else {
                return Ok(());
            };
            let _ignore = self.retransmit_tx.send(AckTimeoutTask::new_ack_req(qpn));
        }

        let _ignore = self.packet_retransmit_tx.send(PacketRetransmitTask::NewWr {
            qpn,
            wr: SendQueueElem::new(wr, psn, qp_params),
        });

        let fragmenter = WrChunkFragmenter::new(wr, qp_params, psn);
        for chunk in fragmenter {
            self.send_scheduler.send(chunk)?;
        }

        Ok(())
    }
}
