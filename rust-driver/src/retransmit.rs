use std::{cmp::Ordering, collections::VecDeque, iter, thread};

use log::debug;

use crate::{
    constants::{MAX_PSN_WINDOW, MAX_QP_CNT},
    fragmenter::WrPacketFragmenter,
    qp::{qpn_index, QpTable},
    send::{QpParams, SendHandle, WorkReqOpCode},
    spawner::SingleThreadTaskWorker,
    types::SendWrRdma,
    utils::Psn,
};

#[allow(variant_size_differences)]
pub(crate) enum PacketRetransmitTask {
    NewWr {
        qpn: u32,
        wr: SendQueueElem,
    },
    RetransmitRange {
        qpn: u32,
        // Inclusive
        psn_low: Psn,
        // Exclusive
        psn_high: Psn,
    },
    RetransmitAll {
        qpn: u32,
    },
    Ack {
        qpn: u32,
        psn: Psn,
    },
}

impl PacketRetransmitTask {
    fn qpn(&self) -> u32 {
        match *self {
            PacketRetransmitTask::RetransmitRange { qpn, .. }
            | PacketRetransmitTask::NewWr { qpn, .. }
            | PacketRetransmitTask::RetransmitAll { qpn }
            | PacketRetransmitTask::Ack { qpn, .. } => qpn,
        }
    }
}

pub(crate) struct PacketRetransmitWorker {
    wr_sender: SendHandle,
    table: QpTable<IbvSendQueue>,
}

impl SingleThreadTaskWorker for PacketRetransmitWorker {
    type Task = PacketRetransmitTask;

    fn process(&mut self, task: Self::Task) {
        let qpn = task.qpn();
        let Some(sq) = self.table.get_qp_mut(qpn) else {
            return;
        };
        match task {
            PacketRetransmitTask::NewWr { wr, .. } => {
                sq.push(wr);
            }
            PacketRetransmitTask::RetransmitRange {
                psn_low, psn_high, ..
            } => {
                debug!("retransmit range, qpn: {qpn}, low: {psn_low}, high: {psn_high}");

                let sqes = sq.range(psn_low, psn_high);
                let packets = sqes
                    .into_iter()
                    .flat_map(|sqe| WrPacketFragmenter::new(sqe.wr(), sqe.qp_param(), sqe.psn()))
                    .skip_while(|x| x.psn < psn_low)
                    .take_while(|x| x.psn < psn_high);
                for mut packet in packets {
                    packet.set_is_retry();
                    self.wr_sender.send(packet);
                }
            }
            PacketRetransmitTask::RetransmitAll { qpn } => {
                debug!("retransmit all, qpn: {qpn}");

                let packets = sq
                    .inner
                    .iter()
                    .flat_map(|sqe| WrPacketFragmenter::new(sqe.wr(), sqe.qp_param(), sqe.psn()))
                    .skip_while(|x| x.psn < sq.base_psn);
                for mut packet in packets {
                    packet.set_is_retry();
                    self.wr_sender.send(packet);
                }
            }

            PacketRetransmitTask::Ack { psn, .. } => {
                sq.pop_until(psn);
            }
        }
    }

    fn maintainance(&mut self) {}
}

impl PacketRetransmitWorker {
    pub(crate) fn new(wr_sender: SendHandle) -> Self {
        Self {
            wr_sender,
            table: QpTable::new(),
        }
    }
}

#[derive(Default)]
pub(crate) struct IbvSendQueue {
    inner: VecDeque<SendQueueElem>,
    base_psn: Psn,
}

impl IbvSendQueue {
    pub(crate) fn push(&mut self, elem: SendQueueElem) {
        self.inner.push_back(elem);
    }

    pub(crate) fn pop_until(&mut self, psn: Psn) {
        let mut a = self.inner.partition_point(|x| x.psn < psn);
        let _drop = self.inner.drain(..a.saturating_sub(1));
        self.base_psn = psn;
    }

    /// Find range [`psn_low`, `psn_high`)
    pub(crate) fn range(&self, psn_low: Psn, psn_high: Psn) -> Vec<SendQueueElem> {
        let mut a = self.inner.partition_point(|x| x.psn <= psn_low);
        let mut b = self.inner.partition_point(|x| x.psn < psn_high);
        a = a.saturating_sub(1);
        if (a..b).is_empty() {
            return Vec::new();
        }
        self.inner.range(a..b).copied().collect()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SendQueueElem {
    psn: Psn,
    wr: SendWrRdma,
    qp_param: QpParams,
}

impl SendQueueElem {
    pub(crate) fn new(wr: SendWrRdma, psn: Psn, qp_param: QpParams) -> Self {
        Self { psn, wr, qp_param }
    }

    pub(crate) fn psn(&self) -> Psn {
        self.psn
    }

    pub(crate) fn wr(&self) -> SendWrRdma {
        self.wr
    }

    pub(crate) fn qp_param(&self) -> QpParams {
        self.qp_param
    }

    pub(crate) fn opcode(&self) -> WorkReqOpCode {
        self.wr.opcode()
    }
}
