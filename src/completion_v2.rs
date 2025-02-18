use std::{
    collections::{HashMap, VecDeque},
    ffi::c_void,
    fs::File,
    io::Write,
    iter,
    os::fd::RawFd,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use bitvec::vec::BitVec;
use parking_lot::Mutex;

use crate::{
    constants::{MAX_CQ_CNT, MAX_MSN_WINDOW, MAX_QP_CNT},
    qp::qpn_index,
    qp_table::QpTable,
    queue_pair::QueuePairAttrTable,
    send_queue::Psn,
    tracker::Msn,
};

#[allow(variant_size_differences)]
pub(crate) enum CompletionTask {
    Register {
        cq_handle: u32,
        event: CompletionEvent,
    },
    UpdateBasePsn {
        qpn: u32,
        psn: u32,
        is_send: bool,
    },
}

pub(crate) struct CompletionWorker {
    cq_table: CompletionQueueCtxTable,
    qp_table: QueuePairAttrTable,
    completion_rx: flume::Receiver<CompletionTask>,
}

impl CompletionWorker {
    pub(crate) fn new(
        qp_table: QueuePairAttrTable,
        completion_rx: flume::Receiver<CompletionTask>,
        completion_queue_table: &CompletionQueueTable,
    ) -> Self {
        Self {
            cq_table: CompletionQueueCtxTable::new(completion_queue_table),
            qp_table,
            completion_rx,
        }
    }

    pub(crate) fn spawn(self) {
        let _handle = std::thread::Builder::new()
            .name("completion-worker".into())
            .spawn(move || self.run())
            .unwrap_or_else(|err| unreachable!("Failed to spawn rx thread: {err}"));
    }

    fn run(mut self) {
        while let Ok(task) = self.completion_rx.recv() {
            match task {
                CompletionTask::Register { cq_handle, event } => {
                    let Some(cq) = self.cq_table.get_cq_mut(cq_handle) else {
                        continue;
                    };
                    cq.registry.register(event);
                }
                CompletionTask::UpdateBasePsn { qpn, psn, is_send } => {
                    let Some(attr) = self.qp_table.get(qpn) else {
                        continue;
                    };
                    let Some(handle) = (if is_send { attr.send_cq } else { attr.recv_cq }) else {
                        continue;
                    };
                    let Some(cq) = self.cq_table.get_cq_mut(handle) else {
                        continue;
                    };
                    cq.ack_event(qpn, psn);
                }
            }
        }
    }
}

#[derive(Default)]
pub(crate) struct CompletionQueue {
    inner: Mutex<VecDeque<CompletionEvent>>,
}

impl CompletionQueue {
    pub(crate) fn push_back(&self, event: CompletionEvent) {
        let mut queue = self.inner.lock();
        queue.push_back(event);
    }

    pub(crate) fn pop_front(&self) -> Option<CompletionEvent> {
        let mut queue = self.inner.lock();
        queue.pop_front()
    }

    pub(crate) fn front(&self) -> Option<CompletionEvent> {
        let queue = self.inner.lock();
        queue.front().copied()
    }
}

pub(crate) struct CompletionQueueTable {
    inner: Box<[Arc<CompletionQueue>]>,
}

impl CompletionQueueTable {
    pub(crate) fn new() -> Self {
        Self {
            inner: iter::repeat_with(Arc::default).take(MAX_CQ_CNT).collect(),
        }
    }

    pub(crate) fn get_cq(&self, handle: u32) -> Option<&CompletionQueue> {
        self.inner.get(handle as usize).map(Arc::as_ref)
    }
}

struct CompletionQueueCtxTable {
    inner: Box<[CompletionQueueCtx]>,
}

impl CompletionQueueCtxTable {
    fn new(completion_queue_table: &CompletionQueueTable) -> Self {
        Self {
            inner: completion_queue_table
                .inner
                .iter()
                .map(Arc::clone)
                .map(CompletionQueueCtx::new)
                .collect(),
        }
    }

    /// Gets a reference to the cq associated with the given cqN
    pub(crate) fn get_cq_mut(&mut self, handle: u32) -> Option<&mut CompletionQueueCtx> {
        self.inner.get_mut(handle as usize)
    }
}

#[derive(Default)]
struct CompletionQueueCtx {
    /// Current number of CQEs
    cqe_count: usize,
    /// Unique handle identifying this CQ
    handle: u32,
    /// Number of CQEs this CQ can hold
    num_cqe: usize,
    /// Event registration
    registry: EventRegistry,
    /// Completion queue
    completion_queue: Arc<CompletionQueue>,
}

impl CompletionQueueCtx {
    fn new(completion_queue: Arc<CompletionQueue>) -> Self {
        Self {
            completion_queue,
            ..Default::default()
        }
    }

    /// Acknowledge an event with the given MSN and queue pair number.
    ///
    /// # Arguments
    /// * `msn` - Message Sequence Number to acknowledge
    /// * `qpn` - Queue Pair Number associated with this event
    #[allow(clippy::as_conversions)] // u16 to usize
    pub(crate) fn ack_event(&mut self, qpn: u32, base_psn: u32) {
        let events = self.registry.ack_psn(qpn, base_psn);
        let mut event_count = events.len();
        for event in events {
            self.completion_queue.push_back(event);
        }
        self.cqe_count += event_count;
    }
}

/// Manages CQs
pub(crate) struct CqManager {
    /// Bitmap tracking allocated CQ handles
    bitmap: BitVec,
}

#[allow(clippy::as_conversions, clippy::indexing_slicing)]
impl CqManager {
    /// Creates a new `CqManager`
    pub(crate) fn new() -> Self {
        let mut bitmap = BitVec::with_capacity(MAX_CQ_CNT);
        bitmap.resize(MAX_CQ_CNT, false);
        Self { bitmap }
    }

    /// Allocates a new cq and returns its cqN
    #[allow(clippy::cast_possible_truncation)] // no larger than u32
    pub(crate) fn create_cq(&mut self) -> Option<u32> {
        let handle = self.bitmap.first_zero()? as u32;
        self.bitmap.set(handle as usize, true);
        Some(handle)
    }

    /// Removes and returns the cq associated with the given cqN
    pub(crate) fn destroy_cq(&mut self, handle: u32) {
        if handle as usize >= MAX_CQ_CNT {
            return;
        }
        self.bitmap.set(handle as usize, false);
    }
}

#[derive(Default, Debug)]
pub(crate) struct EventRegistry {
    table: QpTable<VecDeque<CompletionEvent>>,
}

impl EventRegistry {
    pub(crate) fn ack_psn(&mut self, qpn: u32, base_psn: u32) -> Vec<CompletionEvent> {
        let Some(queue) = self.table.get_qp_mut(qpn) else {
            return vec![];
        };
        let mut elements = Vec::new();
        while let Some(event) = queue.front() {
            if Psn(event.end_psn()) < Psn(base_psn) {
                elements.push(queue.pop_front().unwrap_or_else(|| unreachable!()));
            } else {
                break;
            }
        }
        elements
    }

    pub(crate) fn register(&mut self, event: CompletionEvent) {
        if let Some(queue) = self.table.get_qp_mut(event.qpn()) {
            if queue
                .back()
                .is_some_and(|last| Msn(last.msn()) > Msn(event.msn()))
            {
                // reorder events
                let insert_pos = queue
                    .iter()
                    .position(|x| Msn(x.msn()) > Msn(event.msn()))
                    .unwrap_or(queue.len());
                queue.insert(insert_pos, event);
            } else {
                queue.push_back(event);
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum CompletionEvent {
    RdmaWrite {
        qpn: u32,
        msn: u16,
        end_psn: u32,
        wr_id: u64,
    },
    RecvRdmaWithImm {
        qpn: u32,
        msn: u16,
        end_psn: u32,
        imm: u32,
    },
}

impl CompletionEvent {
    pub(crate) fn new_rdma_write(qpn: u32, msn: u16, end_psn: u32, wr_id: u64) -> Self {
        Self::RdmaWrite {
            qpn,
            msn,
            end_psn,
            wr_id,
        }
    }

    pub(crate) fn new_recv_rdma_with_imm(qpn: u32, msn: u16, end_psn: u32, imm: u32) -> Self {
        Self::RecvRdmaWithImm {
            qpn,
            msn,
            end_psn,
            imm,
        }
    }

    pub(crate) fn qpn(&self) -> u32 {
        match *self {
            CompletionEvent::RdmaWrite { qpn, .. }
            | CompletionEvent::RecvRdmaWithImm { qpn, .. } => qpn,
        }
    }

    pub(crate) fn msn(&self) -> u16 {
        match *self {
            CompletionEvent::RdmaWrite { msn, .. }
            | CompletionEvent::RecvRdmaWithImm { msn, .. } => msn,
        }
    }

    pub(crate) fn end_psn(&self) -> u32 {
        match *self {
            CompletionEvent::RdmaWrite { end_psn, .. }
            | CompletionEvent::RecvRdmaWithImm { end_psn, .. } => end_psn,
        }
    }

    pub(crate) fn opcode(&self) -> u32 {
        match *self {
            CompletionEvent::RdmaWrite { .. } => ibverbs_sys::ibv_wc_opcode::IBV_WC_RDMA_WRITE,
            CompletionEvent::RecvRdmaWithImm { .. } => {
                ibverbs_sys::ibv_wc_opcode::IBV_WC_RECV_RDMA_WITH_IMM
            }
        }
    }
}
