use std::{
    io, iter, thread,
    time::{Duration, Instant},
};

use log::{error, trace, warn};
use serde::{Deserialize, Serialize};

use crate::{
    constants::{MAX_QP_CNT, QPN_KEY_PART_WIDTH},
    qp::{qpn_index, QpTable},
    retransmit::PacketRetransmitTask,
    send::SendHandle,
    spawner::{SingleThreadTaskWorker, TaskTx},
};

const DEFAULT_INIT_RETRY_COUNT: usize = 5;
const DEFAULT_TIMEOUT_CHECK_DURATION: u8 = 8;
const DEFAULT_LOCAL_ACK_TIMEOUT: u8 = 4;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct AckTimeoutConfig {
    // 4.096 uS * 2^(CHECK DURATION)
    pub(crate) check_duration_exp: u8,
    // 4.096 uS * 2^(Local ACK Timeout)
    pub(crate) local_ack_timeout_exp: u8,
    pub(crate) init_retry_count: usize,
}

impl Default for AckTimeoutConfig {
    fn default() -> Self {
        Self {
            check_duration_exp: DEFAULT_TIMEOUT_CHECK_DURATION,
            local_ack_timeout_exp: DEFAULT_LOCAL_ACK_TIMEOUT,
            init_retry_count: DEFAULT_INIT_RETRY_COUNT,
        }
    }
}

impl AckTimeoutConfig {
    pub(crate) fn new(check_duration: u8, local_ack_timeout: u8, init_retry_count: usize) -> Self {
        Self {
            check_duration_exp: check_duration,
            local_ack_timeout_exp: local_ack_timeout,
            init_retry_count,
        }
    }
}

#[allow(variant_size_differences)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum AckTimeoutTask {
    // A new message with the AckReq bit set
    NewAckReq {
        qpn: u32,
    },
    // A new meta is received
    RecvMeta {
        qpn: u32,
    },
    /// The previous message is successfully acknowledged
    Ack {
        qpn: u32,
    },
}

impl AckTimeoutTask {
    pub(crate) fn new_ack_req(qpn: u32) -> Self {
        Self::NewAckReq { qpn }
    }

    pub(crate) fn recv_meta(qpn: u32) -> Self {
        Self::RecvMeta { qpn }
    }

    pub(crate) fn ack(qpn: u32) -> Self {
        Self::Ack { qpn }
    }

    pub(crate) fn qpn(self) -> u32 {
        match self {
            AckTimeoutTask::NewAckReq { qpn }
            | AckTimeoutTask::RecvMeta { qpn }
            | AckTimeoutTask::Ack { qpn } => qpn,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TransportTimer {
    timeout_interval: Option<Duration>,
    last_start: Option<Instant>,
    init_retry_counter: usize,
    current_retry_counter: usize,
}

impl TransportTimer {
    pub(crate) fn new(local_ack_timeout: u8, init_retry_counter: usize) -> Self {
        let timeout_nanos = if local_ack_timeout == 0 {
            // disabled
            None
        } else {
            // 4.096 uS * 2^(Local ACK Timeout)
            Some(4096u64 << local_ack_timeout)
        };

        Self {
            timeout_interval: timeout_nanos.map(Duration::from_nanos),
            last_start: None,
            init_retry_counter,
            current_retry_counter: init_retry_counter,
        }
    }

    /// Returns `Ok(true)` if timeout
    pub(crate) fn check_timeout(&mut self) -> TimerResult {
        let Some(timeout_interval) = self.timeout_interval else {
            return TimerResult::Ok;
        };
        let Some(start_time) = self.last_start else {
            return TimerResult::Ok;
        };
        let elapsed = start_time.elapsed();
        if elapsed < timeout_interval {
            return TimerResult::Ok;
        }
        if self.current_retry_counter == 0 {
            return TimerResult::RetryLimitExceeded;
        }
        self.current_retry_counter -= 1;
        self.restart();
        TimerResult::Timeout
    }

    fn is_running(&self) -> bool {
        self.last_start.is_some()
    }

    fn stop(&mut self) {
        self.last_start = None;
    }

    fn restart(&mut self) {
        self.current_retry_counter = self.init_retry_counter;
        self.last_start = Some(Instant::now());
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum TimerResult {
    Ok,
    Timeout,
    RetryLimitExceeded,
}

pub(crate) struct QpAckTimeoutWorker {
    packet_retransmit_tx: TaskTx<PacketRetransmitTask>,
    timer_table: QpTable<TransportTimer>,
    // TODO: maintain this value as atomic variable
    outstanding_ack_req_cnt: QpTable<usize>,
    config: AckTimeoutConfig,
}

impl SingleThreadTaskWorker for QpAckTimeoutWorker {
    type Task = AckTimeoutTask;

    fn process(&mut self, task: Self::Task) {
        let qpn = task.qpn();
        match task {
            AckTimeoutTask::NewAckReq { qpn } => {
                trace!("new ack req, qpn: {qpn}");
                let _ignore = self.outstanding_ack_req_cnt.map_qp_mut(qpn, |x| *x += 1);
                let _ignore = self.timer_table.map_qp_mut(qpn, TransportTimer::restart);
            }
            AckTimeoutTask::RecvMeta { qpn } => {
                trace!("recv meta, qpn: {qpn}");
                let _ignore = self.timer_table.map_qp_mut(qpn, TransportTimer::restart);
            }
            AckTimeoutTask::Ack { qpn } => {
                if self
                    .outstanding_ack_req_cnt
                    .map_qp_mut(qpn, |x| {
                        *x -= 1;
                        trace!("ack, qpn: {qpn}, outstanding: {x}");
                        *x == 0
                    })
                    .unwrap_or(false)
                {
                    let _ignore = self.timer_table.map_qp_mut(qpn, TransportTimer::stop);
                }
            }
        }
    }

    fn maintainance(&mut self) {
        for (index, timer) in self.timer_table.iter_mut().enumerate() {
            match timer.check_timeout() {
                TimerResult::Ok => {}
                TimerResult::Timeout => {
                    warn!("timeout, qp index: {index}");
                    // no need for exact qpn, as it will be later converted to index anyway
                    let qpn = (index << QPN_KEY_PART_WIDTH) as u32;
                    self.packet_retransmit_tx
                        .send(PacketRetransmitTask::RetransmitAll { qpn });
                }
                TimerResult::RetryLimitExceeded => todo!("handle retry failures"),
            }
        }
    }
}

impl QpAckTimeoutWorker {
    pub(crate) fn new(
        packet_retransmit_tx: TaskTx<PacketRetransmitTask>,
        config: AckTimeoutConfig,
    ) -> Self {
        let timer_table = QpTable::new_with(|| {
            TransportTimer::new(config.local_ack_timeout_exp, config.init_retry_count)
        });
        Self {
            packet_retransmit_tx,
            timer_table,
            config,
            outstanding_ack_req_cnt: QpTable::new(),
        }
    }
}
