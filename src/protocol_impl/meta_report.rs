use std::io;

use crate::device_protocol::{
    AckMeta, CnpMeta, HeaderReadMeta, HeaderWriteMeta, MetaReport, NakMeta, ReportMeta,
};

use super::queue::meta_report_queue::{MetaReportQueue, MetaReportQueueDesc};

/// Handler for meta report queues
pub(crate) struct MetaReportQueueHandler {
    /// All four meta report queues
    inner: Vec<MetaReportQueue>,
    /// Current position, used for round robin polling
    pos: usize,
}

impl MetaReportQueueHandler {
    pub(crate) fn new(inner: Vec<MetaReportQueue>) -> Self {
        Self { inner, pos: 0 }
    }
}

impl MetaReport for MetaReportQueueHandler {
    #[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)] // should never overflow
    fn try_recv_meta(&mut self) -> io::Result<Option<ReportMeta>> {
        let num_queues = self.inner.len();
        for i in 0..num_queues {
            let idx = (self.pos + i) % num_queues;
            let Some(desc) = self.inner[idx].try_pop() else {
                continue;
            };
            self.pos = (idx + 1) % num_queues;
            let meta = match desc {
                MetaReportQueueDesc::WritePacketInfo(d) => ReportMeta::Write(HeaderWriteMeta {
                    pos: d.packet_pos(),
                    msn: d.msn(),
                    psn: d.psn(),
                    solicited: d.solicited(),
                    ack_req: d.ack_req(),
                    is_retry: d.is_retry(),
                    dqpn: d.dqpn(),
                    total_len: d.total_len(),
                    raddr: d.raddr(),
                    rkey: d.rkey(),
                    imm: d.imm_data(),
                    header_type: d.header_type(),
                }),
                MetaReportQueueDesc::ReadPacketInfo((f, n)) => ReportMeta::Read(HeaderReadMeta {
                    dqpn: f.dqpn(),
                    raddr: f.raddr(),
                    rkey: f.rkey(),
                    total_len: n.total_len(),
                    laddr: n.laddr(),
                    lkey: n.lkey(),
                    ack_req: f.ack_req(),
                    msn: f.msn(),
                    psn: f.psn(),
                }),
                MetaReportQueueDesc::CnpPacketInfo(d) => ReportMeta::Cnp(CnpMeta { qpn: d.dqpn() }),
                MetaReportQueueDesc::Ack(d) => ReportMeta::Ack(AckMeta {
                    qpn: d.qpn(),
                    msn: d.msn(),
                    psn_now: d.psn_now(),
                    now_bitmap: d.now_bitmap(),
                    is_window_slided: d.is_window_slided(),
                    is_send_by_local_hw: d.is_send_by_local_hw(),
                    is_send_by_driver: d.is_send_by_driver(),
                }),
                MetaReportQueueDesc::Nak((f, n)) => ReportMeta::Nak(NakMeta {
                    qpn: f.qpn(),
                    msn: f.msn(),
                    psn_now: f.psn_now(),
                    now_bitmap: f.now_bitmap(),
                    psn_before_slide: f.psn_before_slide(),
                    pre_bitmap: n.pre_bitmap(),
                    is_send_by_local_hw: f.is_send_by_local_hw(),
                    is_send_by_driver: f.is_send_by_driver(),
                }),
            };
            return Ok(Some(meta));
        }
        Ok(None)
    }
}
