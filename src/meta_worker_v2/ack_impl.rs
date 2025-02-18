use tracing::error;

use crate::{
    constants::PSN_MASK,
    device_protocol::{AckMeta, NakMeta},
    message_worker::Task,
    packet_retransmit::PacketRetransmitTask,
    queue_pair::Tracker,
    timeout_retransmit::RetransmitTask,
};

use super::{CompletionTask, MetaWorker};

/// Offset between the `now_psn` an `base_psn`
const BASE_PSN_OFFSET: u32 = 0x70;

impl<T> MetaWorker<T> {
    pub(super) fn handle_ack(&mut self, meta: AckMeta) {
        if meta.is_send_by_driver {
            self.handle_ack_driver(meta);
        } else {
            self.handle_ack_hw(meta);
        }
    }

    pub(super) fn handle_nak(&mut self, meta: NakMeta) {
        if meta.is_send_by_driver {
            self.handle_nak_driver(meta);
        } else {
            self.handle_nak_hw(meta);
        }
    }

    fn handle_ack_hw(&mut self, meta: AckMeta) {
        let AckMeta {
            qpn,
            msn: ack_msn,
            psn_now,
            now_bitmap,
            is_window_slided,
            is_send_by_local_hw,
            is_send_by_driver,
        } = meta;
        if !is_send_by_local_hw {
            let _ignore = self.retransmit_tx.send(RetransmitTask::ReceiveACK { qpn });
        }
        let table = if is_send_by_local_hw {
            &mut self.recv_table
        } else {
            &mut self.send_table
        };

        let Some(tracker) = table.get_mut(qpn) else {
            error!("qp number: {qpn} does not exist");
            return;
        };
        if let Some(psn) = Self::update_packet_tracker(tracker, psn_now, now_bitmap, ack_msn) {
            self.send_update(!is_send_by_local_hw, qpn, psn);
        }
    }

    fn handle_ack_driver(&mut self, meta: AckMeta) {
        let AckMeta { qpn, psn_now, .. } = meta;
        let table = &mut self.send_table;
        let Some(tracker) = table.get_mut(qpn) else {
            return;
        };
        if let Some(psn) = tracker.ack_before(psn_now) {
            self.send_update(true, qpn, psn);
        }
    }

    fn handle_nak_hw(&mut self, meta: NakMeta) {
        let NakMeta {
            qpn,
            msn: ack_msn,
            psn_now,
            now_bitmap,
            pre_bitmap,
            psn_before_slide: psn_pre,
            is_send_by_local_hw,
            ..
        } = meta;
        let table = if is_send_by_local_hw {
            &mut self.recv_table
        } else {
            &mut self.send_table
        };
        let Some(tracker) = table.get_mut(qpn) else {
            error!("qp number: {qpn} does not exist");
            return;
        };
        let x = Self::update_packet_tracker(tracker, psn_now, now_bitmap, ack_msn);
        let y = Self::update_packet_tracker(tracker, psn_pre, pre_bitmap, ack_msn);
        for psn in x.into_iter().chain(y) {
            self.send_update(!is_send_by_local_hw, qpn, psn);
        }
        // TODO: implement more fine-grained retransmission
        let psn_low = psn_pre.wrapping_sub(BASE_PSN_OFFSET) & PSN_MASK;
        let psn_high = psn_now.wrapping_add(128).wrapping_sub(BASE_PSN_OFFSET);
        let _ignore = self
            .packet_retransmit_tx
            .send(PacketRetransmitTask::RetransmitRange {
                qpn,
                psn_low,
                psn_high,
            });
    }

    fn handle_nak_driver(&mut self, meta: NakMeta) {
        let NakMeta {
            qpn,
            msn: ack_msn,
            psn_now,
            psn_before_slide: psn_pre,
            ..
        } = meta;
        let table = &mut self.send_table;
        let Some(tracker) = table.get_mut(qpn) else {
            return;
        };
        let _ignore = self
            .packet_retransmit_tx
            .send(PacketRetransmitTask::RetransmitRange {
                qpn,
                psn_low: psn_pre,
                psn_high: psn_now,
            });
    }

    fn update_packet_tracker(
        tracker: &mut Tracker,
        psn: u32,
        bitmap: u128,
        ack_msn: u16,
    ) -> Option<u32> {
        let base_psn = psn.wrapping_sub(BASE_PSN_OFFSET) & PSN_MASK;
        tracker.ack_range(base_psn, bitmap, ack_msn)
    }

    fn send_update(&self, is_send: bool, qpn: u32, psn: u32) {
        let _ignore = self
            .completion_tx
            .send(CompletionTask::UpdateBasePsn { qpn, psn, is_send });
        let __ignore = self
            .packet_retransmit_tx
            .send(PacketRetransmitTask::Ack { qpn, psn });
    }
}
