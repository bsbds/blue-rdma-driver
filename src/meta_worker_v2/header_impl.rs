use tracing::error;

use crate::{
    ack_responder::AckResponse,
    device_protocol::{HeaderType, HeaderWriteMeta, PacketPos},
    message_worker::Task,
    tracker::{MessageMeta, Msn},
};

use super::MetaWorker;

impl<T> MetaWorker<T> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_header_write(&mut self, meta: HeaderWriteMeta) {
        let HeaderWriteMeta {
            pos,
            msn,
            psn,
            solicited,
            ack_req,
            is_retry,
            dqpn,
            total_len,
            raddr,
            rkey,
            imm,
            header_type,
        } = meta;
        let Some(tracker) = self.recv_table.get_mut(dqpn) else {
            error!("qp number: d{dqpn} does not exist");
            return;
        };
        // TODO: send to completion queue if notification is required
        //if matches!(pos, PacketPos::First | PacketPos::Only) {}
        //if let Some(psn) = tracker.ack_one(psn) {}

        /// Timeout of an `AckReq` message, notify retransmission
        if matches!(pos, PacketPos::Last | PacketPos::Only) && is_retry && ack_req {
            let _ignore = self.ack_tx.send(AckResponse::Nak {
                qpn: dqpn,
                base_psn: tracker.base_psn(),
                ack_req_packet_psn: psn,
            });
        }

        match header_type {
            HeaderType::Write => todo!(),
            HeaderType::Send => todo!(),
            HeaderType::ReadResp => todo!(),
        }
    }
}
