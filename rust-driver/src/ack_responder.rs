use std::net::Ipv4Addr;

use bilge::prelude::*;
use log::error;
use pnet::{
    packet::{
        ethernet::{EtherTypes, MutableEthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::{Ipv4Flags, MutableIpv4Packet},
        udp::MutableUdpPacket,
    },
    util::MacAddr,
};

use crate::{
    constants::{CARD_MAC_ADDRESS, CARD_MAC_ADDRESS_OCTETS, PSN_MASK},
    qp::{QpAttr, QpTableShared},
    simple_nic::FrameTx,
    spawner::SingleThreadTaskWorker,
    utils::Psn,
};

#[derive(Debug)]
pub(crate) enum AckResponse {
    Ack {
        qpn: u32,
        msn: u16,
        last_psn: Psn,
    },
    Nak {
        qpn: u32,
        base_psn: Psn,
        ack_req_packet_psn: Psn,
    },
}

impl AckResponse {
    fn qpn(&self) -> u32 {
        match *self {
            AckResponse::Ack { qpn, .. } | AckResponse::Nak { qpn, .. } => qpn,
        }
    }
}

pub(crate) struct AckResponder {
    qp_table: QpTableShared<QpAttr>,
    raw_frame_tx: Box<dyn FrameTx + Send + 'static>,
}

impl SingleThreadTaskWorker for AckResponder {
    type Task = AckResponse;

    fn process(&mut self, task: Self::Task) {
        const NUM_BITS_STRIDE: u8 = 16;
        let qp_attr = self.qp_table.get_qp(task.qpn()).expect("invalid qpn");
        let frame_builder = AckFrameBuilder::new(qp_attr.ip, qp_attr.dqp_ip, qp_attr.dqpn);
        let frame = match task {
            AckResponse::Ack { qpn, msn, last_psn } => {
                frame_builder.build_ack(last_psn, u128::MAX, 0.into(), 0, false, false)
            }
            AckResponse::Nak {
                qpn,
                base_psn,
                ack_req_packet_psn,
            } => frame_builder.build_ack(ack_req_packet_psn + 1, 0, base_psn, 0, true, true),
        };
        if let Err(e) = self.raw_frame_tx.send(&frame) {
            error!("failed to send ack frame");
        }
    }
}

impl AckResponder {
    pub(crate) fn new(
        qp_table: QpTableShared<QpAttr>,
        raw_frame_tx: Box<dyn FrameTx + Send + 'static>,
    ) -> Self {
        Self {
            qp_table,
            raw_frame_tx,
        }
    }
}

struct AckFrameBuilder {
    src_ip: u32,
    dst_ip: u32,
    dqpn: u32,
}

#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::big_endian_bytes
)]
impl AckFrameBuilder {
    fn new(src_ip: u32, dst_ip: u32, dqpn: u32) -> Self {
        Self {
            src_ip,
            dst_ip,
            dqpn,
        }
    }

    fn build_ack(
        &self,
        now_psn: Psn,
        now_bitmap: u128,
        pre_psn: Psn,
        prev_bitmap: u128,
        is_packet_loss: bool,
        is_window_slided: bool,
    ) -> Vec<u8> {
        const TRANS_TYPE_RC: u8 = 0x00;
        const OPCODE_ACKNOWLEDGE: u8 = 0x11;
        const PAYLOAD_SIZE: usize = 48;
        let mac = MacAddr::from(CARD_MAC_ADDRESS_OCTETS);
        let mut payload = [0u8; PAYLOAD_SIZE];

        let mut bth = Bth::default();
        bth.set_opcode(u5::from_u8(OPCODE_ACKNOWLEDGE));
        bth.set_psn(u24::from_u32(now_psn.into_inner()));
        bth.set_dqpn(u24::from_u32(self.dqpn));
        bth.set_trans_type(u3::from_u8(TRANS_TYPE_RC));
        payload[..12].copy_from_slice(&bth.value.to_be_bytes());

        let mut aeth_seg0 = AethSeg0::default();
        aeth_seg0.set_is_send_by_driver(true);
        aeth_seg0.set_is_packet_loss(is_packet_loss);
        aeth_seg0.set_is_window_slided(is_window_slided);
        aeth_seg0.set_pre_psn(u24::from_u32(pre_psn.into_inner()));
        payload[12..28].copy_from_slice(&prev_bitmap.to_be_bytes()); // prev_bitmap
        payload[28..44].copy_from_slice(&now_bitmap.to_be_bytes());
        payload[44..].copy_from_slice(&aeth_seg0.value.to_be_bytes());

        Self::build_ethernet_frame(self.src_ip, self.dst_ip, mac, mac, &payload)
    }

    fn build_ethernet_frame(
        src_ip: u32,
        dst_ip: u32,
        src_mac: MacAddr,
        dst_mac: MacAddr,
        payload: &[u8],
    ) -> Vec<u8> {
        const UDP_PORT: u16 = 4791;
        const ETH_HEADER_LEN: usize = 14;
        const IP_HEADER_LEN: usize = 20;
        const UDP_HEADER_LEN: usize = 8;

        let total_len = ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + payload.len();

        let mut buffer = vec![0u8; total_len];

        let mut eth_packet = MutableEthernetPacket::new(&mut buffer)
            .unwrap_or_else(|| unreachable!("Failed to create ethernet packet"));
        eth_packet.set_source(src_mac);
        eth_packet.set_destination(dst_mac);
        eth_packet.set_ethertype(EtherTypes::Ipv4);

        let mut ipv4_packet = MutableIpv4Packet::new(&mut buffer[ETH_HEADER_LEN..])
            .unwrap_or_else(|| unreachable!("Failed to create IPv4 packet"));
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_dscp(0);
        ipv4_packet.set_ecn(0);
        ipv4_packet.set_total_length((IP_HEADER_LEN + UDP_HEADER_LEN + payload.len()) as u16);
        ipv4_packet.set_identification(0);
        ipv4_packet.set_flags(Ipv4Flags::DontFragment);
        ipv4_packet.set_fragment_offset(0);
        ipv4_packet.set_ttl(64);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ipv4_packet.set_source(Ipv4Addr::from_bits(src_ip));
        ipv4_packet.set_destination(Ipv4Addr::from_bits(dst_ip));
        ipv4_packet.set_checksum(ipv4_packet.get_checksum());

        let mut udp_packet = MutableUdpPacket::new(&mut buffer[ETH_HEADER_LEN + IP_HEADER_LEN..])
            .unwrap_or_else(|| unreachable!("Failed to create UDP packet"));
        udp_packet.set_source(UDP_PORT);
        udp_packet.set_destination(UDP_PORT);
        udp_packet.set_length((UDP_HEADER_LEN + payload.len()) as u16);
        udp_packet.set_payload(payload);
        udp_packet.set_checksum(udp_packet.get_checksum());

        buffer
    }
}

#[bitsize(32)]
#[derive(Default, Clone, Copy, DebugBits, FromBits)]
pub(crate) struct AethSeg0 {
    pre_psn: u24,
    resv0: u5,
    is_send_by_driver: bool,
    is_window_slided: bool,
    is_packet_loss: bool,
}

#[bitsize(96)]
#[derive(Default, Clone, Copy, DebugBits, FromBits)]
pub(crate) struct Bth {
    psn: u24,
    resv7: u7,
    ack_req: bool,
    dqpn: u24,
    resv6: u6,
    becn: bool,
    fecn: bool,
    msn: u16,
    tver: u4,
    pad_cnt: u2,
    is_retry: bool,
    solicited: bool,
    opcode: u5,
    trans_type: u3,
}
