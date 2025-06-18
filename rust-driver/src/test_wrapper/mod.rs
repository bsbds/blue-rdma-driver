#![allow(
    clippy::all,
    missing_docs,
    clippy::missing_errors_doc,
    clippy::missing_docs_in_private_items,
    clippy::unwrap_used,
    missing_debug_implementations,
    missing_copy_implementations,
    clippy::pedantic,
    clippy::missing_inline_in_public_items,
    clippy::as_conversions,
    clippy::arithmetic_side_effects
)]

pub mod bench;
pub mod test_csr_rw;

use std::io;

use ipnetwork::Ipv4Network;

use crate::{
    cmd::CommandConfigurator,
    descriptors::{SendQueueReqDescSeg0, SendQueueReqDescSeg1},
    device::{ffi::EmulatedHwDevice, ops::HwDevice},
    net::config::{MacAddress, NetworkConfig},
    ringbuf_desc::{DescRingBufAllocator, DescRingBuffer},
    send::{ChunkPos, QpParams, SendQueue, SendQueueDesc, WorkReqOpCode, WrChunkBuilder},
    utils::Psn,
};

pub fn test_full_rb() -> io::Result<()> {
    let device = EmulatedHwDevice::new("127.0.0.1:7701".into());
    let adaptor = device.new_adaptor().unwrap();
    let mut allocator = device.new_dma_buf_allocator().unwrap();
    let mut rb_allocator = DescRingBufAllocator::new(allocator);
    let cmd_controller =
        CommandConfigurator::init_v2(&adaptor, rb_allocator.alloc()?, rb_allocator.alloc()?)
            .unwrap();
    let network_config = NetworkConfig {
        ip: Ipv4Network::new("10.0.0.2".parse().unwrap(), 24).unwrap(),
        peer_ip: "10.0.0.1".parse().unwrap(),
        gateway: Some("10.0.0.1".parse().unwrap()),
        mac: MacAddress([1; 6]),
    };
    cmd_controller.set_network(network_config);

    let sqpn = 1;
    let dqpn = 2;
    let qp_params = QpParams::new(1, 0, sqpn, 0, dqpn, 0, 5);

    let mut sq = SendQueue::new(DescRingBuffer::new(rb_allocator.alloc()?.buf));
    let wr = WrChunkBuilder::new_with_opcode(WorkReqOpCode::RdmaWrite)
        .set_qp_params(qp_params)
        .set_ibv_params(0, 0, 4096, 0, 0)
        .set_chunk_meta(Psn(0), 0, 0, 0, ChunkPos::Only)
        .set_is_retry()
        .build();
    let desc0 = SendQueueReqDescSeg0::new(
        wr.opcode,
        wr.msn,
        wr.psn.into_inner(),
        wr.qp_type,
        wr.dqpn,
        wr.flags,
        wr.dqp_ip,
        wr.raddr,
        wr.rkey,
        wr.total_len,
    );
    let desc1 = SendQueueReqDescSeg1::new(
        wr.opcode,
        wr.pmtu,
        wr.is_first,
        wr.is_last,
        wr.is_retry,
        wr.enable_ecn,
        wr.sqpn,
        wr.imm,
        wr.mac_addr,
        wr.lkey,
        wr.len,
        wr.laddr,
    );
    assert!(sq.push(SendQueueDesc::Seg0(desc0)), "failed to push");
    assert!(sq.push(SendQueueDesc::Seg1(desc1)), "failed to push");

    Ok(())
}
