use std::{
    io,
    sync::{atomic::AtomicBool, Arc},
};

use crate::{
    ack_responder::AckResponse,
    completion_v2::CompletionTask,
    mem::PageWithPhysAddr,
    message_worker::Task,
    meta_worker_v2::MetaWorker,
    packet_retransmit::PacketRetransmitTask,
    protocol_impl_hardware::{
        desc::{
            MetaReportQueueAckDesc, MetaReportQueueAckExtraDesc, MetaReportQueueDescFirst,
            MetaReportQueueDescNext, MetaReportQueuePacketBasicInfoDesc,
            MetaReportQueueReadReqExtendInfoDesc, RingBufDescUntyped,
        },
        device::{
            mode::Mode, proxy::build_meta_report_queue_proxies, CsrBaseAddrAdaptor, DeviceAdaptor,
        },
        MetaReportQueueHandler,
    },
    timeout_retransmit::RetransmitTask,
};

use super::DescRingBuffer;

/// Meta report queue descriptors
pub(crate) enum MetaReportQueueDesc {
    /// Packet info for write operations
    WritePacketInfo(MetaReportQueuePacketBasicInfoDesc),
    /// Packet info for read operations
    ReadPacketInfo(
        (
            MetaReportQueuePacketBasicInfoDesc,
            MetaReportQueueReadReqExtendInfoDesc,
        ),
    ),
    /// Packet info for congestion event
    CnpPacketInfo(MetaReportQueuePacketBasicInfoDesc),
    /// Ack
    Ack(MetaReportQueueAckDesc),
    /// Nak
    Nak((MetaReportQueueAckDesc, MetaReportQueueAckExtraDesc)),
}

/// A transmit queue for the simple NIC device.
pub(crate) struct MetaReportQueue {
    /// Inner ring buffer
    inner: DescRingBuffer,
}

impl MetaReportQueue {
    pub(crate) fn new(inner: DescRingBuffer) -> Self {
        Self { inner }
    }

    /// Returns the base address of the buffer
    pub(crate) fn base_addr(&self) -> u64 {
        self.inner.base_addr()
    }

    /// Tries to poll next valid entry from the queue
    pub(crate) fn try_pop(&mut self) -> Option<MetaReportQueueDesc> {
        let first = self
            .inner
            .try_pop()
            .copied()
            .map(MetaReportQueueDescFirst::from)?;

        if !first.has_next() {
            return match first {
                MetaReportQueueDescFirst::PacketInfo(d) if d.ecn_marked() => {
                    Some(MetaReportQueueDesc::CnpPacketInfo(d))
                }
                MetaReportQueueDescFirst::PacketInfo(d) => {
                    Some(MetaReportQueueDesc::WritePacketInfo(d))
                }
                MetaReportQueueDescFirst::Ack(d) => Some(MetaReportQueueDesc::Ack(d)),
            };
        }

        let next = self.inner.try_pop().copied().map_or_else(
            || unreachable!("failed to read next descriptor"),
            MetaReportQueueDescNext::from,
        );
        match (first, next) {
            (MetaReportQueueDescFirst::PacketInfo(f), MetaReportQueueDescNext::ReadInfo(n)) => {
                Some(MetaReportQueueDesc::ReadPacketInfo((f, n)))
            }
            (MetaReportQueueDescFirst::Ack(f), MetaReportQueueDescNext::AckExtra(n)) => {
                Some(MetaReportQueueDesc::Nak((f, n)))
            }
            (MetaReportQueueDescFirst::PacketInfo(_), MetaReportQueueDescNext::AckExtra(_))
            | (MetaReportQueueDescFirst::Ack(_), MetaReportQueueDescNext::ReadInfo(_)) => {
                unreachable!("invalid descriptor format")
            }
        }
    }
}

pub(crate) fn init_and_spawn_meta_worker<Dev>(
    dev: &Dev,
    pages: Vec<PageWithPhysAddr>,
    mode: Mode,
    ack_tx: flume::Sender<AckResponse>,
    retransmit_tx: flume::Sender<RetransmitTask>,
    packet_retransmit_tx: flume::Sender<PacketRetransmitTask>,
    completion_tx: flume::Sender<CompletionTask>,
    is_shutdown: Arc<AtomicBool>,
) -> io::Result<()>
where
    Dev: Clone + DeviceAdaptor + Send + 'static,
{
    let mut mrq_proxies = build_meta_report_queue_proxies(dev.clone(), mode);
    for (proxy, page) in mrq_proxies.iter_mut().zip(pages.iter()) {
        proxy.write_base_addr(page.phys_addr)?;
    }
    let mrqs: Vec<_> = pages
        .into_iter()
        .map(|p| MetaReportQueue::new(DescRingBuffer::new(p.page)))
        .collect();

    MetaWorker::new(
        MetaReportQueueHandler::new(mrqs),
        ack_tx,
        retransmit_tx,
        packet_retransmit_tx,
        completion_tx,
    )
    .spawn(is_shutdown);

    Ok(())
}
