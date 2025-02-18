use std::{
    io, iter,
    marker::PhantomData,
    net::Ipv4Addr,
    ptr,
    sync::{atomic::AtomicBool, Arc, OnceLock},
};

use crossbeam_deque::Worker;
use ipnetwork::{IpNetwork, Ipv4Network};
use parking_lot::Mutex;
use qp_attr::{IbvQpAttr, IbvQpInitAttr};

use crate::{
    ack_responder::AckResponder,
    completion_v2::{
        CompletionEvent, CompletionQueueTable, CompletionTask, CompletionWorker, CqManager,
        EventRegistry,
    },
    constants::PSN_MASK,
    ctx_ops::RdmaCtxOps,
    device_protocol::{
        DeviceCommand, MetaReport, MttEntry, QpParams, RecvBuffer, RecvBufferMeta, SimpleNicTunnel,
        UpdateQp, WorkReqOpCode, WorkReqSend, WrChunk, WrChunkBuilder,
    },
    fragmenter::PacketFragmenter,
    mem::{
        page::{ContiguousPages, EmulatedPageAllocator, PageAllocator},
        virt_to_phy::{AddressResolver, PhysAddrResolverEmulated},
        PageWithPhysAddr,
    },
    message_worker::{spawn_message_workers, Task},
    meta_worker,
    mtt::Mtt,
    net::{
        config::{MacAddress, NetworkConfig},
        tap::TapDevice,
    },
    packet_retransmit::{PacketRetransmitTask, PacketRetransmitWorker},
    protocol_impl_hardware::{
        queue::{
            meta_report_queue::init_and_spawn_meta_worker, DescRingBuffer, DescRingBufferAllocator,
        },
        spawn_send_workers, CommandController, SendQueueScheduler, SendWorker, SendWorkerBuilder,
        SimpleNicController,
    },
    qp::{DeviceQp, QpInitiatorTable, QpTrackerTable},
    qp_table::QpTable,
    queue_pair::{num_psn, QpManager, QueuePairAttrTable, SenderTable},
    recv::{post_recv_channel, PostRecvTx, PostRecvTxTable, RecvWr, RecvWrQueueTable, TcpChannel},
    send::{SendWr, SendWrBase, SendWrRdmaWrite, WrFragmenter, WrPacketFragmenter},
    send_queue::{IbvSendQueue, SendQueueElem},
    timeout_retransmit::{AckTimeoutConfig, RetransmitTask, TimeoutRetransmitWorker},
    tracker::{MessageMeta, Msn},
};

use super::{mode::Mode, DeviceAdaptor, CARD_IP_ADDRESS, CARD_MAC_ADDRESS};

pub(crate) trait HwDevice {
    type Adaptor;
    type PageAllocator;
    type PhysAddrResolver;

    fn new_adaptor(&self) -> Self::Adaptor;
    fn new_page_allocator(&self) -> Self::PageAllocator;
    fn new_phys_addr_resolver(&self) -> Self::PhysAddrResolver;
}

pub(crate) trait DeviceOps {
    fn reg_mr(&mut self, addr: u64, length: usize, access: u8) -> io::Result<u32>;
    fn create_qp(&mut self, attr: IbvQpInitAttr) -> io::Result<u32>;
    fn update_qp(&mut self, qpn: u32, attr: IbvQpAttr) -> io::Result<()>;
    fn destroy_qp(&mut self, qpn: u32);
    fn create_cq(&mut self) -> Option<u32>;
    fn destroy_cq(&mut self, handle: u32);
    fn poll_cq(&mut self, handle: u32, max_num_entries: usize) -> Vec<CompletionEvent>;
    fn post_send(&mut self, qpn: u32, wr: SendWr) -> io::Result<()>;
    fn post_recv(&mut self, qpn: u32, wr: RecvWr) -> io::Result<()>;
}

pub(crate) struct HwDeviceCtx<H: HwDevice> {
    device: H,
    mtt: Mtt,
    mtt_buffer: PageWithPhysAddr,
    qp_manager: QpManager,
    cq_manager: CqManager,
    cq_table: CompletionQueueTable,
    sender_table: SenderTable,
    retransmit_tx: flume::Sender<RetransmitTask>,
    packet_retransmit_tx: flume::Sender<PacketRetransmitTask>,
    completion_tx: flume::Sender<CompletionTask>,
    cmd_controller: CommandController<H::Adaptor>,
    send_scheduler: SendQueueScheduler,
    post_recv_tx_table: PostRecvTxTable,
    recv_wr_queue_table: RecvWrQueueTable,
}

#[allow(private_bounds)]
impl<H> HwDeviceCtx<H>
where
    H: HwDevice,
    H::Adaptor: DeviceAdaptor + Send + 'static,
    H::PageAllocator: PageAllocator<1>,
    H::PhysAddrResolver: AddressResolver,
{
    pub(crate) fn initialize(
        device: H,
        network_config: NetworkConfig,
        ack_config: AckTimeoutConfig,
    ) -> io::Result<Self> {
        let mode = Mode::default();
        let adaptor = device.new_adaptor();
        let mut allocator = device.new_page_allocator();
        let addr_resolver = device.new_phys_addr_resolver();
        let mut alloc_page = || PageWithPhysAddr::alloc(&mut allocator, &addr_resolver);
        let cmd_controller = CommandController::init_v2(&adaptor, alloc_page()?, alloc_page()?)?;
        let send_scheduler = SendQueueScheduler::new();
        let send_pages = iter::repeat_with(&mut alloc_page)
            .take(mode.num_channel())
            .collect::<Result<_, _>>()?;
        let meta_pages = iter::repeat_with(&mut alloc_page)
            .take(mode.num_channel())
            .collect::<Result<_, _>>()?;

        let is_shutdown = Arc::new(AtomicBool::new(false));
        let (completion_tx, completion_rx) = flume::unbounded();
        let (ack_tx, ack_rx) = flume::unbounded();
        let (retransmit_tx, retransmit_rx) = flume::unbounded();
        let (packet_retransmit_tx, packet_retransmit_rx) = flume::unbounded();
        let rx_buffer = alloc_page()?;
        let rx_buffer_pa = rx_buffer.phys_addr;
        let qp_attr_table = QueuePairAttrTable::new();
        let qp_manager = QpManager::new(qp_attr_table.clone_arc());
        let cq_manager = CqManager::new();
        let cq_table = CompletionQueueTable::new();

        let simple_nic_controller = SimpleNicController::init_v2(
            &adaptor,
            alloc_page()?,
            alloc_page()?,
            alloc_page()?,
            rx_buffer,
        )?;
        spawn_send_workers(&adaptor, send_pages, mode, &send_scheduler.injector())?;
        init_and_spawn_meta_worker(
            &adaptor,
            meta_pages,
            mode,
            ack_tx.clone(),
            retransmit_tx.clone(),
            packet_retransmit_tx.clone(),
            completion_tx.clone(),
            Arc::clone(&is_shutdown),
        )?;
        CompletionWorker::new(qp_attr_table.clone_arc(), completion_rx, &cq_table).spawn();
        cmd_controller.set_network(network_config)?;
        cmd_controller.set_raw_packet_recv_buffer(RecvBufferMeta::new(rx_buffer_pa))?;

        let (simple_nic_tx, _simple_nic_rx) = simple_nic_controller.into_split();
        AckResponder::new(qp_attr_table, ack_rx, Box::new(simple_nic_tx)).spawn();
        TimeoutRetransmitWorker::new(retransmit_rx, send_scheduler.clone_arc(), ack_config).spawn();
        PacketRetransmitWorker::new(packet_retransmit_rx, send_scheduler.clone_arc()).spawn();

        Ok(Self {
            device,
            cmd_controller,
            send_scheduler,
            qp_manager,
            cq_manager,
            cq_table,
            sender_table: SenderTable::new(),
            retransmit_tx,
            packet_retransmit_tx,
            completion_tx,
            mtt_buffer: alloc_page()?,
            mtt: Mtt::new(),
            post_recv_tx_table: PostRecvTxTable::new(),
            recv_wr_queue_table: RecvWrQueueTable::new(),
        })
    }
}

impl<H: HwDevice> HwDeviceCtx<H> {
    fn send(&self, qpn: u32, mut wr: SendWrBase) -> io::Result<()> {
        match self.recv_wr_queue_table.pop(qpn) {
            Some(x) => {
                if wr.length != x.length {
                    return Err(io::Error::from(io::ErrorKind::InvalidInput));
                }
                let wr = SendWrRdmaWrite::new_from_base(wr, x.addr, x.lkey);
                self.rdma_write(qpn, wr, WorkReqOpCode::Send)
            }
            None => todo!("return rnr error"),
        }
    }

    fn rdma_write(&self, qpn: u32, wr: SendWrRdmaWrite, opcode: WorkReqOpCode) -> io::Result<()> {
        let qp = self
            .qp_manager
            .get_qp(qpn)
            .ok_or(io::Error::from(io::ErrorKind::InvalidInput))?;
        let addr = wr.raddr();
        let length = wr.length();
        let num_psn =
            num_psn(qp.pmtu, addr, length).ok_or(io::Error::from(io::ErrorKind::InvalidInput))?;
        let (msn, psn) = self
            .sender_table
            .map_qp_mut(qpn, |sender| sender.next_wr(num_psn))
            .flatten()
            .ok_or(io::Error::from(io::ErrorKind::InvalidInput))?;
        let end_psn = (psn + num_psn) & PSN_MASK;
        let chunk_builder = WrChunkBuilder::new().set_qp_params(QpParams::new(
            msn,
            qp.qp_type,
            qp.qpn,
            qp.mac_addr,
            qp.dqpn,
            qp.dqp_ip,
            qp.pmtu,
        ));
        let flags = wr.send_flags();
        let mut ack_req = false;
        if flags & ibverbs_sys::ibv_send_flags::IBV_SEND_SIGNALED.0 != 0 {
            ack_req = true;
            let wr_id = wr.wr_id();
            let send_cq_handle = qp
                .send_cq
                .ok_or(io::Error::from(io::ErrorKind::InvalidInput))?;
            self.completion_tx.send(CompletionTask::Register {
                cq_handle: send_cq_handle,
                event: CompletionEvent::new_rdma_write(qpn, msn, end_psn, wr_id),
            });
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
            let fragmenter = PacketFragmenter::new(wr, qp_params, psn);
            let Some(last_packet_chunk) = fragmenter.into_iter().last() else {
                return Ok(());
            };
            let _ignore = self.retransmit_tx.send(RetransmitTask::NewAckReq {
                qpn,
                last_packet_chunk,
            });
        }

        let _ignore = self.packet_retransmit_tx.send(PacketRetransmitTask::NewWr {
            qpn,
            wr: SendQueueElem::new(psn, wr, qp_params),
        });

        let builder = WrChunkBuilder::new_with_opcode(opcode).set_qp_params(qp_params);
        let fragmenter = WrFragmenter::new(wr, builder, psn);
        for chunk in fragmenter {
            // TODO: Should this never fail
            self.send_scheduler.send(chunk)?;
        }

        Ok(())
    }
}

impl<H> DeviceOps for HwDeviceCtx<H>
where
    H: HwDevice,
    H::Adaptor: DeviceAdaptor + Send + 'static,
    H::PageAllocator: PageAllocator<1>,
    H::PhysAddrResolver: AddressResolver,
{
    fn reg_mr(&mut self, addr: u64, length: usize, access: u8) -> io::Result<u32> {
        let entry = self.mtt.register(
            &self.device.new_phys_addr_resolver(),
            &mut self.mtt_buffer.page,
            self.mtt_buffer.phys_addr,
            addr,
            length,
            0,
            access,
        )?;
        let mr_key = entry.mr_key;
        self.cmd_controller.update_mtt(entry)?;

        Ok(mr_key)
    }

    fn create_qp(&mut self, attr: IbvQpInitAttr) -> io::Result<u32> {
        let qpn = self
            .qp_manager
            .create_qp()
            .ok_or(io::Error::from(io::ErrorKind::WouldBlock))?;
        let _ignore = self.qp_manager.update_qp(qpn, |current| {
            current.qpn = qpn;
            current.qp_type = attr.qp_type();
            current.send_cq = attr.send_cq();
            current.recv_cq = attr.recv_cq();
            current.dqp_ip = CARD_IP_ADDRESS;
            current.mac_addr = CARD_MAC_ADDRESS;
            current.pmtu = ibverbs_sys::IBV_MTU_1024 as u8;
        });
        let entry = UpdateQp {
            ip_addr: CARD_IP_ADDRESS,
            local_udp_port: 0x100,
            peer_mac_addr: CARD_MAC_ADDRESS,
            qp_type: attr.qp_type(),
            qpn,
            ..Default::default()
        };
        self.cmd_controller.update_qp(entry)?;

        Ok(qpn)
    }

    fn update_qp(&mut self, qpn: u32, attr: IbvQpAttr) -> io::Result<()> {
        let entry = self
            .qp_manager
            .update_qp(qpn, |current| {
                let entry = UpdateQp {
                    qpn,
                    ip_addr: CARD_IP_ADDRESS,
                    local_udp_port: 0x100,
                    peer_mac_addr: CARD_MAC_ADDRESS,
                    qp_type: current.qp_type,
                    peer_qpn: attr.dest_qp_num().unwrap_or(current.dqpn),
                    rq_access_flags: attr
                        .qp_access_flags()
                        .map_or(current.access_flags, |x| x as u8),
                    pmtu: attr.path_mtu().map_or(current.pmtu, |x| x as u8),
                };
                current.dqpn = entry.peer_qpn;
                current.access_flags = entry.rq_access_flags;
                current.pmtu = entry.pmtu;
                entry
            })
            .ok_or(io::Error::from(io::ErrorKind::NotFound))?;

        if let Some(dqpn) = attr.dest_qp_num() {
            let (tx, rx) = post_recv_channel::<TcpChannel>(
                CARD_IP_ADDRESS.into(),
                CARD_IP_ADDRESS.into(),
                qpn,
                dqpn,
            )?;
            self.post_recv_tx_table.insert(qpn, tx);
        }

        self.cmd_controller.update_qp(entry)
    }

    fn destroy_qp(&mut self, qpn: u32) {
        self.qp_manager.destroy_qp(qpn);
    }

    fn create_cq(&mut self) -> Option<u32> {
        self.cq_manager.create_cq()
    }

    fn destroy_cq(&mut self, handle: u32) {
        self.cq_manager.destroy_cq(handle);
    }

    fn post_send(&mut self, qpn: u32, wr: SendWr) -> io::Result<()> {
        match wr {
            SendWr::RdmaWrite(wr) => self.rdma_write(qpn, wr, WorkReqOpCode::RdmaWrite),
            SendWr::Send(wr) => self.send(qpn, wr),
        }
    }

    fn poll_cq(&mut self, handle: u32, max_num_entries: usize) -> Vec<CompletionEvent> {
        let Some(cq) = self.cq_table.get_cq(handle) else {
            return vec![];
        };
        iter::repeat_with(|| cq.pop_front())
            .take_while(Option::is_some)
            .take(max_num_entries)
            .flatten()
            .collect()
    }

    fn post_recv(&mut self, qpn: u32, wr: RecvWr) -> io::Result<()> {
        let qp = self
            .qp_manager
            .get_qp(qpn)
            .ok_or(io::Error::from(io::ErrorKind::InvalidInput))?;
        let tx = self
            .post_recv_tx_table
            .get_qp_mut(qpn)
            .ok_or(io::Error::from(io::ErrorKind::InvalidInput))?;
        tx.send(wr)?;

        Ok(())
    }
}

#[allow(unsafe_code, clippy::wildcard_imports)]
pub(crate) mod qp_attr {
    use ibverbs_sys::*;

    pub(crate) struct IbvQpInitAttr {
        inner: ibv_qp_init_attr,
    }

    impl IbvQpInitAttr {
        pub(crate) fn new(inner: ibv_qp_init_attr) -> Self {
            Self { inner }
        }

        pub(crate) fn qp_type(&self) -> u8 {
            self.inner.qp_type as u8
        }

        pub(crate) fn send_cq(&self) -> Option<u32> {
            unsafe { self.inner.send_cq.as_ref() }.map(|cq| cq.handle)
        }

        pub(crate) fn recv_cq(&self) -> Option<u32> {
            unsafe { self.inner.recv_cq.as_ref() }.map(|cq| cq.handle)
        }
    }

    pub(crate) struct IbvQpAttr {
        inner: ibv_qp_attr,
        attr_mask: u32,
    }

    macro_rules! impl_getter {
        ($name:ident, $type:ty, $mask:expr) => {
            pub(crate) fn $name(&self) -> Option<$type> {
                (self.attr_mask & $mask.0 != 0).then_some(self.inner.$name)
            }
        };
    }

    impl IbvQpAttr {
        pub(crate) fn new(inner: ibv_qp_attr, attr_mask: u32) -> Self {
            Self { inner, attr_mask }
        }

        impl_getter!(qp_state, ibv_qp_state::Type, ibv_qp_attr_mask::IBV_QP_STATE);
        impl_getter!(
            cur_qp_state,
            ibv_qp_state::Type,
            ibv_qp_attr_mask::IBV_QP_CUR_STATE
        );
        impl_getter!(path_mtu, ibv_mtu, ibv_qp_attr_mask::IBV_QP_PATH_MTU);
        impl_getter!(
            path_mig_state,
            ibv_mig_state,
            ibv_qp_attr_mask::IBV_QP_PATH_MIG_STATE
        );
        impl_getter!(qkey, u32, ibv_qp_attr_mask::IBV_QP_QKEY);
        impl_getter!(rq_psn, u32, ibv_qp_attr_mask::IBV_QP_RQ_PSN);
        impl_getter!(sq_psn, u32, ibv_qp_attr_mask::IBV_QP_SQ_PSN);
        impl_getter!(dest_qp_num, u32, ibv_qp_attr_mask::IBV_QP_DEST_QPN);
        impl_getter!(
            qp_access_flags,
            ::std::os::raw::c_uint,
            ibv_qp_attr_mask::IBV_QP_ACCESS_FLAGS
        );
        impl_getter!(cap, ibv_qp_cap, ibv_qp_attr_mask::IBV_QP_CAP);
        impl_getter!(ah_attr, ibv_ah_attr, ibv_qp_attr_mask::IBV_QP_AV);
        impl_getter!(alt_ah_attr, ibv_ah_attr, ibv_qp_attr_mask::IBV_QP_ALT_PATH);
        impl_getter!(pkey_index, u16, ibv_qp_attr_mask::IBV_QP_PKEY_INDEX);
        impl_getter!(alt_pkey_index, u16, ibv_qp_attr_mask::IBV_QP_ALT_PATH);
        impl_getter!(
            en_sqd_async_notify,
            u8,
            ibv_qp_attr_mask::IBV_QP_EN_SQD_ASYNC_NOTIFY
        );
        impl_getter!(max_rd_atomic, u8, ibv_qp_attr_mask::IBV_QP_MAX_QP_RD_ATOMIC);
        impl_getter!(
            max_dest_rd_atomic,
            u8,
            ibv_qp_attr_mask::IBV_QP_MAX_DEST_RD_ATOMIC
        );
        impl_getter!(min_rnr_timer, u8, ibv_qp_attr_mask::IBV_QP_MIN_RNR_TIMER);
        impl_getter!(port_num, u8, ibv_qp_attr_mask::IBV_QP_PORT);
        impl_getter!(timeout, u8, ibv_qp_attr_mask::IBV_QP_TIMEOUT);
        impl_getter!(retry_cnt, u8, ibv_qp_attr_mask::IBV_QP_RETRY_CNT);
        impl_getter!(rnr_retry, u8, ibv_qp_attr_mask::IBV_QP_RNR_RETRY);
        impl_getter!(alt_port_num, u8, ibv_qp_attr_mask::IBV_QP_ALT_PATH);
        impl_getter!(alt_timeout, u8, ibv_qp_attr_mask::IBV_QP_ALT_PATH);
        impl_getter!(rate_limit, u32, ibv_qp_attr_mask::IBV_QP_RATE_LIMIT);
    }
}
