use std::{
    io, iter,
    net::Ipv4Addr,
    sync::{atomic::AtomicBool, Arc},
    thread::current,
    time::Duration,
};

use crossbeam_deque::Worker;
use parking_lot::Mutex;
use qp_attr::{IbvQpAttr, IbvQpInitAttr};

use crate::{
    ack_responder::AckResponder,
    ack_timeout::QpAckTimeoutWorker,
    cmd::{CommandConfigurator, MttUpdate, PgtUpdate, RecvBufferMeta, UpdateQp},
    completion::{
        Completion, CompletionQueueTable, CompletionTask, CompletionWorker, CqManager, Event,
        PostRecvEvent,
    },
    config::DeviceConfig,
    constants::CARD_MAC_ADDRESS,
    mem::{
        get_num_page, page::PageAllocator, pin_pages, virt_to_phy::AddressResolver, DmaBuf,
        DmaBufAllocator, MemoryPinner, PageWithPhysAddr, UmemHandler,
    },
    meta_report,
    mtt::{Mtt, PgtEntry},
    net::{config::NetworkConfig, reader::NetConfigReader},
    qp::{QpAttr, QpManager, QpTableShared},
    rdma_worker::{RdmaWriteTask, RdmaWriteWorker},
    recv::{
        post_recv_channel, PostRecvTx, PostRecvTxTable, RecvWorker, RecvWrQueueTable, TcpChannel,
    },
    retransmit::PacketRetransmitWorker,
    ringbuf_desc::DescRingBufAllocator,
    send::{self, SendHandle},
    simple_nic::SimpleNicController,
    spawner::{task_channel, AbortSignal, SingleThreadTaskWorker, TaskTx},
    types::{RecvWr, SendWr, SendWrBase, SendWrRdma},
};

use super::{mode::Mode, DeviceAdaptor};

pub(crate) trait HwDevice {
    type Adaptor;
    type DmaBufAllocator;
    type UmemHandler;

    fn new_adaptor(&self) -> io::Result<Self::Adaptor>;
    fn new_dma_buf_allocator(&self) -> io::Result<Self::DmaBufAllocator>;
    fn new_umem_handler(&self) -> Self::UmemHandler;
}

pub(crate) trait DeviceOps {
    fn reg_mr(&mut self, addr: u64, length: usize, pd_handle: u32, access: u8) -> io::Result<u32>;
    fn dereg_mr(&mut self, mr_key: u32) -> io::Result<()>;
    fn create_qp(&mut self, attr: IbvQpInitAttr) -> io::Result<u32>;
    fn update_qp(&mut self, qpn: u32, attr: IbvQpAttr) -> io::Result<()>;
    fn destroy_qp(&mut self, qpn: u32);
    fn create_cq(&mut self) -> Option<u32>;
    fn destroy_cq(&mut self, handle: u32);
    fn poll_cq(&mut self, handle: u32, max_num_entries: usize) -> Vec<Completion>;
    fn post_send(&mut self, qpn: u32, wr: SendWr) -> io::Result<()>;
    fn post_recv(&mut self, qpn: u32, wr: RecvWr) -> io::Result<()>;
}

pub(crate) struct HwDeviceCtx<H: HwDevice> {
    device: H,
    mtt: Mtt,
    mtt_buffer: DmaBuf,
    qp_manager: QpManager,
    qp_attr_table: QpTableShared<QpAttr>,
    cq_manager: CqManager,
    cq_table: CompletionQueueTable,
    cmd_controller: CommandConfigurator<H::Adaptor>,
    post_recv_tx_table: PostRecvTxTable,
    recv_wr_queue_table: RecvWrQueueTable,
    rdma_write_tx: TaskTx<RdmaWriteTask>,
    completion_tx: TaskTx<CompletionTask>,
    config: DeviceConfig,
    allocator: H::DmaBufAllocator,
}

#[allow(private_bounds)]
impl<H> HwDeviceCtx<H>
where
    H: HwDevice,
    H::Adaptor: DeviceAdaptor + Send + 'static,
    H::DmaBufAllocator: DmaBufAllocator,
    H::UmemHandler: UmemHandler,
{
    pub(crate) fn initialize(device: H, config: DeviceConfig) -> io::Result<Self> {
        let mode = Mode::default();
        let net_config = NetConfigReader::read();
        let adaptor = device.new_adaptor()?;
        let mut allocator = device.new_dma_buf_allocator()?;
        let mut rb_allocator = DescRingBufAllocator::new(&mut allocator);
        let cmd_controller =
            CommandConfigurator::init_v2(&adaptor, rb_allocator.alloc()?, rb_allocator.alloc()?)?;
        let send_bufs = iter::repeat_with(|| rb_allocator.alloc())
            .take(mode.num_channel())
            .collect::<Result<_, _>>()?;
        let meta_bufs = iter::repeat_with(|| rb_allocator.alloc())
            .take(mode.num_channel())
            .collect::<Result<_, _>>()?;

        let (rdma_write_tx, rdma_write_rx) = task_channel();
        let (completion_tx, completion_rx) = task_channel();
        let (ack_timeout_tx, ack_timeout_rx) = task_channel();
        let (packet_retransmit_tx, packet_retransmit_rx) = task_channel();
        let (ack_tx, ack_rx) = task_channel();

        let abort = AbortSignal::new();
        let rx_buffer = rb_allocator.alloc()?;
        let rx_buffer_pa = rx_buffer.phys_addr;
        let qp_attr_table = QpTableShared::new();
        let qp_manager = QpManager::new();
        let cq_manager = CqManager::new();
        let cq_table = CompletionQueueTable::new();
        let simple_nic_controller = SimpleNicController::init_v2(
            &adaptor,
            rb_allocator.alloc()?,
            rb_allocator.alloc()?,
            rb_allocator.alloc()?,
            rx_buffer,
        )?;
        let (simple_nic_tx, simple_nic_rx) = simple_nic_controller.into_split();
        let handle = send::spawn(&adaptor, send_bufs, mode, &abort)?;
        AckResponder::new(qp_attr_table.clone(), Box::new(simple_nic_tx)).spawn(
            ack_rx,
            "AckResponder",
            abort.clone(),
        );
        PacketRetransmitWorker::new(handle.clone()).spawn(
            packet_retransmit_rx,
            "PacketRetransmitWorker",
            abort.clone(),
        );
        QpAckTimeoutWorker::new(packet_retransmit_tx.clone(), config.ack()).spawn_polling(
            ack_timeout_rx,
            "QpAckTimeoutWorker",
            abort.clone(),
            Duration::from_nanos(4096u64 << config.ack().check_duration_exp),
        );
        RdmaWriteWorker::new(
            qp_attr_table.clone(),
            handle,
            ack_timeout_tx.clone(),
            packet_retransmit_tx.clone(),
            completion_tx.clone(),
        )
        .spawn(rdma_write_rx, "RdmaWriteWorker", abort.clone());
        CompletionWorker::new(
            cq_table.clone_arc(),
            qp_attr_table.clone(),
            ack_tx.clone(),
            ack_timeout_tx.clone(),
            rdma_write_tx.clone(),
        )
        .spawn(completion_rx, "CompletionWorker", abort.clone());
        meta_report::spawn(
            &adaptor,
            meta_bufs,
            mode,
            ack_tx.clone(),
            ack_timeout_tx.clone(),
            packet_retransmit_tx.clone(),
            completion_tx.clone(),
            rdma_write_tx.clone(),
            abort.clone(),
        )?;
        cmd_controller.set_network(net_config);
        cmd_controller.set_raw_packet_recv_buffer(RecvBufferMeta::new(rx_buffer_pa));

        #[allow(clippy::mem_forget)]
        std::mem::forget(simple_nic_rx); // prevent libc::munmap being called

        Ok(Self {
            device,
            cmd_controller,
            qp_manager,
            qp_attr_table,
            cq_manager,
            cq_table,
            mtt_buffer: rb_allocator.alloc()?,
            mtt: Mtt::new(),
            post_recv_tx_table: PostRecvTxTable::new(),
            recv_wr_queue_table: RecvWrQueueTable::new(),
            rdma_write_tx,
            completion_tx,
            config,
            allocator,
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
                let wr = SendWrRdma::new_from_base(wr, x.addr, x.lkey);
                self.rdma_write(qpn, wr)
            }
            None => todo!("return rnr error"),
        }
    }

    fn rdma_read(&self, qpn: u32, wr: SendWrRdma) -> io::Result<()> {
        let (task, result_rx) = RdmaWriteTask::new_write(qpn, wr);
        self.rdma_write_tx.send(task);
        result_rx
            .recv()
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?
    }

    fn rdma_write(&self, qpn: u32, wr: SendWrRdma) -> io::Result<()> {
        let (task, result_rx) = RdmaWriteTask::new_write(qpn, wr);
        self.rdma_write_tx.send(task);
        result_rx
            .recv()
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?
    }
}

impl<H> DeviceOps for HwDeviceCtx<H>
where
    H: HwDevice,
    H::Adaptor: DeviceAdaptor + Send + 'static,
    H::UmemHandler: UmemHandler,
{
    fn reg_mr(&mut self, addr: u64, length: usize, pd_handle: u32, access: u8) -> io::Result<u32> {
        fn chunks(entry: PgtEntry) -> Vec<PgtEntry> {
            /// Maximum number of Page Table entries (PGT entries) that can be allocated in a single `PCIe` transaction.
            /// A `PCIe` transaction size is 128 bytes, and each PGT entry is a u64 (8 bytes).
            /// Therefore, 512 bytes / 8 bytes per entry = 16 entries per allocation.
            const MAX_NUM_PGT_ENTRY_PER_ALLOC: usize = 64;

            let base_index = entry.index;
            let end_index = base_index + entry.count;
            (base_index..end_index)
                .step_by(MAX_NUM_PGT_ENTRY_PER_ALLOC)
                .map(|index| PgtEntry {
                    index,
                    count: (MAX_NUM_PGT_ENTRY_PER_ALLOC as u32).min(end_index - index),
                })
                .collect()
        }

        let umem_handler = self.device.new_umem_handler();
        umem_handler.pin_pages(addr, length)?;
        let num_pages = get_num_page(addr, length);
        let (mr_key, pgt_entry) = self.mtt.register(num_pages)?;
        let length_u32 =
            u32::try_from(length).map_err(|_err| io::Error::from(io::ErrorKind::InvalidInput))?;
        let mut phys_addrs = umem_handler
            .virt_to_phys_range(addr, num_pages)?
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or(io::Error::new(
                io::ErrorKind::NotFound,
                "physical address not found",
            ))?
            .into_iter();
        let buf = &mut self.mtt_buffer.buf;
        let base_index = pgt_entry.index;
        let mtt_update = MttUpdate::new(addr, length_u32, mr_key, pd_handle, access, base_index);
        // TODO: makes updates atomic
        self.cmd_controller.update_mtt(mtt_update);
        for PgtEntry { index, count } in chunks(pgt_entry) {
            let bytes: Vec<u8> = phys_addrs
                .by_ref()
                .take(count as usize)
                .flat_map(u64::to_ne_bytes)
                .collect();
            buf.copy_from(0, &bytes);
            let pgt_update = PgtUpdate::new(self.mtt_buffer.phys_addr, index, count - 1);
            self.cmd_controller.update_pgt(pgt_update);
        }

        Ok(mr_key)
    }

    fn dereg_mr(&mut self, mr_key: u32) -> io::Result<()> {
        self.mtt.deregister(mr_key)
    }

    fn create_qp(&mut self, attr: IbvQpInitAttr) -> io::Result<u32> {
        let qpn = self
            .qp_manager
            .create_qp()
            .ok_or(io::Error::from(io::ErrorKind::WouldBlock))?;
        let _ignore = self.qp_attr_table.map_qp_mut(qpn, |current| {
            current.qpn = qpn;
            current.qp_type = attr.qp_type();
            current.send_cq = attr.send_cq();
            current.recv_cq = attr.recv_cq();
            current.mac_addr = CARD_MAC_ADDRESS;
            current.pmtu = ibverbs_sys::IBV_MTU_4096 as u8;
        });
        let entry = UpdateQp {
            ip_addr: 0,
            peer_mac_addr: 0,
            local_udp_port: 0x100,
            qp_type: attr.qp_type(),
            qpn,
            ..Default::default()
        };
        self.cmd_controller.update_qp(entry);

        Ok(qpn)
    }

    fn update_qp(&mut self, qpn: u32, attr: IbvQpAttr) -> io::Result<()> {
        let entry = self
            .qp_attr_table
            .map_qp_mut(qpn, |current| {
                let current_ip = (current.dqp_ip != 0).then_some(current.dqp_ip);
                let attr_ip = attr.dest_qp_ip().map(Ipv4Addr::to_bits);
                let ip_addr = attr_ip.or(current_ip).unwrap_or(0);
                let entry = UpdateQp {
                    qpn,
                    ip_addr,
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
                current.dqp_ip = ip_addr;
                entry
            })
            .ok_or(io::Error::from(io::ErrorKind::NotFound))?;

        self.cmd_controller.update_qp(entry);

        let qp = self
            .qp_attr_table
            .get_qp(qpn)
            .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
        if qp.dqpn != 0 && qp.dqp_ip != 0 && self.post_recv_tx_table.get_qp_mut(qpn).is_none() {
            let dqp_ip = Ipv4Addr::from_bits(qp.dqp_ip);
            let (tx, rx) =
                post_recv_channel::<TcpChannel>(qp.ip.into(), qp.dqp_ip.into(), qpn, qp.dqpn)?;
            self.post_recv_tx_table.insert(qpn, tx);
            let wr_queue = self
                .recv_wr_queue_table
                .clone_recv_wr_queue(qpn)
                .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
            RecvWorker::new(rx, wr_queue).spawn();
        }

        Ok(())
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
            SendWr::Rdma(wr) => self.rdma_write(qpn, wr),
            SendWr::Send(wr) => self.send(qpn, wr),
        }
    }

    fn poll_cq(&mut self, handle: u32, max_num_entries: usize) -> Vec<Completion> {
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
            .qp_attr_table
            .get_qp(qpn)
            .ok_or(io::Error::from(io::ErrorKind::InvalidInput))?;
        let event = Event::PostRecv(PostRecvEvent::new(qpn, wr.wr_id));
        self.completion_tx
            .send(CompletionTask::Register { qpn, event });
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
    use std::net::Ipv4Addr;

    use ibverbs_sys::*;
    use log::info;

    pub(crate) struct IbvQpInitAttr {
        pub(crate) qp_type: u8,
        pub(crate) send_cq: Option<u32>,
        pub(crate) recv_cq: Option<u32>,
    }

    impl IbvQpInitAttr {
        pub(crate) fn new(attr: ibv_qp_init_attr) -> Self {
            let send_cq = unsafe { attr.send_cq.as_ref() }.map(|cq| cq.handle);
            let recv_cq = unsafe { attr.recv_cq.as_ref() }.map(|cq| cq.handle);
            Self {
                qp_type: attr.qp_type as u8,
                send_cq,
                recv_cq,
            }
        }

        pub(crate) fn new_rc() -> Self {
            Self {
                qp_type: ibv_qp_type::IBV_QPT_RC as u8,
                send_cq: None,
                recv_cq: None,
            }
        }

        pub(crate) fn qp_type(&self) -> u8 {
            self.qp_type
        }

        pub(crate) fn send_cq(&self) -> Option<u32> {
            self.send_cq
        }

        pub(crate) fn recv_cq(&self) -> Option<u32> {
            self.recv_cq
        }
    }

    #[derive(Default, Copy, Clone)]
    pub(crate) struct IbvQpAttr {
        pub(crate) qp_state: Option<ibv_qp_state::Type>,
        pub(crate) cur_qp_state: Option<ibv_qp_state::Type>,
        pub(crate) path_mtu: Option<ibv_mtu>,
        pub(crate) path_mig_state: Option<ibv_mig_state>,
        pub(crate) qkey: Option<u32>,
        pub(crate) rq_psn: Option<u32>,
        pub(crate) sq_psn: Option<u32>,
        pub(crate) dest_qp_num: Option<u32>,
        pub(crate) qp_access_flags: Option<::std::os::raw::c_uint>,
        pub(crate) cap: Option<ibv_qp_cap>,
        pub(crate) ah_attr: Option<ibv_ah_attr>,
        pub(crate) alt_ah_attr: Option<ibv_ah_attr>,
        pub(crate) pkey_index: Option<u16>,
        pub(crate) alt_pkey_index: Option<u16>,
        pub(crate) en_sqd_async_notify: Option<u8>,
        pub(crate) max_rd_atomic: Option<u8>,
        pub(crate) max_dest_rd_atomic: Option<u8>,
        pub(crate) min_rnr_timer: Option<u8>,
        pub(crate) port_num: Option<u8>,
        pub(crate) timeout: Option<u8>,
        pub(crate) retry_cnt: Option<u8>,
        pub(crate) rnr_retry: Option<u8>,
        pub(crate) alt_port_num: Option<u8>,
        pub(crate) alt_timeout: Option<u8>,
        pub(crate) rate_limit: Option<u32>,
        pub(crate) dest_qp_ip: Option<Ipv4Addr>,
    }

    impl IbvQpAttr {
        pub(crate) fn new(attr: ibv_qp_attr, attr_mask: u32) -> Self {
            let dest_qp_ip = if attr_mask & ibv_qp_attr_mask::IBV_QP_AV.0 != 0 {
                let gid = unsafe { attr.ah_attr.grh.dgid.raw };
                info!("gid: {:x}", u128::from_be_bytes(gid));

                // Format: ::ffff:a.b.c.d
                let is_ipv4_mapped =
                    gid[..10].iter().all(|&x| x == 0) && gid[10] == 0xFF && gid[11] == 0xFF;

                is_ipv4_mapped.then(|| Ipv4Addr::new(gid[12], gid[13], gid[14], gid[15]))
            } else {
                None
            };

            Self {
                qp_state: (attr_mask & ibv_qp_attr_mask::IBV_QP_STATE.0 != 0)
                    .then_some(attr.qp_state),
                cur_qp_state: (attr_mask & ibv_qp_attr_mask::IBV_QP_CUR_STATE.0 != 0)
                    .then_some(attr.cur_qp_state),
                path_mtu: (attr_mask & ibv_qp_attr_mask::IBV_QP_PATH_MTU.0 != 0)
                    .then_some(attr.path_mtu),
                path_mig_state: (attr_mask & ibv_qp_attr_mask::IBV_QP_PATH_MIG_STATE.0 != 0)
                    .then_some(attr.path_mig_state),
                qkey: (attr_mask & ibv_qp_attr_mask::IBV_QP_QKEY.0 != 0).then_some(attr.qkey),
                rq_psn: (attr_mask & ibv_qp_attr_mask::IBV_QP_RQ_PSN.0 != 0).then_some(attr.rq_psn),
                sq_psn: (attr_mask & ibv_qp_attr_mask::IBV_QP_SQ_PSN.0 != 0).then_some(attr.sq_psn),
                dest_qp_num: (attr_mask & ibv_qp_attr_mask::IBV_QP_DEST_QPN.0 != 0)
                    .then_some(attr.dest_qp_num),
                qp_access_flags: (attr_mask & ibv_qp_attr_mask::IBV_QP_ACCESS_FLAGS.0 != 0)
                    .then_some(attr.qp_access_flags),
                cap: (attr_mask & ibv_qp_attr_mask::IBV_QP_CAP.0 != 0).then_some(attr.cap),
                ah_attr: (attr_mask & ibv_qp_attr_mask::IBV_QP_AV.0 != 0).then_some(attr.ah_attr),
                alt_ah_attr: (attr_mask & ibv_qp_attr_mask::IBV_QP_ALT_PATH.0 != 0)
                    .then_some(attr.alt_ah_attr),
                pkey_index: (attr_mask & ibv_qp_attr_mask::IBV_QP_PKEY_INDEX.0 != 0)
                    .then_some(attr.pkey_index),
                alt_pkey_index: (attr_mask & ibv_qp_attr_mask::IBV_QP_ALT_PATH.0 != 0)
                    .then_some(attr.alt_pkey_index),
                en_sqd_async_notify: (attr_mask & ibv_qp_attr_mask::IBV_QP_EN_SQD_ASYNC_NOTIFY.0
                    != 0)
                    .then_some(attr.en_sqd_async_notify),
                max_rd_atomic: (attr_mask & ibv_qp_attr_mask::IBV_QP_MAX_QP_RD_ATOMIC.0 != 0)
                    .then_some(attr.max_rd_atomic),
                max_dest_rd_atomic: (attr_mask & ibv_qp_attr_mask::IBV_QP_MAX_DEST_RD_ATOMIC.0
                    != 0)
                    .then_some(attr.max_dest_rd_atomic),
                min_rnr_timer: (attr_mask & ibv_qp_attr_mask::IBV_QP_MIN_RNR_TIMER.0 != 0)
                    .then_some(attr.min_rnr_timer),
                port_num: (attr_mask & ibv_qp_attr_mask::IBV_QP_PORT.0 != 0)
                    .then_some(attr.port_num),
                timeout: (attr_mask & ibv_qp_attr_mask::IBV_QP_TIMEOUT.0 != 0)
                    .then_some(attr.timeout),
                retry_cnt: (attr_mask & ibv_qp_attr_mask::IBV_QP_RETRY_CNT.0 != 0)
                    .then_some(attr.retry_cnt),
                rnr_retry: (attr_mask & ibv_qp_attr_mask::IBV_QP_RNR_RETRY.0 != 0)
                    .then_some(attr.rnr_retry),
                alt_port_num: (attr_mask & ibv_qp_attr_mask::IBV_QP_ALT_PATH.0 != 0)
                    .then_some(attr.alt_port_num),
                alt_timeout: (attr_mask & ibv_qp_attr_mask::IBV_QP_ALT_PATH.0 != 0)
                    .then_some(attr.alt_timeout),
                rate_limit: (attr_mask & ibv_qp_attr_mask::IBV_QP_RATE_LIMIT.0 != 0)
                    .then_some(attr.rate_limit),
                dest_qp_ip,
            }
        }

        pub(crate) fn qp_state(&self) -> Option<ibv_qp_state::Type> {
            self.qp_state
        }

        pub(crate) fn cur_qp_state(&self) -> Option<ibv_qp_state::Type> {
            self.cur_qp_state
        }

        pub(crate) fn path_mtu(&self) -> Option<ibv_mtu> {
            self.path_mtu
        }

        pub(crate) fn path_mig_state(&self) -> Option<ibv_mig_state> {
            self.path_mig_state
        }

        pub(crate) fn qkey(&self) -> Option<u32> {
            self.qkey
        }

        pub(crate) fn rq_psn(&self) -> Option<u32> {
            self.rq_psn
        }

        pub(crate) fn sq_psn(&self) -> Option<u32> {
            self.sq_psn
        }

        pub(crate) fn dest_qp_num(&self) -> Option<u32> {
            self.dest_qp_num
        }

        pub(crate) fn qp_access_flags(&self) -> Option<::std::os::raw::c_uint> {
            self.qp_access_flags
        }

        pub(crate) fn cap(&self) -> Option<ibv_qp_cap> {
            self.cap
        }

        pub(crate) fn ah_attr(&self) -> Option<ibv_ah_attr> {
            self.ah_attr
        }

        pub(crate) fn alt_ah_attr(&self) -> Option<ibv_ah_attr> {
            self.alt_ah_attr
        }

        pub(crate) fn pkey_index(&self) -> Option<u16> {
            self.pkey_index
        }

        pub(crate) fn alt_pkey_index(&self) -> Option<u16> {
            self.alt_pkey_index
        }

        pub(crate) fn en_sqd_async_notify(&self) -> Option<u8> {
            self.en_sqd_async_notify
        }

        pub(crate) fn max_rd_atomic(&self) -> Option<u8> {
            self.max_rd_atomic
        }

        pub(crate) fn max_dest_rd_atomic(&self) -> Option<u8> {
            self.max_dest_rd_atomic
        }

        pub(crate) fn min_rnr_timer(&self) -> Option<u8> {
            self.min_rnr_timer
        }

        pub(crate) fn port_num(&self) -> Option<u8> {
            self.port_num
        }

        pub(crate) fn timeout(&self) -> Option<u8> {
            self.timeout
        }

        pub(crate) fn retry_cnt(&self) -> Option<u8> {
            self.retry_cnt
        }

        pub(crate) fn rnr_retry(&self) -> Option<u8> {
            self.rnr_retry
        }

        pub(crate) fn alt_port_num(&self) -> Option<u8> {
            self.alt_port_num
        }

        pub(crate) fn alt_timeout(&self) -> Option<u8> {
            self.alt_timeout
        }

        pub(crate) fn rate_limit(&self) -> Option<u32> {
            self.rate_limit
        }

        pub(crate) fn dest_qp_ip(&self) -> Option<Ipv4Addr> {
            self.dest_qp_ip
        }
    }
}
