use std::ptr::NonNull;
use std::{io, net::Ipv4Addr, ptr};

use ipnetwork::{IpNetwork, Ipv4Network};
use log::error;

use crate::constants::TEST_CARD_IP_ADDRESS;
use crate::{
    ack_timeout::AckTimeoutConfig,
    completion::Completion,
    config::{ConfigLoader, DeviceConfig},
    mem::{
        page::EmulatedPageAllocator, sim_alloc, virt_to_phy::PhysAddrResolverEmulated,
        EmulatedUmemHandler,
    },
    net::config::{MacAddress, NetworkConfig},
    types::{RecvWr, SendWr},
};

use super::{
    emulated::EmulatedDevice,
    hardware::PciHwDevice,
    mock::{MockDeviceCtx, MockHwDevice},
    ops::{
        qp_attr::{IbvQpAttr, IbvQpInitAttr},
        DeviceOps, HwDevice, HwDeviceCtx,
    },
};

use crate::error::Result;

const POST_RECV_TCP_LOOP_BACK_SERVER_ADDRESS: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const POST_RECV_TCP_LOOP_BACK_CLIENT_ADDRESS: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

static HEAP_ALLOCATOR: sim_alloc::Simalloc = sim_alloc::Simalloc::new();

macro_rules! deref_or_ret {
    ($ptr:expr, $ret:expr) => {
        match unsafe { $ptr.as_mut() } {
            Some(val) => *val,
            None => return $ret,
        }
    };
}

#[allow(unsafe_code)]
/// RDMA context operations for Blue-RDMA driver.
///
/// # Safety
/// Implementors must ensure all FFI and RDMA verbs specification requirements are met,
pub unsafe trait RdmaCtxOps {
    fn init();

    #[allow(clippy::new_ret_no_self)]
    /// Safety: caller must ensure `sysfs_name` is a valid pointer
    fn new(sysfs_name: *const std::ffi::c_char) -> *mut std::ffi::c_void;

    fn free(driver_data: *const std::ffi::c_void);

    fn alloc_pd(blue_context: *mut ibverbs_sys::ibv_context) -> *mut ibverbs_sys::ibv_pd;

    fn dealloc_pd(pd: *mut ibverbs_sys::ibv_pd) -> ::std::os::raw::c_int;

    fn query_device_ex(
        blue_context: *mut ibverbs_sys::ibv_context,
        _input: *const ibverbs_sys::ibv_query_device_ex_input,
        device_attr: *mut ibverbs_sys::ibv_device_attr,
        _attr_size: usize,
    ) -> ::std::os::raw::c_int;

    fn query_port(
        blue_context: *mut ibverbs_sys::ibv_context,
        port_num: u8,
        port_attr: *mut ibverbs_sys::ibv_port_attr,
    ) -> ::std::os::raw::c_int;

    fn create_cq(
        blue_context: *mut ibverbs_sys::ibv_context,
        cqe: core::ffi::c_int,
        channel: *mut ibverbs_sys::ibv_comp_channel,
        comp_vector: core::ffi::c_int,
    ) -> *mut ibverbs_sys::ibv_cq;

    fn destroy_cq(cq: *mut ibverbs_sys::ibv_cq) -> ::std::os::raw::c_int;

    fn create_qp(
        pd: *mut ibverbs_sys::ibv_pd,
        init_attr: *mut ibverbs_sys::ibv_qp_init_attr,
    ) -> *mut ibverbs_sys::ibv_qp;

    fn destroy_qp(qp: *mut ibverbs_sys::ibv_qp) -> ::std::os::raw::c_int;

    fn modify_qp(
        qp: *mut ibverbs_sys::ibv_qp,
        attr: *mut ibverbs_sys::ibv_qp_attr,
        attr_mask: core::ffi::c_int,
    ) -> ::std::os::raw::c_int;

    fn query_qp(
        qp: *mut ibverbs_sys::ibv_qp,
        attr: *mut ibverbs_sys::ibv_qp_attr,
        attr_mask: core::ffi::c_int,
        init_attr: *mut ibverbs_sys::ibv_qp_init_attr,
    ) -> ::std::os::raw::c_int;

    fn reg_mr(
        pd: *mut ibverbs_sys::ibv_pd,
        addr: *mut ::std::os::raw::c_void,
        length: usize,
        _hca_va: u64,
        access: core::ffi::c_int,
    ) -> *mut ibverbs_sys::ibv_mr;

    fn dereg_mr(mr: *mut ibverbs_sys::ibv_mr) -> ::std::os::raw::c_int;

    fn post_send(
        qp: *mut ibverbs_sys::ibv_qp,
        wr: *mut ibverbs_sys::ibv_send_wr,
        bad_wr: *mut *mut ibverbs_sys::ibv_send_wr,
    ) -> ::std::os::raw::c_int;

    fn post_recv(
        qp: *mut ibverbs_sys::ibv_qp,
        wr: *mut ibverbs_sys::ibv_recv_wr,
        bad_wr: *mut *mut ibverbs_sys::ibv_recv_wr,
    ) -> ::std::os::raw::c_int;

    fn poll_cq(cq: *mut ibverbs_sys::ibv_cq, num_entries: i32, wc: *mut ibverbs_sys::ibv_wc)
        -> i32;
}

#[allow(
    missing_debug_implementations,
    missing_copy_implementations,
    clippy::exhaustive_structs
)]
pub struct BlueRdmaCore;

impl BlueRdmaCore {
    fn init_logger() {
        let _ignore = env_logger::try_init();
    }

    #[allow(clippy::unwrap_used, clippy::unwrap_in_result)]
    fn new_hw(sysfs_name: &str) -> Result<HwDeviceCtx<PciHwDevice>> {
        Self::init_logger();
        let config = ConfigLoader::load_default()?;
        let device = PciHwDevice::open_default()?;
        device.reset()?;
        #[cfg(feature = "debug_csrs")]
        device.set_custom()?;
        let mut ctx = HwDeviceCtx::initialize(device, config)?;
        Ok(ctx)
    }

    #[allow(clippy::unwrap_used, clippy::unwrap_in_result)]
    fn new_emulated(sysfs_name: &str) -> Result<HwDeviceCtx<EmulatedHwDevice>> {
        let device = match sysfs_name {
            "uverbs0" => {
                sim_alloc::init_global_allocator(0, &HEAP_ALLOCATOR);
                EmulatedHwDevice::new("127.0.0.1:7701".into())
            }
            "uverbs1" => {
                sim_alloc::init_global_allocator(1, &HEAP_ALLOCATOR);
                EmulatedHwDevice::new("127.0.0.1:7702".into())
            }
            _ => unreachable!("unexpected sysfs_name"),
        };
        let (post_recv_ip, post_recv_peer_ip) = match sysfs_name {
            "uverbs0" => (
                POST_RECV_TCP_LOOP_BACK_CLIENT_ADDRESS,
                POST_RECV_TCP_LOOP_BACK_SERVER_ADDRESS,
            ),
            "uverbs1" => (
                POST_RECV_TCP_LOOP_BACK_SERVER_ADDRESS,
                POST_RECV_TCP_LOOP_BACK_CLIENT_ADDRESS,
            ),
            _ => unreachable!("unexpected sysfs_name"),
        };

        let ack = AckTimeoutConfig::new(16, 18, 100);
        let config = DeviceConfig { ack };
        // (check_duration, local_ack_timeout) : (256ms, 1s) because emulator is slow
        HwDeviceCtx::initialize(device, config)
    }

    #[allow(clippy::unnecessary_wraps)]
    fn new_mock(sysfs_name: &str) -> Result<MockDeviceCtx> {
        Ok(MockDeviceCtx::default())
    }
}

pub(crate) struct EmulatedHwDevice {
    addr: String,
}

impl EmulatedHwDevice {
    pub(crate) fn new(addr: String) -> Self {
        Self { addr }
    }
}

impl HwDevice for EmulatedHwDevice {
    type Adaptor = EmulatedDevice;

    type DmaBufAllocator = EmulatedPageAllocator<1>;

    type UmemHandler = EmulatedUmemHandler;

    fn new_adaptor(&self) -> Result<Self::Adaptor> {
        Ok(EmulatedDevice::new_with_addr(&self.addr))
    }

    fn new_dma_buf_allocator(&self) -> Result<Self::DmaBufAllocator> {
        Ok(EmulatedPageAllocator::new(
            sim_alloc::page_start_addr()..sim_alloc::heap_start_addr(),
        ))
    }

    fn new_umem_handler(&self) -> Self::UmemHandler {
        EmulatedUmemHandler::new(sim_alloc::shm_start_addr() as u64)
    }
}

#[allow(unsafe_code)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
unsafe impl RdmaCtxOps for BlueRdmaCore {
    #[inline]
    fn init() {}

    #[inline]
    fn new(sysfs_name: *const std::ffi::c_char) -> *mut std::ffi::c_void {
        let name = unsafe {
            std::ffi::CStr::from_ptr(sysfs_name)
                .to_string_lossy()
                .into_owned()
        };
        #[cfg(feature = "hw")]
        let ctx = BlueRdmaCore::new_hw(&name);
        #[cfg(feature = "sim")]
        let ctx = BlueRdmaCore::new_emulated(&name);
        #[cfg(feature = "mock")]
        let ctx = BlueRdmaCore::new_mock(&name);

        match ctx {
            Ok(x) => Box::into_raw(Box::new(x)).cast(),
            Err(err) => {
                error!("Failed to initialize hw context: {err}");
                ptr::null_mut()
            }
        }
    }

    #[inline]
    fn free(driver_data: *const std::ffi::c_void) {
        if driver_data.is_null() {
            error!("Failed to free driver data");
        } else {
            unsafe {
                drop(Box::from_raw(
                    driver_data as *mut HwDeviceCtx<EmulatedHwDevice>,
                ));
            }
        }
    }

    #[inline]
    fn alloc_pd(blue_context: *mut ibverbs_sys::ibv_context) -> *mut ibverbs_sys::ibv_pd {
        let bluerdma = get_device(blue_context);

        match bluerdma.alloc_pd() {
            Ok(handle) => Box::into_raw(Box::new(ibverbs_sys::ibv_pd {
                context: blue_context,
                handle,
            })),
            Err(err) => {
                error!("Failed to alloc PD: {err}");
                ptr::null_mut()
            }
        }
    }

    #[inline]
    fn dealloc_pd(pd: *mut ibverbs_sys::ibv_pd) -> ::std::os::raw::c_int {
        let pd = deref_or_ret!(pd, libc::EINVAL);
        let bluerdma = get_device(pd.context);

        match bluerdma.dealloc_pd(pd.handle) {
            Ok(()) => 0,
            Err(err) => {
                error!("failed to dealloc PD");
                err.to_errno()
            }
        }
    }

    #[inline]
    fn query_device_ex(
        _blue_context: *mut ibverbs_sys::ibv_context,
        _input: *const ibverbs_sys::ibv_query_device_ex_input,
        device_attr: *mut ibverbs_sys::ibv_device_attr,
        _attr_size: usize,
    ) -> ::std::os::raw::c_int {
        unsafe {
            (*device_attr) = ibverbs_sys::ibv_device_attr {
                max_qp: 256,
                max_qp_wr: 64,
                max_sge: 8,
                max_cq: 256,
                max_cqe: 4096,
                max_mr: 256,
                max_pd: 256,
                phys_port_cnt: 1,
                ..Default::default()
            };
        }
        0
    }

    #[inline]
    fn query_port(
        _blue_context: *mut ibverbs_sys::ibv_context,
        _port_num: u8,
        port_attr: *mut ibverbs_sys::ibv_port_attr,
    ) -> ::std::os::raw::c_int {
        unsafe {
            (*port_attr) = ibverbs_sys::ibv_port_attr {
                state: ibverbs_sys::ibv_port_state::IBV_PORT_ACTIVE,
                max_mtu: ibverbs_sys::IBV_MTU_4096,
                active_mtu: ibverbs_sys::IBV_MTU_4096,
                gid_tbl_len: 256,
                port_cap_flags: 0x0000_2c00,
                max_msg_sz: 1 << 31,
                lid: 1,
                link_layer: ibverbs_sys::IBV_LINK_LAYER_ETHERNET as u8,
                ..Default::default()
            };
        }
        0
    }

    #[inline]
    fn create_cq(
        blue_context: *mut ibverbs_sys::ibv_context,
        cqe: core::ffi::c_int,
        channel: *mut ibverbs_sys::ibv_comp_channel,
        comp_vector: core::ffi::c_int,
    ) -> *mut ibverbs_sys::ibv_cq {
        let bluerdma = get_device(blue_context);
        match bluerdma.create_cq() {
            Ok(handle) => {
                let cq = ibverbs_sys::ibv_cq {
                    context: blue_context,
                    channel,
                    cq_context: ptr::null_mut(),
                    handle,
                    cqe,
                    mutex: ibverbs_sys::pthread_mutex_t::default(),
                    cond: ibverbs_sys::pthread_cond_t::default(),
                    comp_events_completed: 0,
                    async_events_completed: 0,
                };
                Box::into_raw(Box::new(cq))
            }
            Err(err) => {
                error!("Failed to create cq");
                ptr::null_mut()
            }
        }
    }

    #[inline]
    fn destroy_cq(cq: *mut ibverbs_sys::ibv_cq) -> ::std::os::raw::c_int {
        let cq = deref_or_ret!(cq, libc::EINVAL);
        let bluerdma = get_device(cq.context);

        match bluerdma.destroy_cq(cq.handle) {
            Ok(()) => 0,
            Err(err) => {
                error!("Failed to destroy CQ: {}", cq.handle);
                err.to_errno()
            }
        }
    }

    #[inline]
    fn create_qp(
        pd: *mut ibverbs_sys::ibv_pd,
        init_attr: *mut ibverbs_sys::ibv_qp_init_attr,
    ) -> *mut ibverbs_sys::ibv_qp {
        let context = deref_or_ret!(pd, ptr::null_mut()).context;
        let bluerdma = get_device(context);
        let init_attr = deref_or_ret!(init_attr, ptr::null_mut());
        match bluerdma.create_qp(IbvQpInitAttr::new(init_attr)) {
            Ok(qpn) => Box::into_raw(Box::new(ibverbs_sys::ibv_qp {
                context,
                qp_context: ptr::null_mut(),
                pd,
                send_cq: ptr::null_mut(),
                recv_cq: ptr::null_mut(),
                srq: ptr::null_mut(),
                handle: 0,
                qp_num: qpn,
                state: ibverbs_sys::ibv_qp_state::IBV_QPS_INIT,
                qp_type: init_attr.qp_type,
                mutex: ibverbs_sys::pthread_mutex_t::default(),
                cond: ibverbs_sys::pthread_cond_t::default(),
                events_completed: 0,
            })),
            Err(err) => {
                error!("Failed to create qp: {err}");
                ptr::null_mut()
            }
        }
    }

    #[inline]
    fn destroy_qp(qp: *mut ibverbs_sys::ibv_qp) -> ::std::os::raw::c_int {
        let qp = deref_or_ret!(qp, libc::EINVAL);
        let context = qp.context;
        let bluerdma = get_device(context);
        let qpn = qp.qp_num;
        match bluerdma.destroy_qp(qpn) {
            Ok(()) => 0,
            Err(err) => {
                error!("Failed to destroy QP: {qpn}");
                err.to_errno()
            }
        }
    }

    #[allow(clippy::cast_sign_loss)]
    #[inline]
    fn modify_qp(
        qp: *mut ibverbs_sys::ibv_qp,
        attr: *mut ibverbs_sys::ibv_qp_attr,
        attr_mask: core::ffi::c_int,
    ) -> ::std::os::raw::c_int {
        let qp = deref_or_ret!(qp, libc::EINVAL);
        let attr = deref_or_ret!(attr, libc::EINVAL);
        let context = qp.context;
        let bluerdma = get_device(context);
        let mask = attr_mask as u32;
        match bluerdma.update_qp(qp.qp_num, IbvQpAttr::new(attr, attr_mask as u32)) {
            Ok(()) => 0,
            Err(err) => {
                error!("Failed to modify QP: {}", qp.qp_num);
                err.to_errno()
            }
        }
    }

    #[inline]
    fn query_qp(
        qp: *mut ibverbs_sys::ibv_qp,
        attr: *mut ibverbs_sys::ibv_qp_attr,
        attr_mask: core::ffi::c_int,
        init_attr: *mut ibverbs_sys::ibv_qp_init_attr,
    ) -> ::std::os::raw::c_int {
        let qp = deref_or_ret!(qp, libc::EINVAL);
        let context = qp.context;
        let bluerdma = unsafe { get_device(context) };

        0
    }

    #[allow(clippy::cast_sign_loss)]
    #[inline]
    fn reg_mr(
        pd: *mut ibverbs_sys::ibv_pd,
        addr: *mut ::std::os::raw::c_void,
        length: usize,
        _hca_va: u64,
        access: core::ffi::c_int,
    ) -> *mut ibverbs_sys::ibv_mr {
        let pd_deref = deref_or_ret!(pd, ptr::null_mut());
        let context = pd_deref.context;
        let pd_handle = pd_deref.handle;
        let bluerdma = get_device(pd_deref.context);
        match bluerdma.reg_mr(addr as u64, length, pd_handle, access as u8) {
            Ok(mr_key) => {
                let ibv_mr = Box::new(ibverbs_sys::ibv_mr {
                    context,
                    pd,
                    addr,
                    length,
                    handle: mr_key, // the `mr_key` is used for identify the memory region
                    lkey: mr_key,
                    rkey: mr_key,
                });
                Box::into_raw(ibv_mr)
            }
            Err(err) => {
                error!("Failed to register MR");
                ptr::null_mut()
            }
        }
    }

    #[inline]
    fn dereg_mr(mr: *mut ibverbs_sys::ibv_mr) -> ::std::os::raw::c_int {
        let mr = deref_or_ret!(mr, libc::EINVAL);
        let pd = deref_or_ret!(mr.pd, libc::EINVAL);
        let bluerdma = get_device(mr.context);
        match bluerdma.dereg_mr(mr.handle) {
            Ok(()) => 0,
            Err(err) => {
                error!("Failed to deregister MR: {err}");
                err.to_errno()
            }
        }
    }

    #[inline]
    fn post_send(
        qp: *mut ibverbs_sys::ibv_qp,
        wr: *mut ibverbs_sys::ibv_send_wr,
        bad_wr: *mut *mut ibverbs_sys::ibv_send_wr,
    ) -> ::std::os::raw::c_int {
        let qp = deref_or_ret!(qp, libc::EINVAL);
        let wr = deref_or_ret!(wr, libc::EINVAL);
        let context = qp.context;
        let qp_num = qp.qp_num;
        let bluerdma = get_device(context);
        let wr = SendWr::new(wr).unwrap_or_else(|_| todo!("handle invalid input"));
        match bluerdma.post_send(qp_num, wr) {
            Ok(()) => 0,
            Err(err) => {
                error!("Failed to post send WR: {err}");
                err.to_errno()
            }
        }
    }

    #[inline]
    fn post_recv(
        qp: *mut ibverbs_sys::ibv_qp,
        wr: *mut ibverbs_sys::ibv_recv_wr,
        bad_wr: *mut *mut ibverbs_sys::ibv_recv_wr,
    ) -> ::std::os::raw::c_int {
        let qp = deref_or_ret!(qp, libc::EINVAL);
        let wr = deref_or_ret!(wr, libc::EINVAL);
        let context = qp.context;
        let qp_num = qp.qp_num;
        let bluerdma = unsafe { get_device(context) };
        let wr = RecvWr::new(wr).unwrap_or_else(|| todo!("handle invalid input"));
        match bluerdma.post_recv(qp_num, wr) {
            Ok(()) => 0,
            Err(err) => {
                error!("Failed to post recv WR: {err}");
                err.to_errno()
            }
        }
    }

    #[allow(
        clippy::as_conversions,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap
    )]
    #[inline]
    fn poll_cq(
        cq: *mut ibverbs_sys::ibv_cq,
        num_entries: i32,
        wc: *mut ibverbs_sys::ibv_wc,
    ) -> i32 {
        let cq = deref_or_ret!(cq, 0);
        let bluerdma = get_device(cq.context);
        let completions = bluerdma.poll_cq(cq.handle, num_entries as usize);
        let num = completions.len() as i32;
        for (i, c) in completions.into_iter().enumerate() {
            if let Some(wc) = unsafe { wc.add(i).as_mut() } {
                match c {
                    Completion::Send { wr_id }
                    | Completion::RdmaWrite { wr_id }
                    | Completion::RdmaRead { wr_id } => {
                        wc.wr_id = wr_id;
                    }
                    Completion::Recv { wr_id, imm } => {
                        wc.wr_id = wr_id;
                        if let Some(imm) = imm {
                            wc.__bindgen_anon_1.imm_data = imm;
                        }
                    }
                    Completion::RecvRdmaWithImm { imm } => {
                        wc.__bindgen_anon_1.imm_data = imm;
                    }
                }
                wc.opcode = c.opcode();
                wc.status = ibverbs_sys::ibv_wc_status::IBV_WC_SUCCESS;
            }
        }

        num
    }
}

#[repr(C)]
struct BlueRdmaDevice {
    pad: [u8; 712],
    driver: *mut core::ffi::c_void,
    abi_version: core::ffi::c_int,
}

#[allow(unsafe_code)]
fn get_device(context: *mut ibverbs_sys::ibv_context) -> &'static mut dyn DeviceOps {
    let dev_ptr = unsafe { *context }.device.cast::<BlueRdmaDevice>();
    let driver_ptr = unsafe { (*dev_ptr).driver };
    unsafe {
        #[cfg(feature = "hw")]
        {
            driver_ptr.cast::<HwDeviceCtx<PciHwDevice>>().as_mut()
        }
        #[cfg(feature = "sim")]
        {
            driver_ptr.cast::<HwDeviceCtx<EmulatedHwDevice>>().as_mut()
        }
        #[cfg(feature = "mock")]
        {
            driver_ptr.cast::<MockDeviceCtx>().as_mut()
        }
    }
    .unwrap_or_else(|| unreachable!("null device pointer"))
}
