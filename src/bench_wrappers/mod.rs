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

pub mod descs;

use std::io;

use crate::{
    mem::{
        page::{ContiguousPages, HostPageAllocator, PageAllocator},
        slot_alloc::{RcSlot, SlotAlloc, SlotSize},
        virt_to_phy::{AddressResolver, PhysAddrResolverLinuxX86},
    },
    ringbuffer::{DescBuffer, Descriptor, RingBuffer, RingCtx, Syncable, RING_BUF_LEN},
};

#[inline]
pub fn virt_to_phy_bench_wrapper<Vas>(virt_addrs: Vas) -> io::Result<Vec<Option<u64>>>
where
    Vas: IntoIterator<Item = *const u8>,
{
    let resolver = PhysAddrResolverLinuxX86;
    virt_addrs
        .into_iter()
        .map(|va| resolver.virt_to_phys(va as u64))
        .collect()
}

#[inline]
pub fn virt_to_phy_bench_range_wrapper(
    start_addr: *const u8,
    num_pages: usize,
) -> io::Result<Vec<Option<u64>>> {
    let resolver = PhysAddrResolverLinuxX86;
    resolver.virt_to_phys_range(start_addr as u64, num_pages)
}

#[derive(Debug, Clone, Copy)]
pub struct BenchDesc {
    inner: [u8; 32],
}

impl BenchDesc {
    pub fn new(data: [u8; 32]) -> Self {
        Self { inner: data }
    }
}

impl Descriptor for BenchDesc {
    const SIZE: usize = 24;

    fn take_valid(&mut self) -> bool {
        let _valid = self.inner[0] == 1;
        self.inner[0] = 0;
        // ignore the valid bit for benchmark
        true
    }
}

type BenchBuf = RcSlot<ContiguousPages<1>, BenchSlotSize>;

impl Syncable for BenchBuf {
    fn sync(&self) {}
}

impl DescBuffer<BenchDesc> for BenchBuf {}

pub struct RingWrapper {
    inner: RingBuffer<BenchBuf, BenchDesc>,
}

impl RingWrapper {
    pub fn force_produce(&mut self, desc: BenchDesc) {
        self.inner.force_push(desc);
    }

    pub fn produce(&mut self, desc: BenchDesc) {
        self.inner.push(desc).unwrap();
    }

    pub fn consume(&mut self) -> Option<BenchDesc> {
        self.inner.try_pop()
    }
}

struct BenchSlotSize;

impl SlotSize for BenchSlotSize {
    fn size() -> usize {
        BenchDesc::SIZE * RING_BUF_LEN as usize
    }
}

#[allow(unsafe_code)]
impl AsMut<[BenchDesc]> for BenchBuf {
    fn as_mut(&mut self) -> &mut [BenchDesc] {
        unsafe { std::mem::transmute(AsMut::<[u8]>::as_mut(self)) }
    }
}

pub fn create_ring_wrapper() -> RingWrapper {
    let mut allocator = HostPageAllocator::<1>::new();
    let mem = allocator.alloc().unwrap();
    let mut alloc = SlotAlloc::<_, BenchSlotSize>::new(mem);
    let slot = alloc.alloc_one().unwrap();
    let ring_ctx = RingCtx::new();
    let ring = RingBuffer::<_, BenchDesc>::new(ring_ctx, slot).unwrap();
    RingWrapper { inner: ring }
}
