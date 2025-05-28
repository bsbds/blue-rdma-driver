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

use crate::mem::{
    page::{ContiguousPages, HostPageAllocator, PageAllocator},
    slot_alloc::{RcSlot, SlotAlloc, SlotSize},
    virt_to_phy::{AddressResolver, PhysAddrResolverLinuxX86},
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
