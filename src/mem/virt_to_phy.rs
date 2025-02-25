#![allow(clippy::missing_docs_in_private_items)]

use std::{
    fs::File,
    io::{self, Read, Seek},
};

use super::{PAGE_SIZE, PAGE_SIZE_BITS};

/// Size of the PFN (Page Frame Number) mask in bytes
const PFN_MASK_SIZE: usize = 8;
/// PFN are bits 0-54 (see pagemap.txt in Linux Documentation)
const PFN_MASK: u64 = 0x007f_ffff_ffff_ffff;
/// Bit indicating if a page is present in memory
const PAGE_PRESENT_BIT: u8 = 63;

pub(crate) trait AddressResolver<const PAGE_SIZE_BITS: u8 = { super::PAGE_SIZE_BITS }> {
    /// Converts a list of virtual addresses to physical addresses
    ///
    /// # Returns
    ///
    /// A vector of optional physical addresses. `None` indicates
    /// the page is not present in physical memory.
    ///
    /// # Errors
    ///
    /// Returns an IO error if address resolving fails.
    fn virt_to_phys(&self, virt_addr: u64) -> io::Result<Option<u64>>;

    /// Converts a list of virtual addresses to physical addresses
    ///
    /// # Returns
    ///
    /// A vector of optional physical addresses. `None` indicates
    /// the page is not present in physical memory.
    ///
    /// # Errors
    ///
    /// Returns an IO error if address resolving fails.
    #[allow(clippy::as_conversions)]
    fn virt_to_phys_range(
        &self,
        start_addr: u64,
        num_pages: usize,
    ) -> io::Result<Vec<Option<u64>>> {
        (0..num_pages as u64)
            .map(|x| self.virt_to_phys(start_addr.saturating_add(x << PAGE_SIZE_BITS)))
            .collect::<Result<_, _>>()
    }
}

#[cfg(emulation)]
pub(crate) type PhysAddrResolver = PhysAddrResolverEmulated;
#[cfg(not(emulation))]
pub(crate) type PhysAddrResolver = PhysAddrResolverLinuxX86;

pub(crate) struct PhysAddrResolverLinuxX86;

#[allow(
    clippy::as_conversions,
    clippy::arithmetic_side_effects,
    clippy::host_endian_bytes
)]
impl AddressResolver<PAGE_SIZE_BITS> for PhysAddrResolverLinuxX86 {
    fn virt_to_phys(&self, virt_addr: u64) -> io::Result<Option<u64>> {
        let mut file = File::open("/proc/self/pagemap")?;
        let virt_pfn = virt_addr >> PAGE_SIZE_BITS;
        let offset = PFN_MASK_SIZE as u64 * virt_pfn;
        let _pos = file.seek(io::SeekFrom::Start(offset))?;
        let mut buf = [0u8; PFN_MASK_SIZE];
        file.read_exact(&mut buf)?;
        let entry = u64::from_ne_bytes(buf);
        if entry >> PAGE_PRESENT_BIT & 1 == 0 {
            return Ok(None);
        }
        let phy_pfn = entry & PFN_MASK;
        let phy_addr = (phy_pfn << PAGE_SIZE_BITS) + (virt_addr & (PAGE_SIZE as u64 - 1));
        Ok(Some(phy_addr))
    }

    fn virt_to_phys_range(
        &self,
        start_addr: u64,
        num_pages: usize,
    ) -> io::Result<Vec<Option<u64>>> {
        let mut phy_addrs = Vec::with_capacity(num_pages);
        let mut file = File::open("/proc/self/pagemap")?;
        let virt_pfn = start_addr >> PAGE_SIZE_BITS;
        let offset = PFN_MASK_SIZE as u64 * virt_pfn;
        let _pos = file.seek(io::SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; PFN_MASK_SIZE * num_pages];
        file.read_exact(&mut buf)?;
        for chunk in buf
            .chunks(PFN_MASK_SIZE)
            .flat_map(<[u8; PFN_MASK_SIZE]>::try_from)
        {
            let entry = u64::from_ne_bytes(chunk);
            if entry >> PAGE_PRESENT_BIT & 1 == 0 {
                phy_addrs.push(None);
                continue;
            }
            let phy_pfn = entry & PFN_MASK;
            let phy_addr = (phy_pfn << PAGE_SIZE_BITS) + (start_addr & (PAGE_SIZE as u64 - 1));
            phy_addrs.push(Some(phy_addr));
        }

        Ok(phy_addrs)
    }
}

pub(crate) struct PhysAddrResolverEmulated {
    heap_start_addr: u64,
}

impl PhysAddrResolverEmulated {
    pub(crate) fn new(heap_start_addr: u64) -> Self {
        Self { heap_start_addr }
    }
}

impl AddressResolver<PAGE_SIZE_BITS> for PhysAddrResolverEmulated {
    fn virt_to_phys(&self, virt_addr: u64) -> io::Result<Option<u64>> {
        Ok(virt_addr.checked_sub(self.heap_start_addr))
    }
}

/// Converts a list of virtual addresses to physical addresses
///
/// # Returns
///
/// A vector of optional physical addresses. `None` indicates
/// the page is not present in physical memory.
///
/// # Errors
///
/// Returns an IO error if reading from `/proc/self/pagemap` fails.
#[allow(
    clippy::as_conversions,
    clippy::arithmetic_side_effects,
    clippy::host_endian_bytes
)]
pub(crate) fn virt_to_phy<Vas>(virt_addrs: Vas) -> io::Result<Vec<Option<u64>>>
where
    Vas: IntoIterator<Item = u64>,
{
    let virt_addrs: Vec<_> = virt_addrs.into_iter().collect();
    let mut phy_addrs = Vec::with_capacity(virt_addrs.len());

    let mut file = File::open("/proc/self/pagemap")?;
    for virt_addr in virt_addrs {
        let virt_pfn = virt_addr >> PAGE_SIZE_BITS;
        let offset = PFN_MASK_SIZE as u64 * virt_pfn;
        let _pos = file.seek(io::SeekFrom::Start(offset))?;
        let mut buf = [0u8; PFN_MASK_SIZE];
        file.read_exact(&mut buf)?;
        let entry = u64::from_ne_bytes(buf);
        if entry >> PAGE_PRESENT_BIT & 1 == 0 {
            phy_addrs.push(None);
            continue;
        }
        let phy_pfn = entry & PFN_MASK;
        let phy_addr = (phy_pfn << PAGE_SIZE_BITS) + (virt_addr & (PAGE_SIZE as u64 - 1));
        phy_addrs.push(Some(phy_addr));
    }

    Ok(phy_addrs)
}

/// Converts a virtual address range to physical addresses
///
/// # Arguments
///
/// * `start_addr` - Starting virtual address to convert
/// * `num_pages` - Number of pages to convert starting from `start_addr`
///
/// # Returns
///
/// A vector of optional physical addresses. The length is equal to `num_pages`.
/// `None` indicates the page is not present in physical memory.
///
/// # Errors
///
/// Returns an IO error if reading from `/proc/self/pagemap` fails.
#[allow(
    clippy::as_conversions,
    clippy::arithmetic_side_effects,
    clippy::host_endian_bytes
)]
pub(crate) fn virt_to_phy_range(start_addr: u64, num_pages: usize) -> io::Result<Vec<Option<u64>>> {
    let mut phy_addrs = Vec::with_capacity(num_pages);
    let mut file = File::open("/proc/self/pagemap")?;
    let virt_pfn = start_addr >> PAGE_SIZE_BITS;
    let offset = PFN_MASK_SIZE as u64 * virt_pfn;
    let _pos = file.seek(io::SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; PFN_MASK_SIZE * num_pages];
    file.read_exact(&mut buf)?;
    for chunk in buf
        .chunks(PFN_MASK_SIZE)
        .flat_map(<[u8; PFN_MASK_SIZE]>::try_from)
    {
        let entry = u64::from_ne_bytes(chunk);
        if entry >> PAGE_PRESENT_BIT & 1 == 0 {
            phy_addrs.push(None);
            continue;
        }
        let phy_pfn = entry & PFN_MASK;
        let phy_addr = (phy_pfn << PAGE_SIZE_BITS) + (start_addr & (PAGE_SIZE as u64 - 1));
        phy_addrs.push(Some(phy_addr));
    }

    Ok(phy_addrs)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn virt_to_phy_ok() {
        let null = 0;
        let pas = virt_to_phy(Some(null)).expect("translation failed");
        assert!(pas[0].is_none());
        let a: Vec<_> = (0..0xff).collect();
        let pas = virt_to_phy(Some(a.as_ptr() as u64)).expect("translation failed");
        let ptr = a.as_ptr();
        assert!(pas[0].is_some());
    }

    #[test]
    fn virt_to_phy_range_ok() {
        let null = 0;
        let pas = virt_to_phy_range(null, 1).expect("translation failed");
        assert!(pas[0].is_none());
        let a: Vec<_> = (0..0xff).collect();
        let pas = virt_to_phy_range(a.as_ptr() as u64, 1).expect("translation failed");
        let ptr = a.as_ptr();
        assert!(pas[0].is_some());
    }
}
