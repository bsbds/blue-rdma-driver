use std::{ffi::c_void, io, marker::PhantomData, sync::Arc};

use std::ops::{Deref, DerefMut};

use std::arch::x86_64::{_mm_clflush, _mm_mfence};

use crate::mem::{PAGE_SIZE, PAGE_SIZE_BITS};

use super::{ContiguousPages, MmapMut, PageAllocator};

/// A page allocator for allocating pages of host memory
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct HostPageAllocator<const N: usize>;

impl<const N: usize> PageAllocator<N> for HostPageAllocator<N> {
    fn alloc(&mut self) -> io::Result<ContiguousPages<N>> {
        let inner = Self::try_reserve_consecutive(N)?;
        Ok(ContiguousPages { inner })
    }
}

#[allow(unsafe_code)]
impl<const N: usize> HostPageAllocator<N> {
    /// TODO: implements allocating multiple consecutive pages
    const _OK: () = assert!(
        N == 1,
        "allocating multiple contiguous pages is currently unsupported"
    );

    /// Creates a new `HostPageAllocator`
    pub(crate) fn new() -> Self {
        Self
    }

    /// Attempts to reserve consecutive physical memory pages.
    fn try_reserve_consecutive(num_pages: usize) -> io::Result<MmapMut> {
        let mmap = Self::reserve(num_pages)?;
        if Self::ensure_consecutive(&mmap)? {
            return Ok(mmap);
        }

        Err(io::Error::from(io::ErrorKind::OutOfMemory))
    }

    /// Reserves memory pages using mmap.
    fn reserve(num_pages: usize) -> io::Result<MmapMut> {
        /// Number of bits representing a 4K page size
        const PAGE_SIZE_2M: usize = 1 << 21;
        let len = PAGE_SIZE_2M
            .checked_mul(num_pages)
            .ok_or(io::Error::from(io::ErrorKind::Unsupported))?;
        #[cfg(feature = "page_size_2m")]
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON | libc::MAP_HUGETLB | libc::MAP_HUGE_2MB,
                -1,
                0,
            )
        };
        #[cfg(feature = "page_size_4k")]
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        for i in 0..len {
            unsafe {
                *ptr.cast::<u8>().add(i) = 0;
            }
        }

        unsafe {
            if libc::mlock(ptr, len) != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(MmapMut::new(ptr, len))
    }

    /// Checks if the physical pages backing the memory mapping are consecutive.
    #[allow(clippy::unnecessary_wraps)] // casting usize ot u64 is safe
    fn ensure_consecutive(mmap: &MmapMut) -> io::Result<bool> {
        // TODO: implement
        Ok(true)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn consc_mem_alloc_succ() {
        let mem = HostPageAllocator::<1>::new()
            .alloc()
            .expect("failed to allocate");
    }
}
