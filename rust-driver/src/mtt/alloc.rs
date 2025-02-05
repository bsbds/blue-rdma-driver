use bitvec::{array::BitArray, bitarr};
use rand::Rng;

const MAX_MR_CNT: usize = 8192;
const LR_KEY_IDX_PART_WIDTH: u32 = 13;
const LR_KEY_KEY_PART_WIDTH: u32 = 32 - LR_KEY_IDX_PART_WIDTH;
/// Maximum number of entries in the secodn stage table
pub(super) const PGT_LEN: usize = 0x20000;

/// Table memory allocator for MTT
pub(crate) struct Alloc {
    /// First stage table allocator
    mr: MrTableAlloc,
    /// Second stage table allocator
    pgt: PgtAlloc,
}

impl Alloc {
    /// Creates a new allocator instance
    pub(super) fn new() -> Self {
        Self {
            mr: MrTableAlloc::new(),
            pgt: PgtAlloc::new(),
        }
    }

    /// Allocates memory region and page table entries
    ///
    /// # Returns
    ///
    /// * `Some((mr_key, page_index))`
    /// * `None` - If allocation fails
    pub(super) fn alloc(&mut self, num_pages: usize) -> Option<(u32, usize)> {
        let mr_key_idx = self.mr.alloc_mr_key_idx()?;
        let key = rand::thread_rng().gen_range(0..1 << LR_KEY_KEY_PART_WIDTH);
        let mr_key = mr_key_idx.0 << LR_KEY_KEY_PART_WIDTH | key;
        let index = self.pgt.alloc(num_pages)?;
        Some((mr_key, index))
    }

    /// Deallocates memory region and page table entries
    ///
    /// # Returns
    ///
    /// `true` if deallocation is successful, `false` otherwise
    #[allow(clippy::as_conversions)]
    pub(super) fn dealloc(&mut self, mr_key: u32, mr_index: usize, length: usize) -> bool {
        let mr_key_idx = mr_key >> LR_KEY_KEY_PART_WIDTH;
        self.mr.dealloc_mr_key(MrKeyIndex(mr_key_idx));
        self.pgt.dealloc(mr_index, length)
    }
}

/// Memory region key
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct MrKeyIndex(u32);

/// First stage table allocator
///
/// Manages allocation and deallocation of memory region keys from a free list.
pub(super) struct MrTableAlloc {
    /// List of available memory region keys that can be allocated
    free_list: Vec<MrKeyIndex>,
}

impl MrTableAlloc {
    /// Creates a new `MrTableAlloc` instance with a pre-filled free list
    pub(super) fn new() -> Self {
        Self {
            free_list: Self::fill_up_free_list(),
        }
    }

    /// Allocates a new memory region key from the free list
    ///
    /// # Returns
    ///
    /// Returns None if the table is full
    pub(super) fn alloc_mr_key_idx(&mut self) -> Option<MrKeyIndex> {
        self.free_list.pop()
    }

    /// Returns a memory region key back to the free list
    pub(super) fn dealloc_mr_key(&mut self, key: MrKeyIndex) {
        self.free_list.push(key);
    }

    /// Creates initial free list containing all possible memory region keys
    fn fill_up_free_list() -> Vec<MrKeyIndex> {
        (0..u32::try_from(MAX_MR_CNT).unwrap_or_else(|_| unreachable!("invalid  MAX_MR_CNT")))
            .map(MrKeyIndex)
            .collect()
    }
}

/// A simple page table allocator that uses a bit array to track free/used entries
pub(crate) struct PgtAlloc {
    /// Bit array tracking which entries are free `false` or used `true`
    free_list: BitArray<[usize; PGT_LEN / 64]>,
}

impl PgtAlloc {
    /// Creates a new empty `SimplePgtAlloc` with all entries marked as free
    pub(crate) fn new() -> Self {
        Self {
            free_list: bitarr![0; PGT_LEN],
        }
    }

    /// Allocates a contiguous range of page table entries
    ///
    /// # Arguments
    ///
    /// * `len` - Number of contiguous entries to allocate
    ///
    /// # Returns
    ///
    /// * `Some(index)` - Starting index of allocated range if successful
    /// * `None` - If allocation failed
    #[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)] // should never overflow
    fn alloc(&mut self, len: usize) -> Option<usize> {
        let mut count = 0;
        let mut start = 0;

        for i in 0..self.free_list.len() {
            if self.free_list[i] {
                count = 0;
            } else {
                if count == 0 {
                    start = i;
                }
                count += 1;
                if count == len {
                    self.free_list[start..start + len].fill(true);
                    return Some(start);
                }
            }
        }
        None
    }

    /// Deallocates a previously allocated range of page table entries
    ///
    /// # Arguments
    ///
    /// * `index` - Starting index of range to deallocate
    /// * `len` - Number of entries to deallocate
    ///
    /// # Returns
    ///
    /// * `true` - If deallocation was successful
    /// * `false` - If deallocation failed (e.g. invalid range)
    // TODO: track the size of allocated range and check in dealloc
    fn dealloc(&mut self, index: usize, len: usize) -> bool {
        let Some(end) = index.checked_add(len) else {
            return false;
        };
        if let Some(slice) = self.free_list.get_mut(index..end) {
            slice.fill(false);
            return true;
        }
        false
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn mr_table_alloc_dealloc_ok() {
        let mut alloc = MrTableAlloc::new();
        let mr_keys: Vec<_> = std::iter::repeat_with(|| alloc.alloc_mr_key_idx())
            .take(MAX_MR_CNT)
            .flatten()
            .collect();
        assert_eq!(mr_keys.len(), MAX_MR_CNT);
        assert!(alloc.alloc_mr_key_idx().is_none());
        alloc.dealloc_mr_key(mr_keys[0]);
        alloc.alloc_mr_key_idx().unwrap();
    }

    #[test]
    fn simple_pgt_alloc_dealloc_ok() {
        let mut alloc = PgtAlloc::new();
        let index = alloc.alloc(10).unwrap();
        assert!(alloc.alloc(PGT_LEN).is_none());
        assert!(alloc.dealloc(index, 10));
        alloc.alloc(PGT_LEN).unwrap();
    }
}
