use bitvec::vec::BitVec;

use crate::constants::MAX_PD_CNT;

#[derive(Debug)]
pub(crate) struct PdTable {
    bitmap: BitVec<u32>,
}

impl PdTable {
    pub(crate) fn new() -> Self {
        let mut bitmap = BitVec::with_capacity(MAX_PD_CNT);
        bitmap.resize(MAX_PD_CNT, false);
        bitmap.set(0, true);
        Self { bitmap }
    }

    pub(crate) fn alloc(&mut self) -> Option<u32> {
        let index = self.bitmap.first_zero()? as u32;
        self.bitmap.set(index as usize, true);

        Some(index)
    }

    pub(crate) fn dealloc(&mut self, handle: u32) -> bool {
        let index = handle as usize;
        let ret = self.bitmap.get(index).is_some_and(|x| *x);
        self.bitmap.set(index, false);

        ret
    }
}

impl Default for PdTable {
    fn default() -> Self {
        Self::new()
    }
}
