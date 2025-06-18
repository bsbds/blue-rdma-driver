/// Maximum number of bits used to represent a PSN.
pub(crate) const MAX_PSN_SIZE_BITS: usize = 24;
/// Maximum size of the PSN window. This represents the maximum number outstanding PSNs.
pub(crate) const MAX_PSN_WINDOW: usize = 1 << (MAX_PSN_SIZE_BITS - 1);
/// Bit mask used to extract the PSN value from a 32-bit number.
pub(crate) const PSN_MASK: u32 = (1 << MAX_PSN_SIZE_BITS) - 1;

/// Maximum number of bits used to represent a MSN.
pub(crate) const MAX_MSN_SIZE_BITS: usize = 16;
/// Maximum size of the PSN window. This represents the maximum number outstanding PSNs.
pub(crate) const MAX_MSN_WINDOW: usize = 1 << (MAX_MSN_SIZE_BITS - 1);

pub(crate) const MAX_QP_CNT: usize = 1024;
pub(crate) const QPN_KEY_PART_WIDTH: u32 = 8;
pub(crate) const QPN_IDX_PART_WIDTH: u32 = 32 - QPN_KEY_PART_WIDTH;

pub(crate) const MAX_CQ_CNT: usize = 1024;

/// Maximum number of outstanding send work requests (WRs) that can be posted to a Queue Pair (QP).
pub(crate) const MAX_SEND_WR: usize = 0x8000;

pub(crate) const TEST_CARD_IP_ADDRESS: u32 = 0x1122_330A;

// TODO: implement ARP MAC resolution
pub(crate) const CARD_MAC_ADDRESS: u64 = 0xAABB_CCDD_EE0A;
pub(crate) const CARD_MAC_ADDRESS_OCTETS: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x0A];
