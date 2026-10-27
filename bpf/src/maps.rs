use aya_ebpf::{
    macros::map,
    maps::{LruHashMap, RingBuf},
};
use common::RateLimitValue;

#[map]
pub static RING_BUF: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
pub static RING_LIMITER: LruHashMap<u32, RateLimitValue> = LruHashMap::with_max_entries(10_000, 0);

#[map]
pub static BLACKLIST: LruHashMap<u32, u8> = LruHashMap::with_max_entries(10_000, 0);
