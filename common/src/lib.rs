#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub src_ip: u32,
    pub action: u32,
    pub action_reason: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RateLimitValue {
    pub last_seen_ns: u64,
    pub packet_count: u64,
}
