#![no_main]
#![no_std]

mod filters;
mod maps;
mod parsers;

use aya_ebpf::{
    bindings::xdp_action, helpers::generated::bpf_ktime_get_ns, macros::xdp, programs::XdpContext,
};
use common::{PacketLog, RateLimitValue};

use crate::{
    maps::{BLACKLIST, RING_BUF, RING_LIMITER},
    parsers::parse_ipv4,
};

const MAX_PPS: u64 = 10_000;
const ONE_SEC_NS: u64 = 1_000_000_000;

#[xdp]
pub fn ctnet_xdp(ctx: XdpContext) -> u32 {
    match unsafe { process_packet(&ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn process_packet(ctx: &XdpContext) -> Result<u32, ()> {
    let ipv4_hdr = parse_ipv4(ctx)?;
    let src_ip: u32 = u32::from_be_bytes((*ipv4_hdr).src_addr);

    if BLACKLIST.get(&src_ip).is_some() {
        emit_log(ctx, src_ip, xdp_action::XDP_DROP, 1);
        return Ok(xdp_action::XDP_DROP);
    }

    let now = bpf_ktime_get_ns();
    if let Some(entry) = RING_LIMITER.get_ptr_mut(&src_ip) {
        if now - (*entry).last_seen_ns < ONE_SEC_NS {
            (*entry).packet_count += 1;
            if (*entry).packet_count > MAX_PPS {
                emit_log(ctx, src_ip, xdp_action::XDP_DROP, 2);
                return Ok(xdp_action::XDP_DROP);
            }
        } else {
            (*entry).last_seen_ns = now;
            (*entry).packet_count = 1;
        }
    } else {
        let new_entry = RateLimitValue {
            last_seen_ns: now,
            packet_count: 1,
        };
        let _ = RING_LIMITER.insert(&src_ip, &new_entry, 0);
    }
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn emit_log(ctx: &XdpContext, src_ip: u32, action: u32, reason: u32) {
    if let Some(mut entry) = RING_BUF.reserve::<PacketLog>(0) {
        let log = entry.as_mut_ptr();
        unsafe {
            (*log).src_ip = src_ip;
            (*log).action = action;
            (*log).action_reason = reason;
        }
        entry.submit(0);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
