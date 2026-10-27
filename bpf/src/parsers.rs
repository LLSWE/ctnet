use core::mem;

use aya_ebpf::programs::XdpContext;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

#[inline(always)]
pub unsafe fn parse_ipv4(ctx: &XdpContext) -> Result<*const Ipv4Hdr, ()> {
    let start = ctx.data() as usize;
    let end = ctx.data_end() as usize;

    if start + mem::size_of::<EthHdr>() > end {
        return Err(());
    }

    let eth_hdr = start as *const EthHdr;
    if (*eth_hdr).ether_type != EtherType::Ipv4 as u16 {
        return Err(());
    }

    let ip_start = start + mem::size_of::<EthHdr>();
    if ip_start + mem::size_of::<Ipv4Hdr>() > end {
        return Err(());
    }

    Ok(ip_start as *const Ipv4Hdr)
}
