use aya::{
    Ebpf, include_bytes_aligned,
    maps::RingBuf,
    programs::{Xdp, XdpMode},
};
use clap::Parser;
use common::PacketLog;
use serde::Deserialize;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::http::run_server;

mod http;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value = "lo")]
    iface: String,
}

#[derive(Deserialize)]
struct BlockIpReq {
    ip: String,
}

pub struct AppState {
    pub bpf: Mutex<Ebpf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/libbpf.so"
    ))?;

    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/libbpf.so"
    ))?;

    let program: &mut Xdp = bpf.program_mut("ctnet_xdp").unwrap().try_into()?;
    program.load()?;
    program.attach(&args.iface, XdpMode::default())?;

    println!("ctnet online on interface: {}", args.iface);

    let map = bpf.take_map("RING_BUF").unwrap();
    let mut ring_buf = RingBuf::try_from(map)?;

    let state = Arc::new(AppState {
        bpf: Mutex::new(bpf),
    });

    tokio::spawn(async move {
        loop {
            while let Some(item) = ring_buf.next() {
                if item.len() >= std::mem::size_of::<PacketLog>() {
                    let log = unsafe { &*(item.as_ptr() as *const PacketLog) };
                    let ip = Ipv4Addr::from(log.src_ip);
                    println!("[XDP_DROP] IP: {} | Reason Code: {}", ip, log.action_reason);
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
    });

    run_server(state).await?;

    Ok(())
}
