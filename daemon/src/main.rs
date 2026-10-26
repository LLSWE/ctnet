use axum::{Json, Router, routing::post};
use aya::{
    Bpf, Ebpf, include_bytes_aligned,
    maps::{LruHashMap, RingBuf},
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
use common::PacketLog;
use serde::Deserialize;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value = "lo")]
    iface: String,
}

#[derive(Deserialize)]
struct BlockIpReq {
    ip: String,
}

struct AppState {
    bpf: Mutex<Ebpf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/ctnet-ebpf"
    ))?;

    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ctnet-ebpf"
    ))?;

    let program: &mut Xdp = bpf.program_mut("ctnet_xdp").unwrap().try_into()?;
    program.load()?;
    program.attach(&args.iface, XdpFlags::default())?;

    println!("⚡ ctnet ativo na interface: {}", args.iface);

    let ring_buf = RingBuf::try_from(bpf.map_mut("RING_BUF").unwrap())?;
    tokio::spawn(async move {
        let mut buf = ring_buf;
        loop {
            while let Some(item) = buf.next() {
                if item.len() >= std::mem::size_of::<PacketLog>() {
                    let log = unsafe { &*(item.as_ptr() as *const PacketLog) };
                    let ip = Ipv4Addr::from(log.src_ip);
                    println!("[XDP_DROP] IP: {} | Motivo Code: {}", ip, log.action_reason);
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
    });

    let state = Arc::new(AppState {
        bpf: Mutex::new(bpf),
    });

    let app = Router::new()
        .route("/api/v1/block", post(block_ip_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.網絡:8080").await?;
    println!("🚀 Server de controle rodando em http://0.0.0.0:8080");
    axum::serve(listener, app).await?;

    Ok(())
}

async fn block_ip_handler(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(payload): Json<BlockIpReq>,
) -> Result<&'static str, &'static str> {
    let ip: Ipv4Addr = payload.ip.parse().map_err(|_| "IP inválido")?;
    let ip_u32 = u32::from(ip);

    let mut bpf = state.bpf.lock().await;
    let mut blacklist: LruHashMap<_, u32, u8> =
        LruHashMap::try_from(bpf.map_mut("BLACKLIST").unwrap()).map_err(|_| "Erro ao ler Map")?;

    blacklist
        .insert(ip_u32, 1, 0)
        .map_err(|_| "Erro ao inserir no Map")?;
    println!(" IP {} bloqueado via API REST!", ip);

    Ok("IP Bloqueado com Sucesso")
}
