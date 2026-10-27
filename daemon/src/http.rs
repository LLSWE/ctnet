use std::{net::Ipv4Addr, sync::Arc};

use axum::{Json, Router, routing::post};
use aya::maps::HashMap;

use crate::{AppState, BlockIpReq};

pub async fn run_server(state: Arc<AppState>) -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/api/v1/block", post(block_ip_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    println!("Server is running on http://0.0.0.0:8080");
    Ok(axum::serve(listener, app).await?)
}

async fn block_ip_handler(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(payload): Json<BlockIpReq>,
) -> Result<&'static str, &'static str> {
    let ip: Ipv4Addr = payload.ip.parse().map_err(|_| "invalid ip")?;
    let ip_u32 = u32::from(ip);

    let mut bpf = state.bpf.lock().await;
    let mut blacklist: HashMap<_, u32, u8> =
        HashMap::try_from(bpf.map_mut("BLACKLIST").unwrap()).map_err(|_| "Erro ao ler Map")?;

    blacklist
        .insert(ip_u32, 1, 0)
        .map_err(|_| "Error to insert map")?;
    println!(" IP {} blocked by the api", ip);

    Ok("IP blocked successfully!")
}
