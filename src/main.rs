mod auth;
mod chain;
mod config;
mod crypto;
mod error;
mod grpc;
mod init;
mod server;
mod tee;

use anyhow::{Context, Result};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kms=info".into()),
        )
        .init();

    let mut args = std::env::args().skip(1);
    let mut config_path = "kms.toml".to_string();
    let mut is_start_node = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--init" => is_start_node = true,
            _ => config_path = arg,
        }
    }

    let config = config::Config::load(&config_path)
        .with_context(|| format!("Failed to load config from {}", config_path))?;

    // Fetch signing key from tapp-server (or mock)
    let signing_key = tee::fetch_signing_key(&config.tapp)
        .await
        .context("Failed to fetch signing key")?;

    info!(
        eth_address = format!("0x{}", hex::encode(signing_key.eth_address)),
        is_start_node,
        "Node signing key loaded"
    );

    let state = server::AppState::new(config.clone(), signing_key);

    // Init: either generate shards (start node) or fetch shard from peers
    if is_start_node {
        init::init_start_node(&state)
            .await
            .context("Start node initialization failed")?;
    } else {
        init::join_cluster(&state)
            .await
            .context("Failed to join cluster")?;
    }

    let http_addr = config.server.bind.clone();
    let grpc_addr = config.server.grpc_bind.clone();

    let http_state = state.clone();
    let grpc_state = state.clone();

    let http = tokio::spawn(async move {
        let app = server::router(http_state);
        info!(bind = %http_addr, "HTTP server starting");
        let listener = tokio::net::TcpListener::bind(&http_addr)
            .await
            .expect("Failed to bind HTTP");
        axum::serve(listener, app).await.expect("HTTP server error");
    });

    let grpc = tokio::spawn(async move {
        let addr = grpc_addr.parse().expect("Invalid gRPC bind address");
        info!(bind = %grpc_addr, "gRPC server starting");
        tonic::transport::Server::builder()
            .add_service(grpc::service(grpc_state))
            .serve(addr)
            .await
            .expect("gRPC server error");
    });

    tokio::try_join!(http, grpc)?;
    Ok(())
}
