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

    let config_path = std::env::args().nth(1).unwrap_or_else(|| "kms.toml".to_string());

    let config = config::Config::load(&config_path)
        .with_context(|| format!("Failed to load config from {}", config_path))?;

    let signing_key = tee::fetch_signing_key(&config.tapp)
        .await
        .context("Failed to fetch signing key")?;

    info!(
        eth_address = format!("0x{}", hex::encode(signing_key.eth_address)),
        bootstrap = config.cluster.bootstrap,
        self_url = %config.cluster.self_url,
        "Node signing key loaded"
    );

    let state = server::AppState::new(config.clone(), signing_key);

    // Bootstrap node: try to join first (handles restarts gracefully).
    // DISASTER GATE: only create a fresh master when NO peer is reachable (a genuine
    // first-ever cluster start). If a peer is reachable but couldn't serve our shard, the
    // cluster already exists — regenerating a master would fork it and lose every derived
    // key, so we refuse and stay down until we can recover the shard (Phase 4 reshare).
    // Non-bootstrap nodes always join and fail hard if they can't.
    use init::JoinResult;
    if config.cluster.bootstrap {
        match init::join_cluster(&state).await? {
            JoinResult::Joined => info!("Rejoined existing cluster"),
            JoinResult::NoSeedReachable => {
                info!("No existing cluster reachable — bootstrapping as first node");
                init::init_start_node(&state)
                    .await
                    .context("Bootstrap initialization failed")?;
            }
            JoinResult::SeedReachableDeclined => {
                anyhow::bail!(
                    "a cluster peer is reachable but could not serve our shard; refusing to \
                     regenerate a master (that would fork the cluster and lose all derived \
                     keys). This node stays down until it can recover its shard via reshare \
                     (Phase 4) or a peer serves it."
                );
            }
        }
    } else {
        match init::join_cluster(&state).await? {
            JoinResult::Joined => {}
            _ => anyhow::bail!("failed to join cluster: no seed served our shard"),
        }
    }

    // Start gossip background task (peer discovery + liveness)
    grpc::start_gossip_task(state.clone());

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
