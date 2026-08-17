mod auth;
mod chain;
mod config;
mod crypto;
mod dkg;
mod error;
mod grpc;
mod init;
mod metrics;
mod seal;
mod server;
mod tee;

use anyhow::{Context, Result};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // `KMS_LOG_FORMAT=json` emits one JSON object per event, so a log collector can index the
    // structured fields the service record carries (app_id, servers, epoch, duration_ms) instead
    // of reducing them to a string. Left unset the output stays human-readable, which is what
    // the runbooks and the local test harness grep against. Colour follows the terminal, so
    // captured output is never littered with escape codes either way.
    let builder = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kms=info".into()),
        )
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()));
    match std::env::var("KMS_LOG_FORMAT").as_deref() {
        Ok("json") => builder.json().flatten_event(true).init(),
        _ => builder.init(),
    }

    // Initialize here so kms_uptime_seconds is measured from boot, not from the first scrape.
    metrics::m();

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

    // Start gossip so nodes discover each other, then form the cluster key in the background:
    // distributed genesis DKG (fresh cluster) or reshare recovery (established cluster). This
    // needs the gRPC server up (nodes exchange DkgRound messages) and gossip converged, so it
    // runs AFTER the servers start — `state.shard` stays None (and /app-key returns not-ready)
    // until formation completes. The disaster gate lives in form_cluster: an established
    // cluster never triggers genesis, so a restarted node can't silently mint a new master.
    grpc::start_gossip_task(state.clone());
    tokio::spawn(init::form_cluster(state.clone()));

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
