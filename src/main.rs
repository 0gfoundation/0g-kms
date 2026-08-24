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
use tracing_subscriber::fmt::writer::{BoxMakeWriter, MakeWriterExt};

/// Days of log files kept on disk when `KMS_LOG_DIR` is set.
///
/// The node's own log is the fallback for when the collector or the log store is down, so it is
/// worth keeping a week — but it is a hard cap, not a suggestion. On a KMS host the log directory
/// shares the persistent disk with the sealed share, and a log that grows without bound would
/// eventually stop that share from being written, which costs the cluster a recovery slot on the
/// next restart. `kms_share_path_writable` would catch it, but not before the damage.
const LOG_FILES_KEPT: usize = 7;

/// Set up tracing, returning the writer guard the caller must keep alive.
///
/// Two knobs, both env vars so they can be set from a compose file without touching the config:
///
///   * `KMS_LOG_FORMAT=json` — one JSON object per event, so a collector can index the fields the
///     service record carries (app_id, servers, epoch, duration_ms) instead of flattening them
///     into a string. Unset keeps the human-readable format the runbooks grep against.
///   * `KMS_LOG_DIR=<dir>`  — additionally write daily-rotating files there, capped at
///     `LOG_FILES_KEPT`. stdout always keeps getting everything, so `get-app-logs` is unaffected.
///     This exists because a log shipper cannot read another container's stdout; giving it a file
///     on a shared volume avoids handing it the host's docker socket, which would be a far larger
///     grant than reading one log.
fn init_logging() -> Result<Option<tracing_appender::non_blocking::WorkerGuard>> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "kms=info".into());

    let (writer, guard) = match std::env::var("KMS_LOG_DIR") {
        Ok(dir) if !dir.trim().is_empty() => {
            let appender = tracing_appender::rolling::Builder::new()
                .rotation(tracing_appender::rolling::Rotation::DAILY)
                .filename_prefix("kms")
                .filename_suffix("log")
                .max_log_files(LOG_FILES_KEPT)
                .build(dir.trim())
                .with_context(|| format!("cannot open log directory {}", dir.trim()))?;
            // Non-blocking: a slow or full disk must never stall a derive.
            let (nb, guard) = tracing_appender::non_blocking(appender);
            (BoxMakeWriter::new(std::io::stdout.and(nb)), Some(guard))
        }
        _ => (BoxMakeWriter::new(std::io::stdout), None),
    };

    // Colour follows the terminal, and is off entirely once a file is involved — escape codes in
    // a captured log break every downstream parser.
    let ansi = guard.is_none() && std::io::IsTerminal::is_terminal(&std::io::stdout());
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(ansi)
        .with_writer(writer);
    match std::env::var("KMS_LOG_FORMAT").as_deref() {
        Ok("json") => builder.json().flatten_event(true).init(),
        _ => builder.init(),
    }
    Ok(guard)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Held for the lifetime of the process: dropping it flushes the background writer, and
    // dropping it early would silently lose buffered lines.
    let _log_guard = init_logging()?;

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

#[cfg(test)]
mod log_tests {
    /// The retention cap is the only thing standing between an unattended node and a log that
    /// fills the disk the sealed share lives on, so pin it rather than leaving it to a constant
    /// nobody re-reads.
    #[test]
    fn retention_is_capped() {
        assert!(super::LOG_FILES_KEPT > 0 && super::LOG_FILES_KEPT <= 14);
    }

    /// `KMS_LOG_DIR` pointing somewhere unusable must fail loudly at boot rather than starting a
    /// node whose logs silently go nowhere.
    ///
    /// Note the appender *creates* a missing directory, which is deliberate but has a sharp edge:
    /// if the volume failed to mount, the logs land on the container's RAM rootfs instead — they
    /// vanish on restart and the shipper never sees them. The visible symptom is an empty log
    /// store, not an error here.
    #[test]
    fn unusable_log_dir_is_an_error() {
        let r = tracing_appender::rolling::Builder::new()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix("kms")
            .filename_suffix("log")
            .max_log_files(super::LOG_FILES_KEPT)
            // Parent is a regular file → ENOTDIR, which root cannot work around either.
            .build("/etc/hostname/kms-logs");
        assert!(r.is_err());
    }
}
