use std::collections::HashMap;
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use ethers::types::Address;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use tokio::sync::RwLock;

use crate::{
    chain::get_signer_addresses,
    config::Config,
    crypto::ecies_encrypt,
    error::KmsError,
    grpc::collect_and_dprf,
    tee::NodeKey,
};

// ─── Peer table ───────────────────────────────────────────────────────────────

/// A peer counts as LIVE only on direct evidence within this window: it pushed gossip to us,
/// or we successfully pushed to it. Relayed gossip NEVER refreshes liveness (otherwise a mesh
/// keeps re-advertising a dead node's entry and it looks perpetually alive). Gossip runs every
/// 30s, so 90s = three missed rounds.
pub const PEER_LIVENESS_WINDOW_SECS: i64 = 90;

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub grpc_url: String,
    /// Unix seconds of the last DIRECT contact with this peer (it pushed gossip to us, or our
    /// push to it succeeded). 0 = known only via relay, never directly seen. Relayed entries
    /// must not touch this — "known" and "alive" are different things.
    pub last_seen: i64,
    /// Uncompressed secp256k1 pubkey (65 bytes), learned via gossip. Empty until known;
    /// needed to ECIES-encrypt DKG round-1 p2p shares to this peer.
    pub pubkey: Vec<u8>,
    /// Peer's current polynomial epoch, learned via gossip (0 = no share yet). Used to agree
    /// on the cluster epoch so a reshare picks a monotonically increasing next epoch.
    /// (Kept even when the peer is not live — epoch knowledge is monotonic.)
    pub epoch: u64,
    /// Peer's view of the group public key, learned via gossip. Empty = not reported (no share
    /// yet, or a node predating the gossip field). MONITORING ONLY: it is never an input to a
    /// decision, only compared against ours, so that a single node can detect a forked master
    /// instead of an operator diffing logs across every host.
    pub group_pubkey: Vec<u8>,
}

impl PeerInfo {
    /// Direct evidence of life within the liveness window.
    pub fn is_live(&self, now: i64) -> bool {
        now - self.last_seen <= PEER_LIVENESS_WINDOW_SECS
    }
}

// ─── Shared state ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ShardState {
    pub shard_index: u32,
    pub shard_bytes: Vec<u8>,
    /// Polynomial epoch this share belongs to. Genesis = 1; every reshare/refresh/recovery
    /// bumps it. Partials are tagged with this so the coordinator never Lagrange-combines
    /// shares from two different polynomials (which would yield a wrong key).
    pub epoch: u64,
}

/// Inbound round messages for one DKG/reshare session, buffered until the driver consumes
/// them. `rounds[round][from_index] = (broadcast_bytes, decrypted_p2p_bytes)`. The `notify`
/// wakes the session driver each time a new round message arrives so it can re-check its
/// per-round barrier.
#[derive(Default)]
pub struct DkgSession {
    pub rounds: HashMap<u32, HashMap<u32, (Vec<u8>, Vec<u8>)>>,
    pub notify: Arc<tokio::sync::Notify>,
}

impl DkgSession {
    /// Store a received round message and wake any waiting driver.
    pub fn record(&mut self, round: u32, from_index: u32, broadcast: Vec<u8>, p2p: Vec<u8>) {
        self.rounds
            .entry(round)
            .or_default()
            .insert(from_index, (broadcast, p2p));
        self.notify.notify_waiters();
    }
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub signing_key: Arc<NodeKey>,
    /// Own shard — None until init/recovery completes.
    pub shard: Arc<RwLock<Option<ShardState>>>,
    /// Start-node only: all N shards held temporarily until all peers collect theirs.
    pub pending_shards: Arc<RwLock<Option<Vec<(u32, Vec<u8>)>>>>,
    /// Dynamic peer table maintained by gossip: eth_addr → PeerInfo.
    pub peer_table: Arc<RwLock<HashMap<[u8; 20], PeerInfo>>>,
    /// In-flight DKG/reshare sessions: session_id → buffered inbound round messages.
    pub dkg_sessions: Arc<RwLock<HashMap<String, DkgSession>>>,
    /// The cluster's group public key (G1), set after genesis DKG. Serves as the
    /// "genesis has happened" witness and is checked when recovering a share via reshare.
    pub group_pubkey: Arc<RwLock<Option<Vec<u8>>>>,
    /// Latest sealed share (base64url), refreshed on every share change. Exposed via
    /// GET /sealed-share so the deploy pipeline can fetch it without grepping logs. It is
    /// ECIES ciphertext to this node's own TEE key — safe to expose, same as logging it.
    pub sealed_share: Arc<RwLock<Option<String>>>,
}

impl AppState {
    pub fn new(config: Config, signing_key: NodeKey) -> Self {
        Self {
            config: Arc::new(config),
            signing_key: Arc::new(signing_key),
            shard: Arc::new(RwLock::new(None)),
            pending_shards: Arc::new(RwLock::new(None)),
            peer_table: Arc::new(RwLock::new(HashMap::new())),
            dkg_sessions: Arc::new(RwLock::new(HashMap::new())),
            group_pubkey: Arc::new(RwLock::new(None)),
            sealed_share: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn is_initialized(&self) -> bool {
        self.shard.read().await.is_some()
    }

    /// Highest polynomial epoch this node currently knows about: its own share's epoch and
    /// every peer epoch learned via gossip. The cluster's live epoch is the max any member
    /// holds; a fresh cluster (no shares anywhere) is 0.
    pub async fn known_epoch(&self) -> u64 {
        let own = self.shard.read().await.as_ref().map(|s| s.epoch).unwrap_or(0);
        let peer_max = self
            .peer_table
            .read()
            .await
            .values()
            .map(|p| p.epoch)
            .max()
            .unwrap_or(0);
        own.max(peer_max)
    }

    /// Snapshot of current peer gRPC URLs from the dynamic peer table.
    /// Deduplicated by URL: two eth_addrs can legitimately map to the same URL
    /// during key rotation / rebuild windows, but we must not query the same
    /// endpoint twice — it would produce duplicate shards.
    pub async fn peer_urls(&self) -> Vec<String> {
        let mut urls: Vec<String> = self
            .peer_table
            .read()
            .await
            .values()
            .map(|p| p.grpc_url.clone())
            .collect();
        urls.sort();
        urls.dedup();
        urls
    }
}

// ─── HTTP /app-key handler ────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AppKeyRequest {
    pub app_id: String,
    pub timestamp: i64,
    /// hex-encoded secp256k1 public key (65 bytes, uncompressed) for ECIES encryption
    pub pubkey: String,
    /// hex-encoded recoverable secp256k1 signature over "GetSecretResource:{timestamp}"
    pub signature: String,
    /// hex-encoded derivation material, bound into the derived key alongside `app_id`
    /// (opaque to the KMS; for AgenticID = chainId ‖ contractAddress ‖ sealId).
    /// Optional — absent/empty derives purely from the `app_id` namespace.
    #[serde(default)]
    pub material: String,
}

#[derive(Serialize)]
pub struct AppKeyResponse {
    pub encrypted_secret: String, // hex-encoded ECIES ciphertext
}

pub async fn handle_app_key(
    State(state): State<AppState>,
    Json(req): Json<AppKeyRequest>,
) -> Result<impl IntoResponse, KmsError> {
    let app_id = req.app_id.clone();
    let started = std::time::Instant::now();
    let r = app_key_inner(&state, req).await;
    let duration_ms = started.elapsed().as_millis() as u64;

    // One classification, used for both the counter and the log line, so the two can never tell
    // different stories. The four buckets exist because they need different responses:
    //   unauthorized — the caller is not entitled to this key; nothing to fix here
    //   bad_request  — the caller sent malformed input; the service behaved correctly
    //   not_ready    — this node holds no share yet; it will fix itself, or it is stuck
    //   error        — genuinely ours, and the only one worth paging on
    let mt = crate::metrics::m();
    let (counter, result) = match &r {
        Ok(_) => (&mt.appkey_ok, "ok"),
        Err(KmsError::InvalidTimestamp(_))
        | Err(KmsError::InvalidSignature(_))
        | Err(KmsError::AppNotFound(_)) => (&mt.appkey_unauthorized, "unauthorized"),
        Err(KmsError::BadRequest(_)) => (&mt.appkey_bad_request, "bad_request"),
        Err(KmsError::ConfigError(_)) => (&mt.appkey_not_ready, "not_ready"),
        Err(_) => (&mt.appkey_error, "error"),
    };
    crate::metrics::inc(counter);

    // Failures are logged too. Recording only successes leaves exactly the case an operator
    // needs during an incident — "which field was malformed?" — with nothing to look at; the
    // metric says a request failed, and the log is the only thing that can say why.
    match &r {
        Ok((_, trace)) => tracing::info!(
            app_id = %app_id,
            result,
            coordinator = trace.coordinator,
            epoch = trace.epoch,
            // Comma-separated rather than Debug-formatted: `1,3` survives a log pipeline as a
            // plain string a query can match on, where `[1, 3]` would not.
            servers = %trace.servers.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(","),
            server_count = trace.servers.len(),
            duration_ms,
            "app-key issued"
        ),
        // The message is what the caller already received, so logging it leaks nothing new.
        Err(e) => tracing::warn!(
            app_id = %app_id,
            result,
            error = %e,
            duration_ms,
            "app-key failed"
        ),
    }

    r.map(|(resp, _)| resp)
}

/// The derive itself. Returns the response together with the trace of who served it, so the
/// caller can log success and failure through one path.
async fn app_key_inner(
    state: &AppState,
    req: AppKeyRequest,
) -> Result<(impl IntoResponse, crate::grpc::DeriveTrace), KmsError> {
    // 1. Validate timestamp
    let now = chrono::Utc::now().timestamp();
    if (now - req.timestamp).abs() > state.config.server.timestamp_tolerance_secs {
        return Err(KmsError::InvalidTimestamp(format!(
            "timestamp {} is too far from now ({})",
            req.timestamp, now
        )));
    }

    // 2. Verify signature (EIP-191 personal_sign): recover eth address,
    //    check against on-chain signer list.
    //    Signed payload: "\x19Ethereum Signed Message:\n{len}" + "GetSecretResource:{ts}"
    //    hashed with Keccak-256. Compatible with wallet.signMessage / personal_sign.
    let message = format!("GetSecretResource:{}", req.timestamp);
    let recovered_addr = recover_eip191_address(&message, &req.signature)?;

    let signer_addresses = get_signer_addresses(
        &state.config.chain.rpc_url,
        &state.config.chain.contract_address,
        &req.app_id,
    )
    .await?;

    if signer_addresses.is_empty() {
        return Err(KmsError::AppNotFound(req.app_id.clone()));
    }
    if !signer_addresses.contains(&recovered_addr) {
        return Err(KmsError::InvalidSignature(format!(
            "recovered address {:?} not in on-chain signer list for app {}",
            recovered_addr, req.app_id
        )));
    }

    // 3. Threshold-BLS DPRF: collect partials from ≥ threshold nodes and combine them into
    //    the app key, bound to (app_id, material). The master is never reconstructed.
    let material = hex::decode(req.material.trim_start_matches("0x"))
        .map_err(|_| KmsError::BadRequest("invalid material hex".into()))?;
    let (app_key, trace) = collect_and_dprf(state, &req.app_id, &material).await?;

    // 4. ECIES encrypt for caller
    let pubkey_bytes = hex::decode(req.pubkey.trim_start_matches("0x"))
        .map_err(|_| KmsError::BadRequest("invalid pubkey hex".into()))?;
    // The only realistic failure here is the caller's pubkey not being a valid curve point —
    // `app_key` is ours and always well-formed — so this is the caller's mistake, not ours.
    let ciphertext = ecies_encrypt(&pubkey_bytes, &app_key)
        .map_err(|e| KmsError::BadRequest(format!("cannot encrypt to caller pubkey: {}", e)))?;

    Ok((
        (
            StatusCode::OK,
            Json(AppKeyResponse {
                encrypted_secret: hex::encode(ciphertext),
            }),
        ),
        trace,
    ))
}

/// Recover the signer address of an EIP-191 personal_sign signature over `message`.
/// Accepts both normalized (0/1) and Ethereum-style (27/28) v bytes — compatible with
/// wallet.signMessage / personal_sign / `cast wallet sign`.
fn recover_eip191_address(message: &str, signature_hex: &str) -> Result<Address, KmsError> {
    let prefixed = format!("\x19Ethereum Signed Message:\n{}{}", message.len(), message);
    let hash = Keccak256::digest(prefixed.as_bytes());

    let sig_bytes = hex::decode(signature_hex.trim_start_matches("0x"))
        .map_err(|_| KmsError::InvalidSignature("invalid signature hex".into()))?;
    if sig_bytes.len() != 65 {
        return Err(KmsError::InvalidSignature(format!(
            "signature must be 65 bytes (r||s||v), got {}",
            sig_bytes.len()
        )));
    }
    let sig = Signature::from_slice(&sig_bytes[..64])
        .map_err(|_| KmsError::InvalidSignature("cannot parse r||s".into()))?;
    let rid_byte = match sig_bytes[64] {
        v @ (0 | 1) => v,
        v @ (27 | 28) => v - 27,
        v => return Err(KmsError::InvalidSignature(format!("invalid v byte: {}", v))),
    };
    let rid = RecoveryId::try_from(rid_byte)
        .map_err(|_| KmsError::InvalidSignature("invalid recovery id".into()))?;
    let verifying_key = VerifyingKey::recover_from_prehash(&hash, &sig, rid)
        .map_err(|_| KmsError::InvalidSignature("cannot recover signer".into()))?;
    let pubkey = verifying_key.to_encoded_point(false);
    let addr_hash = Keccak256::digest(&pubkey.as_bytes()[1..]);
    Ok(Address::from_slice(&addr_hash[12..]))
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub timestamp: i64,
    /// hex-encoded recoverable secp256k1 signature over "Refresh:{timestamp}"
    /// (EIP-191 personal_sign; e.g. `cast wallet sign "Refresh:<ts>" --private-key <owner>`).
    pub signature: String,
}

/// Trigger a proactive refresh of the whole committee's shares (master preserved, old
/// shares expire). Operator write-op: it forces a cluster-wide reshare, so it is gated to
/// the **on-chain app owner** — the request must carry an EIP-191 signature over
/// "Refresh:{timestamp}" that recovers to `getAppInfo(app_id).owner`.
pub async fn handle_refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<impl IntoResponse, KmsError> {
    let now = chrono::Utc::now().timestamp();
    if (now - req.timestamp).abs() > state.config.server.timestamp_tolerance_secs {
        return Err(KmsError::InvalidTimestamp(format!(
            "timestamp {} is too far from now ({})",
            req.timestamp, now
        )));
    }

    let message = format!("Refresh:{}", req.timestamp);
    let recovered = recover_eip191_address(&message, &req.signature)?;

    let owner = crate::chain::get_app_owner(
        &state.config.chain.rpc_url,
        &state.config.chain.contract_address,
        &state.config.tapp.app_id,
    )
    .await?;
    if recovered != owner {
        return Err(KmsError::InvalidSignature(format!(
            "recovered address {:?} is not the on-chain owner {:?} of app {}",
            recovered, owner, state.config.tapp.app_id
        )));
    }

    tracing::info!(operator = ?recovered, "refresh authorized by app owner");
    let outcome = crate::init::trigger_refresh(&state).await;
    let mt = crate::metrics::m();
    crate::metrics::record(&mt.refresh_ok, &mt.refresh_fail, &outcome);
    match outcome {
        Ok(()) => Ok((StatusCode::OK, "refresh complete".to_string())),
        Err(e) => Ok((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("refresh failed: {}", e),
        )),
    }
}

// ─── Router ───────────────────────────────────────────────────────────────────

/// GET /peers — this node's view of the cluster: itself + every known peer, with the same
/// liveness judgement the reshare dealer selection uses (direct contact within the window).
/// `live_share_holders` counts self (if it holds a share) + live peers with epoch > 0 — i.e.
/// how far the cluster is from the threshold floor.
pub async fn handle_peers(State(state): State<AppState>) -> impl IntoResponse {
    let now = chrono::Utc::now().timestamp();
    // Same snapshot /metrics renders from, so a dashboard and a curl can never disagree about
    // the numbers an operator is deciding on.
    let v = crate::metrics::cluster_view(&state).await;
    let own_gpk = v.group_pubkey.as_ref().map(hex::encode);

    let table = state.peer_table.read().await;
    let peers: Vec<serde_json::Value> = table
        .iter()
        .map(|(addr, p)| {
            serde_json::json!({
                "eth_addr": format!("0x{}", hex::encode(addr)),
                "grpc_url": p.grpc_url,
                "epoch": p.epoch,
                "live": p.is_live(now),
                "last_seen": p.last_seen,
                // Empty = the peer has not reported one (no share yet, or it predates the
                // gossip field). That reads as unknown, not as a disagreement.
                "group_pubkey": if p.group_pubkey.is_empty() {
                    serde_json::Value::Null
                } else {
                    hex::encode(&p.group_pubkey).into()
                },
            })
        })
        .collect();

    Json(serde_json::json!({
        // Cluster-wide current epoch = max over self + all known peers (epoch is monotonic, so
        // even a stale entry's epoch is a valid lower bound). Compare a captured sealed blob's
        // epoch against this before reusing it.
        "cluster_epoch": v.cluster_epoch,
        "self": {
            "eth_addr": format!("0x{}", hex::encode(state.signing_key.eth_address)),
            "grpc_url": state.config.cluster.self_url,
            "epoch": v.own_epoch,
            "has_share": v.has_share,
            // 1-based nodeList position, which is also the shard index. Confirming these run
            // 1..n across the cluster is how a reordered nodeList gets caught before it forks
            // the master.
            "own_id": v.own_id,
            "group_pubkey": own_gpk,
        },
        "peers": peers,
        "threshold": v.threshold,
        "total_nodes": v.total_nodes,
        // The line that matters operationally: below this a shardless node can no longer
        // rejoin, while derives carry on looking perfectly healthy.
        "recovery_threshold": v.recovery_threshold,
        "leading_holders": v.leading_holders,
        "live_share_holders": v.live_share_holders,
        // Live peers reporting a different master. Anything but 0 is a fork.
        "group_pubkey_mismatch": v.group_pubkey_mismatch,
    }))
}

// ─── Monitoring endpoints ─────────────────────────────────────────────────────

/// GET /health — liveness only: the process is up and serving. Deliberately says nothing about
/// cluster state, so a supervisor never restarts a node that is merely waiting to rejoin.
pub async fn handle_health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// GET /ready — readiness: 200 only when this node can actually contribute to a derive, i.e. it
/// holds a share and knows the group public key (needed to verify the combined signature).
/// 503 otherwise, so a load balancer stops sending derives to a node that would only fail them.
pub async fn handle_ready(State(state): State<AppState>) -> impl IntoResponse {
    let has_share = state.shard.read().await.is_some();
    let has_gpk = state.group_pubkey.read().await.is_some();
    if has_share && has_gpk {
        (StatusCode::OK, "ready")
    } else if has_share {
        (StatusCode::SERVICE_UNAVAILABLE, "no group public key")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "no share")
    }
}

/// GET /metrics — Prometheus text exposition for this node. Same exposure as /peers: no key
/// material, and nothing labelled by app or caller.
pub async fn handle_metrics(State(state): State<AppState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        crate::metrics::render(&state).await,
    )
}

/// GET /sealed-share — the latest sealed share blob (base64url), for the deploy pipeline to
/// capture and re-inject via KMS_SEALED_SHARE on the next restart. ECIES ciphertext to this
/// node's own TEE key: unusable by anyone else, so exposing it is as safe as logging it.
pub async fn handle_sealed_share(State(state): State<AppState>) -> impl IntoResponse {
    match state.sealed_share.read().await.clone() {
        Some(b64) => (StatusCode::OK, b64),
        None => (StatusCode::NOT_FOUND, "no sealed share yet".to_string()),
    }
}

pub fn router(state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/app-key", axum::routing::post(handle_app_key))
        .route("/refresh", axum::routing::post(handle_refresh))
        .route("/peers", axum::routing::get(handle_peers))
        .route("/sealed-share", axum::routing::get(handle_sealed_share))
        .route("/health", axum::routing::get(handle_health))
        .route("/ready", axum::routing::get(handle_ready))
        .route("/metrics", axum::routing::get(handle_metrics))
        .with_state(state)
}
