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

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub grpc_url: String,
    pub last_seen: i64,
}

// ─── Shared state ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ShardState {
    pub shard_index: u32,
    pub shard_bytes: Vec<u8>,
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
        }
    }

    pub async fn is_initialized(&self) -> bool {
        self.shard.read().await.is_some()
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
    let prefixed = format!("\x19Ethereum Signed Message:\n{}{}", message.len(), message);
    let hash = Keccak256::digest(prefixed.as_bytes());

    let sig_bytes = hex::decode(req.signature.trim_start_matches("0x"))
        .map_err(|_| KmsError::InvalidSignature("invalid signature hex".into()))?;
    if sig_bytes.len() != 65 {
        return Err(KmsError::InvalidSignature(format!(
            "signature must be 65 bytes (r||s||v), got {}",
            sig_bytes.len()
        )));
    }
    let sig = Signature::from_slice(&sig_bytes[..64])
        .map_err(|_| KmsError::InvalidSignature("cannot parse r||s".into()))?;
    // Accept both normalized (0/1) and Ethereum-style (27/28) v bytes.
    let rid_byte = match sig_bytes[64] {
        v @ (0 | 1) => v,
        v @ (27 | 28) => v - 27,
        v => {
            return Err(KmsError::InvalidSignature(format!(
                "invalid v byte: {}",
                v
            )));
        }
    };
    let rid = RecoveryId::try_from(rid_byte)
        .map_err(|_| KmsError::InvalidSignature("invalid recovery id".into()))?;

    let verifying_key = VerifyingKey::recover_from_prehash(&hash, &sig, rid)
        .map_err(|_| KmsError::InvalidSignature("cannot recover signer".into()))?;
    let pubkey = verifying_key.to_encoded_point(false);
    let addr_hash = Keccak256::digest(&pubkey.as_bytes()[1..]);
    let recovered_addr = Address::from_slice(&addr_hash[12..]);

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
        .map_err(|_| KmsError::CryptoError("invalid material hex".into()))?;
    let app_key = collect_and_dprf(&state, &req.app_id, &material).await?;

    // 4. ECIES encrypt for caller
    let pubkey_bytes = hex::decode(req.pubkey.trim_start_matches("0x"))
        .map_err(|_| KmsError::CryptoError("invalid pubkey hex".into()))?;
    let ciphertext = ecies_encrypt(&pubkey_bytes, &app_key)?;

    tracing::info!(app_id = %req.app_id, signer = ?recovered_addr, "app-key issued");

    Ok((
        StatusCode::OK,
        Json(AppKeyResponse {
            encrypted_secret: hex::encode(ciphertext),
        }),
    ))
}

// ─── Router ───────────────────────────────────────────────────────────────────

pub fn router(state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/app-key", axum::routing::post(handle_app_key))
        .with_state(state)
}
