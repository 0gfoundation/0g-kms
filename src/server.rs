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
    crypto::{derive_app_key, ecies_encrypt},
    error::KmsError,
    grpc::collect_and_reconstruct,
    tee::NodeKey,
};

// ─── Shared state ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ShardState {
    pub shard_index: u32,
    pub shard_bytes: Vec<u8>,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub signing_key: Arc<NodeKey>,
    /// Own shard — None until init/recovery completes.
    pub shard: Arc<RwLock<Option<ShardState>>>,
    /// Start-node only: all N shards held temporarily until all peers collect theirs.
    pub pending_shards: Arc<RwLock<Option<Vec<(u32, Vec<u8>)>>>>,
}

impl AppState {
    pub fn new(config: Config, signing_key: NodeKey) -> Self {
        Self {
            config: Arc::new(config),
            signing_key: Arc::new(signing_key),
            shard: Arc::new(RwLock::new(None)),
            pending_shards: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn is_initialized(&self) -> bool {
        self.shard.read().await.is_some()
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

    // 2. Verify signature: recover eth address, check against on-chain signer list
    let message = format!("GetSecretResource:{}", req.timestamp);
    let sig_bytes = hex::decode(req.signature.trim_start_matches("0x"))
        .map_err(|_| KmsError::InvalidSignature("invalid signature hex".into()))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|_| KmsError::InvalidSignature("cannot parse signature".into()))?;

    let candidate_addrs = recover_all_eth_addresses(message.as_bytes(), &sig);
    if candidate_addrs.is_empty() {
        return Err(KmsError::InvalidSignature("cannot recover signer address".into()));
    }

    let signer_addresses = get_signer_addresses(
        &state.config.chain.rpc_url,
        &state.config.chain.contract_address,
        &req.app_id,
    )
    .await?;

    if signer_addresses.is_empty() {
        return Err(KmsError::AppNotFound(req.app_id.clone()));
    }
    let matched_addr = candidate_addrs
        .iter()
        .find(|a| signer_addresses.contains(a))
        .ok_or_else(|| {
            KmsError::InvalidSignature(format!(
                "recovered address {:?} not in on-chain signer list for app {}",
                candidate_addrs, req.app_id
            ))
        })?;

    // 3. Concurrently collect peer shards, reconstruct masterKey, derive app key
    let master_key = collect_and_reconstruct(&state).await?;
    let app_key = derive_app_key(&master_key, &req.app_id);

    // 4. ECIES encrypt for caller
    let pubkey_bytes = hex::decode(req.pubkey.trim_start_matches("0x"))
        .map_err(|_| KmsError::CryptoError("invalid pubkey hex".into()))?;
    let ciphertext = ecies_encrypt(&pubkey_bytes, &app_key)?;

    tracing::info!(app_id = %req.app_id, signer = ?matched_addr, "app-key issued");

    Ok((
        StatusCode::OK,
        Json(AppKeyResponse {
            encrypted_secret: hex::encode(ciphertext),
        }),
    ))
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn recover_all_eth_addresses(message: &[u8], sig: &Signature) -> Vec<Address> {
    let mut addrs = Vec::new();
    for recovery_id in [0u8, 1u8] {
        if let Ok(rid) = RecoveryId::try_from(recovery_id) {
            if let Ok(verifying_key) = VerifyingKey::recover_from_msg(message, sig, rid) {
                let pubkey = verifying_key.to_encoded_point(false);
                let hash = Keccak256::digest(&pubkey.as_bytes()[1..]);
                addrs.push(Address::from_slice(&hash[12..]));
            }
        }
    }
    addrs
}

// ─── Router ───────────────────────────────────────────────────────────────────

pub fn router(state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/app-key", axum::routing::post(handle_app_key))
        .with_state(state)
}
