use anyhow::{anyhow, Result};
use tracing::info;

use crate::{
    crypto::{ecies_decrypt, share_to_bytes, sign_request, split_master},
    server::{AppState, ShardState},
};

/// Bootstrap flow (first node ever):
///   1. Generate a fresh BLS12-381 master and Shamir-split it into total_nodes shares.
///   2. Store own shard (position 0 in nodeList) in state.shard.
///   3. Store all shards in state.pending_shards for peers to pull.
///
/// The master scalar is dropped after the split and never stored. (S2/DKG will later
/// replace this dealer step with distributed key generation; the resulting shares are
/// the same type, so the derivation path is unaffected.)
pub async fn init_start_node(state: &AppState) -> Result<()> {
    let threshold = state.config.cluster.threshold;
    let total = state.config.cluster.total_nodes;

    info!(threshold, total, "Generating BLS master and splitting into shards");

    let shares = split_master(threshold as usize, total as usize)?;
    // Shard index = 1-based position in the share vector (used for nodeList-position
    // assignment and dedup). The Lagrange identifier travels inside the serialized share.
    let shards: Vec<(u32, Vec<u8>)> = shares
        .iter()
        .enumerate()
        .map(|(i, s)| (i as u32 + 1, share_to_bytes(s)))
        .collect();

    let (own_index, own_bytes) = shards
        .first()
        .ok_or_else(|| anyhow!("split produced no shards"))?
        .clone();

    info!(shard_index = own_index, "Bootstrap node shard assigned");

    *state.shard.write().await = Some(ShardState {
        shard_index: own_index,
        shard_bytes: own_bytes,
    });
    *state.pending_shards.write().await = Some(shards);

    info!("Bootstrap node ready — waiting for peers to collect their shards");
    Ok(())
}

/// Outcome of a join attempt. Distinguishes "no peer reachable" (possibly a genuine
/// first-ever cluster start) from "a peer answered but wouldn't give us a shard" (the
/// cluster already exists) — the disaster gate in `main` relies on this: a node must NEVER
/// regenerate a fresh master when the cluster is already up.
pub enum JoinResult {
    /// Got our shard from a seed and stored it.
    Joined,
    /// No seed was reachable at the connection level (all connects failed).
    NoSeedReachable,
    /// At least one seed was reachable but declined/failed to serve a shard (e.g. recovery
    /// not yet available). The cluster exists → regenerating a master would fork it.
    SeedReachableDeclined,
}

/// Per-seed failure, split by whether the peer was reachable (RPC-level) or not
/// (connection-level). Only "all unreachable" may lead to genesis.
enum SeedError {
    Unreachable(anyhow::Error),
    Declined(anyhow::Error),
}

/// Join flow (non-bootstrap node, or restarted node):
///   1. For each seed: call RequestShard via gRPC, decrypt, store own shard.
///   2. Classify the outcome (see [`JoinResult`]).
/// Returns `Err` only on genuine local errors (e.g. signing) — never conflated with
/// reachability, so the caller never genesis-es on an internal error.
pub async fn join_cluster(state: &AppState) -> Result<JoinResult> {
    let seeds = &state.config.cluster.seeds;
    if seeds.is_empty() {
        info!("no seeds configured — treating as empty cluster (eligible for genesis)");
        return Ok(JoinResult::NoSeedReachable);
    }

    info!(seeds = ?seeds, "Joining cluster — requesting shard from seeds");

    let timestamp = chrono::Utc::now().timestamp();
    let sig = sign_request(&state.signing_key.private_key, "RequestShard", timestamp)?;

    let mut any_reachable = false;
    for seed_url in seeds {
        match request_shard_from_peer(seed_url, &sig, timestamp, state).await {
            Ok(shard) => {
                info!(peer = %seed_url, shard_index = shard.shard_index, "Shard received and stored");
                *state.shard.write().await = Some(shard);
                return Ok(JoinResult::Joined);
            }
            Err(SeedError::Unreachable(e)) => {
                tracing::warn!(peer = %seed_url, error = %e, "seed unreachable");
            }
            Err(SeedError::Declined(e)) => {
                any_reachable = true;
                tracing::warn!(peer = %seed_url, error = %e, "seed reachable but declined shard");
            }
        }
    }

    Ok(if any_reachable {
        JoinResult::SeedReachableDeclined
    } else {
        JoinResult::NoSeedReachable
    })
}

async fn request_shard_from_peer(
    peer_url: &str,
    sig: &[u8],
    timestamp: i64,
    state: &AppState,
) -> std::result::Result<ShardState, SeedError> {
    use tonic::metadata::MetadataValue;
    use tonic::transport::Channel;

    mod proto {
        tonic::include_proto!("kms_cluster");
    }
    use proto::kms_cluster_client::KmsClusterClient;

    // Connection-level failures (bad URL, connect refused/timeout) = Unreachable: the peer
    // may simply not be up yet, so this alone may indicate a genuine first-cluster start.
    let channel = Channel::from_shared(peer_url.to_string())
        .map_err(|e| SeedError::Unreachable(anyhow!("bad seed url {}: {}", peer_url, e)))?
        .connect()
        .await
        .map_err(|e| SeedError::Unreachable(anyhow!("cannot connect to {}: {}", peer_url, e)))?;

    // From here the peer IS reachable: any further failure is Declined (the cluster exists),
    // which must never be mistaken for "empty cluster" and never trigger master regeneration.
    let mut client = KmsClusterClient::new(channel);

    let mut request = tonic::Request::new(());
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(sig))
            .map_err(|e| SeedError::Declined(anyhow!("bad signature metadata: {}", e)))?,
    );
    request.metadata_mut().insert(
        "timestamp",
        MetadataValue::try_from(timestamp.to_string())
            .map_err(|e| SeedError::Declined(anyhow!("bad timestamp metadata: {}", e)))?,
    );

    let resp = client
        .request_shard(request)
        .await
        .map_err(|status| {
            // FailedPrecondition = the peer is an initialized cluster member (cluster exists)
            // → Declined, so the disaster gate refuses genesis. Unavailable = peer not
            // initialized (or transiently down) → Unreachable, not evidence of a cluster.
            let msg = anyhow!("RequestShard on {}: {}", peer_url, status.message());
            match status.code() {
                tonic::Code::Unavailable => SeedError::Unreachable(msg),
                tonic::Code::FailedPrecondition => SeedError::Declined(msg),
                // Any other reachable-peer error: be conservative and treat the cluster as
                // existing (Declined) — never risk regenerating a master.
                _ => SeedError::Declined(msg),
            }
        })?
        .into_inner();

    let shard_bytes = ecies_decrypt(&state.signing_key.private_key, &resp.ciphertext)
        .map_err(|e| SeedError::Declined(anyhow!("ECIES decrypt failed: {}", e)))?;

    Ok(ShardState {
        shard_index: resp.shard_index,
        shard_bytes,
    })
}
