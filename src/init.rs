use anyhow::{anyhow, Result};
use tracing::info;

use crate::{
    crypto::{ecies_decrypt, sign_request, sss_split},
    server::{AppState, ShardState},
};

/// Bootstrap flow (first node ever):
///   1. Generate masterKey.
///   2. SSS split into total_nodes shards.
///   3. Store own shard (position 0 in nodeList) in state.shard.
///   4. Store all shards in state.pending_shards for peers to pull.
pub async fn init_start_node(state: &AppState) -> Result<()> {
    let threshold = state.config.cluster.threshold;
    let total = state.config.cluster.total_nodes;

    info!(threshold, total, "Generating masterKey and splitting into shards");

    let master_key = rand_key();
    let shards = sss_split(&master_key, threshold, total)?;

    let (own_index, own_bytes) = shards
        .first()
        .ok_or_else(|| anyhow!("SSS produced no shards"))?
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

/// Join flow (non-bootstrap node, or restarted node):
///   1. Pick a seed from config.cluster.seeds.
///   2. Call RequestShard via gRPC.
///   3. Decrypt the response.
///   4. Store own shard.
pub async fn join_cluster(state: &AppState) -> Result<()> {
    let seeds = &state.config.cluster.seeds;
    if seeds.is_empty() {
        return Err(anyhow!("no seeds configured — cannot join cluster"));
    }

    info!(seeds = ?seeds, "Joining cluster — requesting shard from seeds");

    let timestamp = chrono::Utc::now().timestamp();
    let sig = sign_request(&state.signing_key.private_key, "RequestShard", timestamp)?;

    let mut last_err = anyhow!("all seeds failed");
    for seed_url in seeds {
        match request_shard_from_peer(seed_url, &sig, timestamp, state).await {
            Ok(shard) => {
                info!(
                    peer = %seed_url,
                    shard_index = shard.shard_index,
                    "Shard received and stored"
                );
                *state.shard.write().await = Some(shard);
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(peer = %seed_url, error = %e, "RequestShard failed");
                last_err = e;
            }
        }
    }

    Err(last_err)
}

async fn request_shard_from_peer(
    peer_url: &str,
    sig: &[u8],
    timestamp: i64,
    state: &AppState,
) -> Result<ShardState> {
    use tonic::metadata::MetadataValue;
    use tonic::transport::Channel;

    mod proto {
        tonic::include_proto!("kms_cluster");
    }
    use proto::kms_cluster_client::KmsClusterClient;

    let channel = Channel::from_shared(peer_url.to_string())?
        .connect()
        .await
        .map_err(|e| anyhow!("cannot connect to {}: {}", peer_url, e))?;

    let mut client = KmsClusterClient::new(channel);

    let mut request = tonic::Request::new(());
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(sig))?,
    );
    request.metadata_mut().insert(
        "timestamp",
        MetadataValue::try_from(timestamp.to_string())?,
    );

    let resp = client
        .request_shard(request)
        .await
        .map_err(|e| anyhow!("RequestShard RPC failed: {}", e))?
        .into_inner();

    let shard_bytes = ecies_decrypt(&state.signing_key.private_key, &resp.ciphertext)
        .map_err(|e| anyhow!("ECIES decrypt failed: {}", e))?;

    Ok(ShardState {
        shard_index: resp.shard_index,
        shard_bytes,
    })
}

fn rand_key() -> [u8; 32] {
    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}
