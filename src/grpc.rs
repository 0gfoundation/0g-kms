use std::sync::Arc;

use futures::future::join_all;
use tonic::{Request, Response, Status};

use crate::{
    auth::authenticate,
    config::Config,
    crypto::{ecies_decrypt, ecies_encrypt, sign_request, sss_reconstruct},
    server::{AppState, ShardState},
};

mod proto {
    tonic::include_proto!("kms_cluster");
}

use proto::{
    kms_cluster_server::{KmsCluster, KmsClusterServer},
    EncryptedShard,
};

pub fn service(state: AppState) -> KmsClusterServer<KmsClusterService> {
    KmsClusterServer::new(KmsClusterService { state })
}

// ─── Service ──────────────────────────────────────────────────────────────────

pub struct KmsClusterService {
    state: AppState,
}

#[tonic::async_trait]
impl KmsCluster for KmsClusterService {
    /// Return own shard encrypted for the caller.
    async fn get_shard_contribution(
        &self,
        request: Request<()>,
    ) -> Result<Response<EncryptedShard>, Status> {
        let ctx = authenticate(request.metadata(), "GetShardContribution", &self.state.config).await?;

        let shard = self
            .state
            .shard
            .read()
            .await
            .clone()
            .ok_or_else(|| Status::unavailable("node not initialized"))?;

        let ciphertext = ecies_encrypt(&ctx.caller_pubkey, &shard.shard_bytes)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(EncryptedShard {
            ciphertext,
            shard_index: shard.shard_index,
        }))
    }

    /// Assign and return the shard that belongs to the caller.
    /// - Init mode:     start node has pending_shards; assign by nodeList position.
    /// - Recovery mode: collect all healthy peer shards, reconstruct masterKey,
    ///                  identify missing shard_index, generate and return it.
    async fn request_shard(
        &self,
        request: Request<()>,
    ) -> Result<Response<EncryptedShard>, Status> {
        let ctx = authenticate(request.metadata(), "RequestShard", &self.state.config).await?;

        // Try init mode first
        if let Some(shard) = self.try_assign_init_shard(&ctx.caller_pubkey).await? {
            return Ok(Response::new(shard));
        }

        // Recovery mode: collect all peer shards + own, reconstruct, derive missing shard
        let shard = self.recover_shard_for_caller(&ctx.caller_pubkey).await?;
        Ok(Response::new(shard))
    }
}

impl KmsClusterService {
    /// Init mode: if pending_shards exists, find the shard for the caller by
    /// their position in the on-chain nodeList and return it encrypted.
    async fn try_assign_init_shard(
        &self,
        caller_pubkey: &[u8],
    ) -> Result<Option<EncryptedShard>, Status> {
        let pending = self.state.pending_shards.read().await;
        let shards = match pending.as_ref() {
            Some(s) => s,
            None => return Ok(None),
        };

        // Recover caller address from pubkey
        let caller_addr = crate::auth::eth_address_from_pubkey(caller_pubkey);

        // Find caller's position in on-chain nodeList
        let node_list = crate::chain::get_signer_addresses(
            &self.state.config.chain.rpc_url,
            &self.state.config.chain.contract_address,
            &self.state.config.tapp.app_id,
        )
        .await
        .map_err(|e| Status::internal(format!("getNodeList failed: {}", e)))?;

        let position = node_list
            .iter()
            .position(|a| *a == caller_addr)
            .ok_or_else(|| Status::permission_denied("caller not in on-chain nodeList"))?;

        let (shard_index, shard_bytes) = shards
            .get(position)
            .ok_or_else(|| Status::internal(format!("no shard at position {}", position)))?;

        let ciphertext = ecies_encrypt(caller_pubkey, shard_bytes)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Some(EncryptedShard {
            ciphertext,
            shard_index: *shard_index,
        }))
    }

    /// Recovery mode: collect shards from all healthy peers, reconstruct masterKey,
    /// identify the missing shard_index, generate and return the missing shard encrypted.
    async fn recover_shard_for_caller(
        &self,
        caller_pubkey: &[u8],
    ) -> Result<EncryptedShard, Status> {
        use crate::crypto::sss_split;

        let own = self
            .state
            .shard
            .read()
            .await
            .clone()
            .ok_or_else(|| Status::unavailable("coordinator not initialized"))?;

        // Concurrently collect shards from all peers
        let timestamp = chrono::Utc::now().timestamp();
        let sig = sign_request(&self.state.signing_key.private_key, "GetShardContribution", timestamp)
            .map_err(|e| Status::internal(e.to_string()))?;

        let peer_futures: Vec<_> = self
            .state
            .config
            .cluster
            .peers
            .iter()
            .map(|url| get_shard_contribution(url, &sig, timestamp, &self.state.signing_key.private_key))
            .collect();

        let peer_results = join_all(peer_futures).await;

        let mut shards: Vec<(u32, Vec<u8>)> = vec![(own.shard_index, own.shard_bytes)];
        for result in peer_results {
            match result {
                Ok((idx, bytes)) => shards.push((idx, bytes)),
                Err(e) => tracing::warn!(error = %e, "peer shard collection failed during recovery"),
            }
        }

        if shards.len() < self.state.config.cluster.threshold as usize {
            return Err(Status::unavailable(format!(
                "not enough shards for recovery: got {}, need {}",
                shards.len(),
                self.state.config.cluster.threshold
            )));
        }

        // Reconstruct masterKey
        let master_key = sss_reconstruct(&shards)
            .map_err(|e| Status::internal(format!("SSS reconstruct failed: {}", e)))?;

        // Find missing shard_index (the one not present among collected shards)
        let total = self.state.config.cluster.total_nodes;
        let present: std::collections::HashSet<u32> = shards.iter().map(|(i, _)| *i).collect();
        let missing_index = (1..=total)
            .find(|i| !present.contains(i))
            .ok_or_else(|| Status::internal("no missing shard index found — cluster may be full"))?;

        // Re-split to generate shard at missing_index
        // (evaluate the polynomial at the missing x-coordinate)
        let all_shards = sss_split(&master_key, self.state.config.cluster.threshold, total)
            .map_err(|e| Status::internal(format!("SSS split failed: {}", e)))?;

        let (_, new_shard_bytes) = all_shards
            .into_iter()
            .find(|(i, _)| *i == missing_index)
            .ok_or_else(|| Status::internal("could not find shard for missing index"))?;

        let ciphertext = ecies_encrypt(caller_pubkey, &new_shard_bytes)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(EncryptedShard {
            ciphertext,
            shard_index: missing_index,
        })
    }
}

// ─── Peer client ──────────────────────────────────────────────────────────────

/// Call GetShardContribution on a peer, decrypt the response, return (shard_index, shard_bytes).
pub async fn get_shard_contribution(
    peer_url: &str,
    sig: &[u8],
    timestamp: i64,
    own_private_key: &[u8; 32],
) -> anyhow::Result<(u32, Vec<u8>)> {
    use tonic::metadata::MetadataValue;
    use tonic::transport::Channel;

    let channel = Channel::from_shared(peer_url.to_string())?
        .connect()
        .await?;

    let mut client = proto::kms_cluster_client::KmsClusterClient::new(channel);

    let mut request = Request::new(());
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(sig))?,
    );
    request.metadata_mut().insert(
        "timestamp",
        MetadataValue::try_from(timestamp.to_string())?,
    );

    let resp = client.get_shard_contribution(request).await?.into_inner();

    // Decrypt shard
    let shard_bytes = ecies_decrypt(own_private_key, &resp.ciphertext)
        .map_err(|e| anyhow::anyhow!("ECIES decrypt failed: {}", e))?;

    Ok((resp.shard_index, shard_bytes))
}

// ─── Concurrent collect helper (used by server.rs /app-key handler) ───────────

/// Concurrently collect shard contributions from all peers + own shard,
/// then reconstruct masterKey. Returns Err if fewer than threshold shards collected.
pub async fn collect_and_reconstruct(state: &AppState) -> Result<[u8; 32], crate::error::KmsError> {
    let own = state
        .shard
        .read()
        .await
        .clone()
        .ok_or_else(|| crate::error::KmsError::ConfigError("node not initialized".into()))?;

    let timestamp = chrono::Utc::now().timestamp();
    let sig = sign_request(&state.signing_key.private_key, "GetShardContribution", timestamp)
        .map_err(|e| crate::error::KmsError::CryptoError(e.to_string()))?;

    let peer_futures: Vec<_> = state
        .config
        .cluster
        .peers
        .iter()
        .map(|url| get_shard_contribution(url, &sig, timestamp, &state.signing_key.private_key))
        .collect();

    let peer_results = join_all(peer_futures).await;

    let mut shards: Vec<(u32, Vec<u8>)> = vec![(own.shard_index, own.shard_bytes)];
    for result in peer_results {
        match result {
            Ok((idx, bytes)) => shards.push((idx, bytes)),
            Err(e) => tracing::warn!(error = %e, "peer shard collection failed"),
        }
    }

    if shards.len() < state.config.cluster.threshold as usize {
        return Err(crate::error::KmsError::CryptoError(format!(
            "not enough shards: got {}, need {}",
            shards.len(),
            state.config.cluster.threshold
        )));
    }

    sss_reconstruct(&shards).map_err(|e| crate::error::KmsError::CryptoError(e.to_string()))
}
