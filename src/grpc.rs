use std::time::Duration;

use futures::future::join_all;
use tonic::{Request, Response, Status};

use crate::{
    auth::authenticate,
    crypto::{ecies_decrypt, ecies_encrypt, sign_request, sss_reconstruct},
    server::{AppState, PeerInfo},
};

mod proto {
    tonic::include_proto!("kms_cluster");
}

use proto::{
    kms_cluster_server::{KmsCluster, KmsClusterServer},
    EncryptedShard, GossipRequest, GossipResponse, NodeInfo,
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
    async fn request_shard(
        &self,
        request: Request<()>,
    ) -> Result<Response<EncryptedShard>, Status> {
        let ctx = authenticate(request.metadata(), "RequestShard", &self.state.config).await?;

        if let Some(shard) = self.try_assign_init_shard(&ctx.caller_pubkey).await? {
            return Ok(Response::new(shard));
        }

        let shard = self.recover_shard_for_caller(&ctx.caller_pubkey).await?;
        Ok(Response::new(shard))
    }

    /// Gossip: update peer table with caller's info, return full member list.
    async fn gossip(
        &self,
        request: Request<GossipRequest>,
    ) -> Result<Response<GossipResponse>, Status> {
        let ctx = authenticate(request.metadata(), "Gossip", &self.state.config).await?;

        let req = request.into_inner();

        // Update peer table with caller's info
        if let Some(info) = req.self_info {
            if !info.grpc_url.is_empty() {
                let now = chrono::Utc::now().timestamp();
                let addr_bytes: [u8; 20] = ctx.caller_eth_addr.into();
                let mut table = self.state.peer_table.write().await;
                let is_new = !table.contains_key(&addr_bytes);
                table.insert(
                    addr_bytes,
                    PeerInfo {
                        grpc_url: info.grpc_url.clone(),
                        last_seen: now,
                    },
                );
                if is_new {
                    tracing::info!(peer_url = %info.grpc_url, "gossip: peer registered");
                }
            }
        }

        // Return all known peers
        let peers: Vec<NodeInfo> = self
            .state
            .peer_table
            .read()
            .await
            .iter()
            .map(|(addr, info)| NodeInfo {
                grpc_url: info.grpc_url.clone(),
                eth_addr: hex::encode(addr),
            })
            .collect();

        Ok(Response::new(GossipResponse { peers }))
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

        let caller_addr = crate::auth::eth_address_from_pubkey(caller_pubkey);

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

    /// Recovery mode: collect shards from all healthy peers, then use Lagrange interpolation
    /// to evaluate the original SSS polynomial at the missing node's x-coordinate.
    /// Never reconstructs the master key; the missing shard is derived directly from peer shards.
    async fn recover_shard_for_caller(
        &self,
        caller_pubkey: &[u8],
    ) -> Result<EncryptedShard, Status> {
        let own = self
            .state
            .shard
            .read()
            .await
            .clone()
            .ok_or_else(|| Status::unavailable("coordinator not initialized"))?;

        let timestamp = chrono::Utc::now().timestamp();
        let sig = sign_request(&self.state.signing_key.private_key, "GetShardContribution", timestamp)
            .map_err(|e| Status::internal(e.to_string()))?;

        let peer_urls = self.state.peer_urls().await;
        let peer_futures: Vec<_> = peer_urls
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

        // Dedup by x-coordinate (bytes[0]): stale peer_table entries can cause
        // the same shard to be fetched twice, which would crash SSS with
        // SharingDuplicateIdentifier / zero denominator.
        let mut seen = std::collections::HashSet::new();
        shards.retain(|(_, bytes)| !bytes.is_empty() && seen.insert(bytes[0]));

        if shards.len() < self.state.config.cluster.threshold as usize {
            return Err(Status::unavailable(format!(
                "not enough shards for recovery: got {}, need {}",
                shards.len(),
                self.state.config.cluster.threshold
            )));
        }

        let total = self.state.config.cluster.total_nodes;
        let present: std::collections::HashSet<u32> = shards.iter().map(|(i, _)| *i).collect();
        let missing_index = (1..=total)
            .find(|i| !present.contains(i))
            .ok_or_else(|| Status::internal("no missing shard index found — cluster may be full"))?;

        // Lagrange interpolation: evaluate the original SSS polynomial at missing_index.
        // This produces a shard consistent with the existing shards without ever reconstructing
        // the master key and without introducing a new random polynomial.
        let new_shard_bytes = crate::crypto::sss_evaluate_at(&shards, missing_index)
            .map_err(|e| Status::internal(format!("Lagrange interpolation failed: {}", e)))?;

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

    let shard_bytes = ecies_decrypt(own_private_key, &resp.ciphertext)
        .map_err(|e| anyhow::anyhow!("ECIES decrypt failed: {}", e))?;

    Ok((resp.shard_index, shard_bytes))
}

// ─── Concurrent collect helper (used by server.rs /app-key handler) ───────────

/// Concurrently collect shard contributions from all peers + own shard,
/// then reconstruct masterKey. Peer list is read from the dynamic peer table.
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

    let peer_urls = state.peer_urls().await;
    let peer_futures: Vec<_> = peer_urls
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

    // Dedup by x-coordinate (bytes[0]): stale peer_table entries can cause the
    // same shard to be fetched twice, which would crash SSS with
    // SharingDuplicateIdentifier.
    let mut seen = std::collections::HashSet::new();
    shards.retain(|(_, bytes)| !bytes.is_empty() && seen.insert(bytes[0]));

    if shards.len() < state.config.cluster.threshold as usize {
        return Err(crate::error::KmsError::CryptoError(format!(
            "not enough shards: got {}, need {}",
            shards.len(),
            state.config.cluster.threshold
        )));
    }

    sss_reconstruct(&shards).map_err(|e| crate::error::KmsError::CryptoError(e.to_string()))
}

// ─── Gossip background task ───────────────────────────────────────────────────

/// Spawn the gossip background task. Call once after node initialization.
pub fn start_gossip_task(state: AppState) {
    tokio::spawn(async move {
        // Short initial delay to let both HTTP and gRPC servers come up
        tokio::time::sleep(Duration::from_secs(5)).await;
        loop {
            gossip_round(&state).await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
}

async fn gossip_round(state: &AppState) {
    let self_url = &state.config.cluster.self_url;
    if self_url.is_empty() {
        tracing::debug!("cluster.self_url not set, skipping gossip");
        return;
    }

    // peer_table is the authoritative source: each node (eth_addr) has exactly one URL.
    // Seeds are only used as bootstrap contacts when no peers are known yet.
    // Once gossip registers a peer, its URL supersedes any seed URL for that node.
    let mut targets: Vec<String> = {
        let table = state.peer_table.read().await;
        table.values().map(|p| p.grpc_url.clone()).collect()
    };
    if targets.is_empty() {
        targets = state.config.cluster.seeds.clone();
    }
    targets.retain(|u| u != self_url);

    if targets.is_empty() {
        return;
    }

    let timestamp = chrono::Utc::now().timestamp();
    let sig = match sign_request(&state.signing_key.private_key, "Gossip", timestamp) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("gossip sign failed: {}", e);
            return;
        }
    };

    let self_eth_addr = hex::encode(state.signing_key.eth_address);

    for target in &targets {
        match push_gossip(target, self_url, &self_eth_addr, &sig, timestamp).await {
            Ok(received) => {
                let now = chrono::Utc::now().timestamp();
                let mut table = state.peer_table.write().await;

                for peer in received {
                    if &peer.grpc_url == self_url || peer.grpc_url.is_empty() {
                        continue;
                    }
                    match hex::decode(&peer.eth_addr) {
                        Ok(bytes) if bytes.len() == 20 => {
                            let mut key = [0u8; 20];
                            key.copy_from_slice(&bytes);
                            table
                                .entry(key)
                                .and_modify(|e| {
                                    e.grpc_url = peer.grpc_url.clone();
                                    e.last_seen = now;
                                })
                                .or_insert_with(|| {
                                    tracing::info!(peer_url = %peer.grpc_url, "gossip: discovered new peer");
                                    PeerInfo {
                                        grpc_url: peer.grpc_url.clone(),
                                        last_seen: now,
                                    }
                                });
                        }
                        _ => tracing::warn!(eth_addr = %peer.eth_addr, "gossip: invalid eth_addr in response"),
                    }
                }

                // Prune peers not seen for > 5 minutes
                let cutoff = now - 300;
                table.retain(|_, v| v.last_seen > cutoff);
            }
            Err(e) => tracing::warn!(target = %target, error = %e, "gossip push failed"),
        }
    }
}

async fn push_gossip(
    peer_url: &str,
    self_url: &str,
    self_eth_addr: &str,
    sig: &[u8],
    timestamp: i64,
) -> anyhow::Result<Vec<NodeInfo>> {
    use tonic::metadata::MetadataValue;
    use tonic::transport::Channel;

    let channel = Channel::from_shared(peer_url.to_string())?
        .connect()
        .await?;

    let mut client = proto::kms_cluster_client::KmsClusterClient::new(channel);

    let mut request = Request::new(GossipRequest {
        self_info: Some(NodeInfo {
            grpc_url: self_url.to_string(),
            eth_addr: self_eth_addr.to_string(),
        }),
    });
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(sig))?,
    );
    request.metadata_mut().insert(
        "timestamp",
        MetadataValue::try_from(timestamp.to_string())?,
    );

    let resp = client.gossip(request).await?.into_inner();
    Ok(resp.peers)
}
