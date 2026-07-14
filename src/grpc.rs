use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use tonic::{Request, Response, Status};

use crate::{
    auth::authenticate,
    crypto::{
        dprf_combine, dprf_message, dprf_partial, ecies_decrypt, ecies_encrypt,
        partial_from_bytes, partial_to_bytes, share_from_bytes, sign_request,
    },
    error::KmsError,
    server::{AppState, PeerInfo},
};

mod proto {
    tonic::include_proto!("kms_cluster");
}

use proto::{
    kms_cluster_server::{KmsCluster, KmsClusterServer},
    DkgRoundAck, DkgRoundMsg, DprfPartialRequest, EncryptedPartial, EncryptedShard, GossipRequest,
    GossipResponse, NodeInfo, ReshareAck, ReshareRequest,
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
    /// Threshold-BLS DPRF: sign the derivation message with this node's own share and
    /// return the partial f(i)·H(msg), encrypted for the caller. Computed entirely locally;
    /// the share never leaves the node.
    async fn get_dprf_partial(
        &self,
        request: Request<DprfPartialRequest>,
    ) -> Result<Response<EncryptedPartial>, Status> {
        let ctx = authenticate(request.metadata(), "GetDprfPartial", &self.state.config).await?;
        let req = request.into_inner();

        let shard = self
            .state
            .shard
            .read()
            .await
            .clone()
            .ok_or_else(|| Status::unavailable("node not initialized"))?;
        let share = share_from_bytes(&shard.shard_bytes)
            .map_err(|e| Status::internal(format!("invalid local shard: {}", e)))?;

        let msg = dprf_message(&req.app_id, &req.material);
        let partial = dprf_partial(&share, &msg)
            .map_err(|e| Status::internal(format!("partial sign failed: {}", e)))?;

        let ciphertext = ecies_encrypt(&ctx.caller_pubkey, &partial_to_bytes(&partial))
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(EncryptedPartial {
            ciphertext,
            shard_index: shard.shard_index,
            epoch: shard.epoch,
        }))
    }

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

        // Can't serve an init shard. Signal whether WE are an initialized cluster member, so
        // the caller's disaster gate can distinguish "the cluster exists" (must NOT let the
        // caller regenerate a master) from "empty/uninitialized cluster" (genesis is fine).
        //   - FailedPrecondition → we hold a shard: the cluster is live but shard recovery
        //     isn't available yet (Phase 4). The caller must refuse to genesis.
        //   - Unavailable → we're not initialized either: not evidence of an existing cluster.
        if self.state.shard.read().await.is_some() {
            return Err(Status::failed_precondition(
                "cluster is active but shard recovery is not yet available (deferred to reshare)",
            ));
        }
        Err(Status::unavailable("node not initialized"))
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
                // Store the caller's pubkey recovered from their signature (authoritative),
                // not a self-reported field.
                table.insert(
                    addr_bytes,
                    PeerInfo {
                        grpc_url: info.grpc_url.clone(),
                        last_seen: now,
                        pubkey: ctx.caller_pubkey.clone(),
                        epoch: info.epoch,
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
                pubkey: info.pubkey.clone(),
                epoch: info.epoch,
            })
            .collect();

        Ok(Response::new(GossipResponse { peers }))
    }

    /// DKG/reshare transport: buffer an inbound round message for the session driver.
    /// The round-1 p2p payload is ECIES-encrypted to us; decrypt it before buffering.
    /// The broadcast is stored as-is (it's public commitment data verified inside gennaro).
    async fn dkg_round(
        &self,
        request: Request<DkgRoundMsg>,
    ) -> Result<Response<DkgRoundAck>, Status> {
        // Authenticate: sender must be a current on-chain node. (Hardening TODO: bind
        // msg.from_index to the caller's nodeList position; gennaro's per-round commitment
        // checks already reject a message routed under the wrong identity.)
        let _ctx = authenticate(request.metadata(), "DkgRound", &self.state.config).await?;
        let msg = request.into_inner();

        let p2p = if msg.p2p.is_empty() {
            Vec::new()
        } else {
            ecies_decrypt(&self.state.signing_key.private_key, &msg.p2p)
                .map_err(|e| Status::internal(format!("dkg p2p decrypt failed: {}", e)))?
        };

        self.state
            .dkg_sessions
            .write()
            .await
            .entry(msg.session_id)
            .or_default()
            .record(msg.round, msg.from_index, msg.broadcast, p2p);

        Ok(Response::new(DkgRoundAck {}))
    }

    /// Reshare trigger: a recovering node asks us (a live committee member holding a share)
    /// to participate as a dealer. We run the reshare in the background and replace our own
    /// share with the refreshed one; the master (group pubkey) is preserved.
    async fn start_reshare(
        &self,
        request: Request<ReshareRequest>,
    ) -> Result<Response<ReshareAck>, Status> {
        let _ctx = authenticate(request.metadata(), "StartReshare", &self.state.config).await?;
        let req = request.into_inner();

        // We can only deal if we hold a share.
        if self.state.shard.read().await.is_none() {
            return Err(Status::failed_precondition("no local share to reshare"));
        }

        // Run the dealer side in the background so we can ack promptly; the session
        // synchronises with the recovering node + other dealers via the DkgRound barrier.
        let state = self.state.clone();
        tokio::spawn(async move {
            if let Err(e) =
                crate::init::run_reshare_dealer(&state, req.session_id, req.dealer_ids, req.epoch)
                    .await
            {
                tracing::error!(error = %e, "reshare dealer session failed");
            }
        });

        Ok(Response::new(ReshareAck {}))
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

    /// Recovery mode: re-issue the shard for a node that has lost it.
    ///
    /// DEFERRED to S3 (proactive resharing). Polynomial-consistent shard repair on the
    /// BLS12-381 share format requires Lagrange interpolation at an arbitrary point, which
    /// `vsss-rs` does not expose as a library primitive (its `combine` only interpolates at
    /// x=0). Hand-rolling that interpolation would be exactly the self-built crypto we are
    /// avoiding; the master-reconstructing variant is exactly the single point S1 removes.
    /// Recovery will return as library-backed resharing under S3.
    async fn recover_shard_for_caller(
        &self,
        _caller_pubkey: &[u8],
    ) -> Result<EncryptedShard, Status> {
        Err(Status::unimplemented(
            "shard recovery is deferred to S3 (proactive resharing); \
             only initial shard assignment is supported in this build",
        ))
    }
}

// ─── Peer client ──────────────────────────────────────────────────────────────

/// Call GetDprfPartial on a peer, decrypt the response, return (shard_index, partial_bytes).
pub async fn get_dprf_partial(
    peer_url: &str,
    app_id: &str,
    material: &[u8],
    sig: &[u8],
    timestamp: i64,
    own_private_key: &[u8; 32],
) -> anyhow::Result<(u32, Vec<u8>, u64)> {
    use tonic::metadata::MetadataValue;
    use tonic::transport::Channel;

    // Bound both the TCP connect and each request so an unreachable/black-hole peer
    // (SYN dropped → connect would otherwise block for the OS SYN timeout) fails fast
    // instead of stalling the whole derivation.
    let channel = Channel::from_shared(peer_url.to_string())?
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(3))
        .connect()
        .await?;

    let mut client = proto::kms_cluster_client::KmsClusterClient::new(channel);

    let mut request = Request::new(DprfPartialRequest {
        app_id: app_id.to_string(),
        material: material.to_vec(),
    });
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(sig))?,
    );
    request.metadata_mut().insert(
        "timestamp",
        MetadataValue::try_from(timestamp.to_string())?,
    );

    let resp = client.get_dprf_partial(request).await?.into_inner();

    let partial_bytes = ecies_decrypt(own_private_key, &resp.ciphertext)
        .map_err(|e| anyhow::anyhow!("ECIES decrypt failed: {}", e))?;

    Ok((resp.shard_index, partial_bytes, resp.epoch))
}

/// Deliver one DKG/reshare round message to a peer (fire-and-forget beyond the ack).
/// `broadcast` is public; `p2p` (round 1 only) must already be ECIES-encrypted for the
/// recipient by the caller (the driver knows each peer's pubkey).
pub async fn send_dkg_round(
    peer_url: &str,
    session_id: &str,
    round: u32,
    from_index: u32,
    broadcast: Vec<u8>,
    p2p: Vec<u8>,
    sig: &[u8],
    timestamp: i64,
) -> anyhow::Result<()> {
    use tonic::metadata::MetadataValue;
    use tonic::transport::Channel;

    let channel = Channel::from_shared(peer_url.to_string())?.connect().await?;
    let mut client = proto::kms_cluster_client::KmsClusterClient::new(channel);

    let mut request = Request::new(DkgRoundMsg {
        session_id: session_id.to_string(),
        round,
        from_index,
        broadcast,
        p2p,
    });
    request
        .metadata_mut()
        .insert("signature", MetadataValue::try_from(hex::encode(sig))?);
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from(timestamp.to_string())?);

    client.dkg_round(request).await?;
    Ok(())
}

/// Ask a live committee member (`peer_url`) to join a reshare as a dealer.
pub async fn send_start_reshare(
    peer_url: &str,
    session_id: &str,
    recovering_id: u32,
    dealer_ids: Vec<u32>,
    epoch: u64,
    sig: &[u8],
    timestamp: i64,
) -> anyhow::Result<()> {
    use tonic::metadata::MetadataValue;
    use tonic::transport::Channel;

    let channel = Channel::from_shared(peer_url.to_string())?
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(3))
        .connect()
        .await?;
    let mut client = proto::kms_cluster_client::KmsClusterClient::new(channel);

    let mut request = Request::new(ReshareRequest {
        session_id: session_id.to_string(),
        recovering_id,
        dealer_ids,
        epoch,
    });
    request
        .metadata_mut()
        .insert("signature", MetadataValue::try_from(hex::encode(sig))?);
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from(timestamp.to_string())?);

    client.start_reshare(request).await?;
    Ok(())
}

// ─── Concurrent collect helper (used by server.rs /app-key handler) ───────────

/// Concurrently collect DPRF partials from all peers + own share, then combine them
/// (in-group Lagrange) into the 32-byte app key for (app_id, material). The master scalar
/// is NEVER reconstructed — this is the threshold-BLS derivation that removes the use-time
/// single point. Peer list is read from the dynamic peer table.
pub async fn collect_and_dprf(
    state: &AppState,
    app_id: &str,
    material: &[u8],
) -> Result<[u8; 32], KmsError> {
    let own = state
        .shard
        .read()
        .await
        .clone()
        .ok_or_else(|| KmsError::ConfigError("node not initialized".into()))?;

    // Own partial, computed locally from this node's share.
    let own_share =
        share_from_bytes(&own.shard_bytes).map_err(|e| KmsError::CryptoError(e.to_string()))?;
    let msg = dprf_message(app_id, material);
    let own_partial =
        dprf_partial(&own_share, &msg).map_err(|e| KmsError::CryptoError(e.to_string()))?;

    let timestamp = chrono::Utc::now().timestamp();
    let sig = sign_request(&state.signing_key.private_key, "GetDprfPartial", timestamp)
        .map_err(|e| KmsError::CryptoError(e.to_string()))?;

    let threshold = state.config.cluster.threshold as usize;

    // Collect partials until ONE epoch reaches `threshold`, then STOP and combine that epoch.
    //
    // Two invariants combine here:
    //   * Never mix epochs: partials from two different polynomials Lagrange-combine to a wrong
    //     key, so we bucket by epoch and only ever combine a single-epoch set. (Every epoch
    //     shares the same master, so any single-epoch threshold set yields the same app key —
    //     it doesn't matter which epoch fills first.)
    //   * A dead node must not affect normal use: we return as soon as some epoch has enough,
    //     never waiting for stragglers; pending peer futures (incl. an unreachable one still
    //     connecting) are dropped/cancelled on return.
    let mut buckets: std::collections::HashMap<u64, Vec<_>> = std::collections::HashMap::new();
    // Per-epoch dedup by source shard index (stale peer_table entries can yield a node twice,
    // which would feed a duplicate Lagrange identifier into the combine).
    let mut seen: std::collections::HashMap<u64, std::collections::HashSet<u32>> =
        std::collections::HashMap::new();
    let mut ready: Option<u64> = None;

    seen.entry(own.epoch).or_default().insert(own.shard_index);
    buckets.entry(own.epoch).or_default().push(own_partial);
    if buckets[&own.epoch].len() >= threshold {
        ready = Some(own.epoch);
    }

    let peer_urls = state.peer_urls().await;
    let mut peer_futures: FuturesUnordered<_> = peer_urls
        .iter()
        .map(|url| {
            get_dprf_partial(url, app_id, material, &sig, timestamp, &state.signing_key.private_key)
        })
        .collect();

    while ready.is_none() {
        match peer_futures.next().await {
            Some(Ok((idx, bytes, epoch))) => {
                if !seen.entry(epoch).or_default().insert(idx) {
                    continue;
                }
                // Parse best-effort: a peer whose gRPC + ECIES succeed can still return an
                // empty/malformed payload. Discard it individually (don't count it) rather than
                // aborting — tolerate up to n - threshold bad nodes.
                match partial_from_bytes(&bytes) {
                    Ok(p) => {
                        let bucket = buckets.entry(epoch).or_default();
                        bucket.push(p);
                        if bucket.len() >= threshold {
                            ready = Some(epoch);
                        }
                    }
                    Err(e) => tracing::warn!(shard_index = idx, epoch, error = %e, "discarding malformed partial"),
                }
            }
            Some(Err(e)) => tracing::warn!(error = %e, "peer partial collection failed"),
            // No more peers to hear from and still short of threshold in every epoch.
            None => break,
        }
    }

    let epoch = ready.ok_or_else(|| {
        let best = buckets.values().map(|b| b.len()).max().unwrap_or(0);
        KmsError::CryptoError(format!(
            "not enough valid partials in any single epoch: best {}, need {}",
            best, threshold
        ))
    })?;

    dprf_combine(&buckets[&epoch]).map_err(|e| KmsError::CryptoError(e.to_string()))
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
    let self_epoch = state.shard.read().await.as_ref().map(|s| s.epoch).unwrap_or(0);

    for target in &targets {
        match push_gossip(target, self_url, &self_eth_addr, self_epoch, &sig, timestamp).await {
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
                                    // Don't clobber a known pubkey with an empty one.
                                    if !peer.pubkey.is_empty() {
                                        e.pubkey = peer.pubkey.clone();
                                    }
                                    // Epoch is monotonic per node; take the larger so a stale
                                    // gossip entry can't drag a peer's known epoch backwards.
                                    e.epoch = e.epoch.max(peer.epoch);
                                })
                                .or_insert_with(|| {
                                    tracing::info!(peer_url = %peer.grpc_url, "gossip: discovered new peer");
                                    PeerInfo {
                                        grpc_url: peer.grpc_url.clone(),
                                        last_seen: now,
                                        pubkey: peer.pubkey.clone(),
                                        epoch: peer.epoch,
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
    self_epoch: u64,
    sig: &[u8],
    timestamp: i64,
) -> anyhow::Result<Vec<NodeInfo>> {
    use tonic::metadata::MetadataValue;
    use tonic::transport::Channel;

    let channel = Channel::from_shared(peer_url.to_string())?
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(3))
        .connect()
        .await?;

    let mut client = proto::kms_cluster_client::KmsClusterClient::new(channel);

    let mut request = Request::new(GossipRequest {
        // pubkey left empty: the responder authoritatively records our pubkey by recovering
        // it from the request signature (see the gossip handler), not from this field.
        self_info: Some(NodeInfo {
            grpc_url: self_url.to_string(),
            eth_addr: self_eth_addr.to_string(),
            pubkey: Vec::new(),
            epoch: self_epoch,
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
