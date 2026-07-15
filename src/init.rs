use std::num::NonZeroUsize;
use std::time::Duration;

use anyhow::{anyhow, Result};
use gennaro_dkg::{Parameters, RefreshParticipant, SecretParticipant};
use group::GroupEncoding;
use tracing::info;

use crate::{
    chain::get_signer_addresses,
    crypto::{
        blsful_share_scalar, ecies_decrypt, gennaro_share_to_blsful, share_from_bytes,
        share_to_bytes, sign_request, split_master, DkgGroup, DkgScalar,
    },
    dkg::{run_session, SessionPeer},
    server::{AppState, ShardState},
};

/// Per-round wall-clock budget for a DKG/reshare session.
const DKG_ROUND_TIMEOUT: Duration = Duration::from_secs(60);

/// Epoch stamped on the shares produced by the initial distributed genesis. Every subsequent
/// reshare/refresh/recovery advances the epoch by one.
pub const GENESIS_EPOCH: u64 = 1;

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
        epoch: GENESIS_EPOCH,
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
        epoch: GENESIS_EPOCH,
    })
}

// ─── Distributed cluster formation (genesis DKG / recovery) ─────────────────────

/// Assemble the DKG participant set from the on-chain nodeList + gossip peer_table.
/// Returns `None` until every other nodeList member is known *with its pubkey* (full
/// membership) so genesis waits for gossip convergence. Otherwise returns
/// Committee membership assembled from the on-chain nodeList + gossip peer_table.
struct Membership {
    /// This node's 1-based nodeList position / participant id.
    own_id: u32,
    /// Other nodeList members that are discovered (pubkey known) AND currently LIVE (direct
    /// gossip contact within the liveness window), each carrying its gossiped epoch. Down or
    /// merely-relayed members are absent from this list — a dead node must never be selected
    /// into a session (it would stall every round at the barrier).
    peers: Vec<SessionPeer>,
    threshold: usize,
    /// Nominal committee size = `cluster.total_nodes` (NOT the count discovered).
    total: usize,
    /// True iff every nodeList member besides self is present in `peers` (everyone alive).
    all_discovered: bool,
}

impl Membership {
    /// Live peers that currently hold a share (epoch > 0) — the candidate reshare dealers.
    /// (`peers` is already liveness-filtered by `assemble_participants`.)
    fn live_dealers(&self) -> Vec<SessionPeer> {
        self.peers.iter().filter(|p| p.epoch > 0).cloned().collect()
    }
}

/// Assemble the committee from chain + gossip. Returns `None` only while the on-chain nodeList
/// hasn't grown to the configured size yet (registration is one-at-a-time). Otherwise returns
/// whoever is currently discovered — callers decide sufficiency: genesis needs
/// `all_discovered`, recovery needs only `>= threshold` live share-holders.
async fn assemble_participants(state: &AppState) -> Result<Option<Membership>> {
    let node_list = get_signer_addresses(
        &state.config.chain.rpc_url,
        &state.config.chain.contract_address,
        &state.config.tapp.app_id,
    )
    .await
    .map_err(|e| anyhow!("nodeList lookup failed: {}", e))?;

    // Genesis is a fixed `total_nodes`-of-`threshold` DKG; wait until the on-chain nodeList has
    // grown to the full configured size (nodes register one at a time — a partial list would
    // give the wrong `total`).
    let total = state.config.cluster.total_nodes as usize;
    if node_list.len() < total {
        return Ok(None);
    }

    let own_addr = state.signing_key.eth_address;
    let own_pos = node_list
        .iter()
        .position(|a| a.0 == own_addr)
        .ok_or_else(|| anyhow!("this node's address is not in the on-chain nodeList"))?;
    let own_id = own_pos as u32 + 1;

    let table = state.peer_table.read().await;
    let now = chrono::Utc::now().timestamp();
    let mut peers = Vec::new();
    let mut all_discovered = true;
    for (i, addr) in node_list.iter().enumerate() {
        let id = i as u32 + 1;
        if id == own_id {
            continue;
        }
        match table.get(&addr.0) {
            // Discovered AND live: pubkey known + direct gossip contact within the window.
            // A known-but-dead entry (e.g. kept alive only by mesh relay) must NOT be picked
            // into a session — it would stall every DKG/reshare round at the barrier.
            Some(info) if !info.pubkey.is_empty() && info.is_live(now) => {
                peers.push(SessionPeer {
                    id,
                    grpc_url: info.grpc_url.clone(),
                    pubkey: info.pubkey.clone(),
                    epoch: info.epoch,
                })
            }
            // A nodeList member that is down / not yet discovered. Don't bail — note the gap
            // so genesis can wait while recovery can proceed on the live subset.
            _ => all_discovered = false,
        }
    }

    Ok(Some(Membership {
        own_id,
        peers,
        threshold: state.config.cluster.threshold as usize,
        total,
        all_discovered,
    }))
}

/// Resolve an explicit set of participant ids to `SessionPeer`s via nodeList + peer_table
/// (excluding self and id 0). Used by the reshare dealer, whose session membership is the
/// exact `{dealers} ∪ {recovering}` set from the request — not the full committee.
async fn resolve_peers(state: &AppState, ids: &[u32], own_id: u32) -> Result<Vec<SessionPeer>> {
    let node_list = get_signer_addresses(
        &state.config.chain.rpc_url,
        &state.config.chain.contract_address,
        &state.config.tapp.app_id,
    )
    .await
    .map_err(|e| anyhow!("nodeList lookup failed: {}", e))?;
    let table = state.peer_table.read().await;
    let mut peers = Vec::new();
    for &id in ids {
        if id == 0 || id == own_id {
            continue;
        }
        let addr = node_list
            .get((id - 1) as usize)
            .ok_or_else(|| anyhow!("participant id {} out of nodeList range", id))?;
        match table.get(&addr.0) {
            Some(info) if !info.pubkey.is_empty() => peers.push(SessionPeer {
                id,
                grpc_url: info.grpc_url.clone(),
                pubkey: info.pubkey.clone(),
                epoch: info.epoch,
            }),
            _ => return Err(anyhow!("reshare participant {} not discovered via gossip", id)),
        }
    }
    Ok(peers)
}

/// Majority quorum for the nominal committee: an epoch-changing reshare must involve more than
/// half the committee so two disjoint subsets can never fork divergent epochs (split-brain).
fn majority(total: usize) -> usize {
    total / 2 + 1
}

/// Store a freshly-obtained share + group pubkey, and emit the sealed base64 blob to the log
/// (`SEALED_SHARE=<b64url>`) so the deploy pipeline can re-inject it via `KMS_SEALED_SHARE` on
/// the next restart. The blob is ECIES-sealed to this node's own TEE key — safe to log.
async fn store_share(state: &AppState, shard: ShardState, group_pubkey: Vec<u8>) {
    match crate::crypto::pubkey_from_private(&state.signing_key.private_key) {
        Ok(pk) => {
            let rec = crate::seal::SealedShareV1::new(
                shard.shard_index,
                shard.epoch,
                group_pubkey.clone(),
                shard.shard_bytes.clone(),
            );
            match crate::seal::seal_b64(&pk, &rec) {
                Ok(b64) => info!(epoch = shard.epoch, "SEALED_SHARE={}", b64),
                Err(e) => tracing::warn!(error = %e, "failed to seal share for persistence"),
            }
        }
        Err(e) => tracing::warn!(error = %e, "failed to derive own pubkey for sealing"),
    }
    *state.group_pubkey.write().await = Some(group_pubkey);
    *state.shard.write().await = Some(shard);
}

/// Boot-time persistence: if `KMS_SEALED_SHARE` is set, unseal it with this node's TEE key and
/// adopt the share IF it is still current. Returns true if a fresh share was loaded (then
/// `form_cluster` returns immediately — no rejoin). Absent / wrong-identity / stale → false →
/// normal genesis/rejoin. A master change is the operator's call: they omit the env to force a
/// fresh start (clear it on any re-genesis).
async fn try_reload_sealed(state: &AppState) -> bool {
    let b64 = match std::env::var("KMS_SEALED_SHARE") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => return false, // no blob → operator wants a fresh start
    };
    let rec = match crate::seal::unseal_b64(&b64, &state.signing_key.private_key) {
        Ok(Some(r)) => r,
        Ok(None) => {
            info!("KMS_SEALED_SHARE not usable by this TEE identity — will rejoin");
            return false;
        }
        Err(e) => {
            tracing::warn!(error = %e, "sealed share corrupt — will rejoin");
            return false;
        }
    };

    // Freshness: don't adopt a share the cluster has already moved past. Give gossip a moment to
    // learn peers' epochs (own shard isn't loaded yet, so known_epoch = max peer epoch), then
    // compare. If we're isolated (no peers) we adopt it — it's our best last-known-good.
    for _ in 0..6 {
        if !state.peer_table.read().await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    let cluster_epoch = state.known_epoch().await;
    if rec.epoch < cluster_epoch {
        info!(
            share_epoch = rec.epoch,
            cluster_epoch, "sealed share is stale — discarding and rejoining"
        );
        return false;
    }

    info!(
        epoch = rec.epoch,
        shard_index = rec.shard_index,
        "reloaded sealed share from KMS_SEALED_SHARE (no rejoin needed)"
    );
    *state.group_pubkey.write().await = Some(rec.master_id);
    *state.shard.write().await = Some(ShardState {
        shard_index: rec.shard_index,
        shard_bytes: rec.share,
        epoch: rec.epoch,
    });
    true
}

/// Run distributed genesis DKG: all N nodes jointly generate the master (no dealer). On
/// success this node holds a share of the shared key and the cluster's group public key.
async fn run_genesis(
    state: &AppState,
    own_id: u32,
    peers: Vec<SessionPeer>,
    threshold: usize,
    total: usize,
) -> Result<()> {
    let params = Parameters::<DkgGroup>::new(
        NonZeroUsize::new(threshold).ok_or_else(|| anyhow!("threshold must be > 0"))?,
        NonZeroUsize::new(total).ok_or_else(|| anyhow!("total_nodes must be > 0"))?,
    );
    let participant = SecretParticipant::<DkgGroup>::new(
        NonZeroUsize::new(own_id as usize).unwrap(),
        params,
    )
    .map_err(|e| anyhow!("genesis participant init: {:?}", e))?;

    let session_id = format!("genesis:{}", state.config.tapp.app_id);
    let (share, pk) = run_session(state, &session_id, participant, &peers, DKG_ROUND_TIMEOUT).await?;

    let sk_share = gennaro_share_to_blsful(own_id as usize, share);
    let pk_bytes = pk.to_bytes().as_ref().to_vec();
    store_share(
        state,
        ShardState {
            shard_index: own_id,
            shard_bytes: share_to_bytes(&sk_share),
            epoch: GENESIS_EPOCH,
        },
        pk_bytes.clone(),
    )
    .await;
    info!(own_id, epoch = GENESIS_EPOCH, group_pubkey = %hex::encode(&pk_bytes), "genesis DKG complete — share and group public key stored");
    Ok(())
}

/// Recovering-node side of reshare recovery: trigger the live committee to reshare and
/// rejoin as a `RefreshParticipant`, coming out with a fresh, consistent share of the same
/// master. The survivors act as dealers (see `run_reshare_dealer`); the master is preserved.
async fn run_reshare_recovery(state: &AppState, m: Membership) -> Result<()> {
    let own_id = m.own_id;
    let threshold = m.threshold;
    let total = m.total;

    // Dealers = the live share-holders (epoch > 0). A dead / shardless member is simply not a
    // dealer — we do NOT wait for full membership (issue #4). Need >= threshold to reconstruct
    // the master, and a majority of the committee participating (dealers + this recovering
    // node) so two disjoint subsets can't fork divergent epochs (split-brain).
    let dealers = m.live_dealers();
    if dealers.len() < threshold {
        return Err(anyhow!(
            "cannot recover yet: {} live share-holders discovered, need >= threshold {}",
            dealers.len(),
            threshold
        ));
    }
    let participants = dealers.len() + 1; // + this recovering node
    if participants < majority(total) {
        return Err(anyhow!(
            "cannot recover yet: {} participants, need a majority ({}) of {} to avoid split-brain",
            participants,
            majority(total),
            total
        ));
    }

    // New polynomial epoch: strictly above whatever the live committee currently holds
    // (learned via gossip). All participants stamp their refreshed share with this, so the
    // recovered node lands on the same epoch as the dealers rather than a stale one.
    let new_epoch = state.known_epoch().await + 1;
    let nonce = chrono::Utc::now().timestamp();
    let session_id = format!("reshare:{}:{}:{}", state.config.tapp.app_id, new_epoch, nonce);
    let mut dealer_ids: Vec<u32> = dealers.iter().map(|p| p.id).collect();
    dealer_ids.sort_unstable();

    // Trigger each live dealer to participate.
    let ts = chrono::Utc::now().timestamp();
    let sig = sign_request(&state.signing_key.private_key, "StartReshare", ts)?;
    for peer in &dealers {
        if let Err(e) = crate::grpc::send_start_reshare(
            &peer.grpc_url,
            &session_id,
            own_id,
            dealer_ids.clone(),
            new_epoch,
            &sig,
            ts,
        )
        .await
        {
            tracing::warn!(peer = %peer.grpc_url, error = %e, "failed to trigger reshare dealer");
        }
    }

    let params = Parameters::<DkgGroup>::new(
        NonZeroUsize::new(threshold).ok_or_else(|| anyhow!("threshold must be > 0"))?,
        NonZeroUsize::new(total).ok_or_else(|| anyhow!("total_nodes must be > 0"))?,
    );
    let participant =
        RefreshParticipant::<DkgGroup>::new(NonZeroUsize::new(own_id as usize).unwrap(), params)
            .map_err(|e| anyhow!("reshare (recovering) participant init: {:?}", e))?;

    // Session peers = the dealers only (the recovering node exchanges rounds with them).
    let (share, pk) = run_session(state, &session_id, participant, &dealers, DKG_ROUND_TIMEOUT).await?;
    let sk_share = gennaro_share_to_blsful(own_id as usize, share);
    let pk_bytes = pk.to_bytes().as_ref().to_vec();
    store_share(
        state,
        ShardState {
            shard_index: own_id,
            shard_bytes: share_to_bytes(&sk_share),
            epoch: new_epoch,
        },
        pk_bytes.clone(),
    )
    .await;
    info!(own_id, epoch = new_epoch, group_pubkey = %hex::encode(&pk_bytes), "reshare recovery complete — share repaired, master preserved");
    Ok(())
}

/// Dealer side of a reshare, invoked from the `StartReshare` RPC handler on a live committee
/// member. Contributes our existing share (so the polynomial's intercept — the master —
/// is preserved) and replaces our stored share with the refreshed one. Refuses to update if
/// the reshare would change the group public key.
pub async fn run_reshare_dealer(
    state: &AppState,
    session_id: String,
    recovering_id: u32,
    dealer_ids: Vec<u32>,
    new_epoch: u64,
) -> Result<()> {
    let threshold = state.config.cluster.threshold as usize;
    let total = state.config.cluster.total_nodes as usize;

    // Our participant id = position in the on-chain nodeList.
    let node_list = get_signer_addresses(
        &state.config.chain.rpc_url,
        &state.config.chain.contract_address,
        &state.config.tapp.app_id,
    )
    .await
    .map_err(|e| anyhow!("nodeList lookup failed: {}", e))?;
    let own_id = node_list
        .iter()
        .position(|a| a.0 == state.signing_key.eth_address)
        .map(|p| p as u32 + 1)
        .ok_or_else(|| anyhow!("reshare dealer: this node is not in the nodeList"))?;

    let own_index = dealer_ids
        .iter()
        .position(|id| *id == own_id)
        .ok_or_else(|| anyhow!("reshare dealer: own id {} not in dealer set", own_id))?;

    // Monotonic epoch: never reshare backwards into an epoch we've already passed.
    let cur_epoch = state.shard.read().await.as_ref().map(|s| s.epoch).unwrap_or(0);
    if new_epoch <= cur_epoch {
        return Err(anyhow!(
            "reshare dealer: target epoch {} not ahead of current {}",
            new_epoch,
            cur_epoch
        ));
    }

    let own_share_bytes = state
        .shard
        .read()
        .await
        .as_ref()
        .ok_or_else(|| anyhow!("reshare dealer: no local share"))?
        .shard_bytes
        .clone();
    let own_scalar = blsful_share_scalar(&share_from_bytes(&own_share_bytes)?);

    // Session participants = the dealer set plus the recovering node (0 = pure refresh, no
    // recovering node). Resolve exactly those from gossip — NOT the full committee, so an
    // absent member doesn't stall the session.
    let mut participant_ids = dealer_ids.clone();
    if recovering_id != 0 {
        participant_ids.push(recovering_id);
    }
    let peers = resolve_peers(state, &participant_ids, own_id).await?;

    let dealer_scalars: Vec<DkgScalar> =
        dealer_ids.iter().map(|id| DkgScalar::from(*id as u64)).collect();

    let params = Parameters::<DkgGroup>::new(
        NonZeroUsize::new(threshold).ok_or_else(|| anyhow!("threshold must be > 0"))?,
        NonZeroUsize::new(total).ok_or_else(|| anyhow!("total_nodes must be > 0"))?,
    );
    let participant = SecretParticipant::<DkgGroup>::with_secret(
        NonZeroUsize::new(own_id as usize).unwrap(),
        params,
        own_scalar,
        &dealer_scalars,
        own_index,
    )
    .map_err(|e| anyhow!("reshare dealer participant init: {:?}", e))?;

    let (new_share, new_pk) =
        run_session(state, &session_id, participant, &peers, DKG_ROUND_TIMEOUT).await?;

    // Master must be preserved: refuse to replace our share if the group pubkey changed.
    let new_pk_bytes = new_pk.to_bytes().as_ref().to_vec();
    if let Some(old) = state.group_pubkey.read().await.as_ref() {
        if *old != new_pk_bytes {
            return Err(anyhow!(
                "reshare changed the group public key — aborting share update to avoid corruption"
            ));
        }
    }
    let sk_share = gennaro_share_to_blsful(own_id as usize, new_share);
    store_share(
        state,
        ShardState {
            shard_index: own_id,
            shard_bytes: share_to_bytes(&sk_share),
            epoch: new_epoch,
        },
        new_pk_bytes.clone(),
    )
    .await;
    info!(own_id, epoch = new_epoch, group_pubkey = %hex::encode(&new_pk_bytes), "reshare dealer complete — share refreshed, master preserved");
    Ok(())
}

/// Proactively refresh the whole live committee's shares — no membership change, no node
/// lost a share. Every node reshares its existing share (all act as dealers), producing a
/// fresh polynomial with the SAME intercept (master): shares are re-randomized so any
/// previously-leaked share becomes useless (proactive security), while every derived app
/// key is unchanged. Triggered manually (e.g. via `/refresh`); an operator can run it
/// periodically. Reuses the dealer path — a refresh is just a reshare where the dealer set
/// is the full committee and there is no recovering `RefreshParticipant`.
pub async fn trigger_refresh(state: &AppState) -> Result<()> {
    if state.shard.read().await.is_none() {
        return Err(anyhow!("cannot refresh: this node has no share"));
    }
    let m = assemble_participants(state)
        .await?
        .ok_or_else(|| anyhow!("refresh: nodeList not yet at configured size"))?;
    // Refresh is proactive and can wait: require the WHOLE committee healthy so no node is
    // left behind on a stale polynomial. If a member is permanently down, resize it out first,
    // then refresh the healthy committee.
    if !m.all_discovered {
        return Err(anyhow!(
            "refresh requires all {} members healthy; some are not discovered — wait or resize",
            m.total
        ));
    }
    let own_id = m.own_id;

    // Dealer set = the entire committee (every node contributes its share).
    let mut dealer_ids: Vec<u32> = m.peers.iter().map(|p| p.id).collect();
    dealer_ids.push(own_id);
    dealer_ids.sort_unstable();
    let peers = m.peers;

    let new_epoch = state.known_epoch().await + 1;
    let nonce = chrono::Utc::now().timestamp();
    let session_id = format!("refresh:{}:{}:{}", state.config.tapp.app_id, new_epoch, nonce);

    // Tell every peer to join the refresh as a dealer (recovering_id = 0: pure refresh).
    let ts = chrono::Utc::now().timestamp();
    let sig = sign_request(&state.signing_key.private_key, "StartReshare", ts)?;
    for peer in &peers {
        if let Err(e) = crate::grpc::send_start_reshare(
            &peer.grpc_url,
            &session_id,
            0,
            dealer_ids.clone(),
            new_epoch,
            &sig,
            ts,
        )
        .await
        {
            tracing::warn!(peer = %peer.grpc_url, error = %e, "failed to trigger refresh dealer");
        }
    }

    info!(own_id, epoch = new_epoch, session = %session_id, "proactive refresh started");
    run_reshare_dealer(state, session_id, 0, dealer_ids, new_epoch).await
}

/// Background cluster formation, run once after the servers + gossip start.
///
/// 1. Wait for full membership (all nodeList members discovered via gossip, with pubkeys).
/// 2. Decide fresh vs established by probing peers (reuses `join_cluster`'s classification):
///    - no peer initialized → **fresh** → run genesis DKG together with all nodes.
///    - a peer is already initialized → **established** → recover our share via reshare.
///      DISASTER GATE: an established cluster must NEVER trigger genesis (would fork it).
pub async fn form_cluster(state: AppState) {
    // Persistence first: if a valid, current sealed share was injected via KMS_SEALED_SHARE,
    // adopt it and skip rejoin entirely (this is the only path that works at the threshold
    // floor, where rejoin is impossible).
    if state.shard.read().await.is_none() {
        try_reload_sealed(&state).await;
    }

    loop {
        // Done once we hold a share (genesis/recovery/sealed-reload succeeded).
        if state.shard.read().await.is_some() {
            return;
        }

        // Assemble whoever is registered on-chain + discovered via gossip (may be a subset).
        let m = match assemble_participants(&state).await {
            Ok(Some(m)) => m,
            Ok(None) => {
                info!("waiting for the on-chain nodeList to reach the configured size…");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
            Err(e) => {
                tracing::warn!(error = %e, "membership assembly failed; retrying");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        let attempt = match join_cluster(&state).await {
            Ok(JoinResult::Joined) => {
                info!("obtained a shard via assignment (legacy path)");
                Ok(())
            }
            Ok(JoinResult::NoSeedReachable) => {
                // Genesis is all-or-nothing: only start once every member is discovered.
                if !m.all_discovered {
                    info!("fresh cluster — waiting for all members before genesis DKG");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                info!(own_id = m.own_id, total = m.total, threshold = m.threshold, "fresh cluster — running genesis DKG");
                run_genesis(&state, m.own_id, m.peers, m.threshold, m.total).await
            }
            Ok(JoinResult::SeedReachableDeclined) => {
                // Established cluster, no local share → recover via reshare from any
                // >= threshold live share-holders (issue #4: do NOT require full membership).
                info!(own_id = m.own_id, "cluster established — recovering our share via reshare");
                run_reshare_recovery(&state, m).await
            }
            Err(e) => Err(anyhow!("cluster probe failed: {}", e)),
        };

        // Retry on failure: nodes register/boot at slightly different times, so a genesis or
        // reshare round can time out before every participant is in the session. Keep retrying
        // until the whole committee lines up and one attempt succeeds (then the top-of-loop
        // shard check returns).
        if let Err(e) = attempt {
            tracing::warn!(error = %e, "cluster formation attempt failed; retrying in 10s");
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }
}
