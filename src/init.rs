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

// ─── Distributed cluster formation (genesis DKG / recovery) ─────────────────────

/// Assemble the DKG participant set from the on-chain nodeList + gossip peer_table.
/// Returns `None` until every other nodeList member is known *with its pubkey* (full
/// membership) so genesis waits for gossip convergence. Otherwise returns
/// `(own_id, other_peers, threshold, total)` where ids are 1-based nodeList positions.
#[allow(clippy::type_complexity)]
async fn assemble_participants(
    state: &AppState,
) -> Result<Option<(u32, Vec<SessionPeer>, usize, usize)>> {
    let node_list = get_signer_addresses(
        &state.config.chain.rpc_url,
        &state.config.chain.contract_address,
        &state.config.tapp.app_id,
    )
    .await
    .map_err(|e| anyhow!("nodeList lookup failed: {}", e))?;

    let own_addr = state.signing_key.eth_address;
    let own_pos = node_list
        .iter()
        .position(|a| a.0 == own_addr)
        .ok_or_else(|| anyhow!("this node's address is not in the on-chain nodeList"))?;
    let own_id = own_pos as u32 + 1;

    let table = state.peer_table.read().await;
    let mut peers = Vec::new();
    for (i, addr) in node_list.iter().enumerate() {
        let id = i as u32 + 1;
        if id == own_id {
            continue;
        }
        match table.get(&addr.0) {
            Some(info) if !info.pubkey.is_empty() => peers.push(SessionPeer {
                id,
                grpc_url: info.grpc_url.clone(),
                pubkey: info.pubkey.clone(),
            }),
            // A nodeList member we haven't fully discovered yet (no URL/pubkey) → not ready.
            _ => return Ok(None),
        }
    }

    Ok(Some((
        own_id,
        peers,
        state.config.cluster.threshold as usize,
        node_list.len(),
    )))
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
    *state.shard.write().await = Some(ShardState {
        shard_index: own_id,
        shard_bytes: share_to_bytes(&sk_share),
    });
    *state.group_pubkey.write().await = Some(pk.to_bytes().as_ref().to_vec());
    info!(own_id, "genesis DKG complete — share and group public key stored");
    Ok(())
}

/// Recovering-node side of reshare recovery: trigger the live committee to reshare and
/// rejoin as a `RefreshParticipant`, coming out with a fresh, consistent share of the same
/// master. The survivors act as dealers (see `run_reshare_dealer`); the master is preserved.
async fn run_reshare_recovery(
    state: &AppState,
    own_id: u32,
    peers: Vec<SessionPeer>,
    threshold: usize,
    total: usize,
) -> Result<()> {
    let epoch = chrono::Utc::now().timestamp();
    let session_id = format!("reshare:{}:{}", state.config.tapp.app_id, epoch);
    let mut dealer_ids: Vec<u32> = peers.iter().map(|p| p.id).collect();
    dealer_ids.sort_unstable();

    // Trigger each survivor to participate as a dealer.
    let ts = chrono::Utc::now().timestamp();
    let sig = sign_request(&state.signing_key.private_key, "StartReshare", ts)?;
    for peer in &peers {
        if let Err(e) = crate::grpc::send_start_reshare(
            &peer.grpc_url,
            &session_id,
            own_id,
            dealer_ids.clone(),
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

    let (share, pk) = run_session(state, &session_id, participant, &peers, DKG_ROUND_TIMEOUT).await?;
    let sk_share = gennaro_share_to_blsful(own_id as usize, share);
    *state.shard.write().await = Some(ShardState {
        shard_index: own_id,
        shard_bytes: share_to_bytes(&sk_share),
    });
    *state.group_pubkey.write().await = Some(pk.to_bytes().as_ref().to_vec());
    info!(own_id, "reshare recovery complete — share repaired, master preserved");
    Ok(())
}

/// Dealer side of a reshare, invoked from the `StartReshare` RPC handler on a live committee
/// member. Contributes our existing share (so the polynomial's intercept — the master —
/// is preserved) and replaces our stored share with the refreshed one. Refuses to update if
/// the reshare would change the group public key.
pub async fn run_reshare_dealer(
    state: &AppState,
    session_id: String,
    dealer_ids: Vec<u32>,
) -> Result<()> {
    let (own_id, peers, threshold, total) = assemble_participants(state)
        .await?
        .ok_or_else(|| anyhow!("reshare dealer: full cluster membership not available"))?;

    let own_share_bytes = state
        .shard
        .read()
        .await
        .as_ref()
        .ok_or_else(|| anyhow!("reshare dealer: no local share"))?
        .shard_bytes
        .clone();
    let own_scalar = blsful_share_scalar(&share_from_bytes(&own_share_bytes)?);

    let dealer_scalars: Vec<DkgScalar> =
        dealer_ids.iter().map(|id| DkgScalar::from(*id as u64)).collect();
    let own_index = dealer_ids
        .iter()
        .position(|id| *id == own_id)
        .ok_or_else(|| anyhow!("reshare dealer: own id {} not in dealer set", own_id))?;

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
    *state.shard.write().await = Some(ShardState {
        shard_index: own_id,
        shard_bytes: share_to_bytes(&sk_share),
    });
    info!(own_id, "reshare dealer complete — share refreshed, master preserved");
    Ok(())
}

/// Background cluster formation, run once after the servers + gossip start.
///
/// 1. Wait for full membership (all nodeList members discovered via gossip, with pubkeys).
/// 2. Decide fresh vs established by probing peers (reuses `join_cluster`'s classification):
///    - no peer initialized → **fresh** → run genesis DKG together with all nodes.
///    - a peer is already initialized → **established** → recover our share via reshare.
///      DISASTER GATE: an established cluster must NEVER trigger genesis (would fork it).
pub async fn form_cluster(state: AppState) {
    if state.shard.read().await.is_some() {
        return; // already have a shard (e.g. future persistent storage)
    }

    let (own_id, peers, threshold, total) = loop {
        match assemble_participants(&state).await {
            Ok(Some(p)) => break p,
            Ok(None) => {
                info!("waiting for full cluster membership (gossip convergence)…");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "membership assembly failed; retrying");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };

    match join_cluster(&state).await {
        Ok(JoinResult::Joined) => {
            info!("obtained a shard via assignment (legacy path)");
        }
        Ok(JoinResult::NoSeedReachable) => {
            info!(own_id, total, threshold, "fresh cluster — running genesis DKG");
            if let Err(e) = run_genesis(&state, own_id, peers, threshold, total).await {
                tracing::error!(error = %e, "genesis DKG failed");
            }
        }
        Ok(JoinResult::SeedReachableDeclined) => {
            // Established cluster, we have no shard → recover our share via reshare from the
            // live committee (never regenerate a master).
            info!(own_id, "cluster established — recovering our share via reshare");
            if let Err(e) = run_reshare_recovery(&state, own_id, peers, threshold, total).await {
                tracing::error!(error = %e, "reshare recovery failed — this node stays without a shard");
            }
        }
        Err(e) => tracing::error!(error = %e, "cluster probe failed; not forming a key"),
    }
}
