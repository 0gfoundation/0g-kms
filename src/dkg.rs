//! Distributed DKG / reshare session driver over the `DkgRound` push transport.
//!
//! Drives one gennaro-dkg participant through the 5 rounds, exchanging messages with the
//! other participants: each round's broadcast goes to every peer, and the round-1 p2p share
//! is ECIES-encrypted per recipient. A per-round barrier waits for every expected
//! participant before advancing. Generic over the participant impl, so the same driver runs
//! genesis (fresh `SecretParticipant`), reshare dealers (`SecretParticipant::with_secret`)
//! and a recovering node (`RefreshParticipant`).
//!
//! The recipient side is `grpc::dkg_round` (buffers into `AppState.dkg_sessions`); this
//! module is the sender/driver side. The resulting scalar share bridges into a blsful
//! `SecretKeyShare` via `crypto::gennaro_share_to_blsful` — the DPRF path is unchanged.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use anyhow::{anyhow, Result};
use gennaro_dkg::{
    Participant, ParticipantImpl, Round1BroadcastData, Round1P2PData, Round2EchoBroadcastData,
    Round3BroadcastData, Round4EchoBroadcastData,
};

use crate::crypto::{ecies_encrypt, sign_request, DkgGroup, DkgScalar};
use crate::grpc::send_dkg_round;
use crate::server::AppState;

/// One other participant in a session (self is excluded).
pub struct SessionPeer {
    /// 1-based participant id (nodeList position).
    pub id: u32,
    pub grpc_url: String,
    /// Uncompressed secp256k1 pubkey (65 bytes) for round-1 p2p ECIES.
    pub pubkey: Vec<u8>,
}

fn ser<T: serde::Serialize>(v: &T) -> Result<Vec<u8>> {
    serde_bare::to_vec(v).map_err(|e| anyhow!("dkg serialize failed: {}", e))
}
fn de<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T> {
    serde_bare::from_slice(b).map_err(|e| anyhow!("dkg deserialize failed: {}", e))
}

/// Await round `round` until messages from all `expected` participant ids are buffered.
/// Returns `from_index -> (broadcast_bytes, decrypted_p2p_bytes)`.
async fn await_round(
    state: &AppState,
    session_id: &str,
    round: u32,
    expected: &[u32],
    timeout: Duration,
) -> Result<HashMap<u32, (Vec<u8>, Vec<u8>)>> {
    // Get (or create) the session's notify handle so we don't miss wakeups.
    let notify = {
        let mut sessions = state.dkg_sessions.write().await;
        sessions
            .entry(session_id.to_string())
            .or_default()
            .notify
            .clone()
    };
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        // Register for notification BEFORE checking, to avoid a lost wakeup.
        let notified = notify.notified();
        {
            let sessions = state.dkg_sessions.read().await;
            if let Some(msgs) = sessions.get(session_id).and_then(|s| s.rounds.get(&round)) {
                if expected.iter().all(|id| msgs.contains_key(id)) {
                    return Ok(msgs.clone());
                }
            }
        }
        if tokio::time::timeout_at(deadline, notified).await.is_err() {
            return Err(anyhow!(
                "DKG session '{}' round {} timed out waiting for peers",
                session_id,
                round
            ));
        }
    }
}

/// Send this node's round message to every peer (round-1 also carries per-peer ECIES p2p).
async fn broadcast_round(
    state: &AppState,
    session_id: &str,
    round: u32,
    own_id: u32,
    broadcast: Vec<u8>,
    p2p_per_peer: &HashMap<u32, Vec<u8>>,
    peers: &[SessionPeer],
) -> Result<()> {
    let ts = chrono::Utc::now().timestamp();
    let sig = sign_request(&state.signing_key.private_key, "DkgRound", ts)?;
    let sends = peers.iter().map(|peer| {
        let p2p = p2p_per_peer.get(&peer.id).cloned().unwrap_or_default();
        let bcast = broadcast.clone();
        let sig = sig.clone();
        let sid = session_id.to_string();
        let url = peer.grpc_url.clone();
        async move {
            if let Err(e) =
                send_dkg_round(&url, &sid, round, own_id, bcast, p2p, &sig, ts).await
            {
                tracing::warn!(peer = %url, round, error = %e, "dkg round send failed");
            }
        }
    });
    futures::future::join_all(sends).await;
    Ok(())
}

/// Drive a full 5-round session and return `(secret_share_scalar, group_public_key)`.
pub async fn run_session<I>(
    state: &AppState,
    session_id: &str,
    mut participant: Participant<I, DkgGroup>,
    peers: &[SessionPeer],
    round_timeout: Duration,
) -> Result<(DkgScalar, DkgGroup)>
where
    I: ParticipantImpl<DkgGroup> + Default,
{
    let own_id = participant.get_id() as u32;
    let expected: Vec<u32> = peers.iter().map(|p| p.id).collect();
    tracing::info!(session = %session_id, own_id, peers = expected.len(), "DKG session starting");

    // ── Round 1: broadcast commitments + per-peer ECIES-encrypted p2p share ──
    let (b1, p2p1) = participant.round1().map_err(|e| anyhow!("round1: {:?}", e))?;
    let b1_bytes = ser(&b1)?;
    let mut p2p_enc: HashMap<u32, Vec<u8>> = HashMap::new();
    for peer in peers {
        let share = p2p1
            .get(&(peer.id as usize))
            .ok_or_else(|| anyhow!("missing round1 p2p for peer {}", peer.id))?;
        let enc = ecies_encrypt(&peer.pubkey, &ser(share)?)
            .map_err(|e| anyhow!("round1 p2p ecies for peer {}: {}", peer.id, e))?;
        p2p_enc.insert(peer.id, enc);
    }
    broadcast_round(state, session_id, 1, own_id, b1_bytes, &p2p_enc, peers).await?;
    let r1 = await_round(state, session_id, 1, &expected, round_timeout).await?;

    let mut bmap1: BTreeMap<usize, Round1BroadcastData<DkgGroup>> = BTreeMap::new();
    let mut pmap1: BTreeMap<usize, Round1P2PData> = BTreeMap::new();
    for (from, (bcast, p2p)) in &r1 {
        bmap1.insert(*from as usize, de(bcast)?);
        pmap1.insert(*from as usize, de(p2p)?);
    }
    let b2 = participant
        .round2(bmap1, pmap1)
        .map_err(|e| anyhow!("round2: {:?}", e))?;

    // ── Round 2 (broadcast only) ──
    broadcast_round(state, session_id, 2, own_id, ser(&b2)?, &HashMap::new(), peers).await?;
    let r2 = await_round(state, session_id, 2, &expected, round_timeout).await?;
    // rounds 3+ take the full map INCLUDING self's own broadcast.
    let mut bmap2: BTreeMap<usize, Round2EchoBroadcastData> = BTreeMap::new();
    bmap2.insert(own_id as usize, b2);
    for (from, (bcast, _)) in &r2 {
        bmap2.insert(*from as usize, de(bcast)?);
    }
    let b3 = participant.round3(&bmap2).map_err(|e| anyhow!("round3: {:?}", e))?;

    // ── Round 3 ──
    broadcast_round(state, session_id, 3, own_id, ser(&b3)?, &HashMap::new(), peers).await?;
    let r3 = await_round(state, session_id, 3, &expected, round_timeout).await?;
    let mut bmap3: BTreeMap<usize, Round3BroadcastData<DkgGroup>> = BTreeMap::new();
    bmap3.insert(own_id as usize, b3);
    for (from, (bcast, _)) in &r3 {
        bmap3.insert(*from as usize, de(bcast)?);
    }
    let b4 = participant.round4(&bmap3).map_err(|e| anyhow!("round4: {:?}", e))?;

    // ── Round 4 ──
    broadcast_round(state, session_id, 4, own_id, ser(&b4)?, &HashMap::new(), peers).await?;
    let r4 = await_round(state, session_id, 4, &expected, round_timeout).await?;
    let mut bmap4: BTreeMap<usize, Round4EchoBroadcastData<DkgGroup>> = BTreeMap::new();
    bmap4.insert(own_id as usize, b4);
    for (from, (bcast, _)) in &r4 {
        bmap4.insert(*from as usize, de(bcast)?);
    }
    // ── Round 5 (verification echo) ──
    participant
        .round5(&bmap4)
        .map_err(|e| anyhow!("round5: {:?}", e))?;

    let share = participant
        .get_secret_share()
        .ok_or_else(|| anyhow!("no secret share after round5"))?;
    let pk = participant
        .get_public_key()
        .ok_or_else(|| anyhow!("no public key after round5"))?;

    // Session complete — drop its buffers.
    state.dkg_sessions.write().await.remove(session_id);
    tracing::info!(session = %session_id, own_id, "DKG session complete");
    Ok((share, pk))
}
