//! The node's own monitoring surface: `/metrics` (Prometheus text) and the counters behind it.
//!
//! Deliberately dependency-free — counters are plain atomics bumped at the call sites, and every
//! gauge is read straight off `AppState` when scraped, so a gauge can never drift away from the
//! state it describes.
//!
//! The gauge set is built around one thing the ops runbook calls out as the easiest failure to
//! miss: a cluster can drop below the epoch at which it can still heal itself while continuing to
//! serve derives perfectly. `kms_leading_holders` vs `kms_recovery_threshold` is that line — see
//! the comment on `recovery_threshold` below.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use std::sync::OnceLock;
use std::time::Instant;

use crate::server::AppState;

/// Process-wide counter set. Everything here is monotonic except the few explicitly-named
/// "last"/gauge fields, which are overwritten in place.
pub struct Metrics {
    started: Instant,

    // ── Derive path (`POST /app-key`) ─────────────────────────────────────────
    pub appkey_ok: AtomicU64,
    /// Signature didn't recover to an on-chain signer of the requested app (or app unknown).
    pub appkey_unauthorized: AtomicU64,
    /// This node has no share yet — it cannot even contribute its own partial.
    pub appkey_not_ready: AtomicU64,
    /// Everything else: partial collection short of threshold, crypto failure, bad input.
    pub appkey_error: AtomicU64,

    // ── DPRF partial collection ───────────────────────────────────────────────
    // Note: there is deliberately no "partials per derive" gauge. Collection short-circuits the
    // moment one epoch bucket reaches `threshold` (so a dead node can't slow a derive), which
    // means such a gauge would read exactly `threshold` on every successful derive and carry no
    // information. Spare capacity is `kms_leading_holders`.
    /// A peer answered but its payload didn't parse.
    pub dprf_discarded_malformed: AtomicU64,
    /// A peer couldn't be reached / refused / timed out during collection.
    pub dprf_discarded_peer_error: AtomicU64,
    /// No single epoch ever reached threshold — the derive failed.
    pub dprf_short: AtomicU64,

    // ── Share formation and repair ────────────────────────────────────────────
    pub genesis_ok: AtomicU64,
    pub genesis_fail: AtomicU64,
    /// This node recovering its own share from the live committee.
    pub recovery_ok: AtomicU64,
    pub recovery_fail: AtomicU64,
    /// This node acting as a dealer in someone else's reshare.
    pub dealer_ok: AtomicU64,
    pub dealer_fail: AtomicU64,
    /// Operator-triggered proactive refresh (`POST /refresh`).
    pub refresh_ok: AtomicU64,
    pub refresh_fail: AtomicU64,
    /// Watchdog found this node stranded on a stale polynomial and triggered a catch-up.
    pub fall_behind: AtomicU64,
    /// Membership couldn't be assembled (chain lookup failed, or this node's signer is not in
    /// the on-chain nodeList). While this keeps climbing the node cannot form or rejoin.
    pub membership_fail: AtomicU64,

    // ── Sealed-share persistence ──────────────────────────────────────────────
    /// Could not write the sealed blob to the durable path. Silent today, fatal on the next
    /// restart — the node would have to rejoin instead of reloading.
    pub sealed_persist_fail: AtomicU64,
    /// A sealed blob was found at boot but was older than the cluster epoch, so it was dropped
    /// and the node rejoined instead.
    pub sealed_stale_discarded: AtomicU64,
    /// A sealed blob was present but sealed to a different TEE identity (hardware identity
    /// changed) — the node must rejoin.
    pub sealed_identity_mismatch: AtomicU64,
    /// 1 = the sealed-share path was writable at the last probe, 0 = not, -1 = no path
    /// configured. Probed off the gossip loop, not on the scrape path.
    pub share_path_writable: AtomicI64,

    // ── Master baseline ───────────────────────────────────────────────────────
    /// 1 = the live master matches the baseline recorded on first formation, 0 = it does NOT
    /// (the cluster forked, or a re-genesis minted a new master), -1 = no baseline on file yet.
    pub master_matches_baseline: AtomicI64,

    // ── Recovery timing ───────────────────────────────────────────────────────
    /// Seconds the last transition from shardless to holding a share took. 0 = no such
    /// transition since boot. This is the "single-node recovery time" the incident review
    /// identified as the number that actually runs away — the whole committee's tolerance is
    /// spent in units of it.
    pub last_recovery_seconds: AtomicU64,

    // ── Gossip and chain ──────────────────────────────────────────────────────
    pub gossip_push_ok: AtomicU64,
    pub gossip_push_fail: AtomicU64,
    /// Unix seconds of the last gossip push that succeeded against any peer. 0 = never.
    pub gossip_last_success: AtomicI64,
    pub chain_rpc_ok: AtomicU64,
    pub chain_rpc_fail: AtomicU64,
    /// An RPC failure was absorbed by serving the last known nodeList. Authorization is running
    /// on data that is no longer being refreshed.
    pub chain_stale_served: AtomicU64,
}

impl Metrics {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            appkey_ok: AtomicU64::new(0),
            appkey_unauthorized: AtomicU64::new(0),
            appkey_not_ready: AtomicU64::new(0),
            appkey_error: AtomicU64::new(0),
            dprf_discarded_malformed: AtomicU64::new(0),
            dprf_discarded_peer_error: AtomicU64::new(0),
            dprf_short: AtomicU64::new(0),
            genesis_ok: AtomicU64::new(0),
            genesis_fail: AtomicU64::new(0),
            recovery_ok: AtomicU64::new(0),
            recovery_fail: AtomicU64::new(0),
            dealer_ok: AtomicU64::new(0),
            dealer_fail: AtomicU64::new(0),
            refresh_ok: AtomicU64::new(0),
            refresh_fail: AtomicU64::new(0),
            fall_behind: AtomicU64::new(0),
            membership_fail: AtomicU64::new(0),
            sealed_persist_fail: AtomicU64::new(0),
            sealed_stale_discarded: AtomicU64::new(0),
            sealed_identity_mismatch: AtomicU64::new(0),
            share_path_writable: AtomicI64::new(-1),
            master_matches_baseline: AtomicI64::new(-1),
            last_recovery_seconds: AtomicU64::new(0),
            gossip_push_ok: AtomicU64::new(0),
            gossip_push_fail: AtomicU64::new(0),
            gossip_last_success: AtomicI64::new(0),
            chain_rpc_ok: AtomicU64::new(0),
            chain_rpc_fail: AtomicU64::new(0),
            chain_stale_served: AtomicU64::new(0),
        }
    }
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

/// The process-wide metric set. Call once early in `main` so `kms_uptime_seconds` is measured
/// from boot rather than from the first request.
pub fn m() -> &'static Metrics {
    METRICS.get_or_init(Metrics::new)
}

pub fn inc(c: &AtomicU64) {
    c.fetch_add(1, Relaxed);
}

/// Freeze how long this node took to go from boot (shardless) to holding a share.
///
/// Only the first such transition counts: later reshares replace a share the node already had,
/// so they are not recovery. Safe to call on every share adoption — the guard picks the first.
pub fn note_share_acquired() {
    let m = m();
    if m.last_recovery_seconds.load(Relaxed) == 0 {
        // Floor at 1 so an instant reload is still distinguishable from "never happened".
        m.last_recovery_seconds
            .store(m.started.elapsed().as_secs().max(1), Relaxed);
    }
}

/// Tally a session outcome, leaving the result itself untouched.
pub fn record<T, E>(ok: &AtomicU64, fail: &AtomicU64, r: &Result<T, E>) {
    inc(if r.is_ok() { ok } else { fail });
}

/// Probe whether the sealed-share path is actually writable, by creating and removing a
/// neighbouring temp file. A plain permission check would not catch the failure that matters
/// here — a root filesystem that remounted read-only, which leaves the mode bits untouched and
/// makes the node look healthy right up until it needs to persist a new share.
///
/// Called from the gossip loop (every 30s) so the scrape path stays free of filesystem I/O.
/// Returns the verdict it stored, so tests can assert on it without racing other tests over the
/// process-wide metric.
pub fn probe_share_path(path: Option<&str>) -> i64 {
    let verdict = match path {
        None => -1,
        Some(p) => {
            let probe = format!("{}.probe", p);
            match std::fs::write(&probe, b"") {
                Ok(()) => {
                    let _ = std::fs::remove_file(&probe);
                    1
                }
                Err(_) => 0,
            }
        }
    };
    m().share_path_writable.store(verdict, Relaxed);
    verdict
}

// ─── Master baseline ──────────────────────────────────────────────────────────

/// Filename of the master baseline, written next to the sealed share on the durable volume.
const BASELINE_FILE: &str = "master.baseline";

/// Where the baseline lives: alongside the sealed share, since that path is already required to
/// be durable. `None` when no durable path is configured — then there is nothing to anchor to.
pub fn baseline_path(sealed_share_path: Option<&str>) -> Option<String> {
    let p = std::path::Path::new(sealed_share_path?);
    Some(p.with_file_name(BASELINE_FILE).to_string_lossy().into_owned())
}

/// Record the master on first formation, and on every later formation check the live one
/// against it.
///
/// The point is to answer a question a node otherwise cannot: *is this still the same cluster
/// I originally joined?* After a TEE identity change the sealed share can no longer be opened,
/// so the node rejoins with no memory at all and will accept whatever master the committee
/// hands it. The baseline is plaintext — it is a public key — so it survives exactly the event
/// that destroys every other anchor.
///
/// Written once and then never overwritten automatically. A version that re-recorded the master
/// whenever it changed would always agree with itself and detect nothing; changing it has to be
/// a human deleting the file. It must be cleared alongside the sealed shares on a deliberate
/// re-genesis, which legitimately mints a new master.
/// Returns the verdict it stored (1 match / 0 mismatch / -1 unknown), so tests can assert on it
/// without racing other tests over the process-wide metric.
pub fn check_master_baseline(path: Option<&str>, live_master: &[u8]) -> i64 {
    let Some(path) = baseline_path(path) else {
        return -1; // no durable path configured — nothing to anchor against
    };
    let live = hex::encode(live_master);

    let verdict = match crate::seal::read_blob_file(&path) {
        Ok(Some(recorded)) if recorded == live => 1,
        Ok(Some(recorded)) => {
            // Loud on purpose: either the cluster forked, or a re-genesis happened without the
            // baseline being cleared. Both need a human before this node serves another derive.
            tracing::error!(
                baseline = %recorded,
                live = %live,
                "MASTER CHANGED — this node's master no longer matches the baseline recorded when \
                 it first formed. Either the cluster forked, or a re-genesis was run without \
                 clearing the baseline. Do not assume derived keys are reproducible."
            );
            0
        }
        Ok(None) => match crate::seal::write_blob_file(&path, &live) {
            Ok(()) => {
                tracing::info!(master = %live, path = %path, "recorded master baseline");
                1
            }
            Err(e) => {
                tracing::warn!(error = %e, "could not record master baseline");
                -1
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "could not read master baseline");
            -1
        }
    };
    m().master_matches_baseline.store(verdict, Relaxed);
    verdict
}

#[cfg(test)]
mod baseline_tests {
    use super::*;

    fn tmp(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("kms-baseline-{name}"));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("share.sealed").to_string_lossy().into_owned()
    }

    #[test]
    fn records_on_first_formation_then_verifies() {
        let share = tmp("first");
        let master = b"master-one";

        assert_eq!(check_master_baseline(Some(&share), master), 1, "first write");
        // Same master again: still matches, and the file is untouched.
        assert_eq!(check_master_baseline(Some(&share), master), 1, "unchanged master");

        let path = baseline_path(Some(&share)).unwrap();
        assert_eq!(
            crate::seal::read_blob_file(&path).unwrap().unwrap(),
            hex::encode(master)
        );
    }

    #[test]
    fn a_changed_master_is_reported_and_never_silently_adopted() {
        let share = tmp("changed");
        check_master_baseline(Some(&share), b"master-one");

        assert_eq!(check_master_baseline(Some(&share), b"master-two"), 0, "fork detected");

        // The baseline must still hold the ORIGINAL master. Overwriting it here is the one bug
        // that would make this whole mechanism useless — it would agree with itself forever.
        let path = baseline_path(Some(&share)).unwrap();
        assert_eq!(
            crate::seal::read_blob_file(&path).unwrap().unwrap(),
            hex::encode(b"master-one"),
            "baseline must not be overwritten by the value it disagrees with"
        );
    }

    #[test]
    fn no_durable_path_means_no_anchor() {
        assert_eq!(check_master_baseline(None, b"master-one"), -1);
    }
}

#[cfg(test)]
mod probe_tests {
    use super::*;

    #[test]
    fn writability_probe_distinguishes_the_three_states() {
        assert_eq!(probe_share_path(None), -1, "no path configured");

        let dir = std::env::temp_dir().join("kms-probe-test");
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("share.sealed");
        assert_eq!(probe_share_path(Some(good.to_str().unwrap())), 1, "writable directory");
        // The probe must clean up after itself, or it leaves litter next to the real blob.
        assert!(!dir.join("share.sealed.probe").exists());

        // Stands in for the failure this metric exists to catch: the path is configured and
        // looks fine, but a write cannot land.
        assert_eq!(probe_share_path(Some("/nonexistent-mount/share.sealed")), 0, "unwritable path");

        std::fs::remove_dir_all(&dir).ok();
    }
}

/// A live cluster snapshot, derived once and shared by `/metrics` and `GET /peers` so the two
/// views can never disagree about the numbers an operator is paging on.
pub struct ClusterView {
    pub has_share: bool,
    pub own_id: u32,
    pub own_epoch: u64,
    pub cluster_epoch: u64,
    pub threshold: usize,
    pub total_nodes: usize,
    /// `max(threshold, ⌊n/2⌋)` — the number of live holders at the leading epoch below which a
    /// shardless node can no longer rejoin.
    ///
    /// Both gates in `run_reshare_recovery` have to pass: at least `threshold` dealers, and
    /// dealers + the recovering node forming a majority of the committee. For a node that holds
    /// no share the second gate reduces to `holders >= majority(n) - 1 = ⌊n/2⌋`, so the binding
    /// constraint is the larger of the two. Derives keep working below this line, which is
    /// exactly what makes it easy to miss.
    pub recovery_threshold: usize,
    /// Live peers holding a share (any epoch), plus self if it holds one. Reported for
    /// continuity with the old `/peers` field — alert on `leading_holders` instead, since a
    /// holder stranded on a stale epoch cannot act as a dealer.
    pub live_share_holders: usize,
    /// Live share-holders sitting on the *leading* epoch, self included. This is the population
    /// a reshare can actually draw dealers from.
    pub leading_holders: usize,
    pub peers_known: usize,
    pub peers_live: usize,
    pub group_pubkey: Option<Vec<u8>>,
    /// Live peers whose gossiped group public key differs from ours. Non-zero means the cluster
    /// has forked into two masters and one side is serving keys that cannot be reproduced by
    /// the other. Peers that have not reported one yet are not counted.
    pub group_pubkey_mismatch: usize,
}

pub async fn cluster_view(state: &AppState) -> ClusterView {
    let now = chrono::Utc::now().timestamp();

    let (own_id, own_epoch, has_share) = {
        let s = state.shard.read().await;
        match s.as_ref() {
            Some(x) => (x.shard_index, x.epoch, true),
            None => (0, 0, false),
        }
    };
    let group_pubkey = state.group_pubkey.read().await.clone();

    let table = state.peer_table.read().await;
    let peers_known = table.len();
    let live: Vec<_> = table.values().filter(|p| p.is_live(now)).collect();
    let peers_live = live.len();

    let cluster_epoch = own_epoch.max(table.values().map(|p| p.epoch).max().unwrap_or(0));

    let live_share_holders =
        (has_share as usize) + live.iter().filter(|p| p.epoch > 0).count();

    // Leading epoch among live holders (self included when it holds a share) — mirrors
    // `Membership::leading_dealers`, which is what the recovery gates actually count.
    let leading_epoch = live
        .iter()
        .filter(|p| p.epoch > 0)
        .map(|p| p.epoch)
        .chain(if has_share { Some(own_epoch) } else { None })
        .max()
        .unwrap_or(0);
    let leading_holders = if leading_epoch == 0 {
        0
    } else {
        ((has_share && own_epoch == leading_epoch) as usize)
            + live.iter().filter(|p| p.epoch == leading_epoch).count()
    };

    let group_pubkey_mismatch = match group_pubkey.as_ref() {
        Some(own) => live
            .iter()
            .filter(|p| !p.group_pubkey.is_empty() && &p.group_pubkey != own)
            .count(),
        None => 0,
    };

    let threshold = state.config.cluster.threshold as usize;
    let total_nodes = state.config.cluster.total_nodes as usize;

    ClusterView {
        has_share,
        own_id,
        own_epoch,
        cluster_epoch,
        threshold,
        total_nodes,
        recovery_threshold: threshold.max(total_nodes / 2),
        live_share_holders,
        leading_holders,
        peers_known,
        peers_live,
        group_pubkey,
        group_pubkey_mismatch,
    }
}

/// Render the Prometheus text exposition. Nothing here is labelled with an `app_id` or a caller
/// address: the metric set describes this node, and per-caller labels would both leak who is
/// using the KMS and let a caller drive unbounded cardinality.
pub async fn render(state: &AppState) -> String {
    let m = m();
    let v = cluster_view(state).await;
    let now = chrono::Utc::now().timestamp();
    let mut o = String::with_capacity(4096);

    // A macro rather than a closure so it doesn't hold a borrow on `o` across the raw
    // `write!` blocks used for the labelled metrics below.
    macro_rules! g {
        ($name:expr, $help:expr, $kind:expr, $val:expr $(,)?) => {
            let _ = write!(
                o,
                "# HELP {n} {h}\n# TYPE {n} {k}\n{n} {v}\n",
                n = $name,
                h = $help,
                k = $kind,
                v = $val
            );
        };
    }

    g!(
        "kms_build_info",
        "Build metadata; always 1, read the labels.",
        "gauge",
        format!("{{version=\"{}\"}} 1", env!("CARGO_PKG_VERSION")),
    );
    g!(
        "kms_uptime_seconds",
        "Seconds since process start.",
        "gauge",
        m.started.elapsed().as_secs().to_string(),
    );

    // ── Share and epoch ───────────────────────────────────────────────────────
    g!(
        "kms_has_share",
        "1 if this node holds a share of the master key.",
        "gauge",
        (v.has_share as u8).to_string(),
    );
    g!(
        "kms_shardless_seconds",
        "Seconds this node has been running without a share. Stays 0 once a share is held. \
         Unbounded growth means recovery is not converging and needs a human.",
        "gauge",
        if v.has_share { "0".into() } else { m.started.elapsed().as_secs().to_string() },
    );
    g!(
        "kms_own_id",
        "This node's 1-based participant id, which is also its shard index. Derived from its \
         position in the on-chain nodeList, so it changes if that list is reordered. 0 = no share.",
        "gauge",
        v.own_id.to_string(),
    );
    g!(
        "kms_epoch",
        "Polynomial epoch of this node's own share. 0 = none.",
        "gauge",
        v.own_epoch.to_string(),
    );
    g!(
        "kms_cluster_epoch",
        "Highest epoch known across self and all gossiped peers.",
        "gauge",
        v.cluster_epoch.to_string(),
    );
    g!(
        "kms_epoch_lag",
        "cluster_epoch - own epoch. Non-zero for more than a reshare's duration means this node \
         is stranded on a stale polynomial and is silently not contributing to derives.",
        "gauge",
        v.cluster_epoch.saturating_sub(v.own_epoch).to_string(),
    );

    // ── Committee ─────────────────────────────────────────────────────────────
    g!(
        "kms_threshold",
        "Partials required to derive a key (the service threshold).",
        "gauge",
        v.threshold.to_string(),
    );
    g!(
        "kms_total_nodes",
        "Configured committee size.",
        "gauge",
        v.total_nodes.to_string(),
    );
    g!(
        "kms_recovery_threshold",
        "max(threshold, floor(n/2)) — live leading-epoch holders needed for a shardless node to \
         rejoin. Alert on this, not on kms_threshold: derives keep working below it while the \
         cluster has already lost the ability to heal.",
        "gauge",
        v.recovery_threshold.to_string(),
    );
    g!(
        "kms_leading_holders",
        "Live share-holders on the leading epoch, self included. The population a reshare can \
         draw dealers from.",
        "gauge",
        v.leading_holders.to_string(),
    );
    g!(
        "kms_live_share_holders",
        "Live share-holders on any epoch, self included. Reported for continuity; alert on \
         kms_leading_holders, since a holder on a stale epoch cannot be a dealer.",
        "gauge",
        v.live_share_holders.to_string(),
    );
    g!(
        "kms_peers_known",
        "Peers in the gossip table, alive or not.",
        "gauge",
        v.peers_known.to_string(),
    );
    g!(
        "kms_peers_live",
        "Peers seen by direct contact within the liveness window.",
        "gauge",
        v.peers_live.to_string(),
    );

    // ── Master identity ───────────────────────────────────────────────────────
    g!(
        "kms_group_pubkey_known",
        "1 if this node knows the cluster's group public key.",
        "gauge",
        (v.group_pubkey.is_some() as u8).to_string(),
    );
    // The master as a LABEL, so the fork check is a count of distinct values across the fleet
    // rather than a node's own opinion:
    //     count(count by (hash) (kms_group_pubkey_info))
    // A node on the wrong side of a fork reports its wrong hash just as confidently as the rest
    // report the right one, which is exactly what makes counting them work. Cardinality is safe:
    // reshare and refresh preserve the master, so a second value can only appear if something
    // genuinely went wrong. Truncated to 16 hex chars — enough to distinguish, short enough to
    // read in a dashboard.
    if let Some(pk) = v.group_pubkey.as_ref() {
        let _ = write!(
            o,
            "# HELP kms_group_pubkey_info The cluster master this node holds, as a label. Always 1.\n\
             # TYPE kms_group_pubkey_info gauge\n\
             kms_group_pubkey_info{{hash=\"{}\"}} 1\n",
            &hex::encode(pk)[..16.min(pk.len() * 2)],
        );
    }
    g!(
        "kms_group_pubkey_mismatch",
        "Live peers whose gossiped master differs from ours. This node's own observation — it \
         says a fork exists, not who is right. Use kms_group_pubkey_info to decide that.",
        "gauge",
        v.group_pubkey_mismatch.to_string(),
    );
    g!(
        "kms_master_matches_baseline",
        "1 = the master matches the baseline recorded when this node first formed, 0 = it does \
         NOT (the cluster forked, or a re-genesis ran without clearing the baseline), -1 = no \
         baseline on file. Unlike the gossip comparison this survives a TEE identity change, \
         which is precisely when a rejoining node has no other memory of which cluster it was in.",
        "gauge",
        m.master_matches_baseline.load(Relaxed).to_string(),
    );
    g!(
        "kms_last_recovery_seconds",
        "Seconds this node took to go from boot to holding a share. 0 = no such transition since \
         boot. This is the single-node recovery time the committee's fault tolerance is spent in \
         units of — when it runs away, the margin goes with it.",
        "gauge",
        m.last_recovery_seconds.load(Relaxed).to_string(),
    );

    // ── Derive path ───────────────────────────────────────────────────────────
    let _ = write!(
        o,
        "# HELP kms_appkey_requests_total App-key requests by outcome.\n\
         # TYPE kms_appkey_requests_total counter\n\
         kms_appkey_requests_total{{result=\"ok\"}} {}\n\
         kms_appkey_requests_total{{result=\"unauthorized\"}} {}\n\
         kms_appkey_requests_total{{result=\"not_ready\"}} {}\n\
         kms_appkey_requests_total{{result=\"error\"}} {}\n",
        m.appkey_ok.load(Relaxed),
        m.appkey_unauthorized.load(Relaxed),
        m.appkey_not_ready.load(Relaxed),
        m.appkey_error.load(Relaxed),
    );
    let _ = write!(
        o,
        "# HELP kms_dprf_discarded_total Peer partials dropped during collection, by reason.\n\
         # TYPE kms_dprf_discarded_total counter\n\
         kms_dprf_discarded_total{{reason=\"malformed\"}} {}\n\
         kms_dprf_discarded_total{{reason=\"peer_error\"}} {}\n",
        m.dprf_discarded_malformed.load(Relaxed),
        m.dprf_discarded_peer_error.load(Relaxed),
    );
    g!(
        "kms_dprf_short_total",
        "Derives that failed because no single epoch reached threshold.",
        "counter",
        m.dprf_short.load(Relaxed).to_string(),
    );

    // ── Formation and repair ──────────────────────────────────────────────────
    let _ = write!(
        o,
        "# HELP kms_session_total Key-formation sessions by kind and outcome.\n\
         # TYPE kms_session_total counter\n\
         kms_session_total{{kind=\"genesis\",result=\"ok\"}} {}\n\
         kms_session_total{{kind=\"genesis\",result=\"fail\"}} {}\n\
         kms_session_total{{kind=\"recovery\",result=\"ok\"}} {}\n\
         kms_session_total{{kind=\"recovery\",result=\"fail\"}} {}\n\
         kms_session_total{{kind=\"dealer\",result=\"ok\"}} {}\n\
         kms_session_total{{kind=\"dealer\",result=\"fail\"}} {}\n\
         kms_session_total{{kind=\"refresh\",result=\"ok\"}} {}\n\
         kms_session_total{{kind=\"refresh\",result=\"fail\"}} {}\n",
        m.genesis_ok.load(Relaxed),
        m.genesis_fail.load(Relaxed),
        m.recovery_ok.load(Relaxed),
        m.recovery_fail.load(Relaxed),
        m.dealer_ok.load(Relaxed),
        m.dealer_fail.load(Relaxed),
        m.refresh_ok.load(Relaxed),
        m.refresh_fail.load(Relaxed),
    );
    g!(
        "kms_fall_behind_total",
        "Times the watchdog found this node on a stale epoch and triggered a catch-up rejoin.",
        "counter",
        m.fall_behind.load(Relaxed).to_string(),
    );
    g!(
        "kms_membership_failures_total",
        "Failures to assemble the committee (chain lookup failed, or this node's signer is not \
         in the on-chain nodeList). While this climbs the node cannot form or rejoin.",
        "counter",
        m.membership_fail.load(Relaxed).to_string(),
    );

    // ── Sealed-share persistence ──────────────────────────────────────────────
    g!(
        "kms_sealed_persist_failures_total",
        "Failures to write the sealed share to durable storage. Harmless while running, fatal on \
         the next restart — the node would have to rejoin instead of reloading.",
        "counter",
        m.sealed_persist_fail.load(Relaxed).to_string(),
    );
    g!(
        "kms_sealed_stale_discarded_total",
        "Sealed blobs dropped at boot for being older than the cluster epoch.",
        "counter",
        m.sealed_stale_discarded.load(Relaxed).to_string(),
    );
    g!(
        "kms_sealed_identity_mismatch_total",
        "Sealed blobs that could not be opened by this TEE identity, meaning the hardware \
         identity changed and a rejoin is required.",
        "counter",
        m.sealed_identity_mismatch.load(Relaxed).to_string(),
    );
    g!(
        "kms_share_path_writable",
        "1 = the sealed-share path was writable at the last probe, 0 = not writable (a read-only \
         filesystem looks healthy everywhere else), -1 = no path configured.",
        "gauge",
        m.share_path_writable.load(Relaxed).to_string(),
    );

    // ── Gossip and chain ──────────────────────────────────────────────────────
    let _ = write!(
        o,
        "# HELP kms_gossip_push_total Outbound gossip pushes by outcome.\n\
         # TYPE kms_gossip_push_total counter\n\
         kms_gossip_push_total{{result=\"ok\"}} {}\n\
         kms_gossip_push_total{{result=\"fail\"}} {}\n",
        m.gossip_push_ok.load(Relaxed),
        m.gossip_push_fail.load(Relaxed),
    );
    let last = m.gossip_last_success.load(Relaxed);
    g!(
        "kms_gossip_last_success_age_seconds",
        "Seconds since the last gossip push that reached any peer. -1 = never succeeded. Growing \
         past a few rounds means this node is partitioned and its peer view is going stale.",
        "gauge",
        if last == 0 { "-1".into() } else { (now - last).to_string() },
    );
    let _ = write!(
        o,
        "# HELP kms_chain_rpc_total nodeList lookups against the chain RPC, by outcome.\n\
         # TYPE kms_chain_rpc_total counter\n\
         kms_chain_rpc_total{{result=\"ok\"}} {}\n\
         kms_chain_rpc_total{{result=\"fail\"}} {}\n",
        m.chain_rpc_ok.load(Relaxed),
        m.chain_rpc_fail.load(Relaxed),
    );
    g!(
        "kms_chain_stale_served_total",
        "RPC failures absorbed by serving the last known nodeList. Authorization is running on \
         data that is no longer being refreshed.",
        "counter",
        m.chain_stale_served.load(Relaxed).to_string(),
    );

    o
}
