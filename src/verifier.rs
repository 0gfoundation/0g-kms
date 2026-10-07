//! Attested-admission gate (issue #14): before deriving for an app signer or trusting a cluster
//! peer, ask the tappscan verifier whether that (app_id, signer) has verified TEE evidence.
//!
//! The on-chain nodeList proves only that the *owner* endorsed an address — the contract never
//! sees a quote, so a stolen owner key is sufficient to register a plain, non-TEE keypair.
//! tappscan is what actually checks evidence (quote, runtime-event replay, reconciliation with
//! the on-chain declaration); this module makes the KMS *consume* that verdict instead of
//! leaving it as unenforced audit.
//!
//! Trust model, in one breath: a human reviews scan once (its reference values live in the
//! 0g-tapp-verifier repo — publication on chain vs. in a repo confers no trust either way);
//! the KMS then pins scan's **attested TLS key** from config and believes its verdicts about
//! everyone else. Scan's verdicts are never used to vouch for scan itself — that verification
//! is a public, human-reproducible act, and the pin is its output.
//!
//! Failure semantics — fail-closed *for the increment only*:
//!   * a signer with a cached positive verdict keeps working when scan is unreachable
//!     (existing traffic never depends on scan's availability),
//!   * a signer we have never verified is refused until scan answers.
//! Positive verdicts refresh hourly (so a revocation propagates), negatives and errors are
//! damped for thirty seconds (so a burst of derives can't hammer scan). Signer keys rotate on
//! every tapp-server restart, so the cache needs no identity-generation logic: a new identity
//! is simply a new key.
//!
//! Scan not knowing a signer (404) is neither: every caller has already found that signer in
//! the on-chain list itself, so it means scan has not synced the registration yet — the normal
//! state for a node that restarted and re-registered seconds ago. `/app-key` keeps asking for a
//! few seconds, and if scan still does not know the signer the refusal is not cached.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use sha2::Digest as _;
use ethers::types::Address;
use tokio::sync::{Mutex, RwLock};

use crate::config::{Config, VerifierConfig};

/// How long a positive verdict is trusted before re-asking. Not an availability hazard: a
/// refresh that fails against an unreachable scan re-stamps the stale positive and keeps
/// serving (see `require_verified`), so this is purely how fast a *revocation* propagates.
const POSITIVE_REFRESH: Duration = Duration::from_secs(3600);

/// Damping for negative verdicts and fetch errors. A caller retrying a rejected or unknown
/// signer inside this window is answered from cache — scan's own per-target cooldown is the
/// real limiter, this just keeps the KMS from queueing on it.
const NEGATIVE_TTL: Duration = Duration::from_secs(30);

/// One verify round-trip may include scan fetching evidence from the target node and running
/// the attestation service — seconds, not milliseconds.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// How long `/app-key` keeps asking when scan does not know a signer this KMS has just found
/// on chain. Scan follows the chain on a schedule and forces a sync for an unknown target at
/// most every 10s, so a node that re-registered on restart is usually known within this. Peer
/// calls pass zero: their callers time out after 3s and retry on their own loops.
pub const SCAN_LAG_WAIT: Duration = Duration::from_secs(12);
const SCAN_LAG_POLL: Duration = Duration::from_secs(3);

/// After a wait that ended with scan still not knowing the signer, requests for it get the same
/// answer for this long instead of each starting a wait of their own. Deliberately not the
/// 30s negative damping: the signer is on chain, scan is behind, and the caller will retry.
const SCAN_LAG_DAMP: Duration = Duration::from_secs(3);

/// What scan's 404 is reported as. tapp-server's KMS client waits on this text (0g-tapp#136),
/// so it is a contract, not just a message.
const NOT_REGISTERED: &str = "not registered on-chain per verifier";

// ─── Pinned-key TLS ─────────────────────────────────────────────────────────────

/// Accepts exactly the configured public keys and nothing else. No CA, no chain, no expiry:
/// the attested cert is self-signed by design, and the entire trust decision is "does the
/// server hold the pinned attested key" — possession is proven by the TLS handshake signature,
/// which is still verified (below) with the provider's real algorithms.
///
/// The pinned value is **sha256 of the full SubjectPublicKeyInfo DER** — the curl
/// `--pinnedpubkey` convention, and exactly the `tls_public_key` scan's evidence carries and
/// its `/api/apps/:app_id/cert` publishes. NOT the raw key bits: for scan's P-256 key those
/// would be the 65-byte uncompressed point, a different value entirely — comparing against the
/// wrong encoding was PR #15's second-round blocker, caught because as-documented no handshake
/// could ever succeed.
#[derive(Debug)]
struct PinnedKeyVerifier {
    /// sha256(SPKI DER) values, 32 bytes each. A small set, not a single key, so a scan
    /// identity rotation can be rolled without a flag day.
    pinned: Vec<Vec<u8>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let (_, cert) = x509_parser::parse_x509_certificate(end_entity.as_ref())
            .map_err(|e| rustls::Error::General(format!("verifier cert unparseable: {e}")))?;
        // Hash the WHOLE SubjectPublicKeyInfo DER (algorithm header included) — hashing only
        // the inner bit string is not the --pinnedpubkey convention and would not match the
        // value scan publishes.
        let presented: [u8; 32] =
            sha2::Sha256::digest(cert.tbs_certificate.subject_pki.raw).into();
        if self.pinned.iter().any(|k| k.as_slice() == presented) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "verifier served a key that does not match any pinned attested key".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ─── Client ─────────────────────────────────────────────────────────────────────

/// Cap on how long a positive verdict may be served past the last *successful* confirmation.
/// Without it, every failed hourly refresh against a down scan would re-stamp the stale
/// positive and a verified-then-revoked signer would keep working for the whole outage
/// (PR #15 review finding 3). With it, a sustained scan outage degrades existing traffic only
/// after this long — a deliberate availability/revocation-latency trade.
const MAX_VERDICT_STALENESS: Duration = Duration::from_secs(24 * 3600);

struct CacheEntry {
    verified: bool,
    /// For a refusal: what a caller is told while it is answered from cache.
    refusal: String,
    /// For a refusal: how long it is answered from cache.
    damp: Duration,
    /// Damping stamp: drives the hourly-refresh / 30s-negative TTLs. Re-stamped on a failed
    /// refresh so a dead scan is not re-queried on every request.
    at: Instant,
    /// Last *successful* positive confirmation from scan. Never moved by failures — this is
    /// what bounds how long a revocation can stay invisible.
    confirmed_at: Instant,
}

type Key = (String, Address);

pub struct Verifier {
    cfg: VerifierConfig,
    client: reqwest::Client,
    cache: RwLock<HashMap<Key, CacheEntry>>,
    /// Per-key single-flight (PR #15 review finding 4): a node restart makes every in-flight
    /// derive discover the same new signer at once — one fetches, the rest wait. Per KEY, not
    /// global: N distinct first-seen signers must not serialize behind one slow 10s fetch.
    fetch_locks: Mutex<HashMap<Key, Arc<Mutex<()>>>>,
}

/// What `POST {url}/verify` returns (contract in 0g-tapp-verifier#14). Scan also returns
/// `warnings` and `image_env`; a verdict scan has already failed (DEBUG TD, revoked TCB, a dev
/// image on mainnet) arrives as `verified: false`, so the KMS needs only these two.
#[derive(serde::Deserialize)]
struct VerifyResponse {
    verified: bool,
    #[serde(default)]
    reason: String,
}

enum Answer {
    Verdict { verified: bool, reason: String },
    /// Scan does not know (app_id, signer). Every caller has found the signer in its own
    /// on-chain list first, so this means scan is behind the chain.
    Unknown,
}

impl Verifier {
    pub fn new(cfg: VerifierConfig) -> Result<Self> {
        // Boot invariant (PR #15 review finding 1): a malformed [verifier] must fail HERE,
        // loudly — not per-request, where a typo'd scheme is indistinguishable from a scan
        // outage and quietly freezes admission of new signers.
        if !cfg.url.starts_with("http://") && !cfg.url.starts_with("https://") {
            return Err(anyhow!(
                "[verifier] url must start with http:// or https://, got {:?}",
                cfg.url
            ));
        }
        let client = if let Some(rest) = cfg.url.strip_prefix("http://") {
            // Plaintext = no pin = no authenticity. Only for tests against a local mock.
            if !cfg.insecure_http {
                return Err(anyhow!(
                    "[verifier] url is plain http ({rest}) — the pin only works over https; \
                     set insecure_http = true ONLY for local testing"
                ));
            }
            tracing::warn!("verifier over PLAINTEXT http — pinning disabled, test use only");
            reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()?
        } else {
            let pinned: Vec<Vec<u8>> = cfg
                .pubkeys
                .iter()
                .map(|k| {
                    let bytes = hex::decode(k.trim_start_matches("0x"))
                        .map_err(|e| anyhow!("[verifier] pubkey {k} is not hex: {e}"))?;
                    if bytes.len() != 32 {
                        // The pin is sha256 of the SPKI DER — always 32 bytes. A 65-byte value
                        // is the raw EC point (the wrong encoding this check exists to catch);
                        // empty/short values are sloppy config. All fail the boot loudly.
                        return Err(anyhow!(
                            "[verifier] pubkey {k} is {} bytes; expected the 32-byte sha256 of \
                             the SPKI DER (scan's tls_public_key, curl --pinnedpubkey value)",
                            bytes.len()
                        ));
                    }
                    Ok(bytes)
                })
                .collect::<Result<_>>()?;
            if pinned.is_empty() {
                return Err(anyhow!("[verifier] configured with no pinned pubkeys"));
            }
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let tls = rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .map_err(|e| anyhow!("tls protocol setup: {e}"))?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedKeyVerifier {
                    pinned,
                    provider,
                }))
                .with_no_client_auth();
            reqwest::Client::builder()
                .use_preconfigured_tls(tls)
                .timeout(REQUEST_TIMEOUT)
                .build()?
        };
        Ok(Self {
            cfg,
            client,
            cache: RwLock::new(HashMap::new()),
            fetch_locks: Mutex::new(HashMap::new()),
        })
    }

    /// Gate a signer. `Ok(())` = derive/serve; `Err(reason)` = refuse (the reason is safe to
    /// return to the caller — it describes their admission status, nothing internal).
    ///
    /// The caller must already have found `signer` in the app's on-chain list. `scan_lag_wait`
    /// is how long to keep asking if scan has not caught up with that list yet.
    pub async fn require_verified(
        &self,
        app_id: &str,
        signer: &Address,
        scan_lag_wait: Duration,
    ) -> Result<(), String> {
        let key: Key = (app_id.to_string(), *signer);
        let m = crate::metrics::m();

        if let Some(d) = self.cached_decision(&key).await {
            return d;
        }

        // Per-key single-flight; re-check under the lock — the winner usually filled the cache.
        let key_lock = {
            let mut locks = self.fetch_locks.lock().await;
            locks.entry(key.clone()).or_default().clone()
        };
        let _g = key_lock.lock().await;
        if let Some(d) = self.cached_decision(&key).await {
            return d;
        }

        let mut outcome = self.fetch(app_id, signer).await;
        // A signer with a usable positive is served from it at once if scan does not know it;
        // only a signer with nothing to fall back on waits for scan to catch up.
        if !self.has_stale_positive(&key).await {
            let deadline = Instant::now() + scan_lag_wait;
            while matches!(outcome, Ok(Answer::Unknown))
                && Instant::now() + SCAN_LAG_POLL <= deadline
            {
                tokio::time::sleep(SCAN_LAG_POLL).await;
                outcome = self.fetch(app_id, signer).await;
            }
        }
        let now = Instant::now();
        let mut cache = self.cache.write().await;
        // Bound the cache: entries whose damping stamp is far past every TTL are dead weight
        // (each signer generation leaves one behind, forever). Amortized on the fetch path,
        // which is already the slow path.
        if cache.len() > 4096 {
            cache.retain(|_, e| e.at.elapsed() < MAX_VERDICT_STALENESS);
        }
        let refused = |refusal: String, damp: Duration| CacheEntry {
            verified: false,
            refusal,
            damp,
            at: now,
            confirmed_at: now,
        };
        // Scan cannot answer for this signer right now — unreachable, or behind the chain. A
        // positive confirmed within the staleness cap keeps working: re-stamp the damping
        // clock so a dead scan is retried hourly, not per request. `confirmed_at` is
        // deliberately NOT moved: it is what bounds how long a revocation can stay invisible.
        let restamp_stale = |cache: &mut HashMap<Key, CacheEntry>| match cache.get_mut(&key) {
            Some(e) if e.verified && e.confirmed_at.elapsed() < MAX_VERDICT_STALENESS => {
                e.at = now;
                true
            }
            _ => false,
        };
        let result = match outcome {
            Ok(Answer::Verdict { verified: true, .. }) => {
                cache.insert(
                    key.clone(),
                    CacheEntry {
                        verified: true,
                        refusal: String::new(),
                        damp: Duration::ZERO,
                        at: now,
                        confirmed_at: now,
                    },
                );
                crate::metrics::inc(&m.verifier_allowed);
                Ok(())
            }
            Ok(Answer::Verdict { verified: false, reason }) => {
                // A fresh negative resets confirmed_at too: an explicit revocation must not
                // leave a stale-positive escape hatch behind.
                cache.insert(
                    key.clone(),
                    refused(
                        format!("attestation not verified (recently checked): {reason}"),
                        NEGATIVE_TTL,
                    ),
                );
                crate::metrics::inc(&m.verifier_denied);
                tracing::warn!(app_id, signer = ?signer, %reason, "verifier denied signer");
                Err(format!("attestation not verified: {reason}"))
            }
            Ok(Answer::Unknown) if restamp_stale(&mut cache) => {
                crate::metrics::inc(&m.verifier_stale_served);
                tracing::warn!(app_id, signer = ?signer,
                    "verifier does not know an on-chain signer — serving stale positive verdict");
                Ok(())
            }
            Ok(Answer::Unknown) => {
                // Not a negative: the signer is on chain and scan has not synced it. Only a
                // brief marker, so requests queued behind this one don't each wait again.
                let refusal = format!("attestation not verified: {NOT_REGISTERED}");
                cache.insert(key.clone(), refused(refusal.clone(), SCAN_LAG_DAMP));
                crate::metrics::inc(&m.verifier_scan_behind);
                tracing::warn!(app_id, signer = ?signer, waited_s = scan_lag_wait.as_secs(),
                    "verifier does not know an on-chain signer yet — refusing until it syncs");
                Err(refusal)
            }
            Err(e) if restamp_stale(&mut cache) => {
                crate::metrics::inc(&m.verifier_stale_served);
                tracing::warn!(app_id, signer = ?signer, error = %e,
                    "verifier unreachable — serving stale positive verdict");
                Ok(())
            }
            Err(e) => {
                cache.insert(
                    key.clone(),
                    refused(
                        "attestation not verified (recently checked): verifier unreachable".into(),
                        NEGATIVE_TTL,
                    ),
                );
                crate::metrics::inc(&m.verifier_unavailable_refused);
                tracing::warn!(app_id, signer = ?signer, error = %e,
                    "verifier unreachable and signer has no fresh-enough verdict — refusing");
                Err("attestation verifier unreachable and this signer has no fresh-enough verdict".into())
            }
        };
        drop(cache);
        // The lock map only ever needs entries someone is actively fetching.
        self.fetch_locks.lock().await.remove(&key);
        result
    }

    /// Cache-only decision: `Some(Ok)` allow, `Some(Err)` deny, `None` = must ask scan.
    async fn cached_decision(&self, key: &Key) -> Option<Result<(), String>> {
        let m = crate::metrics::m();
        let cache = self.cache.read().await;
        let e = cache.get(key)?;
        if e.verified
            && e.at.elapsed() < POSITIVE_REFRESH
            && e.confirmed_at.elapsed() < MAX_VERDICT_STALENESS
        {
            crate::metrics::inc(&m.verifier_allowed);
            return Some(Ok(()));
        }
        if !e.verified && e.at.elapsed() < e.damp {
            crate::metrics::inc(&m.verifier_denied);
            return Some(Err(e.refusal.clone()));
        }
        None
    }

    /// A positive that may still be served while scan cannot answer.
    async fn has_stale_positive(&self, key: &Key) -> bool {
        let cache = self.cache.read().await;
        cache
            .get(key)
            .is_some_and(|e| e.verified && e.confirmed_at.elapsed() < MAX_VERDICT_STALENESS)
    }

    async fn fetch(&self, app_id: &str, signer: &Address) -> Result<Answer> {
        let mut req = self
            .client
            .post(format!("{}/verify", self.cfg.url.trim_end_matches('/')))
            .json(&serde_json::json!({
                "app_id": app_id,
                "signer": format!("{:#x}", signer),
            }));
        if !self.cfg.api_key.is_empty() {
            req = req.header("x-api-key", &self.cfg.api_key);
        }
        let resp = req.send().await.map_err(|e| anyhow!("verify request: {e}"))?;
        match resp.status() {
            s if s.is_success() => {
                let v: VerifyResponse =
                    resp.json().await.map_err(|e| anyhow!("verify response: {e}"))?;
                Ok(Answer::Verdict { verified: v.verified, reason: v.reason })
            }
            // Unknown (app_id, signer): scan rejects before fetching anything, because its
            // copy of the registry does not have the pair.
            reqwest::StatusCode::NOT_FOUND => Ok(Answer::Unknown),
            s => Err(anyhow!("verifier returned {s}")),
        }
    }
}

// ─── Process-wide instance ──────────────────────────────────────────────────────

static VERIFIER: OnceLock<Option<Arc<Verifier>>> = OnceLock::new();

/// Build the process verifier from config. Call once in main, before serving: a malformed
/// [verifier] section must fail the boot loudly, not silently run ungated.
pub fn init(config: &Config) -> Result<()> {
    let v = match &config.verifier {
        Some(cfg) => Some(Arc::new(Verifier::new(cfg.clone())?)),
        None => None,
    };
    crate::metrics::m().verifier_enabled.store(
        v.is_some() as i64,
        std::sync::atomic::Ordering::Relaxed,
    );
    VERIFIER
        .set(v)
        .map_err(|_| anyhow!("verifier::init called twice"))?;
    Ok(())
}

/// The admission gate used by the HTTP and gRPC paths. With no [verifier] configured this is a
/// no-op — the feature ships dark and turns on with a config change once scan serves its
/// attested key (0g-tapp-verifier#14). See `Verifier::require_verified` for `scan_lag_wait`.
pub async fn require_verified(
    app_id: &str,
    signer: &Address,
    scan_lag_wait: Duration,
) -> Result<(), String> {
    match VERIFIER.get() {
        Some(Some(v)) => v.require_verified(app_id, signer, scan_lag_wait).await,
        _ => Ok(()),
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier as _;

    fn test_cfg(url: String) -> VerifierConfig {
        VerifierConfig {
            url,
            pubkeys: vec![],
            api_key: "test-key".into(),
            insecure_http: true,
        }
    }

    /// The pin is the entire authenticity story, so test it with P-256 — the curve scan
    /// actually serves, and the one where "raw point" and "SPKI hash" are different values.
    /// The expected pin is minted from rcgen's own SPKI DER (`public_key_der`), an independent
    /// derivation from the extraction under test — the previous Ed25519 version minted its
    /// expectation through the code under test and was structurally blind to the encoding bug.
    #[test]
    fn pin_accepts_exactly_the_pinned_key() {
        let kp1 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let kp2 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert1 = rcgen::CertificateParams::new(vec!["scan".into()])
            .unwrap()
            .self_signed(&kp1)
            .unwrap();
        let cert2 = rcgen::CertificateParams::new(vec!["scan".into()])
            .unwrap()
            .self_signed(&kp2)
            .unwrap();

        let pin1: [u8; 32] = sha2::Sha256::digest(kp1.public_key_der()).into();
        let v = PinnedKeyVerifier {
            pinned: vec![pin1.to_vec()],
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        };
        let name = rustls::pki_types::ServerName::try_from("scan").unwrap();
        let now = rustls::pki_types::UnixTime::now();

        assert!(v.verify_server_cert(cert1.der(), &[], &name, &[], now).is_ok());
        assert!(v.verify_server_cert(cert2.der(), &[], &name, &[], now).is_err());

        // And the raw 65-byte point must NOT be accepted as a pin — that is exactly the wrong
        // encoding the second-round review caught.
        let raw_point = PinnedKeyVerifier {
            pinned: vec![kp1.public_key_raw().to_vec()],
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        };
        assert!(raw_point.verify_server_cert(cert1.der(), &[], &name, &[], now).is_err());
    }

    /// Ground truth from OUTSIDE this codebase: a P-256 certificate generated with openssl and
    /// its pin computed by `openssl x509 -pubkey | openssl pkey -pubin -outform der | sha256sum`
    /// — the documented operator flow. If the extraction ever hashes the wrong bytes again,
    /// this vector fails regardless of how the expectation in the other test is minted.
    #[test]
    fn pin_matches_openssl_derived_vector() {
        use base64::Engine as _;
        const CERT_DER_B64: &str = "MIIBcjCCARmgAwIBAgIUfCxSzNoq7qm/oi1ugTmy7eEmbPUwCgYIKoZIzj0EAwIwDzENMAsGA1UEAwwEc2NhbjAeFw0yNjA5MzAwMzM4MjBaFw0zNjA5MjcwMzM4MjBaMA8xDTALBgNVBAMMBHNjYW4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARrYuw2nBIQxct5l9TmkbvUPlToniTlW4UE+sriPnXJeJQCfRax99BTnXoJwFuG3C7ljvv+Fpy21KvK03m77jwio1MwUTAdBgNVHQ4EFgQUTZ063JN8YVwx4edU98NTSNGnYyowHwYDVR0jBBgwFoAUTZ063JN8YVwx4edU98NTSNGnYyowDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiA8Btl0CoZIB0Kvj8MZgWUpHq2p/ALnmd4NzMqRHZWN2QIgeT7JsgO7FL+9vtGEUpIlBjV6dChnKvkjJBACgcS1RJM=";
        const OPENSSL_PIN: &str = "915497ac63671c8f78b8cecda9ca2c01e6c702de46bb71091252b60b0b375c80";

        let der = base64::engine::general_purpose::STANDARD
            .decode(CERT_DER_B64)
            .unwrap();
        let cert = rustls::pki_types::CertificateDer::from(der);
        let v = PinnedKeyVerifier {
            pinned: vec![hex::decode(OPENSSL_PIN).unwrap()],
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        };
        let name = rustls::pki_types::ServerName::try_from("scan").unwrap();
        assert!(v
            .verify_server_cert(&cert, &[], &name, &[], rustls::pki_types::UnixTime::now())
            .is_ok());
    }

    /// Finding 1 of the PR review: a malformed [verifier] must fail at construction, not at
    /// the first request where it is indistinguishable from a scan outage.
    #[test]
    fn malformed_config_fails_at_boot() {
        // scheme-less / typo'd scheme
        for url in ["scan.example", "tcp://scan.example", "htps://scan.example"] {
            let cfg = VerifierConfig {
                url: url.into(),
                pubkeys: vec!["0xabcd".into()],
                api_key: String::new(),
                insecure_http: false,
            };
            assert!(Verifier::new(cfg).is_err(), "{url} must be rejected at boot");
        }
        // https with no pins, non-hex, empty, and WRONG-LENGTH pins must all be rejected —
        // notably the 65-byte raw EC point, the encoding mixup the second review round caught
        for pubkeys in [
            vec![],
            vec!["zz".to_string()],
            vec!["".to_string()],
            vec!["0x".to_string()],
            vec!["0x7b13d132".to_string()],          // 4 bytes: truncated hash
            vec![format!("0x04{}", "ab".repeat(64))], // 65 bytes: raw uncompressed point
        ] {
            let cfg = VerifierConfig {
                url: "https://scan.example".into(),
                pubkeys,
                api_key: String::new(),
                insecure_http: false,
            };
            assert!(Verifier::new(cfg).is_err());
        }
        // and a well-formed one (a real 32-byte sha256) builds
        let cfg = VerifierConfig {
            url: "https://scan.example".into(),
            pubkeys: vec![format!("0x{}", "ab".repeat(32))],
            api_key: String::new(),
            insecure_http: false,
        };
        assert!(Verifier::new(cfg).is_ok());
    }

    /// The full verdict lifecycle against a mock scan: allow is cached (scan can die and the
    /// signer keeps working), deny is damped, and an unknown signer with scan down is refused.
    #[tokio::test]
    async fn verdict_semantics() {
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let scan = MockServer::start().await;
        let good: Address = "0x1111111111111111111111111111111111111111".parse().unwrap();
        let bad: Address = "0x2222222222222222222222222222222222222222".parse().unwrap();

        Mock::given(method("POST"))
            .and(path("/verify"))
            .and(body_partial_json(serde_json::json!({"signer": format!("{:#x}", good)})))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"verified": true})),
            )
            .expect(1) // the second allow MUST come from cache
            .mount(&scan)
            .await;
        Mock::given(method("POST"))
            .and(path("/verify"))
            .and(body_partial_json(serde_json::json!({"signer": format!("{:#x}", bad)})))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"verified": false, "reason": "replay failed"}),
            ))
            .expect(1) // the second deny MUST come from the damping cache
            .mount(&scan)
            .await;

        let v = Verifier::new(test_cfg(scan.uri())).unwrap();

        let no_wait = Duration::ZERO;
        assert!(v.require_verified("app", &good, no_wait).await.is_ok());
        assert!(v.require_verified("app", &good, no_wait).await.is_ok());
        assert_eq!(
            v.require_verified("app", &bad, no_wait).await,
            Err("attestation not verified: replay failed".into())
        );
        // The damped repeat still says why.
        assert_eq!(
            v.require_verified("app", &bad, no_wait).await,
            Err("attestation not verified (recently checked): replay failed".into())
        );

        // Scan dies. The verified signer keeps working from cache; a never-seen signer is
        // refused — fail-closed applies to the increment only.
        drop(scan);
        let unseen: Address = "0x3333333333333333333333333333333333333333".parse().unwrap();
        assert!(v.require_verified("app", &good, no_wait).await.is_ok());
        assert!(v.require_verified("app", &unseen, no_wait).await.is_err());
    }

    /// A node that restarted re-registers its new signer and asks for its key at once; scan,
    /// which follows the chain on a schedule, answers 404 until it syncs. `/app-key` waits that
    /// out inside the request (0g-kms#15 review).
    #[tokio::test]
    async fn a_signer_scan_has_not_synced_yet_is_waited_for() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let scan = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/verify"))
            .respond_with(ResponseTemplate::new(404))
            .up_to_n_times(1)
            .mount(&scan)
            .await;
        Mock::given(method("POST"))
            .and(path("/verify"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"verified": true})),
            )
            .expect(1)
            .mount(&scan)
            .await;

        let v = Verifier::new(test_cfg(scan.uri())).unwrap();
        let fresh: Address = "0x4444444444444444444444444444444444444444".parse().unwrap();
        assert_eq!(v.require_verified("app", &fresh, SCAN_LAG_WAIT).await, Ok(()));
    }

    /// If scan still does not know the signer, the answer is the text tapp-server waits on, and
    /// it is not damped like a negative: the signer is on chain, so the next try may succeed.
    #[tokio::test]
    async fn a_signer_scan_does_not_know_is_not_cached_as_a_negative() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let scan = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/verify"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1) // the immediate repeat is answered by the marker
            .mount(&scan)
            .await;

        let v = Verifier::new(test_cfg(scan.uri())).unwrap();
        let s: Address = "0x5555555555555555555555555555555555555555".parse().unwrap();
        let want = Err("attestation not verified: not registered on-chain per verifier".into());
        assert_eq!(v.require_verified("app", &s, Duration::ZERO).await, want);
        assert_eq!(v.require_verified("app", &s, Duration::ZERO).await, want);

        let cache = v.cache.read().await;
        let e = cache.get(&("app".to_string(), s)).unwrap();
        assert!(!e.verified);
        assert_eq!(e.damp, SCAN_LAG_DAMP);
        assert!(SCAN_LAG_DAMP < NEGATIVE_TTL);
    }

    /// A signer with a positive past its hourly refresh keeps working if scan does not know it
    /// (scan resynced its registry, say), and is not held up by the wait meant for new signers.
    #[tokio::test]
    async fn a_known_signer_is_not_held_up_when_scan_forgets_it() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let scan = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/verify"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&scan)
            .await;

        let v = Verifier::new(test_cfg(scan.uri())).unwrap();
        let s: Address = "0x6666666666666666666666666666666666666666".parse().unwrap();
        let two_hours_ago = Instant::now() - Duration::from_secs(2 * 3600);
        v.cache.write().await.insert(
            ("app".to_string(), s),
            CacheEntry {
                verified: true,
                refusal: String::new(),
                damp: Duration::ZERO,
                at: two_hours_ago,
                confirmed_at: two_hours_ago,
            },
        );

        let started = Instant::now();
        assert_eq!(v.require_verified("app", &s, SCAN_LAG_WAIT).await, Ok(()));
        assert!(started.elapsed() < SCAN_LAG_POLL);
    }
}
