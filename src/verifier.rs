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

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
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

// ─── Pinned-key TLS ─────────────────────────────────────────────────────────────

/// Accepts exactly the configured public keys and nothing else. No CA, no chain, no expiry:
/// the attested cert is self-signed by design, and the entire trust decision is "does the
/// server hold the pinned attested key" — possession is proven by the TLS handshake signature,
/// which is still verified (below) with the provider's real algorithms.
#[derive(Debug)]
struct PinnedKeyVerifier {
    /// Raw SubjectPublicKeyInfo key bytes (e.g. the 32 bytes of an Ed25519 key). A small set,
    /// not a single key, so a scan identity rotation can be rolled without a flag day.
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
        let presented = cert.public_key().subject_public_key.data.as_ref();
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

/// What `POST {url}/verify` returns (contract in 0g-tapp-verifier#14).
#[derive(serde::Deserialize)]
struct VerifyResponse {
    verified: bool,
    #[serde(default)]
    reason: String,
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
                    if bytes.is_empty() {
                        // An empty key can never match a presented cert — sloppy config that
                        // would otherwise pass boot and refuse every handshake forever.
                        return Err(anyhow!("[verifier] empty pubkey entry"));
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
    pub async fn require_verified(&self, app_id: &str, signer: &Address) -> Result<(), String> {
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

        let outcome = self.fetch(app_id, signer).await;
        let now = Instant::now();
        let mut cache = self.cache.write().await;
        // Bound the cache: entries whose damping stamp is far past every TTL are dead weight
        // (each signer generation leaves one behind, forever). Amortized on the fetch path,
        // which is already the slow path.
        if cache.len() > 4096 {
            cache.retain(|_, e| e.at.elapsed() < MAX_VERDICT_STALENESS);
        }
        let result = match outcome {
            Ok((true, _)) => {
                cache.insert(key.clone(), CacheEntry { verified: true, at: now, confirmed_at: now });
                crate::metrics::inc(&m.verifier_allowed);
                Ok(())
            }
            Ok((false, reason)) => {
                // A fresh negative resets confirmed_at too: an explicit revocation must not
                // leave a stale-positive escape hatch behind.
                cache.insert(key.clone(), CacheEntry { verified: false, at: now, confirmed_at: now });
                crate::metrics::inc(&m.verifier_denied);
                tracing::warn!(app_id, signer = ?signer, %reason, "verifier denied signer");
                Err(format!("attestation not verified: {reason}"))
            }
            Err(e) => {
                // Scan unreachable / rate-limited / broken. A positive confirmed within the
                // staleness cap keeps working — re-stamp the damping clock so a dead scan is
                // retried hourly, not per request. `confirmed_at` is deliberately NOT moved:
                // it is what bounds how long a revocation can stay invisible during an outage.
                if let Some(entry) = cache.get_mut(&key) {
                    if entry.verified && entry.confirmed_at.elapsed() < MAX_VERDICT_STALENESS {
                        entry.at = now;
                        crate::metrics::inc(&m.verifier_stale_served);
                        tracing::warn!(app_id, signer = ?signer, error = %e,
                            "verifier unreachable — serving stale positive verdict");
                        return Ok(());
                    }
                }
                cache.insert(key.clone(), CacheEntry { verified: false, at: now, confirmed_at: now });
                crate::metrics::inc(&m.verifier_unavailable_refused);
                tracing::warn!(app_id, signer = ?signer, error = %e,
                    "verifier unreachable and signer has no fresh-enough verdict — refusing");
                Err("attestation verifier unreachable and this signer has no prior verdict".into())
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
        if !e.verified && e.at.elapsed() < NEGATIVE_TTL {
            crate::metrics::inc(&m.verifier_denied);
            return Some(Err("attestation not verified (recently checked)".into()));
        }
        None
    }

    async fn fetch(&self, app_id: &str, signer: &Address) -> Result<(bool, String)> {
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
                Ok((v.verified, v.reason))
            }
            // Unknown (app_id, signer): scan rejects before fetching anything — the pair is not
            // registered on-chain. A definite negative, not an outage.
            reqwest::StatusCode::NOT_FOUND => {
                Ok((false, "not registered on-chain per verifier".into()))
            }
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
/// attested key (0g-tapp-verifier#14).
pub async fn require_verified(app_id: &str, signer: &Address) -> Result<(), String> {
    match VERIFIER.get() {
        Some(Some(v)) => v.require_verified(app_id, signer).await,
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

    /// The pin is the entire authenticity story, so test it against real DER: a cert carrying
    /// the pinned key passes, any other key fails — regardless of names, expiry, or issuer.
    #[test]
    fn pin_accepts_exactly_the_pinned_key() {
        let kp1 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let kp2 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert1 = rcgen::CertificateParams::new(vec!["scan".into()])
            .unwrap()
            .self_signed(&kp1)
            .unwrap();
        let cert2 = rcgen::CertificateParams::new(vec!["scan".into()])
            .unwrap()
            .self_signed(&kp2)
            .unwrap();

        let v = PinnedKeyVerifier {
            pinned: vec![kp1.public_key_raw().to_vec()],
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        };
        let name = rustls::pki_types::ServerName::try_from("scan").unwrap();
        let now = rustls::pki_types::UnixTime::now();

        assert!(v
            .verify_server_cert(cert1.der(), &[], &name, &[], now)
            .is_ok());
        assert!(v
            .verify_server_cert(cert2.der(), &[], &name, &[], now)
            .is_err());
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
        // https with no pins, non-hex pin, and an EMPTY pin (hex-decodes to zero bytes and
        // could never match a presented cert) must all be rejected
        for pubkeys in [vec![], vec!["zz".to_string()], vec!["".to_string()], vec!["0x".to_string()]] {
            let cfg = VerifierConfig {
                url: "https://scan.example".into(),
                pubkeys,
                api_key: String::new(),
                insecure_http: false,
            };
            assert!(Verifier::new(cfg).is_err());
        }
        // and a well-formed one builds
        let cfg = VerifierConfig {
            url: "https://scan.example".into(),
            pubkeys: vec!["0x7b13d132".into()],
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

        assert!(v.require_verified("app", &good).await.is_ok());
        assert!(v.require_verified("app", &good).await.is_ok());
        assert!(v.require_verified("app", &bad).await.is_err());
        assert!(v.require_verified("app", &bad).await.is_err());

        // Scan dies. The verified signer keeps working from cache; a never-seen signer is
        // refused — fail-closed applies to the increment only.
        drop(scan);
        let unseen: Address = "0x3333333333333333333333333333333333333333".parse().unwrap();
        assert!(v.require_verified("app", &good).await.is_ok());
        assert!(v.require_verified("app", &unseen).await.is_err());
    }
}
