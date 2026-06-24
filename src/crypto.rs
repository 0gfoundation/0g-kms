use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};

use blsful::{Bls12381G2Impl, SecretKey, SecretKeyShare, Signature, SignatureSchemes, SignatureShare};

use crate::error::KmsError;

// ─── Threshold-BLS DPRF (linear key derivation) ────────────────────────────────
//
// app_key = KDF( σ ),  σ = s · H(msg),  msg = bind(app_id, material)
//
// where `s` is the cluster master (Shamir-shared as f, with f(0) = s) and each node
// holds a share f(i). The per-node partial is the BLS *partial signature* f(i)·H(msg);
// the partials are combined by in-group Lagrange interpolation (`Signature::from_shares`)
// into σ = s·H(msg). The master scalar `s` is NEVER reconstructed — this removes the
// use-time single point that the old `reconstruct master → HKDF` path had.
//
// Why threshold BLS rather than an additive offset (master + H(app_id)):
//   - linear over the shares  → combine without reconstructing the master ✓
//   - one-way (child → master)→ releasing one app_key reveals nothing about `s`
//     (recovering s from σ = s·H(msg) is the discrete log) → multi-tenant safe ✓
//   - deterministic            → `Basic` scheme has no nonce, so σ(msg) is fixed ✓
// An additive public offset would be linear but NOT one-way (master = app_key − H(app_id)),
// so a single leaked app_key would expose the whole keyspace. BLS gives both properties.
//
// The crypto primitives here are entirely provided by `blsful` (IETF BLS12-381, blst
// backend); the only logic we own is the derivation-message binding and the KDF.

/// Concrete curve impl: pubkeys in G1, signatures in G2.
pub type Bls = Bls12381G2Impl;

/// Domain separation tag for the derivation message (preimage of hash-to-curve).
const DPRF_DST: &[u8] = b"0g-kms:dprf:v1";
/// Domain separation tag for hashing σ down to a 32-byte app key.
const KDF_DST: &[u8] = b"0g-kms:dprf-kdf:v1";

/// Bind `app_id` (namespace) and caller-supplied `material` into a single, canonical
/// derivation message. Length-prefixed so no two distinct (app_id, material) pairs can
/// produce the same message — this is what makes the appId namespace isolation
/// unforgeable. The KMS does not interpret `material`; for AgenticID it is the canonical
/// encoding of (chainId ‖ contractAddress ‖ sealId).
pub fn dprf_message(app_id: &str, material: &[u8]) -> Vec<u8> {
    let app = app_id.as_bytes();
    let mut msg = Vec::with_capacity(DPRF_DST.len() + 16 + app.len() + material.len());
    msg.extend_from_slice(DPRF_DST);
    msg.extend_from_slice(&(app.len() as u64).to_be_bytes());
    msg.extend_from_slice(app);
    msg.extend_from_slice(&(material.len() as u64).to_be_bytes());
    msg.extend_from_slice(material);
    msg
}

/// Genesis: generate a fresh master and split it into `total` shares with reconstruction
/// threshold `threshold`. Returned shares are distributed one-per-node; the master scalar
/// is dropped here and never stored. (S2/DKG will later replace this dealer step with a
/// distributed key generation that produces the same `SecretKeyShare` type — the
/// derivation path below is unaffected.)
pub fn split_master(threshold: usize, total: usize) -> Result<Vec<SecretKeyShare<Bls>>> {
    let master = SecretKey::<Bls>::new();
    master
        .split(threshold, total)
        .map_err(|e| anyhow!("master split failed: {:?}", e))
}

/// One node's partial evaluation: f(i) · H(msg), computed locally from its own share.
/// `Basic` is the deterministic (nonce-free) BLS scheme, so the partial — and hence the
/// combined σ — is a fixed function of `msg`.
pub fn dprf_partial(share: &SecretKeyShare<Bls>, msg: &[u8]) -> Result<SignatureShare<Bls>> {
    share
        .sign(SignatureSchemes::Basic, msg)
        .map_err(|e| anyhow!("partial sign failed: {:?}", e))
}

/// Combine ≥ threshold partials into the 32-byte app key. Internally this is in-group
/// Lagrange interpolation of the partial signatures → σ = s·H(msg); the master is never
/// assembled. The caller MUST enforce the threshold count (a sub-threshold set of partials
/// interpolates a *different*, wrong σ rather than erroring).
pub fn dprf_combine(partials: &[SignatureShare<Bls>]) -> Result<[u8; 32]> {
    let sigma = Signature::<Bls>::from_shares(partials)
        .map_err(|e| anyhow!("partial combine failed: {:?}", e))?;
    // Canonical, backend-agnostic serialization of the σ point (compressed) → KDF.
    let sigma_bytes = Vec::<u8>::from(&sigma);
    let mut h = Sha256::new();
    h.update(KDF_DST);
    h.update(&sigma_bytes);
    Ok(h.finalize().into())
}

// ─── Share serialization (wire format for shard distribution + partials) ───────

/// Serialize a secret-key share for on-the-wire distribution (ECIES-wrapped to the peer).
pub fn share_to_bytes(share: &SecretKeyShare<Bls>) -> Vec<u8> {
    Vec::<u8>::from(share)
}

/// Parse a secret-key share received over the wire.
pub fn share_from_bytes(bytes: &[u8]) -> Result<SecretKeyShare<Bls>> {
    SecretKeyShare::<Bls>::try_from(bytes.to_vec())
        .map_err(|e| anyhow!("invalid secret-key share bytes: {:?}", e))
}

/// Serialize a partial signature (DPRF contribution) for the wire.
pub fn partial_to_bytes(partial: &SignatureShare<Bls>) -> Vec<u8> {
    Vec::<u8>::from(partial)
}

/// Parse a partial signature received over the wire.
pub fn partial_from_bytes(bytes: &[u8]) -> Result<SignatureShare<Bls>> {
    SignatureShare::<Bls>::try_from(bytes.to_vec())
        .map_err(|e| anyhow!("invalid partial signature bytes: {:?}", e))
}

// ─── ECIES ────────────────────────────────────────────────────────────────────

/// ECIES-encrypt `plaintext` for a secp256k1 public key (65 bytes, uncompressed).
pub fn ecies_encrypt(pubkey_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, KmsError> {
    ecies::encrypt(pubkey_bytes, plaintext)
        .map_err(|e| KmsError::CryptoError(format!("ECIES encrypt failed: {}", e)))
}

/// ECIES-decrypt `ciphertext` with a secp256k1 private key (32 bytes).
pub fn ecies_decrypt(private_key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, KmsError> {
    ecies::decrypt(private_key, ciphertext)
        .map_err(|e| KmsError::CryptoError(format!("ECIES decrypt failed: {}", e)))
}

// ─── Signing ──────────────────────────────────────────────────────────────────

/// Sign a gRPC request message with a secp256k1 private key.
/// Returns a recoverable signature (65 bytes: r || s || v).
/// Signed message: "kms:{method}:{timestamp}"
pub fn sign_request(private_key: &[u8; 32], method: &str, timestamp: i64) -> Result<Vec<u8>> {
    use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, SigningKey};
    use sha3::{Digest, Keccak256};

    let message = format!("kms:{}:{}", method, timestamp);
    let hash = Keccak256::digest(message.as_bytes());

    let signing_key = SigningKey::from_bytes(private_key.into())
        .map_err(|e| anyhow!("invalid signing key: {}", e))?;
    let (sig, recovery_id): (k256::ecdsa::Signature, RecoveryId) =
        signing_key.sign_prehash(&hash)
            .map_err(|e| anyhow!("signing failed: {}", e))?;

    let mut bytes = sig.to_bytes().to_vec(); // 64 bytes: r || s
    bytes.push(recovery_id.to_byte());       // + v
    Ok(bytes)
}

// ─── Tests ────────────────────────────────────────────────────────────────────
//
// Guardrail #2: blsful itself ships only a thin test suite, so we exhaustively pin the
// exact slice we depend on — determinism, material/namespace binding, and threshold
// behaviour — independent of the crate's own coverage.

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    /// Derive an app key end-to-end from a set of shares for a given (app_id, material).
    fn derive(shares: &[SecretKeyShare<Bls>], app_id: &str, material: &[u8]) -> [u8; 32] {
        let msg = dprf_message(app_id, material);
        let partials: Vec<_> = shares.iter().map(|s| dprf_partial(s, &msg).unwrap()).collect();
        dprf_combine(&partials).unwrap()
    }

    #[test]
    fn dprf_is_deterministic() {
        let shares = split_master(2, 3).unwrap();
        let k1 = derive(&shares[..2], "app-A", b"material-1");
        let k2 = derive(&shares[..2], "app-A", b"material-1");
        assert_eq!(k1, k2, "same (master, app_id, material) must yield byte-identical key");
    }

    #[test]
    fn dprf_threshold_subsets_agree() {
        // t=2, n=3: any 2-of-3 subset must reconstruct the SAME app key (the true s·H(msg)).
        let shares = split_master(2, 3).unwrap();
        let msg = dprf_message("app-A", b"mat");
        let p: Vec<_> = shares.iter().map(|s| dprf_partial(s, &msg).unwrap()).collect();

        let k01 = dprf_combine(&[p[0].clone(), p[1].clone()]).unwrap();
        let k02 = dprf_combine(&[p[0].clone(), p[2].clone()]).unwrap();
        let k12 = dprf_combine(&[p[1].clone(), p[2].clone()]).unwrap();
        let k012 = dprf_combine(&p).unwrap();

        assert_eq!(k01, k02);
        assert_eq!(k01, k12);
        assert_eq!(k01, k012, "full set and any threshold subset must agree");
    }

    #[test]
    fn dprf_subthreshold_differs() {
        // Below the reconstruction threshold the combine interpolates a DIFFERENT (wrong)
        // polynomial value, not s·H(msg) — and the library does so SILENTLY rather than
        // erroring. This is exactly why the threshold count must be enforced at the collect
        // layer (collect_and_dprf), not relied upon from the crypto primitive.
        // t=3, n=4: a 2-of-4 combine succeeds (≥2 distinct shares) but is wrong; 3-of-4 is right.
        let shares = split_master(3, 4).unwrap();
        let msg = dprf_message("app-A", b"mat");
        let p: Vec<_> = shares.iter().map(|s| dprf_partial(s, &msg).unwrap()).collect();

        let wrong = dprf_combine(&[p[0].clone(), p[1].clone()]).unwrap(); // sub-threshold (2 < 3)
        let right = dprf_combine(&[p[0].clone(), p[1].clone(), p[2].clone()]).unwrap(); // threshold
        assert_ne!(wrong, right, "sub-threshold combine must not equal the true key");
    }

    #[test]
    fn dprf_material_binding() {
        let shares = split_master(2, 3).unwrap();
        let k1 = derive(&shares[..2], "app-A", b"material-1");
        let k2 = derive(&shares[..2], "app-A", b"material-2");
        assert_ne!(k1, k2, "different material must yield different keys");
    }

    #[test]
    fn dprf_appid_namespace_isolation() {
        let shares = split_master(2, 3).unwrap();
        let k_a = derive(&shares[..2], "app-A", b"same-material");
        let k_b = derive(&shares[..2], "app-B", b"same-material");
        assert_ne!(k_a, k_b, "different app_id namespaces must be cryptographically isolated");
    }

    #[test]
    fn dprf_message_is_unambiguous() {
        // Length-prefixing must prevent (app_id, material) boundary collisions:
        // ("ab","c") and ("a","bc") must NOT collapse to the same message.
        assert_ne!(dprf_message("ab", b"c"), dprf_message("a", b"bc"));
    }

    #[test]
    fn share_roundtrip() {
        let shares = split_master(2, 3).unwrap();
        let bytes = share_to_bytes(&shares[0]);
        let back = share_from_bytes(&bytes).unwrap();
        let msg = dprf_message("app", b"m");
        assert_eq!(
            partial_to_bytes(&dprf_partial(&shares[0], &msg).unwrap()),
            partial_to_bytes(&dprf_partial(&back, &msg).unwrap()),
            "share must survive a wire roundtrip unchanged"
        );
    }

    #[test]
    fn partial_roundtrip_and_combine() {
        // Partials must combine correctly after a wire roundtrip (the collect path).
        let shares = split_master(2, 3).unwrap();
        let msg = dprf_message("app", b"m");
        let direct: Vec<_> = shares[..2].iter().map(|s| dprf_partial(s, &msg).unwrap()).collect();
        let viawire: Vec<_> = direct
            .iter()
            .map(|p| partial_from_bytes(&partial_to_bytes(p)).unwrap())
            .collect();
        assert_eq!(dprf_combine(&direct).unwrap(), dprf_combine(&viawire).unwrap());
    }

    #[test]
    fn test_ecies_roundtrip() {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let pubkey = signing_key.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let privkey: [u8; 32] = signing_key.to_bytes().into();

        let plaintext = b"hello kms shard";
        let ciphertext = ecies_encrypt(&pubkey, plaintext).unwrap();
        let decrypted = ecies_decrypt(&privkey, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_sign_request() {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let privkey: [u8; 32] = signing_key.to_bytes().into();
        let sig = sign_request(&privkey, "GetShardContribution", 1234567890).unwrap();
        assert_eq!(sig.len(), 65);
    }
}
