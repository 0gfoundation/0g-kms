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

// ─── DKG bridge (gennaro-dkg → blsful) ─────────────────────────────────────────
//
// Genesis (no dealer) and lost-share recovery are done with gennaro-dkg, which is
// curve-agnostic. We instantiate it over blsful's own blst backend (blstrs_plus) so a
// participant's raw scalar share drops straight into a blsful `SecretKeyShare` with no
// re-encoding — the DPRF path above is then identical whether the share came from a
// dealer split, a distributed DKG, or a reshare. Verified end-to-end (PoC): the bridged
// share signs/combines to the same σ as a dealer-split share, and reconstructed sk·G
// equals the DKG group public key.

/// The group gennaro runs over. blsful's `Bls12381G2Impl` puts public keys in G1, so the
/// DKG group public key lives in G1 and share values are the shared BLS12-381 scalar field.
pub type DkgGroup = blstrs_plus::G1Projective;
/// The BLS12-381 scalar field element type — same `Scalar` blsful uses internally (blst).
pub type DkgScalar = blstrs_plus::Scalar;

/// Bridge a gennaro participant's `(id, secret_share)` output into a blsful `SecretKeyShare`.
/// `id` is the 1-based on-chain nodeList position (also the Lagrange identifier); `scalar`
/// is `Participant::get_secret_share()`. The identifier/value types are exactly blsful's
/// inner share type over the same blstrs_plus `Scalar`, so this is a zero-cost re-wrap.
pub fn gennaro_share_to_blsful(id: usize, scalar: DkgScalar) -> SecretKeyShare<Bls> {
    use blsful::vsss_rs::{DefaultShare, IdentifierPrimeField};
    let identifier = IdentifierPrimeField(DkgScalar::from(id as u64));
    let value = IdentifierPrimeField(scalar);
    SecretKeyShare(DefaultShare { identifier, value })
}

/// Extract the raw scalar value from a blsful secret-key share (inverse of the bridge), so
/// a genesis/DKG share can be fed back into a gennaro reshare as a dealer's secret.
pub fn blsful_share_scalar(share: &SecretKeyShare<Bls>) -> DkgScalar {
    share.0.value.0
}

/// This node's own uncompressed secp256k1 public key (65 bytes, 0x04-prefixed) from its
/// private key. Gossiped to peers so they can ECIES-encrypt DKG round-1 p2p shares to us
/// (peer_table otherwise only knows the eth_addr, a hash from which the pubkey can't be
/// recovered).
pub fn pubkey_from_private(private_key: &[u8; 32]) -> Result<Vec<u8>> {
    use k256::ecdsa::SigningKey;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let sk = SigningKey::from_bytes(private_key.into())
        .map_err(|e| anyhow!("invalid private key: {}", e))?;
    Ok(sk.verifying_key().to_encoded_point(false).as_bytes().to_vec())
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

// ─── DKG bridge tests (gennaro genesis + reshare recovery → blsful DPRF) ────────
//
// Proves in-process that shares produced by a distributed DKG, and shares repaired by a
// reshare, both drop into the blsful DPRF path and derive the SAME app key as before —
// i.e. genesis without a dealer, and lost-share recovery, preserve the master. The
// distributed transport (Phase 2) drives the exact same gennaro rounds over gRPC.

#[cfg(test)]
mod dkg_tests {
    use super::*;
    use blstrs_plus::{G1Projective, Scalar};
    use ff::Field;
    use gennaro_dkg::{Parameters, RefreshParticipant, SecretParticipant};
    use group::Group;
    use std::collections::BTreeMap;
    use std::num::NonZeroUsize;

    fn nz(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).unwrap()
    }

    /// App key from a set of (id, scalar-share) via the real DPRF path (bridge + combine).
    fn app_key(shares: &[(usize, Scalar)], app_id: &str, material: &[u8]) -> [u8; 32] {
        let msg = dprf_message(app_id, material);
        let partials: Vec<_> = shares
            .iter()
            .map(|(id, s)| dprf_partial(&gennaro_share_to_blsful(*id, *s), &msg).unwrap())
            .collect();
        dprf_combine(&partials).unwrap()
    }

    /// Lagrange interpolation at x=0 over (id, share) points (for the sk·G == pk check).
    fn lagrange0(points: &[(usize, Scalar)]) -> Scalar {
        let mut acc = Scalar::ZERO;
        for (i, (xi, yi)) in points.iter().enumerate() {
            let xi_s = Scalar::from(*xi as u64);
            let (mut num, mut den) = (Scalar::ONE, Scalar::ONE);
            for (j, (xj, _)) in points.iter().enumerate() {
                if i == j {
                    continue;
                }
                let xj_s = Scalar::from(*xj as u64);
                num *= xj_s;
                den *= xj_s - xi_s;
            }
            acc += *yi * num * den.invert().unwrap();
        }
        acc
    }

    /// Drive a homogeneous set of SecretParticipants through the 5 DKG rounds in-process.
    fn drive(ps: &mut [SecretParticipant<G1Projective>]) {
        let ids: Vec<usize> = ps.iter().map(|p| p.get_id()).collect();
        let n = ps.len();
        let (mut b1, mut p2p1) = (Vec::new(), Vec::new());
        for p in ps.iter_mut() {
            let (b, p2p) = p.round1().unwrap();
            b1.push(b);
            p2p1.push(p2p);
        }
        let mut b2 = BTreeMap::new();
        for i in 0..n {
            let my = ids[i];
            let (mut bd, mut pd) = (BTreeMap::new(), BTreeMap::new());
            for j in 0..n {
                if i == j {
                    continue;
                }
                bd.insert(ids[j], b1[j].clone());
                pd.insert(ids[j], p2p1[j][&my].clone());
            }
            b2.insert(my, ps[i].round2(bd, pd).unwrap());
        }
        let mut b3 = BTreeMap::new();
        for i in 0..n {
            b3.insert(ids[i], ps[i].round3(&b2).unwrap());
        }
        let mut b4 = BTreeMap::new();
        for i in 0..n {
            b4.insert(ids[i], ps[i].round4(&b3).unwrap());
        }
        for p in ps.iter_mut() {
            p.round5(&b4).unwrap();
        }
    }

    #[test]
    fn dkg_genesis_bridges_to_dprf() {
        // Distributed 2-of-3 genesis (no dealer), then derive via the DPRF path.
        let params = Parameters::<G1Projective>::new(nz(2), nz(3));
        let mut ps: Vec<_> = (1..=3)
            .map(|i| SecretParticipant::<G1Projective>::new(nz(i), params).unwrap())
            .collect();
        drive(&mut ps);

        let pk = ps[0].get_public_key().unwrap();
        assert_eq!(pk, ps[1].get_public_key().unwrap());
        assert_eq!(pk, ps[2].get_public_key().unwrap());

        let sh: Vec<(usize, Scalar)> = ps
            .iter()
            .map(|p| (p.get_id(), p.get_secret_share().unwrap()))
            .collect();
        let k_all = app_key(&sh, "app", b"m");
        assert_eq!(k_all, app_key(&sh[0..2], "app", b"m"), "subset {{1,2}} agrees");
        assert_eq!(k_all, app_key(&sh[1..3], "app", b"m"), "subset {{2,3}} agrees");
        assert_ne!(k_all, app_key(&sh, "app", b"other"), "material-bound");

        // The DKG shares lie on a polynomial whose intercept is the master: sk·G == pk.
        assert_eq!(G1Projective::generator() * lagrange0(&sh[0..2]), pk);
    }

    #[test]
    fn dkg_reshare_recovers_lost_share() {
        // Genesis 2-of-3.
        let params = Parameters::<G1Projective>::new(nz(2), nz(3));
        let mut ps: Vec<_> = (1..=3)
            .map(|i| SecretParticipant::<G1Projective>::new(nz(i), params).unwrap())
            .collect();
        drive(&mut ps);
        let pk0 = ps[0].get_public_key().unwrap();
        let sh0: Vec<(usize, Scalar)> = ps
            .iter()
            .map(|p| (p.get_id(), p.get_secret_share().unwrap()))
            .collect();
        let k0 = app_key(&sh0, "app", b"m");

        // Node 3 lost its share. Survivors {1,2} reshare (with_secret preserves the master);
        // node 3 rejoins as a RefreshParticipant (contributes 0) and comes out with a share.
        let rp = Parameters::<G1Projective>::new(nz(2), nz(3));
        let dealer_ids = [Scalar::from(1u64), Scalar::from(2u64)];
        let mut d1 =
            SecretParticipant::<G1Projective>::with_secret(nz(1), rp, sh0[0].1, &dealer_ids, 0)
                .unwrap();
        let mut d2 =
            SecretParticipant::<G1Projective>::with_secret(nz(2), rp, sh0[1].1, &dealer_ids, 1)
                .unwrap();
        let mut r3 = RefreshParticipant::<G1Projective>::new(nz(3), rp).unwrap();

        // Round 1 (broadcast + p2p; round-data types are parameterised by the group only,
        // so SecretParticipant and RefreshParticipant outputs share a type and mix freely).
        let (b1, p1) = d1.round1().unwrap();
        let (b2, p2) = d2.round1().unwrap();
        let (b3, p3) = r3.round1().unwrap();

        // Round 2.
        let r2_1 = d1
            .round2(
                BTreeMap::from([(2, b2.clone()), (3, b3.clone())]),
                BTreeMap::from([(2, p2[&1].clone()), (3, p3[&1].clone())]),
            )
            .unwrap();
        let r2_2 = d2
            .round2(
                BTreeMap::from([(1, b1.clone()), (3, b3.clone())]),
                BTreeMap::from([(1, p1[&2].clone()), (3, p3[&2].clone())]),
            )
            .unwrap();
        let r2_3 = r3
            .round2(
                BTreeMap::from([(1, b1.clone()), (2, b2.clone())]),
                BTreeMap::from([(1, p1[&3].clone()), (2, p2[&3].clone())]),
            )
            .unwrap();

        // Rounds 3–5 take the full map of the previous round's broadcasts (incl. self).
        let b2map = BTreeMap::from([(1, r2_1), (2, r2_2), (3, r2_3)]);
        let b3map = BTreeMap::from([
            (1, d1.round3(&b2map).unwrap()),
            (2, d2.round3(&b2map).unwrap()),
            (3, r3.round3(&b2map).unwrap()),
        ]);
        let b4map = BTreeMap::from([
            (1, d1.round4(&b3map).unwrap()),
            (2, d2.round4(&b3map).unwrap()),
            (3, r3.round4(&b3map).unwrap()),
        ]);
        d1.round5(&b4map).unwrap();
        d2.round5(&b4map).unwrap();
        r3.round5(&b4map).unwrap();

        // Master (group pubkey) is unchanged, and node 3 has a fresh, consistent share.
        assert_eq!(r3.get_public_key().unwrap(), pk0, "reshare must preserve the master");
        let sh_new = [
            (1, d1.get_secret_share().unwrap()),
            (2, d2.get_secret_share().unwrap()),
            (3, r3.get_secret_share().unwrap()),
        ];
        assert_eq!(app_key(&sh_new, "app", b"m"), k0, "recovered committee derives same key");
        // NOTE: reshare refreshes the WHOLE committee onto a new polynomial f' (f'(0) still
        // = master). Survivors' shares change too, so an ORIGINAL share must NOT be mixed
        // with reshared ones — Phase 4 must persist every participant's new share.
    }
}
