use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::KmsError;

// ─── HKDF ─────────────────────────────────────────────────────────────────────

/// Derive a 32-byte app key from the master key using HKDF-SHA256.
/// info = "tapp-kms:" || app_id  (no salt; master key is already high-entropy)
pub fn derive_app_key(master_key: &[u8; 32], app_id: &str) -> [u8; 32] {
    let info = format!("tapp-kms:{}", app_id);
    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = [0u8; 32];
    hkdf.expand(info.as_bytes(), &mut okm)
        .expect("HKDF expand failed (32-byte output is always valid)");
    okm
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

// ─── SSS ──────────────────────────────────────────────────────────────────────
//
// Share format (vsss-rs 3.x): GenericArray<u8, U33>
//   byte[0]   = identifier (x-coordinate, 1-based)
//   byte[1..] = scalar value (32 bytes)

// ─── SSS ──────────────────────────────────────────────────────────────────────
//
// Share format (vsss-rs 3.x): GenericArray<u8, U33>
//   byte[0]   = identifier (x-coordinate, 1-based)
//   byte[1..] = scalar value (32 bytes)

use generic_array::GenericArray;
use typenum::U33;
type ScalarShare = GenericArray<u8, U33>;

/// Split a 32-byte secret into `total` shares with `threshold` reconstruction threshold.
/// Returns a vec of (shard_index, shard_bytes) pairs.
/// shard_index is the first byte of the share (x-coordinate, 1-based).
pub fn sss_split(secret: &[u8; 32], threshold: u32, total: u32) -> Result<Vec<(u32, Vec<u8>)>> {
    use elliptic_curve::ff::PrimeField;
    use k256::Scalar;
    use vsss_rs::shamir;

    let repr = GenericArray::from_slice(secret);
    let scalar = Option::<Scalar>::from(Scalar::from_repr(*repr))
        .ok_or_else(|| anyhow!("secret is not a valid k256 scalar"))?;

    let shares: Vec<ScalarShare> = shamir::split_secret::<Scalar, u8, ScalarShare>(
        threshold as usize,
        total as usize,
        scalar,
        &mut rand::thread_rng(),
    )
    .map_err(|e| anyhow!("SSS split failed: {:?}", e))?;

    Ok(shares
        .into_iter()
        .map(|s| (s[0] as u32, s.to_vec()))
        .collect())
}

/// Reconstruct a 32-byte secret from at least `threshold` (shard_index, shard_bytes) pairs.
pub fn sss_reconstruct(shards: &[(u32, Vec<u8>)]) -> Result<[u8; 32]> {
    use elliptic_curve::ff::PrimeField;
    use k256::Scalar;
    use vsss_rs::combine_shares;

    let shares: Vec<ScalarShare> = shards
        .iter()
        .map(|(_, bytes)| {
            if bytes.len() != 33 {
                return Err(anyhow!("shard must be 33 bytes, got {}", bytes.len()));
            }
            Ok(*GenericArray::from_slice(bytes))
        })
        .collect::<Result<Vec<_>>>()?;

    let scalar: Scalar = combine_shares(&shares)
        .map_err(|e| anyhow!("SSS reconstruct failed: {:?}", e))?;

    Ok(scalar.to_repr().into())
}

/// Evaluate the original SSS polynomial at coordinate `x` using Lagrange interpolation
/// over the existing shares.  Returns a 33-byte share [x, y[0..32]] that is consistent
/// with the other shares (same polynomial), unlike a fresh sss_split which uses a new
/// random polynomial and produces incompatible shares.
pub fn sss_evaluate_at(shards: &[(u32, Vec<u8>)], x: u32) -> Result<Vec<u8>> {
    use elliptic_curve::ff::PrimeField;
    use k256::Scalar;

    // Parse each shard into (x_i, y_i) scalars.
    // vsss-rs share format: bytes[0] = x-coord, bytes[1..33] = y-coord.
    let points: Vec<(Scalar, Scalar)> = shards
        .iter()
        .map(|(_, bytes)| {
            if bytes.len() != 33 {
                return Err(anyhow!("shard must be 33 bytes, got {}", bytes.len()));
            }
            let x_i = scalar_from_u8(bytes[0]);
            let y_repr = *GenericArray::from_slice(&bytes[1..]);
            let y_i = Option::<Scalar>::from(Scalar::from_repr(y_repr))
                .ok_or_else(|| anyhow!("invalid scalar in shard"))?;
            Ok((x_i, y_i))
        })
        .collect::<Result<Vec<_>>>()?;

    let x_s = scalar_from_u8(x as u8);

    // Lagrange interpolation: f(x) = Σ y_i · L_i(x)
    // where L_i(x) = Π_{j≠i} (x - x_j) / (x_i - x_j)
    let mut result = Scalar::ZERO;
    for (i, (x_i, y_i)) in points.iter().enumerate() {
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for (j, (x_j, _)) in points.iter().enumerate() {
            if i != j {
                num *= x_s - x_j;
                den *= x_i - x_j;
            }
        }
        let den_inv = Option::<Scalar>::from(den.invert())
            .ok_or_else(|| anyhow!("zero denominator — duplicate x-coordinates?"))?;
        result += *y_i * num * den_inv;
    }

    // Pack result into 33-byte vsss-rs share format.
    let mut share_bytes = vec![x as u8];
    let repr: [u8; 32] = result.to_repr().into();
    share_bytes.extend_from_slice(&repr);
    Ok(share_bytes)
}

fn scalar_from_u8(x: u8) -> k256::Scalar {
    use elliptic_curve::ff::PrimeField;
    let mut repr = [0u8; 32];
    repr[31] = x;
    Option::<k256::Scalar>::from(k256::Scalar::from_repr(*GenericArray::from_slice(&repr)))
        .expect("single byte is always a valid scalar")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    #[test]
    fn test_derive_app_key_deterministic() {
        let master = [0x42u8; 32];
        assert_eq!(derive_app_key(&master, "myapp"), derive_app_key(&master, "myapp"));
    }

    #[test]
    fn test_derive_app_key_different_apps() {
        let master = [0x42u8; 32];
        assert_ne!(derive_app_key(&master, "app-one"), derive_app_key(&master, "app-two"));
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
    fn test_sss_split_reconstruct() {
        let secret = [0xABu8; 32];
        let shards = sss_split(&secret, 2, 3).unwrap();
        assert_eq!(shards.len(), 3);

        // reconstruct from any 2 shards
        let recovered = sss_reconstruct(&shards[..2]).unwrap();
        assert_eq!(recovered, secret);

        let recovered = sss_reconstruct(&shards[1..]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_sign_request() {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let privkey: [u8; 32] = signing_key.to_bytes().into();
        let sig = sign_request(&privkey, "GetShardContribution", 1234567890).unwrap();
        assert_eq!(sig.len(), 65);
    }

    #[test]
    fn test_sss_evaluate_at_consistent_with_split() {
        let secret = [0x77u8; 32];
        // threshold=2, total=3 → degree-1 polynomial
        let shards = sss_split(&secret, 2, 3).unwrap();

        // Interpolate shard[2] from shard[0] + shard[1]
        let recovered2 = sss_evaluate_at(&shards[..2], shards[2].0).unwrap();
        assert_eq!(recovered2, shards[2].1,
            "Lagrange-interpolated shard must match original split shard");

        // Interpolate shard[0] from shard[1] + shard[2]
        let recovered0 = sss_evaluate_at(&shards[1..], shards[0].0).unwrap();
        assert_eq!(recovered0, shards[0].1,
            "Lagrange-interpolated shard must match original split shard (reverse)");
    }
}
