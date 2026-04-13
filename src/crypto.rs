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
}
