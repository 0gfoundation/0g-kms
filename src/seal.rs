//! Sealed on-disk share (persistence).
//!
//! A node seals its current share to disk so an app/container restart can reload it WITHOUT a
//! rejoin. This is the only thing that works at the **threshold floor** (exactly `threshold`
//! live share-holders), where rejoin is mathematically impossible (rejoin needs `>= threshold`
//! OTHER live holders).
//!
//! ## Binding to the TEE identity (this is what gives the restart-vs-crash distinction)
//!
//! The record is ECIES-encrypted to the node's OWN TEE-derived secp256k1 public key, so only
//! the same TEE identity (same app-key) can unseal it:
//!   * app / container restart      → app-key unchanged → unseal succeeds → reload, no rejoin.
//!   * tapp-daemon crash / new host → app-key changes (= signer changes) → ECIES decrypt fails
//!                                    → treated as "no usable blob" → fall back to rejoin.
//!
//! Confidentiality of the share at rest comes from the ECIES envelope (the TEE key), NOT from
//! the disk — the blob may live on ordinary host storage.
//!
//! ## File format (v1) — canonical & versioned
//!
//! ```text
//! file = MAGIC(4) ‖ ENVELOPE_VERSION(1) ‖ ECIES(own_uncompressed_pubkey, serde_bare(Record))
//!
//! MAGIC            = b"KMSS"        // KMS Sealed Share
//! ENVELOPE_VERSION = 0x01           // cleartext, so a future envelope change is detectable
//!
//! Record (serde_bare, encrypted) {
//!     record_version : u16   = 1
//!     shard_index    : u32          // 1-based nodeList participant id (= Lagrange x)
//!     epoch          : u64          // polynomial epoch of this share (staleness check)
//!     master_id      : Vec<u8>      // group public key (BLS12-381 G1, 48B) — identifies master
//!     share          : Vec<u8>      // canonical blsful SecretKeyShare<Bls12381G2Impl> bytes,
//!                                   // exactly crypto::share_to_bytes — the ONE share format
//!                                   // used in-memory, on the wire, and at rest. NOT re-encoded.
//! }
//! ```
//!
//! On boot the caller must still validate the record against the live cluster before trusting
//! it: `master_id` must match the cluster group pubkey (else a re-genesis happened) and `epoch`
//! must not be behind the cluster (else the node fell behind during downtime) — otherwise the
//! share is discarded and the node rejoins.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use crate::crypto::{ecies_decrypt, ecies_encrypt};

const MAGIC: [u8; 4] = *b"KMSS";
const ENVELOPE_VERSION: u8 = 1;
const RECORD_VERSION: u16 = 1;

/// The versioned, sealed share record (see the module-level format spec).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedShareV1 {
    pub record_version: u16,
    pub shard_index: u32,
    pub epoch: u64,
    /// Group public key bytes (BLS12-381 G1) — identifies which master this share belongs to.
    pub master_id: Vec<u8>,
    /// Canonical blsful `SecretKeyShare<Bls12381G2Impl>` bytes (= `crypto::share_to_bytes`).
    pub share: Vec<u8>,
}

impl SealedShareV1 {
    pub fn new(shard_index: u32, epoch: u64, master_id: Vec<u8>, share: Vec<u8>) -> Self {
        Self {
            record_version: RECORD_VERSION,
            shard_index,
            epoch,
            master_id,
            share,
        }
    }
}

/// Seal `rec` to `path`, encrypted to `own_pubkey` (uncompressed secp256k1, 65 bytes).
/// Written atomically (tmp + rename) so a crash mid-write can't leave a truncated blob.
pub fn seal(path: &str, own_pubkey: &[u8], rec: &SealedShareV1) -> Result<()> {
    let payload = serde_bare::to_vec(rec).map_err(|e| anyhow!("seal serialize: {}", e))?;
    let ct = ecies_encrypt(own_pubkey, &payload).map_err(|e| anyhow!("seal encrypt: {}", e))?;

    let mut buf = Vec::with_capacity(5 + ct.len());
    buf.extend_from_slice(&MAGIC);
    buf.push(ENVELOPE_VERSION);
    buf.extend_from_slice(&ct);

    let tmp = format!("{}.tmp", path);
    std::fs::write(&tmp, &buf).map_err(|e| anyhow!("seal write {}: {}", tmp, e))?;
    std::fs::rename(&tmp, path).map_err(|e| anyhow!("seal rename -> {}: {}", path, e))?;
    Ok(())
}

/// Read + unseal the record at `path` with `own_privkey`.
///
/// Returns `Ok(None)` (NOT an error) for every "no usable share, just rejoin" case: file
/// absent, foreign/old magic or envelope, or ECIES decrypt failure (a DIFFERENT TEE identity —
/// the crash-vs-restart signal). Returns `Err` only on genuine corruption of an otherwise-ours
/// record (decryptable but unparseable), which the caller should log and then rejoin.
pub fn unseal(path: &str, own_privkey: &[u8; 32]) -> Result<Option<SealedShareV1>> {
    let buf = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow!("unseal read {}: {}", path, e)),
    };
    if buf.len() < 5 || buf[0..4] != MAGIC {
        return Ok(None); // not one of our sealed files
    }
    if buf[4] != ENVELOPE_VERSION {
        return Ok(None); // unknown envelope version — don't guess
    }
    // Decrypt failure = a different TEE identity (new signer) or a corrupt envelope → no usable
    // share; the node must rejoin. This is exactly the recoverable-vs-unrecoverable distinction.
    let payload = match ecies_decrypt(own_privkey, &buf[5..]) {
        Ok(p) => p,
        Err(_) => return Ok(None),
    };
    let rec: SealedShareV1 =
        serde_bare::from_slice(&payload).map_err(|e| anyhow!("unseal deserialize: {}", e))?;
    if rec.record_version != RECORD_VERSION {
        return Ok(None); // future record format we can't read
    }
    Ok(Some(rec))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pubkey_from_private;

    fn tmp_path(tag: &str) -> String {
        std::env::temp_dir()
            .join(format!("kms-seal-test-{}-{}.bin", tag, std::process::id()))
            .to_string_lossy()
            .into_owned()
    }

    fn rec() -> SealedShareV1 {
        SealedShareV1::new(3, 7, vec![0xAAu8; 48], vec![0x11u8; 40])
    }

    #[test]
    fn seal_unseal_roundtrip_same_identity() {
        let sk = [7u8; 32];
        let pk = pubkey_from_private(&sk).unwrap();
        let path = tmp_path("roundtrip");
        seal(&path, &pk, &rec()).unwrap();
        let got = unseal(&path, &sk).unwrap().unwrap();
        assert_eq!(got, rec(), "same TEE identity unseals the exact record");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unseal_fails_for_different_identity() {
        // A different TEE identity (crash → new signer) must NOT be able to unseal.
        let sk = [7u8; 32];
        let pk = pubkey_from_private(&sk).unwrap();
        let path = tmp_path("wrongkey");
        seal(&path, &pk, &rec()).unwrap();
        let other = [9u8; 32];
        assert!(
            unseal(&path, &other).unwrap().is_none(),
            "a different key must yield None (→ rejoin), never the share"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unseal_absent_or_foreign_is_none() {
        let sk = [7u8; 32];
        assert!(unseal(&tmp_path("absent-xyz"), &sk).unwrap().is_none());

        let path = tmp_path("foreign");
        std::fs::write(&path, b"not a kms sealed file").unwrap();
        assert!(unseal(&path, &sk).unwrap().is_none(), "foreign magic → None");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampered_ciphertext_does_not_yield_share() {
        let sk = [7u8; 32];
        let pk = pubkey_from_private(&sk).unwrap();
        let path = tmp_path("tamper");
        seal(&path, &pk, &rec()).unwrap();
        let mut buf = std::fs::read(&path).unwrap();
        let last = buf.len() - 1;
        buf[last] ^= 0xFF; // flip a ciphertext byte
        std::fs::write(&path, &buf).unwrap();
        // AEAD must reject: either None (decrypt failed) or a hard error — never the record.
        match unseal(&path, &sk) {
            Ok(None) | Err(_) => {}
            Ok(Some(_)) => panic!("tampered blob must never yield a usable share"),
        }
        let _ = std::fs::remove_file(&path);
    }
}
