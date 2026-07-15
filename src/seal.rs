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
//! ## Transport (v1) — canonical & versioned
//!
//! The sealed share is a **base64url string** carried in an env var into the container
//! (`KMS_SEALED_SHARE`) and emitted back out on every seal as a `SEALED_SHARE=<b64url>` log
//! line (safe — it is ciphertext, useless without this TEE's key). The deploy pipeline captures
//! the latest from the logs and re-injects it on the next start. No durable disk is assumed.
//! Absent env → the operator is signalling a deliberate fresh start (they know the master
//! changed) → the node rejoins/genesis-es anew.
//!
//! ```text
//! blob = MAGIC(4) ‖ ENVELOPE_VERSION(1) ‖ ECIES(own_uncompressed_pubkey, serde_bare(Record))
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
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
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

/// Seal `rec` into the raw blob bytes, encrypted to `own_pubkey` (uncompressed secp256k1).
pub fn seal_to_bytes(own_pubkey: &[u8], rec: &SealedShareV1) -> Result<Vec<u8>> {
    let payload = serde_bare::to_vec(rec).map_err(|e| anyhow!("seal serialize: {}", e))?;
    let ct = ecies_encrypt(own_pubkey, &payload).map_err(|e| anyhow!("seal encrypt: {}", e))?;
    let mut buf = Vec::with_capacity(5 + ct.len());
    buf.extend_from_slice(&MAGIC);
    buf.push(ENVELOPE_VERSION);
    buf.extend_from_slice(&ct);
    Ok(buf)
}

/// Unseal a raw blob with `own_privkey`.
///
/// Returns `Ok(None)` (NOT an error) for every "no usable share, just rejoin" case: foreign /
/// old magic or envelope, or ECIES decrypt failure (a DIFFERENT TEE identity — the
/// crash-vs-restart signal). `Err` only on genuine corruption of an otherwise-ours record
/// (decryptable but unparseable), which the caller should log and then rejoin.
pub fn unseal_from_bytes(buf: &[u8], own_privkey: &[u8; 32]) -> Result<Option<SealedShareV1>> {
    if buf.len() < 5 || buf[0..4] != MAGIC {
        return Ok(None); // not one of our sealed blobs
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

/// Seal to a base64url (no-pad) string for env/log transport.
pub fn seal_b64(own_pubkey: &[u8], rec: &SealedShareV1) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(seal_to_bytes(own_pubkey, rec)?))
}

/// Unseal from a base64url string (as carried in `KMS_SEALED_SHARE`). A malformed base64
/// string yields `Ok(None)` — treat as "no usable share" and rejoin.
pub fn unseal_b64(s: &str, own_privkey: &[u8; 32]) -> Result<Option<SealedShareV1>> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    match URL_SAFE_NO_PAD.decode(s) {
        Ok(buf) => unseal_from_bytes(&buf, own_privkey),
        Err(_) => Ok(None),
    }
}

/// Atomically persist the base64 blob to `path` (tmp + rename, so a crash mid-write can't
/// leave a truncated file). Used when `KMS_SEALED_SHARE_PATH` points at a durable volume —
/// then a restart reloads automatically, no pipeline capture/inject needed.
pub fn write_blob_file(path: &str, b64: &str) -> Result<()> {
    let tmp = format!("{}.tmp", path);
    std::fs::write(&tmp, b64).map_err(|e| anyhow!("seal write {}: {}", tmp, e))?;
    std::fs::rename(&tmp, path).map_err(|e| anyhow!("seal rename -> {}: {}", path, e))?;
    Ok(())
}

/// Read a persisted blob file. Absent file → `Ok(None)` (fresh start / no durable state).
pub fn read_blob_file(path: &str) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(s) if !s.trim().is_empty() => Ok(Some(s.trim().to_string())),
        Ok(_) => Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow!("seal read {}: {}", path, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pubkey_from_private;

    fn rec() -> SealedShareV1 {
        SealedShareV1::new(3, 7, vec![0xAAu8; 48], vec![0x11u8; 40])
    }

    #[test]
    fn seal_unseal_roundtrip_same_identity() {
        let sk = [7u8; 32];
        let pk = pubkey_from_private(&sk).unwrap();
        let s = seal_b64(&pk, &rec()).unwrap();
        // base64url string: env/log safe (no +, /, =).
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        let got = unseal_b64(&s, &sk).unwrap().unwrap();
        assert_eq!(got, rec(), "same TEE identity unseals the exact record");
    }

    #[test]
    fn unseal_fails_for_different_identity() {
        // A different TEE identity (crash → new signer) must NOT be able to unseal.
        let sk = [7u8; 32];
        let pk = pubkey_from_private(&sk).unwrap();
        let s = seal_b64(&pk, &rec()).unwrap();
        let other = [9u8; 32];
        assert!(
            unseal_b64(&s, &other).unwrap().is_none(),
            "a different key must yield None (→ rejoin), never the share"
        );
    }

    #[test]
    fn unseal_empty_or_foreign_is_none() {
        let sk = [7u8; 32];
        assert!(unseal_b64("", &sk).unwrap().is_none(), "empty env → None");
        assert!(unseal_b64("   ", &sk).unwrap().is_none(), "blank env → None");
        assert!(
            unseal_b64("bm90IGEga21zIHNlYWw", &sk).unwrap().is_none(),
            "foreign magic → None"
        );
        assert!(
            unseal_b64("!!!not base64!!!", &sk).unwrap().is_none(),
            "malformed base64 → None"
        );
    }

    #[test]
    fn blob_file_roundtrip_and_absent() {
        let sk = [7u8; 32];
        let pk = pubkey_from_private(&sk).unwrap();
        let path = std::env::temp_dir()
            .join(format!("kms-seal-file-{}.b64", std::process::id()))
            .to_string_lossy()
            .into_owned();
        // Absent → None (fresh start).
        assert!(read_blob_file(&path).unwrap().is_none());
        // Auto-persist + reload: the SAME base64 string round-trips through the file and
        // unseals to the exact record.
        let b64 = seal_b64(&pk, &rec()).unwrap();
        write_blob_file(&path, &b64).unwrap();
        let loaded = read_blob_file(&path).unwrap().unwrap();
        assert_eq!(loaded, b64);
        assert_eq!(unseal_b64(&loaded, &sk).unwrap().unwrap(), rec());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampered_ciphertext_does_not_yield_share() {
        let sk = [7u8; 32];
        let pk = pubkey_from_private(&sk).unwrap();
        let mut buf = seal_to_bytes(&pk, &rec()).unwrap();
        let last = buf.len() - 1;
        buf[last] ^= 0xFF; // flip a ciphertext byte
        match unseal_from_bytes(&buf, &sk) {
            Ok(None) | Err(_) => {}
            Ok(Some(_)) => panic!("tampered blob must never yield a usable share"),
        }
    }
}
