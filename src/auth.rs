/// gRPC inter-node request authentication.
///
/// Every inbound gRPC call must carry two metadata entries:
///   "signature" — recoverable secp256k1 ECDSA signature (hex, 65 bytes)
///                 over "kms:{method}:{timestamp}"
///   "timestamp" — Unix seconds as a decimal string
///
/// Verification steps:
///   1. Parse and range-check timestamp (±timestamp_tolerance_secs).
///   2. Recover caller's public key and eth address from signature.
///   3. Call getNodeList(own_app_id) on-chain; verify caller is in the list.
///
/// On success returns the caller's recovered secp256k1 public key (65 bytes,
/// uncompressed) and eth address so handlers can ECIES-encrypt responses and
/// update the peer table.
use anyhow::{anyhow, Result};
use ethers::types::Address;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};
use tonic::{metadata::MetadataMap, Status};

use crate::chain::get_signer_addresses;
use crate::config::Config;

pub struct AuthContext {
    /// Caller's recovered secp256k1 public key (65 bytes, uncompressed, 0x04 prefix).
    pub caller_pubkey: Vec<u8>,
    /// Caller's Ethereum address derived from caller_pubkey.
    pub caller_eth_addr: Address,
}

/// Authenticate an inbound gRPC request.
/// `method` is the RPC name, e.g. "GetShardContribution".
pub async fn authenticate(
    metadata: &MetadataMap,
    method: &str,
    config: &Config,
) -> Result<AuthContext, Status> {
    let (sig_bytes, timestamp) = parse_metadata(metadata)?;

    // 1. Validate timestamp
    let now = chrono::Utc::now().timestamp();
    if (now - timestamp).abs() > config.server.timestamp_tolerance_secs {
        return Err(Status::unauthenticated(format!(
            "timestamp {} too far from now ({})",
            timestamp, now
        )));
    }

    // 2. Recover caller public key from signature
    let message = format!("kms:{}:{}", method, timestamp);
    let caller_pubkey = recover_pubkey(message.as_bytes(), &sig_bytes)
        .map_err(|e| Status::unauthenticated(format!("invalid signature: {}", e)))?;

    // 3. Derive eth address and verify on-chain
    let caller_eth_addr = eth_address_from_pubkey(&caller_pubkey);
    verify_on_chain(&caller_eth_addr, config)
        .await
        .map_err(|e| Status::unauthenticated(format!("on-chain verification failed: {}", e)))?;

    Ok(AuthContext { caller_pubkey, caller_eth_addr })
}

fn parse_metadata(metadata: &MetadataMap) -> Result<(Vec<u8>, i64), Status> {
    let sig_hex = metadata
        .get("signature")
        .ok_or_else(|| Status::unauthenticated("missing 'signature' metadata"))?
        .to_str()
        .map_err(|_| Status::unauthenticated("'signature' is not valid UTF-8"))?;

    let ts_str = metadata
        .get("timestamp")
        .ok_or_else(|| Status::unauthenticated("missing 'timestamp' metadata"))?
        .to_str()
        .map_err(|_| Status::unauthenticated("'timestamp' is not valid UTF-8"))?;

    let sig_bytes = hex::decode(sig_hex.trim_start_matches("0x"))
        .map_err(|_| Status::unauthenticated("'signature' is not valid hex"))?;
    if sig_bytes.len() != 65 {
        return Err(Status::unauthenticated("signature must be 65 bytes"));
    }

    let timestamp = ts_str
        .parse::<i64>()
        .map_err(|_| Status::unauthenticated("'timestamp' is not a valid integer"))?;

    Ok((sig_bytes, timestamp))
}

/// Recover uncompressed secp256k1 public key (65 bytes) from a recoverable signature.
/// sig_bytes layout: r (32) || s (32) || v (1)
fn recover_pubkey(message: &[u8], sig_bytes: &[u8]) -> Result<Vec<u8>> {
    let v = sig_bytes[64];
    let recovery_id = RecoveryId::try_from(v % 2)
        .map_err(|_| anyhow!("invalid recovery id {}", v))?;
    let sig = Signature::from_slice(&sig_bytes[..64])
        .map_err(|e| anyhow!("cannot parse signature: {}", e))?;
    let hash = Keccak256::digest(message);
    let verifying_key = VerifyingKey::recover_from_prehash(&hash, &sig, recovery_id)
        .map_err(|e| anyhow!("key recovery failed: {}", e))?;
    Ok(verifying_key.to_encoded_point(false).as_bytes().to_vec())
}

/// Derive Ethereum address from an uncompressed public key (65 bytes, 0x04 prefix).
pub fn eth_address_from_pubkey(pubkey: &[u8]) -> Address {
    let hash = Keccak256::digest(&pubkey[1..]); // skip 0x04 prefix
    Address::from_slice(&hash[12..])
}

/// Verify that `addr` is registered in getNodeList(own_app_id) on-chain.
async fn verify_on_chain(addr: &Address, config: &Config) -> Result<()> {
    let signers = get_signer_addresses(
        &config.chain.rpc_url,
        &config.chain.contract_address,
        &config.tapp.app_id,
    )
    .await
    .map_err(|e| anyhow!("getNodeList failed: {}", e))?;

    if signers.is_empty() {
        return Err(anyhow!("app '{}' not found on-chain", config.tapp.app_id));
    }
    if !signers.contains(addr) {
        return Err(anyhow!("caller {:?} is not a registered node", addr));
    }
    Ok(())
}
