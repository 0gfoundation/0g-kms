//! Test-only client for the threshold-BLS DPRF `/app-key` endpoint.
//!
//! Signs an EIP-191 request, POSTs it to a KMS node, and ECIES-decrypts the response
//! using the SAME `ecies`/`k256` crates as the server — so it is guaranteed wire- and
//! algorithm-compatible (avoids the eciesjs AES-vs-XChaCha mismatch). Prints the derived
//! 32-byte app key as hex, so callers can compare keys across invocations/nodes.
//!
//! Usage:
//!   cargo run --example dprf_client -- <node_http_url> <app_id> <material_hex> <privkey_hex>
//!
//! Example:
//!   cargo run --example dprf_client -- http://localhost:9101 0g-kms 00112233 \
//!     0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

use anyhow::{anyhow, Result};
use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature, SigningKey};
use sha3::{Digest, Keccak256};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        return Err(anyhow!(
            "usage: dprf_client <node_http_url> <app_id> <material_hex> <privkey_hex>"
        ));
    }
    let url = format!("{}/app-key", args[1].trim_end_matches('/'));
    let app_id = args[2].clone();
    let material_hex = args[3].trim_start_matches("0x").to_string();
    let priv_hex = args[4].trim_start_matches("0x");

    let priv_bytes: [u8; 32] = hex::decode(priv_hex)?
        .try_into()
        .map_err(|_| anyhow!("privkey must be 32 bytes"))?;
    let sk = SigningKey::from_bytes((&priv_bytes).into())?;

    // Uncompressed secp256k1 public key (65 bytes) for the ECIES response.
    let pubkey = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();

    // EIP-191 personal_sign over "GetSecretResource:{timestamp}".
    let ts = chrono::Utc::now().timestamp();
    let message = format!("GetSecretResource:{}", ts);
    let prefixed = format!("\x19Ethereum Signed Message:\n{}{}", message.len(), message);
    let hash = Keccak256::digest(prefixed.as_bytes());
    let (sig, recid): (Signature, RecoveryId) = sk.sign_prehash(&hash)?;
    let mut sig_bytes = sig.to_bytes().to_vec();
    sig_bytes.push(recid.to_byte());

    let body = serde_json::json!({
        "app_id": app_id,
        "timestamp": ts,
        "pubkey": hex::encode(&pubkey),
        "signature": hex::encode(&sig_bytes),
        "material": material_hex,
    });

    let resp = reqwest::blocking::Client::new().post(&url).json(&body).send()?;
    let status = resp.status();
    let text = resp.text()?;
    if !status.is_success() {
        return Err(anyhow!("HTTP {}: {}", status, text));
    }

    let v: serde_json::Value = serde_json::from_str(&text)?;
    let ct_hex = v["encrypted_secret"]
        .as_str()
        .ok_or_else(|| anyhow!("no encrypted_secret in response: {}", text))?;
    let ct = hex::decode(ct_hex.trim_start_matches("0x"))?;
    let app_key = ecies::decrypt(&priv_bytes, &ct).map_err(|e| anyhow!("ECIES decrypt failed: {}", e))?;

    println!("{}", hex::encode(&app_key));
    Ok(())
}
