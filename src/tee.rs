/// Fetch the node's secp256k1 signing key.
///
/// Decision tree (mirrors 0g-sandbox pattern):
///   1. config.tapp.mock_tee = true → use MOCK_APP_PRIVATE_KEY / MOCK_APP_ETH_ADDRESS env vars
///   2. Otherwise → gRPC call to tapp-server (GetAppSecretKey), with retry for lazy-load timing
use anyhow::{anyhow, bail, Result};
use tracing::{info, warn};

use crate::config::TappConfig;

pub struct NodeKey {
    pub private_key: [u8; 32],
    pub eth_address: [u8; 20],
}

pub async fn fetch_signing_key(cfg: &TappConfig) -> Result<NodeKey> {
    if cfg.mock_tee {
        fetch_mock()
    } else {
        fetch_grpc(cfg).await
    }
}

fn fetch_mock() -> Result<NodeKey> {
    let raw = std::env::var("MOCK_APP_PRIVATE_KEY")
        .map_err(|_| anyhow!("mock_tee=true but MOCK_APP_PRIVATE_KEY is not set"))?;
    let hex = raw.trim_start_matches("0x");
    if hex.len() != 64 {
        bail!("MOCK_APP_PRIVATE_KEY must be 32-byte hex (got {} chars)", hex.len());
    }
    let private_key: [u8; 32] = hex::decode(hex)?.try_into().unwrap();

    let addr_raw = std::env::var("MOCK_APP_ETH_ADDRESS")
        .map_err(|_| anyhow!("mock_tee=true but MOCK_APP_ETH_ADDRESS is not set"))?;
    let addr_hex = addr_raw.trim_start_matches("0x");
    if addr_hex.len() != 40 {
        bail!("MOCK_APP_ETH_ADDRESS must be 20-byte hex (got {} chars)", addr_hex.len());
    }
    let eth_address: [u8; 20] = hex::decode(addr_hex)?.try_into().unwrap();

    Ok(NodeKey { private_key, eth_address })
}

async fn fetch_grpc(cfg: &TappConfig) -> Result<NodeKey> {
    mod tapp_service {
        tonic::include_proto!("tapp_service");
    }
    use tapp_service::tapp_service_client::TappServiceClient;
    use tapp_service::GetAppSecretKeyRequest;
    use tonic::transport::Channel;

    let url = cfg.tapp_url();
    let channel = Channel::from_shared(url.clone())
        .map_err(|e| anyhow!("invalid tapp-server URL {}: {}", url, e))?
        .connect()
        .await
        .map_err(|e| anyhow!("cannot connect to tapp-server at {}: {}", url, e))?;

    let mut client = TappServiceClient::new(channel);
    let mut last_err = anyhow!("GetAppSecretKey never attempted");

    for attempt in 1u32..=10 {
        match client
            .get_app_secret_key(GetAppSecretKeyRequest {
                app_id: cfg.app_id.clone(),
                key_type: "ethereum".to_string(),
                x25519: false,
            })
            .await
        {
            Ok(r) => {
                let resp = r.into_inner();
                if !resp.success {
                    bail!("GetAppSecretKey failed: {}", resp.message);
                }
                if resp.private_key.len() != 32 {
                    bail!("GetAppSecretKey returned invalid private key length: {}", resp.private_key.len());
                }
                if resp.eth_address.len() != 20 {
                    bail!("GetAppSecretKey returned invalid eth_address length: {}", resp.eth_address.len());
                }
                return Ok(NodeKey {
                    private_key: resp.private_key.try_into().unwrap(),
                    eth_address: resp.eth_address.try_into().unwrap(),
                });
            }
            Err(e) => {
                let delay = std::time::Duration::from_secs(attempt as u64);
                warn!(attempt, error = %e, "GetAppSecretKey failed, retrying in {}s", delay.as_secs());
                last_err = anyhow!("GetAppSecretKey RPC failed: {}", e);
                tokio::time::sleep(delay).await;
            }
        }
    }

    Err(last_err)
}
