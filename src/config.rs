use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub tapp: TappConfig,
    pub chain: ChainConfig,
    pub cluster: ClusterConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// HTTP bind address for the /app-key endpoint (tapp-server ↔ KMS).
    #[serde(default = "default_http_bind")]
    pub bind: String,
    /// gRPC bind address for inter-node communication.
    #[serde(default = "default_grpc_bind")]
    pub grpc_bind: String,
    /// Allowed clock skew for timestamp validation (seconds).
    #[serde(default = "default_timestamp_tolerance_secs")]
    pub timestamp_tolerance_secs: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TappConfig {
    /// KMS app identifier in TappRegistry (used to verify peer node membership).
    pub app_id: String,
    /// tapp-server host.
    #[serde(default = "default_tapp_ip")]
    pub tapp_ip: String,
    /// tapp-server gRPC port.
    #[serde(default = "default_tapp_port")]
    pub tapp_port: u16,
    /// If true, use MOCK_APP_PRIVATE_KEY env var instead of calling tapp-server.
    /// For development and CI only — never set in production.
    #[serde(default)]
    pub mock_tee: bool,
}

impl TappConfig {
    pub fn tapp_url(&self) -> String {
        format!("http://{}:{}", self.tapp_ip, self.tapp_port)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainConfig {
    pub rpc_url: String,
    pub contract_address: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClusterConfig {
    /// Minimum number of shard contributions needed to reconstruct masterKey.
    pub threshold: u32,
    /// Total number of nodes in the KMS cluster.
    pub total_nodes: u32,
    /// gRPC URLs of all peer nodes (excluding self).
    #[serde(default)]
    pub peers: Vec<String>,
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }
}

fn default_http_bind() -> String { "0.0.0.0:8080".to_string() }
fn default_grpc_bind() -> String { "0.0.0.0:9090".to_string() }
fn default_timestamp_tolerance_secs() -> i64 { 300 }
fn default_tapp_ip() -> String { "127.0.0.1".to_string() }
fn default_tapp_port() -> u16 { 50051 }
