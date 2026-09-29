use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub tapp: TappConfig,
    pub chain: ChainConfig,
    pub cluster: ClusterConfig,
    #[serde(default)]
    pub verifier: Option<VerifierConfig>,
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
    /// Optional Unix-domain-socket path to the local tapp-server (e.g.
    /// "/run/tapp/tapp.sock"). When set, the KMS connects over this socket (local
    /// IPC) instead of TCP (`tapp_ip:tapp_port`) — the KMS runs on the same host as
    /// its tapp-server, so "local = socket, external = gRPC/TCP". TCP stays the
    /// default when unset, so existing configs are unaffected.
    #[serde(default)]
    pub tapp_socket: Option<String>,
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

/// The tappscan verifier this node believes about TEE evidence (issue #14). Optional: absent
/// means admission is chain-membership only, exactly as before — the gate ships dark and turns
/// on with a config change once scan serves its attested TLS key (0g-tapp-verifier#14).
#[derive(Debug, Clone, Deserialize)]
pub struct VerifierConfig {
    /// Base URL, e.g. "https://scan.example". Plain http is refused unless `insecure_http`.
    pub url: String,
    /// Pinned attested TLS public keys (hex; the raw SubjectPublicKeyInfo key bits, i.e. the
    /// `tls_public_key` scan's evidence carries). A set, so a scan identity rotation can be
    /// rolled without a flag day. The pin — not any CA — is the whole authenticity story.
    #[serde(default)]
    pub pubkeys: Vec<String>,
    /// API key for scan's higher rate-limit tier. QoS only, NOT a security boundary — a stolen
    /// key wins quota, nothing else — which is why it may sit in plaintext config.
    #[serde(default)]
    pub api_key: String,
    /// Allow a plain-http verifier URL. Disables pinning entirely; local tests only.
    #[serde(default)]
    pub insecure_http: bool,
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
    /// If true: on startup, try to join first; if join fails, bootstrap as the
    /// first node (generate and split masterKey).  Set this only on the
    /// designated bootstrap node.
    #[serde(default)]
    pub bootstrap: bool,
    /// This node's own gRPC URL as seen by peers (e.g. "http://1.2.3.4:9092").
    /// Required for gossip to work.
    #[serde(default)]
    pub self_url: String,
    /// Seed peers used at startup for initial contact (gRPC URLs).
    /// After startup the runtime peer table is maintained by gossip.
    /// Field was previously named "peers" — both names are accepted.
    #[serde(default, alias = "peers")]
    pub seeds: Vec<String>,
    /// Optional sealed-share blob (base64url, as emitted in `SEALED_SHARE=` logs or by
    /// GET /sealed-share) to reload at boot instead of rejoining. Per-node value — paste it
    /// into this node's deploy config on restart. Omit for a deliberate fresh start (e.g.
    /// after a re-genesis). The KMS_SEALED_SHARE env var overrides this if set.
    #[serde(default)]
    pub sealed_share: Option<String>,
    /// Optional path to auto-persist the sealed share on every share change (atomic write).
    /// Only useful if the path lives on a volume that survives restarts; at boot the file is
    /// read when no blob is provided. The KMS_SEALED_SHARE_PATH env var overrides this.
    #[serde(default)]
    pub sealed_share_path: Option<String>,
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
