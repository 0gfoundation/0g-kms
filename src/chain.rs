use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use ethers::{
    contract::abigen,
    providers::{Http, Provider},
    types::Address,
};
use tokio::sync::{Mutex, RwLock};

use crate::error::KmsError;

abigen!(
    TappRegistry,
    "abi/TappRegistry.json"
);

/// TTL for the per-app nodeList cache. The signer list changes only on addNode/removeNode
/// (rare, operator-driven), but it is read on EVERY authorization — the coordinator checks the
/// client, and each peer re-checks the coordinator when serving a DPRF partial, i.e. one derive
/// fans out into ~(1 + threshold) reads. Uncached, that exhausted the public RPC's rate budget
/// at ~15 concurrent derives (issue #5). With the cache, warm-path derives make zero on-chain
/// calls; the cost is that a membership change (e.g. removing a node's authorization) takes up
/// to this long to be enforced.
const NODE_LIST_TTL: Duration = Duration::from_secs(30);

struct NodeListEntry {
    addrs: Vec<Address>,
    fetched_at: Instant,
}

fn node_list_cache() -> &'static RwLock<HashMap<String, NodeListEntry>> {
    static CACHE: OnceLock<RwLock<HashMap<String, NodeListEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Serializes cache refreshes (single-flight): when the TTL lapses under load, exactly one
/// caller performs the RPC while the burst waits and then reads the refreshed entry — instead
/// of the whole burst stampeding the rate-limited RPC at once.
fn refresh_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// One `Provider` per RPC URL for the process lifetime (connection reuse), instead of a fresh
/// provider + HTTP client per call.
fn providers() -> &'static RwLock<HashMap<String, Arc<Provider<Http>>>> {
    static PROVIDERS: OnceLock<RwLock<HashMap<String, Arc<Provider<Http>>>>> = OnceLock::new();
    PROVIDERS.get_or_init(|| RwLock::new(HashMap::new()))
}

async fn provider_for(rpc_url: &str) -> Result<Arc<Provider<Http>>, KmsError> {
    if let Some(p) = providers().read().await.get(rpc_url) {
        return Ok(p.clone());
    }
    let p = Arc::new(
        Provider::<Http>::try_from(rpc_url)
            .map_err(|e| KmsError::ChainError(format!("invalid RPC URL: {}", e)))?,
    );
    providers().write().await.insert(rpc_url.to_string(), p.clone());
    Ok(p)
}

fn parse_contract(contract_address: &str) -> Result<Address, KmsError> {
    contract_address
        .parse()
        .map_err(|_| KmsError::ChainError(format!("invalid contract address: {}", contract_address)))
}

/// Returns the on-chain owner of the given app_id (TappRegistry `getAppInfo().owner`).
/// Used to gate operator endpoints (e.g. /refresh) to the app owner. Not cached — operator
/// endpoints are rare and freshness matters more there.
pub async fn get_app_owner(
    rpc_url: &str,
    contract_address: &str,
    app_id: &str,
) -> Result<Address, KmsError> {
    let provider = provider_for(rpc_url).await?;
    let contract = TappRegistry::new(parse_contract(contract_address)?, provider);
    let info = contract
        .get_app_info(app_id.to_string())
        .call()
        .await
        .map_err(|e| KmsError::ChainError(format!("getAppInfo failed: {}", e)))?;
    Ok(info.owner)
}

async fn fetch_node_list(
    rpc_url: &str,
    contract_address: &str,
    app_id: &str,
) -> Result<Vec<Address>, KmsError> {
    let provider = provider_for(rpc_url).await?;
    let contract = TappRegistry::new(parse_contract(contract_address)?, provider);
    contract
        .get_node_list(app_id.to_string())
        .call()
        .await
        .map_err(|e| KmsError::ChainError(format!("getNodeList failed: {}", e)))
}

/// Returns all registered signer addresses for the given app_id, cached with a short TTL
/// (see `NODE_LIST_TTL`). Used to verify that a KMS request signature comes from a legitimate
/// TEE node — this is the authorization hot path, so warm calls must not touch the chain.
///
/// On an RPC failure with a stale entry present, the stale list is served (with a warning):
/// for reads, availability under RPC rate-limiting/flap beats hard-failing every derive.
pub async fn get_signer_addresses(
    rpc_url: &str,
    contract_address: &str,
    app_id: &str,
) -> Result<Vec<Address>, KmsError> {
    let key = format!("{}|{}|{}", rpc_url, contract_address, app_id);

    // Fast path: fresh cache hit — zero on-chain calls.
    if let Some(e) = node_list_cache().read().await.get(&key) {
        if e.fetched_at.elapsed() < NODE_LIST_TTL {
            return Ok(e.addrs.clone());
        }
    }

    // Slow path: single-flight refresh.
    let _guard = refresh_lock().lock().await;
    // Someone may have refreshed while we waited for the lock.
    if let Some(e) = node_list_cache().read().await.get(&key) {
        if e.fetched_at.elapsed() < NODE_LIST_TTL {
            return Ok(e.addrs.clone());
        }
    }

    match fetch_node_list(rpc_url, contract_address, app_id).await {
        Ok(addrs) => {
            crate::metrics::inc(&crate::metrics::m().chain_rpc_ok);
            node_list_cache().write().await.insert(
                key,
                NodeListEntry {
                    addrs: addrs.clone(),
                    fetched_at: Instant::now(),
                },
            );
            Ok(addrs)
        }
        Err(e) => {
            crate::metrics::inc(&crate::metrics::m().chain_rpc_fail);
            // Stale fallback: serve the last known list rather than failing every request
            // while the RPC is rate-limited or flapping.
            if let Some(old) = node_list_cache().read().await.get(&key) {
                crate::metrics::inc(&crate::metrics::m().chain_stale_served);
                tracing::warn!(error = %e, app_id, "nodeList refresh failed — serving stale cache");
                return Ok(old.addrs.clone());
            }
            Err(e)
        }
    }
}
