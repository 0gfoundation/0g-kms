use std::sync::Arc;

use ethers::{
    contract::abigen,
    providers::{Http, Provider},
    types::Address,
};

use crate::error::KmsError;

abigen!(
    TappRegistry,
    "abi/TappRegistry.json"
);

/// Returns the on-chain owner of the given app_id (TappRegistry `getAppInfo().owner`).
/// Used to gate operator endpoints (e.g. /refresh) to the app owner.
pub async fn get_app_owner(
    rpc_url: &str,
    contract_address: &str,
    app_id: &str,
) -> Result<Address, KmsError> {
    let provider = Provider::<Http>::try_from(rpc_url)
        .map_err(|e| KmsError::ChainError(format!("invalid RPC URL: {}", e)))?;
    let contract_addr: Address = contract_address
        .parse()
        .map_err(|_| KmsError::ChainError(format!("invalid contract address: {}", contract_address)))?;
    let contract = TappRegistry::new(contract_addr, Arc::new(provider));
    let info = contract
        .get_app_info(app_id.to_string())
        .call()
        .await
        .map_err(|e| KmsError::ChainError(format!("getAppInfo failed: {}", e)))?;
    Ok(info.owner)
}

/// Returns all registered signer addresses for the given app_id.
/// Used to verify that a KMS request signature comes from a legitimate TEE node.
pub async fn get_signer_addresses(
    rpc_url: &str,
    contract_address: &str,
    app_id: &str,
) -> Result<Vec<Address>, KmsError> {
    let provider = Provider::<Http>::try_from(rpc_url)
        .map_err(|e| KmsError::ChainError(format!("invalid RPC URL: {}", e)))?;

    let contract_addr: Address = contract_address
        .parse()
        .map_err(|_| KmsError::ChainError(format!("invalid contract address: {}", contract_address)))?;

    let contract = TappRegistry::new(contract_addr, Arc::new(provider));

    let addrs = contract
        .get_node_list(app_id.to_string())
        .call()
        .await
        .map_err(|e| KmsError::ChainError(format!("getNodeList failed: {}", e)))?;

    Ok(addrs)
}
