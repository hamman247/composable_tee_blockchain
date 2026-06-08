//! JSON-RPC server implementing standard Ethereum + TEE-specific APIs.

use anyhow::Result;
use alloy_primitives::{Address, B256, U256};
use jsonrpsee::server::{ServerBuilder, ServerHandle};
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use crate::state::NodeState;

/// Standard Ethereum JSON-RPC methods + TEE extensions.
#[rpc(server)]
pub trait TeeChainRpc {
    #[method(name = "eth_chainId")]
    async fn chain_id(&self) -> RpcResult<String>;

    #[method(name = "eth_blockNumber")]
    async fn block_number(&self) -> RpcResult<String>;

    #[method(name = "eth_getBalance")]
    async fn get_balance(&self, address: String, block: Option<String>) -> RpcResult<String>;

    #[method(name = "eth_getTransactionCount")]
    async fn get_transaction_count(&self, address: String, block: Option<String>) -> RpcResult<String>;

    #[method(name = "net_version")]
    async fn net_version(&self) -> RpcResult<String>;

    #[method(name = "eth_gasPrice")]
    async fn gas_price(&self) -> RpcResult<String>;

    #[method(name = "tee_getRegisteredTEEs")]
    async fn get_registered_tees(&self) -> RpcResult<Vec<String>>;

    #[method(name = "tee_getNodeInfo")]
    async fn get_node_info(&self) -> RpcResult<serde_json::Value>;
}

pub struct TeeChainRpcImpl {
    state: NodeState,
}

#[async_trait::async_trait]
impl TeeChainRpcServer for TeeChainRpcImpl {
    async fn chain_id(&self) -> RpcResult<String> {
        Ok(format!("0x{:x}", self.state.chain_id()))
    }

    async fn block_number(&self) -> RpcResult<String> {
        Ok(format!("0x{:x}", self.state.block_number()))
    }

    async fn get_balance(&self, address: String, _block: Option<String>) -> RpcResult<String> {
        let addr = address.parse::<Address>()
            .map_err(|e| jsonrpsee::types::ErrorObjectOwned::owned(
                -32602, format!("Invalid address: {e}"), None::<()>,
            ))?;
        let balance = self.state.get_balance(&addr);
        Ok(format!("0x{:x}", balance))
    }

    async fn get_transaction_count(&self, address: String, _block: Option<String>) -> RpcResult<String> {
        let addr = address.parse::<Address>()
            .map_err(|e| jsonrpsee::types::ErrorObjectOwned::owned(
                -32602, format!("Invalid address: {e}"), None::<()>,
            ))?;
        Ok(format!("0x{:x}", self.state.get_nonce(&addr)))
    }

    async fn net_version(&self) -> RpcResult<String> {
        Ok(self.state.chain_id().to_string())
    }

    async fn gas_price(&self) -> RpcResult<String> {
        Ok("0x3b9aca00".to_string()) // 1 Gwei default
    }

    async fn get_registered_tees(&self) -> RpcResult<Vec<String>> {
        let guard = self.state.consensus_engine();
        let tees = guard.consensus.registry().all_tee_ids();
        Ok(tees.iter().map(|id| id.to_string()).collect())
    }

    async fn get_node_info(&self) -> RpcResult<serde_json::Value> {
        Ok(serde_json::json!({
            "chain_id": self.state.chain_id(),
            "block_number": self.state.block_number(),
            "block_hash": format!("{}", self.state.block_hash()),
            "pending_txns": self.state.pending_txn_count(),
            "version": env!("CARGO_PKG_VERSION"),
        }))
    }
}

/// Start the JSON-RPC server.
pub async fn start_rpc_server(addr: &str, state: NodeState) -> Result<ServerHandle> {
    let server = ServerBuilder::default()
        .build(addr)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to build RPC server: {e}"))?;

    let rpc_impl = TeeChainRpcImpl { state };
    let handle = server.start(rpc_impl.into_rpc());

    Ok(handle)
}
