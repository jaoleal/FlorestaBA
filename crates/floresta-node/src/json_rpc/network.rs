//! This module holds all RPC server side methods for interacting with our node's network stack.

use floresta_rpc::rpc::FlorestaJsonRPC;
use floresta_rpc::rpc::RpcResult;
use floresta_rpc::rpc_types::Error;

use super::server::RpcChain;
use super::server::RpcServer;

impl<Blockchain> FlorestaJsonRPC for RpcServer<Blockchain>
where
    Blockchain: RpcChain,
{
    async fn ping(&self) -> RpcResult<()> {
        self.node
            .ping()
            .await
            .map_err(|e| Error::Internal(e.to_string()));
        Ok(())
    }
}
