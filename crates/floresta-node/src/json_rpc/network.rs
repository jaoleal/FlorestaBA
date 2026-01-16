//! This module holds all RPC server side methods for interacting with our node's network stack.

use super::server::RpcChain;
use super::server::RpcImpl;
use crate::json_rpc::server::RpcServerError;

impl<Blockchain: RpcChain> RpcImpl<Blockchain> {
    pub(crate) async fn ping(&self) -> Result<bool, RpcServerError> {
        self.node
            .ping()
            .await
            .map_err(|e| RpcServerError::Node(e.to_string()))
    }
}
