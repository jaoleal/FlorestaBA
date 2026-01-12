use std::fmt::Debug;

use async_trait::async_trait;
use bitcoin::BlockHash;
use bitcoin::Txid;
use corepc_types::v29::GetTxOut;
use corepc_types::v30::GetBestBlockHash;
use corepc_types::v30::GetBlockCount;
use corepc_types::v30::GetBlockHash;
use corepc_types::v30::GetBlockHeader;
use corepc_types::v30::GetRpcInfo;
use corepc_types::v30::GetTransaction;
use corepc_types::v30::RescanBlockchain;
use corepc_types::v30::SendRawTransaction;
use serde::Deserialize;
use serde_json::Number;
use serde_json::Value;

use crate::rpc::FlorestaJsonRPC;
use crate::rpc::RpcResult;
use crate::rpc_types::AddNodeCommand;
use crate::rpc_types::Error;
use crate::rpc_types::GetBlock;
use crate::rpc_types::GetBlockchainInfoRes;
use crate::rpc_types::GetMemInfoRes;
use crate::rpc_types::PeerInfo;
use crate::rpc_types::RescanConfidence;
// Define a Client struct that wraps a jsonrpc::Client
#[derive(Debug)]
pub struct Client(jsonrpc::Client);

// Configuration struct for JSON-RPC client
pub struct JsonRPCConfig {
    pub url: String,
    pub user: Option<String>,
    pub pass: Option<String>,
}

impl Client {
    // Constructor to create a new Client with a URL
    pub fn new(url: String) -> Self {
        let client =
            jsonrpc::Client::simple_http(&url, None, None).expect("Failed to create client");
        Self(client)
    }

    // Constructor to create a new Client with a configuration
    pub fn new_with_config(config: JsonRPCConfig) -> Self {
        let client =
            jsonrpc::Client::simple_http(&config.url, config.user.clone(), config.pass.clone())
                .expect("Failed to create client");
        Self(client)
    }

    // Method to make an RPC call
    pub fn rpc_call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        method: &str,
        params: &[serde_json::Value],
    ) -> RpcResult<T> {
        let raw = serde_json::value::to_raw_value(params)?;

        let req = self.0.build_request(method, Some(&*raw));

        self.0
            .send_request(req)
            .map_err(crate::rpc_types::Error::from)?
            .result()
            .map_err(crate::rpc_types::Error::from)
    }
}

#[async_trait]
impl FlorestaJsonRPC for Client {
    async fn find_tx_out(
        &self,
        tx_id: Txid,
        outpoint: u32,
        script: String,
        height_hint: u32,
    ) -> RpcResult<Value> {
        self.rpc_call(
            "findtxout",
            &[
                Value::String(tx_id.to_string()),
                Value::Number(Number::from(outpoint)),
                Value::String(script),
                Value::Number(Number::from(height_hint)),
            ],
        )
    }

    async fn uptime(&self) -> RpcResult<u32> {
        self.rpc_call("uptime", &[])
    }

    async fn get_memory_info(&self, mode: String) -> RpcResult<GetMemInfoRes> {
        self.rpc_call("getmemoryinfo", &[Value::String(mode)])
    }

    async fn get_rpc_info(&self) -> RpcResult<GetRpcInfo> {
        self.rpc_call("getrpcinfo", &[])
    }

    async fn add_node(
        &self,
        node: String,
        command: AddNodeCommand,
        v2transport: bool,
    ) -> RpcResult<Value> {
        self.rpc_call(
            "addnode",
            &[
                Value::String(node),
                Value::String(command.to_string()),
                Value::Bool(v2transport),
            ],
        )
    }

    async fn stop(&self) -> RpcResult<String> {
        self.rpc_call("stop", &[])
    }

    async fn rescanblockchain(
        &self,
        start_height: Option<u32>,
        stop_height: Option<u32>,
        use_timestamp: bool,
        confidence: RescanConfidence,
    ) -> RpcResult<RescanBlockchain> {
        let start_height = start_height.unwrap_or(0u32);

        let stop_height = stop_height.unwrap_or(0u32);

        self.rpc_call(
            "rescanblockchain",
            &[
                Value::Number(Number::from(start_height)),
                Value::Number(Number::from(stop_height)),
                Value::Bool(use_timestamp),
                serde_json::to_value(&confidence).expect("RescanConfidence implements Ser/De"),
            ],
        )
    }

    async fn get_roots(&self) -> RpcResult<Vec<String>> {
        self.rpc_call("getroots", &[])
    }

    async fn get_block(&self, hash: BlockHash, verbosity: Option<u32>) -> RpcResult<GetBlock> {
        let verbosity = verbosity.unwrap_or(0);
        self.rpc_call(
            "getblock",
            &[
                Value::String(hash.to_string()),
                Value::Number(Number::from(verbosity)),
            ],
        )
    }

    async fn get_block_count(&self) -> RpcResult<GetBlockCount> {
        self.rpc_call("getblockcount", &[])
    }

    async fn get_tx_out(&self, tx_id: Txid, outpoint: u32) -> RpcResult<GetTxOut> {
        let result: serde_json::Value = self.rpc_call(
            "gettxout",
            &[
                Value::String(tx_id.to_string()),
                Value::Number(Number::from(outpoint)),
            ],
        )?;
        if result.is_null() {
            return Err(Error::TxOutNotFound);
        }
        serde_json::from_value(result).map_err(Error::Serde)
    }

    async fn get_txout_proof(
        &self,
        txids: Vec<Txid>,
        blockhash: Option<BlockHash>,
    ) -> RpcResult<Option<String>> {
        let params: Vec<Value> = match blockhash {
            Some(blockhash) => vec![
                serde_json::to_value(txids)
                    .expect("Unreachable, Vec<Txid> can be parsed into a json value"),
                Value::String(blockhash.to_string()),
            ],
            None => {
                let txids = serde_json::to_value(txids)
                    .expect("Unreachable, Vec<Txid> can be parsed into a json value");
                vec![txids]
            }
        };
        self.rpc_call("gettxoutproof", &params)
    }

    async fn get_peer_info(&self) -> RpcResult<Vec<PeerInfo>> {
        self.rpc_call("getpeerinfo", &[])
    }

    async fn get_best_block_hash(&self) -> RpcResult<GetBestBlockHash> {
        self.rpc_call("getbestblockhash", &[])
    }

    async fn get_block_hash(&self, height: u32) -> RpcResult<GetBlockHash> {
        self.rpc_call("getblockhash", &[Value::Number(Number::from(height))])
    }

    async fn get_transaction(
        &self,
        tx_id: Txid,
        verbosity: Option<bool>,
    ) -> RpcResult<GetTransaction> {
        let verbosity = verbosity.unwrap_or(false);
        self.rpc_call(
            "gettransaction",
            &[Value::String(tx_id.to_string()), Value::Bool(verbosity)],
        )
    }

    async fn load_descriptor(&self, descriptor: String) -> RpcResult<bool> {
        self.rpc_call("loaddescriptor", &[Value::String(descriptor)])
    }

    async fn get_block_filter(&self, height: u32) -> RpcResult<String> {
        self.rpc_call("getblockfilter", &[Value::Number(Number::from(height))])
    }

    async fn get_block_header(&self, hash: BlockHash) -> RpcResult<GetBlockHeader> {
        self.rpc_call("getblockheader", &[Value::String(hash.to_string())])
    }

    async fn get_blockchain_info(&self) -> RpcResult<GetBlockchainInfoRes> {
        self.rpc_call("getblockchaininfo", &[])
    }

    async fn send_raw_transaction(&self, tx: String) -> RpcResult<SendRawTransaction> {
        self.rpc_call("sendrawtransaction", &[Value::String(tx)])
    }

    async fn list_descriptors(&self) -> RpcResult<Vec<String>> {
        self.rpc_call("listdescriptors", &[])
    }

    async fn ping(&self) -> RpcResult<()> {
        self.rpc_call("ping", &[])
    }
}

// Struct to represent a JSON-RPC response
#[derive(Debug, Deserialize)]
pub struct JsonRpcResponse<Res> {
    pub jsonrpc: String,
    pub id: u64,
    pub result: Option<Res>,
    pub error: Option<serde_json::Value>,
}
