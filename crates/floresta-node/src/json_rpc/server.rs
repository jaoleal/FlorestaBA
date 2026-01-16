use std::collections::HashMap;
use std::fmt::Display;
use std::net::SocketAddr;
use std::slice;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::http::Method;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::Json;
use axum::Router;
use bitcoin::consensus::deserialize;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::Address;
use bitcoin::BlockHash;
use bitcoin::Network;
use bitcoin::ScriptBuf;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Txid;
use floresta_chain::extensions::HeaderExtError;
use floresta_chain::ThreadSafeChain;
use floresta_common::impl_error_from;
use floresta_common::parse_descriptors;
use floresta_compact_filters::flat_filters_store::FlatFiltersStore;
use floresta_compact_filters::network_filters::NetworkFilters;
use floresta_rpc::typed_commands::arg_parser::get_bool;
use floresta_rpc::typed_commands::arg_parser::get_hash;
use floresta_rpc::typed_commands::arg_parser::get_hashes_array;
use floresta_rpc::typed_commands::arg_parser::get_numeric;
use floresta_rpc::typed_commands::arg_parser::get_optional_field;
use floresta_rpc::typed_commands::arg_parser::get_string;
use floresta_rpc::typed_commands::request::RescanConfidence;
use floresta_rpc::typed_commands::response::GetBlockRes;
use floresta_rpc::typed_commands::response::RawTx;
use floresta_rpc::typed_commands::response::ScriptPubKeyJson;
use floresta_rpc::typed_commands::response::ScriptSigJson;
use floresta_rpc::typed_commands::response::TxInJson;
use floresta_rpc::typed_commands::response::TxOutJson;
use floresta_rpc::typed_commands::ArgParseError;
use floresta_rpc::typed_commands::JsonRequest;
use floresta_rpc::typed_commands::RpcError;
use floresta_watch_only::kv_database::KvDatabase;
use floresta_watch_only::AddressCache;
use floresta_watch_only::CachedTransaction;
use floresta_wire::node_interface::NodeInterface;
use floresta_wire::node_interface::PeerInfo;
use serde_json::json;
use serde_json::Value;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tracing::debug;
use tracing::error;
use tracing::info;

pub(super) struct InflightRpc {
    pub method: String,
    pub when: Instant,
}

/// Utility trait to ensure that the chain implements all the necessary traits
///
/// Instead of using this very complex trait bound declaration on every impl block
/// and function, this trait makes sure everything we need is implemented.
pub trait RpcChain: ThreadSafeChain + Clone {}

impl<T> RpcChain for T where T: ThreadSafeChain + Clone {}

pub struct RpcImpl<Blockchain: RpcChain> {
    pub(super) block_filter_storage: Option<Arc<NetworkFilters<FlatFiltersStore>>>,
    pub(super) network: Network,
    pub(super) chain: Blockchain,
    pub(super) wallet: Arc<AddressCache<KvDatabase>>,
    pub(super) node: NodeInterface,
    pub(super) kill_signal: Arc<RwLock<bool>>,
    pub(super) inflight: Arc<RwLock<HashMap<Value, InflightRpc>>>,
    pub(super) log_path: String,
    pub(super) start_time: Instant,
}

type Result<T> = std::result::Result<T, RpcServerError>;

impl<Blockchain: RpcChain> RpcImpl<Blockchain> {
    async fn add_node(&self, node: String, command: String, v2transport: bool) -> Result<Value> {
        let node = node.split(':').collect::<Vec<&str>>();
        let (ip, port) = if node.len() == 2 {
            (
                node[0],
                node[1].parse().map_err(|_| RpcServerError::InvalidPort)?,
            )
        } else {
            // TODO(@luisschwab): use `NetworkExt` to append the correct port
            // once https://github.com/rust-bitcoin/rust-bitcoin/pull/4639 makes it into a release.
            match self.network {
                Network::Bitcoin => (node[0], 8333),
                Network::Signet => (node[0], 38333),
                Network::Testnet => (node[0], 18333),
                Network::Testnet4 => (node[0], 48333),
                Network::Regtest => (node[0], 18444),
            }
        };

        let peer = ip.parse().map_err(|_| RpcServerError::InvalidAddress)?;

        let _ = match command.as_str() {
            "add" => self.node.add_peer(peer, port, v2transport).await,
            "remove" => self.node.remove_peer(peer, port).await,
            "onetry" => self.node.onetry_peer(peer, port, v2transport).await,
            _ => return Err(RpcServerError::InvalidAddnodeCommand),
        };

        Ok(json!(null))
    }

    fn get_transaction(&self, tx_id: Txid, verbosity: Option<bool>) -> Result<Value> {
        if verbosity == Some(true) {
            let tx = self
                .wallet
                .get_transaction(&tx_id)
                .ok_or(RpcServerError::TxNotFound);
            return tx.map(|tx| serde_json::to_value(self.make_raw_transaction(tx)).unwrap());
        }

        self.wallet
            .get_transaction(&tx_id)
            .and_then(|tx| serde_json::to_value(self.make_raw_transaction(tx)).ok())
            .ok_or(RpcServerError::TxNotFound)
    }

    fn load_descriptor(&self, descriptor: String) -> Result<bool> {
        let desc = slice::from_ref(&descriptor);
        let mut parsed = parse_descriptors(desc)?;

        // It's ok to unwrap because we know there is at least one element in the vector
        let addresses = parsed.pop().unwrap();
        let addresses = (0..100)
            .map(|index| {
                let address = addresses
                    .at_derivation_index(index)
                    .unwrap()
                    .script_pubkey();
                self.wallet.cache_address(address.clone());
                address
            })
            .collect::<Vec<_>>();

        debug!("Rescanning with block filters for addresses: {addresses:?}");

        let addresses = self.wallet.get_cached_addresses();
        let wallet = self.wallet.clone();
        if self.block_filter_storage.is_none() {
            return Err(RpcServerError::InInitialBlockDownload);
        };

        let cfilters = self.block_filter_storage.as_ref().unwrap().clone();
        let node = self.node.clone();
        let chain = self.chain.clone();

        tokio::task::spawn(Self::rescan_with_block_filters(
            addresses, chain, wallet, cfilters, node, None, None,
        ));

        self.wallet.push_descriptor(&descriptor)?;
        debug!("Descriptor pushed: {descriptor}");

        Ok(true)
    }

    fn rescan_blockchain(
        &self,
        start: Option<u32>,
        stop: Option<u32>,
        use_timestamp: bool,
        confidence: Option<RescanConfidence>,
    ) -> Result<bool> {
        let (start_height, stop_height) =
            self.get_rescan_interval(use_timestamp, start, stop, confidence)?;

        if stop_height != 0 && start_height >= stop_height {
            // When stop height is a non zero value it needs atleast to be greater than start_height.
            return Err(RpcServerError::InvalidRescanVal);
        }

        // if we are on ibd, we don't have any filters to rescan
        if self.chain.is_in_ibd() {
            return Err(RpcServerError::InInitialBlockDownload);
        }

        let addresses = self.wallet.get_cached_addresses();

        if addresses.is_empty() {
            return Err(RpcServerError::NoAddressesToRescan);
        }

        let wallet = self.wallet.clone();

        if self.block_filter_storage.is_none() {
            return Err(RpcServerError::NoBlockFilters);
        };

        let cfilters = self.block_filter_storage.as_ref().unwrap().clone();

        let node = self.node.clone();

        let chain = self.chain.clone();

        tokio::task::spawn(Self::rescan_with_block_filters(
            addresses,
            chain,
            wallet,
            cfilters,
            node,
            (start_height != 0).then_some(start_height), // Its ugly but to maintain the API here its necessary to recast to a Option.
            (stop_height != 0).then_some(stop_height),
        ));
        Ok(true)
    }

    fn send_raw_transaction(&self, tx: String) -> Result<Txid> {
        let tx_hex = Vec::from_hex(&tx).map_err(|_| RpcServerError::InvalidHex)?;
        let tx = deserialize(&tx_hex).map_err(|e| RpcServerError::Decode(e.to_string()))?;
        self.chain
            .broadcast(&tx)
            .map_err(|_| RpcServerError::Chain)?;

        Ok(tx.compute_txid())
    }

    async fn get_peer_info(&self) -> Result<Vec<PeerInfo>> {
        self.node
            .get_peer_info()
            .await
            .map_err(|_| RpcServerError::Node("Failed to get peer info".to_string()))
    }
}

async fn handle_json_rpc_request(
    req: JsonRequest,
    state: Arc<RpcImpl<impl RpcChain>>,
) -> Result<serde_json::Value> {
    let JsonRequest {
        jsonrpc,
        method,
        params,
        id,
    } = req;

    if let Some(version) = jsonrpc {
        if !["1.0", "2.0"].contains(&version.as_str()) {
            return Err(RpcServerError::InvalidRequest);
        }
    }

    state.inflight.write().await.insert(
        id.clone(),
        InflightRpc {
            method: method.clone(),
            when: Instant::now(),
        },
    );

    match method.as_str() {
        // blockchain
        "getbestblockhash" => {
            let hash = state.get_best_block_hash()?;
            Ok(serde_json::to_value(hash).unwrap())
        }

        "getblock" => {
            let hash = get_hash(&params, 0, "block_hash")?;
            let verbosity = get_numeric(&params, 1, "verbosity")?;

            match verbosity {
                0 => {
                    let block = state.get_block_serialized(hash).await?;

                    let block = GetBlockRes::Serialized(block);
                    Ok(serde_json::to_value(block).unwrap())
                }

                1 => {
                    let block = state.get_block(hash).await?;

                    let block = GetBlockRes::Verbose(block.into());
                    Ok(serde_json::to_value(block).unwrap())
                }

                _ => Err(RpcServerError::InvalidVerbosityLevel),
            }
        }

        "getblockchaininfo" => state
            .get_blockchain_info()
            .map(|v| serde_json::to_value(v).unwrap()),

        "getblockcount" => state
            .get_block_count()
            .map(|v| serde_json::to_value(v).unwrap()),

        "getblockfrompeer" => {
            let hash = get_hash(&params, 0, "block_hash")?;
            state
                .get_block(hash)
                .await
                .map(|v| serde_json::to_value(v).unwrap())
        }

        "getblockhash" => {
            let height = get_numeric(&params, 0, "block_height")?;
            state
                .get_block_hash(height)
                .map(|h| serde_json::to_value(h).unwrap())
        }

        "getblockheader" => {
            let hash = get_hash(&params, 0, "block_hash")?;
            state
                .get_block_header(hash)
                .map(|h| serde_json::to_value(h).unwrap())
        }

        "gettxout" => {
            let txid = get_hash(&params, 0, "txid")?;
            let vout = get_numeric(&params, 1, "vout")?;
            let include_mempool =
                get_optional_field(&params, 2, "include_mempool", get_bool)?.unwrap_or(false);

            state
                .get_tx_out(txid, vout, include_mempool)
                .map(|v| serde_json::to_value(v).unwrap())
        }

        "gettxoutproof" => {
            let txids = get_hashes_array(&params, 0, "txids")?;
            let block_hash = get_optional_field(&params, 1, "block_hash", get_hash)?;

            Ok(serde_json::to_value(
                state
                    .get_txout_proof(&txids, block_hash)
                    .await?
                    .0
                    .to_lower_hex_string(),
            )
            .expect("GetTxOutProof implements serde"))
        }

        "getrawtransaction" => {
            let txid = get_hash(&params, 0, "txid")?;
            let verbosity = get_optional_field(&params, 1, "verbosity", get_bool)?;

            state
                .get_transaction(txid, verbosity)
                .map(|v| serde_json::to_value(v).unwrap())
        }

        "getroots" => state.get_roots().map(|v| serde_json::to_value(v).unwrap()),

        "findtxout" => {
            let txid = get_hash(&params, 0, "txid")?;
            let vout = get_numeric(&params, 1, "vout")?;
            let script = get_string(&params, 2, "script")?;
            let script = ScriptBuf::from_hex(&script).map_err(|_| RpcServerError::InvalidScript)?;
            let height = get_numeric(&params, 3, "height")?;

            let state = state.clone();
            state.find_tx_out(txid, vout, script, height).await
        }

        // control
        "getmemoryinfo" => {
            let mode =
                get_optional_field(&params, 0, "mode", get_string)?.unwrap_or("stats".into());

            state
                .get_memory_info(&mode)
                .map(|v| serde_json::to_value(v).unwrap())
        }

        "getrpcinfo" => state
            .get_rpc_info()
            .await
            .map(|v| serde_json::to_value(v).unwrap()),

        // help
        // logging
        "stop" => state.stop().await.map(|v| serde_json::to_value(v).unwrap()),

        "uptime" => {
            let uptime = state.uptime();
            Ok(serde_json::to_value(uptime).unwrap())
        }

        // network
        "getpeerinfo" => state
            .get_peer_info()
            .await
            .map(|v| serde_json::to_value(v).unwrap()),

        "addnode" => {
            let node = get_string(&params, 0, "node")?;
            let command = get_string(&params, 1, "command")?;
            let v2transport =
                get_optional_field(&params, 2, "V2transport", get_bool)?.unwrap_or(false);

            state
                .add_node(node, command, v2transport)
                .await
                .map(|v| serde_json::to_value(v).unwrap())
        }

        "ping" => {
            state.ping().await?;

            Ok(serde_json::json!(null))
        }

        // wallet
        "loaddescriptor" => {
            let descriptor = get_string(&params, 0, "descriptor")?;

            state
                .load_descriptor(descriptor)
                .map(|v| serde_json::to_value(v).unwrap())
        }

        "rescanblockchain" => {
            let start_height = get_optional_field(&params, 0, "start_height", get_numeric)?;
            let stop_height = get_optional_field(&params, 1, "stop_height", get_numeric)?;
            let use_timestamp =
                get_optional_field(&params, 2, "use_timestamp", get_bool)?.unwrap_or(false);
            let confidence_str = get_optional_field(&params, 3, "confidence", get_string)?
                .unwrap_or("medium".into());

            let confidence = match confidence_str.as_str() {
                "low" => RescanConfidence::Low,
                "medium" => RescanConfidence::Medium,
                "high" => RescanConfidence::High,
                "exact" => RescanConfidence::Exact,
                _ => return Err(RpcServerError::InvalidRescanVal),
            };

            state
                .rescan_blockchain(start_height, stop_height, use_timestamp, Some(confidence))
                .map(|v| serde_json::to_value(v).unwrap())
        }

        "sendrawtransaction" => {
            let tx = get_string(&params, 0, "hex")?;
            state
                .send_raw_transaction(tx)
                .map(|v| serde_json::to_value(v).unwrap())
        }

        "listdescriptors" => state
            .list_descriptors()
            .map(|v| serde_json::to_value(v).unwrap()),

        _ => {
            let error = RpcServerError::MethodNotFound;
            Err(error)
        }
    }
}

fn get_http_error_code(err: &RpcServerError) -> u16 {
    match err {
        // you messed up
        RpcServerError::InvalidHex
        | RpcServerError::InvalidAddress
        | RpcServerError::InvalidScript
        | RpcServerError::InvalidRequest
        | RpcServerError::InvalidPort
        | RpcServerError::InvalidDescriptor(_)
        | RpcServerError::InvalidVerbosityLevel
        | RpcServerError::Decode(_)
        | RpcServerError::NoBlockFilters
        | RpcServerError::InvalidMemInfoMode
        | RpcServerError::InvalidAddnodeCommand
        | RpcServerError::InvalidTimestamp
        | RpcServerError::InvalidRescanVal
        | RpcServerError::NoAddressesToRescan
        | RpcServerError::ChainWorkOverflow
        | RpcServerError::Parse(_)
        | RpcServerError::Wallet(_) => 400,

        // idunnolol
        RpcServerError::MethodNotFound
        | RpcServerError::BlockNotFound
        | RpcServerError::TxNotFound => 404,

        // we messed up, sowwy
        RpcServerError::InInitialBlockDownload
        | RpcServerError::Node(_)
        | RpcServerError::Chain
        | RpcServerError::Filters(_) => 503,
    }
}

fn get_json_rpc_error_code(err: &RpcServerError) -> i32 {
    match err {
        // Parse Error
        RpcServerError::Decode(_) | RpcServerError::Parse(_) => -32700,

        // Invalid Request
        RpcServerError::InvalidHex
        | RpcServerError::InvalidAddress
        | RpcServerError::InvalidScript
        | RpcServerError::MethodNotFound
        | RpcServerError::InvalidRequest
        | RpcServerError::InvalidPort
        | RpcServerError::InvalidDescriptor(_)
        | RpcServerError::InvalidVerbosityLevel
        | RpcServerError::TxNotFound
        | RpcServerError::BlockNotFound
        | RpcServerError::InvalidTimestamp
        | RpcServerError::InvalidMemInfoMode
        | RpcServerError::InvalidAddnodeCommand
        | RpcServerError::InvalidRescanVal
        | RpcServerError::NoAddressesToRescan
        | RpcServerError::ChainWorkOverflow
        | RpcServerError::Wallet(_) => -32600,

        // server error
        RpcServerError::InInitialBlockDownload
        | RpcServerError::Node(_)
        | RpcServerError::Chain
        | RpcServerError::NoBlockFilters
        | RpcServerError::Filters(_) => -32603,
    }
}

async fn json_rpc_request(
    State(state): State<Arc<RpcImpl<impl RpcChain>>>,
    Json(req): Json<JsonRequest>,
) -> axum::http::Response<axum::body::Body> {
    debug!("Received JSON-RPC request: {req:?}");

    let id = req.id.clone();
    let res = handle_json_rpc_request(req, state.clone()).await;

    state.inflight.write().await.remove(&id);

    match res {
        Ok(res) => {
            let body = serde_json::json!({
                "result": res,
                "id": id,
            });

            axum::http::Response::builder()
                .status(axum::http::StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap()
        }

        Err(e) => {
            let http_error_code = get_http_error_code(&e);
            let json_rpc_error_code = get_json_rpc_error_code(&e);
            let error = RpcError {
                code: json_rpc_error_code,
                message: e.to_string(),
                data: None,
            };

            let body = serde_json::json!({
                "error": error,
                "id": id,
            });

            axum::http::Response::builder()
                .status(axum::http::StatusCode::from_u16(http_error_code).unwrap())
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap()
        }
    }
}

async fn cannot_get(_state: State<Arc<RpcImpl<impl RpcChain>>>) -> Json<serde_json::Value> {
    Json(json!({
        "error": "Cannot get on this route",
    }))
}

impl<Blockchain: RpcChain> RpcImpl<Blockchain> {
    async fn rescan_with_block_filters(
        addresses: Vec<ScriptBuf>,
        chain: Blockchain,
        wallet: Arc<AddressCache<KvDatabase>>,
        cfilters: Arc<NetworkFilters<FlatFiltersStore>>,
        node: NodeInterface,
        start_height: Option<u32>,
        stop_height: Option<u32>,
    ) -> Result<()> {
        let blocks = cfilters
            .match_any(
                addresses.iter().map(|a| a.as_bytes()).collect(),
                start_height,
                stop_height,
                chain.clone(),
            )
            .unwrap();

        info!("rescan filter hits: {blocks:?}");

        for block in blocks {
            if let Ok(Some(block)) = node.get_block(block).await {
                let height = chain
                    .get_block_height(&block.block_hash())
                    .unwrap()
                    .unwrap();

                wallet.block_process(&block, height);
            }
        }

        Ok(())
    }

    fn make_vin(&self, input: TxIn) -> TxInJson {
        let txid = serialize_hex(&input.previous_output.txid);
        let vout = input.previous_output.vout;
        let sequence = input.sequence.0;
        TxInJson {
            txid,
            vout,
            script_sig: ScriptSigJson {
                asm: input.script_sig.to_asm_string(),
                hex: input.script_sig.to_hex_string(),
            },
            witness: input
                .witness
                .iter()
                .map(|w| w.to_hex_string(bitcoin::hex::Case::Upper))
                .collect(),
            sequence,
        }
    }

    fn get_script_type(script: ScriptBuf) -> Option<&'static str> {
        if script.is_p2pkh() {
            return Some("p2pkh");
        }
        if script.is_p2sh() {
            return Some("p2sh");
        }
        if script.is_p2wpkh() {
            return Some("v0_p2wpkh");
        }
        if script.is_p2wsh() {
            return Some("v0_p2wsh");
        }
        None
    }

    fn make_vout(&self, output: TxOut, n: u32) -> TxOutJson {
        let value = output.value;
        TxOutJson {
            value: value.to_sat(),
            n,
            script_pub_key: ScriptPubKeyJson {
                asm: output.script_pubkey.to_asm_string(),
                hex: output.script_pubkey.to_hex_string(),
                req_sigs: 0, // This field is deprecated
                address: Address::from_script(&output.script_pubkey, self.network)
                    .map(|a| a.to_string())
                    .unwrap(),
                type_: Self::get_script_type(output.script_pubkey)
                    .unwrap_or("nonstandard")
                    .to_string(),
            },
        }
    }

    fn make_raw_transaction(&self, tx: CachedTransaction) -> RawTx {
        let raw_tx = tx.tx;
        let in_active_chain = tx.height != 0;
        let hex = serialize_hex(&raw_tx);
        let txid = serialize_hex(&raw_tx.compute_txid());
        let block_hash = self
            .chain
            .get_block_hash(tx.height)
            .unwrap_or(BlockHash::all_zeros());
        let tip = self.chain.get_height().unwrap();
        let confirmations = if in_active_chain {
            tip - tx.height + 1
        } else {
            0
        };

        RawTx {
            in_active_chain,
            hex,
            txid,
            hash: serialize_hex(&raw_tx.compute_wtxid()),
            size: raw_tx.total_size() as u32,
            vsize: raw_tx.vsize() as u32,
            weight: raw_tx.weight().to_wu() as u32,
            version: raw_tx.version.0 as u32,
            locktime: raw_tx.lock_time.to_consensus_u32(),
            vin: raw_tx
                .input
                .iter()
                .map(|input| self.make_vin(input.clone()))
                .collect(),
            vout: raw_tx
                .output
                .into_iter()
                .enumerate()
                .map(|(i, output)| self.make_vout(output, i as u32))
                .collect(),
            blockhash: serialize_hex(&block_hash),
            confirmations,
            blocktime: self
                .chain
                .get_block_header(&block_hash)
                .map(|h| h.time)
                .unwrap_or(0),
            time: self
                .chain
                .get_block_header(&block_hash)
                .map(|h| h.time)
                .unwrap_or(0),
        }
    }

    // TODO(@luisschwab): get rid of this once
    // https://github.com/rust-bitcoin/rust-bitcoin/pull/4639 makes it into a release.
    fn get_port(net: &Network) -> u16 {
        match net {
            Network::Bitcoin => 8332,
            Network::Signet => 38332,
            Network::Testnet => 18332,
            Network::Testnet4 => 48332,
            Network::Regtest => 18442,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        chain: Blockchain,
        wallet: Arc<AddressCache<KvDatabase>>,
        node: NodeInterface,
        kill_signal: Arc<RwLock<bool>>,
        network: Network,
        block_filter_storage: Option<Arc<NetworkFilters<FlatFiltersStore>>>,
        address: Option<SocketAddr>,
        log_path: String,
    ) {
        let address = address.unwrap_or_else(|| {
            format!("127.0.0.1:{}", Self::get_port(&network))
                .parse()
                .unwrap()
        });

        let listener = match tokio::net::TcpListener::bind(address).await {
            Ok(listener) => {
                let local_addr = listener
                    .local_addr()
                    .expect("Infallible: listener binding was `Ok`");
                info!("RPC server is running at {local_addr}");
                listener
            }
            Err(_) => {
                error!(
                    "Failed to bind to address {address}. Floresta is probably already running.",
                );
                std::process::exit(-1);
            }
        };

        let router = Router::new()
            .route("/", post(json_rpc_request).get(cannot_get))
            .layer(
                CorsLayer::new()
                    .allow_private_network(true)
                    .allow_methods([Method::POST, Method::HEAD]),
            )
            .with_state(Arc::new(RpcImpl {
                chain,
                wallet,
                node,
                kill_signal,
                network,
                block_filter_storage,
                inflight: Arc::new(RwLock::new(HashMap::new())),
                log_path,
                start_time: Instant::now(),
            }));

        axum::serve(listener, router)
            .await
            .expect("failed to start rpc server");
    }
}

#[derive(Debug)]
pub enum RpcServerError {
    /// There was a rescan request but we do not have any addresses in the watch-only wallet.
    NoAddressesToRescan,

    /// There was a rescan request with invalid values
    InvalidRescanVal,

    /// Verbosity level is not 0 or 1
    InvalidVerbosityLevel,

    /// The requested transaction is not found in the blockchain
    TxNotFound,

    /// The provided script is invalid, e.g., if it is not a valid P2PKH or P2SH script
    InvalidScript,

    /// The provided descriptor is invalid, e.g., if it does not match the expected format
    InvalidDescriptor(miniscript::Error),

    /// The requested block is not found in the blockchain
    BlockNotFound,

    /// There is an error with the chain, e.g., if the chain is not synced or when the chain is not valid
    Chain,

    /// The request is invalid, e.g., some parameters use an incorrect type
    InvalidRequest,

    /// The requested method is not found, e.g., if the method is not implemented or when the method is not available
    MethodNotFound,

    /// This error is returned when there is an error decoding the request, e.g., if the request is not valid JSON
    Decode(String),

    /// The provided port is invalid, e.g., when it is not a valid port number (0-65535)
    InvalidPort,

    /// The provided address is invalid, e.g., when it is not a valid IP address or hostname
    InvalidAddress,

    /// This error is returned when there is an error with the node, e.g., if the node is not connected or when the node is not responding
    Node(String),

    /// This error is returned when the node does not have block filters enabled, which is required for some RPC calls
    NoBlockFilters,

    /// This error is returned when a hex value is invalid
    InvalidHex,

    /// This error is returned when the node is in initial block download, which means it is still syncing the blockchain
    InInitialBlockDownload,

    InvalidMemInfoMode,

    /// This error is returned when there is an error with the wallet, e.g., if the wallet is not loaded or when the wallet is not available
    Wallet(String),

    /// This error is returned when there is an error with block filters, e.g., if the filters are not available or when there is an issue with the filter data
    Filters(String),

    /// This error is returned when there is an error calculating the chain work
    ChainWorkOverflow,

    /// This error is returned when the addnode command is invalid, e.g., if the command is not recognized or when the parameters are incorrect
    InvalidAddnodeCommand,

    /// Raised if when the rescanblockchain command, with the timestamp flag activated, contains some timestamp thats less than the genesis one and not zero which is the default value for this arg.
    InvalidTimestamp,

    Parse(ArgParseError),
}

impl Display for RpcServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcServerError::InvalidTimestamp => write!(f, "Invalid timestamp, ensure that it is between the genesis and the tip."),
            RpcServerError::InvalidRescanVal => write!(f, "Your rescan request contains invalid values"),
            RpcServerError::NoAddressesToRescan => write!(f, "You do not have any address to proceed with the rescan"),
            RpcServerError::InvalidRequest => write!(f, "Invalid request"),
            RpcServerError::InvalidHex =>  write!(f, "Invalid hex"),
            RpcServerError::MethodNotFound =>  write!(f, "Method not found"),
            RpcServerError::Decode(e) =>  write!(f, "error decoding request: {e}"),
            RpcServerError::TxNotFound =>  write!(f, "Transaction not found"),
            RpcServerError::InvalidDescriptor(e) =>  write!(f, "Invalid descriptor: {e}"),
            RpcServerError::BlockNotFound =>  write!(f, "Block not found"),
            RpcServerError::Chain => write!(f, "Chain error"),
            RpcServerError::InvalidPort => write!(f, "Invalid port"),
            RpcServerError::InvalidAddress => write!(f, "Invalid address"),
            RpcServerError::Node(e) => write!(f, "Node error: {e}"),
            RpcServerError::NoBlockFilters => write!(f, "You don't have block filters enabled, please start florestad without --no-cfilters to run this RPC"),
            RpcServerError::InInitialBlockDownload => write!(f, "Node is in initial block download, wait until it's finished"),
            RpcServerError::InvalidScript => write!(f, "Invalid script"),
            RpcServerError::InvalidVerbosityLevel => write!(f, "Invalid verbosity level"),
            RpcServerError::InvalidMemInfoMode => write!(f, "Invalid meminfo mode, should be stats or mallocinfo"),
            RpcServerError::Wallet(e) => write!(f, "Wallet error: {e}"),
            RpcServerError::Filters(e) => write!(f, "Error with filters: {e}"),
            RpcServerError::ChainWorkOverflow => write!(f, "Overflow while calculating the chain work"),
            RpcServerError::InvalidAddnodeCommand => write!(f, "Invalid addnode command"),
            RpcServerError::Parse(e) => write!(f, "{e:?}")
        }
    }
}

impl IntoResponse for RpcServerError {
    fn into_response(self) -> axum::http::Response<axum::body::Body> {
        let body = serde_json::json!({
            "error": self.to_string(),
            "result": serde_json::Value::Null,
            "id": serde_json::Value::Null,
        });
        axum::http::Response::builder()
            .status(axum::http::StatusCode::BAD_REQUEST)
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }
}

impl From<HeaderExtError> for RpcServerError {
    fn from(value: HeaderExtError) -> Self {
        match value {
            HeaderExtError::Chain(_) => RpcServerError::Chain,
            HeaderExtError::BlockNotFound => RpcServerError::BlockNotFound,
            HeaderExtError::ChainWorkOverflow => RpcServerError::ChainWorkOverflow,
        }
    }
}

impl_error_from!(RpcServerError, miniscript::Error, InvalidDescriptor);

impl_error_from!(RpcServerError, ArgParseError, Parse);

impl<T: std::fmt::Debug> From<floresta_watch_only::WatchOnlyError<T>> for RpcServerError {
    fn from(e: floresta_watch_only::WatchOnlyError<T>) -> Self {
        RpcServerError::Wallet(e.to_string())
    }
}
