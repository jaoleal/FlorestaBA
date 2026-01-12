//! This module holds all RPC server side methods for interacting with our node's network stack.

use bitcoin::BlockHash;
use bitcoin::ScriptBuf;
use bitcoin::Txid;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hex::DisplayHex;
use corepc_types::v29::GetTxOut;
use corepc_types::v30::GetBestBlockHash;
use corepc_types::v30::GetBlockCount;
use corepc_types::v30::GetBlockHash;
use corepc_types::v30::GetBlockHeader;
use corepc_types::v30::GetRpcInfo;
use corepc_types::v30::GetTransaction;
use corepc_types::v30::RescanBlockchain;
use corepc_types::v30::SendRawTransaction;
use floresta_rpc::rpc::FlorestaRPC;
use floresta_rpc::rpc::RpcResult;
use floresta_rpc::rpc_types::AddNodeCommand;
use floresta_rpc::rpc_types::Error;
use floresta_rpc::rpc_types::GetBlock;
use floresta_rpc::rpc_types::GetBlockchainInfoRes;
use floresta_rpc::rpc_types::GetMemInfoRes;
use floresta_rpc::rpc_types::PeerInfo;
use floresta_rpc::rpc_types::RescanConfidence;
use serde_json::Value;

use super::res::GetBlockRes;
use super::res::JsonRpcError;
use super::server::RpcChain;
use super::server::RpcServer;

/// Helper function to convert JsonRpcError to rpc_types::Error
fn map_error(e: JsonRpcError) -> Error {
    Error::Internal(e.to_string())
}

impl<Blockchain> FlorestaRPC for RpcServer<Blockchain>
where
    Blockchain: RpcChain,
{
    async fn get_block_filter(&self, height: u32) -> RpcResult<String> {
        // Block filters are not implemented yet in the server
        // This would need to access block_filter_storage
        if let Some(ref filters) = self.block_filter_storage {
            filters
                .get_filter(height)
                .map(|f| f.content.to_lower_hex_string())
                .map_err(|e| Error::Internal(format!("Failed to get block filter: {}", e)))
        } else {
            Err(Error::Internal("Block filters not enabled".to_string()))
        }
    }

    async fn get_blockchain_info(&self) -> RpcResult<GetBlockchainInfoRes> {
        self.get_blockchain_info().map_err(map_error)
    }

    async fn get_best_block_hash(&self) -> RpcResult<GetBestBlockHash> {
        self.get_best_block_hash()
            .map(|hash| GetBestBlockHash(hash.to_string()))
            .map_err(map_error)
    }

    async fn get_block_hash(&self, height: u32) -> RpcResult<GetBlockHash> {
        self.get_block_hash(height)
            .map(|hash| GetBlockHash(hash.to_string()))
            .map_err(map_error)
    }

    async fn get_block_header(&self, hash: BlockHash) -> RpcResult<GetBlockHeader> {
        self.get_block_header(hash)
            .map(|header| GetBlockHeader {
                hash: header.block_hash().to_string(),
                confirmations: self.chain.get_height().unwrap_or(0)
                    - self.chain.get_block_height(&header.block_hash()).unwrap().unwrap_or(0)
                    + 1,
                height: self.chain.get_block_height(&header.block_hash()).unwrap().unwrap_or(0),
                version: header.version.to_consensus(),
                version_hex: format!("{:08x}", header.version.to_consensus()),
                merkleroot: header.merkle_root.to_string(),
                time: header.time,
                mediantime: header.time, // Simplified - should calculate median time past
                nonce: header.nonce,
                bits: format!("{:08x}", header.bits.to_consensus()),
                difficulty: header.difficulty(self.chain.get_params()) as f64,
                chainwork: "0".to_string(), // Simplified
                n_tx: 0, // Not available from header alone
                previousblockhash: header.prev_blockhash.to_string(),
                nextblockhash: None, // Would need to query chain
            })
            .map_err(map_error)
    }

    async fn get_transaction(&self, tx_id: Txid, verbosity: Option<bool>) -> RpcResult<GetTransaction> {
        let verbosity = verbosity.unwrap_or(false);
        let tx_value = self.get_transaction(tx_id, Some(verbosity))
            .map_err(map_error)?;
        
        // Convert Value to GetTransaction
        serde_json::from_value(tx_value)
            .map_err(|e| Error::Internal(format!("Failed to parse transaction: {}", e)))
    }

    async fn get_txout_proof(
        &self,
        txids: Vec<Txid>,
        blockhash: Option<BlockHash>,
    ) -> RpcResult<Option<String>> {
        self.get_txout_proof(&txids, blockhash)
            .await
            .map(|proof| Some(proof.0.to_lower_hex_string()))
            .map_err(map_error)
    }

    async fn load_descriptor(&self, descriptor: String) -> RpcResult<bool> {
        self.load_descriptor(descriptor).map_err(map_error)
    }

    async fn rescanblockchain(
        &self,
        start_block: Option<u32>,
        stop_block: Option<u32>,
        use_timestamp: bool,
        confidence: RescanConfidence,
    ) -> RpcResult<RescanBlockchain> {
        // Convert RescanConfidence from rpc_types to server res type
        let server_confidence = match confidence {
            RescanConfidence::Low => super::res::RescanConfidence::Low,
            RescanConfidence::Medium => super::res::RescanConfidence::Medium,
            RescanConfidence::High => super::res::RescanConfidence::High,
            RescanConfidence::Exact => super::res::RescanConfidence::Exact,
        };
        
        self.rescan_blockchain(start_block, stop_block, use_timestamp, Some(server_confidence))
            .map(|_| {
                let (start, stop) = self.get_rescan_interval(use_timestamp, start_block, stop_block, Some(server_confidence))
                    .unwrap_or((0, 0));
                RescanBlockchain {
                    start_height: start,
                    stop_height: stop,
                }
            })
            .map_err(map_error)
    }

    async fn get_block_count(&self) -> RpcResult<GetBlockCount> {
        self.get_block_count()
            .map(|count| GetBlockCount(count))
            .map_err(map_error)
    }

    async fn send_raw_transaction(&self, tx: String) -> RpcResult<SendRawTransaction> {
        self.send_raw_transaction(tx)
            .map(|txid| SendRawTransaction(txid.to_string()))
            .map_err(map_error)
    }

    async fn get_roots(&self) -> RpcResult<Vec<String>> {
        self.get_roots().map_err(map_error)
    }

    async fn get_peer_info(&self) -> RpcResult<Vec<PeerInfo>> {
        self.get_peer_info()
            .await
            .map(|peers| {
                peers.into_iter().map(|p| floresta_rpc::rpc_types::PeerInfo {
                    address: p.address,
                    services: p.services,
                    user_agent: p.user_agent,
                    initial_height: p.initial_height,
                    kind: p.kind,
                    state: p.state,
                    transport_protocol: p.transport_protocol,
                }).collect()
            })
            .map_err(map_error)
    }

    async fn get_block(&self, hash: BlockHash, verbosity: Option<u32>) -> RpcResult<GetBlock> {
        let verbosity = verbosity.unwrap_or(0);
        match verbosity {
            0 => {
                let block_hex = self.get_block_serialized(hash).await.map_err(map_error)?;
                Ok(GetBlock::Two(corepc_types::v30::GetBlockVerboseZero(block_hex)))
            }
            1 => {
                let block = self.get_block(hash).await.map_err(map_error)?;
                let block_verbose = corepc_types::v30::GetBlockVerboseOne {
                    hash: block.hash,
                    confirmations: block.confirmations,
                    size: block.size as u32,
                    strippedsize: block.strippedsize as u32,
                    weight: block.weight as u32,
                    height: block.height,
                    version: block.version,
                    version_hex: block.version_hex,
                    merkleroot: block.merkleroot,
                    tx: block.tx,
                    time: block.time,
                    mediantime: block.mediantime,
                    nonce: block.nonce,
                    bits: block.bits,
                    difficulty: block.difficulty,
                    chainwork: block.chainwork,
                    n_tx: block.n_tx as u32,
                    previousblockhash: block.previousblockhash,
                    nextblockhash: block.nextblockhash,
                };
                Ok(GetBlock::One(block_verbose))
            }
            _ => Err(Error::InvalidVerbosity),
        }
    }

    async fn get_tx_out(&self, tx_id: Txid, outpoint: u32) -> RpcResult<GetTxOut> {
        self.get_tx_out(tx_id, outpoint, false)
            .map_err(map_error)?
            .ok_or_else(|| Error::TxOutNotFound)
    }

    async fn stop(&self) -> RpcResult<String> {
        self.stop()
            .await
            .map(|s| s.to_string())
            .map_err(map_error)
    }

    async fn add_node(
        &self,
        node: String,
        command: AddNodeCommand,
        v2transport: bool,
    ) -> RpcResult<Value> {
        let command_str = command.to_string();
        self.add_node(node, command_str, v2transport)
            .await
            .map_err(map_error)
    }

    async fn find_tx_out(
        &self,
        tx_id: Txid,
        outpoint: u32,
        script: String,
        height_hint: u32,
    ) -> RpcResult<Value> {
        let script = ScriptBuf::from_hex(&script)
            .map_err(|_| Error::Internal("Invalid script hex".to_string()))?;
        self.find_tx_out(tx_id, outpoint, script, height_hint)
            .await
            .map_err(map_error)
    }

    async fn get_memory_info(&self, mode: String) -> RpcResult<GetMemInfoRes> {
        self.get_memory_info(&mode).map_err(map_error)
    }

    async fn get_rpc_info(&self) -> RpcResult<GetRpcInfo> {
        self.get_rpc_info()
            .await
            .map(|info| GetRpcInfo {
                active_commands: info.active_commands.into_iter().map(|cmd| {
                    corepc_types::v30::ActiveCommand {
                        method: cmd.method,
                        duration: cmd.duration,
                    }
                }).collect(),
                logpath: info.logpath,
            })
            .map_err(map_error)
    }

    async fn uptime(&self) -> RpcResult<u32> {
        Ok(self.uptime() as u32)
    }

    async fn list_descriptors(&self) -> RpcResult<Vec<String>> {
        self.list_descriptors().map_err(map_error)
    }

    async fn ping(&self) -> RpcResult<()> {
        self.node
            .ping()
            .await
            .map_err(|e| Error::Internal(e.to_string()))
    }
}

