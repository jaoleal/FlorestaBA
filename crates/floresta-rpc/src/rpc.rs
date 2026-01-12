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
use serde_json::Value;

use crate::rpc_types::AddNodeCommand;
use crate::rpc_types::Error;
use crate::rpc_types::GetBlock;
use crate::rpc_types::GetBlockchainInfoRes;
use crate::rpc_types::GetMemInfoRes;
use crate::rpc_types::PeerInfo;
use crate::rpc_types::RescanConfidence;

pub type RpcResult<T> = std::result::Result<T, Error>;

/// A trait defining the signature of our rpc commands.
///
/// Both client and server should implement this to ensure type compatibility between them.
///
/// The client would implement this building a request for the server with the given input,
/// and the server by receiving the request have to decode the request calling the exact same
/// method on its side, returning the data and the request after that, which should be received
/// by the client returning the received data.
///
/// Is it confuse? With that we can do type inferring on both sides without any worry of them
/// mismatching.
///
/// To maintain API compatibility for all sides the signature of the commands **need** to
/// be the same, with this trait the only part that can differ is CLI <- -> Client.
///
/// I know thats ugly but it should help a lot finding references in the code just by keeping
/// the method name the same as the command.
#[async_trait]
pub trait FlorestaJsonRPC {
    /// Get the BIP158 filter for a given block height
    ///
    /// BIP158 filters are a compact representation of the set of transactions in a block,
    /// designed for efficient light client synchronization. This method returns the filter
    /// for a given block height, encoded as a hexadecimal string.
    /// You need to have enabled block filters by setting the `blockfilters=1` option
    async fn get_block_filter(&self, _height: u32) -> RpcResult<String> {
        Err(Error::NotImplemented)
    }

    /// Returns general information about the chain we are on
    ///
    /// This method returns a bunch of information about the chain we are on, including
    /// the current height, the best block hash, the difficulty, and whether we are
    /// currently in IBD (Initial Block Download) mode.
    async fn get_blockchain_info(&self) -> RpcResult<GetBlockchainInfoRes> {
        Err(Error::NotImplemented)
    }

    /// Returns the hash of the best (tip) block in the most-work fully-validated chain.
    async fn get_best_block_hash(&self) -> RpcResult<GetBestBlockHash> {
        Err(Error::NotImplemented)
    }

    /// Returns the hash of the block at the given height
    ///
    /// This method returns the hash of the block at the given height. If the height is
    /// invalid, an error is returned.
    async fn get_block_hash(&self, _height: u32) -> RpcResult<GetBlockHash> {
        Err(Error::NotImplemented)
    }

    /// Returns the block header for the given block hash
    ///
    /// This method returns the block header for the given block hash, as defined
    /// in the Bitcoin protocol specification. A header contains the block's version,
    /// the previous block hash, the merkle root, the timestamp, the difficulty target,
    /// and the nonce.
    async fn get_block_header(&self, _hash: BlockHash) -> RpcResult<GetBlockHeader> {
        Err(Error::NotImplemented)
    }

    /// Gets a transaction from the blockchain
    ///
    /// This method returns a transaction that's cached in our wallet. If the verbosity flag is
    /// set to false, the transaction is returned as a hexadecimal string. If the verbosity
    /// flag is set to true, the transaction is returned as a json object.
    async fn get_transaction(
        &self,
        _tx_id: Txid,
        _verbosity: Option<bool>,
    ) -> RpcResult<GetTransaction> {
        Err(Error::NotImplemented)
    }

    /// Returns the proof that one or more transactions were included in a block
    ///
    /// This method returns the Merkle proof, showing that a transaction was included in a block.
    /// The pooof is returned as a vector hexadecimal string.
    async fn get_txout_proof(
        &self,
        _txids: Vec<Txid>,
        _blockhash: Option<BlockHash>,
    ) -> RpcResult<Option<String>> {
        Err(Error::NotImplemented)
    }

    /// Loads up a descriptor into the wallet
    ///
    /// This method loads up a descriptor into the wallet. If the rescan option is not None,
    /// the wallet will be rescanned for transactions matching the descriptor. If you have
    /// compact block filters enabled, this process will be much faster and use less bandwidth.
    /// The rescan parameter is the height at which to start the rescan, and should be at least
    /// as old as the oldest transaction this descriptor could have been used in.
    async fn load_descriptor(&self, _descriptor: String) -> RpcResult<bool> {
        Err(Error::NotImplemented)
    }

    #[doc = include_str!("../../../doc/rpc/rescanblockchain.md")]
    async fn rescanblockchain(
        &self,
        _start_block: Option<u32>,
        _stop_block: Option<u32>,
        _use_timestamp: bool,
        _confidence: RescanConfidence,
    ) -> RpcResult<RescanBlockchain> {
        Err(Error::NotImplemented)
    }

    /// Returns the current height of the blockchain
    async fn get_block_count(&self) -> RpcResult<GetBlockCount> {
        Err(Error::NotImplemented)
    }

    /// Sends a hex-encoded transaction to the network
    ///
    /// This method sends a transaction to the network. The transaction should be encoded as a
    /// hexadecimal string. If the transaction is valid, it will be broadcast to the network, and
    /// return the transaction id. If the transaction is invalid, an error will be returned.
    async fn send_raw_transaction(&self, _tx: String) -> RpcResult<SendRawTransaction> {
        Err(Error::NotImplemented)
    }

    /// Gets the current accumulator for the chain we're on
    ///
    /// This method returns the current accumulator for the chain we're on. The accumulator is
    /// a set of roots, that let's us prove that a UTXO exists in the chain. This method returns
    /// a vector of hexadecimal strings, each of which is a root in the accumulator.
    async fn get_roots(&self) -> RpcResult<Vec<String>> {
        Err(Error::NotImplemented)
    }

    /// Gets information about the peers we're connected with
    ///
    /// This method returns information about the peers we're connected with. This includes
    /// the peer's IP address, the peer's version, the peer's user agent, the transport protocol
    /// and the peer's current height.
    async fn get_peer_info(&self) -> RpcResult<Vec<PeerInfo>> {
        Err(Error::NotImplemented)
    }

    /// Returns a block, given a block hash
    ///
    /// This method returns a block, given a block hash. If the verbosity flag is 0, the block
    /// is returned as a hexadecimal string. If the verbosity flag is 1, the block is returned
    /// as a json object.
    async fn get_block(&self, _hash: BlockHash, _verbosity: Option<u32>) -> RpcResult<GetBlock> {
        Err(Error::NotImplemented)
    }

    /// Return a cached transaction output
    ///
    /// This method returns a cached transaction output. If the output is not in the cache,
    /// or is spent, an empty object is returned. If you want to find a utxo that's not in
    /// the cache, you can use the findtxout method.
    async fn get_tx_out(&self, _tx_id: Txid, _outpoint: u32) -> RpcResult<GetTxOut> {
        Err(Error::NotImplemented)
    }

    /// Stops the florestad process
    ///
    /// This can be used to gracefully stop the florestad process.
    async fn stop(&self) -> RpcResult<String> {
        Err(Error::NotImplemented)
    }

    /// Tells florestad to connect with a peer
    ///
    /// You can use this to connect with a given node, providing it's IP address and port.
    /// If the `v2transport` option is set, we won't retry connecting using the old, unencrypted
    /// P2P protocol.
    #[doc = include_str!("../../../doc/rpc/addnode.md")]
    async fn add_node(
        &self,
        _node: String,
        _command: AddNodeCommand,
        _v2transport: bool,
    ) -> RpcResult<Value> {
        Err(Error::NotImplemented)
    }

    /// Finds an specific utxo in the chain
    ///
    /// You can use this to look for a utxo. If it exists, it will return the amount and
    /// scriptPubKey of this utxo. It returns an empty object if the utxo doesn't exist.
    /// You must have enabled block filters by setting the `blockfilters=1` option.
    async fn find_tx_out(
        &self,
        _tx_id: Txid,
        _outpoint: u32,
        _script: String,
        _height_hint: u32,
    ) -> RpcResult<Value> {
        Err(Error::NotImplemented)
    }

    /// Returns statistics about Floresta's memory usage.
    ///
    /// Returns zeroed values for all runtimes that are not *-gnu or MacOS.
    async fn get_memory_info(&self, _mode: String) -> RpcResult<GetMemInfoRes> {
        Err(Error::NotImplemented)
    }

    /// Returns stats about our RPC server
    async fn get_rpc_info(&self) -> RpcResult<GetRpcInfo> {
        Err(Error::NotImplemented)
    }

    /// Returns for how long florestad has been running, in seconds
    async fn uptime(&self) -> RpcResult<u32> {
        Err(Error::NotImplemented)
    }

    /// Returns a list of all descriptors currently loaded in the wallet
    async fn list_descriptors(&self) -> RpcResult<Vec<String>> {
        Err(Error::NotImplemented)
    }

    /// Sends a ping to all peers, checking if they are still alive
    async fn ping(&self) -> RpcResult<()> {
        Err(Error::NotImplemented)
    }
}
