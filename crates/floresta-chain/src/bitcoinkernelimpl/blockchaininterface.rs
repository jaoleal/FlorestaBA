extern crate std;

use std::ops::Mul;
use std::sync::Arc;

use bitcoin::block::Header as BlockHeader;
use bitcoin::constants::genesis_block;
use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;
use bitcoin::params::Params;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::OutPoint;
use bitcoin::Transaction;
use bitcoinkernel::core::BlockHashExt;
use bitcoinkernel::ChainstateManager;
use bitcoinkernel::Context;
use bitcoinkernel::ProcessBlockResult as KernelProcessBlockResult;
use rustreexo::accumulator::proof::Proof;
use rustreexo::accumulator::stump::Stump;
use spin::RwLock;
use tracing::info;

use crate::prelude::*;
use crate::pruned_utreexo::utxo_data::UtxoData;
use crate::pruned_utreexo::BlockchainInterface;
use crate::pruned_utreexo::UpdatableChainstate;
use crate::BlockConsumer;
use crate::BlockchainError;
use crate::ChainStore;
use crate::DiskBlockHeader;
use crate::FlatChainStore;
use crate::FlatChainStoreConfig;

#[derive(Debug)]
pub enum HeadersOnlyErrs {
    Orphan,
    IDontKnowThisGuy,
}

pub struct HeadersOnly {
    /// Persisted headers storage.
    store: RwLock<FlatChainStore>,
    /// Lets keep these for fast access.
    cache: RwLock<HashMap<BlockHash, (BlockHeader, u32)>>, // ← Wrap in RwLock
    /// How much headers I want to keep in memory
    cache_size: u32,
    /// how many times we flushed.
    flush_count: RwLock<u32>, // ← Wrap in RwLock if it needs to be mutable
}

impl HeadersOnly {
    pub fn new(path: String) -> Self {
        let dbcfg = FlatChainStoreConfig::new(path);
        let store = FlatChainStore::new(dbcfg).unwrap().into();
        let cache = RwLock::new(HashMap::new());
        let cache_size = 0u32; // expose this later
        let flush_count = RwLock::new(0u32);

        let genesis = genesis_block(Params::MAINNET);

        cache
            .write()
            .insert(genesis.header.block_hash(), (genesis.header, 0u32));

        Self {
            store,
            cache,
            cache_size,
            flush_count,
        }
    }
    pub fn get_best_block(&self) -> (BlockHeader, u32) {
        let height = self.get_headers_height();
        info!("{height}");
        self.get_header_by_height(height).unwrap()
    }

    fn get_headers_height(&self) -> u32 {
        let cache_len = self.cache.read().len() as u32 - 1u32;
        if self.cache_size == 0 {
            cache_len
        } else {
            cache_len + (self.flush_count.read().mul(self.cache_size))
        }
    }

    // Now takes &self instead of mut self
    pub fn connect_header(&self, header: BlockHeader) -> Result<(), HeadersOnlyErrs> {
        let prev_hash = header.prev_blockhash;
        let blockhash = header.block_hash();

        // Check if we already have this header
        if self.get_header(&blockhash).is_ok() {
            return Ok(());
        }

        // Get the previous header to determine height
        let (_, prev_height) = self.get_header(&prev_hash)?;
        let new_height = prev_height + 1;

        self.try_flush()?;

        // Now we can mutate through the RwLock
        self.cache.write().insert(blockhash, (header, new_height));
        info! {"cache_header_count{new_height}"}
        info! {"best_block{new_height}"}
        Ok(())
    }

    pub fn try_flush(&self) -> Result<(), HeadersOnlyErrs> {
        // let cache_len = self.cache.read().len();
        // if self.cache_size as usize <= cache_len {
        //     self.flush()?;
        // }
        Ok(())
    }

    pub fn get_header_by_height(&self, height: u32) -> Result<(BlockHeader, u32), HeadersOnlyErrs> {
        let flush_count = *self.flush_count.read();
        let was_flushed = self.cache_size > 0 && (flush_count * self.cache_size) >= height;

        if was_flushed {
            match self.store.read().get_header_by_height(height) {
                Ok(Some(DiskBlockHeader::FullyValid(header, h))) => Ok((header, h)),
                _ => Err(HeadersOnlyErrs::IDontKnowThisGuy),
            }
        } else {
            // Search in cache
            let cache = self.cache.read();
            for (_, (hdr, h)) in cache.iter() {
                if *h == height {
                    return Ok((*hdr, *h));
                }
            }
            Err(HeadersOnlyErrs::IDontKnowThisGuy)
        }
    }

    pub fn get_header(&self, hash: &BlockHash) -> Result<(BlockHeader, u32), HeadersOnlyErrs> {
        // First check cache
        if let Some(header) = self.cache.read().get(hash) {
            return Ok(*header);
        }
        // Then check store
        match self.store.read().get_header(hash) {
            Ok(Some(DiskBlockHeader::FullyValid(header, height))) => Ok((header, height)),
            _ => Err(HeadersOnlyErrs::IDontKnowThisGuy),
        }
    }

    fn flush(&self) -> Result<(), HeadersOnlyErrs> {
        let cache = self.cache.read();
        let mut store = self.store.write();

        for (_, (header, height)) in cache.iter() {
            store
                .save_header(&DiskBlockHeader::FullyValid(*header, *height))
                .unwrap();
        }

        drop(cache);
        drop(store);

        // Clear cache and increment flush count
        self.cache.write().clear();
        *self.flush_count.write() += 1;

        Ok(())
    }
}

/// Bitcoin Kernel-based chainstate implementation
///
/// This implementation delegates consensus validation and UTXO management to
/// libbitcoinkernel, while maintaining Utreexo accumulator state for the
/// Floresta node's needs.
pub struct BitcoinKernelChainstate {
    /// The bitcoin-kernel chainstate manager - handles validation & UTXO state
    chainman: ChainstateManager,
    /// Bitcoin kernel context (must outlive chainman)
    _context: Arc<Context>,
    /// Utreexo accumulator for compact UTXO proofs
    /// (bitcoin-kernel doesn't know about utreexo, so we manage this separately)
    acc: RwLock<Stump>,
    /// Holds a HeadersOnly database that is discarted after IBD.
    ///
    /// Until btck have a header only mode i think thats stricly necessary for floresta because it does headers only.
    headers_only: Option<Arc<HeadersOnly>>,
}

impl BitcoinKernelChainstate {
    pub fn new(
        headers_only: HeadersOnly,
        context: Arc<Context>,
        chainman: ChainstateManager,
        initial_acc: Stump,
    ) -> Self {
        Self {
            chainman,
            _context: context,
            acc: RwLock::new(initial_acc),
            headers_only: Some(Arc::new(headers_only)),
        }
    }
}

impl BlockchainInterface for BitcoinKernelChainstate {
    type Error = BlockchainError;

    fn get_block_hash(&self, height: u32) -> Result<BlockHash, Self::Error> {
        if let Some(headers_chain) = self.headers_only.clone() {
            let (header, _) = headers_chain
                .get_header_by_height(height)
                .map_err(|_| BlockchainError::BlockNotPresent)?;
            return Ok(header.block_hash());
        }

        let chain = self.chainman.active_chain();

        let entry = chain
            .at_height(height as usize)
            .ok_or(BlockchainError::BlockNotPresent)?;

        // Convert bitcoin-kernel BlockHash to bitcoin:: BlockHash
        let hash_bytes = entry.block_hash().to_bytes();

        Ok(BlockHash::from_byte_array(hash_bytes))
    }

    fn get_tx(&self, _txid: &bitcoin::Txid) -> Result<Option<Transaction>, Self::Error> {
        // bitcoin-kernel doesn't have a direct "get transaction by txid" API
        // This would require scanning blocks or maintaining a separate tx index
        todo!("Implement tx lookup - may need separate index")
    }

    fn get_height(&self) -> Result<u32, Self::Error> {
        let chain = self.chainman.active_chain();
        Ok(chain.height() as u32)
    }

    fn broadcast(&self, _tx: &Transaction) -> Result<(), Self::Error> {
        // bitcoin-kernel doesn't handle p2p networking
        // Broadcasting would be handled by Floresta's p2p layer
        todo!("Broadcasting handled by p2p layer, not chainstate")
    }

    fn estimate_fee(&self, _target: usize) -> Result<f64, Self::Error> {
        // Fee estimation would require mempool integration
        // bitcoin-kernel can work with a mempool but that's separate
        todo!("Implement fee estimation")
    }

    fn get_block(&self, hash: &BlockHash) -> Result<Block, Self::Error> {
        // First get the block tree entry
        let kernel_hash = bitcoinkernel::BlockHash::from(hash.to_byte_array());
        let entry = self
            .chainman
            .get_block_tree_entry(&kernel_hash)
            .ok_or(BlockchainError::BlockNotPresent)?;

        // Then read the full block data from disk
        let kernel_block = self.chainman.read_block_data(&entry).unwrap();
        // Convert kernel Block to bitcoin::Block
        let block_bytes = kernel_block.consensus_encode().unwrap();
        Ok(bitcoin::consensus::deserialize(&block_bytes).unwrap())
    }

    fn get_best_block(&self) -> Result<(u32, BlockHash), Self::Error> {
        if let Some(headers_chain) = self.headers_only.clone() {
            let (header, height) = headers_chain.get_best_block();
            return Ok((height, header.block_hash()));
        }
        let tip_block = self.chainman.active_chain().tip();
        let height = tip_block.height() as u32;
        let hash_bytes = tip_block.block_hash().to_bytes();
        let hash = BlockHash::from_slice(&hash_bytes).expect("Valid block hash");
        Ok((height, hash))
    }

    fn get_block_header(&self, hash: &BlockHash) -> Result<BlockHeader, Self::Error> {
        // TODO: bitcoin-kernel might have a more efficient header-only API
        let block = self.get_block(hash)?;
        Ok(block.header)
    }

    fn subscribe(&self, consumer: Arc<dyn BlockConsumer>) {
        // AAAAAAAAAAAAAAAAAA WHATEVER
    }

    fn is_in_ibd(&self) -> bool {
        self.headers_only.is_some()
    }

    fn get_unbroadcasted(&self) -> Vec<Transaction> {
        // This would be tracked separately in the p2p layer
        Vec::new()
    }

    fn is_coinbase_mature(&self, height: u32, _block: BlockHash) -> Result<bool, Self::Error> {
        let current_height = self.get_height()?;
        // Bitcoin coinbase maturity is 100 blocks
        Ok(current_height >= height + 100)
    }

    fn get_block_locator(&self) -> Result<Vec<BlockHash>, Self::Error> {
        // Build a block locator from the active chain
        let chain = self.chainman.active_chain();
        let mut locator = Vec::new();
        let mut step = 1;
        let mut height = chain.height() as usize;

        while height > 0 {
            if let Some(entry) = chain.at_height(height) {
                let hash_bytes = entry.block_hash().to_bytes();
                locator.push(BlockHash::from_slice(&hash_bytes).expect("Valid hash"));
            }

            if locator.len() >= 10 {
                step *= 2;
            }
            height = height.saturating_sub(step);
        }

        // Always include genesis
        if let Some(genesis) = chain.at_height(0) {
            let hash_bytes = genesis.block_hash().to_bytes();
            locator.push(BlockHash::from_slice(&hash_bytes).expect("Valid hash"));
        }

        Ok(locator)
    }

    fn get_block_locator_for_tip(
        &self,
        _tip: BlockHash,
    ) -> Result<Vec<BlockHash>, BlockchainError> {
        // TODO: Implement for specific tip (would need to traverse from that point)
        self.get_block_locator()
    }

    fn get_validation_index(&self) -> Result<u32, Self::Error> {
        // In bitcoin-kernel, validation index == chain tip
        self.get_height()
    }

    fn get_block_height(&self, hash: &BlockHash) -> Result<Option<u32>, Self::Error> {
        let kernel_hash = bitcoinkernel::BlockHash::from(hash.to_byte_array());
        let entry = self.chainman.get_block_tree_entry(&kernel_hash);
        Ok(entry.map(|e| e.height() as u32))
    }

    fn update_acc(
        &self,
        acc: Stump,
        _block: Block,
        _height: u32,
        _proof: Proof,
        _del_hashes: Vec<sha256::Hash>,
    ) -> Result<Stump, Self::Error> {
        *self.acc.write() = acc.clone();
        Ok(acc)
    }

    fn get_chain_tips(&self) -> Result<Vec<BlockHash>, Self::Error> {
        let (_, tip_hash) = self.get_best_block()?;
        Ok(vec![tip_hash])
    }

    fn validate_block(
        &self,
        block: &Block,
        _proof: Proof,
        _inputs: HashMap<OutPoint, UtxoData>,
        _del_hashes: Vec<sha256::Hash>,
        _acc: Stump,
    ) -> Result<(), Self::Error> {
        // Convert bitcoin:: Block to kernel Block
        let block_bytes = bitcoin::consensus::serialize(block);
        let kernel_block = bitcoinkernel::Block::new(&block_bytes).unwrap();

        // Let bitcoin-kernel do the heavy lifting of validation!
        // It checks consensus rules, POW, connects to UTXO set, etc.
        match self.chainman.process_block(&kernel_block) {
            KernelProcessBlockResult::NewBlock | KernelProcessBlockResult::Duplicate => Ok(()),
            KernelProcessBlockResult::Rejected => Err(BlockchainError::OrphanOrInvalidBlock),
        }
    }

    fn get_fork_point(&self, _block: BlockHash) -> Result<BlockHash, Self::Error> {
        todo!("Implement fork point detection")
    }

    fn get_params(&self) -> bitcoin::params::Params {
        // Would need to map from kernel's ChainParams to bitcoin::params:: Params
        todo!("Map chain params from kernel")
    }

    fn acc(&self) -> Stump {
        self.acc.read().clone()
    }
}

impl UpdatableChainstate for BitcoinKernelChainstate {
    fn connect_block(
        &self,
        block: &Block,
        proof: Proof,
        inputs: HashMap<OutPoint, UtxoData>,
        del_hashes: Vec<sha256::Hash>,
    ) -> Result<u32, BlockchainError> {
        let hash_bytes = bitcoin::consensus::serialize(&block.header.prev_blockhash);
        let block_hash = bitcoinkernel::BlockHash::new(&hash_bytes).unwrap();

        let height = match self.chainman.get_block_tree_entry(&block_hash) {
            Some(entry) => {
                //we have the previous block so it can extend the tip.
                entry.height() as u32
            }
            None => {
                // feijoada
                panic!()
            }
        };

        // Convert bitcoin:: Block to kernel Block
        let block_bytes = bitcoin::consensus::serialize(block);
        let kernel_block = bitcoinkernel::Block::new(&block_bytes).unwrap();

        let _insert = self.chainman.process_block(&kernel_block);

        info!(
            "New tip! hash={} height={height} tx_count={}",
            block.block_hash(),
            block.txdata.len()
        );

        #[cfg(feature = "metrics")]
        metrics::get_metrics().block_height.set(height.into());

        if !self.is_in_ibd() || height % 100_000 == 0 {
            self.flush()?;
        }

        Ok(height)
    }

    fn switch_chain(&self, _new_tip: BlockHash) -> Result<(), BlockchainError> {
        todo!()
    }

    fn accept_header(&self, header: BlockHeader) -> Result<(), BlockchainError> {
        if let Some(ref header_only) = self.headers_only {
            header_only
                .connect_header(header)
                .map_err(|_| BlockchainError::OrphanOrInvalidBlock)?;
            return Ok(()); // ← Don't forget to return Ok on success!
        }
        Err(BlockchainError::ChainNotInitialized)
    }
    fn handle_transaction(&self) -> Result<(), BlockchainError> {
        todo!()
    }

    fn flush(&self) -> Result<(), BlockchainError> {
        todo!()
    }

    fn toggle_ibd(&self, is_ibd: bool) {
        todo!()
    }

    fn invalidate_block(&self, block: BlockHash) -> Result<(), BlockchainError> {
        todo!()
    }

    fn mark_block_as_valid(&self, block: BlockHash) -> Result<(), BlockchainError> {
        todo!()
    }

    fn get_root_hashes(&self) -> Vec<rustreexo::accumulator::node_hash::BitcoinNodeHash> {
        todo!()
    }

    fn get_partial_chain(
        &self,
        initial_height: u32,
        final_height: u32,
        acc: Stump,
    ) -> Result<crate::pruned_utreexo::partial_chain::PartialChainState, BlockchainError> {
        unimplemented!("UTXO set based chainstates cant have partial chains, i guess.")
    }

    fn mark_chain_as_assumed(&self, acc: Stump, tip: BlockHash) -> Result<bool, BlockchainError> {
        unimplemented!("IDK, i have to read more.")
    }

    fn get_acc(&self) -> Stump {
        self.acc()
    }
}
