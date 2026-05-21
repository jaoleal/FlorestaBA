// SPDX-License-Identifier: MIT OR Apache-2.0

use core::error::Error;

use bitcoin::block::Header;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::Work;
use floresta_common::bhash;
use floresta_common::prelude::Box;
use floresta_common::prelude::String;
use floresta_common::prelude::Vec;

use crate::BlockchainInterface;

const MEDIAN_TIME_PAST_BLOCK_COUNT: usize = 11;

pub trait Bip30UnspendableExt {
    /// Returns true if the coinbase output in this block is BIP-30 unspendable.
    fn is_bip30_unspendable(&self, height: u32) -> bool;
}

impl Bip30UnspendableExt for Block {
    fn is_bip30_unspendable(&self, height: u32) -> bool {
        let bhash_91722 =
            bhash!("00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e");
        let bhash_91812 =
            bhash!("00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f");

        match height {
            91722 => self.block_hash() == bhash_91722,
            91812 => self.block_hash() == bhash_91812,
            _ => false,
        }
    }
}

/// Provides additional methods for working with [`Header`] objects,
pub trait HeaderExt {
    /// Calculates the Median Time Past (MTP) for the block.
    fn calculate_median_time_past(
        &self,
        chain: &impl BlockchainInterface,
    ) -> Result<u32, HeaderExtError>;

    /// Calculates the total accumulated chain work up to the current block.
    fn calculate_chain_work(
        &self,
        chain: &impl BlockchainInterface,
    ) -> Result<Work, HeaderExtError>;

    /// Retrieves the hash of the next block in the chain, if it exists.
    ///
    /// Returns `None` if the block is the tip of the chain.
    fn get_next_block_hash(
        &self,
        chain: &impl BlockchainInterface,
    ) -> Result<Option<BlockHash>, HeaderExtError>;

    /// Retrieves the header of the previous block in the chain.
    fn get_previous_block_header(
        &self,
        chain: &impl BlockchainInterface,
    ) -> Result<Header, HeaderExtError>;

    /// Returns the block's "bits" field as a hexadecimal string.
    fn get_bits_hex(&self) -> String;

    /// Calculates the number of confirmations for the current block.
    fn get_confirmations(&self, chain: &impl BlockchainInterface) -> Result<u32, HeaderExtError>;

    /// Returns the block's difficulty as a floating-point number.
    fn get_difficulty(&self) -> f64;

    /// Retrieves the height of the block in the blockchain.
    fn get_height(&self, chain: &impl BlockchainInterface) -> Result<u32, HeaderExtError>;

    /// Returns the block's target as a hexadecimal string.
    ///
    /// In `rust-bitcoin`, calling `to_string` on `Target` returns the value in decimal
    /// because it wraps a `U256`, which defaults to decimal string conversion. However,
    /// Bitcoin Core represents targets in hexadecimal. This method ensures the target
    /// is returned in hexadecimal format, consistent with Bitcoin Core.
    fn get_target_hex(&self) -> String;

    /// Returns the block's version as a hexadecimal string.
    ///
    /// Bitcoin Core represents the block version as a 32-bit unsigned integer (`u32`)
    /// in hexadecimal format. This method ensures the version is returned as a
    /// properly formatted hexadecimal string, consistent with Bitcoin Core.
    fn get_version_hex(&self) -> String;
}

/// Errors that can occur when using the `HeaderExt` methods.
#[derive(Debug)]
pub enum HeaderExtError {
    /// An error related to the blockchain interface, wrapping the actual error.
    Chain(Box<dyn Error + Send + Sync>),

    /// Indicates that the block could not be found in the blockchain.
    BlockNotFound,

    /// You got an overflow while calculating the chain work.
    ChainWorkOverflow,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// The possible states of a BIP 9 soft-fork deployment.
pub enum ThresholdState {
    /// The deployment is not yet active and has not been signaled for.
    Defined,

    /// MTP has passed the deployment's start_time; miners may now signal.
    Started,

    /// Enough miners signaled in a retarget period; activation is locked in.
    LockedIn,

    /// The deployment is active and its rules are enforced.
    Active,

    /// MTP passed the timeout without reaching threshold; deployment failed.
    Failed,
}

/// How a deployment's start and timeout are measured.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ActivationThreshold {
    /// Classic BIP 9: start and timeout are compared against median-time-past.
    Time { start_time: u32, timeout: u32 },

    /// Speedy Trial (BIP 9 variant): start and timeout are block heights,
    /// with an optional minimum activation height gate after lock-in.
    Height {
        start_height: u32,
        timeout_height: u32,
        min_activation_height: u32,
    },
}

/// Defines a BIP 9 soft-fork deployment.
pub struct Bip9Deployment {
    /// Human-readable name for the deployment (e.g. "csv", "segwit", "taproot").
    pub name: &'static str,

    /// The version bit used for signaling (0..=28).
    pub bit: u8,

    /// How this deployment's start/timeout are measured.
    pub activation: ActivationThreshold,

    /// Signaling window size. If `None`, uses the network default
    /// (`params.miner_confirmation_window`, typically 2016).
    pub period: Option<u32>,

    /// Number of signaling blocks required in a window. If `None`, uses the
    /// network default (`params.rule_change_activation_threshold`).
    pub threshold: Option<u32>,
}

/// Extension trait for BIP 9 version bits soft-fork detection on block headers.
pub trait Bip9Ext {
    /// Returns `true` if this block's nVersion signals for the given bit
    /// according to BIP 9 rules (top 3 bits are `001` and the specified bit is set).
    fn is_signaling(&self, bit: u8) -> bool;

    /// Computes the BIP 9 deployment state at this block's position in the chain.
    ///
    /// The state machine is evaluated at retarget period boundaries
    /// (`miner_confirmation_window` blocks). Blocks between boundaries inherit
    /// the state from the previous boundary.
    fn bip9_state(
        &self,
        deployment: &Bip9Deployment,
        chain: &impl BlockchainInterface,
    ) -> Result<ThresholdState, HeaderExtError>;
}

impl HeaderExt for Header {
    fn calculate_median_time_past(
        &self,
        chain: &impl BlockchainInterface,
    ) -> Result<u32, HeaderExtError> {
        let mut block_timestamps = Vec::with_capacity(MEDIAN_TIME_PAST_BLOCK_COUNT);
        let mut current_header = *self;
        for _ in 0..MEDIAN_TIME_PAST_BLOCK_COUNT {
            block_timestamps.push(current_header.time);
            let Ok(prev_header) = current_header.get_previous_block_header(chain) else {
                break;
            };
            current_header = prev_header;
        }
        block_timestamps.sort();
        let median_time_past = block_timestamps[block_timestamps.len() / 2];

        Ok(median_time_past)
    }

    fn calculate_chain_work(
        &self,
        chain: &impl BlockchainInterface,
    ) -> Result<Work, HeaderExtError> {
        chain
            .get_work(self.block_hash())
            .map_err(|err| HeaderExtError::Chain(Box::new(err)))
    }

    fn get_next_block_hash(
        &self,
        chain: &impl BlockchainInterface,
    ) -> Result<Option<BlockHash>, HeaderExtError> {
        let height = self.get_height(chain)?;

        // If obtaining the next block hash fails, treat it as "no next block" and return Ok(None)
        match chain.get_block_hash(height + 1) {
            Ok(opt_hash) => Ok(Some(opt_hash)),
            Err(_) => Ok(None),
        }
    }

    fn get_previous_block_header(
        &self,
        chain: &impl BlockchainInterface,
    ) -> Result<Header, HeaderExtError> {
        let prev_header = chain
            .get_block_header(&self.prev_blockhash)
            .map_err(|e| HeaderExtError::Chain(Box::new(e)))?;
        Ok(prev_header)
    }

    fn get_bits_hex(&self) -> String {
        serialize_hex(&self.bits.to_consensus().to_be())
    }

    fn get_confirmations(&self, chain: &impl BlockchainInterface) -> Result<u32, HeaderExtError> {
        let height = self.get_height(chain)?;

        let chain_height = chain
            .get_height()
            .map_err(|e| HeaderExtError::Chain(Box::new(e)))?;

        Ok(chain_height - height + 1)
    }

    fn get_difficulty(&self) -> f64 {
        self.difficulty_float()
    }

    fn get_height(&self, chain: &impl BlockchainInterface) -> Result<u32, HeaderExtError> {
        let height = match chain.get_block_height(&self.block_hash()) {
            Ok(Some(height)) => height,
            Ok(None) => return Err(HeaderExtError::BlockNotFound),
            Err(e) => return Err(HeaderExtError::Chain(Box::new(e))),
        };

        Ok(height)
    }

    fn get_target_hex(&self) -> String {
        serialize_hex(&self.target().to_be_bytes())
    }

    fn get_version_hex(&self) -> String {
        serialize_hex(&(self.version.to_consensus() as u32).to_be())
    }
}

impl Bip9Ext for Header {
    fn is_signaling(&self, bit: u8) -> bool {
        self.version.is_signalling_soft_fork(bit)
    }

    fn bip9_state(
        &self,
        deployment: &Bip9Deployment,
        chain: &impl BlockchainInterface,
    ) -> Result<ThresholdState, HeaderExtError> {
        let params = chain.get_params();
        let window = deployment
            .period
            .unwrap_or(params.miner_confirmation_window);
        let threshold = deployment
            .threshold
            .unwrap_or(params.rule_change_activation_threshold);

        let height = self.get_height(chain)?;

        // Genesis block is always Defined.
        if height == 0 {
            return Ok(ThresholdState::Defined);
        }

        // Find the start of this block's retarget period.
        let period_start = height - (height % window);

        // Walk forward from Defined, transitioning at each boundary.
        let mut state = ThresholdState::Defined;

        for period_boundary in (window..=period_start).step_by(window as usize) {
            // Resolve the activation metric used for start/timeout checks.
            // For time-based deployments this is MTP; for height-based it is
            // the period boundary height itself.
            let (activation_metric, start, timeout) = match deployment.activation {
                ActivationThreshold::Time {
                    start_time,
                    timeout,
                } => {
                    let prev_hash = chain
                        .get_block_hash(period_boundary - 1)
                        .map_err(|e| HeaderExtError::Chain(Box::new(e)))?;
                    let prev_header = chain
                        .get_block_header(&prev_hash)
                        .map_err(|e| HeaderExtError::Chain(Box::new(e)))?;
                    let mtp = prev_header.calculate_median_time_past(chain)?;
                    (mtp, start_time, timeout)
                }
                ActivationThreshold::Height {
                    start_height,
                    timeout_height,
                    ..
                } => (period_boundary, start_height, timeout_height),
            };

            state = match state {
                ThresholdState::Defined => {
                    if activation_metric >= timeout {
                        ThresholdState::Failed
                    } else if activation_metric >= start {
                        ThresholdState::Started
                    } else {
                        ThresholdState::Defined
                    }
                }
                ThresholdState::Started => {
                    if activation_metric >= timeout {
                        ThresholdState::Failed
                    } else {
                        // Count signaling blocks in the previous period.
                        let count_start = period_boundary - window;
                        let mut count = 0u32;
                        for block_h in count_start..period_boundary {
                            let hash = chain
                                .get_block_hash(block_h)
                                .map_err(|e| HeaderExtError::Chain(Box::new(e)))?;
                            let hdr = chain
                                .get_block_header(&hash)
                                .map_err(|e| HeaderExtError::Chain(Box::new(e)))?;
                            if hdr.is_signaling(deployment.bit) {
                                count += 1;
                            }
                        }
                        if count >= threshold {
                            ThresholdState::LockedIn
                        } else {
                            ThresholdState::Started
                        }
                    }
                }
                ThresholdState::LockedIn => {
                    // For Speedy Trial, activation is gated on min_activation_height.
                    if let ActivationThreshold::Height {
                        min_activation_height,
                        ..
                    } = deployment.activation
                    {
                        if period_boundary < min_activation_height {
                            ThresholdState::LockedIn
                        } else {
                            ThresholdState::Active
                        }
                    } else {
                        ThresholdState::Active
                    }
                }
                ThresholdState::Active => ThresholdState::Active,
                ThresholdState::Failed => ThresholdState::Failed,
            };
        }

        Ok(state)
    }
}

impl From<ChainWorkOverflow> for HeaderExtError {
    fn from(_: ChainWorkOverflow) -> Self {
        Self::ChainWorkOverflow
    }
}

#[derive(Debug, PartialEq)]
pub struct ChainWorkOverflow;

pub trait WorkExt {
    /// Multiplies the Work by a u32 factor, returning an error if overflow occurs.
    fn multiply_work_by_u32(self, factor: u32) -> Result<Work, ChainWorkOverflow>;

    /// Returns the hexadecimal string representation of the Work.
    ///
    /// In `rust-bitcoin`, calling `to_string` on `Work` returns the value in decimal
    /// because it wraps a `U256`, which defaults to decimal string conversion. However,
    /// Bitcoin Core represents targets in hexadecimal. This method ensures the `Work``
    /// is returned in hexadecimal format, consistent with Bitcoin Core.
    fn to_string_hex(&self) -> String;
}

impl WorkExt for Work {
    fn multiply_work_by_u32(self, factor: u32) -> Result<Work, ChainWorkOverflow> {
        if factor == 0 {
            return Ok(Work::from_be_bytes([0u8; 32]));
        }

        if factor == 1 {
            return Ok(self);
        }

        // Convert Work to little-endian bytes for easier manipulation (least significant byte first)
        let work_bytes = self.to_le_bytes();
        let mut carry_high: u64 = 0;
        let mut result_bytes = [0u8; 32];
        let word_size = 4_usize;

        // Multiply each 4-byte word (u32) of Work by the factor, propagating carry
        // Work is processed in little-endian order (from least significant byte to most significant byte),
        // but result is stored in big-endian
        let by_chunks: Vec<u32> = work_bytes
            .chunks_exact(word_size)
            .map(|chunk| {
                let mut array = [0u8; 4];
                array.copy_from_slice(chunk);
                u32::from_le_bytes(array)
            })
            .collect();

        for (word_index, word) in by_chunks.iter().enumerate() {
            // Multiply the word by factor and add carry from previous step
            // Use u64 to avoid overflow during multiplication
            let product: u64 = (*word as u64) * (factor as u64) + carry_high;
            carry_high = product >> 32;

            // Store the low 32 bits of the product in the result
            // Result is built in big-endian order, so calculate the index accordingly
            let byte_index = by_chunks.len() - word_index;
            result_bytes[(byte_index - 1) * word_size..byte_index * word_size]
                .copy_from_slice(&(product as u32).to_be_bytes());
        }

        if carry_high > 0 {
            return Err(ChainWorkOverflow);
        }

        Ok(Work::from_be_bytes(result_bytes))
    }

    fn to_string_hex(&self) -> String {
        serialize_hex(&self.to_be_bytes())
    }
}

#[cfg(test)]
mod tests {
    use core::fmt;
    use core::fmt::Display;
    use core::fmt::Formatter;
    use std::collections::HashMap;
    use std::sync::Arc;

    use bitcoin::block::Header;
    use bitcoin::block::Version;
    use bitcoin::consensus::encode::deserialize_hex;
    use bitcoin::hashes::sha256::Hash as Sha256Hash;
    use bitcoin::params::Params;
    use bitcoin::Block;
    use bitcoin::BlockHash;
    use bitcoin::OutPoint;
    use bitcoin::Transaction;
    use bitcoin::Txid;
    use rustreexo::proof::Proof;
    use rustreexo::stump::Stump;

    use super::*;
    use crate::BlockConsumer;
    use crate::BlockchainError;
    use crate::UtxoData;

    #[derive(Debug)]
    pub enum MockBlockchainError {
        NotFound,
    }

    impl Display for MockBlockchainError {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "MockBlockchainError")
        }
    }

    impl core::error::Error for MockBlockchainError {}

    pub struct MockBlockchainInterface {
        pub headers: HashMap<BlockHash, Header>,
        pub heights: HashMap<BlockHash, u32>,
        pub chain_height: u32,
    }

    impl MockBlockchainInterface {
        pub fn new() -> Self {
            Self {
                headers: HashMap::new(),
                heights: HashMap::new(),
                chain_height: 0,
            }
        }

        pub fn add_block(&mut self, hash: BlockHash, header: Header, height: u32) {
            self.headers.insert(hash, header);
            self.heights.insert(hash, height);
            self.chain_height = self.chain_height.max(height);
        }
    }

    impl BlockchainInterface for MockBlockchainInterface {
        type Error = MockBlockchainError;

        fn get_block_header(&self, hash: &BlockHash) -> Result<Header, Self::Error> {
            self.headers
                .get(hash)
                .cloned()
                .ok_or(MockBlockchainError::NotFound)
        }

        fn get_block_hash(&self, height: u32) -> Result<BlockHash, Self::Error> {
            self.heights
                .iter()
                .find(|(_, &h)| h == height)
                .map(|(hash, _)| *hash)
                .ok_or(MockBlockchainError::NotFound)
        }

        fn get_block_height(&self, hash: &BlockHash) -> Result<Option<u32>, Self::Error> {
            Ok(self.heights.get(hash).cloned())
        }

        fn get_height(&self) -> Result<u32, Self::Error> {
            Ok(self.chain_height)
        }

        fn get_work(&self, _tip: BlockHash) -> Result<Work, Self::Error> {
            let work_hex = "00000000000000000000000000000000000000000000000000000bb80bb80bb8";
            Ok(Work::from_hex(&format!("0x{work_hex}")).expect("hardcoded work"))
        }

        fn get_tx(&self, _: &Txid) -> Result<Option<Transaction>, Self::Error> {
            unimplemented!()
        }

        fn estimate_fee(&self, _: usize) -> Result<f64, Self::Error> {
            unimplemented!()
        }

        fn get_block(&self, _: &BlockHash) -> Result<Block, Self::Error> {
            unimplemented!()
        }

        fn get_best_block(&self) -> Result<(u32, BlockHash), Self::Error> {
            unimplemented!()
        }

        fn subscribe(&self, _: Arc<dyn BlockConsumer>) {
            unimplemented!()
        }

        fn is_in_ibd(&self) -> bool {
            unimplemented!()
        }

        fn is_coinbase_mature(&self, _: u32, _: BlockHash) -> Result<bool, Self::Error> {
            unimplemented!()
        }

        fn get_block_locator(&self) -> Result<Vec<BlockHash>, Self::Error> {
            unimplemented!()
        }

        fn get_block_locator_for_tip(
            &self,
            _: BlockHash,
        ) -> Result<Vec<BlockHash>, BlockchainError> {
            unimplemented!()
        }

        fn get_validation_index(&self) -> Result<u32, Self::Error> {
            unimplemented!()
        }

        fn update_acc(
            &self,
            _: Stump,
            _: &Block,
            _: u32,
            _: Proof,
            _: Vec<Sha256Hash>,
        ) -> Result<Stump, Self::Error> {
            unimplemented!()
        }

        fn get_chain_tips(&self) -> Result<Vec<BlockHash>, Self::Error> {
            unimplemented!()
        }

        fn validate_block(
            &self,
            _: &Block,
            _: Proof,
            _: HashMap<OutPoint, UtxoData>,
            _: Vec<Sha256Hash>,
            _: Stump,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        fn get_fork_point(&self, _: BlockHash) -> Result<BlockHash, Self::Error> {
            unimplemented!()
        }

        fn get_params(&self) -> Params {
            Params::new(bitcoin::Network::Regtest)
        }

        fn acc(&self) -> Stump {
            unimplemented!()
        }
    }

    fn get_genesis_header() -> Header {
        let genesis_header = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
        let header: Header = deserialize_hex(genesis_header).expect("Failed to deserialize header");
        header
    }

    fn get_chain_and_headers(height: u32) -> (MockBlockchainInterface, Vec<Header>) {
        let mut mock_chain = MockBlockchainInterface::new();

        let mut headers = vec![];
        let mut prev_blockhash = get_genesis_header().block_hash();
        let genesis_header = get_genesis_header();
        mock_chain.add_block(prev_blockhash, genesis_header, 0);
        headers.push(genesis_header);

        for i in 1..height {
            let header = Header {
                time: 1231006505 + i * 600,
                prev_blockhash,
                ..genesis_header
            };
            headers.push(header);
            let hash = header.block_hash();
            mock_chain.add_block(hash, header, i);
            prev_blockhash = header.block_hash();
        }

        (mock_chain, headers)
    }

    /// Builds a mock chain where a callback controls the version of each block header.
    fn get_chain_with_versions(
        height: u32,
        version_fn: impl Fn(u32) -> Version,
    ) -> (MockBlockchainInterface, Vec<Header>) {
        let mut mock_chain = MockBlockchainInterface::new();
        let genesis_header = get_genesis_header();
        let mut headers = vec![];
        let mut prev_blockhash = genesis_header.block_hash();
        mock_chain.add_block(prev_blockhash, genesis_header, 0);
        headers.push(genesis_header);

        for i in 1..height {
            let header = Header {
                version: version_fn(i),
                time: 1231006505 + i * 600,
                prev_blockhash,
                ..genesis_header
            };
            headers.push(header);
            let hash = header.block_hash();
            mock_chain.add_block(hash, header, i);
            prev_blockhash = hash;
        }

        (mock_chain, headers)
    }

    #[test]
    fn test_calculate_median_time_past_more_than_11_blocks() {
        let (mock_chain, headers) = get_chain_and_headers(21);

        let median_header = headers[headers.len() - 1];
        let mtp = median_header
            .calculate_median_time_past(&mock_chain)
            .expect("Failed to calculate MTP");

        let mut times = headers
            .iter()
            .rev()
            .take(11)
            .map(|h| h.time)
            .collect::<Vec<_>>();
        times.sort();
        let expected_mtp = times[times.len() / 2];

        assert_eq!(mtp, expected_mtp);
    }

    #[test]
    fn test_calculate_median_time_past_less_than_11_blocks() {
        let (mock_chain, headers) = get_chain_and_headers(7);

        let median_header = headers[headers.len() - 1];
        let mtp = median_header
            .calculate_median_time_past(&mock_chain)
            .expect("Failed to calculate MTP");

        let mut times = headers.iter().map(|h| h.time).collect::<Vec<_>>();
        times.sort();
        let expected_mtp = times[times.len() / 2];

        assert_eq!(mtp, expected_mtp);
    }

    #[test]
    fn test_calculate_median_time_past_genesis_only() {
        let (mock_chain, headers) = get_chain_and_headers(1);

        // Test the MTP calculation
        let median_header = headers[0];
        let mtp = median_header
            .calculate_median_time_past(&mock_chain)
            .expect("Failed to calculate MTP");

        let expected_mtp = headers[0].time;

        assert_eq!(mtp, expected_mtp);
    }

    #[test]
    fn test_get_next_block_hash() {
        let (mock_chain, headers) = get_chain_and_headers(5);

        let header = headers[2];
        let next_hash = header
            .get_next_block_hash(&mock_chain)
            .expect("Failed to get next block hash")
            .expect("Next block hash is None");

        let expected_hash = headers[3].block_hash();

        assert_eq!(next_hash, expected_hash);

        let last_header = headers[headers.len() - 1];
        let next_hash = last_header
            .get_next_block_hash(&mock_chain)
            .expect("Failed to get next block hash");

        assert!(next_hash.is_none());
    }

    #[test]
    fn test_get_bits() {
        let header = get_genesis_header();
        let bits_hex = header.get_bits_hex();
        assert_eq!(bits_hex, "1d00ffff");
    }

    #[test]
    fn test_get_confirmations() {
        let (mock_chain, headers) = get_chain_and_headers(5);

        let header = headers[2];
        let confirmations = header
            .get_confirmations(&mock_chain)
            .expect("Failed to get confirmations");

        let expected_confirmations = headers.len() - 2;

        assert_eq!(confirmations, expected_confirmations as u32);
    }

    #[test]
    fn test_get_difficulty() {
        let header = get_genesis_header();
        let difficulty = header.get_difficulty();
        assert_eq!(difficulty, 1.0);
    }

    #[test]
    fn test_get_height() {
        let (mock_chain, headers) = get_chain_and_headers(5);
        let height_expected = 3;

        let header = headers[height_expected];
        let height = header
            .get_height(&mock_chain)
            .expect("Failed to get block height");

        assert_eq!(height, height_expected as u32);

        let mut header_missing = headers[0];
        header_missing.nonce = 0;
        let result = header_missing.get_height(&mock_chain);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_target() {
        let header = get_genesis_header();
        let target_hex = header.get_target_hex();
        assert_eq!(
            target_hex,
            "00000000ffff0000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_get_version_hex() {
        let header = get_genesis_header();
        let version_hex = header.get_version_hex();
        assert_eq!(version_hex, "00000001");
    }

    #[test]
    fn test_multiply_work_by_u32_success() {
        let work_bytes: [u8; 32] = [
            0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0,
            0, 0, 4,
        ];
        let work = Work::from_be_bytes(work_bytes);
        let factor = 2;

        let result = work.multiply_work_by_u32(factor).unwrap();

        let expected_bytes: [u8; 32] = [
            0, 0, 0, 6, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0,
            0, 0, 8,
        ];
        let expected = Work::from_be_bytes(expected_bytes);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_multiply_work_by_u32_overflow() {
        let work_bytes: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
        ];
        let work = Work::from_be_bytes(work_bytes);
        let factor = u32::MAX;

        let result = work.multiply_work_by_u32(factor);

        assert_eq!(result, Err(ChainWorkOverflow));
    }

    #[test]
    fn test_calculate_chain_work() {
        let (mock_chain, headers) = get_chain_and_headers(3000);
        let header = headers[headers.len() - 1];

        let work = header
            .calculate_chain_work(&mock_chain)
            .expect("Failed to calculate chain work");

        let expected_hex_string =
            "00000000000000000000000000000000000000000000000000000bb80bb80bb8";
        let expected_work = Work::from_hex(&format!("0x{expected_hex_string}")).unwrap();

        assert_eq!(work.to_string_hex(), expected_hex_string);
        assert_eq!(work, expected_work);
    }

    // Regtest params: window = 144, threshold = 108 (75%).
    // Genesis timestamp in tests: 1231006505.
    // Block i timestamp: 1231006505 + i * 600.
    fn test_deployment(bit: u8, start_time: u32, timeout: u32) -> Bip9Deployment {
        Bip9Deployment {
            name: "testdeploy",
            bit,
            activation: ActivationThreshold::Time {
                start_time,
                timeout,
            },
            period: None,
            threshold: None,
        }
    }

    #[test]
    fn test_is_signaling_bip9() {
        let genesis = get_genesis_header();

        // BIP9 base + bit 0 set
        let mut signaling = genesis;
        signaling.version = Version::from_consensus(0x20000001);
        assert!(signaling.is_signaling(0));
        assert!(!signaling.is_signaling(1));

        // BIP9 base, no bits set
        let mut no_signal = genesis;
        no_signal.version = Version::from_consensus(0x20000000);
        assert!(!no_signal.is_signaling(0));

        // Old-style version (no BIP9 top bits)
        assert!(!genesis.is_signaling(0));
    }

    #[test]
    fn test_bip9_state() {
        // Regtest params: window = 144, threshold = 108 (75%).
        // One chain of 450 signaling blocks covers Defined -> Started -> LockedIn -> Active.
        let (signaling_chain, signaling_headers) =
            get_chain_with_versions(450, |_| Version::from_consensus(0x20000001));
        let deployment = test_deployment(0, 0, u32::MAX);

        // Genesis is always Defined.
        assert_eq!(
            signaling_headers[0]
                .bip9_state(&deployment, &signaling_chain)
                .expect("genesis"),
            ThresholdState::Defined,
        );

        // Before first boundary (height 143) — inherits Defined from genesis.
        assert_eq!(
            signaling_headers[143]
                .bip9_state(&deployment, &signaling_chain)
                .expect("before boundary"),
            ThresholdState::Defined,
        );

        // First boundary (height 144): Defined -> Started (MTP > start_time=0).
        assert_eq!(
            signaling_headers[144]
                .bip9_state(&deployment, &signaling_chain)
                .expect("at boundary"),
            ThresholdState::Started,
        );

        // Boundary 288: count [144..287] = 144 >= 108 -> LockedIn.
        assert_eq!(
            signaling_headers[289]
                .bip9_state(&deployment, &signaling_chain)
                .expect("locked in"),
            ThresholdState::LockedIn,
        );

        // Boundary 432: LockedIn -> Active.
        assert_eq!(
            signaling_headers[440]
                .bip9_state(&deployment, &signaling_chain)
                .expect("active"),
            ThresholdState::Active,
        );

        // Same chain, but a deployment whose start_time hasn't arrived — stays Defined.
        let future_deployment = test_deployment(0, u32::MAX - 1, u32::MAX);
        assert_eq!(
            signaling_headers[200]
                .bip9_state(&future_deployment, &signaling_chain)
                .expect("defined before start"),
            ThresholdState::Defined,
        );

        // Defined -> Failed: both start_time and timeout already passed.
        let expired_deployment = test_deployment(0, 100, 200);
        assert_eq!(
            signaling_headers[200]
                .bip9_state(&expired_deployment, &signaling_chain)
                .expect("failed from defined"),
            ThresholdState::Failed,
        );

        // Started -> Failed: no signaling chain, timeout reached after Started.
        let (no_signal_chain, no_signal_headers) = get_chain_and_headers(300);
        let mtp_at_143 = 1231006505 + 138 * 600;
        let timeout_deployment = test_deployment(0, 0, mtp_at_143 + 1);
        assert_eq!(
            no_signal_headers[299]
                .bip9_state(&timeout_deployment, &no_signal_chain)
                .expect("failed from started"),
            ThresholdState::Failed,
        );

        // Threshold not met: ~50% signaling (72/144) stays Started.
        let (half_chain, half_headers) = get_chain_with_versions(300, |i| {
            if i % 2 == 0 {
                Version::from_consensus(0x20000001)
            } else {
                Version::from_consensus(0x20000000)
            }
        });

        assert_eq!(
            half_headers[289]
                .bip9_state(&deployment, &half_chain)
                .expect("threshold not met"),
            ThresholdState::Started,
        );

        // Exactly at threshold: 108/144 signal -> LockedIn.
        let (exact_chain, exact_headers) = get_chain_with_versions(300, |i| {
            if i >= 144 && i <= 251 {
                Version::from_consensus(0x20000001)
            } else {
                Version::from_consensus(0x20000000)
            }
        });
        assert_eq!(
            exact_headers[289]
                .bip9_state(&deployment, &exact_chain)
                .expect("exactly at threshold"),
            ThresholdState::LockedIn,
        );
    }
}
