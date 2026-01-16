use bitcoin::BlockHash;
use bitcoin::Txid;
use serde::Deserialize;
use serde::Serialize;

use crate::typed_commands::response::AddNodeCommand;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetBlockchainInfo;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetBlockHash {
    pub height: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetBestBlockHash;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetBlockCount;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetTxOutProof {
    pub txids: Vec<Txid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blockhash: Option<BlockHash>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetTransaction {
    pub txid: Txid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verbose: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RescanBlockchain {
    #[serde(default)]
    pub start_block: u32,
    #[serde(default)]
    pub stop_block: u32,
    #[serde(default)]
    pub use_timestamp: bool,
    pub confidence: RescanConfidence,
}

/// A confidence enum to auxiliate rescan timestamp values.
///
/// Tells how much confidence you need for this rescan request. That is, the how conservative you want floresta to be when determining which block to start the rescan.
/// will make the rescan to start in a block that have an lower timestamp than the given in order to be more certain
/// about finding addresses and relevant transactions, a lower confidence will make the rescan to be closer to the given value.
///
/// This input is necessary to cover network variancy specially in testnet, for mainnet you can safely use low or medium confidences
/// depending on how much sure you are about the given timestamp covering the addresses you need.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[serde(rename_all = "lowercase")]
pub enum RescanConfidence {
    /// `high`: 99% confidence interval. Meaning 46 minutes in seconds.
    High,

    /// `medium` (default): 95% confidence interval. Meaning 30 minutes in seconds.
    Medium,

    /// `low`: 90% confidence interval. Meaning 23 minutes in seconds.
    Low,

    /// `exact`: Removes any lookback addition. Meaning 0 in seconds.
    Exact,
}

impl RescanConfidence {
    /// In cases where `use_timestamp` is set, tells how much confidence the user wants for finding its addresses from this rescan request, a higher confidence will add more lookback seconds to the targeted timestamp and rescanning more blocks.
    /// Under the hood this uses an [Exponential distribution](https://en.wikipedia.org/wiki/Exponential_distribution) [cumulative distribution function (CDF)](https:///en.wikipedia.org/wiki/Cumulative_distribution_function) where the parameter $\lambda$ (rate) is $\frac{1}{600}$ (1 block every 600 seconds, 10 minutes).
    ///   The supplied string can be one of:
    ///
    ///   - `high`: 99% confidence interval. Returning 46 minutes in seconds for `val`.
    ///   - `medium` (default): 95% confidence interval. Returning 30 minutes in seconds for `val`.
    ///   - `low`: 90% confidence interval. Returning 23 minutes in seconds for `val`.
    ///   - `exact`: Removes any lookback addition. Returning 0 for `val`
    pub const fn as_secs(&self) -> u32 {
        match self {
            Self::Exact => 0,
            Self::Low => 1_380,
            Self::Medium => 1_800,
            Self::High => 2_760,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SendRawTransaction {
    pub tx: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetBlockHeader {
    pub hash: BlockHash,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoadDescriptor {
    pub desc: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetRoots;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetBlock {
    pub hash: BlockHash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verbosity: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetPeerInfo;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetTxOut {
    pub txid: Txid,
    pub vout: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Stop;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AddNode {
    pub node: String,
    pub command: AddNodeCommand,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v2transport: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FindTxOut {
    pub txid: Txid,
    pub vout: u32,
    pub script: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height_hint: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetMemoryInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetRpcInfo;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Uptime;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListDescriptors;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Ping;
