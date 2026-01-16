//! We deal with RPCs in a manner that allow us to be flexible with it, naturally in rust, everything is a type
//! and thats not different for RPCs Requests and Results schema. We translate command schemas into rust native types
//! and we only translate them to another notation language like json when transporting, excluding IPC.
//!
//! The purpose of this module is to offer rpc types and handling for them in such a manner that they dont affect
//! how one should send, receive and transport them.

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

pub mod request;
pub mod response;

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Represents a JSON-RPC 2.0 request.
pub struct JsonRequest {
    /// The JSON-RPC version, typically "2.0".
    ///
    /// For JSON-RPC 2.0, this field is required. For earlier versions, it may be omitted.
    ///
    /// Source: <`https://json-rpc.dev/docs/reference/version-diff`>
    pub jsonrpc: Option<String>,

    /// The method to be invoked, e.g., "getblock", "sendtransaction".
    pub method: String,

    /// The parameters for the method, as an array of json values.
    pub params: Vec<Value>,

    /// An optional identifier for the request, which can be used to match responses.
    pub id: Value,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    pub data: Option<String>,
}

/// Some utility functions to extract parameters from the request. These
/// methods already handle the case where the parameter is missing or has an
/// unexpected type, returning an error if so.
pub mod arg_parser {
    use std::str::FromStr;

    use serde_json::Value;

    use crate::typed_commands::ArgParseError;

    /// Extracts a u64 parameter from the request parameters at the specified index.
    ///
    /// This function checks if the parameter exists, is of type u64 and can be converted to `T`.
    /// Returns an error otherwise.
    pub fn get_numeric<T: TryFrom<u64>>(
        params: &[Value],
        index: usize,
        opt_name: &str,
    ) -> Result<T, ArgParseError> {
        let v = params
            .get(index)
            .ok_or_else(|| ArgParseError::MissingParameter(opt_name.to_string()))?;

        let n = v.as_u64().ok_or_else(|| {
            ArgParseError::InvalidParameterType(format!("{opt_name} must be a number"))
        })?;

        T::try_from(n)
            .map_err(|_| ArgParseError::InvalidParameterType(format!("{opt_name} is out-of-range")))
    }

    /// Extracts a string parameter from the request parameters at the specified index.
    ///
    /// This function checks if the parameter exists and is of type string. Returns an error
    /// otherwise.
    pub fn get_string(
        params: &[Value],
        index: usize,
        opt_name: &str,
    ) -> Result<String, ArgParseError> {
        let v = params
            .get(index)
            .ok_or_else(|| ArgParseError::MissingParameter(opt_name.to_string()))?;

        let str = v.as_str().ok_or_else(|| {
            ArgParseError::InvalidParameterType(format!("{opt_name} must be a string"))
        })?;

        Ok(str.to_string())
    }

    /// Extracts a boolean parameter from the request parameters at the specified index.
    ///
    /// This function checks if the parameter exists and is of type boolean. Returns an error
    /// otherwise.
    pub fn get_bool(params: &[Value], index: usize, opt_name: &str) -> Result<bool, ArgParseError> {
        let v = params
            .get(index)
            .ok_or_else(|| ArgParseError::MissingParameter(opt_name.to_string()))?;

        v.as_bool().ok_or_else(|| {
            ArgParseError::InvalidParameterType(format!("{opt_name} must be a boolean"))
        })
    }

    /// Extracts a hash parameter from the request parameters at the specified index.
    ///
    /// This function can extract any type that implements `FromStr`, such as `BlockHash` or
    /// `Txid`. It checks if the parameter exists and is a valid string representation of the type.
    /// Returns an error otherwise.
    pub fn get_hash<T: FromStr>(
        params: &[Value],
        index: usize,
        opt_name: &str,
    ) -> Result<T, ArgParseError> {
        let v = params
            .get(index)
            .ok_or_else(|| ArgParseError::MissingParameter(opt_name.to_string()))?;

        v.as_str().and_then(|s| s.parse().ok()).ok_or_else(|| {
            ArgParseError::InvalidParameterType(format!("{opt_name} must be a valid hash"))
        })
    }

    /// Extracts an array of hashes from the request parameters at the specified index.
    ///
    /// This function can extract an array of any type that implements `FromStr`, such as
    /// `BlockHash` or `Txid`. It checks if the parameter exists and is an array of valid string
    /// representations of the type. Returns an error otherwise.
    pub fn get_hashes_array<T: FromStr>(
        params: &[Value],
        index: usize,
        opt_name: &str,
    ) -> Result<Vec<T>, ArgParseError> {
        let v = params
            .get(index)
            .ok_or_else(|| ArgParseError::MissingParameter(opt_name.to_string()))?;

        let array = v.as_array().ok_or_else(|| {
            ArgParseError::InvalidParameterType(format!("{opt_name} must be an array of hashes"))
        })?;

        array
            .iter()
            .map(|v| {
                v.as_str().and_then(|s| s.parse().ok()).ok_or_else(|| {
                    ArgParseError::InvalidParameterType(format!("{opt_name} must be a valid hash"))
                })
            })
            .collect()
    }

    /// Extracts an optional field from the request parameters at the specified index.
    ///
    /// This function checks if the parameter exists and is of the expected type. If the parameter
    /// doesn't exist, it returns `None`. If it exists but is of an unexpected type, it returns an
    /// error.
    pub fn get_optional_field<T>(
        params: &[Value],
        index: usize,
        opt_name: &str,
        extractor_fn: impl Fn(&[Value], usize, &str) -> Result<T, ArgParseError>,
    ) -> Result<Option<T>, ArgParseError> {
        if params.len() <= index {
            return Ok(None);
        }

        let value = extractor_fn(params, index, opt_name)?;
        Ok(Some(value))
    }
}

#[derive(Debug)]
pub enum ArgParseError {
    MissingParameter(String),
    InvalidParameterType(String),
}
