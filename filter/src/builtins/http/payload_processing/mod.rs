// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! HTTP payload processing filters: compression, JSON body field
//! extraction, JSON-RPC envelope parsing, and token usage extraction.

pub mod body_parsing;
mod compression;
pub(crate) mod compression_config;
pub mod config_validation;
mod json_body_field;
pub mod json_rpc;
pub mod on_invalid;
#[cfg(feature = "ai-inference")]
pub(crate) mod token_usage;
#[cfg(feature = "ai-inference")]
mod token_count;
#[cfg(feature = "ai-inference")]
mod x_token_headers;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length for dynamic values promoted to headers or metadata.
pub const MAX_DYNAMIC_VALUE_LEN: usize = 256;

pub use compression::CompressionFilter;
pub use json_body_field::JsonBodyFieldFilter;
pub use json_rpc::JsonRpcFilter;
pub use on_invalid::OnInvalidBehavior;
#[cfg(feature = "ai-inference")]
pub use token_count::TokenCountFilter;
#[cfg(feature = "ai-inference")]
pub use x_token_headers::XTokenHeadersFilter;
