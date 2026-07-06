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
pub(crate) mod token_usage;
mod token_count;
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
pub use token_count::TokenCountFilter;
pub use x_token_headers::XTokenHeadersFilter;
