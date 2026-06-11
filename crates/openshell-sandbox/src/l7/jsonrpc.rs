// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! JSON-RPC 2.0 over HTTP L7 inspection.

use miette::Result;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::l7::provider::{L7Provider, L7Request};

pub const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024;

pub struct JsonRpcHttpRequest {
    pub request: L7Request,
    pub info: JsonRpcRequestInfo,
}

pub(crate) async fn parse_jsonrpc_http_request<C: AsyncRead + AsyncWrite + Unpin + Send>(
    client: &mut C,
    max_body_bytes: usize,
    canonicalize_options: crate::l7::path::CanonicalizeOptions,
) -> Result<Option<JsonRpcHttpRequest>> {
    let provider = crate::l7::rest::RestProvider::with_options(canonicalize_options);
    let Some(mut request) = provider.parse_request(client).await? else {
        return Ok(None);
    };
    let body =
        crate::l7::http::read_body_for_inspection(client, &mut request, max_body_bytes).await?;
    let info = parse_jsonrpc_body(&body);
    Ok(Some(JsonRpcHttpRequest { request, info }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonRpcRequestInfo {
    pub method: Option<String>,
    pub error: Option<String>,
}

/// Returns true if the parsed request's method matches the given `rpc_method` rule pattern.
///
/// An empty `rpc_method` pattern matches any method.
pub fn rpc_method_rule_matches(info: &JsonRpcRequestInfo, rpc_method: &str) -> bool {
    if rpc_method.is_empty() {
        return true;
    }
    info.method.as_deref() == Some(rpc_method)
}

/// Parse a JSON-RPC 2.0 request body and extract the `method` field.
///
/// Returns an info struct with `method` set on success, or `error` set if the
/// body is not valid JSON-RPC 2.0.
pub fn parse_jsonrpc_body(body: &[u8]) -> JsonRpcRequestInfo {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return JsonRpcRequestInfo {
            method: None,
            error: Some("invalid JSON".to_string()),
        };
    };
    let Some(method) = value.get("method").and_then(|m| m.as_str()) else {
        return JsonRpcRequestInfo {
            method: None,
            error: Some("missing or non-string 'method' field".to_string()),
        };
    };
    JsonRpcRequestInfo {
        method: Some(method.to_string()),
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_method_from_request_body() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let info = parse_jsonrpc_body(body);
        assert_eq!(info.method.as_deref(), Some("initialize"));
        assert!(info.error.is_none());
    }

    #[test]
    fn rpc_method_rule_empty_matches_any() {
        let info = parse_jsonrpc_body(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#);
        assert!(rpc_method_rule_matches(&info, ""));
    }

    #[test]
    fn rpc_method_rule_matches_exact_method() {
        let info = parse_jsonrpc_body(br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#);
        assert!(rpc_method_rule_matches(&info, "initialize"));
    }

    #[test]
    fn rpc_method_rule_does_not_match_different_method() {
        let info = parse_jsonrpc_body(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#);
        assert!(!rpc_method_rule_matches(&info, "initialize"));
    }
}
