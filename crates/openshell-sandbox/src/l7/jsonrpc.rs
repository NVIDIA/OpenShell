// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! JSON-RPC 2.0 over HTTP L7 inspection.

use miette::Result;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::collections::HashMap;
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
    pub calls: Vec<JsonRpcCallInfo>,
    pub is_batch: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonRpcCallInfo {
    pub method: String,
    pub params: HashMap<String, String>,
}

impl JsonRpcRequestInfo {
    pub(crate) fn params_sha256(&self) -> Option<String> {
        if self.is_batch {
            if self.calls.is_empty() || self.calls.iter().all(|call| call.params.is_empty()) {
                return None;
            }
            let canonical_params = self
                .calls
                .iter()
                .map(|call| canonical_params_map(&call.params))
                .collect::<Vec<_>>();
            return Some(sha256_json(&canonical_params));
        }

        let call = self.calls.first()?;
        if call.params.is_empty() {
            return None;
        }
        Some(sha256_json(&canonical_params_map(&call.params)))
    }
}
/// Parse a JSON-RPC 2.0 request body and extract the `method` field.
///
/// Returns an info struct with `method` set on success, or `error` set if the
/// body is not valid JSON-RPC 2.0.
pub fn parse_jsonrpc_body(body: &[u8]) -> JsonRpcRequestInfo {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return JsonRpcRequestInfo {
            calls: Vec::new(),
            is_batch: false,
            error: Some("invalid JSON".to_string()),
        };
    };

    if let serde_json::Value::Array(items) = value {
        if items.is_empty() {
            return JsonRpcRequestInfo {
                calls: Vec::new(),
                is_batch: true,
                error: Some("empty batch".to_string()),
            };
        }
        let mut calls = Vec::new();
        for item in &items {
            let Some(call) = parse_jsonrpc_call(item) else {
                return JsonRpcRequestInfo {
                    calls: Vec::new(),
                    is_batch: true,
                    error: Some("batch item missing or non-string 'method' field".to_string()),
                };
            };
            calls.push(call);
        }
        return JsonRpcRequestInfo {
            calls,
            is_batch: true,
            error: None,
        };
    }

    let Some(call) = parse_jsonrpc_call(&value) else {
        return JsonRpcRequestInfo {
            calls: Vec::new(),
            is_batch: false,
            error: Some("missing or non-string 'method' field".to_string()),
        };
    };
    JsonRpcRequestInfo {
        calls: vec![call],
        is_batch: false,
        error: None,
    }
}

fn parse_jsonrpc_call(value: &serde_json::Value) -> Option<JsonRpcCallInfo> {
    let method = value.get("method").and_then(|m| m.as_str())?;
    Some(JsonRpcCallInfo {
        method: method.to_string(),
        params: value
            .get("params")
            .map_or_else(HashMap::new, flatten_jsonrpc_params),
    })
}

fn flatten_jsonrpc_params(value: &serde_json::Value) -> HashMap<String, String> {
    let mut params = HashMap::new();
    flatten_json_value("", value, &mut params);
    params
}

fn canonical_params_map(params: &HashMap<String, String>) -> BTreeMap<String, String> {
    params
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn sha256_json(value: &impl serde::Serialize) -> String {
    let encoded = serde_json::to_vec(value).expect("canonical JSON-RPC params should serialize");
    hex::encode(Sha256::digest(&encoded))
}

fn flatten_json_value(prefix: &str, value: &serde_json::Value, out: &mut HashMap<String, String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let next = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten_json_value(&next, child, out);
            }
        }
        serde_json::Value::String(s) if !prefix.is_empty() => {
            out.insert(prefix.to_string(), s.clone());
        }
        serde_json::Value::Number(n) if !prefix.is_empty() => {
            out.insert(prefix.to_string(), n.to_string());
        }
        serde_json::Value::Bool(b) if !prefix.is_empty() => {
            out.insert(prefix.to_string(), b.to_string());
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_method_from_request_body() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let info = parse_jsonrpc_body(body);
        assert_eq!(
            info.calls.first().map(|call| call.method.as_str()),
            Some("initialize")
        );
        assert_eq!(info.calls.len(), 1);
        assert!(!info.is_batch);
        assert!(info.error.is_none());
    }

    #[test]
    fn flattens_object_params_for_policy_matching() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"submit_report","arguments":{"scope":"workspace/main"}}}"#;
        let info = parse_jsonrpc_body(body);
        let params = &info.calls.first().expect("single request call").params;
        assert_eq!(
            params.get("name").map(String::as_str),
            Some("submit_report")
        );
        assert_eq!(
            params.get("arguments.scope").map(String::as_str),
            Some("workspace/main")
        );
    }

    #[test]
    fn parses_valid_batch_without_error() {
        let body = br#"[
            {"jsonrpc":"2.0","id":1,"method":"tools/list"},
            {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_status"}}
        ]"#;
        let info = parse_jsonrpc_body(body);
        assert!(info.error.is_none());
        assert!(info.is_batch);
        assert_eq!(info.calls.len(), 2);
        assert_eq!(info.calls[0].method, "tools/list");
        assert_eq!(info.calls[1].method, "tools/call");
        assert_eq!(
            info.calls[1].params.get("name").map(String::as_str),
            Some("read_status")
        );
    }

    #[test]
    fn params_digest_is_canonical_and_redacted() {
        let first = parse_jsonrpc_body(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"submit_report","arguments":{"scope":"workspace/main"}}}"#,
        );
        let reordered = parse_jsonrpc_body(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"scope":"workspace/main"},"name":"submit_report"}}"#,
        );
        let changed = parse_jsonrpc_body(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"submit_report","arguments":{"scope":"workspace/other"}}}"#,
        );

        let digest = first.params_sha256().expect("params digest");
        assert_eq!(Some(digest.as_str()), reordered.params_sha256().as_deref());
        assert_ne!(Some(digest.as_str()), changed.params_sha256().as_deref());
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!digest.contains("workspace/main"));
        assert!(!digest.contains("submit_report"));
    }

    #[test]
    fn batch_params_digest_covers_call_params_without_raw_values() {
        let batch = parse_jsonrpc_body(
            br#"[
                {"jsonrpc":"2.0","id":1,"method":"tools/list"},
                {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"blocked_action"}}
            ]"#,
        );
        let empty_batch = parse_jsonrpc_body(
            br#"[
                {"jsonrpc":"2.0","id":1,"method":"tools/list"},
                {"jsonrpc":"2.0","id":2,"method":"initialize"}
            ]"#,
        );

        let digest = batch.params_sha256().expect("batch params digest");
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!digest.contains("blocked_action"));
        assert!(empty_batch.params_sha256().is_none());
    }
}
