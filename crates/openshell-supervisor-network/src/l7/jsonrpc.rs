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
    if jsonrpc_receive_stream_request(&request) {
        return Ok(Some(JsonRpcHttpRequest {
            request,
            info: JsonRpcRequestInfo::receive_stream(),
        }));
    }
    let body =
        crate::l7::http::read_body_for_inspection(client, &mut request, max_body_bytes).await?;
    let info = parse_jsonrpc_body(&body);
    Ok(Some(JsonRpcHttpRequest { request, info }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonRpcRequestInfo {
    pub calls: Vec<JsonRpcCallInfo>,
    pub is_batch: bool,
    pub has_response: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonRpcCallInfo {
    pub method: String,
    pub params: HashMap<String, String>,
}

impl JsonRpcRequestInfo {
    pub(crate) fn receive_stream() -> Self {
        Self {
            calls: Vec::new(),
            is_batch: false,
            has_response: false,
            error: None,
        }
    }

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

pub(crate) fn jsonrpc_receive_stream_request(request: &L7Request) -> bool {
    request.action.eq_ignore_ascii_case("GET")
        && matches!(
            request.body_length,
            crate::l7::provider::BodyLength::None
                | crate::l7::provider::BodyLength::ContentLength(0)
        )
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
            has_response: false,
            error: Some("invalid JSON".to_string()),
        };
    };

    if let serde_json::Value::Array(items) = value {
        if items.is_empty() {
            return JsonRpcRequestInfo {
                calls: Vec::new(),
                is_batch: true,
                has_response: false,
                error: Some("empty batch".to_string()),
            };
        }
        let mut calls = Vec::new();
        let mut has_response = false;
        for item in &items {
            match parse_jsonrpc_message(item) {
                Ok(JsonRpcMessageInfo::Call(call)) => calls.push(call),
                Ok(JsonRpcMessageInfo::Response) => has_response = true,
                Err(error) => {
                    return JsonRpcRequestInfo {
                        calls: Vec::new(),
                        is_batch: true,
                        has_response: false,
                        error: Some(format!("batch item invalid: {error}")),
                    };
                }
            }
        }
        return JsonRpcRequestInfo {
            calls,
            is_batch: true,
            has_response,
            error: None,
        };
    }

    match parse_jsonrpc_message(&value) {
        Ok(JsonRpcMessageInfo::Call(call)) => JsonRpcRequestInfo {
            calls: vec![call],
            is_batch: false,
            has_response: false,
            error: None,
        },
        Ok(JsonRpcMessageInfo::Response) => JsonRpcRequestInfo {
            calls: Vec::new(),
            is_batch: false,
            has_response: true,
            error: None,
        },
        Err(error) => JsonRpcRequestInfo {
            calls: Vec::new(),
            is_batch: false,
            has_response: false,
            error: Some(error),
        },
    }
}

enum JsonRpcMessageInfo {
    Call(JsonRpcCallInfo),
    Response,
}

fn parse_jsonrpc_message(
    value: &serde_json::Value,
) -> std::result::Result<JsonRpcMessageInfo, String> {
    let version = value
        .get("jsonrpc")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing or non-string 'jsonrpc' field".to_string())?;
    if version != "2.0" {
        return Err(format!("unsupported JSON-RPC version '{version}'"));
    }

    let has_method = value.get("method").is_some();
    let has_response_payload = jsonrpc_response_payload_present(value);
    if has_method && has_response_payload {
        return Err("JSON-RPC message includes both method and result/error".to_string());
    }

    if has_response_payload {
        parse_jsonrpc_response(value)?;
        return Ok(JsonRpcMessageInfo::Response);
    }

    if has_method {
        return parse_jsonrpc_call(value).map(JsonRpcMessageInfo::Call);
    }

    Err("missing or non-string 'method' field".to_string())
}

fn parse_jsonrpc_call(value: &serde_json::Value) -> std::result::Result<JsonRpcCallInfo, String> {
    let method = value
        .get("method")
        .and_then(|m| m.as_str())
        .ok_or_else(|| "missing or non-string 'method' field".to_string())?;
    let params = value
        .get("params")
        .map_or_else(|| Ok(HashMap::new()), flatten_jsonrpc_params)?;
    Ok(JsonRpcCallInfo {
        method: method.to_string(),
        params,
    })
}

fn jsonrpc_response_payload_present(value: &serde_json::Value) -> bool {
    value.get("result").is_some() || value.get("error").is_some()
}

fn parse_jsonrpc_response(value: &serde_json::Value) -> std::result::Result<(), String> {
    let has_result = value.get("result").is_some();
    let has_error = value.get("error").is_some();
    match (has_result, has_error) {
        (true, true) => return Err("JSON-RPC response includes both result and error".to_string()),
        (false, false) => return Err("JSON-RPC response missing result or error".to_string()),
        _ => {}
    }

    let id = value
        .get("id")
        .ok_or_else(|| "JSON-RPC response missing id".to_string())?;
    if !(id.is_string() || id.is_number() || id.is_null()) {
        return Err("JSON-RPC response id must be string, number, or null".to_string());
    }

    if let Some(error) = value.get("error")
        && !error.is_object()
    {
        return Err("JSON-RPC response error must be an object".to_string());
    }

    Ok(())
}

fn flatten_jsonrpc_params(
    value: &serde_json::Value,
) -> std::result::Result<HashMap<String, String>, String> {
    let mut params = HashMap::new();
    flatten_json_value("", value, &mut params)?;
    Ok(params)
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

fn flatten_json_value(
    prefix: &str,
    value: &serde_json::Value,
    out: &mut HashMap<String, String>,
) -> std::result::Result<(), String> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if key.contains('.') {
                    return Err(format!(
                        "ambiguous dotted params key '{key}' is not allowed"
                    ));
                }
                let next = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten_json_value(&next, child, out)?;
            }
        }
        serde_json::Value::String(s) if !prefix.is_empty() => {
            insert_flattened_param(out, prefix, s.clone())?;
        }
        serde_json::Value::Number(n) if !prefix.is_empty() => {
            insert_flattened_param(out, prefix, n.to_string())?;
        }
        serde_json::Value::Bool(b) if !prefix.is_empty() => {
            insert_flattened_param(out, prefix, b.to_string())?;
        }
        _ => {}
    }
    Ok(())
}

fn insert_flattened_param(
    out: &mut HashMap<String, String>,
    key: &str,
    value: String,
) -> std::result::Result<(), String> {
    if out.insert(key.to_string(), value).is_some() {
        return Err(format!("ambiguous params key collision at '{key}'"));
    }
    Ok(())
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
        assert!(!info.has_response);
        assert!(info.error.is_none());
    }

    #[test]
    fn parses_jsonrpc_response_body_without_method() {
        let body = br#"{"jsonrpc":"2.0","id":1,"result":{"action":"accept","content":{}}}"#;
        let info = parse_jsonrpc_body(body);

        assert!(info.calls.is_empty());
        assert!(!info.is_batch);
        assert!(info.has_response);
        assert!(info.error.is_none());
        assert!(info.params_sha256().is_none());
    }

    #[test]
    fn parses_jsonrpc_error_response_body_without_method() {
        let body =
            br#"{"jsonrpc":"2.0","id":"request-1","error":{"code":-32603,"message":"failed"}}"#;
        let info = parse_jsonrpc_body(body);

        assert!(info.calls.is_empty());
        assert!(info.has_response);
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
    fn rejects_literal_dotted_param_keys() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments.scope":"workspace/other","arguments":{"scope":"workspace/main"}}}"#;
        let info = parse_jsonrpc_body(body);

        assert!(info.calls.is_empty());
        assert!(
            info.error
                .as_deref()
                .is_some_and(|error| error.contains("ambiguous dotted params key")),
            "expected dotted params key error, got {info:?}"
        );
    }

    #[test]
    fn recognizes_streamable_http_get_receive_streams() {
        let request = L7Request {
            action: "GET".to_string(),
            target: "/mcp".to_string(),
            query_params: HashMap::new(),
            raw_header: Vec::new(),
            body_length: crate::l7::provider::BodyLength::None,
        };

        assert!(jsonrpc_receive_stream_request(&request));

        let info = JsonRpcRequestInfo::receive_stream();
        assert!(info.error.is_none());
        assert!(info.calls.is_empty());
        assert!(info.params_sha256().is_none());
    }

    #[test]
    fn rejects_requests_missing_jsonrpc_version() {
        let body = br#"{"id":1,"method":"tools/list"}"#;
        let info = parse_jsonrpc_body(body);

        assert!(info.calls.is_empty());
        assert_eq!(
            info.error.as_deref(),
            Some("missing or non-string 'jsonrpc' field")
        );
    }

    #[test]
    fn rejects_batch_items_missing_jsonrpc_version() {
        let body = br#"[
            {"jsonrpc":"2.0","id":1,"method":"tools/list"},
            {"id":2,"method":"tools/call","params":{"name":"read_status"}}
        ]"#;
        let info = parse_jsonrpc_body(body);

        assert!(info.calls.is_empty());
        assert!(info.is_batch);
        assert_eq!(
            info.error.as_deref(),
            Some("batch item invalid: missing or non-string 'jsonrpc' field")
        );
    }

    #[test]
    fn rejects_unsupported_jsonrpc_version() {
        let body = br#"{"jsonrpc":"1.0","id":1,"method":"tools/list"}"#;
        let info = parse_jsonrpc_body(body);

        assert!(info.calls.is_empty());
        assert_eq!(
            info.error.as_deref(),
            Some("unsupported JSON-RPC version '1.0'")
        );
    }

    #[test]
    fn detects_flattened_param_collisions() {
        let mut params = HashMap::from([("arguments.scope".to_string(), "first".to_string())]);

        let error = insert_flattened_param(&mut params, "arguments.scope", "second".to_string())
            .expect_err("duplicate flattened key should be ambiguous");

        assert!(error.contains("ambiguous params key collision"));
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
        assert!(!info.has_response);
        assert_eq!(info.calls.len(), 2);
        assert_eq!(info.calls[0].method, "tools/list");
        assert_eq!(info.calls[1].method, "tools/call");
        assert_eq!(
            info.calls[1].params.get("name").map(String::as_str),
            Some("read_status")
        );
    }

    #[test]
    fn parses_batch_with_calls_and_responses() {
        let body = br#"[
            {"jsonrpc":"2.0","id":1,"method":"tools/list"},
            {"jsonrpc":"2.0","id":2,"result":{"ok":true}}
        ]"#;
        let info = parse_jsonrpc_body(body);

        assert!(info.error.is_none());
        assert!(info.is_batch);
        assert!(info.has_response);
        assert_eq!(info.calls.len(), 1);
        assert_eq!(info.calls[0].method, "tools/list");
    }

    #[test]
    fn rejects_invalid_jsonrpc_response_body() {
        let body =
            br#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-32603,"message":"failed"}}"#;
        let info = parse_jsonrpc_body(body);

        assert!(info.calls.is_empty());
        assert!(!info.has_response);
        assert_eq!(
            info.error.as_deref(),
            Some("JSON-RPC response includes both result and error")
        );
    }

    #[test]
    fn rejects_message_with_method_and_result_or_error() {
        let result_body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","result":{}}"#;
        let result_info = parse_jsonrpc_body(result_body);
        assert!(result_info.calls.is_empty());
        assert_eq!(
            result_info.error.as_deref(),
            Some("JSON-RPC message includes both method and result/error")
        );

        let error_body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","error":{"code":-32603,"message":"failed"}}"#;
        let error_info = parse_jsonrpc_body(error_body);
        assert!(error_info.calls.is_empty());
        assert_eq!(
            error_info.error.as_deref(),
            Some("JSON-RPC message includes both method and result/error")
        );
    }

    #[test]
    fn rejects_batch_item_with_method_and_result() {
        let body = br#"[
            {"jsonrpc":"2.0","id":1,"method":"tools/list"},
            {"jsonrpc":"2.0","id":2,"method":"initialize","result":{}}
        ]"#;
        let info = parse_jsonrpc_body(body);

        assert!(info.calls.is_empty());
        assert!(info.is_batch);
        assert_eq!(
            info.error.as_deref(),
            Some("batch item invalid: JSON-RPC message includes both method and result/error")
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
