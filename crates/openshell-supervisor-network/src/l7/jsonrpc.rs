// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! JSON-RPC 2.0 over HTTP L7 inspection.

use miette::Result;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::collections::HashMap;
use tokio::io::{AsyncRead, AsyncWrite};
use tower_mcp_types::protocol::{
    JSONRPC_VERSION, JsonRpcNotification, JsonRpcRequest, McpNotification, McpRequest,
};

use crate::l7::provider::{L7Provider, L7Request};

pub const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024;

/// Selects whether the parser should treat a JSON-RPC message as generic
/// JSON-RPC 2.0 or as an MCP message with MCP method/params validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonRpcInspectionMode {
    JsonRpc,
    Mcp,
}

impl JsonRpcInspectionMode {
    pub(crate) fn for_protocol(protocol: crate::l7::L7Protocol) -> Self {
        match protocol {
            crate::l7::L7Protocol::Mcp => Self::Mcp,
            _ => Self::JsonRpc,
        }
    }
}

/// Endpoint-specific JSON-RPC-family parser settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonRpcInspectionOptions {
    pub mode: JsonRpcInspectionMode,
    pub mcp_strict_tool_names: bool,
}

impl JsonRpcInspectionOptions {
    pub(crate) fn for_config(config: &crate::l7::L7EndpointConfig) -> Self {
        Self {
            mode: JsonRpcInspectionMode::for_protocol(config.protocol),
            mcp_strict_tool_names: config.mcp_strict_tool_names,
        }
    }
}

impl From<JsonRpcInspectionMode> for JsonRpcInspectionOptions {
    fn from(mode: JsonRpcInspectionMode) -> Self {
        Self {
            mode,
            mcp_strict_tool_names: true,
        }
    }
}

/// Parsed HTTP request plus the JSON-RPC-family metadata extracted from the
/// body. The original HTTP request is still forwarded if policy allows it.
pub struct JsonRpcHttpRequest {
    pub request: L7Request,
    pub info: JsonRpcRequestInfo,
}

pub(crate) async fn parse_jsonrpc_http_request<C: AsyncRead + AsyncWrite + Unpin + Send>(
    client: &mut C,
    max_body_bytes: usize,
    canonicalize_options: crate::l7::path::CanonicalizeOptions,
    inspection_options: JsonRpcInspectionOptions,
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
    let info = parse_jsonrpc_body_with_options(&body, inspection_options);
    Ok(Some(JsonRpcHttpRequest { request, info }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonRpcRequestInfo {
    /// Calls found in the request body. Responses and receive-stream GETs have
    /// no calls but are still represented so policy can allow relay behavior.
    pub calls: Vec<JsonRpcCallInfo>,
    pub is_batch: bool,
    pub receive_stream: bool,
    pub has_response: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonRpcCallInfo {
    /// JSON-RPC method, or the MCP method name after typed MCP parsing.
    pub method: String,
    /// Flattened scalar params used by the current Rego matcher path. Strings,
    /// numbers, and booleans are represented as strings for compatibility with
    /// the existing query matcher implementation.
    pub params: HashMap<String, String>,
    /// MCP `tools/call` tool name when known. Generic JSON-RPC leaves this as
    /// a best-effort projection of `params.name`.
    pub tool: Option<String>,
}

impl JsonRpcRequestInfo {
    /// MCP streamable HTTP uses an empty GET to receive server messages. It has
    /// no request body to inspect, but it must still pass through MCP endpoints.
    pub(crate) fn receive_stream() -> Self {
        Self {
            calls: Vec::new(),
            is_batch: false,
            receive_stream: true,
            has_response: false,
            error: None,
        }
    }

    /// Logs store only a digest of params. For batches, hash the per-call
    /// canonical maps so denied-call logging cannot leak raw argument values.
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
        && request_accepts_sse(request)
}

fn request_accepts_sse(request: &L7Request) -> bool {
    let header_end = request
        .raw_header
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(request.raw_header.len(), |p| p + 4);
    let header = String::from_utf8_lossy(&request.raw_header[..header_end]);
    header.lines().skip(1).any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.trim().eq_ignore_ascii_case("accept")
            && value.split(',').any(|part| {
                part.split(';').next().is_some_and(|media_type| {
                    media_type.trim().eq_ignore_ascii_case("text/event-stream")
                })
            })
    })
}
/// Parse a JSON-RPC-family body using the endpoint's inspection mode.
pub fn parse_jsonrpc_body(
    body: &[u8],
    inspection_mode: JsonRpcInspectionMode,
) -> JsonRpcRequestInfo {
    parse_jsonrpc_body_with_options(body, inspection_mode.into())
}

/// Parse a JSON-RPC-family body using the endpoint's inspection options.
pub fn parse_jsonrpc_body_with_options(
    body: &[u8],
    inspection_options: JsonRpcInspectionOptions,
) -> JsonRpcRequestInfo {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return JsonRpcRequestInfo {
            calls: Vec::new(),
            is_batch: false,
            receive_stream: false,
            has_response: false,
            error: Some("invalid JSON".to_string()),
        };
    };

    if let serde_json::Value::Array(items) = value {
        if items.is_empty() {
            return JsonRpcRequestInfo {
                calls: Vec::new(),
                is_batch: true,
                receive_stream: false,
                has_response: false,
                error: Some("empty batch".to_string()),
            };
        }
        let mut calls = Vec::new();
        let mut has_response = false;
        for item in &items {
            match parse_jsonrpc_message(item, inspection_options) {
                Ok(JsonRpcMessageInfo::Call(call)) => calls.push(call),
                Ok(JsonRpcMessageInfo::Response) => has_response = true,
                Err(error) => {
                    return JsonRpcRequestInfo {
                        calls: Vec::new(),
                        is_batch: true,
                        receive_stream: false,
                        has_response: false,
                        error: Some(format!("batch item invalid: {error}")),
                    };
                }
            }
        }
        return JsonRpcRequestInfo {
            calls,
            is_batch: true,
            receive_stream: false,
            has_response,
            error: None,
        };
    }

    match parse_jsonrpc_message(&value, inspection_options) {
        Ok(JsonRpcMessageInfo::Call(call)) => JsonRpcRequestInfo {
            calls: vec![call],
            is_batch: false,
            receive_stream: false,
            has_response: false,
            error: None,
        },
        Ok(JsonRpcMessageInfo::Response) => JsonRpcRequestInfo {
            calls: Vec::new(),
            is_batch: false,
            receive_stream: false,
            has_response: true,
            error: None,
        },
        Err(error) => JsonRpcRequestInfo {
            calls: Vec::new(),
            is_batch: false,
            receive_stream: false,
            has_response: false,
            error: Some(error),
        },
    }
}

enum JsonRpcMessageInfo {
    Call(JsonRpcCallInfo),
    Response,
}

// Shared framing for JSON-RPC-family messages. MCP-specific validation starts
// only after the common JSON-RPC version/method/response checks.
fn parse_jsonrpc_message(
    value: &serde_json::Value,
    inspection_options: JsonRpcInspectionOptions,
) -> std::result::Result<JsonRpcMessageInfo, String> {
    let version = value
        .get("jsonrpc")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing or non-string 'jsonrpc' field".to_string())?;
    if version != JSONRPC_VERSION {
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
        return parse_jsonrpc_call(value, inspection_options).map(JsonRpcMessageInfo::Call);
    }

    Err("missing or non-string 'method' field".to_string())
}

fn parse_jsonrpc_call(
    value: &serde_json::Value,
    inspection_options: JsonRpcInspectionOptions,
) -> std::result::Result<JsonRpcCallInfo, String> {
    // MCP mode delegates method-specific validation to tower-mcp-types. The
    // generic mode intentionally remains looser for non-MCP JSON-RPC servers.
    if inspection_options.mode == JsonRpcInspectionMode::Mcp {
        return parse_mcp_call(value, inspection_options.mcp_strict_tool_names);
    }

    let method = value
        .get("method")
        .and_then(|m| m.as_str())
        .ok_or_else(|| "missing or non-string 'method' field".to_string())?;
    let params = flatten_jsonrpc_params_opt(value.get("params"))?;
    let tool = params.get("name").cloned();
    Ok(JsonRpcCallInfo {
        method: method.to_string(),
        params,
        tool,
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

fn parse_mcp_call(
    value: &serde_json::Value,
    strict_tool_names: bool,
) -> std::result::Result<JsonRpcCallInfo, String> {
    if value.get("id").is_some() {
        // Typed parsing validates known MCP params, but policy method profiles
        // stay OpenShell-owned; see McpOptions in proto/sandbox.proto.
        let request: JsonRpcRequest = serde_json::from_value(value.clone())
            .map_err(|error| format!("invalid MCP request: {error}"))?;
        request
            .validate()
            .map_err(|error| format!("invalid MCP request: {error:?}"))?;
        let mcp_request = McpRequest::from_jsonrpc(&request)
            .map_err(|error| format!("invalid MCP request params: {error}"))?;
        let tool = mcp_tool_name(&mcp_request);
        if strict_tool_names && let Some(tool_name) = tool.as_deref() {
            validate_mcp_tool_name(tool_name)?;
        }

        return Ok(JsonRpcCallInfo {
            method: mcp_request.method_name().to_string(),
            params: flatten_jsonrpc_params_opt(request.params.as_ref())?,
            tool,
        });
    }

    // Notifications have no id and no response expectation. Validate them as
    // MCP notifications but keep extension notifications addressable.
    let notification: JsonRpcNotification = serde_json::from_value(value.clone())
        .map_err(|error| format!("invalid MCP notification: {error}"))?;
    if notification.jsonrpc != JSONRPC_VERSION {
        return Err(format!(
            "unsupported JSON-RPC version '{}'",
            notification.jsonrpc
        ));
    }
    McpNotification::from_jsonrpc(&notification)
        .map_err(|error| format!("invalid MCP notification params: {error}"))?;

    Ok(JsonRpcCallInfo {
        method: notification.method,
        params: flatten_jsonrpc_params_opt(notification.params.as_ref())?,
        tool: None,
    })
}

fn flatten_jsonrpc_params(
    value: &serde_json::Value,
) -> std::result::Result<HashMap<String, String>, String> {
    let mut params = HashMap::<String, FlattenedParam>::new();
    flatten_json_value("", 0, value, &mut params)?;
    Ok(params
        .into_iter()
        .map(|(key, param)| (key, param.value))
        .collect())
}

fn flatten_jsonrpc_params_opt(
    value: Option<&serde_json::Value>,
) -> std::result::Result<HashMap<String, String>, String> {
    value.map_or_else(|| Ok(HashMap::new()), flatten_jsonrpc_params)
}

fn mcp_tool_name(request: &McpRequest) -> Option<String> {
    if let McpRequest::CallTool(params) = request {
        Some(params.name.clone())
    } else {
        None
    }
}

// OpenShell's default MCP hardening enforces the spec-recommended tool-name
// boundary for tools/call. See McpOptions in proto/sandbox.proto for sources.
fn validate_mcp_tool_name(name: &str) -> std::result::Result<(), String> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(
            "MCP tool name must match ^[A-Za-z0-9_.-]{1,128}$ when strict_tool_names is enabled"
                .to_string(),
        );
    }
    Ok(())
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
    path_segments: usize,
    value: &serde_json::Value,
    out: &mut HashMap<String, FlattenedParam>,
) -> std::result::Result<(), String> {
    // Keep the runtime input flat for the existing OPA matcher. Literal dotted
    // keys are accepted; if they collide with a flattened nested path, the
    // literal key wins because it has fewer JSON path segments.
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let next_path_segments = path_segments + 1;
                let next = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten_json_value(&next, next_path_segments, child, out)?;
            }
        }
        serde_json::Value::String(s) if !prefix.is_empty() => {
            insert_flattened_param(out, prefix, s.clone(), path_segments)?;
        }
        serde_json::Value::Number(n) if !prefix.is_empty() => {
            insert_flattened_param(out, prefix, n.to_string(), path_segments)?;
        }
        serde_json::Value::Bool(b) if !prefix.is_empty() => {
            insert_flattened_param(out, prefix, b.to_string(), path_segments)?;
        }
        _ => {}
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct FlattenedParam {
    value: String,
    path_segments: usize,
}

fn insert_flattened_param(
    out: &mut HashMap<String, FlattenedParam>,
    key: &str,
    value: String,
    path_segments: usize,
) -> std::result::Result<(), String> {
    let param = FlattenedParam {
        value,
        path_segments,
    };
    if let Some(existing) = out.get_mut(key) {
        if param.path_segments < existing.path_segments {
            *existing = param;
        } else if param.path_segments == existing.path_segments {
            return Err(format!("ambiguous params key collision at '{key}'"));
        }
        return Ok(());
    }
    out.insert(key.to_string(), param);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_method_from_request_body() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::JsonRpc);
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
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::JsonRpc);

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
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::JsonRpc);

        assert!(info.calls.is_empty());
        assert!(info.has_response);
        assert!(info.error.is_none());
    }

    #[test]
    fn flattens_object_params_for_policy_matching() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"submit_report","arguments":{"scope":"workspace/main"}}}"#;
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::JsonRpc);
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
    fn mcp_mode_validates_known_methods_and_extracts_tool() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_web","arguments":{"query":"openshell"}}}"#;
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::Mcp);

        assert!(info.error.is_none(), "expected valid MCP call: {info:?}");
        let call = info.calls.first().expect("single MCP call");
        assert_eq!(call.method, "tools/call");
        assert_eq!(call.tool.as_deref(), Some("search_web"));
        assert_eq!(
            call.params.get("arguments.query").map(String::as_str),
            Some("openshell")
        );
    }

    #[test]
    fn mcp_mode_rejects_non_recommended_tool_names_by_default() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read status","arguments":{}}}"#;
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::Mcp);

        assert!(info.calls.is_empty());
        assert!(
            info.error
                .as_deref()
                .is_some_and(|error| error.contains("strict_tool_names")),
            "expected strict tool-name error, got {info:?}"
        );
    }

    #[test]
    fn mcp_mode_can_disable_strict_tool_names() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read status","arguments":{}}}"#;
        let info = parse_jsonrpc_body_with_options(
            body,
            JsonRpcInspectionOptions {
                mode: JsonRpcInspectionMode::Mcp,
                mcp_strict_tool_names: false,
            },
        );

        let call = info
            .calls
            .first()
            .expect("permissive MCP call should parse");
        assert!(info.error.is_none(), "permissive MCP call failed: {info:?}");
        assert_eq!(call.tool.as_deref(), Some("read status"));
    }

    #[test]
    fn mcp_mode_rejects_invalid_known_method_params() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"query":"openshell"}}}"#;
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::Mcp);

        assert!(info.calls.is_empty());
        assert!(
            info.error
                .as_deref()
                .is_some_and(|error| error.contains("invalid MCP request params")),
            "expected MCP params validation error, got {info:?}"
        );
    }

    #[test]
    fn mcp_mode_allows_unknown_extension_methods() {
        let body =
            br#"{"jsonrpc":"2.0","id":1,"method":"vendor/extension","params":{"name":"custom"}}"#;
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::Mcp);

        assert!(
            info.error.is_none(),
            "extension method should remain addressable"
        );
        assert_eq!(
            info.calls.first().map(|call| call.method.as_str()),
            Some("vendor/extension")
        );
    }

    #[test]
    fn allows_literal_dotted_param_keys() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments.scope":"workspace/other","arguments":{"scope":"workspace/main"}}}"#;
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::JsonRpc);
        let params = &info.calls.first().expect("single request call").params;

        assert!(info.error.is_none());
        assert_eq!(
            params.get("arguments.scope").map(String::as_str),
            Some("workspace/other")
        );
    }

    #[test]
    fn recognizes_streamable_http_get_receive_streams() {
        let request = L7Request {
            action: "GET".to_string(),
            target: "/mcp".to_string(),
            query_params: HashMap::new(),
            raw_header: b"GET /mcp HTTP/1.1\r\nHost: mcp.test\r\nAccept: application/json, text/event-stream\r\n\r\n".to_vec(),
            body_length: crate::l7::provider::BodyLength::None,
        };

        assert!(jsonrpc_receive_stream_request(&request));

        let info = JsonRpcRequestInfo::receive_stream();
        assert!(info.receive_stream);
        assert!(info.error.is_none());
        assert!(info.calls.is_empty());
        assert!(info.params_sha256().is_none());
    }

    #[test]
    fn bodyless_get_without_sse_accept_is_not_receive_stream() {
        let request = L7Request {
            action: "GET".to_string(),
            target: "/mcp".to_string(),
            query_params: HashMap::new(),
            raw_header: b"GET /mcp HTTP/1.1\r\nHost: mcp.test\r\nAccept: application/json\r\n\r\n"
                .to_vec(),
            body_length: crate::l7::provider::BodyLength::None,
        };

        assert!(!jsonrpc_receive_stream_request(&request));
    }

    #[test]
    fn rejects_requests_missing_jsonrpc_version() {
        let body = br#"{"id":1,"method":"tools/list"}"#;
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::JsonRpc);

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
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::JsonRpc);

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
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::JsonRpc);

        assert!(info.calls.is_empty());
        assert_eq!(
            info.error.as_deref(),
            Some("unsupported JSON-RPC version '1.0'")
        );
    }

    #[test]
    fn detects_flattened_param_collisions() {
        let mut params = HashMap::from([(
            "arguments.scope".to_string(),
            FlattenedParam {
                value: "first".to_string(),
                path_segments: 2,
            },
        )]);

        let error = insert_flattened_param(&mut params, "arguments.scope", "second".to_string(), 2)
            .expect_err("duplicate flattened key should be ambiguous");

        assert!(error.contains("ambiguous params key collision"));
    }

    #[test]
    fn parses_valid_batch_without_error() {
        let body = br#"[
            {"jsonrpc":"2.0","id":1,"method":"tools/list"},
            {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_status"}}
        ]"#;
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::JsonRpc);
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
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::JsonRpc);

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
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::JsonRpc);

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
        let result_info = parse_jsonrpc_body(result_body, JsonRpcInspectionMode::JsonRpc);
        assert!(result_info.calls.is_empty());
        assert_eq!(
            result_info.error.as_deref(),
            Some("JSON-RPC message includes both method and result/error")
        );

        let error_body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","error":{"code":-32603,"message":"failed"}}"#;
        let error_info = parse_jsonrpc_body(error_body, JsonRpcInspectionMode::JsonRpc);
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
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::JsonRpc);

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
            JsonRpcInspectionMode::JsonRpc,
        );
        let reordered = parse_jsonrpc_body(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"scope":"workspace/main"},"name":"submit_report"}}"#,
            JsonRpcInspectionMode::JsonRpc,
        );
        let changed = parse_jsonrpc_body(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"submit_report","arguments":{"scope":"workspace/other"}}}"#,
            JsonRpcInspectionMode::JsonRpc,
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
            JsonRpcInspectionMode::JsonRpc,
        );
        let empty_batch = parse_jsonrpc_body(
            br#"[
                {"jsonrpc":"2.0","id":1,"method":"tools/list"},
                {"jsonrpc":"2.0","id":2,"method":"initialize"}
            ]"#,
            JsonRpcInspectionMode::JsonRpc,
        );

        let digest = batch.params_sha256().expect("batch params digest");
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!digest.contains("blocked_action"));
        assert!(empty_batch.params_sha256().is_none());
    }
}
