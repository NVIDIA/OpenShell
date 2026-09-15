// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! JSON-RPC 2.0 over HTTP L7 inspection.

use std::{collections::HashMap, fmt};

use miette::Result;
use openshell_core::mcp::{MAX_MCP_LEGACY_BATCH_MESSAGES, McpProtocolVersion};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use tokio::io::{AsyncRead, AsyncWrite};
use tower_mcp_types::{
    inspection::{
        JsonRpcEnvelope, JsonRpcPayload, McpCallKind, McpDirection, McpInspection,
        McpInspectionError, McpInspectionErrorKind, McpInspector,
        McpMethodClassification as TowerMcpMethodClassification,
    },
    protocol::{InitializeParams, JSONRPC_VERSION, McpRequest, RequestMeta, validate_meta_object},
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
    /// Select generic JSON-RPC or MCP semantic inspection.
    pub mode: JsonRpcInspectionMode,
    /// Enforce the MCP recommended tool-name character and length boundary.
    pub mcp_strict_tool_names: bool,
    /// Exact revision selected by the HTTP transport for non-initialize MCP
    /// traffic. `None` permits only a bootstrap `initialize` request.
    pub mcp_revision: Option<McpProtocolVersion>,
}

impl JsonRpcInspectionOptions {
    pub(crate) fn for_config(config: &crate::l7::L7EndpointConfig) -> Self {
        Self {
            mode: JsonRpcInspectionMode::for_protocol(config.protocol),
            mcp_strict_tool_names: config.mcp_strict_tool_names,
            // Policy declares an allowlist, not an effective wire revision.
            // The transport must select one from the request version header
            // or the declared legacy fallback.
            mcp_revision: None,
        }
    }

    /// Return MCP inspection options for an initial `initialize` request.
    ///
    /// Any non-initialize MCP payload inspected with these options fails
    /// closed because no effective revision has been selected yet.
    #[must_use]
    pub const fn mcp_bootstrap(strict_tool_names: bool) -> Self {
        Self {
            mode: JsonRpcInspectionMode::Mcp,
            mcp_strict_tool_names: strict_tool_names,
            mcp_revision: None,
        }
    }

    /// Return MCP inspection options for one exact effective wire revision.
    #[must_use]
    pub const fn mcp_selected(revision: McpProtocolVersion, strict_tool_names: bool) -> Self {
        Self {
            mode: JsonRpcInspectionMode::Mcp,
            mcp_strict_tool_names: strict_tool_names,
            mcp_revision: Some(revision),
        }
    }

    /// Bind an exact transport-selected MCP revision to existing options.
    #[must_use]
    pub const fn with_mcp_revision(mut self, revision: McpProtocolVersion) -> Self {
        self.mcp_revision = Some(revision);
        self
    }
}

impl From<JsonRpcInspectionMode> for JsonRpcInspectionOptions {
    fn from(mode: JsonRpcInspectionMode) -> Self {
        Self {
            mode,
            mcp_strict_tool_names: true,
            // Mode alone cannot select an MCP wire revision. The resulting
            // options accept bootstrap initialize only until the transport
            // supplies exact per-request revision evidence.
            mcp_revision: None,
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

/// Reinspect a fully buffered JSON-RPC-family HTTP request after middleware.
///
/// Initial inspection normalizes chunked bodies to `Content-Length` and keeps
/// the complete body after the raw header block. Middleware rebuilding keeps
/// that representation, so a final pre-forward check can use the exact header
/// and body bytes that the upstream will receive without reading the client
/// stream again.
pub(crate) fn inspect_buffered_jsonrpc_http_request(
    request: &L7Request,
    inspection_options: JsonRpcInspectionOptions,
) -> Result<JsonRpcRequestInfo> {
    if jsonrpc_receive_stream_request(request) {
        return Ok(JsonRpcRequestInfo::receive_stream());
    }

    let header_end = request
        .raw_header
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| miette::miette!("HTTP request headers are missing the CRLF terminator"))?
        + 4;
    let body = &request.raw_header[header_end..];
    match request.body_length {
        crate::l7::provider::BodyLength::None if body.is_empty() => {}
        crate::l7::provider::BodyLength::ContentLength(length) => {
            let length = usize::try_from(length)
                .map_err(|_| miette::miette!("HTTP request body length exceeds platform limit"))?;
            if body.len() != length {
                return Err(miette::miette!(
                    "buffered HTTP request body length does not match Content-Length"
                ));
            }
        }
        crate::l7::provider::BodyLength::None => {
            return Err(miette::miette!(
                "buffered HTTP request has bytes without body framing"
            ));
        }
        crate::l7::provider::BodyLength::Chunked => {
            return Err(miette::miette!(
                "buffered JSON-RPC request retained chunked framing"
            ));
        }
    }

    Ok(parse_jsonrpc_body_with_options(body, inspection_options))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonRpcRequestInfo {
    /// Calls found in the request body. Responses and receive-stream GETs have
    /// no calls but are still represented so policy can allow relay behavior.
    pub calls: Vec<JsonRpcCallInfo>,
    pub is_batch: bool,
    pub receive_stream: bool,
    pub has_response: bool,
    /// Exact MCP revision used for semantic inspection. Bootstrap initialize,
    /// receive-stream requests, and generic JSON-RPC leave this unset.
    pub mcp_revision: Option<McpProtocolVersion>,
    /// Body fields mirrored into HTTP headers by sessionless MCP requests.
    /// Populated only after the request passes its selected inspection profile.
    pub mcp_http_metadata: Option<McpHttpRequestMetadata>,
    /// Typed inspection failure discovered before policy evaluation.
    pub error: Option<JsonRpcInspectionError>,
}

/// Inspected body fields that the MCP HTTP transport must compare with headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpHttpRequestMetadata {
    /// The JSON-RPC method mirrored in `Mcp-Method`.
    pub method: String,
    /// Tool or prompt name, or resource URI, mirrored in `Mcp-Name` when required.
    pub name: Option<String>,
}

/// Stable kind of failure found while inspecting a JSON-RPC-family message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JsonRpcInspectionErrorKind {
    /// The request body is not valid JSON.
    InvalidJson,
    /// The decoded JSON fails JSON-RPC or protocol-specific message validation.
    InvalidMessage,
    /// MCP traffic lacked the transport-selected revision required for exact
    /// semantic inspection.
    RevisionNotSelected,
    /// The selected MCP revision's immutable wire profile rejected the body.
    McpProfileViolation,
    /// An MCP lifecycle message appeared in a forbidden wire shape.
    McpLifecycleViolation,
}

/// Typed JSON-RPC inspection failure with an inseparable kind and diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonRpcInspectionError {
    kind: JsonRpcInspectionErrorKind,
    detail: String,
}

impl JsonRpcInspectionError {
    fn invalid_json() -> Self {
        Self {
            kind: JsonRpcInspectionErrorKind::InvalidJson,
            detail: "invalid JSON".to_string(),
        }
    }

    fn invalid_json_with_detail(detail: impl Into<String>) -> Self {
        Self {
            kind: JsonRpcInspectionErrorKind::InvalidJson,
            detail: detail.into(),
        }
    }

    fn invalid_message(detail: impl Into<String>) -> Self {
        Self {
            kind: JsonRpcInspectionErrorKind::InvalidMessage,
            detail: detail.into(),
        }
    }

    fn revision_not_selected() -> Self {
        Self {
            kind: JsonRpcInspectionErrorKind::RevisionNotSelected,
            detail: "MCP effective protocol revision has not been selected".to_string(),
        }
    }

    fn mcp_profile_violation(detail: impl Into<String>) -> Self {
        Self {
            kind: JsonRpcInspectionErrorKind::McpProfileViolation,
            detail: detail.into(),
        }
    }

    fn mcp_lifecycle_violation(detail: impl Into<String>) -> Self {
        Self {
            kind: JsonRpcInspectionErrorKind::McpLifecycleViolation,
            detail: detail.into(),
        }
    }

    /// Return the stable failure kind used by typed control flow.
    #[must_use]
    pub const fn kind(&self) -> JsonRpcInspectionErrorKind {
        self.kind
    }

    /// Return the existing policy-visible and human-readable diagnostic.
    ///
    /// Callers must use [`Self::kind`] instead of parsing this text for control flow.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Render the existing proxy denial reason for an inspection failure.
    pub(crate) fn rejection_reason(&self) -> String {
        format!("JSON-RPC request rejected: {self}")
    }
}

impl fmt::Display for JsonRpcInspectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for JsonRpcInspectionError {}

/// Policy-relevant classification of one accepted MCP method.
///
/// Known methods unavailable in the selected revision are rejected before a
/// call is produced, so the policy boundary represents only core methods that
/// are available and unknown extension methods that need an exact allow rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum McpMethodClassification {
    /// A core method defined by the selected MCP revision.
    Available,
    /// A method unknown to every supported core profile.
    Extension,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonRpcCallInfo {
    /// JSON-RPC method, or the MCP method name after typed MCP parsing.
    pub method: String,
    /// Policy-visible params for JSON-RPC-family matching. Generic JSON-RPC
    /// leaves this empty because params matching is not supported. MCP exposes
    /// only `params.name` for tools/call tool selection.
    pub params: HashMap<String, String>,
    /// MCP `tools/call` tool name when known. Generic JSON-RPC leaves this
    /// unset because params are not inspected.
    pub tool: Option<String>,
    /// Exact-profile MCP method classification retained for policy evaluation.
    /// Generic JSON-RPC calls leave this unset.
    pub mcp_classification: Option<McpMethodClassification>,
    /// Whether this call is a JSON-RPC notification without an `id`.
    ///
    /// MCP initialization is a request, so transport code uses this bit to
    /// avoid treating an extension notification named `initialize` as the
    /// header-exempt initialization exchange.
    pub is_notification: bool,
}

impl JsonRpcRequestInfo {
    fn rejected(is_batch: bool, error: JsonRpcInspectionError) -> Self {
        Self {
            calls: Vec::new(),
            is_batch,
            receive_stream: false,
            has_response: false,
            mcp_revision: None,
            mcp_http_metadata: None,
            error: Some(error),
        }
    }

    /// MCP streamable HTTP uses an empty GET to receive server messages. It has
    /// no request body to inspect, but it must still pass through MCP endpoints.
    pub(crate) fn receive_stream() -> Self {
        Self {
            calls: Vec::new(),
            is_batch: false,
            receive_stream: true,
            has_response: false,
            mcp_revision: None,
            mcp_http_metadata: None,
            error: None,
        }
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
///
/// Mode-only MCP inspection accepts the bootstrap `initialize` request but
/// rejects later requests until the negotiated revision is supplied through
/// [`parse_jsonrpc_body_with_options`].
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
    let value = match parse_unique_json_value(body) {
        Ok(value) => value,
        Err(error) => return JsonRpcRequestInfo::rejected(false, error),
    };

    if inspection_options.mode == JsonRpcInspectionMode::Mcp {
        return parse_mcp_payload(&value, inspection_options);
    }

    if let serde_json::Value::Array(items) = value {
        if items.is_empty() {
            return JsonRpcRequestInfo::rejected(
                true,
                JsonRpcInspectionError::invalid_message("empty batch"),
            );
        }
        let mut calls = Vec::new();
        let mut has_response = false;
        for item in &items {
            match parse_jsonrpc_message(item) {
                Ok(JsonRpcMessageInfo::Call(call)) => calls.push(call),
                Ok(JsonRpcMessageInfo::Response) => has_response = true,
                Err(error) => {
                    return JsonRpcRequestInfo::rejected(
                        true,
                        JsonRpcInspectionError::invalid_message(format!(
                            "batch item invalid: {error}"
                        )),
                    );
                }
            }
        }
        return JsonRpcRequestInfo {
            calls,
            is_batch: true,
            receive_stream: false,
            has_response,
            mcp_revision: None,
            mcp_http_metadata: None,
            error: None,
        };
    }

    match parse_jsonrpc_message(&value) {
        Ok(JsonRpcMessageInfo::Call(call)) => JsonRpcRequestInfo {
            calls: vec![call],
            is_batch: false,
            receive_stream: false,
            has_response: false,
            mcp_revision: None,
            mcp_http_metadata: None,
            error: None,
        },
        Ok(JsonRpcMessageInfo::Response) => JsonRpcRequestInfo {
            calls: Vec::new(),
            is_batch: false,
            receive_stream: false,
            has_response: true,
            mcp_revision: None,
            mcp_http_metadata: None,
            error: None,
        },
        Err(error) => {
            JsonRpcRequestInfo::rejected(false, JsonRpcInspectionError::invalid_message(error))
        }
    }
}

#[derive(Debug)]
struct DuplicateJsonObjectKey {
    key: String,
    object_path: String,
}

struct UniqueJsonValueSeed<'a> {
    duplicate: &'a mut Option<DuplicateJsonObjectKey>,
    path: String,
}

impl<'de> DeserializeSeed<'de> for UniqueJsonValueSeed<'_> {
    type Value = serde_json::Value;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonValueVisitor {
            duplicate: self.duplicate,
            path: self.path,
        })
    }
}

struct UniqueJsonValueVisitor<'a> {
    duplicate: &'a mut Option<DuplicateJsonObjectKey>,
    path: String,
}

impl<'de> Visitor<'de> for UniqueJsonValueVisitor<'_> {
    type Value = serde_json::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(serde_json::Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(serde_json::Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(serde_json::Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| E::custom("JSON number must be finite"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(serde_json::Value::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(serde_json::Value::String(value))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        UniqueJsonValueSeed {
            duplicate: self.duplicate,
            path: self.path,
        }
        .deserialize(deserializer)
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(UniqueJsonValueSeed {
            duplicate: &mut *self.duplicate,
            path: format!("{}[{}]", self.path, values.len()),
        })? {
            values.push(value);
        }
        Ok(serde_json::Value::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = object.next_key::<String>()? {
            // Record the first duplicate but continue decoding so syntax and
            // trailing-data failures still use serde_json's normal handling.
            if values.contains_key(&key) && self.duplicate.is_none() {
                *self.duplicate = Some(DuplicateJsonObjectKey {
                    key: key.clone(),
                    object_path: self.path.clone(),
                });
            }
            let value = object.next_value_seed(UniqueJsonValueSeed {
                duplicate: &mut *self.duplicate,
                path: format!("{}.{}", self.path, key),
            })?;
            values.insert(key, value);
        }
        Ok(serde_json::Value::Object(values))
    }
}

/// Decode one JSON value while rejecting duplicate object keys recursively.
///
/// Callers that inspect and then forward the original bytes must use this
/// boundary so `OpenShell` and the upstream cannot select different values for
/// the same object key.
pub(crate) fn parse_unique_json_value(
    body: &[u8],
) -> std::result::Result<serde_json::Value, JsonRpcInspectionError> {
    let mut duplicate = None;
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let value = UniqueJsonValueSeed {
        duplicate: &mut duplicate,
        path: "$".to_string(),
    }
    .deserialize(&mut deserializer)
    .map_err(|_| JsonRpcInspectionError::invalid_json())?;
    deserializer
        .end()
        .map_err(|_| JsonRpcInspectionError::invalid_json())?;

    if let Some(duplicate) = duplicate {
        return Err(JsonRpcInspectionError::invalid_json_with_detail(format!(
            "duplicate JSON object key '{}' at {}",
            duplicate.key, duplicate.object_path
        )));
    }
    Ok(value)
}

enum JsonRpcMessageInfo {
    Call(JsonRpcCallInfo),
    Response,
}

// Shared framing for JSON-RPC-family messages. MCP-specific validation starts
// only after the common JSON-RPC version/method/response checks.
fn parse_jsonrpc_message(
    value: &serde_json::Value,
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
        return parse_jsonrpc_call(value).map(JsonRpcMessageInfo::Call);
    }

    Err("missing or non-string 'method' field".to_string())
}

fn parse_jsonrpc_call(value: &serde_json::Value) -> std::result::Result<JsonRpcCallInfo, String> {
    let method = value
        .get("method")
        .and_then(|m| m.as_str())
        .ok_or_else(|| "missing or non-string 'method' field".to_string())?;
    Ok(JsonRpcCallInfo {
        method: method.to_string(),
        params: HashMap::new(),
        tool: None,
        mcp_classification: None,
        is_notification: value.get("id").is_none(),
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

fn parse_mcp_payload(
    value: &serde_json::Value,
    inspection_options: JsonRpcInspectionOptions,
) -> JsonRpcRequestInfo {
    let payload = match JsonRpcPayload::inspect(value) {
        Ok(payload) => payload,
        Err(error) => {
            return JsonRpcRequestInfo::rejected(
                value.is_array(),
                JsonRpcInspectionError::invalid_message(error.to_string()),
            );
        }
    };

    // Legacy initialization proposes a revision rather than selecting one.
    // Sessionless requests carry their revision in _meta and must never use
    // this exemption, even if the transport has not selected a profile yet.
    if payload_contains_method(&payload, "initialize")
        && inspection_options.mcp_revision != Some(McpProtocolVersion::V2026_07_28)
        && value
            .pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
            .and_then(serde_json::Value::as_str)
            != Some("2026-07-28")
    {
        return parse_mcp_initialize(payload);
    }

    let Some(revision) = inspection_options.mcp_revision else {
        return JsonRpcRequestInfo::rejected(
            payload.is_batch(),
            JsonRpcInspectionError::revision_not_selected(),
        );
    };

    let mut mcp_http_metadata = match inspect_mcp_request_metadata(value, revision) {
        Ok(metadata) => metadata,
        Err(error) => return JsonRpcRequestInfo::rejected(payload.is_batch(), error),
    };

    let inspection =
        match inspect_mcp_payload_for_revision(&payload, revision, McpDirection::ClientToServer) {
            Ok(inspection) => inspection,
            Err(error) => return JsonRpcRequestInfo::rejected(payload.is_batch(), error),
        };

    let mut calls = Vec::with_capacity(inspection.methods().len());
    for method in inspection.methods() {
        let named_request = match mcp_named_request_for_inspected_method(
            inspection.payload(),
            method.method(),
            method.batch_index(),
        ) {
            Ok(request) => request,
            Err(error) => {
                return JsonRpcRequestInfo::rejected(
                    inspection.payload().is_batch(),
                    JsonRpcInspectionError::invalid_message(error),
                );
            }
        };
        // Use the same typed tool name for authorization and its HTTP mirror.
        // Prompt names and resource URIs participate only in HTTP matching.
        let (tool, http_name) = match named_request {
            Some(McpRequest::CallTool(params)) => (Some(params.name.clone()), Some(params.name)),
            Some(McpRequest::GetPrompt(params)) => (None, Some(params.name)),
            Some(McpRequest::ReadResource(params)) => (None, Some(params.uri)),
            None => (None, None),
            Some(_) => {
                return JsonRpcRequestInfo::rejected(
                    inspection.payload().is_batch(),
                    JsonRpcInspectionError::invalid_message(
                        "inspected MCP name-bearing method has an unexpected typed request",
                    ),
                );
            }
        };
        if let Some(metadata) = mcp_http_metadata.as_mut() {
            metadata.name = http_name;
        }
        if inspection_options.mcp_strict_tool_names
            && let Some(tool_name) = tool.as_deref()
            && let Err(error) = validate_mcp_tool_name(tool_name)
        {
            return JsonRpcRequestInfo::rejected(
                inspection.payload().is_batch(),
                JsonRpcInspectionError::invalid_message(error),
            );
        }

        let mcp_classification = match method.classification() {
            TowerMcpMethodClassification::Available => McpMethodClassification::Available,
            TowerMcpMethodClassification::Extension => McpMethodClassification::Extension,
            TowerMcpMethodClassification::Unavailable => {
                return JsonRpcRequestInfo::rejected(
                    inspection.payload().is_batch(),
                    JsonRpcInspectionError::mcp_profile_violation(format!(
                        "MCP {revision} does not make `{}` available",
                        method.method()
                    )),
                );
            }
            _ => {
                return JsonRpcRequestInfo::rejected(
                    inspection.payload().is_batch(),
                    JsonRpcInspectionError::mcp_profile_violation(format!(
                        "MCP {revision} returned an unsupported classification for `{}`",
                        method.method()
                    )),
                );
            }
        };

        calls.push(JsonRpcCallInfo {
            method: method.method().to_string(),
            params: mcp_policy_params(tool.as_deref()),
            tool,
            mcp_classification: Some(mcp_classification),
            is_notification: method.kind() == McpCallKind::Notification,
        });
    }

    JsonRpcRequestInfo {
        calls,
        is_batch: inspection.payload().is_batch(),
        receive_stream: false,
        has_response: payload_has_response(inspection.payload()),
        mcp_revision: Some(revision),
        mcp_http_metadata,
        error: None,
    }
}

/// Validate the common request contract before method-specific inspection.
/// Extension requests need the same metadata as core requests, even when the
/// upstream inspector has no typed parameter schema for their method.
fn inspect_mcp_request_metadata(
    value: &serde_json::Value,
    revision: McpProtocolVersion,
) -> std::result::Result<Option<McpHttpRequestMetadata>, JsonRpcInspectionError> {
    // A legacy header or missing-header fallback cannot reinterpret a body
    // that explicitly declares a different per-request protocol revision.
    let messages = value
        .as_array()
        .map_or_else(|| std::slice::from_ref(value), Vec::as_slice);
    for message in messages {
        if let Some(declared) =
            message.pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
            && declared.as_str() != Some(revision.as_str())
        {
            return Err(JsonRpcInspectionError::mcp_profile_violation(
                "MCP request metadata protocol version must match the selected revision",
            ));
        }
    }

    if revision != McpProtocolVersion::V2026_07_28 {
        return Ok(None);
    }
    let Some(method) = value.get("method").and_then(serde_json::Value::as_str) else {
        return Err(JsonRpcInspectionError::mcp_profile_violation(
            "MCP 2026-07-28 HTTP bodies must contain one request or extension notification",
        ));
    };
    if value.get("id").is_none() {
        // Cancellation for HTTP is closing the response stream. The core
        // notification exists only for stdio; extension notifications retain
        // their explicit policy gate and have no standardized HTTP metadata.
        if method == "notifications/cancelled" {
            return Err(JsonRpcInspectionError::mcp_profile_violation(
                "MCP 2026-07-28 notifications/cancelled is not available over HTTP",
            ));
        }
        return Ok(None);
    }

    let meta = value.pointer("/params/_meta").ok_or_else(|| {
        JsonRpcInspectionError::invalid_message("MCP 2026-07-28 requests require params._meta")
    })?;
    validate_meta_object(meta)
        .map_err(|error| JsonRpcInspectionError::invalid_message(error.to_string()))?;
    // Tower owns the capability and implementation schemas. Apply its common
    // metadata contract here so extension requests receive the same checks
    // even though the method inspector has no extension parameter schema.
    let meta: RequestMeta = serde_json::from_value(meta.clone())
        .map_err(|error| JsonRpcInspectionError::invalid_message(error.to_string()))?;
    meta.validate_for_version(revision.as_str())
        .map_err(|error| JsonRpcInspectionError::invalid_message(error.to_string()))?;

    Ok(Some(McpHttpRequestMetadata {
        method: method.to_string(),
        // Name-bearing parameters are projected from Tower's typed requests
        // only after exact-revision method inspection succeeds.
        name: None,
    }))
}

/// Inspect one complete JSON-RPC payload under an exact MCP wire profile.
///
/// The caller supplies the peer direction because it is transport context, not
/// JSON-RPC data. This boundary enforces the revision's batch shape and bound,
/// typed method parameters, peer direction, and known-method availability.
/// Unknown extension methods remain valid for explicit policy authorization.
pub(crate) fn inspect_mcp_payload_for_revision(
    payload: &JsonRpcPayload,
    revision: McpProtocolVersion,
    direction: McpDirection,
) -> std::result::Result<McpInspection, JsonRpcInspectionError> {
    // Bound work before typed inspection. Tower owns whether the selected
    // revision permits batches; this limit applies to every attempted batch.
    if payload.is_batch() && payload.len() > MAX_MCP_LEGACY_BATCH_MESSAGES {
        return Err(JsonRpcInspectionError::mcp_profile_violation(format!(
            "MCP {revision} batch contains {} messages; the maximum is {MAX_MCP_LEGACY_BATCH_MESSAGES}",
            payload.len()
        )));
    }

    let inspector = McpInspector::new(revision.as_str())
        .map_err(|error| JsonRpcInspectionError::mcp_profile_violation(error.to_string()))?;
    let inspection = inspector
        .inspect_payload(payload.clone(), Some(direction))
        .map_err(map_mcp_inspection_error)?;

    for method in inspection.methods() {
        match method.classification() {
            TowerMcpMethodClassification::Unavailable => {
                return Err(JsonRpcInspectionError::mcp_profile_violation(format!(
                    "MCP {revision} does not make `{}` available",
                    method.method()
                )));
            }
            TowerMcpMethodClassification::Available | TowerMcpMethodClassification::Extension => {}
            _ => {
                return Err(JsonRpcInspectionError::mcp_profile_violation(format!(
                    "MCP {revision} returned an unsupported classification for `{}`",
                    method.method()
                )));
            }
        }
    }

    Ok(inspection)
}

fn parse_mcp_initialize(payload: JsonRpcPayload) -> JsonRpcRequestInfo {
    if payload.is_batch() {
        return JsonRpcRequestInfo::rejected(
            true,
            JsonRpcInspectionError::mcp_lifecycle_violation(
                "MCP `initialize` must be exactly one non-batched request",
            ),
        );
    }

    let Some(JsonRpcEnvelope::Request(request)) = payload.as_single() else {
        return JsonRpcRequestInfo::rejected(
            false,
            JsonRpcInspectionError::mcp_lifecycle_violation(
                "MCP `initialize` must be a request with an id",
            ),
        );
    };
    let Some(params) = request.params.as_ref() else {
        return JsonRpcRequestInfo::rejected(
            false,
            JsonRpcInspectionError::invalid_message("MCP `initialize` params are required"),
        );
    };
    if let Err(error) = serde_json::from_value::<InitializeParams>(params.clone()) {
        return JsonRpcRequestInfo::rejected(
            false,
            JsonRpcInspectionError::invalid_message(format!(
                "invalid MCP `initialize` params: {error}"
            )),
        );
    }

    JsonRpcRequestInfo {
        calls: vec![JsonRpcCallInfo {
            method: "initialize".to_string(),
            params: HashMap::new(),
            tool: None,
            mcp_classification: Some(McpMethodClassification::Available),
            is_notification: false,
        }],
        is_batch: false,
        receive_stream: false,
        has_response: false,
        mcp_revision: None,
        mcp_http_metadata: None,
        error: None,
    }
}

fn payload_contains_method(payload: &JsonRpcPayload, expected: &str) -> bool {
    if let Some(envelope) = payload.as_single() {
        return envelope_method(envelope) == Some(expected);
    }
    payload.as_batch().is_some_and(|batch| {
        batch
            .messages()
            .iter()
            .any(|envelope| envelope_method(envelope) == Some(expected))
    })
}

fn envelope_method(envelope: &JsonRpcEnvelope) -> Option<&str> {
    match envelope {
        JsonRpcEnvelope::Request(request) => Some(request.method.as_str()),
        JsonRpcEnvelope::Notification(notification) => Some(notification.method.as_str()),
        _ => None,
    }
}

fn payload_has_response(payload: &JsonRpcPayload) -> bool {
    if let Some(envelope) = payload.as_single() {
        return matches!(
            envelope,
            JsonRpcEnvelope::Result(_) | JsonRpcEnvelope::Error(_)
        );
    }
    payload.as_batch().is_some_and(|batch| {
        batch.messages().iter().any(|envelope| {
            matches!(
                envelope,
                JsonRpcEnvelope::Result(_) | JsonRpcEnvelope::Error(_)
            )
        })
    })
}

// The inspector retains untyped envelopes. Decode name-bearing requests with
// Tower so policy and HTTP metadata share its parameter schemas.
fn mcp_named_request_for_inspected_method(
    payload: &JsonRpcPayload,
    method: &str,
    batch_index: Option<usize>,
) -> std::result::Result<Option<McpRequest>, String> {
    if !matches!(method, "tools/call" | "prompts/get" | "resources/read") {
        return Ok(None);
    }

    let envelope = batch_index
        .map_or_else(
            || payload.as_single(),
            |index| {
                payload
                    .as_batch()
                    .and_then(|batch| batch.messages().get(index))
            },
        )
        .ok_or_else(|| "inspected MCP method is missing its JSON-RPC envelope".to_string())?;
    let JsonRpcEnvelope::Request(request) = envelope else {
        return Err(format!("MCP `{method}` must be a request with an id"));
    };
    let request = McpRequest::from_jsonrpc(request)
        .map_err(|error| format!("invalid MCP `{method}` params: {error}"))?;
    Ok(Some(request))
}

fn map_mcp_inspection_error(error: McpInspectionError) -> JsonRpcInspectionError {
    match error.kind() {
        McpInspectionErrorKind::BatchUnavailable
        | McpInspectionErrorKind::DirectionMismatch
        | McpInspectionErrorKind::UnsupportedProfile => {
            JsonRpcInspectionError::mcp_profile_violation(error.to_string())
        }
        McpInspectionErrorKind::InitializeInBatch => {
            JsonRpcInspectionError::mcp_lifecycle_violation(error.to_string())
        }
        McpInspectionErrorKind::JsonRpc
        | McpInspectionErrorKind::MessageKindMismatch
        | McpInspectionErrorKind::MissingParams
        | McpInspectionErrorKind::InvalidParams => {
            JsonRpcInspectionError::invalid_message(error.to_string())
        }
        _ => JsonRpcInspectionError::mcp_profile_violation(error.to_string()),
    }
}

fn mcp_policy_params(tool: Option<&str>) -> HashMap<String, String> {
    let mut params = HashMap::new();
    if let Some(tool) = tool {
        params.insert("name".to_string(), tool.to_string());
    }
    params
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
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn mcp_options(revision: McpProtocolVersion) -> JsonRpcInspectionOptions {
        JsonRpcInspectionOptions::mcp_selected(revision, true)
    }

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

    fn sessionless_request(method: &str, mut params: serde_json::Value) -> serde_json::Value {
        params["_meta"] = serde_json::json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {}
        });
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    }

    #[test]
    fn mcp_sessionless_inspects_core_and_extension_requests_without_initialize() {
        for (method, params, name, classification) in [
            (
                "server/discover",
                serde_json::json!({}),
                None,
                McpMethodClassification::Available,
            ),
            (
                "tools/list",
                serde_json::json!({}),
                None,
                McpMethodClassification::Available,
            ),
            (
                "tools/call",
                serde_json::json!({"name": "echo", "arguments": {}}),
                Some("echo"),
                McpMethodClassification::Available,
            ),
            (
                "prompts/get",
                serde_json::json!({"name": "summarize"}),
                Some("summarize"),
                McpMethodClassification::Available,
            ),
            (
                "resources/read",
                serde_json::json!({"uri": "file:///guide.txt"}),
                Some("file:///guide.txt"),
                McpMethodClassification::Available,
            ),
            (
                "subscriptions/listen",
                serde_json::json!({"notifications": {"toolsListChanged": true}}),
                None,
                McpMethodClassification::Available,
            ),
            (
                "vendor/inspect",
                serde_json::json!({}),
                None,
                McpMethodClassification::Extension,
            ),
        ] {
            let body = serde_json::to_vec(&sessionless_request(method, params)).unwrap();
            let info = parse_jsonrpc_body_with_options(
                &body,
                mcp_options(McpProtocolVersion::V2026_07_28),
            );
            assert!(info.error.is_none(), "{method}: {:?}", info.error);
            assert_eq!(info.calls.len(), 1);
            assert_eq!(info.calls[0].mcp_classification, Some(classification));
            let expected_tool = if method == "tools/call" { name } else { None };
            assert_eq!(info.calls[0].tool.as_deref(), expected_tool);
            assert_eq!(
                info.calls[0].params.get("name").map(String::as_str),
                expected_tool
            );
            assert_eq!(
                info.mcp_http_metadata,
                Some(McpHttpRequestMetadata {
                    method: method.to_string(),
                    name: name.map(str::to_string),
                })
            );
        }
    }

    #[test]
    fn mcp_sessionless_requires_valid_common_metadata_for_extension_requests_too() {
        for method in ["server/discover", "vendor/inspect"] {
            for meta in [
                serde_json::Value::Null,
                serde_json::json!({}),
                serde_json::json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28"}),
                serde_json::json!({"io.modelcontextprotocol/protocolVersion": "2025-11-25", "io.modelcontextprotocol/clientCapabilities": {}}),
                serde_json::json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": "invalid"}),
                serde_json::json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}, "invalid key": true}),
            ] {
                let mut request = sessionless_request(method, serde_json::json!({}));
                request["params"]["_meta"] = meta;
                let info = parse_jsonrpc_body_with_options(
                    &serde_json::to_vec(&request).unwrap(),
                    mcp_options(McpProtocolVersion::V2026_07_28),
                );
                assert!(info.error.is_some(), "accepted {request}");
                assert!(info.mcp_http_metadata.is_none());
            }
        }
    }

    #[test]
    fn mcp_sessionless_preserves_arbitrary_extension_and_experimental_settings() {
        for method in ["server/discover", "vendor/inspect"] {
            let mut request = sessionless_request(method, serde_json::json!({}));
            request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] = serde_json::json!({
                "roots": {"listChanged": true, "deprecated": {}},
                "sampling": {"tools": {}, "context": {}, "deprecated": {}},
                "elicitation": {"form": {}, "url": {}},
                "tasks": {
                    "list": {}, "cancel": {},
                    "requests": {"sampling": {"createMessage": {}}, "elicitation": {"create": {}}}
                },
                "experimental": {"list": [1, true, null], "label": "custom", "optional": null},
                "extensions": {"com.example/custom": {"list": [1, true, null], "optional": null}},
                "vendorData": []
            });
            let info = parse_jsonrpc_body_with_options(
                &serde_json::to_vec(&request).unwrap(),
                mcp_options(McpProtocolVersion::V2026_07_28),
            );
            assert!(info.error.is_none(), "{method}: {:?}", info.error);
            assert!(info.mcp_http_metadata.is_some());
        }
    }

    #[test]
    fn mcp_sessionless_validates_subscription_parameters() {
        for (notifications, valid) in [
            (serde_json::json!({}), true),
            (serde_json::json!({"toolsListChanged": true}), true),
            (serde_json::json!(null), false),
            (serde_json::json!({"toolsListChanged": []}), false),
        ] {
            let request = sessionless_request(
                "subscriptions/listen",
                serde_json::json!({"notifications": notifications}),
            );
            let info = parse_jsonrpc_body_with_options(
                &serde_json::to_vec(&request).unwrap(),
                mcp_options(McpProtocolVersion::V2026_07_28),
            );
            assert_eq!(info.error.is_none(), valid, "{request}: {:?}", info.error);
            assert_eq!(info.mcp_http_metadata.is_some(), valid);
        }
    }

    #[test]
    fn mcp_sessionless_metadata_cannot_be_inspected_as_a_legacy_revision() {
        let body =
            serde_json::to_vec(&sessionless_request("tools/list", serde_json::json!({}))).unwrap();
        for revision in [
            McpProtocolVersion::V2025_03_26,
            McpProtocolVersion::V2025_06_18,
            McpProtocolVersion::V2025_11_25,
        ] {
            let info = parse_jsonrpc_body_with_options(&body, mcp_options(revision));
            assert!(
                info.error.is_some(),
                "sessionless body accepted as {revision}"
            );
        }
    }

    #[test]
    fn mcp_sessionless_rejects_legacy_lifecycle_and_non_http_message_shapes() {
        let options = mcp_options(McpProtocolVersion::V2026_07_28);
        let initialize = sessionless_request(
            "initialize",
            serde_json::json!({
                "protocolVersion": "2026-07-28", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}
            }),
        );
        let bootstrap = parse_jsonrpc_body_with_options(
            &serde_json::to_vec(&initialize).unwrap(),
            JsonRpcInspectionOptions::mcp_bootstrap(true),
        );
        assert!(
            bootstrap.error.is_some(),
            "sessionless initialize used legacy bootstrap"
        );
        for request in [
            initialize,
            sessionless_request("logging/setLevel", serde_json::json!({"level": "info"})),
            sessionless_request(
                "resources/subscribe",
                serde_json::json!({"uri": "file:///guide.txt"}),
            ),
            serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            serde_json::json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}}),
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
            serde_json::json!([sessionless_request("tools/list", serde_json::json!({}))]),
            sessionless_request("subscriptions/listen", serde_json::json!({})),
        ] {
            let info =
                parse_jsonrpc_body_with_options(&serde_json::to_vec(&request).unwrap(), options);
            assert!(info.error.is_some(), "accepted {request}");
        }
        let extension = parse_jsonrpc_body_with_options(
            br#"{"jsonrpc":"2.0","method":"vendor/notice","params":{}}"#,
            options,
        );
        assert!(extension.error.is_none(), "{:?}", extension.error);
        assert_eq!(
            extension.calls[0].mcp_classification,
            Some(McpMethodClassification::Extension)
        );
        assert!(extension.mcp_http_metadata.is_none());
    }

    #[test]
    fn inspection_error_kinds_distinguish_invalid_json_and_messages() {
        fn assert_inspection_error(
            body: &[u8],
            mode: JsonRpcInspectionMode,
            expected_kind: JsonRpcInspectionErrorKind,
            expected_detail: &str,
        ) {
            let info = parse_jsonrpc_body(body, mode);
            let error = info.error.as_ref().expect("inspection failure");

            assert_eq!(error.kind(), expected_kind);
            assert_eq!(error.detail(), expected_detail);
        }

        assert_inspection_error(
            b"{",
            JsonRpcInspectionMode::JsonRpc,
            JsonRpcInspectionErrorKind::InvalidJson,
            "invalid JSON",
        );
        assert_inspection_error(
            br"[]",
            JsonRpcInspectionMode::JsonRpc,
            JsonRpcInspectionErrorKind::InvalidMessage,
            "empty batch",
        );
        assert_inspection_error(
            br"null",
            JsonRpcInspectionMode::JsonRpc,
            JsonRpcInspectionErrorKind::InvalidMessage,
            "missing or non-string 'jsonrpc' field",
        );
        assert_inspection_error(
            br#"[{"jsonrpc":"2.0","id":1,"method":"reports.list"},{"id":2,"method":"reports.search"}]"#,
            JsonRpcInspectionMode::JsonRpc,
            JsonRpcInspectionErrorKind::InvalidMessage,
            "batch item invalid: missing or non-string 'jsonrpc' field",
        );
    }

    #[test]
    fn rejects_duplicate_jsonrpc_envelope_keys_before_semantic_inspection() {
        let fixtures: &[(&str, &[u8])] = &[
            (
                "jsonrpc",
                br#"{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
            ),
            (
                "id",
                br#"{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/list","params":{}}"#,
            ),
            (
                "method",
                br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"vendor/other","params":{}}"#,
            ),
            (
                "params",
                br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{},"params":{"cursor":"next"}}"#,
            ),
        ];

        for (key, body) in fixtures {
            let info =
                parse_jsonrpc_body_with_options(body, mcp_options(McpProtocolVersion::V2025_11_25));
            assert!(info.calls.is_empty());
            assert_eq!(
                info.error.as_ref().map(JsonRpcInspectionError::kind),
                Some(JsonRpcInspectionErrorKind::InvalidJson),
                "duplicate {key} must fail before MCP inspection: {info:?}"
            );
            assert!(
                info.error
                    .as_ref()
                    .is_some_and(|error| error.detail().contains(key)),
                "duplicate-key detail should identify {key}: {info:?}"
            );
        }
    }

    #[test]
    fn rejects_duplicate_keys_recursively_but_allows_same_key_in_distinct_objects() {
        let duplicate = br#"{
            "jsonrpc":"2.0",
            "id":1,
            "method":"tools/call",
            "params":{
                "name":"search_web",
                "arguments":{"query":"allowed","query":"different"}
            }
        }"#;
        let rejected = parse_jsonrpc_body_with_options(
            duplicate,
            mcp_options(McpProtocolVersion::V2025_11_25),
        );
        assert!(rejected.calls.is_empty());
        assert_eq!(
            rejected.error.as_ref().map(JsonRpcInspectionError::kind),
            Some(JsonRpcInspectionErrorKind::InvalidJson)
        );

        let distinct_objects = br#"{
            "jsonrpc":"2.0",
            "id":1,
            "method":"tools/call",
            "params":{
                "name":"search_web",
                "arguments":{"left":{"value":1},"right":{"value":2}}
            }
        }"#;
        let accepted = parse_jsonrpc_body_with_options(
            distinct_objects,
            mcp_options(McpProtocolVersion::V2025_11_25),
        );
        assert!(
            accepted.error.is_none(),
            "keys may repeat in different objects: {accepted:?}"
        );
    }

    #[test]
    fn ignores_params_when_extracting_method() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"reports.search","params":{"query":"quarterly","filters":{"scope":"workspace/main"}}}"#;
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::JsonRpc);
        assert!(info.error.is_none());
        assert_eq!(
            info.calls.first().map(|call| call.method.as_str()),
            Some("reports.search")
        );
        let call = info.calls.first().expect("single request call");
        assert!(call.params.is_empty());
        assert!(call.tool.is_none());
    }

    #[test]
    fn ignores_dotted_param_collisions_for_generic_jsonrpc() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"reports.search","params":{"filters.scope":{"value":"literal"},"filters":{"scope.value":"nested"}}}"#;
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::JsonRpc);

        assert!(info.error.is_none(), "params should be ignored: {info:?}");
        assert_eq!(
            info.calls.first().map(|call| call.method.as_str()),
            Some("reports.search")
        );
        assert!(
            info.calls
                .first()
                .is_some_and(|call| call.params.is_empty() && call.tool.is_none())
        );
    }

    #[test]
    fn mcp_mode_validates_known_methods_and_extracts_tool() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_web","arguments":{"query":"openshell"}}}"#;
        let info =
            parse_jsonrpc_body_with_options(body, mcp_options(McpProtocolVersion::V2025_11_25));

        assert!(info.error.is_none(), "expected valid MCP call: {info:?}");
        let call = info.calls.first().expect("single MCP call");
        assert_eq!(call.method, "tools/call");
        assert_eq!(call.tool.as_deref(), Some("search_web"));
        assert_eq!(
            call.params.get("name").map(String::as_str),
            Some("search_web")
        );
        assert_eq!(call.params.len(), 1);
        assert_eq!(
            call.mcp_classification,
            Some(McpMethodClassification::Available)
        );
        assert_eq!(info.mcp_revision, Some(McpProtocolVersion::V2025_11_25));
    }

    #[test]
    fn mcp_mode_rejects_non_recommended_tool_names_by_default() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read status","arguments":{}}}"#;
        let info =
            parse_jsonrpc_body_with_options(body, mcp_options(McpProtocolVersion::V2025_11_25));

        assert!(info.calls.is_empty());
        assert!(
            info.error
                .as_ref()
                .map(JsonRpcInspectionError::detail)
                .is_some_and(|error| error.contains("strict_tool_names")),
            "expected strict tool-name error, got {info:?}"
        );
    }

    #[test]
    fn mcp_mode_can_disable_strict_tool_names() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read status","arguments":{}}}"#;
        let info = parse_jsonrpc_body_with_options(
            body,
            JsonRpcInspectionOptions::mcp_selected(McpProtocolVersion::V2025_11_25, false),
        );

        let call = info
            .calls
            .first()
            .expect("permissive MCP call should parse");
        assert!(info.error.is_none(), "permissive MCP call failed: {info:?}");
        assert_eq!(call.tool.as_deref(), Some("read status"));
        assert_eq!(
            call.params.get("name").map(String::as_str),
            Some("read status")
        );
    }

    #[test]
    fn mcp_mode_rejects_invalid_known_method_params() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"query":"openshell"}}}"#;
        let info =
            parse_jsonrpc_body_with_options(body, mcp_options(McpProtocolVersion::V2025_11_25));

        assert!(info.calls.is_empty());
        assert_eq!(
            info.error.as_ref().map(JsonRpcInspectionError::kind),
            Some(JsonRpcInspectionErrorKind::InvalidMessage)
        );
        assert!(
            info.error
                .as_ref()
                .map(JsonRpcInspectionError::detail)
                .is_some_and(|error| error.contains("invalid `tools/call` params")),
            "expected MCP params validation error, got {info:?}"
        );
    }

    #[test]
    fn mcp_mode_allows_unknown_extension_methods() {
        let body =
            br#"{"jsonrpc":"2.0","id":1,"method":"vendor/extension","params":{"name":"custom"}}"#;
        let info =
            parse_jsonrpc_body_with_options(body, mcp_options(McpProtocolVersion::V2025_06_18));

        assert!(
            info.error.is_none(),
            "extension method should remain addressable"
        );
        assert_eq!(
            info.calls.first().map(|call| call.method.as_str()),
            Some("vendor/extension")
        );
        assert!(info.calls.first().is_some_and(|call| call.params.is_empty()
            && call.tool.is_none()
            && call.mcp_classification == Some(McpMethodClassification::Extension)));
    }

    #[test]
    fn mcp_mode_ignores_tool_arguments_when_extracting_policy_params() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_status","arguments":{"scope.key":"literal","scope":{"key":"nested"}}}}"#;
        let info =
            parse_jsonrpc_body_with_options(body, mcp_options(McpProtocolVersion::V2025_11_25));
        let call = info.calls.first().expect("single MCP call");

        assert!(info.error.is_none(), "expected valid MCP call: {info:?}");
        assert_eq!(call.tool.as_deref(), Some("read_status"));
        assert_eq!(
            call.params.get("name").map(String::as_str),
            Some("read_status")
        );
        assert_eq!(call.params.len(), 1);
    }

    #[test]
    fn accepts_any_valid_jsonrpc_params_shape() {
        let body =
            br#"{"jsonrpc":"2.0","id":1,"method":"reports.search","params":["ignored",{"nested":true}]}"#;
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::JsonRpc);

        assert!(info.error.is_none());
        assert_eq!(
            info.calls.first().map(|call| call.method.as_str()),
            Some("reports.search")
        );
        assert!(
            info.calls
                .first()
                .is_some_and(|call| call.params.is_empty() && call.tool.is_none())
        );
    }

    #[test]
    fn recognizes_streamable_http_get_receive_streams() {
        let request = L7Request {
            action: "GET".to_string(),
            target: "/rpc".to_string(),
            query_params: HashMap::new(),
            raw_header: b"GET /rpc HTTP/1.1\r\nHost: jsonrpc.test\r\nAccept: application/json, text/event-stream\r\n\r\n".to_vec(),
            body_length: crate::l7::provider::BodyLength::None,
        };

        assert!(jsonrpc_receive_stream_request(&request));

        let info = JsonRpcRequestInfo::receive_stream();
        assert!(info.receive_stream);
        assert!(info.error.is_none());
        assert!(info.calls.is_empty());
    }

    #[test]
    fn bodyless_get_without_sse_accept_is_not_receive_stream() {
        let request = L7Request {
            action: "GET".to_string(),
            target: "/rpc".to_string(),
            query_params: HashMap::new(),
            raw_header:
                b"GET /rpc HTTP/1.1\r\nHost: jsonrpc.test\r\nAccept: application/json\r\n\r\n"
                    .to_vec(),
            body_length: crate::l7::provider::BodyLength::None,
        };

        assert!(!jsonrpc_receive_stream_request(&request));
    }

    #[test]
    fn rejects_requests_missing_jsonrpc_version() {
        let body = br#"{"id":1,"method":"reports.list"}"#;
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::JsonRpc);

        assert!(info.calls.is_empty());
        assert_eq!(
            info.error.as_ref().map(JsonRpcInspectionError::detail),
            Some("missing or non-string 'jsonrpc' field")
        );
    }

    #[test]
    fn rejects_batch_items_missing_jsonrpc_version() {
        let body = br#"[
            {"jsonrpc":"2.0","id":1,"method":"reports.list"},
            {"id":2,"method":"reports.search","params":{"query":"quarterly"}}
        ]"#;
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::JsonRpc);

        assert!(info.calls.is_empty());
        assert!(info.is_batch);
        assert_eq!(
            info.error.as_ref().map(JsonRpcInspectionError::detail),
            Some("batch item invalid: missing or non-string 'jsonrpc' field")
        );
    }

    #[test]
    fn rejects_unsupported_jsonrpc_version() {
        let body = br#"{"jsonrpc":"1.0","id":1,"method":"reports.list"}"#;
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::JsonRpc);

        assert!(info.calls.is_empty());
        assert_eq!(
            info.error.as_ref().map(JsonRpcInspectionError::detail),
            Some("unsupported JSON-RPC version '1.0'")
        );
    }

    #[test]
    fn parses_valid_batch_without_error() {
        let body = br#"[
            {"jsonrpc":"2.0","id":1,"method":"reports.list"},
            {"jsonrpc":"2.0","id":2,"method":"reports.search","params":{"query":"quarterly"}}
        ]"#;
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::JsonRpc);
        assert!(info.error.is_none());
        assert!(info.is_batch);
        assert!(!info.has_response);
        assert_eq!(info.calls.len(), 2);
        assert_eq!(info.calls[0].method, "reports.list");
        assert_eq!(info.calls[1].method, "reports.search");
    }

    #[test]
    fn mcp_batch_acceptance_follows_the_selected_revision() {
        let body = br#"[
            {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_status","arguments":{}}},
            {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_web","arguments":{"query":"openshell"}}}
        ]"#;
        let march =
            parse_jsonrpc_body_with_options(body, mcp_options(McpProtocolVersion::V2025_03_26));

        assert!(
            march.error.is_none(),
            "March MCP batch should be valid: {march:?}"
        );
        assert!(march.is_batch);
        assert_eq!(march.calls.len(), 2);
        assert_eq!(march.calls[0].tool.as_deref(), Some("read_status"));
        assert_eq!(march.calls[1].tool.as_deref(), Some("search_web"));

        for revision in [
            McpProtocolVersion::V2025_06_18,
            McpProtocolVersion::V2025_11_25,
        ] {
            let info = parse_jsonrpc_body_with_options(body, mcp_options(revision));
            assert!(info.calls.is_empty());
            assert!(info.is_batch);
            assert_eq!(
                info.error.as_ref().map(JsonRpcInspectionError::kind),
                Some(JsonRpcInspectionErrorKind::McpProfileViolation),
                "revision {revision} must reject batches: {info:?}"
            );
        }
    }

    #[test]
    fn march_batch_limit_counts_all_top_level_messages() {
        let mut messages = (0..MAX_MCP_LEGACY_BATCH_MESSAGES)
            .map(|index| {
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": index,
                    "result": {"ok": true}
                })
            })
            .collect::<Vec<_>>();
        let at_limit = serde_json::to_vec(&serde_json::Value::Array(messages.clone()))
            .expect("serialize in-bound MCP batch fixture");
        let accepted = parse_jsonrpc_body_with_options(
            &at_limit,
            mcp_options(McpProtocolVersion::V2025_03_26),
        );
        assert!(
            accepted.error.is_none(),
            "64-member March batch should be accepted: {accepted:?}"
        );

        messages.push(serde_json::json!({
            "jsonrpc": "2.0",
            "id": MAX_MCP_LEGACY_BATCH_MESSAGES,
            "result": {"ok": true}
        }));
        let over_limit = serde_json::to_vec(&serde_json::Value::Array(messages))
            .expect("serialize over-limit MCP batch fixture");
        let info = parse_jsonrpc_body_with_options(
            &over_limit,
            mcp_options(McpProtocolVersion::V2025_03_26),
        );

        assert!(info.calls.is_empty());
        assert!(info.is_batch);
        assert_eq!(
            info.error.as_ref().map(JsonRpcInspectionError::kind),
            Some(JsonRpcInspectionErrorKind::McpProfileViolation)
        );
        assert!(
            info.error
                .as_ref()
                .is_some_and(|error| error.detail().contains("maximum is 64")),
            "expected total-message batch bound, got {info:?}"
        );
    }

    #[test]
    fn initialize_proposal_is_not_treated_as_an_effective_revision() {
        let body = br#"{
            "jsonrpc":"2.0",
            "id":"bootstrap-1",
            "method":"initialize",
            "params":{
                "protocolVersion":"2099-12-31",
                "capabilities":{},
                "clientInfo":{"name":"test-client","version":"1.0"}
            }
        }"#;
        let info =
            parse_jsonrpc_body_with_options(body, JsonRpcInspectionOptions::mcp_bootstrap(true));

        assert!(info.error.is_none(), "initialize should parse: {info:?}");
        assert_eq!(info.calls.len(), 1);
        assert_eq!(info.calls[0].method, "initialize");
        assert_eq!(
            info.calls[0].mcp_classification,
            Some(McpMethodClassification::Available)
        );
        assert_eq!(info.mcp_revision, None);
    }

    #[test]
    fn non_initialize_mcp_requires_a_transport_selected_revision() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
        let info =
            parse_jsonrpc_body_with_options(body, JsonRpcInspectionOptions::mcp_bootstrap(true));

        assert!(info.calls.is_empty());
        assert_eq!(
            info.error.as_ref().map(JsonRpcInspectionError::kind),
            Some(JsonRpcInspectionErrorKind::RevisionNotSelected)
        );
    }

    #[test]
    fn known_method_unavailable_in_selected_revision_is_rejected() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{"taskId":"task-1"}}"#;
        let info =
            parse_jsonrpc_body_with_options(body, mcp_options(McpProtocolVersion::V2025_06_18));

        assert!(info.calls.is_empty());
        assert_eq!(
            info.error.as_ref().map(JsonRpcInspectionError::kind),
            Some(JsonRpcInspectionErrorKind::McpProfileViolation)
        );
        assert!(
            info.error
                .as_ref()
                .is_some_and(|error| error.detail().contains("tasks/get")),
            "expected unavailable-method evidence, got {info:?}"
        );
    }

    #[test]
    fn server_originated_method_is_rejected_in_client_to_server_direction() {
        let body = br#"{
            "jsonrpc":"2.0",
            "id":1,
            "method":"sampling/createMessage",
            "params":{"messages":[],"maxTokens":1}
        }"#;
        let info =
            parse_jsonrpc_body_with_options(body, mcp_options(McpProtocolVersion::V2025_03_26));

        assert!(info.calls.is_empty());
        assert_eq!(
            info.error.as_ref().map(JsonRpcInspectionError::kind),
            Some(JsonRpcInspectionErrorKind::McpProfileViolation)
        );
        assert!(
            info.error
                .as_ref()
                .is_some_and(|error| error.detail().contains("client-to-server")),
            "expected direction mismatch evidence, got {info:?}"
        );
    }

    #[test]
    fn mcp_initialize_is_not_valid_in_a_batch() {
        let body = br#"[
            {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}},
            {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_status","arguments":{}}}
        ]"#;
        let info =
            parse_jsonrpc_body_with_options(body, JsonRpcInspectionOptions::mcp_bootstrap(true));

        assert!(info.is_batch);
        assert!(info.calls.is_empty());
        assert!(!info.has_response);
        assert_eq!(
            info.error.as_ref().map(JsonRpcInspectionError::detail),
            Some("MCP `initialize` must be exactly one non-batched request")
        );
    }

    #[test]
    fn generic_jsonrpc_keeps_batch_initialize_behavior() {
        let body = br#"[
            {"jsonrpc":"2.0","id":1,"method":"initialize","params":{}},
            {"jsonrpc":"2.0","id":2,"method":"reports.list","params":{}}
        ]"#;
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::JsonRpc);

        assert!(
            info.error.is_none(),
            "generic batch should remain valid: {info:?}"
        );
        assert!(info.is_batch);
        assert_eq!(info.calls.len(), 2);
    }

    #[test]
    fn parses_batch_with_calls_and_responses() {
        let body = br#"[
            {"jsonrpc":"2.0","id":1,"method":"reports.list"},
            {"jsonrpc":"2.0","id":2,"result":{"ok":true}}
        ]"#;
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::JsonRpc);

        assert!(info.error.is_none());
        assert!(info.is_batch);
        assert!(info.has_response);
        assert_eq!(info.calls.len(), 1);
        assert_eq!(info.calls[0].method, "reports.list");
    }

    #[test]
    fn rejects_invalid_jsonrpc_response_body() {
        let body =
            br#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-32603,"message":"failed"}}"#;
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::JsonRpc);

        assert!(info.calls.is_empty());
        assert!(!info.has_response);
        assert_eq!(
            info.error.as_ref().map(JsonRpcInspectionError::detail),
            Some("JSON-RPC response includes both result and error")
        );
    }

    #[test]
    fn rejects_message_with_method_and_result_or_error() {
        let result_body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","result":{}}"#;
        let result_info = parse_jsonrpc_body(result_body, JsonRpcInspectionMode::JsonRpc);
        assert!(result_info.calls.is_empty());
        assert_eq!(
            result_info
                .error
                .as_ref()
                .map(JsonRpcInspectionError::detail),
            Some("JSON-RPC message includes both method and result/error")
        );

        let error_body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","error":{"code":-32603,"message":"failed"}}"#;
        let error_info = parse_jsonrpc_body(error_body, JsonRpcInspectionMode::JsonRpc);
        assert!(error_info.calls.is_empty());
        assert_eq!(
            error_info
                .error
                .as_ref()
                .map(JsonRpcInspectionError::detail),
            Some("JSON-RPC message includes both method and result/error")
        );
    }

    #[test]
    fn rejects_batch_item_with_method_and_result() {
        let body = br#"[
            {"jsonrpc":"2.0","id":1,"method":"reports.list"},
            {"jsonrpc":"2.0","id":2,"method":"initialize","result":{}}
        ]"#;
        let info = parse_jsonrpc_body(body, JsonRpcInspectionMode::JsonRpc);

        assert!(info.calls.is_empty());
        assert!(info.is_batch);
        assert_eq!(
            info.error.as_ref().map(JsonRpcInspectionError::detail),
            Some("batch item invalid: JSON-RPC message includes both method and result/error")
        );
    }
}
