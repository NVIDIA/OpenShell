// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::mcp::McpProtocolVersion;
use std::collections::HashMap;
use std::fmt;

pub const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024;

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
    pub fn invalid_json() -> Self {
        Self {
            kind: JsonRpcInspectionErrorKind::InvalidJson,
            detail: "invalid JSON".to_string(),
        }
    }

    pub fn invalid_json_with_detail(detail: impl Into<String>) -> Self {
        Self {
            kind: JsonRpcInspectionErrorKind::InvalidJson,
            detail: detail.into(),
        }
    }

    pub fn invalid_message(detail: impl Into<String>) -> Self {
        Self {
            kind: JsonRpcInspectionErrorKind::InvalidMessage,
            detail: detail.into(),
        }
    }

    pub fn revision_not_selected() -> Self {
        Self {
            kind: JsonRpcInspectionErrorKind::RevisionNotSelected,
            detail: "MCP effective protocol revision has not been selected".to_string(),
        }
    }

    pub fn mcp_profile_violation(detail: impl Into<String>) -> Self {
        Self {
            kind: JsonRpcInspectionErrorKind::McpProfileViolation,
            detail: detail.into(),
        }
    }

    pub fn mcp_lifecycle_violation(detail: impl Into<String>) -> Self {
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
    pub fn rejection_reason(&self) -> String {
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
    pub fn rejected(is_batch: bool, error: JsonRpcInspectionError) -> Self {
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
    pub fn receive_stream() -> Self {
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
