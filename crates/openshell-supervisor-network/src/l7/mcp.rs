// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MCP Streamable HTTP request-version selection.

use openshell_core::mcp::McpProtocolVersion;

use crate::l7::jsonrpc::JsonRpcRequestInfo;
use crate::l7::provider::L7Request;

const MCP_PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";

/// Protocol revision selected for one MCP HTTP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum McpRequestProtocolVersion {
    /// A valid standalone initialize request selects its revision in the JSON-RPC body.
    Initialization,
    /// A subsequent request selected an exact revision from its header or the legacy fallback.
    Selected(McpProtocolVersion),
}

/// Failure to select a policy-allowed protocol revision for an MCP HTTP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum McpProtocolVersionError {
    /// The HTTP header block could not yield one unambiguous header value.
    InvalidHeader,
    /// The header value is not an MCP revision supported by this `OpenShell` build.
    UnsupportedHeaderValue,
    /// The selected supported revision is absent from the endpoint allowlist.
    NotAllowed(McpProtocolVersion),
}

impl McpProtocolVersionError {
    /// Return the HTTP status for this transport or policy rejection.
    #[must_use]
    pub(super) const fn http_status(self) -> &'static str {
        match self {
            Self::InvalidHeader | Self::UnsupportedHeaderValue => "400 Bad Request",
            Self::NotAllowed(_) => "403 Forbidden",
        }
    }

    /// Return a stable machine-readable response code.
    #[must_use]
    pub(super) const fn response_code(self) -> &'static str {
        match self {
            Self::InvalidHeader => "invalid_mcp_protocol_version_header",
            Self::UnsupportedHeaderValue => "unsupported_mcp_protocol_version",
            Self::NotAllowed(_) => "mcp_protocol_version_not_allowed",
        }
    }
}

impl std::fmt::Display for McpProtocolVersionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidHeader => formatter
                .write_str("MCP-Protocol-Version must contain exactly one non-empty header value"),
            Self::UnsupportedHeaderValue => {
                formatter.write_str("MCP-Protocol-Version names an unsupported protocol version")
            }
            Self::NotAllowed(version) => write!(
                formatter,
                "MCP protocol version {version} is not allowed by endpoint policy"
            ),
        }
    }
}

impl std::error::Error for McpProtocolVersionError {}

/// Select and authorize the protocol revision for one MCP HTTP request.
///
/// MCP initialization negotiates its revision in the JSON-RPC body and is the
/// only request exempt from the header. Every other request is self-contained:
/// an absent header selects the specification-defined `2025-03-26` fallback,
/// and the resulting supported revision must appear in the endpoint allowlist.
pub(super) fn select_request_protocol_version(
    request: &L7Request,
    info: &JsonRpcRequestInfo,
    allowed_versions: &[McpProtocolVersion],
) -> Result<McpRequestProtocolVersion, McpProtocolVersionError> {
    if is_standalone_initialize(info) {
        return Ok(McpRequestProtocolVersion::Initialization);
    }

    let version = match request_protocol_version_header(&request.raw_header)? {
        Some(value) => value
            .parse::<McpProtocolVersion>()
            .map_err(|_| McpProtocolVersionError::UnsupportedHeaderValue)?,
        None => McpProtocolVersion::V2025_03_26,
    };
    if !allowed_versions.contains(&version) {
        return Err(McpProtocolVersionError::NotAllowed(version));
    }

    Ok(McpRequestProtocolVersion::Selected(version))
}

fn is_standalone_initialize(info: &JsonRpcRequestInfo) -> bool {
    !info.is_batch
        && !info.has_response
        && info.error.is_none()
        && matches!(
            info.calls.as_slice(),
            [call] if call.method == "initialize" && !call.is_notification
        )
}

fn request_protocol_version_header(
    raw_header: &[u8],
) -> Result<Option<&str>, McpProtocolVersionError> {
    let header_end = raw_header
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(McpProtocolVersionError::InvalidHeader)?
        + 4;
    let headers = std::str::from_utf8(&raw_header[..header_end])
        .map_err(|_| McpProtocolVersionError::InvalidHeader)?;
    let mut values = headers.split("\r\n").skip(1).filter_map(|line| {
        let (name, value) = line.split_once(':')?;
        // HTTP field-value optional whitespace is only SP or HTAB. Using
        // Unicode whitespace trimming here would accept bytes that are part
        // of the protocol-version value rather than HTTP framing.
        name.eq_ignore_ascii_case(MCP_PROTOCOL_VERSION_HEADER)
            .then_some(value.trim_matches([' ', '\t']))
    });
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if value.is_empty() || values.next().is_some() {
        return Err(McpProtocolVersionError::InvalidHeader);
    }
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l7::jsonrpc::{JsonRpcInspectionMode, parse_jsonrpc_body};
    use crate::l7::provider::BodyLength;

    fn request(method: &str, headers: &str) -> L7Request {
        L7Request {
            action: method.to_string(),
            target: "/mcp".to_string(),
            query_params: std::collections::HashMap::new(),
            raw_header: format!("{method} /mcp HTTP/1.1\r\nHost: example.test\r\n{headers}\r\n")
                .into_bytes(),
            body_length: BodyLength::None,
        }
    }

    fn request_info(body: &[u8]) -> JsonRpcRequestInfo {
        parse_jsonrpc_body(body, JsonRpcInspectionMode::Mcp)
    }

    #[test]
    fn standalone_initialize_uses_body_negotiation_only() {
        let info = request_info(
            br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#,
        );

        assert_eq!(
            select_request_protocol_version(&request("POST", ""), &info, &[]),
            Ok(McpRequestProtocolVersion::Initialization)
        );
    }

    #[test]
    fn initialize_notification_is_not_treated_as_initialization() {
        let info = request_info(br#"{"jsonrpc":"2.0","method":"initialize","params":{}}"#);

        assert_eq!(
            select_request_protocol_version(
                &request("POST", ""),
                &info,
                &[McpProtocolVersion::V2025_03_26]
            ),
            Ok(McpRequestProtocolVersion::Selected(
                McpProtocolVersion::V2025_03_26
            ))
        );
    }

    #[test]
    fn subsequent_requests_select_exact_header_for_every_http_method() {
        let info = request_info(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);

        for method in ["POST", "GET", "DELETE"] {
            assert_eq!(
                select_request_protocol_version(
                    &request(method, "MCP-Protocol-Version: 2025-11-25\r\n"),
                    &info,
                    &[McpProtocolVersion::V2025_11_25]
                ),
                Ok(McpRequestProtocolVersion::Selected(
                    McpProtocolVersion::V2025_11_25
                )),
                "method {method} must use the same per-request selection"
            );
        }
    }

    #[test]
    fn missing_header_uses_only_the_legacy_specification_fallback() {
        let info = request_info(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);

        assert_eq!(
            select_request_protocol_version(
                &request("POST", ""),
                &info,
                &[McpProtocolVersion::V2025_03_26]
            ),
            Ok(McpRequestProtocolVersion::Selected(
                McpProtocolVersion::V2025_03_26
            ))
        );
        assert_eq!(
            select_request_protocol_version(
                &request("POST", ""),
                &info,
                &[McpProtocolVersion::V2025_11_25]
            ),
            Err(McpProtocolVersionError::NotAllowed(
                McpProtocolVersion::V2025_03_26
            ))
        );
    }

    #[test]
    fn repeated_or_empty_headers_are_bad_requests() {
        let info = request_info(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);

        for headers in [
            "MCP-Protocol-Version:\r\n",
            "MCP-Protocol-Version: 2025-11-25\r\nMCP-Protocol-Version: 2025-11-25\r\n",
            "MCP-Protocol-Version: 2025-03-26\r\nmcp-protocol-version: 2025-11-25\r\n",
        ] {
            assert_eq!(
                select_request_protocol_version(
                    &request("POST", headers),
                    &info,
                    &[McpProtocolVersion::V2025_11_25]
                ),
                Err(McpProtocolVersionError::InvalidHeader)
            );
        }
    }

    #[test]
    fn unsupported_or_non_exact_header_values_are_bad_requests() {
        let info = request_info(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);

        for value in [
            "2026-07-28",
            "2025-11-25, 2025-03-26",
            "2025-11-25x",
            "\u{00a0}2025-11-25",
        ] {
            assert_eq!(
                select_request_protocol_version(
                    &request("POST", &format!("MCP-Protocol-Version: {value}\r\n")),
                    &info,
                    &[McpProtocolVersion::V2025_11_25]
                ),
                Err(McpProtocolVersionError::UnsupportedHeaderValue)
            );
        }
    }

    #[test]
    fn supported_but_disallowed_header_is_forbidden() {
        let info = request_info(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);

        let error = select_request_protocol_version(
            &request("POST", "MCP-Protocol-Version: 2025-06-18\r\n"),
            &info,
            &[McpProtocolVersion::V2025_11_25],
        )
        .expect_err("supported revision is outside endpoint policy");
        assert_eq!(
            error,
            McpProtocolVersionError::NotAllowed(McpProtocolVersion::V2025_06_18)
        );
        assert_eq!(error.http_status(), "403 Forbidden");
    }
}
