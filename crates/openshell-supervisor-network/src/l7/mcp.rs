// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MCP Streamable HTTP revision selection and request metadata validation.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use openshell_core::mcp::McpProtocolVersion;

use crate::l7::jsonrpc::JsonRpcRequestInfo;
use crate::l7::provider::L7Request;

const MCP_PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";
const MCP_METHOD_HEADER: &str = "mcp-method";
const MCP_NAME_HEADER: &str = "mcp-name";

/// Protocol revision selected for one MCP HTTP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum McpRequestProtocolVersion {
    /// A valid standalone legacy initialize request negotiates its revision in the body.
    Initialization,
    /// A request selected an exact revision from its header or the legacy fallback.
    Selected(McpProtocolVersion),
}

/// Failure to select a policy-allowed protocol revision for an MCP HTTP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum McpProtocolVersionError {
    /// The HTTP header block could not yield one unambiguous end-to-end value.
    InvalidHeader,
    /// The header value is not an MCP revision supported by this `OpenShell` build.
    UnsupportedHeaderValue,
    /// Required HTTP metadata is missing, malformed, or differs from the inspected body.
    InvalidRequestMetadata,
    /// The selected revision does not support this HTTP method.
    MethodNotAllowed,
    /// The selected supported revision is absent from the endpoint allowlist.
    NotAllowed(McpProtocolVersion),
}

impl McpProtocolVersionError {
    /// Return the HTTP status for this transport or policy rejection.
    #[must_use]
    pub(super) const fn http_status(self) -> &'static str {
        match self {
            Self::InvalidHeader | Self::UnsupportedHeaderValue | Self::InvalidRequestMetadata => {
                "400 Bad Request"
            }
            Self::MethodNotAllowed => "405 Method Not Allowed",
            Self::NotAllowed(_) => "403 Forbidden",
        }
    }

    /// Return a stable machine-readable response code.
    #[must_use]
    pub(super) const fn response_code(self) -> &'static str {
        match self {
            Self::InvalidHeader => "invalid_mcp_protocol_version_header",
            Self::UnsupportedHeaderValue => "unsupported_mcp_protocol_version",
            Self::InvalidRequestMetadata => "invalid_mcp_request_metadata",
            Self::MethodNotAllowed => "mcp_http_method_not_allowed",
            Self::NotAllowed(_) => "mcp_protocol_version_not_allowed",
        }
    }
}

impl std::fmt::Display for McpProtocolVersionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidHeader => formatter.write_str(
                "MCP-Protocol-Version must contain one non-empty end-to-end header value",
            ),
            Self::UnsupportedHeaderValue => {
                formatter.write_str("MCP-Protocol-Version names an unsupported protocol version")
            }
            Self::InvalidRequestMetadata => {
                formatter.write_str("MCP request headers must match the inspected request metadata")
            }
            Self::MethodNotAllowed => {
                formatter.write_str("MCP protocol version 2026-07-28 requires HTTP POST")
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
/// Legacy initialization negotiates its revision in the body. It cannot exempt
/// an explicit `2026-07-28` request or an endpoint allowing only that revision.
/// An absent header otherwise selects the `2025-03-26` fallback; the selected
/// revision must appear in the endpoint allowlist.
pub(super) fn select_request_protocol_version(
    request: &L7Request,
    info: &JsonRpcRequestInfo,
    allowed_versions: &[McpProtocolVersion],
) -> Result<McpRequestProtocolVersion, McpProtocolVersionError> {
    let header = request_protocol_version_header(&request.raw_header)?;
    let version = match header {
        Some(value) => value
            .parse::<McpProtocolVersion>()
            .map_err(|_| McpProtocolVersionError::UnsupportedHeaderValue)?,
        None => McpProtocolVersion::V2025_03_26,
    };
    let modern_only = !allowed_versions.is_empty()
        && allowed_versions
            .iter()
            .all(|version| *version == McpProtocolVersion::V2026_07_28);
    if is_standalone_initialize(info) && version != McpProtocolVersion::V2026_07_28 && !modern_only
    {
        return Ok(McpRequestProtocolVersion::Initialization);
    }

    if !allowed_versions.contains(&version) {
        return Err(McpProtocolVersionError::NotAllowed(version));
    }
    // Sessionless MCP carries each message in its own POST. Standalone GET
    // streams and DELETE session termination belong to the legacy revisions.
    if version == McpProtocolVersion::V2026_07_28 && request.action != "POST" {
        return Err(McpProtocolVersionError::MethodNotAllowed);
    }

    Ok(McpRequestProtocolVersion::Selected(version))
}

/// Match the sessionless revision's mandatory HTTP mirrors to the inspected body.
///
/// Only validated request bodies carry this metadata. Extension notifications
/// have no specified mirrored-header contract; unknown `Mcp-Param-*` fields are
/// also left to the server that owns the tool schema.
pub(super) fn validate_request_metadata(
    request: &L7Request,
    info: &JsonRpcRequestInfo,
) -> Result<(), McpProtocolVersionError> {
    if info.mcp_revision != Some(McpProtocolVersion::V2026_07_28) {
        return Ok(());
    }
    let Some(metadata) = &info.mcp_http_metadata else {
        return Ok(());
    };
    let invalid = McpProtocolVersionError::InvalidRequestMetadata;
    let version = request_header_value(&request.raw_header, MCP_PROTOCOL_VERSION_HEADER)
        .map_err(|_| invalid)?
        .ok_or(invalid)?;
    if version != McpProtocolVersion::V2026_07_28.as_str() {
        return Err(invalid);
    }
    let method = request_header_value(&request.raw_header, MCP_METHOD_HEADER)
        .map_err(|_| invalid)?
        .ok_or(invalid)?;
    if !is_plain_header_value(method) || method != metadata.method {
        return Err(invalid);
    }
    if let Some(name) = &metadata.name {
        let value = request_header_value(&request.raw_header, MCP_NAME_HEADER)
            .map_err(|_| invalid)?
            .ok_or(invalid)?;
        // Decoding happens before equality so header-based routing and
        // body-based policy authorize the same tool, prompt, or resource.
        if decode_name_header(value)? != *name {
            return Err(invalid);
        }
    }
    Ok(())
}

fn is_plain_header_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte == b'\t' || (b' '..=b'~').contains(&byte))
}

fn decode_name_header(value: &str) -> Result<String, McpProtocolVersionError> {
    if let Some(encoded) = value
        .strip_prefix("=?base64?")
        .and_then(|value| value.strip_suffix("?="))
    {
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|_| McpProtocolVersionError::InvalidRequestMetadata)?;
        return String::from_utf8(bytes)
            .map_err(|_| McpProtocolVersionError::InvalidRequestMetadata);
    }
    if !is_plain_header_value(value) {
        return Err(McpProtocolVersionError::InvalidRequestMetadata);
    }
    Ok(value.to_string())
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
    request_header_value(raw_header, MCP_PROTOCOL_VERSION_HEADER)
}

fn request_header_value<'a>(
    raw_header: &'a [u8],
    header_name: &str,
) -> Result<Option<&'a str>, McpProtocolVersionError> {
    let header_end = raw_header
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(McpProtocolVersionError::InvalidHeader)?
        + 4;
    let headers = std::str::from_utf8(&raw_header[..header_end])
        .map_err(|_| McpProtocolVersionError::InvalidHeader)?;
    // Forwarding removes Connection-nominated fields. Required MCP metadata
    // must survive that cleanup, including after middleware rebuilds.
    let nominated = crate::l7::rest::connection_nominated_header_names(&raw_header[..header_end])
        .map_err(|_| McpProtocolVersionError::InvalidHeader)?;
    if nominated.contains(header_name) {
        return Err(McpProtocolVersionError::InvalidHeader);
    }
    let mut values = headers.split("\r\n").skip(1).filter_map(|line| {
        let (name, value) = line.split_once(':')?;
        // HTTP field-value optional whitespace is only SP or HTAB. Using
        // Unicode whitespace trimming here would accept bytes that are part
        // of the protocol-version value rather than HTTP framing.
        name.eq_ignore_ascii_case(header_name)
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
    use crate::l7::jsonrpc::{JsonRpcInspectionMode, McpHttpRequestMetadata, parse_jsonrpc_body};
    use crate::l7::provider::BodyLength;
    use std::fmt::Write as _;

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

    fn modern_request_info(method: &str, name: Option<&str>) -> JsonRpcRequestInfo {
        JsonRpcRequestInfo {
            calls: Vec::new(),
            is_batch: false,
            receive_stream: false,
            has_response: false,
            mcp_revision: Some(McpProtocolVersion::V2026_07_28),
            mcp_http_metadata: Some(McpHttpRequestMetadata {
                method: method.to_string(),
                name: name.map(str::to_string),
            }),
            error: None,
        }
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
    fn protocol_version_must_remain_an_end_to_end_field() {
        for connection_options in [
            "mcp-protocol-version",
            "keep-alive, MCP-Protocol-Version",
            "\tMcp-Protocol-Version\t, close",
        ] {
            let headers = request("POST", &format!("Connection: {connection_options}\r\n"));
            assert_eq!(
                request_protocol_version_header(&headers.raw_header),
                Err(McpProtocolVersionError::InvalidHeader),
                "revision metadata cannot be declared hop-by-hop"
            );
        }
        let headers = request("POST", "Connection: keep-alive, x-request-id\r\n");
        assert_eq!(
            request_protocol_version_header(&headers.raw_header),
            Ok(None)
        );
    }

    #[test]
    fn unsupported_or_non_exact_header_values_are_bad_requests() {
        let info = request_info(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);

        for value in [
            "2099-01-01",
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

    #[test]
    fn sessionless_revision_requires_explicit_policy_opt_in() {
        let info = modern_request_info("server/discover", None);
        let request = request("POST", "MCP-Protocol-Version: 2026-07-28\r\n");

        assert_eq!(
            select_request_protocol_version(&request, &info, &[McpProtocolVersion::V2025_11_25],),
            Err(McpProtocolVersionError::NotAllowed(
                McpProtocolVersion::V2026_07_28
            ))
        );
        assert_eq!(
            select_request_protocol_version(&request, &info, &[McpProtocolVersion::V2026_07_28],),
            Ok(McpRequestProtocolVersion::Selected(
                McpProtocolVersion::V2026_07_28
            ))
        );
    }

    #[test]
    fn initialize_cannot_exempt_sessionless_requests_from_revision_selection() {
        let info = request_info(
            br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#,
        );
        assert_eq!(
            select_request_protocol_version(
                &request("POST", "MCP-Protocol-Version: 2026-07-28\r\n"),
                &info,
                &[McpProtocolVersion::V2026_07_28],
            ),
            Ok(McpRequestProtocolVersion::Selected(
                McpProtocolVersion::V2026_07_28
            ))
        );
        assert_eq!(
            select_request_protocol_version(
                &request("POST", ""),
                &info,
                &[McpProtocolVersion::V2026_07_28],
            ),
            Err(McpProtocolVersionError::NotAllowed(
                McpProtocolVersion::V2025_03_26
            ))
        );
        assert_eq!(
            select_request_protocol_version(
                &request("POST", "MCP-Protocol-Version: \r\n"),
                &info,
                &[McpProtocolVersion::V2025_11_25],
            ),
            Err(McpProtocolVersionError::InvalidHeader)
        );
    }

    #[test]
    fn sessionless_revision_accepts_only_post() {
        let info = modern_request_info("subscriptions/listen", None);
        for method in ["GET", "DELETE", "PUT", "post"] {
            let error = select_request_protocol_version(
                &request(method, "MCP-Protocol-Version: 2026-07-28\r\n"),
                &info,
                &[McpProtocolVersion::V2026_07_28],
            )
            .expect_err("sessionless messages require POST");
            assert_eq!(error, McpProtocolVersionError::MethodNotAllowed);
            assert_eq!(error.http_status(), "405 Method Not Allowed");
        }
    }

    #[test]
    fn sessionless_standard_headers_match_each_request_shape() {
        for (method, name) in [
            ("server/discover", None),
            ("subscriptions/listen", None),
            ("example/extension", None),
            ("tools/call", Some("get_weather")),
            ("prompts/get", Some("summarize")),
            ("resources/read", Some("file:///documents/readme.txt")),
        ] {
            let mut headers =
                format!("mCp-PrOtOcOl-VeRsIoN:\t2026-07-28 \r\nMcP-MeThOd: {method}\t\r\n");
            if let Some(name) = name {
                write!(headers, "mCp-NaMe: {name}\r\n").unwrap();
            }
            assert_eq!(
                validate_request_metadata(
                    &request("POST", &headers),
                    &modern_request_info(method, name),
                ),
                Ok(()),
                "standard metadata for {method} must match its body fields"
            );
        }
    }

    #[test]
    fn sessionless_metadata_requires_unambiguous_matching_headers() {
        let info = modern_request_info("tools/call", Some("get_weather"));
        let valid = "MCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: get_weather\r\n";
        for headers in [
            valid.replace("MCP-Protocol-Version: 2026-07-28\r\n", ""),
            valid.replace("2026-07-28", "2025-11-25"),
            valid.replace("Mcp-Method: tools/call\r\n", ""),
            valid.replace("tools/call", "Tools/Call"),
            valid.replace("Mcp-Name: get_weather\r\n", ""),
            valid.replace("get_weather", ""),
            valid.replace("get_weather", "Get_Weather"),
            format!("{valid}mcp-protocol-version: 2026-07-28\r\n"),
            format!("{valid}mcp-method: tools/call\r\n"),
            format!("{valid}mcp-name: get_weather\r\n"),
            format!("{valid}Connection: keep-alive, MCP-Protocol-Version\r\n"),
            format!("{valid}Connection: keep-alive, Mcp-Method\r\n"),
            format!("{valid}Connection: keep-alive, Mcp-Name\r\n"),
        ] {
            assert_eq!(
                validate_request_metadata(&request("POST", &headers), &info),
                Err(McpProtocolVersionError::InvalidRequestMetadata),
                "invalid headers: {headers:?}"
            );
        }
    }

    #[test]
    fn sessionless_names_decode_utf8_base64_before_matching() {
        for name in ["天気", " padded ", "=?base64?literal?=", "line1\nline2"] {
            let encoded = STANDARD.encode(name);
            let headers = format!(
                "MCP-Protocol-Version: 2026-07-28\r\nMcp-Method: prompts/get\r\nMcp-Name: =?base64?{encoded}?=\r\n"
            );
            assert_eq!(
                validate_request_metadata(
                    &request("POST", &headers),
                    &modern_request_info("prompts/get", Some(name)),
                ),
                Ok(())
            );
        }
    }

    #[test]
    fn sessionless_names_reject_invalid_encoding_and_unsafe_plain_values() {
        for (name, value) in [
            ("天気", "天気"),
            (" padded ", " padded "),
            ("=?base64?literal?=", "=?base64?literal?="),
            ("weather", "=?base64?%%%?="),
            ("weather", "=?base64?/w==?="),
            ("weather", "=?BASE64?d2VhdGhlcg==?="),
            ("bad\u{7f}name", "bad\u{7f}name"),
        ] {
            let headers = format!(
                "MCP-Protocol-Version: 2026-07-28\r\nMcp-Method: prompts/get\r\nMcp-Name: {value}\r\n"
            );
            assert_eq!(
                validate_request_metadata(
                    &request("POST", &headers),
                    &modern_request_info("prompts/get", Some(name)),
                ),
                Err(McpProtocolVersionError::InvalidRequestMetadata)
            );
        }
    }

    #[test]
    fn sessionless_mirrors_leave_unknown_headers_and_removed_session_fields_alone() {
        let info = modern_request_info("tools/call", Some("get_weather"));
        let headers = "MCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: get_weather\r\nMcp-Param-Region: west\r\nMcp-Session-Id: unused\r\nLast-Event-ID: unused\r\n";
        assert_eq!(
            validate_request_metadata(&request("POST", headers), &info),
            Ok(())
        );
    }

    #[test]
    fn mirrored_headers_are_not_required_for_legacy_or_extension_notifications() {
        let request = request("POST", "");
        let mut info = modern_request_info("example/notification", None);
        info.mcp_http_metadata = None;
        assert_eq!(validate_request_metadata(&request, &info), Ok(()));

        let mut info = modern_request_info("tools/call", Some("weather"));
        info.mcp_revision = Some(McpProtocolVersion::V2025_11_25);
        assert_eq!(validate_request_metadata(&request, &info), Ok(()));
    }
}
