// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{sign, SignableBody, SignableRequest, SigningSettings};
use aws_sigv4::sign::v4;
use aws_smithy_runtime_api::client::identity::Identity;
use std::time::SystemTime;

pub fn extract_aws_region_and_service(host: &str) -> Option<(String, String)> {
    // Pattern: <service>.<region>.amazonaws.com
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 4 && parts[parts.len() - 2] == "amazonaws" && parts[parts.len() - 1] == "com"
    {
        let raw_service = parts[0];
        let region = parts[1].to_string();
        let service = normalize_aws_signing_name(raw_service).to_string();
        Some((region, service))
    } else {
        None
    }
}

// AWS services have signing name overrides that differ from hostname
// prefixes. The full SDK embeds these per-service (e.g.
// aws-sdk-bedrockruntime hardcodes SigningName("bedrock")). There is
// no lightweight crate for this mapping, so we maintain our own table.
fn normalize_aws_signing_name(hostname_prefix: &str) -> &str {
    match hostname_prefix {
        "bedrock-runtime" | "bedrock-agent" | "bedrock-agent-runtime" => "bedrock",
        other => other,
    }
}

/// Strip AWS auth headers from raw HTTP request bytes.
///
/// Removes Authorization, X-Amz-Date, X-Amz-Security-Token, and
/// X-Amz-Content-Sha256 headers so the request can pass through the
/// proxy's fail-closed placeholder scan before SigV4 re-signing.
pub fn strip_aws_headers(raw: &[u8]) -> Vec<u8> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(raw.len(), |p| p + 4);

    let header_str = String::from_utf8_lossy(&raw[..header_end]);
    let lines: Vec<&str> = header_str.split("\r\n").collect();

    let mut output = Vec::with_capacity(raw.len());

    for (i, line) in lines.iter().enumerate() {
        if i == 0 {
            output.extend_from_slice(line.as_bytes());
            output.extend_from_slice(b"\r\n");
            continue;
        }
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("authorization:")
            || lower.starts_with("x-amz-date:")
            || lower.starts_with("x-amz-security-token:")
            || lower.starts_with("x-amz-content-sha256:")
        {
            continue;
        }
        output.extend_from_slice(line.as_bytes());
        output.extend_from_slice(b"\r\n");
    }

    output.extend_from_slice(b"\r\n");

    if header_end < raw.len() {
        output.extend_from_slice(&raw[header_end..]);
    }

    output
}

/// Apply SigV4 signing to a raw HTTP request buffer.
///
/// Strips existing AWS auth headers, computes a new SigV4 signature using
/// the official `aws-sigv4` crate, and returns the rewritten request bytes.
pub fn apply_sigv4_to_request(
    raw: &[u8],
    host: &str,
    region: &str,
    service: &str,
    access_key: &str,
    secret_key: &str,
) -> Vec<u8> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(raw.len(), |p| p + 4);

    let body = if header_end < raw.len() {
        &raw[header_end..]
    } else {
        &[]
    };

    let header_str = String::from_utf8_lossy(&raw[..header_end]);
    let lines: Vec<&str> = header_str.split("\r\n").collect();

    let (method, path) = if let Some(first_line) = lines.first() {
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            (parts[0], parts[1])
        } else {
            ("GET", "/")
        }
    } else {
        ("GET", "/")
    };

    // Collect existing headers, skipping AWS auth headers we'll replace
    let mut existing_headers: Vec<(String, String)> = Vec::new();
    for line in lines.iter().skip(1) {
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("authorization:")
            || lower.starts_with("x-amz-date:")
            || lower.starts_with("x-amz-security-token:")
            || lower.starts_with("x-amz-content-sha256:")
        {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            existing_headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    let uri = format!("https://{host}{path}");

    let identity: Identity = Credentials::new(
        access_key,
        secret_key,
        None,
        None,
        "openshell",
    )
    .into();

    let signing_params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name(service)
        .time(SystemTime::now())
        .settings(SigningSettings::default())
        .build()
        .expect("all required signing params provided")
        .into();

    let signable_request = SignableRequest::new(
        method,
        &uri,
        existing_headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str())),
        SignableBody::Bytes(body),
    )
    .expect("valid signable request");

    let (instructions, _signature) = sign(signable_request, &signing_params)
        .expect("signing should not fail with valid inputs")
        .into_parts();

    // Rebuild the request with signed headers
    let mut output = Vec::with_capacity(raw.len() + 256);

    // Request line
    if let Some(first_line) = lines.first() {
        output.extend_from_slice(first_line.as_bytes());
        output.extend_from_slice(b"\r\n");
    }

    // Existing headers (filtered)
    for (k, v) in &existing_headers {
        output.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }

    // Signed headers from the SDK
    for (name, value) in instructions.headers() {
        output.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }

    // End of headers
    output.extend_from_slice(b"\r\n");

    // Body
    output.extend_from_slice(body);

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_region_and_service_from_hostname() {
        let (region, service) =
            extract_aws_region_and_service("bedrock-runtime.us-east-2.amazonaws.com").unwrap();
        assert_eq!(region, "us-east-2");
        assert_eq!(service, "bedrock");
    }

    #[test]
    fn extract_sts_from_hostname() {
        let (region, service) =
            extract_aws_region_and_service("sts.us-east-1.amazonaws.com").unwrap();
        assert_eq!(region, "us-east-1");
        assert_eq!(service, "sts");
    }

    #[test]
    fn non_aws_hostname_returns_none() {
        assert!(extract_aws_region_and_service("api.anthropic.com").is_none());
    }

    #[test]
    fn sign_produces_valid_format() {
        let raw = b"POST /model/us.anthropic.claude-sonnet-4-6/invoke HTTP/1.1\r\nHost: bedrock-runtime.us-east-2.amazonaws.com\r\nContent-Type: application/json\r\n\r\n{}";
        let result = apply_sigv4_to_request(
            raw,
            "bedrock-runtime.us-east-2.amazonaws.com",
            "us-east-2",
            "bedrock",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        );
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"));
        assert!(result_str.contains("x-amz-date: "));
    }

    #[test]
    fn apply_sigv4_rewrites_request() {
        let raw = b"POST /model/test/invoke HTTP/1.1\r\nHost: bedrock-runtime.us-east-2.amazonaws.com\r\nContent-Type: application/json\r\nAuthorization: AWS4-HMAC-SHA256 old-invalid-sig\r\nX-Amz-Date: old-date\r\n\r\n{}";
        let result = apply_sigv4_to_request(
            raw,
            "bedrock-runtime.us-east-2.amazonaws.com",
            "us-east-2",
            "bedrock",
            "AKIATEST",
            "secret",
        );
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("authorization: AWS4-HMAC-SHA256 Credential=AKIATEST/"));
        assert!(!result_str.contains("old-invalid-sig"));
        assert!(!result_str.contains("old-date"));
    }
}
