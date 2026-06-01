// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{
    PayloadChecksumKind, SignableBody, SignableRequest, SigningSettings, sign,
};
use aws_sigv4::sign::v4;
use aws_smithy_runtime_api::client::identity::Identity;
use miette::{Result, miette};
use std::time::SystemTime;

/// Extract the AWS region from a standard AWS hostname.
/// Pattern: `<service>.<region>.amazonaws.com` → `<region>`.
pub fn extract_aws_region(host: &str) -> Option<String> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 4 && parts[parts.len() - 2] == "amazonaws" && parts[parts.len() - 1] == "com"
    {
        Some(parts[1].to_string())
    } else {
        None
    }
}

/// Strip AWS auth headers from raw HTTP request bytes.
///
/// Removes `Authorization`, `X-Amz-Date`, `X-Amz-Security-Token`, and
/// `X-Amz-Content-Sha256` headers so the request can pass through the
/// proxy's fail-closed placeholder scan before re-signing.
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

/// Apply AWS Signature Version 4 signing to a raw HTTP request buffer.
///
/// Strips existing AWS auth headers, computes a new signature using the
/// `aws-sigv4` crate, and returns the rewritten request bytes.
pub fn apply_sigv4_to_request(
    raw: &[u8],
    host: &str,
    region: &str,
    service: &str,
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
) -> Result<Vec<u8>> {
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

    let (method, path) = lines.first().map_or(("GET", "/"), |first_line| {
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            (parts[0], parts[1])
        } else {
            ("GET", "/")
        }
    });

    // Collect all non-AWS headers for forwarding, and a subset for signing.
    // Only host, content-type, and content-length are included in the SigV4
    // signature. Signing all headers causes failures when the proxy or
    // transport modifies unsigned-by-convention headers (Connection,
    // Accept-Encoding, etc.) between signing and delivery.
    let mut headers_to_sign: Vec<(String, String)> = Vec::new();
    let mut all_headers: Vec<(String, String)> = Vec::new();
    for line in lines.iter().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let lower = k.trim().to_ascii_lowercase();
            if lower.starts_with("authorization")
                || lower.starts_with("x-amz-date")
                || lower.starts_with("x-amz-security-token")
                || lower.starts_with("x-amz-content-sha256")
            {
                continue;
            }
            all_headers.push((lower.clone(), v.trim().to_string()));
            if lower == "host" || lower == "content-type" || lower == "content-length" {
                headers_to_sign.push((lower, v.trim().to_string()));
            }
        }
    }

    let uri = format!("https://{host}{path}");

    let identity: Identity = Credentials::new(
        access_key,
        secret_key,
        session_token.map(ToString::to_string),
        None,
        "openshell",
    )
    .into();

    let mut settings = SigningSettings::default();
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;

    let signing_params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name(service)
        .time(SystemTime::now())
        .settings(settings)
        .build()
        .map_err(|e| miette!("SigV4 signing params: {e}"))?
        .into();

    let signable_request = SignableRequest::new(
        method,
        &uri,
        headers_to_sign
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str())),
        SignableBody::Bytes(body),
    )
    .map_err(|e| miette!("SigV4 signable request: {e}"))?;

    let (instructions, _signature) = sign(signable_request, &signing_params)
        .map_err(|e| miette!("SigV4 signing failed: {e}"))?
        .into_parts();

    // Rebuild the request with signed headers
    let mut output = Vec::with_capacity(raw.len() + 256);

    // Request line
    if let Some(first_line) = lines.first() {
        output.extend_from_slice(first_line.as_bytes());
        output.extend_from_slice(b"\r\n");
    }

    // All original non-AWS headers
    for (k, v) in &all_headers {
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

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_region_from_hostname() {
        let region = extract_aws_region("bedrock-runtime.us-east-2.amazonaws.com").unwrap();
        assert_eq!(region, "us-east-2");
    }

    #[test]
    fn extract_region_from_sts_hostname() {
        let region = extract_aws_region("sts.us-east-1.amazonaws.com").unwrap();
        assert_eq!(region, "us-east-1");
    }

    #[test]
    fn non_aws_hostname_returns_none() {
        assert!(extract_aws_region("api.anthropic.com").is_none());
    }

    #[test]
    fn global_endpoint_returns_none() {
        assert!(extract_aws_region("s3.amazonaws.com").is_none());
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
            None,
        )
        .unwrap();
        let result_str = String::from_utf8_lossy(&result);
        assert!(
            result_str.contains("authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/")
        );
        assert!(result_str.contains("x-amz-content-sha256: "));
        assert!(result_str.contains("x-amz-date: "));
        assert!(!result_str.contains("x-amz-security-token"));
    }

    #[test]
    fn sign_with_session_token() {
        let raw = b"POST /model/test/invoke HTTP/1.1\r\nHost: bedrock-runtime.us-east-2.amazonaws.com\r\nContent-Type: application/json\r\n\r\n{}";
        let result = apply_sigv4_to_request(
            raw,
            "bedrock-runtime.us-east-2.amazonaws.com",
            "us-east-2",
            "bedrock",
            "ASIAEXAMPLE",
            "secret",
            Some("FwoGZXIvYXdzEBYaDH+session+token"),
        )
        .unwrap();
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("authorization: AWS4-HMAC-SHA256 Credential=ASIAEXAMPLE/"));
        assert!(result_str.contains("x-amz-security-token: FwoGZXIvYXdzEBYaDH+session+token"));
    }

    #[test]
    fn non_signed_headers_preserved() {
        let raw = b"POST /model/test/invoke HTTP/1.1\r\nHost: bedrock-runtime.us-east-2.amazonaws.com\r\nContent-Type: application/json\r\nAccept: application/json\r\nUser-Agent: my-agent/1.0\r\n\r\n{}";
        let result = apply_sigv4_to_request(
            raw,
            "bedrock-runtime.us-east-2.amazonaws.com",
            "us-east-2",
            "bedrock",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            None,
        )
        .unwrap();
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("accept: application/json\r\n"));
        assert!(result_str.contains("user-agent: my-agent/1.0\r\n"));
        assert!(result_str.contains("authorization: AWS4-HMAC-SHA256 Credential="));
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
            None,
        )
        .unwrap();
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("authorization: AWS4-HMAC-SHA256 Credential=AKIATEST/"));
        assert!(!result_str.contains("old-invalid-sig"));
        assert!(!result_str.contains("old-date"));
    }
}
