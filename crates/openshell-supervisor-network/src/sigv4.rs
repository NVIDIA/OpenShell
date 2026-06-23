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

/// AWS regions contain a hyphen followed by a digit (e.g., `us-east-1`).
/// Service names like `s3` or `bedrock-runtime` do not.
fn looks_like_region(s: &str) -> bool {
    let bytes = s.as_bytes();
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i] == b'-' && bytes[i + 1].is_ascii_digit() {
            return true;
        }
    }
    false
}

/// Extract the AWS region from an AWS hostname.
///
/// Supports standard, dualstack, FIPS, virtual-hosted, and China partition
/// hostnames. The region is the label immediately before `amazonaws.com`
/// (or `amazonaws.com.cn`).
pub fn extract_aws_region(host: &str) -> Option<String> {
    let parts: Vec<&str> = host.split('.').collect();
    // China partition: *.amazonaws.com.cn
    if parts.len() >= 5
        && parts[parts.len() - 3] == "amazonaws"
        && parts[parts.len() - 2] == "com"
        && parts[parts.len() - 1] == "cn"
    {
        let candidate = parts[parts.len() - 4];
        if looks_like_region(candidate) {
            return Some(candidate.to_string());
        }
        return None;
    }
    // Standard/dualstack/FIPS/virtual-hosted: *.amazonaws.com
    // Scan right-to-left from "amazonaws", skipping non-region labels
    // like "dualstack". Handles: s3.us-east-1.amazonaws.com,
    // s3.dualstack.us-west-2.amazonaws.com,
    // s3-fips.dualstack.us-west-2.amazonaws.com, etc.
    if parts.len() >= 4 && parts[parts.len() - 2] == "amazonaws" && parts[parts.len() - 1] == "com"
    {
        let mut idx = parts.len() - 3;
        while idx > 0 && parts[idx] == "dualstack" {
            idx -= 1;
        }
        if idx > 0 && looks_like_region(parts[idx]) {
            return Some(parts[idx].to_string());
        }
    }
    None
}

/// Strip AWS auth headers from raw HTTP request bytes.
///
/// Removes `Authorization`, `X-Amz-Date`, `X-Amz-Security-Token`, and
/// `X-Amz-Content-Sha256` headers so the request can pass through the
/// proxy's fail-closed placeholder scan before re-signing.
///
/// Returns `Err` if the header block is not valid UTF-8.  Failing closed
/// prevents non-UTF-8 requests from passing through with their original
/// AWS credentials intact.
pub fn strip_aws_headers(raw: &[u8]) -> Result<Vec<u8>> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(raw.len(), |p| p + 4);

    // The caller (rest.rs) validates UTF-8 strictly before reaching this
    // point, so `from_utf8` should never fail here. Fail closed so that
    // crafted non-UTF-8 bytes cannot smuggle AWS credentials through.
    let header_str = std::str::from_utf8(&raw[..header_end])
        .map_err(|e| miette!("strip_aws_headers: header block is not valid UTF-8: {e}"))?;
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

    Ok(output)
}

struct RequestParts<'a> {
    method: &'a str,
    path: &'a str,
    request_line: &'a str,
    headers_to_sign: Vec<(String, String)>,
    all_headers: Vec<(String, String)>,
}

/// Parse raw HTTP headers into components needed for `SigV4` signing.
///
/// Only host, content-type, and content-length are included in the `SigV4`
/// signature. Signing all headers causes failures when the proxy or
/// transport modifies unsigned-by-convention headers (Connection,
/// Accept-Encoding, etc.) between signing and delivery.
///
/// Header names are lowercased for comparison and stored in lowered form
/// in `all_headers`. This is intentional — AWS services accept
/// case-insensitive header names, and this function is only used on the
/// `SigV4` signing path.
fn parse_request_parts(header_str: &str) -> RequestParts<'_> {
    // Headers stripped entirely — the SDK re-generates auth headers, and
    // `Expect` is handled by the proxy before forwarding.
    const STRIP_HEADERS: &[&str] = &[
        "authorization",
        "x-amz-date",
        "x-amz-security-token",
        "x-amz-content-sha256",
        "expect",
    ];
    // Headers forwarded but NOT signed — the proxy or transport may modify
    // them between signing and delivery, which would invalidate the signature.
    const UNSIGNED_HEADERS: &[&str] = &[
        "connection",
        "accept-encoding",
        "transfer-encoding",
        "user-agent",
        "amz-sdk-invocation-id",
        "amz-sdk-request",
    ];

    let lines: Vec<&str> = header_str.split("\r\n").collect();

    let (method, path, request_line) =
        lines
            .first()
            .map_or(("GET", "/", "GET / HTTP/1.1"), |first_line| {
                let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
                if parts.len() >= 2 {
                    (parts[0], parts[1], *first_line)
                } else {
                    ("GET", "/", *first_line)
                }
            });

    let mut headers_to_sign: Vec<(String, String)> = Vec::new();
    let mut all_headers: Vec<(String, String)> = Vec::new();
    for line in lines.iter().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let lower = k.trim().to_ascii_lowercase();
            if STRIP_HEADERS.iter().any(|s| lower.starts_with(s)) {
                continue;
            }
            all_headers.push((lower.clone(), v.trim().to_string()));
            if !UNSIGNED_HEADERS.iter().any(|s| lower.starts_with(s)) {
                headers_to_sign.push((lower, v.trim().to_string()));
            }
        }
    }

    RequestParts {
        method,
        path,
        request_line,
        headers_to_sign,
        all_headers,
    }
}

fn build_signing_params<'a>(
    identity: &'a Identity,
    region: &'a str,
    service: &'a str,
) -> Result<aws_sigv4::http_request::SigningParams<'a>> {
    let mut settings = SigningSettings::default();
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;

    Ok(v4::SigningParams::builder()
        .identity(identity)
        .region(region)
        .name(service)
        .time(SystemTime::now())
        .settings(settings)
        .build()
        .map_err(|e| miette!("SigV4 signing params: {e}"))?
        .into())
}

fn build_identity(access_key: &str, secret_key: &str, session_token: Option<&str>) -> Identity {
    Credentials::new(
        access_key,
        secret_key,
        session_token.map(ToString::to_string),
        None,
        "openshell",
    )
    .into()
}

fn rebuild_request(
    parts: &RequestParts<'_>,
    instructions: &aws_sigv4::http_request::SigningInstructions,
    body: &[u8],
) -> Vec<u8> {
    let mut output = Vec::with_capacity(256 + body.len());

    output.extend_from_slice(parts.request_line.as_bytes());
    output.extend_from_slice(b"\r\n");

    for (k, v) in &parts.all_headers {
        output.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }

    for (name, value) in instructions.headers() {
        output.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }

    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(body);

    output
}

/// Apply AWS Signature Version 4 signing to a raw HTTP request buffer.
///
/// Strips existing AWS auth headers, computes a new signature using the
/// `aws-sigv4` crate, and returns the rewritten request bytes including body.
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

    let header_str = std::str::from_utf8(&raw[..header_end])
        .map_err(|e| miette!("SigV4 signing: request headers are not valid UTF-8: {e}"))?;
    let parts = parse_request_parts(header_str);
    let uri = format!("https://{host}{}", parts.path);
    let identity = build_identity(access_key, secret_key, session_token);
    let signing_params = build_signing_params(&identity, region, service)?;

    let signable_request = SignableRequest::new(
        parts.method,
        &uri,
        parts
            .headers_to_sign
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str())),
        SignableBody::Bytes(body),
    )
    .map_err(|e| miette!("SigV4 signable request: {e}"))?;

    let (instructions, _signature) = sign(signable_request, &signing_params)
        .map_err(|e| miette!("SigV4 signing failed: {e}"))?
        .into_parts();

    Ok(rebuild_request(&parts, &instructions, body))
}

/// Apply AWS `SigV4` signing to HTTP headers only, using UNSIGNED-PAYLOAD.
///
/// Returns signed headers ending with `\r\n\r\n`. The caller is responsible
/// for streaming the body separately. Use when the body is chunked or when
/// the service accepts unsigned payloads (e.g. S3 over HTTPS).
pub fn apply_sigv4_headers_only(
    raw_headers: &[u8],
    host: &str,
    region: &str,
    service: &str,
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
) -> Result<Vec<u8>> {
    apply_sigv4_headers_only_with_body(
        raw_headers,
        host,
        region,
        service,
        access_key,
        secret_key,
        session_token,
        SignableBody::UnsignedPayload,
    )
}

/// Apply AWS `SigV4` signing to HTTP headers only with a caller-chosen
/// `SignableBody` mode (e.g. `UnsignedPayload` or
/// `StreamingUnsignedPayloadTrailer`).
///
/// Returns signed headers ending with `\r\n\r\n`.
#[allow(clippy::too_many_arguments)]
pub fn apply_sigv4_headers_only_with_body(
    raw_headers: &[u8],
    host: &str,
    region: &str,
    service: &str,
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
    body: SignableBody<'_>,
) -> Result<Vec<u8>> {
    let header_str = std::str::from_utf8(raw_headers)
        .map_err(|e| miette!("SigV4 signing: request headers are not valid UTF-8: {e}"))?;
    let parts = parse_request_parts(header_str);
    let uri = format!("https://{host}{}", parts.path);
    let identity = build_identity(access_key, secret_key, session_token);
    let signing_params = build_signing_params(&identity, region, service)?;

    let signable_request = SignableRequest::new(
        parts.method,
        &uri,
        parts
            .headers_to_sign
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str())),
        body,
    )
    .map_err(|e| miette!("SigV4 signable request: {e}"))?;

    let (instructions, _signature) = sign(signable_request, &signing_params)
        .map_err(|e| miette!("SigV4 signing failed: {e}"))?
        .into_parts();

    Ok(rebuild_request(&parts, &instructions, &[]))
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
    fn virtual_hosted_global_endpoint_returns_none() {
        assert!(extract_aws_region("my-bucket.s3.amazonaws.com").is_none());
    }

    #[test]
    fn extract_region_dualstack() {
        let region = extract_aws_region("s3.dualstack.us-west-2.amazonaws.com").unwrap();
        assert_eq!(region, "us-west-2");
    }

    #[test]
    fn extract_region_fips() {
        let region = extract_aws_region("bedrock-runtime-fips.us-east-1.amazonaws.com").unwrap();
        assert_eq!(region, "us-east-1");
    }

    #[test]
    fn extract_region_china() {
        let region = extract_aws_region("s3.cn-north-1.amazonaws.com.cn").unwrap();
        assert_eq!(region, "cn-north-1");
    }

    #[test]
    fn extract_region_fips_dualstack() {
        let region = extract_aws_region("s3-fips.dualstack.us-west-2.amazonaws.com").unwrap();
        assert_eq!(region, "us-west-2");
    }

    #[test]
    fn extract_region_govcloud() {
        let region = extract_aws_region("s3.us-gov-west-1.amazonaws.com").unwrap();
        assert_eq!(region, "us-gov-west-1");
    }

    #[test]
    fn extract_region_virtual_hosted_s3() {
        let region = extract_aws_region("my-bucket.s3.us-east-2.amazonaws.com").unwrap();
        assert_eq!(region, "us-east-2");
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

    #[test]
    fn headers_only_produces_unsigned_payload() {
        let raw = b"PUT /my-bucket/my-key HTTP/1.1\r\nHost: s3.us-east-1.amazonaws.com\r\nContent-Type: application/octet-stream\r\nContent-Length: 1024\r\n\r\n";
        let result = apply_sigv4_headers_only(
            raw,
            "s3.us-east-1.amazonaws.com",
            "us-east-1",
            "s3",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            None,
        )
        .unwrap();
        let result_str = String::from_utf8_lossy(&result);
        assert!(
            result_str.contains("authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/")
        );
        assert!(result_str.contains("x-amz-content-sha256: UNSIGNED-PAYLOAD"));
        assert!(result_str.contains("x-amz-date: "));
        assert!(result_str.ends_with("\r\n\r\n"));
    }

    #[test]
    fn headers_only_strips_old_auth() {
        let raw = b"PUT /bucket/key HTTP/1.1\r\nHost: s3.us-east-1.amazonaws.com\r\nAuthorization: AWS4-HMAC-SHA256 old-sig\r\nX-Amz-Date: old-date\r\nX-Amz-Content-Sha256: old-hash\r\nContent-Type: application/octet-stream\r\n\r\n";
        let result = apply_sigv4_headers_only(
            raw,
            "s3.us-east-1.amazonaws.com",
            "us-east-1",
            "s3",
            "AKIATEST",
            "secret",
            None,
        )
        .unwrap();
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("authorization: AWS4-HMAC-SHA256 Credential=AKIATEST/"));
        assert!(!result_str.contains("old-sig"));
        assert!(!result_str.contains("old-date"));
        assert!(!result_str.contains("old-hash"));
        assert!(result_str.contains("x-amz-content-sha256: UNSIGNED-PAYLOAD"));
    }

    #[test]
    fn headers_only_with_session_token() {
        let raw = b"PUT /bucket/key HTTP/1.1\r\nHost: s3.us-east-1.amazonaws.com\r\nContent-Type: application/octet-stream\r\n\r\n";
        let result = apply_sigv4_headers_only(
            raw,
            "s3.us-east-1.amazonaws.com",
            "us-east-1",
            "s3",
            "ASIAEXAMPLE",
            "secret",
            Some("FwoGZXIvYXdzEBYaDH+session+token"),
        )
        .unwrap();
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("x-amz-security-token: FwoGZXIvYXdzEBYaDH+session+token"));
        assert!(result_str.contains("x-amz-content-sha256: UNSIGNED-PAYLOAD"));
    }
}
