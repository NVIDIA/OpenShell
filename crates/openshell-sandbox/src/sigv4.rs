// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::SystemTime;

type HmacSha256 = Hmac<Sha256>;

pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

pub fn extract_aws_region_and_service(host: &str) -> Option<(String, String)> {
    // Pattern: <service>.<region>.amazonaws.com
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 4 && parts[parts.len() - 2] == "amazonaws" && parts[parts.len() - 1] == "com"
    {
        let raw_service = parts[0];
        let region = parts[1].to_string();
        // AWS signing service name overrides: some services use a base name
        // that differs from the hostname prefix. The aws-sigv4 SDK crate
        // handles this automatically via internal endpoint metadata — for this
        // POC we hardcode known overrides. TODO: replace with aws-sigv4 crate.
        let service = normalize_aws_signing_name(raw_service).to_string();
        Some((region, service))
    } else {
        None
    }
}

fn normalize_aws_signing_name(hostname_prefix: &str) -> &str {
    match hostname_prefix {
        "bedrock-runtime" | "bedrock-agent" | "bedrock-agent-runtime" => "bedrock",
        other => other,
    }
}

pub fn sign_request(
    method: &str,
    path: &str,
    host: &str,
    headers: &[(String, String)],
    body: &[u8],
    region: &str,
    service: &str,
    credentials: &AwsCredentials,
) -> (String, String, String) {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock before epoch");
    let secs = now.as_secs();
    let datetime = format_iso8601(secs);
    let date = &datetime[..8];

    let payload_hash = sha256_hex(body);

    // Canonical headers: must include host, x-amz-date, x-amz-content-sha256
    // plus any existing headers the SDK sent that are in the signed-headers list.
    let mut canonical_headers: Vec<(String, String)> = Vec::new();
    canonical_headers.push(("host".to_string(), host.to_string()));
    canonical_headers.push(("x-amz-content-sha256".to_string(), payload_hash.clone()));
    canonical_headers.push(("x-amz-date".to_string(), datetime.clone()));

    // Include content-type if present in original headers
    for (k, v) in headers {
        let lower = k.to_ascii_lowercase();
        if lower == "content-type" || lower == "content-length" {
            canonical_headers.push((lower, v.trim().to_string()));
        }
    }

    canonical_headers.sort_by(|a, b| a.0.cmp(&b.0));

    let canonical_headers_str: String = canonical_headers
        .iter()
        .map(|(k, v)| format!("{k}:{v}\n"))
        .collect();

    let signed_headers: String = canonical_headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    // Split path from query string
    let (canon_path, query_string) = match path.split_once('?') {
        Some((p, q)) => (p, q.to_string()),
        None => (path, String::new()),
    };

    let canonical_request = format!(
        "{method}\n{canon_path}\n{query_string}\n{canonical_headers_str}\n{signed_headers}\n{payload_hash}"
    );

    let credential_scope = format!("{date}/{region}/{service}/aws4_request");

    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{datetime}\n{credential_scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );

    let key = signing_key(&credentials.secret_access_key, date, region, service);
    let signature = hex::encode(hmac_sha256(&key, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
        credentials.access_key_id,
    );

    (authorization, datetime, payload_hash)
}

fn format_iso8601(epoch_secs: u64) -> String {
    let days_since_epoch = epoch_secs / 86400;
    let time_of_day = epoch_secs % 86400;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Civil date from days since 1970-01-01 (algorithm from Howard Hinnant)
    let z = days_since_epoch as i64 + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}{m:02}{d:02}T{hours:02}{minutes:02}{seconds:02}Z")
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
/// the provided credentials, and returns the rewritten request bytes.
pub fn apply_sigv4_to_request(
    raw: &[u8],
    host: &str,
    region: &str,
    service: &str,
    credentials: &AwsCredentials,
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

    // Parse method and path from request line
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

    let (authorization, amz_date, content_sha256) =
        sign_request(method, path, host, &existing_headers, body, region, service, credentials);

    // Rebuild the request
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

    // Injected AWS headers
    output.extend_from_slice(format!("Authorization: {authorization}\r\n").as_bytes());
    output.extend_from_slice(format!("X-Amz-Date: {amz_date}\r\n").as_bytes());
    output.extend_from_slice(format!("X-Amz-Content-Sha256: {content_sha256}\r\n").as_bytes());

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
        let creds = AwsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
        };
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];
        let (auth, date, hash) = sign_request(
            "POST",
            "/model/us.anthropic.claude-sonnet-4-6/invoke",
            "bedrock-runtime.us-east-2.amazonaws.com",
            &headers,
            b"{}",
            "us-east-2",
            "bedrock",
            &creds,
        );
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"));
        assert!(auth.contains("SignedHeaders="));
        assert!(auth.contains("Signature="));
        assert_eq!(date.len(), 16); // 20060102T150405Z
        assert_eq!(hash.len(), 64); // SHA256 hex
    }

    #[test]
    fn apply_sigv4_rewrites_request() {
        let raw = b"POST /model/test/invoke HTTP/1.1\r\nHost: bedrock-runtime.us-east-2.amazonaws.com\r\nContent-Type: application/json\r\nAuthorization: AWS4-HMAC-SHA256 old-invalid-sig\r\nX-Amz-Date: old-date\r\n\r\n{}";
        let creds = AwsCredentials {
            access_key_id: "AKIATEST".to_string(),
            secret_access_key: "secret".to_string(),
        };
        let result = apply_sigv4_to_request(
            raw,
            "bedrock-runtime.us-east-2.amazonaws.com",
            "us-east-2",
            "bedrock-runtime",
            &creds,
        );
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("Authorization: AWS4-HMAC-SHA256 Credential=AKIATEST/"));
        assert!(result_str.contains("X-Amz-Date: "));
        assert!(result_str.contains("X-Amz-Content-Sha256: "));
        // Old auth headers should be gone
        assert!(!result_str.contains("old-invalid-sig"));
        assert!(!result_str.contains("old-date"));
    }
}
