// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Collector request headers in the `OTEL_EXPORTER_OTLP_HEADERS` format.

use std::fmt::Write as _;

use http::{HeaderMap, HeaderName, HeaderValue};

/// Parse headers the way the SDK parses `OTEL_EXPORTER_OTLP_HEADERS`:
/// comma-separated `key=value` pairs with percent-encoded values. Entries
/// that are empty or not valid HTTP headers are skipped.
#[must_use]
pub fn parse_otlp_headers(headers: &str) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (key, value) in headers.split_terminator(',').filter_map(|entry| {
        let (key, value) = entry.trim().split_once('=')?;
        let (key, value) = (key.trim(), value.trim());
        let value = percent_decode(value).unwrap_or_else(|| value.to_string());
        (!key.is_empty() && !value.is_empty()).then_some((key.to_string(), value))
    }) {
        if let (Ok(key), Ok(value)) = (
            HeaderName::try_from(key),
            HeaderValue::try_from(value.as_str()),
        ) {
            map.insert(key, value);
        }
    }
    map
}

/// Encode `headers` for [`parse_otlp_headers`], percent-encoding every value
/// byte outside the URI unreserved set.
#[must_use]
pub fn encode_otlp_headers(headers: &HeaderMap) -> String {
    let mut encoded = String::new();
    for (key, value) in headers {
        if !encoded.is_empty() {
            encoded.push(',');
        }
        encoded.push_str(key.as_str());
        encoded.push('=');
        for &byte in value.as_bytes() {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                encoded.push(char::from(byte));
            } else {
                let _ = write!(encoded, "%{byte:02X}");
            }
        }
    }
    encoded
}

/// `headers` with each header in `overrides` replacing any of the same name.
#[must_use]
pub fn merge_otlp_headers(mut headers: HeaderMap, overrides: HeaderMap) -> HeaderMap {
    headers.extend(overrides);
    headers
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = std::str::from_utf8(bytes.get(index + 1..index + 3)?).ok()?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(entries: &[(&'static str, &'static str)]) -> HeaderMap {
        entries
            .iter()
            .map(|(key, value)| {
                (
                    HeaderName::from_static(key),
                    HeaderValue::from_static(value),
                )
            })
            .collect()
    }

    #[test]
    fn headers_parse_like_the_sdk_environment_variable() {
        let headers = parse_otlp_headers(
            "authorization=Bearer%20secret, x-tenant = blue ,=empty-key,no-value=,bad",
        );
        assert_eq!(headers["authorization"], "Bearer secret");
        assert_eq!(headers["x-tenant"], "blue");
        assert_eq!(headers.len(), 2);
    }

    #[test]
    fn malformed_percent_encoding_is_kept_verbatim() {
        assert_eq!(parse_otlp_headers("token=abc%zz")["token"], "abc%zz");
    }

    #[test]
    fn encoded_headers_parse_back_to_the_same_values() {
        let mut headers = map(&[("x-mlflow-experiment-id", "0")]);
        headers.insert(
            "authorization",
            HeaderValue::from_str("Bearer a,b=c%d").unwrap(),
        );
        let encoded = encode_otlp_headers(&headers);
        assert!(!encoded.contains(' '), "{encoded}");
        assert_eq!(parse_otlp_headers(&encoded), headers);
    }

    #[test]
    fn overrides_replace_headers_of_the_same_name() {
        let merged = merge_otlp_headers(
            map(&[("authorization", "toml"), ("x-tenant", "blue")]),
            map(&[("authorization", "env"), ("x-extra", "1")]),
        );
        assert_eq!(
            merged,
            map(&[
                ("authorization", "env"),
                ("x-tenant", "blue"),
                ("x-extra", "1")
            ])
        );
    }
}
