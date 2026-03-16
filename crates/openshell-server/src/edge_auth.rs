// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Edge authentication helpers for Cloudflare/reverse-proxy deployments.

use axum::http::HeaderMap;
use tonic::metadata::MetadataMap;

/// Return `true` when headers include a usable edge auth token.
#[must_use]
pub fn has_edge_auth_http(headers: &HeaderMap) -> bool {
    header_or_cookie_token(headers)
}

/// Return `true` when gRPC metadata includes a usable edge auth token.
#[must_use]
pub fn has_edge_auth_grpc(metadata: &MetadataMap) -> bool {
    metadata_token(metadata, "cf-authorization") || metadata_bearer(metadata, "authorization")
}

fn header_or_cookie_token(headers: &HeaderMap) -> bool {
    header_token(headers, "cf-authorization")
        || header_bearer(headers, "authorization")
        || cookie_token(headers)
}

fn header_token(headers: &HeaderMap, name: &str) -> bool {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| !v.trim().is_empty())
}

fn header_bearer(headers: &HeaderMap, name: &str) -> bool {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .is_some_and(has_bearer_prefix)
}

fn cookie_token(headers: &HeaderMap) -> bool {
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| extract_cookie(cookies, "CF_Authorization"))
        .is_some_and(|v| !v.trim().is_empty())
}

fn extract_cookie(cookies: &str, name: &str) -> Option<String> {
    cookies.split(';').find_map(|c| {
        let mut parts = c.trim().splitn(2, '=');
        let key = parts.next()?.trim();
        let val = parts.next()?.trim();
        if key == name {
            Some(val.to_string())
        } else {
            None
        }
    })
}

fn metadata_token(metadata: &MetadataMap, name: &str) -> bool {
    metadata
        .get(name)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| !v.trim().is_empty())
}

fn metadata_bearer(metadata: &MetadataMap, name: &str) -> bool {
    metadata
        .get(name)
        .and_then(|v| v.to_str().ok())
        .is_some_and(has_bearer_prefix)
}

fn has_bearer_prefix(value: &str) -> bool {
    value
        .strip_prefix("Bearer ")
        .is_some_and(|token| !token.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};
    use tonic::metadata::{MetadataMap, MetadataValue};

    #[test]
    fn http_accepts_cf_authorization_header() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-authorization", HeaderValue::from_static("jwt-token"));
        assert!(has_edge_auth_http(&headers));
    }

    #[test]
    fn http_accepts_bearer_authorization_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer jwt-token"),
        );
        assert!(has_edge_auth_http(&headers));
    }

    #[test]
    fn http_accepts_cf_authorization_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static("foo=bar; CF_Authorization=jwt-token"),
        );
        assert!(has_edge_auth_http(&headers));
    }

    #[test]
    fn http_rejects_missing_token() {
        let headers = HeaderMap::new();
        assert!(!has_edge_auth_http(&headers));
    }

    #[test]
    fn grpc_accepts_cf_authorization_metadata() {
        let mut metadata = MetadataMap::new();
        metadata.insert("cf-authorization", MetadataValue::from_static("jwt-token"));
        assert!(has_edge_auth_grpc(&metadata));
    }

    #[test]
    fn grpc_accepts_bearer_authorization_metadata() {
        let mut metadata = MetadataMap::new();
        metadata.insert(
            "authorization",
            MetadataValue::from_static("Bearer jwt-token"),
        );
        assert!(has_edge_auth_grpc(&metadata));
    }

    #[test]
    fn grpc_rejects_missing_token() {
        let metadata = MetadataMap::new();
        assert!(!has_edge_auth_grpc(&metadata));
    }
}
