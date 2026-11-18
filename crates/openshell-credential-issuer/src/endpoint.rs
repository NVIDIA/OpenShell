// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Token endpoint normalization for workspace-secret endpoint constraints.
//!
//! A workspace secret names the only token endpoints its value may be sent to.
//! Creation and every mint compare endpoints in this normalized form, so the
//! two checks cannot disagree about what a URL means.

/// Normalize a token endpoint for exact comparison.
///
/// Accepts absolute `https` URLs, or `http` URLs for loopback hosts (local
/// tests). Rejects user information, queries, and fragments. The result has a
/// lowercase scheme and host, no default port, and a non-empty path.
///
/// # Errors
///
/// Returns a short description of why the URL is not an acceptable endpoint.
pub fn normalize_token_endpoint(raw: &str) -> Result<String, &'static str> {
    let url = reqwest::Url::parse(raw.trim()).map_err(|_| "must be an absolute URL")?;
    let Some(host) = url.host_str().filter(|host| !host.is_empty()) else {
        return Err("must include a host");
    };
    match url.scheme() {
        "https" => {}
        "http" if is_loopback_host(host) => {}
        _ => return Err("must use https, or http for a loopback host"),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("must not include user information");
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("must not include a query or fragment");
    }
    Ok(url.to_string())
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

#[cfg(test)]
mod tests {
    use super::normalize_token_endpoint;

    #[test]
    fn normalizes_case_default_port_and_empty_path() {
        assert_eq!(
            normalize_token_endpoint("HTTPS://Login.Example.COM:443").unwrap(),
            "https://login.example.com/"
        );
        assert_eq!(
            normalize_token_endpoint(" https://login.example.com:8443/oauth/token ").unwrap(),
            "https://login.example.com:8443/oauth/token"
        );
    }

    #[test]
    fn allows_http_only_for_loopback() {
        assert!(normalize_token_endpoint("http://127.0.0.1:9000/token").is_ok());
        assert!(normalize_token_endpoint("http://localhost/token").is_ok());
        assert!(normalize_token_endpoint("http://[::1]:9000/token").is_ok());
        assert!(normalize_token_endpoint("http://login.example.com/token").is_err());
    }

    #[test]
    fn rejects_ambiguous_or_credential_bearing_urls() {
        for raw in [
            "",
            "/oauth/token",
            "ftp://login.example.com/token",
            "https://user:pass@login.example.com/token",
            "https://login.example.com/token?tenant=a",
            "https://login.example.com/token#frag",
        ] {
            assert!(normalize_token_endpoint(raw).is_err(), "{raw}");
        }
    }
}
