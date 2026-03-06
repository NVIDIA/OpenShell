// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::RouterError;
use crate::config::{AuthHeader, ResolvedRoute};

/// Response from a proxied HTTP request to a backend.
#[derive(Debug)]
pub struct ProxyResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: bytes::Bytes,
}

/// Forward a raw HTTP request to the backend configured in `route`.
///
/// Rewrites the auth header with the route's API key (using the
/// route's configured [`AuthHeader`] mechanism) and the `Host` header
/// to match the backend endpoint. The original path is appended to
/// the route's endpoint URL.
pub async fn proxy_to_backend(
    client: &reqwest::Client,
    route: &ResolvedRoute,
    _source_protocol: &str,
    method: &str,
    path: &str,
    headers: Vec<(String, String)>,
    body: bytes::Bytes,
) -> Result<ProxyResponse, RouterError> {
    let url = build_backend_url(&route.endpoint, path);

    let reqwest_method: reqwest::Method = method
        .parse()
        .map_err(|_| RouterError::Internal(format!("invalid HTTP method: {method}")))?;

    let mut builder = client.request(reqwest_method, &url);

    // Inject API key using the route's configured auth mechanism.
    match &route.auth {
        AuthHeader::Bearer => {
            builder = builder.bearer_auth(&route.api_key);
        }
        AuthHeader::Custom(header_name) => {
            builder = builder.header(*header_name, &route.api_key);
        }
    }

    // Collect header names we need to strip (auth, host, and any default header
    // names that will be set from route defaults).
    let strip_headers: Vec<String> = {
        let mut s = vec![
            "authorization".to_string(),
            "x-api-key".to_string(),
            "host".to_string(),
        ];
        for (name, _) in &route.default_headers {
            s.push(name.to_ascii_lowercase());
        }
        s
    };

    // Forward non-sensitive headers (skip auth, host, and any we'll override)
    for (name, value) in &headers {
        let name_lc = name.to_ascii_lowercase();
        if strip_headers.contains(&name_lc) {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_str());
    }

    // Apply route-level default headers (e.g. anthropic-version) unless
    // the client already sent them.
    for (name, value) in &route.default_headers {
        let already_sent = headers.iter().any(|(h, _)| h.eq_ignore_ascii_case(name));
        if !already_sent {
            builder = builder.header(name.as_str(), value.as_str());
        }
    }

    // Set the "model" field in the JSON body to the route's configured model so the
    // backend receives the correct model ID regardless of what the client sent.
    let body = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(mut json) => {
            if let Some(obj) = json.as_object_mut() {
                obj.insert(
                    "model".to_string(),
                    serde_json::Value::String(route.model.clone()),
                );
            }
            bytes::Bytes::from(serde_json::to_vec(&json).unwrap_or_else(|_| body.to_vec()))
        }
        Err(_) => body,
    };
    builder = builder.body(body);

    let response = builder.send().await.map_err(|e| {
        if e.is_timeout() {
            RouterError::UpstreamUnavailable(format!("request to {url} timed out"))
        } else if e.is_connect() {
            RouterError::UpstreamUnavailable(format!("failed to connect to {url}: {e}"))
        } else {
            RouterError::Internal(format!("HTTP request failed: {e}"))
        }
    })?;

    let status = response.status().as_u16();
    let resp_headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let resp_body = response
        .bytes()
        .await
        .map_err(|e| RouterError::UpstreamProtocol(format!("failed to read response body: {e}")))?;

    Ok(ProxyResponse {
        status,
        headers: resp_headers,
        body: resp_body,
    })
}

fn build_backend_url(endpoint: &str, path: &str) -> String {
    let base = endpoint.trim_end_matches('/');
    if base.ends_with("/v1") && (path == "/v1" || path.starts_with("/v1/")) {
        return format!("{base}{}", &path[3..]);
    }

    format!("{base}{path}")
}

#[cfg(test)]
mod tests {
    use super::build_backend_url;

    #[test]
    fn build_backend_url_dedupes_v1_prefix() {
        assert_eq!(
            build_backend_url("https://api.openai.com/v1", "/v1/chat/completions"),
            "https://api.openai.com/v1/chat/completions"
        );
    }

    #[test]
    fn build_backend_url_preserves_non_versioned_base() {
        assert_eq!(
            build_backend_url("https://api.anthropic.com", "/v1/messages"),
            "https://api.anthropic.com/v1/messages"
        );
    }

    #[test]
    fn build_backend_url_handles_exact_v1_path() {
        assert_eq!(
            build_backend_url("https://api.openai.com/v1", "/v1"),
            "https://api.openai.com/v1"
        );
    }
}
