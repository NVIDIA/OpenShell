// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::RouterError;
use crate::config::ResolvedRoute;

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
/// protocol-appropriate mechanism) and the `Host` header to match the
/// backend endpoint. The original path is appended to the route's
/// endpoint URL.
pub async fn proxy_to_backend(
    client: &reqwest::Client,
    route: &ResolvedRoute,
    source_protocol: &str,
    method: &str,
    path: &str,
    headers: Vec<(String, String)>,
    body: bytes::Bytes,
) -> Result<ProxyResponse, RouterError> {
    let base = route.endpoint.trim_end_matches('/');
    let url = format!("{base}{path}");

    let reqwest_method: reqwest::Method = method
        .parse()
        .map_err(|_| RouterError::Internal(format!("invalid HTTP method: {method}")))?;

    let mut builder = client.request(reqwest_method, &url);

    // Set the route's API key using the protocol-appropriate header.
    // Anthropic uses `x-api-key`; OpenAI and others use `Authorization: Bearer`.
    if source_protocol.starts_with("anthropic") {
        builder = builder.header("x-api-key", &route.api_key);
    } else {
        builder = builder.bearer_auth(&route.api_key);
    }

    // Forward non-sensitive headers (skip auth and host — we rewrite those)
    for (name, value) in &headers {
        let name_lc = name.to_ascii_lowercase();
        if name_lc == "authorization" || name_lc == "x-api-key" || name_lc == "host" {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_str());
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
