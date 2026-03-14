// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::RouterError;
use crate::config::{AuthHeader, ResolvedRoute};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedEndpoint {
    pub url: String,
    pub protocol: String,
}

struct ValidationProbe {
    path: &'static str,
    protocol: &'static str,
    body: bytes::Bytes,
}

/// Response from a proxied HTTP request to a backend (fully buffered).
#[derive(Debug)]
pub struct ProxyResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: bytes::Bytes,
}

/// Response from a proxied HTTP request where the body can be streamed
/// incrementally via [`StreamingProxyResponse::next_chunk`].
pub struct StreamingProxyResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// Either a live response to stream from, or a pre-buffered body (for mock routes).
    body: StreamingBody,
}

enum StreamingBody {
    /// Live upstream response — call `chunk().await` to read incrementally.
    Live(reqwest::Response),
    /// Pre-buffered body (e.g. from mock routes). Drained on first `next_chunk()`.
    Buffered(Option<bytes::Bytes>),
}

impl StreamingProxyResponse {
    /// Create from a fully-buffered [`ProxyResponse`] (for mock routes).
    pub fn from_buffered(resp: ProxyResponse) -> Self {
        Self {
            status: resp.status,
            headers: resp.headers,
            body: StreamingBody::Buffered(Some(resp.body)),
        }
    }

    /// Read the next body chunk. Returns `None` when the body is exhausted.
    pub async fn next_chunk(&mut self) -> Result<Option<bytes::Bytes>, RouterError> {
        match &mut self.body {
            StreamingBody::Live(response) => response.chunk().await.map_err(|e| {
                RouterError::UpstreamProtocol(format!("failed to read response chunk: {e}"))
            }),
            StreamingBody::Buffered(buf) => Ok(buf.take()),
        }
    }
}

/// Build and send an HTTP request to the backend configured in `route`.
///
/// Returns the [`reqwest::Response`] with status, headers, and an un-consumed
/// body stream. Shared by both the buffered and streaming public APIs.
async fn send_backend_request(
    client: &reqwest::Client,
    route: &ResolvedRoute,
    method: &str,
    path: &str,
    headers: Vec<(String, String)>,
    body: bytes::Bytes,
) -> Result<reqwest::Response, RouterError> {
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

    // Strip auth and host headers — auth is re-injected above from the route
    // config, and host must match the upstream.
    let strip_headers: [&str; 3] = ["authorization", "x-api-key", "host"];

    // Forward non-sensitive headers.
    for (name, value) in &headers {
        let name_lc = name.to_ascii_lowercase();
        if strip_headers.contains(&name_lc.as_str()) {
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

    builder.send().await.map_err(|e| {
        if e.is_timeout() {
            RouterError::UpstreamUnavailable(format!("request to {url} timed out"))
        } else if e.is_connect() {
            RouterError::UpstreamUnavailable(format!("failed to connect to {url}: {e}"))
        } else {
            RouterError::Internal(format!("HTTP request failed: {e}"))
        }
    })
}

fn validation_probe(route: &ResolvedRoute) -> Result<ValidationProbe, RouterError> {
    if route
        .protocols
        .iter()
        .any(|protocol| protocol == "openai_chat_completions")
    {
        return Ok(ValidationProbe {
            path: "/v1/chat/completions",
            protocol: "openai_chat_completions",
            body: bytes::Bytes::from_static(
                br#"{"messages":[{"role":"user","content":"ping"}],"max_tokens":1}"#,
            ),
        });
    }

    if route
        .protocols
        .iter()
        .any(|protocol| protocol == "anthropic_messages")
    {
        return Ok(ValidationProbe {
            path: "/v1/messages",
            protocol: "anthropic_messages",
            body: bytes::Bytes::from_static(
                br#"{"messages":[{"role":"user","content":"ping"}],"max_tokens":1}"#,
            ),
        });
    }

    if route
        .protocols
        .iter()
        .any(|protocol| protocol == "openai_responses")
    {
        return Ok(ValidationProbe {
            path: "/v1/responses",
            protocol: "openai_responses",
            body: bytes::Bytes::from_static(br#"{"input":"ping","max_output_tokens":1}"#),
        });
    }

    if route
        .protocols
        .iter()
        .any(|protocol| protocol == "openai_completions")
    {
        return Ok(ValidationProbe {
            path: "/v1/completions",
            protocol: "openai_completions",
            body: bytes::Bytes::from_static(br#"{"prompt":"ping","max_tokens":1}"#),
        });
    }

    Err(RouterError::Internal(format!(
        "route '{}' does not expose a writable inference protocol for validation",
        route.name
    )))
}

pub async fn verify_backend_endpoint(
    client: &reqwest::Client,
    route: &ResolvedRoute,
) -> Result<ValidatedEndpoint, RouterError> {
    let probe = validation_probe(route)?;
    let response =
        send_backend_request(client, route, "POST", probe.path, Vec::new(), probe.body).await?;
    let url = build_backend_url(&route.endpoint, probe.path);

    if response.status().is_success() {
        return Ok(ValidatedEndpoint {
            url,
            protocol: probe.protocol.to_string(),
        });
    }

    let status = response.status();
    let body = response.text().await.map_err(|e| {
        RouterError::UpstreamProtocol(format!("failed to read validation response body: {e}"))
    })?;
    let body = body.trim();
    let body_suffix = if body.is_empty() {
        String::new()
    } else {
        format!(
            " Response body: {}",
            body.chars().take(200).collect::<String>()
        )
    };

    let details = match status.as_u16() {
        400 | 404 | 405 | 422 => {
            format!("upstream rejected the validation request with HTTP {status}.{body_suffix}")
        }
        401 | 403 => {
            format!("upstream rejected credentials with HTTP {status}.{body_suffix}")
        }
        429 => {
            format!("upstream rate-limited the validation request with HTTP {status}.{body_suffix}")
        }
        500..=599 => format!("upstream returned HTTP {status}.{body_suffix}"),
        _ => format!("upstream returned unexpected HTTP {status}.{body_suffix}"),
    };

    Err(RouterError::UpstreamProtocol(details))
}

/// Extract status and headers from a [`reqwest::Response`].
fn extract_response_metadata(response: &reqwest::Response) -> (u16, Vec<(String, String)>) {
    let status = response.status().as_u16();
    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    (status, headers)
}

/// Forward a raw HTTP request to the backend configured in `route`.
///
/// Buffers the entire response body before returning. Suitable for
/// non-streaming responses or mock routes.
pub async fn proxy_to_backend(
    client: &reqwest::Client,
    route: &ResolvedRoute,
    _source_protocol: &str,
    method: &str,
    path: &str,
    headers: Vec<(String, String)>,
    body: bytes::Bytes,
) -> Result<ProxyResponse, RouterError> {
    let response = send_backend_request(client, route, method, path, headers, body).await?;
    let (status, resp_headers) = extract_response_metadata(&response);
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

/// Forward a raw HTTP request to the backend, returning response headers
/// immediately without buffering the body.
///
/// The caller streams the body incrementally via
/// [`StreamingProxyResponse::response`] using `chunk().await`.
pub async fn proxy_to_backend_streaming(
    client: &reqwest::Client,
    route: &ResolvedRoute,
    _source_protocol: &str,
    method: &str,
    path: &str,
    headers: Vec<(String, String)>,
    body: bytes::Bytes,
) -> Result<StreamingProxyResponse, RouterError> {
    let response = send_backend_request(client, route, method, path, headers, body).await?;
    let (status, resp_headers) = extract_response_metadata(&response);

    Ok(StreamingProxyResponse {
        status,
        headers: resp_headers,
        body: StreamingBody::Live(response),
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
    use super::{build_backend_url, verify_backend_endpoint};
    use crate::config::ResolvedRoute;
    use openshell_core::inference::AuthHeader;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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

    fn test_route(endpoint: &str, protocols: &[&str], auth: AuthHeader) -> ResolvedRoute {
        ResolvedRoute {
            name: "inference.local".to_string(),
            endpoint: endpoint.to_string(),
            model: "test-model".to_string(),
            api_key: "sk-test".to_string(),
            protocols: protocols.iter().map(|p| (*p).to_string()).collect(),
            auth,
            default_headers: vec![("anthropic-version".to_string(), "2023-06-01".to_string())],
        }
    }

    #[tokio::test]
    async fn verify_backend_endpoint_uses_route_auth_and_shape() {
        let mock_server = MockServer::start().await;
        let route = test_route(
            &mock_server.uri(),
            &["anthropic_messages"],
            AuthHeader::Custom("x-api-key"),
        );

        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(header("x-api-key", "sk-test"))
            .and(header("anthropic-version", "2023-06-01"))
            .and(body_partial_json(serde_json::json!({
                "model": "test-model",
                "max_tokens": 1,
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": "msg_1"})),
            )
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::builder().build().unwrap();
        let validated = verify_backend_endpoint(&client, &route).await.unwrap();

        assert_eq!(validated.protocol, "anthropic_messages");
        assert_eq!(validated.url, format!("{}/v1/messages", mock_server.uri()));
    }
}
