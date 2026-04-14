// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::RouterError;
use crate::config::{AuthHeader, ResolvedRoute};
use crate::mock;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedEndpoint {
    pub url: String,
    pub protocol: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationFailureKind {
    RequestShape,
    Credentials,
    RateLimited,
    Connectivity,
    UpstreamHealth,
    Unexpected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationFailure {
    pub kind: ValidationFailureKind,
    pub details: String,
}

struct ValidationProbe {
    path: &'static str,
    protocol: &'static str,
    body: bytes::Bytes,
    /// Alternate body to try when the primary probe fails with HTTP 400.
    /// Used for OpenAI chat completions where newer models require
    /// `max_completion_tokens` while legacy/self-hosted backends only
    /// accept `max_tokens`.
    fallback_body: Option<bytes::Bytes>,
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

const COMMON_INFERENCE_REQUEST_HEADERS: [&str; 4] =
    ["content-type", "accept", "accept-encoding", "user-agent"];

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

fn sanitize_request_headers(
    route: &ResolvedRoute,
    headers: &[(String, String)],
) -> Vec<(String, String)> {
    let mut allowed = HashSet::new();
    allowed.extend(
        COMMON_INFERENCE_REQUEST_HEADERS
            .iter()
            .map(|name| (*name).to_string()),
    );
    allowed.extend(
        route
            .passthrough_headers
            .iter()
            .map(|name| name.to_ascii_lowercase()),
    );
    allowed.extend(
        route
            .default_headers
            .iter()
            .map(|(name, _)| name.to_ascii_lowercase()),
    );

    headers
        .iter()
        .filter_map(|(name, value)| {
            let name_lc = name.to_ascii_lowercase();
            if should_strip_request_header(&name_lc) || !allowed.contains(&name_lc) {
                return None;
            }
            Some((name.clone(), value.clone()))
        })
        .collect()
}

fn should_strip_request_header(name: &str) -> bool {
    matches!(
        name,
        "authorization" | "x-api-key" | "host" | "content-length"
    ) || is_hop_by_hop_header(name)
}

fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Build and send an HTTP request to the backend configured in `route`.
///
/// Returns the prepared [`reqwest::RequestBuilder`] with auth, headers, model
/// rewrite, and body applied. The caller decides whether to apply a total
/// request timeout before sending.
fn prepare_backend_request(
    client: &reqwest::Client,
    route: &ResolvedRoute,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: bytes::Bytes,
) -> Result<(reqwest::RequestBuilder, String), RouterError> {
    let url = build_backend_url(&route.endpoint, path);
    let headers = sanitize_request_headers(route, &headers);

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
    for (name, value) in &headers {
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

    Ok((builder, url))
}

/// Send an error-mapped request, shared by both buffered and streaming paths.
fn map_send_error(e: reqwest::Error, url: &str) -> RouterError {
    if e.is_timeout() {
        RouterError::UpstreamUnavailable(format!("request to {url} timed out"))
    } else if e.is_connect() {
        RouterError::UpstreamUnavailable(format!("failed to connect to {url}: {e}"))
    } else {
        RouterError::Internal(format!("HTTP request failed: {e}"))
    }
}

/// Build and send an HTTP request to the backend with a total request timeout.
///
/// The timeout covers the entire request lifecycle (connect + headers + body).
/// Suitable for non-streaming responses where the body is buffered completely.
async fn send_backend_request(
    client: &reqwest::Client,
    route: &ResolvedRoute,
    method: &str,
    path: &str,
    headers: Vec<(String, String)>,
    body: bytes::Bytes,
) -> Result<reqwest::Response, RouterError> {
    let (builder, url) = prepare_backend_request(client, route, method, path, &headers, body)?;
    builder
        .timeout(route.timeout)
        .send()
        .await
        .map_err(|e| map_send_error(e, &url))
}

/// Build and send an HTTP request without a total request timeout.
///
/// For streaming responses, the total duration is unbounded — liveness is
/// enforced by the caller's per-chunk idle timeout instead. Connection
/// establishment is still bounded by the client-level `connect_timeout`.
async fn send_backend_request_streaming(
    client: &reqwest::Client,
    route: &ResolvedRoute,
    method: &str,
    path: &str,
    headers: Vec<(String, String)>,
    body: bytes::Bytes,
) -> Result<reqwest::Response, RouterError> {
    let (builder, url) = prepare_backend_request(client, route, method, path, &headers, body)?;
    builder.send().await.map_err(|e| map_send_error(e, &url))
}

fn validation_probe(route: &ResolvedRoute) -> Result<ValidationProbe, ValidationFailure> {
    if route
        .protocols
        .iter()
        .any(|protocol| protocol == "openai_chat_completions")
    {
        // Use max_completion_tokens (modern OpenAI parameter, required by GPT-5+)
        // with max_tokens as fallback for legacy/self-hosted backends.
        return Ok(ValidationProbe {
            path: "/v1/chat/completions",
            protocol: "openai_chat_completions",
            body: bytes::Bytes::from_static(
                br#"{"messages":[{"role":"user","content":"ping"}],"max_completion_tokens":32}"#,
            ),
            fallback_body: Some(bytes::Bytes::from_static(
                br#"{"messages":[{"role":"user","content":"ping"}],"max_tokens":32}"#,
            )),
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
                br#"{"messages":[{"role":"user","content":"ping"}],"max_tokens":32}"#,
            ),
            fallback_body: None,
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
            body: bytes::Bytes::from_static(br#"{"input":"ping","max_output_tokens":32}"#),
            fallback_body: None,
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
            body: bytes::Bytes::from_static(br#"{"prompt":"ping","max_tokens":32}"#),
            fallback_body: None,
        });
    }

    Err(ValidationFailure {
        kind: ValidationFailureKind::RequestShape,
        details: format!(
            "route '{}' does not expose a writable inference protocol for validation",
            route.name
        ),
    })
}

pub async fn verify_backend_endpoint(
    client: &reqwest::Client,
    route: &ResolvedRoute,
) -> Result<ValidatedEndpoint, ValidationFailure> {
    let probe = validation_probe(route)?;
    let headers = vec![("content-type".to_string(), "application/json".to_string())];

    if mock::is_mock_route(route) {
        return Ok(ValidatedEndpoint {
            url: build_backend_url(&route.endpoint, probe.path),
            protocol: probe.protocol.to_string(),
        });
    }

    let result = try_validation_request(
        client,
        route,
        probe.path,
        probe.protocol,
        headers.clone(),
        probe.body,
    )
    .await;

    // If the primary probe failed with a request-shape error (HTTP 400) and
    // there is a fallback body, retry with the alternate token parameter.
    // This handles the split between `max_completion_tokens` (GPT-5+) and
    // `max_tokens` (legacy/self-hosted backends).
    if let (Err(err), Some(fallback_body)) = (&result, probe.fallback_body) {
        if err.kind == ValidationFailureKind::RequestShape {
            return try_validation_request(
                client,
                route,
                probe.path,
                probe.protocol,
                headers,
                fallback_body,
            )
            .await;
        }
    }

    result
}

/// Send a single validation request and classify the response.
async fn try_validation_request(
    client: &reqwest::Client,
    route: &ResolvedRoute,
    path: &str,
    protocol: &str,
    headers: Vec<(String, String)>,
    body: bytes::Bytes,
) -> Result<ValidatedEndpoint, ValidationFailure> {
    let response = send_backend_request(client, route, "POST", path, headers, body)
        .await
        .map_err(|err| match err {
            RouterError::UpstreamUnavailable(details) => ValidationFailure {
                kind: ValidationFailureKind::Connectivity,
                details,
            },
            RouterError::Internal(details) | RouterError::UpstreamProtocol(details) => {
                ValidationFailure {
                    kind: ValidationFailureKind::Unexpected,
                    details,
                }
            }
            RouterError::RouteNotFound(details)
            | RouterError::NoCompatibleRoute(details)
            | RouterError::Unauthorized(details) => ValidationFailure {
                kind: ValidationFailureKind::Unexpected,
                details,
            },
        })?;
    let url = build_backend_url(&route.endpoint, path);

    if response.status().is_success() {
        return Ok(ValidatedEndpoint {
            url,
            protocol: protocol.to_string(),
        });
    }

    let status = response.status();
    let body = response.text().await.map_err(|e| ValidationFailure {
        kind: ValidationFailureKind::Unexpected,
        details: format!("failed to read validation response body: {e}"),
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

    Err(ValidationFailure {
        kind: match status.as_u16() {
            400 | 404 | 405 | 422 => ValidationFailureKind::RequestShape,
            401 | 403 => ValidationFailureKind::Credentials,
            429 => ValidationFailureKind::RateLimited,
            500..=599 => ValidationFailureKind::UpstreamHealth,
            _ => ValidationFailureKind::Unexpected,
        },
        details,
    })
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
    let response =
        send_backend_request_streaming(client, route, method, path, headers, body).await?;
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
    use super::{ValidationFailureKind, build_backend_url, verify_backend_endpoint};
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
            passthrough_headers: vec![
                "anthropic-version".to_string(),
                "anthropic-beta".to_string(),
            ],
            timeout: crate::config::DEFAULT_ROUTE_TIMEOUT,
        }
    }

    #[test]
    fn sanitize_request_headers_drops_unknown_sensitive_headers() {
        let route = ResolvedRoute {
            name: "inference.local".to_string(),
            endpoint: "https://api.example.com/v1".to_string(),
            model: "test-model".to_string(),
            api_key: "sk-test".to_string(),
            protocols: vec!["openai_chat_completions".to_string()],
            auth: AuthHeader::Bearer,
            default_headers: Vec::new(),
            passthrough_headers: vec!["openai-organization".to_string()],
            timeout: crate::config::DEFAULT_ROUTE_TIMEOUT,
        };

        let kept = super::sanitize_request_headers(
            &route,
            &[
                ("content-type".to_string(), "application/json".to_string()),
                ("authorization".to_string(), "Bearer client".to_string()),
                ("cookie".to_string(), "session=1".to_string()),
                ("x-amz-security-token".to_string(), "token".to_string()),
                ("openai-organization".to_string(), "org_123".to_string()),
            ],
        );

        assert!(
            kept.iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        );
        assert!(
            kept.iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("openai-organization"))
        );
        assert!(
            kept.iter()
                .all(|(name, _)| !name.eq_ignore_ascii_case("authorization"))
        );
        assert!(
            kept.iter()
                .all(|(name, _)| !name.eq_ignore_ascii_case("cookie"))
        );
        assert!(
            kept.iter()
                .all(|(name, _)| !name.eq_ignore_ascii_case("x-amz-security-token"))
        );
    }

    #[test]
    fn sanitize_request_headers_preserves_allowed_provider_headers() {
        let route = test_route(
            "https://api.anthropic.com/v1",
            &["anthropic_messages"],
            AuthHeader::Custom("x-api-key"),
        );

        let kept = super::sanitize_request_headers(
            &route,
            &[
                ("anthropic-version".to_string(), "2024-10-22".to_string()),
                (
                    "anthropic-beta".to_string(),
                    "tool-use-2024-10-22".to_string(),
                ),
                ("x-api-key".to_string(), "client-key".to_string()),
            ],
        );

        assert!(kept.iter().any(
            |(name, value)| name.eq_ignore_ascii_case("anthropic-version") && value == "2024-10-22"
        ));
        assert!(
            kept.iter()
                .any(|(name, value)| name.eq_ignore_ascii_case("anthropic-beta")
                    && value == "tool-use-2024-10-22")
        );
        assert!(
            kept.iter()
                .all(|(name, _)| !name.eq_ignore_ascii_case("x-api-key"))
        );
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
            .and(header("content-type", "application/json"))
            .and(header("anthropic-version", "2023-06-01"))
            .and(body_partial_json(serde_json::json!({
                "model": "test-model",
                "max_tokens": 32,
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

    #[tokio::test]
    async fn verify_backend_endpoint_accepts_mock_routes() {
        let route = test_route(
            "mock://test-backend",
            &["openai_chat_completions"],
            AuthHeader::Bearer,
        );

        let client = reqwest::Client::builder().build().unwrap();
        let validated = verify_backend_endpoint(&client, &route).await.unwrap();

        assert_eq!(validated.protocol, "openai_chat_completions");
        assert_eq!(validated.url, "mock://test-backend/v1/chat/completions");
    }

    /// GPT-5+ models reject `max_tokens` — the primary probe uses
    /// `max_completion_tokens` so validation should succeed directly.
    #[tokio::test]
    async fn verify_openai_chat_uses_max_completion_tokens() {
        let mock_server = MockServer::start().await;
        let route = test_route(
            &mock_server.uri(),
            &["openai_chat_completions"],
            AuthHeader::Bearer,
        );

        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(body_partial_json(serde_json::json!({
                "max_completion_tokens": 32,
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": "chatcmpl-1"})),
            )
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::builder().build().unwrap();
        let validated = verify_backend_endpoint(&client, &route).await.unwrap();

        assert_eq!(validated.protocol, "openai_chat_completions");
    }

    /// Legacy/self-hosted backends that reject `max_completion_tokens`
    /// should succeed on the fallback probe using `max_tokens`.
    #[tokio::test]
    async fn verify_openai_chat_falls_back_to_max_tokens() {
        let mock_server = MockServer::start().await;
        let route = test_route(
            &mock_server.uri(),
            &["openai_chat_completions"],
            AuthHeader::Bearer,
        );

        // Reject the primary probe (max_completion_tokens) with 400.
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(body_partial_json(serde_json::json!({
                "max_completion_tokens": 32,
            })))
            .respond_with(ResponseTemplate::new(400).set_body_string(
                r#"{"error":{"message":"Unsupported parameter: 'max_completion_tokens'"}}"#,
            ))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Accept the fallback probe (max_tokens).
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(body_partial_json(serde_json::json!({
                "max_tokens": 32,
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": "chatcmpl-2"})),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::builder().build().unwrap();
        let validated = verify_backend_endpoint(&client, &route).await.unwrap();

        assert_eq!(validated.protocol, "openai_chat_completions");
    }

    /// Non-chat-completions probes (e.g. anthropic_messages) should not
    /// have a fallback — a 400 remains a hard failure.
    #[tokio::test]
    async fn verify_non_chat_completions_no_fallback() {
        let mock_server = MockServer::start().await;
        let route = test_route(
            &mock_server.uri(),
            &["anthropic_messages"],
            AuthHeader::Custom("x-api-key"),
        );

        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::builder().build().unwrap();
        let result = verify_backend_endpoint(&client, &route).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind,
            ValidationFailureKind::RequestShape
        );
    }
}
