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
    /// Used for `OpenAI` chat completions where newer models require
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

/// The `anthropic_version` value required by Vertex AI's rawPredict endpoint for
/// Anthropic Claude models. Google publishes this version string; update here if
/// the Vertex AI Anthropic API version changes.
///
/// See: <https://cloud.google.com/vertex-ai/generative-ai/docs/partner-models/use-claude>
const VERTEX_ANTHROPIC_VERSION: &str = "vertex-2023-10-16";

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

    // Vertex AI Anthropic rawPredict endpoints do not accept the
    // `anthropic-beta` header. Beta feature enablement for Vertex AI is
    // controlled through Google Cloud, not HTTP headers. Strip it here so
    // clients (e.g. Claude Code) that always send beta flags don't cause
    // HTTP 400 errors from the Vertex AI backend.
    let strip_anthropic_beta = is_vertex_anthropic_rawpredict_route(route);

    headers
        .iter()
        .filter_map(|(name, value)| {
            let name_lc = name.to_ascii_lowercase();
            if should_strip_request_header(&name_lc) || !allowed.contains(&name_lc) {
                return None;
            }
            if strip_anthropic_beta && name_lc == "anthropic-beta" {
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
///
/// `stream_response` controls whether Vertex AI Anthropic routes upgrade the
/// stored `:rawPredict` suffix to `:streamRawPredict` in the upstream URL.
/// It must match the transport the caller intends to use:
///
/// | Caller                      | `stream_response` | Vertex suffix used     |
/// |-----------------------------|-------------------|------------------------|
/// | `send_backend_request`      | `false`           | `:rawPredict` (unary)  |
/// | `send_backend_request_streaming` | `true`       | `:streamRawPredict`    |
///
/// `verify_backend_endpoint` explicitly passes `false` to probe the unary
/// `:rawPredict` endpoint during validation. The `inference.local` intercept
/// path always calls `send_backend_request_streaming` (and therefore always
/// passes `true`), but `:streamRawPredict` accepts both streaming and
/// non-streaming request bodies, so the behaviour is correct in all cases.
fn prepare_backend_request(
    client: &reqwest::Client,
    route: &ResolvedRoute,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: bytes::Bytes,
    stream_response: bool,
) -> Result<(reqwest::RequestBuilder, String), RouterError> {
    let url = build_provider_url(route, &route.model, path, stream_response);
    let headers = sanitize_request_headers(route, headers);

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

    // Rewrite the JSON body for backend compatibility:
    // - Standard routes: set "model" to the route's configured model so the
    //   backend receives the correct model ID regardless of what the client sent.
    // - Vertex AI rawPredict routes: remove "model" (it is encoded in the URL
    //   path) and inject "anthropic_version" (required in the body, not a header).
    // Non-JSON bodies pass through unchanged; model rewrite and version injection
    // are silently skipped. Such bodies would be rejected by the upstream anyway.
    let body = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(mut json) => {
            if let Some(obj) = json.as_object_mut() {
                // Vertex AI Anthropic endpoints require anthropic_version in the body.
                // Standard Anthropic SDK sends it as a header; Vertex AI needs it as a body field.
                // We inject it only for the Vertex rawPredict-style route contract used for
                // Anthropic publisher endpoints, not for arbitrary model-in-path routes.
                let needs_vertex_anthropic_version = is_vertex_anthropic_rawpredict_route(route);
                if needs_vertex_anthropic_version {
                    // Vertex AI rawPredict encodes the model in the URL path, not
                    // the request body. Clients using the standard Anthropic API
                    // (e.g. Claude Code via inference.local) always send "model"
                    // in the body; strip it so Vertex AI does not reject the
                    // request with "Extra inputs are not permitted".
                    obj.remove("model");
                } else {
                    obj.insert(
                        "model".to_string(),
                        serde_json::Value::String(route.model.clone()),
                    );
                }
                if needs_vertex_anthropic_version && !obj.contains_key("anthropic_version") {
                    obj.insert(
                        "anthropic_version".to_string(),
                        serde_json::Value::String(VERTEX_ANTHROPIC_VERSION.to_string()),
                    );
                }
            }

            bytes::Bytes::from(serde_json::to_vec(&json).map_err(|err| {
                RouterError::Internal(format!(
                    "failed to serialize rewritten inference request body: {err}"
                ))
            })?)
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
    let (builder, url) =
        prepare_backend_request(client, route, method, path, &headers, body, false)?;
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
    let (builder, url) =
        prepare_backend_request(client, route, method, path, &headers, body, true)?;
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
            url: build_provider_url(route, &route.model, probe.path, false),
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
    if let (Err(err), Some(fallback_body)) = (&result, probe.fallback_body)
        && err.kind == ValidationFailureKind::RequestShape
    {
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
    let url = build_provider_url(route, &route.model, path, false);

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

/// Build the upstream URL for a provider route.
///
/// `stream_response` selects between the unary and streaming Vertex AI
/// Anthropic endpoint suffixes. Pass the same value used for the enclosing
/// [`prepare_backend_request`] call. See that function's documentation for the
/// full caller table.
///
/// Behavior matrix (`request_path_override`, `model_in_path`):
/// - `(Some(suffix), true)`: `{endpoint}/{model_id}{suffix}`
///   Used by Vertex AI Anthropic: `stream_response=false` keeps `:rawPredict`
///   (unary); `stream_response=true` upgrades to `:streamRawPredict`.
/// - `(Some(override_path), false)`: `{endpoint}{override_path}`
///   Used when a fixed path replaces the protocol-derived path.
/// - `(None, true)`: `{endpoint}/{model_id}/{protocol_path}`
///   Model embedded before protocol path.
/// - `(None, false)`: delegates to `build_backend_url` (default, with /v1 dedup).
fn build_provider_url(
    route: &ResolvedRoute,
    model_id: &str,
    protocol_path: &str,
    stream_response: bool,
) -> String {
    let base = route.endpoint.trim_end_matches('/');
    match (&route.request_path_override, route.model_in_path) {
        // Vertex AI publisher endpoint: model in URL path with suffix
        // e.g. .../publishers/anthropic/models/claude-3-5-sonnet@20241022:rawPredict
        (Some(suffix), true) => {
            // suffix is appended directly after model_id (e.g. ":rawPredict").
            // It must not start with '/' — use the (Some, false) arm for path overrides.
            debug_assert!(
                !suffix.starts_with('/'),
                "suffix in model_in_path branch must not start with '/'; got: {suffix:?}"
            );
            let suffix = if stream_response
                && suffix == ":rawPredict"
                && is_vertex_anthropic_rawpredict_route(route)
            {
                ":streamRawPredict"
            } else {
                suffix.as_str()
            };
            format!("{base}/{model_id}{suffix}")
        }
        // Explicit path override, model NOT in URL.
        // Normalize: ensure override_path begins with '/' so the concatenation
        // never produces a broken URL like `https://host.compath`.
        (Some(override_path), false) => {
            if override_path.starts_with('/') || override_path.is_empty() {
                format!("{base}{override_path}")
            } else {
                format!("{base}/{override_path}")
            }
        }
        // Model in path, no override — append model then protocol-derived path
        (None, true) => {
            let path = protocol_path.trim_start_matches('/');
            format!("{base}/{model_id}/{path}")
        }
        // Default: existing behavior (includes /v1 deduplication)
        (None, false) => build_backend_url(&route.endpoint, protocol_path),
    }
}

fn build_backend_url(endpoint: &str, path: &str) -> String {
    let base = endpoint.trim_end_matches('/');
    if base.ends_with("/v1") && (path == "/v1" || path.starts_with("/v1/")) {
        return format!("{base}{}", &path[3..]);
    }

    format!("{base}{path}")
}

/// Check whether a route targets a Vertex AI Anthropic rawPredict endpoint.
///
/// The predicate is purely structural — it tests `model_in_path`,
/// `anthropic_messages` protocol, and `:rawPredict` suffix — so any future
/// provider with the same route shape automatically inherits the same
/// transforms without code changes.
///
/// The router stores the neutral `:rawPredict` suffix on resolved routes.
/// [`build_provider_url`] upgrades it to `:streamRawPredict` when
/// `stream_response=true` (see [`prepare_backend_request`] for the caller
/// table). [`verify_backend_endpoint`] deliberately passes `stream_response=false`
/// to probe the unary endpoint during validation.
fn is_vertex_anthropic_rawpredict_route(route: &ResolvedRoute) -> bool {
    route.model_in_path
        && route.protocols.iter().any(|p| p == "anthropic_messages")
        && route
            .request_path_override
            .as_deref()
            .is_some_and(|suffix| suffix == ":rawPredict")
}

#[cfg(test)]
mod tests {
    use super::{
        ValidationFailureKind, build_backend_url, build_provider_url, verify_backend_endpoint,
    };
    use crate::config::{DEFAULT_ROUTE_TIMEOUT, ResolvedRoute};
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
            timeout: DEFAULT_ROUTE_TIMEOUT,
            model_in_path: false,
            request_path_override: None,
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
            timeout: DEFAULT_ROUTE_TIMEOUT,
            model_in_path: false,
            request_path_override: None,
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

    #[test]
    fn vertex_anthropic_rawpredict_strips_anthropic_beta() {
        // Vertex AI rawPredict endpoints reject the anthropic-beta header.
        // The router must strip it before forwarding to avoid HTTP 400 errors
        // from the Vertex AI backend when clients (e.g. Claude Code) always
        // send beta feature flags.
        let route = ResolvedRoute {
            name: "inference.local".to_string(),
            endpoint: "https://us-central1-aiplatform.googleapis.com/v1/projects/proj/locations/us-central1/publishers/anthropic/models".to_string(),
            model: "claude-sonnet-4-20250514".to_string(),
            api_key: "ya29.token".to_string(),
            protocols: vec!["anthropic_messages".to_string()],
            auth: AuthHeader::Bearer,
            default_headers: vec![],
            passthrough_headers: vec!["anthropic-beta".to_string()],
            timeout: DEFAULT_ROUTE_TIMEOUT,
            model_in_path: true,
            request_path_override: Some(":rawPredict".to_string()),
        };

        let headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            (
                "anthropic-beta".to_string(),
                "prompt-caching-scope-2026-01-05,redact-thinking-2026-02-12".to_string(),
            ),
        ];

        let kept = super::sanitize_request_headers(&route, &headers);

        assert!(
            kept.iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("content-type")),
            "content-type should be preserved"
        );
        assert!(
            kept.iter()
                .all(|(name, _)| !name.eq_ignore_ascii_case("anthropic-beta")),
            "anthropic-beta must be stripped for Vertex AI rawPredict routes"
        );
    }

    #[test]
    fn direct_anthropic_preserves_anthropic_beta() {
        // The anthropic-beta header must still pass through for direct
        // Anthropic API routes -- only Vertex AI rawPredict strips it.
        let route = test_route(
            "https://api.anthropic.com/v1",
            &["anthropic_messages"],
            AuthHeader::Custom("x-api-key"),
        );

        let headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            (
                "anthropic-beta".to_string(),
                "prompt-caching-2024-07-31".to_string(),
            ),
        ];

        let kept = super::sanitize_request_headers(&route, &headers);

        assert!(
            kept.iter()
                .any(|(name, value)| name.eq_ignore_ascii_case("anthropic-beta")
                    && value == "prompt-caching-2024-07-31"),
            "anthropic-beta must be preserved for direct Anthropic API routes"
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

    /// Non-chat-completions probes (e.g. `anthropic_messages`) should not
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

    #[tokio::test]
    async fn verify_vertex_anthropic_route_uses_buffered_rawpredict_probe() {
        let mock_server = MockServer::start().await;
        let route = ResolvedRoute {
            name: "vertex-anthropic".to_string(),
            endpoint: format!(
                "{}/v1/projects/my-project/locations/us-east5/publishers/anthropic/models",
                mock_server.uri()
            ),
            model: "claude-3-5-sonnet@20241022".to_string(),
            api_key: "ya29.token".to_string(),
            protocols: vec!["anthropic_messages".to_string()],
            auth: AuthHeader::Bearer,
            default_headers: Vec::new(),
            passthrough_headers: Vec::new(),
            timeout: DEFAULT_ROUTE_TIMEOUT,
            model_in_path: true,
            request_path_override: Some(":rawPredict".to_string()),
        };

        Mock::given(method("POST"))
            .and(path(
                "/v1/projects/my-project/locations/us-east5/publishers/anthropic/models/claude-3-5-sonnet@20241022:rawPredict",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "msg_vertex_verify"
            })))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::builder().build().unwrap();
        let validated = verify_backend_endpoint(&client, &route).await.unwrap();
        assert!(
            validated.url.ends_with(":rawPredict"),
            "buffered verification should probe the unary Vertex endpoint, got: {}",
            validated.url
        );
    }

    /// Vertex AI pattern: `model_in_path=true`, `request_path_override=Some(":rawPredict")`
    /// means buffered requests POST to `base_url/model_id:rawPredict`.
    #[test]
    fn build_provider_url_model_in_path_with_suffix() {
        let route = ResolvedRoute {
            name: "inference.local".to_string(),
            endpoint:
                "https://us-east5-aiplatform.googleapis.com/v1/projects/my-project/locations/us-east5/publishers/anthropic/models"
                    .to_string(),
            model: "claude-3-5-sonnet@20241022".to_string(),
            api_key: "token".to_string(),
            protocols: vec!["anthropic_messages".to_string()],
            auth: AuthHeader::Bearer,
            default_headers: Vec::new(),
            passthrough_headers: Vec::new(),
            timeout: DEFAULT_ROUTE_TIMEOUT,
            model_in_path: true,
            request_path_override: Some(":rawPredict".to_string()),
        };

        let url = build_provider_url(&route, "claude-3-5-sonnet@20241022", "/v1/messages", false);
        assert!(
            url.ends_with("/claude-3-5-sonnet@20241022:rawPredict"),
            "expected URL to end with model id and suffix, got: {url}"
        );
        assert!(
            !url.contains("/v1/messages"),
            "expected no protocol path appended, got: {url}"
        );
    }

    #[test]
    fn build_provider_url_vertex_anthropic_streaming_upgrades_to_stream_rawpredict() {
        let route = ResolvedRoute {
            name: "inference.local".to_string(),
            endpoint:
                "https://us-east5-aiplatform.googleapis.com/v1/projects/my-project/locations/us-east5/publishers/anthropic/models"
                    .to_string(),
            model: "claude-3-5-sonnet@20241022".to_string(),
            api_key: "token".to_string(),
            protocols: vec!["anthropic_messages".to_string()],
            auth: AuthHeader::Bearer,
            default_headers: Vec::new(),
            passthrough_headers: Vec::new(),
            timeout: DEFAULT_ROUTE_TIMEOUT,
            model_in_path: true,
            request_path_override: Some(":rawPredict".to_string()),
        };

        let url = build_provider_url(&route, "claude-3-5-sonnet@20241022", "/v1/messages", true);
        assert!(
            url.ends_with("/claude-3-5-sonnet@20241022:streamRawPredict"),
            "expected streaming URL to upgrade the suffix, got: {url}"
        );
    }

    /// Vertex AI pattern: `model_in_path=true`, `request_path_override=Some("")` (empty suffix)
    /// means POST directly to `base_url/model_id` with no additional path segment.
    #[test]
    fn build_provider_url_model_in_path_empty_suffix() {
        let route = ResolvedRoute {
            name: "inference.local".to_string(),
            endpoint: "https://example.com/models".to_string(),
            model: "my-model".to_string(),
            api_key: "token".to_string(),
            protocols: vec!["anthropic_messages".to_string()],
            auth: AuthHeader::Bearer,
            default_headers: Vec::new(),
            passthrough_headers: Vec::new(),
            timeout: DEFAULT_ROUTE_TIMEOUT,
            model_in_path: true,
            request_path_override: Some(String::new()),
        };

        let url = build_provider_url(&route, "my-model", "/v1/messages", false);
        assert_eq!(url, "https://example.com/models/my-model");
    }

    /// Explicit path override: `request_path_override=Some("/v1/chat/completions")`
    /// appends the override path to `base_url`, ignoring `model_in_path`.
    #[test]
    fn build_provider_url_with_path_override() {
        let route = ResolvedRoute {
            name: "inference.local".to_string(),
            endpoint: "https://api.example.com".to_string(),
            model: "some-model".to_string(),
            api_key: "key".to_string(),
            protocols: vec!["openai_chat_completions".to_string()],
            auth: AuthHeader::Bearer,
            default_headers: Vec::new(),
            passthrough_headers: Vec::new(),
            timeout: DEFAULT_ROUTE_TIMEOUT,
            model_in_path: false,
            request_path_override: Some("/v1/chat/completions".to_string()),
        };

        let url = build_provider_url(&route, "some-model", "/v1/chat/completions", false);
        assert!(
            url.ends_with("/v1/chat/completions"),
            "expected URL to end with path override, got: {url}"
        );
    }

    /// Default behavior: `model_in_path=false`, `request_path_override=None` uses
    /// the existing `build_backend_url` logic (protocol-derived path only).
    #[test]
    fn build_provider_url_default_behavior() {
        let route = ResolvedRoute {
            name: "inference.local".to_string(),
            endpoint: "https://api.openai.com/v1".to_string(),
            model: "gpt-4o".to_string(),
            api_key: "key".to_string(),
            protocols: vec!["openai_chat_completions".to_string()],
            auth: AuthHeader::Bearer,
            default_headers: Vec::new(),
            passthrough_headers: Vec::new(),
            timeout: DEFAULT_ROUTE_TIMEOUT,
            model_in_path: false,
            request_path_override: None,
        };

        let url = build_provider_url(&route, "gpt-4o", "/v1/chat/completions", false);
        assert_eq!(
            url, "https://api.openai.com/v1/chat/completions",
            "default behavior should dedupe v1 prefix and use protocol path"
        );
    }

    #[test]
    fn build_provider_url_override_path_normalizes_missing_leading_slash() {
        // An override_path without a leading '/' must not produce a broken URL.
        let route = ResolvedRoute {
            name: "test".to_string(),
            endpoint: "https://example.com/v1/projects/proj/locations/us/endpoints/openapi"
                .to_string(),
            model: "gemini-pro".to_string(),
            api_key: "key".to_string(),
            protocols: vec!["openai_chat_completions".to_string()],
            auth: AuthHeader::Bearer,
            default_headers: Vec::new(),
            passthrough_headers: Vec::new(),
            timeout: DEFAULT_ROUTE_TIMEOUT,
            model_in_path: false,
            request_path_override: Some("chat/completions".to_string()), // no leading slash
        };
        let url = build_provider_url(&route, &route.model, "/v1/chat/completions", false);
        // Must not produce https://...openaichat/completions
        assert!(
            url.contains("/chat/completions"),
            "URL must contain /chat/completions, got: {url}"
        );
        assert!(
            !url.contains("openaichat"),
            "URL must not smash endpoint and path, got: {url}"
        );
        assert_eq!(
            url,
            "https://example.com/v1/projects/proj/locations/us/endpoints/openapi/chat/completions"
        );
    }

    /// Vertex AI Anthropic routes require `anthropic_version` in the request body.
    /// Verify it is injected on the buffered `:rawPredict` path when the client
    /// did not already include it.
    #[tokio::test]
    async fn vertex_ai_body_injects_anthropic_version() {
        let mock_server = MockServer::start().await;

        // Build a Vertex-AI-style route: model in path, suffix :rawPredict
        let base_path = "/v1/projects/my-project/locations/us-east5/publishers/anthropic/models";
        let route = ResolvedRoute {
            name: "vertex-anthropic".to_string(),
            endpoint: format!("{}{base_path}", mock_server.uri()),
            model: "claude-3-5-sonnet@20241022".to_string(),
            api_key: "ya29.token".to_string(),
            protocols: vec!["anthropic_messages".to_string()],
            auth: AuthHeader::Bearer,
            default_headers: Vec::new(),
            passthrough_headers: Vec::new(),
            timeout: DEFAULT_ROUTE_TIMEOUT,
            model_in_path: true,
            request_path_override: Some(":rawPredict".to_string()),
        };

        Mock::given(method("POST"))
            .and(path(format!(
                "{base_path}/claude-3-5-sonnet@20241022:rawPredict"
            )))
            .and(body_partial_json(serde_json::json!({
                "anthropic_version": "vertex-2023-10-16",
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": "msg_vertex_1"})),
            )
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::builder().build().unwrap();
        let body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 32,
            }))
            .unwrap(),
        );
        let headers = vec![("content-type".to_string(), "application/json".to_string())];

        let (builder, _url) = super::prepare_backend_request(
            &client,
            &route,
            "POST",
            "/v1/messages",
            &headers,
            body,
            false,
        )
        .unwrap();

        let response = builder.send().await.unwrap();
        assert_eq!(
            response.status().as_u16(),
            200,
            "mock should match body with anthropic_version injected"
        );
        let received = mock_server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        let received_body: serde_json::Value = serde_json::from_slice(&received[0].body).unwrap();
        assert!(
            !received_body.as_object().unwrap().contains_key("model"),
            "Vertex Anthropic route must not inject model into the body, got: {received_body}"
        );
    }

    /// Claude Code and other Anthropic SDK clients always send "model" in the
    /// request body. For Vertex AI rawPredict routes the model is in the URL
    /// path; the body field must be stripped to avoid HTTP 400
    /// "Extra inputs are not permitted" from the Vertex AI backend.
    #[tokio::test]
    async fn vertex_ai_body_strips_client_model_field() {
        let mock_server = MockServer::start().await;

        let base_path = "/v1/projects/my-project/locations/us-east5/publishers/anthropic/models";
        let route = ResolvedRoute {
            name: "vertex-anthropic".to_string(),
            endpoint: format!("{}{base_path}", mock_server.uri()),
            model: "claude-3-5-sonnet@20241022".to_string(),
            api_key: "ya29.token".to_string(),
            protocols: vec!["anthropic_messages".to_string()],
            auth: AuthHeader::Bearer,
            default_headers: Vec::new(),
            passthrough_headers: Vec::new(),
            timeout: DEFAULT_ROUTE_TIMEOUT,
            model_in_path: true,
            request_path_override: Some(":rawPredict".to_string()),
        };

        Mock::given(method("POST"))
            .and(path(format!(
                "{base_path}/claude-3-5-sonnet@20241022:rawPredict"
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": "msg_1"})),
            )
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::builder().build().unwrap();
        // Simulate a client (e.g. Claude Code) that always sends "model" in the body.
        let body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "model": "claude-3-5-sonnet-20241022",
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 32,
            }))
            .unwrap(),
        );
        let headers = vec![("content-type".to_string(), "application/json".to_string())];

        let (builder, _url) = super::prepare_backend_request(
            &client,
            &route,
            "POST",
            "/v1/messages",
            &headers,
            body,
            false,
        )
        .unwrap();

        let response = builder.send().await.unwrap();
        assert_eq!(response.status().as_u16(), 200);
        let received = mock_server.received_requests().await.unwrap();
        let received_body: serde_json::Value = serde_json::from_slice(&received[0].body).unwrap();
        assert!(
            !received_body.as_object().unwrap().contains_key("model"),
            "model field must be stripped from Vertex AI rawPredict body, got: {received_body}"
        );
    }

    #[tokio::test]
    async fn vertex_ai_body_preserves_client_anthropic_version() {
        // When the client already sends anthropic_version, the router must NOT overwrite it.
        let mock_server = MockServer::start().await;

        // Expect the body to contain the client's version, NOT "vertex-2023-10-16"
        Mock::given(method("POST"))
            .and(body_partial_json(serde_json::json!({
                "anthropic_version": "custom-client-version",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "model": "claude-3-5-sonnet@20241022",
                "content": [{"type": "text", "text": "ok"}]
            })))
            .mount(&mock_server)
            .await;

        let router = crate::Router::new().unwrap();
        let candidates = vec![ResolvedRoute {
            name: "vertex-test".to_string(),
            endpoint: format!(
                "{}/v1/projects/proj/locations/us-east5/publishers/anthropic/models",
                mock_server.uri()
            ),
            model: "claude-3-5-sonnet@20241022".to_string(),
            api_key: "ya29.test".to_string(),
            protocols: vec!["anthropic_messages".to_string()],
            auth: AuthHeader::Bearer,
            default_headers: Vec::new(),
            passthrough_headers: Vec::new(),
            timeout: DEFAULT_ROUTE_TIMEOUT,
            model_in_path: true,
            request_path_override: Some(":rawPredict".to_string()),
        }];

        let body = serde_json::to_vec(&serde_json::json!({
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 32,
            "anthropic_version": "custom-client-version",
        }))
        .unwrap();

        let response = router
            .proxy_with_candidates(
                "anthropic_messages",
                "POST",
                "/v1/messages",
                vec![("content-type".to_string(), "application/json".to_string())],
                bytes::Bytes::from(body),
                &candidates,
            )
            .await
            .unwrap();

        assert_eq!(
            response.status, 200,
            "proxy should succeed when client sends anthropic_version"
        );
    }

    /// Standard Anthropic route (`model_in_path=false`) must NOT inject `anthropic_version`.
    /// Vertex body injection must not affect non-Vertex Anthropic providers.
    #[tokio::test]
    async fn standard_anthropic_body_does_not_inject_vertex_anthropic_version() {
        let mock_server = MockServer::start().await;

        let route = ResolvedRoute {
            name: "anthropic-direct".to_string(),
            endpoint: mock_server.uri(),
            model: "claude-3-5-sonnet-20241022".to_string(),
            api_key: "sk-ant-test".to_string(),
            protocols: vec!["anthropic_messages".to_string()],
            auth: AuthHeader::Custom("x-api-key"),
            default_headers: Vec::new(),
            passthrough_headers: Vec::new(),
            timeout: DEFAULT_ROUTE_TIMEOUT,
            model_in_path: false,
            request_path_override: None,
        };

        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": "msg_1"})),
            )
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::builder().build().unwrap();
        let body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 32,
            }))
            .unwrap(),
        );
        let headers = vec![("content-type".to_string(), "application/json".to_string())];

        let (builder, _url) = super::prepare_backend_request(
            &client,
            &route,
            "POST",
            "/v1/messages",
            &headers,
            body,
            false,
        )
        .unwrap();

        builder.send().await.unwrap();

        let received = mock_server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        let received_body: serde_json::Value = serde_json::from_slice(&received[0].body).unwrap();
        assert!(
            !received_body
                .as_object()
                .unwrap()
                .contains_key("anthropic_version"),
            "standard Anthropic route must not inject anthropic_version, got: {received_body}"
        );
    }

    /// Model-in-path alone is not enough; only Vertex rawPredict-style routes should inject.
    #[tokio::test]
    async fn anthropic_model_in_path_without_rawpredict_suffix_does_not_inject_version() {
        let mock_server = MockServer::start().await;

        let route = ResolvedRoute {
            name: "non-vertex-model-path".to_string(),
            endpoint: format!("{}/publisher/models", mock_server.uri()),
            model: "claude-3-5-sonnet@20241022".to_string(),
            api_key: "token".to_string(),
            protocols: vec!["anthropic_messages".to_string()],
            auth: AuthHeader::Bearer,
            default_headers: Vec::new(),
            passthrough_headers: Vec::new(),
            timeout: DEFAULT_ROUTE_TIMEOUT,
            model_in_path: true,
            request_path_override: Some(String::new()),
        };

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"id": "msg_model_path"})),
            )
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::builder().build().unwrap();
        let body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 32,
            }))
            .unwrap(),
        );
        let headers = vec![("content-type".to_string(), "application/json".to_string())];

        let (builder, _url) = super::prepare_backend_request(
            &client,
            &route,
            "POST",
            "/v1/messages",
            &headers,
            body,
            false,
        )
        .unwrap();

        builder.send().await.unwrap();

        let received = mock_server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        let received_body: serde_json::Value = serde_json::from_slice(&received[0].body).unwrap();
        assert!(
            !received_body
                .as_object()
                .unwrap()
                .contains_key("anthropic_version"),
            "non-rawPredict model-in-path routes must not inject anthropic_version, got: {received_body}"
        );
    }

    /// Vertex AI Gemini route (`model_in_path=false`, `openai_chat_completions`) must NOT inject.
    #[tokio::test]
    async fn vertex_gemini_body_does_not_inject_vertex_anthropic_version() {
        let mock_server = MockServer::start().await;

        let route = ResolvedRoute {
            name: "vertex-gemini".to_string(),
            endpoint: format!(
                "{}/v1beta1/projects/my-project/locations/us-central1/endpoints/openapi",
                mock_server.uri()
            ),
            model: "gemini-pro".to_string(),
            api_key: "ya29.token".to_string(),
            protocols: vec!["openai_chat_completions".to_string()],
            auth: AuthHeader::Bearer,
            default_headers: Vec::new(),
            passthrough_headers: Vec::new(),
            timeout: DEFAULT_ROUTE_TIMEOUT,
            model_in_path: false,
            request_path_override: None,
        };

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": "msg_gemini"})),
            )
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::builder().build().unwrap();
        let body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 32,
            }))
            .unwrap(),
        );
        let headers = vec![("content-type".to_string(), "application/json".to_string())];

        let (builder, _url) = super::prepare_backend_request(
            &client,
            &route,
            "POST",
            "/v1/chat/completions",
            &headers,
            body,
            false,
        )
        .unwrap();

        builder.send().await.unwrap();

        let received = mock_server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        let received_body: serde_json::Value = serde_json::from_slice(&received[0].body).unwrap();
        assert!(
            !received_body
                .as_object()
                .unwrap()
                .contains_key("anthropic_version"),
            "Vertex Gemini route must not inject anthropic_version, got: {received_body}"
        );
        assert_eq!(
            received_body
                .as_object()
                .unwrap()
                .get("model")
                .and_then(serde_json::Value::as_str),
            Some("gemini-pro"),
            "Vertex Gemini route must still rewrite the model field, got: {received_body}"
        );
    }
}
