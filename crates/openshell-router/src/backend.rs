// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::RouterError;
use crate::config::{AuthHeader, ResolvedRoute};
use crate::mock;
use std::collections::HashSet;

/// Maximum buffered inference response body, in bytes. The buffered path
/// reads the whole response into memory; the route timeout bounds time, not
/// memory, so without this cap an oversized upstream could force unbounded
/// allocation. Mirrors the sandbox streaming byte cap. Over-cap responses fail
/// as an upstream protocol error.
const MAX_BUFFERED_RESPONSE_BODY: usize = 32 * 1024 * 1024;

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
    /// Alternate body to try when the primary probe is rejected specifically
    /// for `max_completion_tokens`. Used for `OpenAI` chat completions where
    /// newer models require `max_completion_tokens` while legacy/self-hosted
    /// backends only accept `max_tokens`. The retry is gated on the error
    /// body naming that parameter, so an unrelated request-shape rejection
    /// (wrong protocol for the model) falls through instead.
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

/// Request body fields that are Anthropic SDK extension features not
/// supported by Vertex AI rawPredict endpoints. These cause HTTP 400
/// "Extra inputs are not permitted" if forwarded to Vertex AI.
///
/// Add new fields here as Claude Code and other Anthropic SDK clients
/// introduce new extension-only body fields.
const VERTEX_INCOMPATIBLE_BODY_FIELDS: &[&str] = &[
    // Vertex AI rawPredict encodes the model in the URL path, not the request body.
    // Clients using the standard Anthropic API always send "model" in the body; strip it.
    "model",
    // Claude Code 2.1.x context management feature (USE_API_CONTEXT_MANAGEMENT).
    // Disabled in clients by CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1.
    // Vertex AI schema does not include this field; it causes HTTP 400.
    "context_management",
];

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
    // For AWS Bedrock routes the model id is encoded in the URL path
    // (`/model/{modelId}/invoke[-with-response-stream]`), not in the
    // JSON body. The caller's path can carry any model id; rewrite it
    // to the operator-configured `route.model` so a sandbox cannot
    // pick a different upstream model than what `inference set`
    // configured. If the path is not a recognized Bedrock shape on a
    // Bedrock route, reject the request rather than forwarding
    // verbatim.
    let rewritten_path: String;
    let path = if route_is_bedrock(route) {
        match rewrite_bedrock_path(route, path) {
            Some(p) => {
                rewritten_path = p;
                rewritten_path.as_str()
            }
            None => {
                return Err(RouterError::Internal(format!(
                    "AWS Bedrock route received unprocessable path '{path}' or invalid \
                     route.model; expected /model/<id>/invoke and a model id with no \
                     path separators, URL delimiters, percent escapes, traversal \
                     segments, whitespace, or control characters"
                )));
            }
        }
    } else {
        path
    };
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
        AuthHeader::None => {
            // Bridge-fronted upstream: no router-side auth injection.
            // The configured `endpoint` is expected to be a translating
            // bridge / proxy whose own pod holds operator-side
            // credentials. Used today by the `aws-bedrock` profile
            // (SigV4 signing is a separate follow-up).
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
                    // Strip body fields not supported by Vertex AI rawPredict.
                    // Vertex AI schema-validates the request body and rejects unknown fields with
                    // HTTP 400 "Extra inputs are not permitted". Header-level betas are already
                    // stripped above (`strip_anthropic_beta`); this handles the body-field equivalent.
                    for field in VERTEX_INCOMPATIBLE_BODY_FIELDS {
                        obj.remove(*field);
                    }
                } else if route_is_bedrock(route) {
                    // AWS Bedrock InvokeModel encodes the model in the URL
                    // path; the request body is the raw provider-specific
                    // payload (e.g. an Anthropic Messages body for Claude
                    // models, a Mistral payload for Mistral models). The
                    // body must not be mutated — injecting a "model" field
                    // here would either be silently ignored or rejected as
                    // an unexpected key by the upstream / bridge.
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
    headers: &[(String, String)],
    body: bytes::Bytes,
) -> Result<reqwest::Response, RouterError> {
    let (builder, url) =
        prepare_backend_request(client, route, method, path, headers, body, false)?;
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
    headers: &[(String, String)],
    body: bytes::Bytes,
) -> Result<reqwest::Response, RouterError> {
    let (builder, url) = prepare_backend_request(client, route, method, path, headers, body, true)?;
    builder.send().await.map_err(|e| map_send_error(e, &url))
}

/// Validation probes for a route, in preference order.
///
/// A managed route advertises every protocol in its provider profile, so an
/// embeddings model resolves to a route that also lists chat/completions. The
/// caller tries these in order and falls through to the next on a request-shape
/// rejection, so such a model validates against `/v1/embeddings` even though
/// the chat probe rejects it. Embeddings is ordered last so a genuinely
/// chat-capable route still validates against chat. Empty when the route
/// exposes no writable protocol.
fn validation_probes(route: &ResolvedRoute) -> Vec<ValidationProbe> {
    let has = |protocol: &str| route.protocols.iter().any(|p| p == protocol);
    let mut probes = Vec::new();

    if has("openai_chat_completions") {
        // Use max_completion_tokens (modern OpenAI parameter, required by GPT-5+)
        // with max_tokens as fallback for legacy/self-hosted backends.
        probes.push(ValidationProbe {
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

    if has("anthropic_messages") {
        probes.push(ValidationProbe {
            path: "/v1/messages",
            protocol: "anthropic_messages",
            body: bytes::Bytes::from_static(
                br#"{"messages":[{"role":"user","content":"ping"}],"max_tokens":32}"#,
            ),
            fallback_body: None,
        });
    }

    if has("openai_responses") {
        probes.push(ValidationProbe {
            path: "/v1/responses",
            protocol: "openai_responses",
            body: bytes::Bytes::from_static(br#"{"input":"ping","max_output_tokens":32}"#),
            fallback_body: None,
        });
    }

    if has("openai_completions") {
        probes.push(ValidationProbe {
            path: "/v1/completions",
            protocol: "openai_completions",
            body: bytes::Bytes::from_static(br#"{"prompt":"ping","max_tokens":32}"#),
            fallback_body: None,
        });
    }

    // Last so a chat-capable route prefers a chat probe, but an embeddings-only
    // model still validates against its single writable endpoint.
    if has("openai_embeddings") {
        probes.push(ValidationProbe {
            path: "/v1/embeddings",
            protocol: "openai_embeddings",
            body: bytes::Bytes::from_static(br#"{"input":"ping"}"#),
            fallback_body: None,
        });
    }

    probes
}

/// The request-shape failure for a route that advertises no writable protocol.
///
/// Shared by the empty-probe guard and the all-probes-failed fallback so the
/// otherwise-unreachable terminal case is a value rather than a panic.
fn no_writable_protocol_failure(route: &ResolvedRoute) -> ValidationFailure {
    ValidationFailure {
        kind: ValidationFailureKind::RequestShape,
        details: format!(
            "route '{}' does not expose a writable inference protocol for validation",
            route.name
        ),
    }
}

pub async fn verify_backend_endpoint(
    client: &reqwest::Client,
    route: &ResolvedRoute,
) -> Result<ValidatedEndpoint, ValidationFailure> {
    let probes = validation_probes(route);
    let Some(first) = probes.first() else {
        return Err(no_writable_protocol_failure(route));
    };

    if mock::is_mock_route(route) {
        return Ok(ValidatedEndpoint {
            url: build_provider_url(route, &route.model, first.path, false),
            protocol: first.protocol.to_string(),
        });
    }

    let headers = vec![("content-type".to_string(), "application/json".to_string())];
    let mut last_shape_failure = None;

    for probe in &probes {
        match try_validation_probe(client, route, probe, &headers).await {
            Ok(endpoint) => return Ok(endpoint),
            // A request-shape rejection means this protocol is wrong for the
            // model (e.g. a chat probe against an embeddings model), so fall
            // through to the next advertised protocol. Any other failure
            // describes the backend itself (credentials, rate limit,
            // connectivity, health) and is terminal across all protocols.
            //
            // Keep the first shape failure: it is the most-preferred protocol's
            // rejection and the most actionable error to report.
            Err(err) if err.kind == ValidationFailureKind::RequestShape => {
                last_shape_failure.get_or_insert(err);
            }
            Err(err) => return Err(err),
        }
    }

    Err(last_shape_failure.unwrap_or_else(|| no_writable_protocol_failure(route)))
}

/// Run one validation probe, retrying with its fallback body only when the
/// upstream specifically rejected `max_completion_tokens`.
///
/// That retry exists for the GPT-5+ (`max_completion_tokens`) versus legacy
/// (`max_tokens`) chat split. Firing it for any request-shape rejection would
/// issue a second, pointless probe when the real signal is "wrong protocol for
/// this model", and a transient `429`/`5xx` on that retry could become a
/// terminal failure that stops the caller from reaching a protocol that would
/// have validated.
async fn try_validation_probe(
    client: &reqwest::Client,
    route: &ResolvedRoute,
    probe: &ValidationProbe,
    headers: &[(String, String)],
) -> Result<ValidatedEndpoint, ValidationFailure> {
    let result = try_validation_request(
        client,
        route,
        probe.path,
        probe.protocol,
        headers,
        probe.body.clone(),
    )
    .await;

    if let (Err(err), Some(fallback_body)) = (&result, &probe.fallback_body)
        && err.kind == ValidationFailureKind::RequestShape
        && err.details.contains("max_completion_tokens")
    {
        return try_validation_request(
            client,
            route,
            probe.path,
            probe.protocol,
            headers,
            fallback_body.clone(),
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
    headers: &[(String, String)],
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

    // Some OpenAI-compatible providers report an auth failure as 400/404/422
    // with an auth-shaped error body rather than 401/403. Classify those as a
    // terminal credential failure so a bad key is not mistaken for a
    // wrong-protocol probe and masked by a later probe that accepts it.
    let kind = match status.as_u16() {
        401 | 403 => ValidationFailureKind::Credentials,
        400 | 404 | 422 if body_looks_like_auth_error(body) => ValidationFailureKind::Credentials,
        400 | 404 | 405 | 422 => ValidationFailureKind::RequestShape,
        429 => ValidationFailureKind::RateLimited,
        500..=599 => ValidationFailureKind::UpstreamHealth,
        _ => ValidationFailureKind::Unexpected,
    };

    let summary = match kind {
        ValidationFailureKind::Credentials => "upstream rejected credentials",
        ValidationFailureKind::RateLimited => "upstream rate-limited the validation request",
        ValidationFailureKind::UpstreamHealth => "upstream returned a server error",
        ValidationFailureKind::RequestShape => "upstream rejected the validation request",
        _ => "upstream returned an unexpected response",
    };

    Err(ValidationFailure {
        kind,
        details: format!("{summary} with HTTP {status}.{body_suffix}"),
    })
}

/// Whether an upstream error body reads as an authentication or authorization
/// failure. Some OpenAI-compatible providers return these as HTTP 400/404/422
/// rather than 401/403, so validation inspects the body to avoid classifying a
/// bad key as a wrong-protocol probe. Matching is conservative: only strong,
/// auth-specific phrases, lowercased, to avoid catching generic "invalid model"
/// request-shape errors.
fn body_looks_like_auth_error(body: &str) -> bool {
    let body = body.to_ascii_lowercase();
    [
        "invalid_api_key",
        "invalid api key",
        "incorrect api key",
        "invalid_authentication",
        "authentication_error",
        "authentication failed",
        "unauthorized",
        "permission_denied",
        "permission denied",
        "missing api key",
    ]
    .iter()
    .any(|needle| body.contains(needle))
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
    let response = send_backend_request(client, route, method, path, &headers, body).await?;
    let (status, resp_headers) = extract_response_metadata(&response);
    let body = read_capped_response_body(response, MAX_BUFFERED_RESPONSE_BODY).await?;

    Ok(ProxyResponse {
        status,
        headers: resp_headers,
        body,
    })
}

/// Read a response body fully into memory, rejecting anything over `max` bytes.
///
/// Used by the buffered proxy path so a misbehaving upstream cannot force
/// unbounded allocation. The `Content-Length` check is a fast early-out; the
/// chunk loop is the real guard and bounds an absent, chunked, or
/// under-reported length. The cap counts the bytes reqwest yields: with no
/// decompression features enabled (see `Cargo.toml`) those are wire bytes, so
/// enabling a compression feature later would change what the cap measures.
/// Over-cap responses fail as `UpstreamProtocol` and are never partially
/// returned.
async fn read_capped_response_body(
    mut response: reqwest::Response,
    max: usize,
) -> Result<bytes::Bytes, RouterError> {
    if let Some(len) = response.content_length()
        && len > max as u64
    {
        return Err(RouterError::UpstreamProtocol(format!(
            "inference response body of {len} bytes exceeds the {max} byte cap"
        )));
    }

    // Preallocate to the advertised length when it is within the cap; the loop
    // still enforces the bound for an absent or under-reported length.
    let mut body: Vec<u8> = match response.content_length() {
        Some(len) if len <= max as u64 => Vec::with_capacity(usize::try_from(len).unwrap_or(max)),
        _ => Vec::new(),
    };
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| RouterError::UpstreamProtocol(format!("failed to read response body: {e}")))?
    {
        if body.len() + chunk.len() > max {
            return Err(RouterError::UpstreamProtocol(format!(
                "inference response body exceeds the {max} byte cap"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(bytes::Bytes::from(body))
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
        send_backend_request_streaming(client, route, method, path, &headers, body).await?;
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
    // Strip the /v1 prefix from the request path when the base URL's path
    // component has /v1 as its first segment (e.g. openai/nvidia: "/v1",
    // deepinfra: "/v1/openai") or its final segment (e.g. groq:
    // "/openai/v1"). This covers all known provider shapes while preserving
    // the full path for proxy endpoints where /v1 is buried in the middle
    // (e.g. "https://proxy.example/api/v1/openai" → path "/api/v1/openai",
    // neither first nor last segment).
    let base_path_has_v1_edge_segment = base
        .find("://")
        .and_then(|i| base[i + 3..].find('/').map(|j| i + 3 + j))
        .is_some_and(|path_start| {
            let base_path = &base[path_start..];
            base_path.starts_with("/v1/") || base_path.ends_with("/v1")
        });
    if base_path_has_v1_edge_segment && (path == "/v1" || path.starts_with("/v1/")) {
        return format!("{base}{}", &path[3..]);
    }

    format!("{base}{path}")
}

/// Check whether a route targets an AWS Bedrock `InvokeModel` endpoint.
///
/// Returns true when any of the route's protocols is one of the Bedrock
/// invocation protocols. Used to gate Bedrock-specific request shaping
/// (path-segment rewriting, skipped body-model injection) in
/// [`prepare_backend_request`].
///
/// `aws_bedrock_invoke_stream` is recognized for forward-compatibility
/// with the streaming follow-up but is not currently advertised by the
/// L7 pattern set.
fn route_is_bedrock(route: &ResolvedRoute) -> bool {
    route
        .protocols
        .iter()
        .any(|p| p == "aws_bedrock_invoke" || p == "aws_bedrock_invoke_stream")
}

/// Parse a Bedrock invocation path into its `(model_id, action_suffix, query_tail)`
/// components.
///
/// Recognized shape (caller's path on the way into the router):
/// - `/model/<model_id>/invoke[?<query>]`             → action `/invoke`
///
/// `<model_id>` must be non-empty and contain no `/`. The query tail
/// (including the leading `?`) is preserved so [`rewrite_bedrock_path`]
/// can restore it; the L7 matcher accepts queries, so silently dropping
/// them here would mutate the request shape between the matcher and
/// the upstream. Returns `None` when the path does not match — the
/// caller treats that as a malformed request and rejects rather than
/// forwarding verbatim.
///
/// `InvokeModelWithResponseStream` (`/invoke-with-response-stream`) is
/// deferred until the streaming relay grows protocol-aware AWS
/// event-stream error termination; the L7 pattern set does not
/// advertise it today, so it cannot reach this parser.
fn parse_bedrock_invocation_path(path: &str) -> Option<(&str, &'static str, &str)> {
    // Slice up to but not including `?`, then keep the `?`-prefixed
    // tail so callers can re-attach it without reconstructing the
    // delimiter.
    let (path_only, query_tail) = path
        .find('?')
        .map_or((path, ""), |idx| (&path[..idx], &path[idx..]));
    let rest = path_only.strip_prefix("/model/")?;
    let slash_at = rest.find('/')?;
    if slash_at == 0 {
        return None;
    }
    let model_id = &rest[..slash_at];
    let suffix = &rest[slash_at..];
    let action: &'static str = match suffix {
        "/invoke" => "/invoke",
        _ => return None,
    };
    Some((model_id, action, query_tail))
}

/// Rewrite a Bedrock invocation path so the model segment is the
/// operator-configured `route.model` rather than whatever the caller
/// supplied. Returns the rewritten path on success, or `None` when the
/// inbound path is not a recognized Bedrock invocation shape or when
/// `route.model` is not a valid Bedrock model id.
///
/// Why rewrite rather than reject: the inbound L7 pattern detector
/// already accepts only `/model/{x}/invoke` shapes for Bedrock routes,
/// so a caller-supplied model segment that differs from the
/// operator-configured one is the only case this function changes —
/// and changing it (vs. rejecting) lets sandbox code that hardcodes a
/// different model continue to work, while still guaranteeing the
/// operator's chosen model is what reaches the upstream.
///
/// Defense-in-depth model-ID validation: the server-side resolver
/// (`openshell-server::inference::resolve_provider_route`) already
/// rejects malformed Bedrock model ids at route-save time, but the
/// router enforces the same contract before interpolating
/// `route.model` into a URL path segment. Values containing `/`, `\`,
/// `?`, `#`, `%`, traversal segments, whitespace, or control chars
/// are rejected so a stale or hand-edited route store cannot produce
/// ambiguous or malformed upstream paths.
fn rewrite_bedrock_path(route: &ResolvedRoute, path: &str) -> Option<String> {
    if !is_valid_bedrock_model_id(&route.model) {
        return None;
    }
    let (_caller_model, action, query_tail) = parse_bedrock_invocation_path(path)?;
    Some(format!("/model/{}{}{}", route.model, action, query_tail))
}

/// Defense-in-depth predicate matching the server-side
/// `validate_aws_bedrock_model_id` contract — see that function for the
/// authoritative reasoning. Returns `true` when `value` is safe to
/// interpolate into a Bedrock URL path segment. The router uses this
/// before constructing an upstream path so a stale or out-of-band route
/// store cannot bypass the resolver's validation.
fn is_valid_bedrock_model_id(value: &str) -> bool {
    if value.is_empty() || value != value.trim() {
        return false;
    }
    if value.contains('/') || value.contains('\\') {
        return false;
    }
    if value.chars().any(|c| matches!(c, '?' | '#' | '%')) {
        return false;
    }
    if value.contains("..") {
        return false;
    }
    if value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    true
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
        ValidationFailure, ValidationFailureKind, build_backend_url, build_provider_url,
        parse_bedrock_invocation_path, prepare_backend_request, rewrite_bedrock_path,
        route_is_bedrock, verify_backend_endpoint,
    };
    use crate::RouterError;
    use crate::config::{DEFAULT_ROUTE_TIMEOUT, ResolvedRoute};
    use openshell_core::inference::AuthHeader;
    use std::time::Duration;
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

    #[test]
    fn build_backend_url_dedupes_v1_for_base_with_v1_subpath() {
        // DeepInfra base URL contains /v1/ internally — /v1 in the request
        // path must still be stripped so chat/completions is not doubled.
        assert_eq!(
            build_backend_url(
                "https://api.deepinfra.com/v1/openai",
                "/v1/chat/completions"
            ),
            "https://api.deepinfra.com/v1/openai/chat/completions"
        );
    }

    #[test]
    fn build_backend_url_dedupes_v1_for_base_ending_with_v1() {
        // Providers like Groq use a base URL where /v1 is the final segment
        // below a non-root prefix (e.g. /openai/v1). The /v1 in the request
        // path must still be stripped so it is not doubled.
        assert_eq!(
            build_backend_url("https://api.groq.com/openai/v1", "/v1/chat/completions"),
            "https://api.groq.com/openai/v1/chat/completions"
        );
    }

    #[test]
    fn build_backend_url_preserves_v1_for_nested_proxy_path() {
        // A proxy whose base path has /v1 buried in the middle (neither first
        // nor last segment) must NOT have /v1 stripped — the full request
        // path must be appended so the upstream receives the correct prefix.
        assert_eq!(
            build_backend_url(
                "https://proxy.example/api/v1/openai",
                "/v1/chat/completions"
            ),
            "https://proxy.example/api/v1/openai/v1/chat/completions"
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

    /// The buffered path must reject an over-cap upstream response rather than
    /// buffer it. Guards the DoS/OOM exposure of reading the body unbounded.
    #[tokio::test]
    async fn proxy_to_backend_rejects_over_cap_response_body() {
        use super::{MAX_BUFFERED_RESPONSE_BODY, proxy_to_backend};

        let mock_server = MockServer::start().await;
        // One byte over the cap. wiremock sets an accurate Content-Length, so
        // the size check rejects before the body is buffered.
        let oversized = vec![b'a'; MAX_BUFFERED_RESPONSE_BODY + 1];
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(oversized))
            .mount(&mock_server)
            .await;

        let route = test_route(&mock_server.uri(), &["model_discovery"], AuthHeader::Bearer);
        let client = reqwest::Client::new();
        let result = proxy_to_backend(
            &client,
            &route,
            "model_discovery",
            "GET",
            "/v1/models",
            vec![],
            bytes::Bytes::new(),
        )
        .await;

        assert!(
            matches!(result, Err(RouterError::UpstreamProtocol(_))),
            "over-cap response must fail as UpstreamProtocol, got: {result:?}"
        );
    }

    /// Spawn a one-shot HTTP/1.1 upstream that replies with a chunked body and
    /// no `Content-Length`, so the buffered read cannot pre-check a length and
    /// must enforce the cap inside the chunk loop.
    async fn spawn_chunked_upstream(chunks: &'static [&'static str]) -> std::net::SocketAddr {
        use std::fmt::Write as _;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let mut resp = String::from(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n",
            );
            for c in chunks {
                let _ = write!(resp, "{:x}\r\n{c}\r\n", c.len());
            }
            resp.push_str("0\r\n\r\n");
            sock.write_all(resp.as_bytes()).await.unwrap();
        });
        addr
    }

    /// The chunk-accumulation guard (not the `Content-Length` pre-check) must
    /// reject an over-cap body when the response advertises no length.
    #[tokio::test]
    async fn read_capped_response_body_rejects_over_cap_chunked() {
        let addr = spawn_chunked_upstream(&["aaaa", "bbbb", "cccc"]).await;
        let response = reqwest::Client::new()
            .get(format!("http://{addr}/"))
            .send()
            .await
            .unwrap();
        assert!(
            response.content_length().is_none(),
            "chunked response should advertise no Content-Length"
        );
        let result = super::read_capped_response_body(response, 8).await;
        assert!(
            matches!(result, Err(RouterError::UpstreamProtocol(_))),
            "over-cap chunked body must be rejected by the loop, got: {result:?}"
        );
    }

    /// A body exactly at the cap is accepted (inclusive bound) and returned
    /// intact through the chunk loop.
    #[tokio::test]
    async fn read_capped_response_body_accepts_body_at_cap() {
        let addr = spawn_chunked_upstream(&["aaaa", "bbbb"]).await;
        let response = reqwest::Client::new()
            .get(format!("http://{addr}/"))
            .send()
            .await
            .unwrap();
        let body = super::read_capped_response_body(response, 8).await.unwrap();
        assert_eq!(&body[..], b"aaaabbbb");
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

    /// A managed route for an embeddings model advertises the full provider
    /// protocol set. The chat probe (tried first) rejects the embeddings model
    /// as wrong-shape, so validation must fall through to the embeddings probe
    /// rather than fail the route.
    #[tokio::test]
    async fn verify_embeddings_model_falls_through_chat_probe() {
        let mock_server = MockServer::start().await;
        let route = test_route(
            &mock_server.uri(),
            &[
                "openai_chat_completions",
                "openai_completions",
                "openai_responses",
                "openai_embeddings",
                "model_discovery",
            ],
            AuthHeader::Bearer,
        );

        // Chat, completions, and responses probes reject the embedding model.
        for chat_path in ["/v1/chat/completions", "/v1/completions", "/v1/responses"] {
            Mock::given(method("POST"))
                .and(path(chat_path))
                .respond_with(
                    ResponseTemplate::new(400)
                        .set_body_string(r#"{"error":{"message":"not a chat model"}}"#),
                )
                .mount(&mock_server)
                .await;
        }
        // The embeddings probe accepts it.
        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"object": "list", "data": []})),
            )
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let validated = verify_backend_endpoint(&client, &route)
            .await
            .expect("embeddings model should validate via the embeddings probe");
        assert_eq!(validated.protocol, "openai_embeddings");
    }

    /// A non-request-shape failure (credentials) is terminal: validation must
    /// stop at the first probe and not fall through to a protocol that would
    /// succeed, so a bad key is reported as such rather than masked.
    #[tokio::test]
    async fn verify_stops_on_credentials_failure() {
        let mock_server = MockServer::start().await;
        let route = test_route(
            &mock_server.uri(),
            &["openai_chat_completions", "openai_embeddings"],
            AuthHeader::Bearer,
        );

        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(401).set_body_string(r#"{"error":"bad key"}"#))
            .mount(&mock_server)
            .await;
        // Would succeed, but credentials failure on the first probe is terminal
        // and this must never be reached.
        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"object": "list", "data": []})),
            )
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let err = verify_backend_endpoint(&client, &route)
            .await
            .expect_err("a 401 must fail validation");
        assert_eq!(err.kind, ValidationFailureKind::Credentials);
    }

    /// A 429 on the first probe is terminal (`RateLimited`) and must not fall
    /// through to a later probe that would succeed.
    #[tokio::test]
    async fn verify_stops_on_rate_limit() {
        let mock_server = MockServer::start().await;
        let route = test_route(
            &mock_server.uri(),
            &["openai_chat_completions", "openai_embeddings"],
            AuthHeader::Bearer,
        );
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(429).set_body_string(r#"{"error":"slow down"}"#))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"object": "list", "data": []})),
            )
            .mount(&mock_server)
            .await;

        let err = reqwest_verify(&route).await;
        assert_eq!(err.kind, ValidationFailureKind::RateLimited);
    }

    /// An auth failure reported as HTTP 400 with an auth-shaped body is terminal
    /// (`Credentials`), not a request-shape fall-through, so a bad key cannot be
    /// masked by a later probe that accepts it.
    #[tokio::test]
    async fn verify_auth_error_as_400_is_terminal() {
        let mock_server = MockServer::start().await;
        let route = test_route(
            &mock_server.uri(),
            &["openai_chat_completions", "openai_embeddings"],
            AuthHeader::Bearer,
        );
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(400).set_body_string(
                r#"{"error":{"code":"invalid_api_key","message":"Incorrect API key provided"}}"#,
            ))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"object": "list", "data": []})),
            )
            .mount(&mock_server)
            .await;

        let err = reqwest_verify(&route).await;
        assert_eq!(err.kind, ValidationFailureKind::Credentials);
    }

    /// When every probe is rejected as request-shape, validation returns the
    /// first (most-preferred protocol's) failure, not the last.
    #[tokio::test]
    async fn verify_all_probes_request_shape_returns_first() {
        let mock_server = MockServer::start().await;
        let route = test_route(
            &mock_server.uri(),
            &["openai_chat_completions", "openai_embeddings"],
            AuthHeader::Bearer,
        );
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(404).set_body_string(r#"{"error":"model not found: chat"}"#),
            )
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string(r#"{"error":"not an embeddings model"}"#),
            )
            .mount(&mock_server)
            .await;

        let err = reqwest_verify(&route).await;
        assert_eq!(err.kind, ValidationFailureKind::RequestShape);
        assert!(
            err.details.contains("model not found: chat"),
            "should report the first (chat) failure, got: {}",
            err.details
        );
    }

    /// Helper: run `verify_backend_endpoint` and return the expected failure.
    async fn reqwest_verify(route: &ResolvedRoute) -> ValidationFailure {
        verify_backend_endpoint(&reqwest::Client::new(), route)
            .await
            .expect_err("validation should fail")
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

        let (builder, _url) = prepare_backend_request(
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

        let (builder, _url) = prepare_backend_request(
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

        let (builder, _url) = prepare_backend_request(
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

        let (builder, _url) = prepare_backend_request(
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

        let (builder, _url) = prepare_backend_request(
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

    // ============================================================
    // AWS Bedrock route shaping (path rewriting + body preservation)
    // ============================================================

    /// `parse_bedrock_invocation_path` rejects malformed paths.
    #[test]
    fn parse_bedrock_invocation_path_rejects_malformed() {
        // Empty model id: `/model//invoke`
        assert!(parse_bedrock_invocation_path("/model//invoke").is_none());
        // Multi-segment model id: `/model/a/b/invoke`
        assert!(parse_bedrock_invocation_path("/model/a/b/invoke").is_none());
        // Unknown action: `/model/foo/converse`
        assert!(parse_bedrock_invocation_path("/model/foo/converse").is_none());
        // Streaming variant is deferred until protocol-aware error
        // framing exists; the parser must reject it the same way it
        // rejects any other unknown action.
        assert!(parse_bedrock_invocation_path("/model/foo/invoke-with-response-stream").is_none());
        // Wrong prefix: `/v1/messages`
        assert!(parse_bedrock_invocation_path("/v1/messages").is_none());
        // Missing slash before action
        assert!(parse_bedrock_invocation_path("/model/foo").is_none());
    }

    #[test]
    fn parse_bedrock_invocation_path_accepts_invoke() {
        let parsed = parse_bedrock_invocation_path(
            "/model/anthropic.claude-3-5-sonnet-20241022-v2:0/invoke",
        );
        assert_eq!(
            parsed,
            Some(("anthropic.claude-3-5-sonnet-20241022-v2:0", "/invoke", ""))
        );
    }

    /// Query strings on Bedrock invoke paths are preserved through the
    /// rewrite so the matcher (which accepts queries) and the upstream
    /// see the same shape.
    #[test]
    fn parse_bedrock_invocation_path_preserves_query_string() {
        let parsed =
            parse_bedrock_invocation_path("/model/anthropic.claude-opus-4-7/invoke?trace=1");
        assert_eq!(
            parsed,
            Some(("anthropic.claude-opus-4-7", "/invoke", "?trace=1"))
        );
    }

    /// `route_is_bedrock` matches the Bedrock invocation protocol(s).
    /// `aws_bedrock_invoke_stream` is recognized for forward-compatibility
    /// even though no L7 pattern advertises it today.
    #[test]
    fn route_is_bedrock_matches_invoke_protocols() {
        let invoke_only = test_route(
            "https://example.com",
            &["aws_bedrock_invoke"],
            AuthHeader::None,
        );
        assert!(route_is_bedrock(&invoke_only));

        let stream_forward_compat = test_route(
            "https://example.com",
            &["aws_bedrock_invoke_stream"],
            AuthHeader::None,
        );
        assert!(route_is_bedrock(&stream_forward_compat));

        let openai = test_route(
            "https://example.com",
            &["openai_chat_completions"],
            AuthHeader::Bearer,
        );
        assert!(!route_is_bedrock(&openai));
    }

    /// `rewrite_bedrock_path` swaps caller's model segment for the
    /// route-configured model and preserves any query string.
    #[test]
    fn rewrite_bedrock_path_substitutes_operator_model() {
        let mut route = test_route(
            "https://bedrock-bridge.example",
            &["aws_bedrock_invoke"],
            AuthHeader::None,
        );
        route.model = "anthropic.claude-opus-4-7".to_string();

        let rewritten = rewrite_bedrock_path(&route, "/model/some-other-model/invoke");
        assert_eq!(
            rewritten,
            Some("/model/anthropic.claude-opus-4-7/invoke".to_string())
        );

        let rewritten_with_query =
            rewrite_bedrock_path(&route, "/model/some-other-model/invoke?trace=1");
        assert_eq!(
            rewritten_with_query,
            Some("/model/anthropic.claude-opus-4-7/invoke?trace=1".to_string())
        );
    }

    #[test]
    fn rewrite_bedrock_path_returns_none_for_non_bedrock_path() {
        let route = test_route(
            "https://bedrock-bridge.example",
            &["aws_bedrock_invoke"],
            AuthHeader::None,
        );
        assert_eq!(rewrite_bedrock_path(&route, "/v1/messages"), None);
        assert_eq!(rewrite_bedrock_path(&route, "/model//invoke"), None);
        assert_eq!(rewrite_bedrock_path(&route, "/model/a/b/invoke"), None);
        // Streaming variant is deferred at the L7 layer; the router
        // must not produce an upstream path for it either.
        assert_eq!(
            rewrite_bedrock_path(&route, "/model/x/invoke-with-response-stream"),
            None
        );
    }

    /// Defense-in-depth: `rewrite_bedrock_path` rejects route models
    /// that would produce ambiguous or malformed upstream URL paths,
    /// even if a malformed value somehow reached the router store.
    #[test]
    fn rewrite_bedrock_path_rejects_unsafe_route_model() {
        let mut route = test_route(
            "https://bedrock-bridge.example",
            &["aws_bedrock_invoke"],
            AuthHeader::None,
        );

        for unsafe_model in [
            "anthropic.claude/../../etc/passwd",
            "anthropic.claude\\backslash",
            "model?injected=1",
            "model#fragment",
            "percent%2fencoded",
            "..",
            " leading-space",
            "trailing-space ",
            "tab\there",
            "newline\nhere",
            "",
        ] {
            route.model = unsafe_model.to_string();
            assert!(
                rewrite_bedrock_path(&route, "/model/foo/invoke").is_none(),
                "rewrite_bedrock_path must reject unsafe route.model: {unsafe_model:?}"
            );
        }
    }

    /// End-to-end: an inbound Bedrock request that names a different
    /// model in the path arrives at the upstream/bridge with the
    /// operator's model, and the body is unchanged (no `"model"`
    /// injection).
    #[tokio::test]
    async fn bedrock_route_rewrites_model_in_path_and_preserves_body() {
        let mock_server = MockServer::start().await;
        let mut route = test_route(
            &mock_server.uri(),
            &["aws_bedrock_invoke"],
            AuthHeader::None,
        );
        route.model = "anthropic.claude-opus-4-7".to_string();

        // The mock asserts the upstream sees the operator's model in
        // the path, NOT the caller's model.
        Mock::given(method("POST"))
            .and(path("/model/anthropic.claude-opus-4-7/invoke"))
            // Caller body has a "model" key; we expect it to pass
            // through unchanged. The mock uses body_partial_json so
            // additional fields are OK; the assertion below pins the
            // body more tightly.
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("client");

        // Caller-supplied body — we deliberately include a "model"
        // field naming a DIFFERENT model than the operator's, to
        // verify the router does not inject route.model on top of
        // it. The body should pass through verbatim because Bedrock
        // encodes the model in the path.
        let caller_body = serde_json::json!({
            "model": "caller-supplied-model-name",
            "messages": [{"role": "user", "content": "hi"}],
        });

        let (builder, url) = prepare_backend_request(
            &client,
            &route,
            "POST",
            "/model/some-other-model/invoke",
            &[],
            bytes::Bytes::from(caller_body.to_string()),
            false,
        )
        .expect("prepare should succeed");

        // URL should target the operator's model, not the caller's.
        assert!(
            url.ends_with("/model/anthropic.claude-opus-4-7/invoke"),
            "URL must use operator model, got: {url}"
        );

        let resp = builder.send().await.expect("send");
        assert_eq!(resp.status(), 200);

        // Inspect what wiremock actually received.
        let received = mock_server.received_requests().await.expect("requests");
        assert_eq!(received.len(), 1);
        let req = &received[0];
        let received_body: serde_json::Value =
            serde_json::from_slice(&req.body).expect("json body");
        // Caller's model name should pass through (NOT replaced by
        // route.model). This proves the body is untouched.
        assert_eq!(
            received_body.get("model").and_then(|v| v.as_str()),
            Some("caller-supplied-model-name"),
            "Bedrock route must NOT rewrite body model, got: {received_body}"
        );
        assert!(
            received_body.get("messages").is_some(),
            "messages field should pass through unchanged"
        );
    }

    /// Defense-in-depth: a Bedrock route receiving a non-Bedrock path
    /// is rejected rather than forwarded. The L7 pattern detector
    /// upstream of the router should never produce this combination,
    /// but if it ever did, we must not silently forward.
    #[test]
    fn bedrock_route_rejects_non_bedrock_path() {
        let client = reqwest::Client::new();
        let route = test_route(
            "https://bedrock-bridge.example",
            &["aws_bedrock_invoke"],
            AuthHeader::None,
        );
        let result = prepare_backend_request(
            &client,
            &route,
            "POST",
            "/v1/messages",
            &[],
            bytes::Bytes::from(r"{}"),
            false,
        );
        match result {
            Err(RouterError::Internal(msg)) => {
                assert!(
                    msg.contains("Bedrock") && msg.contains("/v1/messages"),
                    "error must name the offending path, got: {msg}"
                );
            }
            other => panic!("expected RouterError::Internal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn vertex_ai_body_strips_context_management_field() {
        // Claude Code 2.1.x sends "context_management" in the request body when
        // USE_API_CONTEXT_MANAGEMENT is active. Vertex AI rawPredict rejects this
        // with HTTP 400 "Extra inputs are not permitted". The router must strip it.
        let mock_server = MockServer::start().await;

        let base_path = "/v1/projects/my-project/locations/us-east5/publishers/anthropic/models";
        let route = ResolvedRoute {
            name: "vertex-anthropic".to_string(),
            endpoint: format!("{}{base_path}", mock_server.uri()),
            model: "claude-sonnet-4-6".to_string(),
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
            .and(path(format!("{base_path}/claude-sonnet-4-6:rawPredict")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": "msg_1"})),
            )
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::builder().build().unwrap();
        let body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "model": "claude-sonnet-4-6",
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 32,
                "context_management": {
                    "enabled": true,
                    "strategy": "auto"
                }
            }))
            .unwrap(),
        );
        let headers = vec![("content-type".to_string(), "application/json".to_string())];

        let (builder, _url) = prepare_backend_request(
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
            !received_body
                .as_object()
                .unwrap()
                .contains_key("context_management"),
            "context_management must be stripped from Vertex AI rawPredict body, got: {received_body}"
        );
        assert!(
            !received_body.as_object().unwrap().contains_key("model"),
            "model must also be stripped from Vertex AI rawPredict body, got: {received_body}"
        );
    }

    #[tokio::test]
    async fn direct_anthropic_preserves_context_management_field() {
        // context_management must only be stripped for Vertex AI rawPredict routes.
        // Direct Anthropic API routes must forward it intact.
        let mock_server = MockServer::start().await;

        let route = ResolvedRoute {
            name: "direct-anthropic".to_string(),
            endpoint: mock_server.uri(),
            model: "claude-sonnet-4-6".to_string(),
            api_key: "sk-ant-test".to_string(),
            protocols: vec!["anthropic_messages".to_string()],
            auth: AuthHeader::Custom("x-api-key"),
            default_headers: vec![("anthropic-version".to_string(), "2023-06-01".to_string())],
            passthrough_headers: vec!["anthropic-beta".to_string()],
            timeout: DEFAULT_ROUTE_TIMEOUT,
            model_in_path: false,
            request_path_override: None,
        };

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": "msg_1"})),
            )
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::builder().build().unwrap();
        let body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "model": "claude-sonnet-4-6",
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 32,
                "context_management": {"enabled": true}
            }))
            .unwrap(),
        );
        let headers = vec![("content-type".to_string(), "application/json".to_string())];

        let (builder, _url) = prepare_backend_request(
            &client,
            &route,
            "POST",
            "/v1/messages",
            &headers,
            body,
            false,
        )
        .unwrap();

        let _ = builder.send().await.unwrap();
        let received = mock_server.received_requests().await.unwrap();
        let received_body: serde_json::Value = serde_json::from_slice(&received[0].body).unwrap();
        assert!(
            received_body
                .as_object()
                .unwrap()
                .contains_key("context_management"),
            "context_management must be preserved for direct Anthropic API routes, got: {received_body}"
        );
    }
}
