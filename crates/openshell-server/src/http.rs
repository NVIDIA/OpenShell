// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP health endpoints using Axum.

use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::IntoResponse,
    routing::get,
};
use metrics_exporter_prometheus::PrometheusHandle;
use serde::Serialize;
use std::sync::Arc;

/// Health check response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Service status.
    pub status: &'static str,

    /// Service version.
    pub version: &'static str,
}

/// Simple health check - returns 200 OK.
async fn health() -> impl IntoResponse {
    StatusCode::OK
}

/// Kubernetes liveness probe.
async fn healthz() -> impl IntoResponse {
    StatusCode::OK
}

/// Kubernetes readiness probe with detailed status.
async fn readyz() -> impl IntoResponse {
    let response = HealthResponse {
        status: "healthy",
        version: openshell_core::VERSION,
    };

    (StatusCode::OK, Json(response))
}

/// Create the health router.
pub fn health_router() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
}

/// Create the metrics router for the dedicated metrics port.
pub fn metrics_router(handle: PrometheusHandle) -> Router {
    Router::new()
        .route("/metrics", get(render_metrics))
        .with_state(handle)
}

async fn render_metrics(State(handle): State<PrometheusHandle>) -> impl IntoResponse {
    handle.render()
}

/// Create the HTTP router.
pub fn http_router(state: Arc<crate::ServerState>) -> Router {
    crate::ws_tunnel::router(state.clone())
        .merge(crate::auth::router(state.clone()))
        .layer(middleware::from_fn_with_state(
            state,
            sandbox_service_routing_first,
        ))
}

/// Create the plaintext loopback-only router for browser service endpoints.
///
/// This router intentionally exposes only sandbox service routing. It does not
/// include gRPC, auth, health, metrics, or WebSocket tunnel routes.
pub fn service_http_router(state: Arc<crate::ServerState>) -> Router {
    Router::new()
        .fallback(sandbox_service_routing_only)
        .with_state(state)
}

async fn sandbox_service_routing_first(
    State(state): State<Arc<crate::ServerState>>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    if crate::service_routing::is_sandbox_service_request(&req, &state.config.service_routing) {
        return crate::service_routing::proxy_sandbox_service_request(state, req)
            .await
            .into_response();
    }
    next.run(req).await.into_response()
}

async fn sandbox_service_routing_only(
    State(state): State<Arc<crate::ServerState>>,
    req: Request,
) -> impl IntoResponse {
    if !crate::service_routing::is_sandbox_service_request(&req, &state.config.service_routing) {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !browser_context_allows_plaintext_service_request(&req) {
        crate::service_routing::emit_cross_origin_service_http_rejection(&state, &req);
        return crate::service_routing::service_error_response(
            StatusCode::FORBIDDEN,
            "Cross-origin service request rejected",
        );
    }
    crate::service_routing::proxy_sandbox_service_request(state, req)
        .await
        .into_response()
}

fn browser_context_allows_plaintext_service_request(req: &Request) -> bool {
    if let Some(fetch_site) = header_str(req.headers(), "sec-fetch-site")
        && !matches!(
            fetch_site.to_ascii_lowercase().as_str(),
            "same-origin" | "none"
        )
    {
        return false;
    }

    if let Some(origin) = header_str(req.headers(), header::ORIGIN.as_str()) {
        let Some(request_origin) = request_origin(req) else {
            return false;
        };
        return parse_origin(origin).is_some_and(|origin| origin == request_origin);
    }

    if let Some(referer) = header_str(req.headers(), header::REFERER.as_str()) {
        let Some(request_origin) = request_origin(req) else {
            return false;
        };
        return parse_origin(referer).is_some_and(|origin| origin == request_origin);
    }

    true
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

#[derive(Debug, Eq, PartialEq)]
struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

fn request_origin(req: &Request) -> Option<Origin> {
    let host = crate::service_routing::request_host(req)?;
    parse_origin_authority("http", host)
}

fn parse_origin(value: &str) -> Option<Origin> {
    if value.eq_ignore_ascii_case("null") {
        return None;
    }
    let (scheme, rest) = value.split_once("://")?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    parse_origin_authority(scheme, &rest[..authority_end])
}

fn parse_origin_authority(scheme: &str, authority: &str) -> Option<Origin> {
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let authority = authority.trim();
    if authority.is_empty() || authority.contains('@') {
        return None;
    }

    let (host, port) = split_host_port(authority)?;
    let host = normalize_host(host)?;
    Some(Origin {
        scheme,
        host,
        port: port.unwrap_or(default_port),
    })
}

fn split_host_port(authority: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        let port = if rest.is_empty() {
            None
        } else {
            Some(rest.strip_prefix(':')?.parse().ok()?)
        };
        return Some((host, port));
    }

    match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) => {
            Some((host, Some(port.parse().ok()?)))
        }
        Some(_) if authority.matches(':').count() == 1 => None,
        _ => Some((authority, None)),
    }
}

fn normalize_host(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service_request(headers: &[(&str, &str)]) -> Request {
        let mut builder = Request::builder()
            .uri("/some/path")
            .header(header::HOST, "sandbox--web.dev.openshell.localhost:8080");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(axum::body::Body::empty()).unwrap()
    }

    #[test]
    fn plaintext_service_browser_context_allows_direct_tools() {
        let req = service_request(&[]);

        assert!(browser_context_allows_plaintext_service_request(&req));
    }

    #[test]
    fn plaintext_service_browser_context_allows_same_origin_fetch_metadata() {
        let req = service_request(&[("sec-fetch-site", "same-origin")]);

        assert!(browser_context_allows_plaintext_service_request(&req));
    }

    #[test]
    fn plaintext_service_browser_context_allows_direct_navigation_fetch_metadata() {
        let req = service_request(&[("sec-fetch-site", "none")]);

        assert!(browser_context_allows_plaintext_service_request(&req));
    }

    #[test]
    fn plaintext_service_browser_context_rejects_cross_site_fetch_metadata() {
        let req = service_request(&[("sec-fetch-site", "cross-site")]);

        assert!(!browser_context_allows_plaintext_service_request(&req));
    }

    #[test]
    fn plaintext_service_browser_context_rejects_same_site_sibling_requests() {
        let req = service_request(&[("sec-fetch-site", "same-site")]);

        assert!(!browser_context_allows_plaintext_service_request(&req));
    }

    #[test]
    fn plaintext_service_browser_context_requires_matching_origin() {
        let req =
            service_request(&[("origin", "http://sandbox--web.dev.openshell.localhost:8080")]);

        assert!(browser_context_allows_plaintext_service_request(&req));

        let req = service_request(&[(
            "origin",
            "http://sandbox--other.dev.openshell.localhost:8080",
        )]);

        assert!(!browser_context_allows_plaintext_service_request(&req));
    }

    #[test]
    fn plaintext_service_browser_context_requires_matching_referer() {
        let req = service_request(&[(
            "referer",
            "http://sandbox--web.dev.openshell.localhost:8080/page",
        )]);

        assert!(browser_context_allows_plaintext_service_request(&req));

        let req = service_request(&[(
            "referer",
            "http://sandbox--other.dev.openshell.localhost:8080/page",
        )]);

        assert!(!browser_context_allows_plaintext_service_request(&req));
    }

    #[test]
    fn plaintext_service_browser_context_rejects_mismatched_origin_scheme() {
        let req = service_request(&[(
            "origin",
            "https://sandbox--web.dev.openshell.localhost:8080",
        )]);

        assert!(!browser_context_allows_plaintext_service_request(&req));
    }
}
