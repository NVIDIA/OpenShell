// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP health endpoints using Axum.
//!
//! Three endpoints with distinct semantics:
//! - `/healthz` — Kubernetes liveness probe. Returns `200 OK` whenever the
//!   process is responsive. Intentionally does NOT depend on the database
//!   so a transient outage does not cascade into a `CrashLoopBackOff`.
//! - `/readyz` — Kubernetes readiness probe. Reads the cached state
//!   published by [`crate::readiness::DatabaseHealthMonitor`] and returns
//!   `503 Service Unavailable` when the latest background check failed.
//!   Handler latency is sub-millisecond: the database is never pinged from
//!   inside the request path, so the response cannot race the kubelet's
//!   probe timeout.
//! - `/health` — Alias of `/readyz` for external monitors
//!   that conventionally probe `/health`.

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
use tokio::sync::watch;

use crate::persistence::Store;
use crate::readiness::{DatabaseHealthMonitor, HealthError, HealthState};

const STATUS_HEALTHY: &str = "healthy";
const STATUS_UNHEALTHY: &str = "unhealthy";
const DATABASE_INITIALIZING_ERROR: &str = "readiness monitor still initializing";
const DATABASE_UNAVAILABLE_ERROR: &str = "database unavailable";
const DATABASE_TIMEOUT_ERROR: &str = "database health check timed out";

#[derive(Clone)]
struct HealthRouterState {
    health: watch::Receiver<HealthState>,
}

/// Per-dependency check entry exposed under `checks` in the JSON payload.
#[derive(Debug, Serialize)]
pub struct DependencyCheck {
    /// `"healthy"` or `"unhealthy"`.
    pub status: &'static str,

    /// Wall-clock time of the latest background ping, when measurable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,

    /// Failure detail. Absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Aggregated dependency results.
#[derive(Debug, Serialize)]
pub struct HealthChecks {
    pub database: DependencyCheck,
}

/// Readiness response payload.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Overall status: `"healthy"` if every dependency is healthy.
    pub status: &'static str,

    /// Service version.
    pub version: &'static str,

    /// Per-dependency breakdown.
    pub checks: HealthChecks,
}

/// Kubernetes liveness probe — process responsiveness only.
async fn healthz() -> impl IntoResponse {
    StatusCode::OK
}

/// Kubernetes readiness probe — reflects the cached background DB state.
async fn readyz(State(state): State<Arc<HealthRouterState>>) -> impl IntoResponse {
    render_response(&state.health.borrow())
}

/// Convenience alias of [`readyz`] for monitors that probe `/health`.
async fn health(State(state): State<Arc<HealthRouterState>>) -> impl IntoResponse {
    render_response(&state.health.borrow())
}

fn render_response(state: &HealthState) -> (StatusCode, Json<HealthResponse>) {
    let database = render_database(state);
    let healthy = state.is_healthy();
    let response = HealthResponse {
        status: if healthy {
            STATUS_HEALTHY
        } else {
            STATUS_UNHEALTHY
        },
        version: openshell_core::VERSION,
        checks: HealthChecks { database },
    };
    let code = if healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(response))
}

fn render_database(state: &HealthState) -> DependencyCheck {
    match state {
        HealthState::Initializing => DependencyCheck {
            status: STATUS_UNHEALTHY,
            latency_ms: None,
            error: Some(DATABASE_INITIALIZING_ERROR.to_string()),
        },
        HealthState::Healthy { latency_ms } => DependencyCheck {
            status: STATUS_HEALTHY,
            latency_ms: Some(*latency_ms),
            error: None,
        },
        HealthState::Unhealthy(HealthError::Unavailable { latency_ms }) => DependencyCheck {
            status: STATUS_UNHEALTHY,
            latency_ms: Some(*latency_ms),
            error: Some(DATABASE_UNAVAILABLE_ERROR.to_string()),
        },
        HealthState::Unhealthy(HealthError::Timeout) => DependencyCheck {
            status: STATUS_UNHEALTHY,
            latency_ms: None,
            error: Some(DATABASE_TIMEOUT_ERROR.to_string()),
        },
    }
}

/// Build the health router by spawning a background [`DatabaseHealthMonitor`]
/// for `store` and wiring its receiver into the handlers.
///
/// Returns immediately so the listener is responsive from t=0. The router's
/// initial state is [`HealthState::Initializing`] — `/readyz` and `/health`
/// will return `503` with a structured `{"checks": {"database": {"status":
/// "initializing"}}}` payload until the background monitor publishes its
/// first real probe outcome (within one [`crate::readiness::DEFAULT_CHECK_INTERVAL`]).
/// The background task continues running detached for the remainder of the
/// runtime.
pub fn health_router(store: Arc<Store>) -> Router {
    let monitor = DatabaseHealthMonitor::spawn(store);
    health_router_from_receiver(monitor.subscribe())
}

/// Build the health router from an existing monitor receiver.
///
/// Crate-internal: used by [`health_router`] and by tests that drive the
/// `HealthState` directly without spinning up the polling task.
pub fn health_router_from_receiver(receiver: watch::Receiver<HealthState>) -> Router {
    let state = Arc::new(HealthRouterState { health: receiver });

    Router::new()
        .route("/health", get(health))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(state)
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

/// Create the HTTP router served on the multiplexed gateway port.
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

#[cfg(test)]
mod readiness_tests {
    use super::*;
    use axum::body::Body;
    use http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn in_memory_store() -> Arc<Store> {
        Arc::new(
            Store::connect("sqlite::memory:")
                .await
                .expect("connect in-memory sqlite store"),
        )
    }

    /// Build a [`health_router`] that has already observed its first probe
    /// outcome. Test-only — production code must not block the listener on
    /// the first poll (see [`health_router`]).
    async fn polled_health_router(store: Arc<Store>) -> Router {
        let mut monitor = DatabaseHealthMonitor::spawn(store);
        monitor.wait_until_polled().await;
        health_router_from_receiver(monitor.subscribe())
    }

    async fn get(router: Router, path: &str) -> (StatusCode, serde_json::Value) {
        let response = router
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .expect("router responds");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        let body = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("response is valid JSON")
        };
        (status, body)
    }

    /// Build a router whose state is driven by a `HealthState` we control,
    /// so each handler-shape test can pin the exact mapping under test.
    fn router_with_state(state: HealthState) -> Router {
        let (_tx, rx) = watch::channel(state);
        health_router_from_receiver(rx)
    }

    #[tokio::test]
    async fn healthz_is_minimal_and_does_not_touch_the_database() {
        // Liveness must succeed even when the database is unreachable —
        // otherwise a transient outage would CrashLoopBackOff the gateway.
        let store = in_memory_store().await;
        store.close().await;
        let (status, body) = get(health_router(store), "/healthz").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.is_null(), "healthz must return an empty body");
    }

    #[tokio::test]
    async fn readyz_returns_200_with_healthy_payload_when_db_is_reachable() {
        let store = in_memory_store().await;
        let (status, body) = get(polled_health_router(store).await, "/readyz").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "healthy");
        assert_eq!(body["checks"]["database"]["status"], "healthy");
        assert!(
            body["checks"]["database"]["latency_ms"].is_number(),
            "expected latency_ms in healthy payload"
        );
        assert!(
            body["checks"]["database"]["error"].is_null(),
            "healthy payload must omit the error field"
        );
    }

    #[tokio::test]
    async fn health_alias_mirrors_readyz_when_db_is_reachable() {
        let store = in_memory_store().await;
        let (status, body) = get(polled_health_router(store).await, "/health").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "healthy");
        assert_eq!(body["checks"]["database"]["status"], "healthy");
    }

    #[tokio::test]
    async fn readyz_returns_503_with_unhealthy_payload_when_db_is_unreachable() {
        let store = in_memory_store().await;
        store.close().await;
        let (status, body) = get(polled_health_router(store).await, "/readyz").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "unhealthy");
        assert_eq!(body["checks"]["database"]["status"], "unhealthy");
        assert_eq!(
            body["checks"]["database"]["error"],
            DATABASE_UNAVAILABLE_ERROR
        );
    }

    #[tokio::test]
    async fn health_alias_returns_503_when_db_is_unreachable() {
        let store = in_memory_store().await;
        store.close().await;
        let (status, body) = get(polled_health_router(store).await, "/health").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "unhealthy");
        assert_eq!(body["checks"]["database"]["status"], "unhealthy");
    }

    #[tokio::test]
    async fn readyz_reports_initializing_state_as_unhealthy_with_explicit_reason() {
        let (status, body) = get(router_with_state(HealthState::Initializing), "/readyz").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "unhealthy");
        assert_eq!(body["checks"]["database"]["status"], "unhealthy");
        assert_eq!(
            body["checks"]["database"]["error"],
            DATABASE_INITIALIZING_ERROR
        );
        assert!(
            body["checks"]["database"]["latency_ms"].is_null(),
            "initializing state has no latency to report yet"
        );
    }

    #[tokio::test]
    async fn readyz_renders_timeout_state_with_dedicated_error_string() {
        let (status, body) = get(
            router_with_state(HealthState::Unhealthy(HealthError::Timeout)),
            "/readyz",
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "unhealthy");
        assert_eq!(body["checks"]["database"]["error"], DATABASE_TIMEOUT_ERROR);
        assert!(
            body["checks"]["database"]["latency_ms"].is_null(),
            "timeout state has no completed-call latency"
        );
    }
}
