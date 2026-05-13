// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Browser-facing HTTP routing for sandbox service endpoints.

use axum::{
    body::Body,
    response::{IntoResponse, Response as AxumResponse},
};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, header};
use hyper_util::rt::TokioIo;
use openshell_core::config::ServiceRoutingConfig;
use openshell_core::proto::{Sandbox, SandboxPhase, ServiceEndpoint, TcpRelayTarget, relay_open};
use openshell_core::{ObjectId, VERSION};
use openshell_ocsf::{
    ActionId, ActivityId, ConfigStateChangeBuilder, DispositionId, Endpoint, HttpActivityBuilder,
    HttpRequest, HttpResponse as OcsfHttpResponse, NetworkActivityBuilder, OCSF_TARGET, OcsfEvent,
    SandboxContext, SeverityId, StateId, StatusId, Url as OcsfUrl,
};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

use crate::ServerState;
use crate::persistence::{ObjectType, Store};

const ENDPOINT_OBJECT_TYPE: &str = "service_endpoint";
const ROUTING_RULE_NAME: &str = "sandbox_service_routing";
const ROUTING_RULE_TYPE: &str = "gateway";
const RELAY_RULE_NAME: &str = "sandbox_service_relay";
const RELAY_TARGET_HOST: &str = "127.0.0.1";

impl ObjectType for ServiceEndpoint {
    fn object_type() -> &'static str {
        ENDPOINT_OBJECT_TYPE
    }
}

pub fn endpoint_key(sandbox: &str, service: &str) -> String {
    if service.is_empty() {
        sandbox.to_string()
    } else {
        format!("{sandbox}--{service}")
    }
}

pub fn endpoint_url(
    config: &openshell_core::Config,
    sandbox: &str,
    service: &str,
) -> Option<String> {
    let host = endpoint_host(&config.service_routing, sandbox, service)?;
    let scheme = endpoint_scheme(config);
    let port = config.bind_address.port();
    let include_port = !matches!((scheme, port), ("https", 443) | ("http", 80));
    Some(if include_port {
        format!("{scheme}://{host}:{port}/")
    } else {
        format!("{scheme}://{host}/")
    })
}

fn endpoint_scheme(config: &openshell_core::Config) -> &'static str {
    if config.tls.is_none()
        || (config.bind_address.ip().is_loopback()
            && config.service_routing.enable_loopback_service_http)
    {
        "http"
    } else {
        "https"
    }
}

fn endpoint_host(config: &ServiceRoutingConfig, sandbox: &str, service: &str) -> Option<String> {
    let base_domain = config.base_domains.first()?;
    Some(if service.is_empty() {
        format!("{sandbox}.{base_domain}")
    } else {
        format!("{sandbox}--{service}.{base_domain}")
    })
}

pub fn parse_host(host: &str, config: &ServiceRoutingConfig) -> Option<(String, String)> {
    let host = host.split_once(':').map_or(host, |(name, _)| name);
    for base_domain in &config.base_domains {
        let expected_suffix = format!(".{base_domain}");
        let Some(encoded) = host.strip_suffix(&expected_suffix) else {
            continue;
        };
        let (sandbox, service) = if let Some((sandbox, service)) = encoded.split_once("--") {
            if service.is_empty() || service.contains("--") {
                return None;
            }
            (sandbox, service)
        } else {
            (encoded, "")
        };
        if sandbox.is_empty() || sandbox.contains("--") {
            return None;
        }
        return Some((sandbox.to_string(), service.to_string()));
    }
    None
}

pub fn is_sandbox_service_request<B>(req: &Request<B>, config: &ServiceRoutingConfig) -> bool {
    request_host(req).is_some_and(|host| parse_host(host, config).is_some())
}

pub async fn proxy_sandbox_service_request(
    state: Arc<ServerState>,
    req: Request<Body>,
) -> impl IntoResponse {
    let Some(host) = request_host(&req) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some((sandbox_name, service_name)) = parse_host(host, &state.config.service_routing) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    match proxy_to_endpoint(state, req, sandbox_name, service_name).await {
        Ok(response) => response.into_response(),
        Err(err) => err.into_response(),
    }
}

#[derive(Debug, Clone)]
struct ServiceRouteError {
    status: StatusCode,
    message: &'static str,
    reason: &'static str,
}

impl ServiceRouteError {
    const fn new(status: StatusCode, message: &'static str, reason: &'static str) -> Self {
        Self {
            status,
            message,
            reason,
        }
    }

    const fn endpoint_not_found() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "Service endpoint not found",
            "service endpoint not found",
        )
    }

    const fn endpoint_unavailable() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "Service endpoint is not available",
            "service endpoint unavailable",
        )
    }

    const fn sandbox_not_ready() -> Self {
        Self::new(
            StatusCode::PRECONDITION_FAILED,
            "Sandbox is not ready",
            "sandbox not ready",
        )
    }

    const fn service_unreachable() -> Self {
        Self::new(
            StatusCode::BAD_GATEWAY,
            "Service endpoint is not reachable",
            "service endpoint unreachable",
        )
    }

    const fn invalid_request() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "Invalid service request",
            "invalid service request",
        )
    }

    const fn internal_error() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Service endpoint is not available",
            "service endpoint internal error",
        )
    }
}

impl IntoResponse for ServiceRouteError {
    fn into_response(self) -> AxumResponse {
        service_error_response(self.status, self.message)
    }
}

pub fn service_error_response(status: StatusCode, message: &'static str) -> AxumResponse {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        message,
    )
        .into_response()
}

async fn proxy_to_endpoint(
    state: Arc<ServerState>,
    mut req: Request<Body>,
    sandbox_name: String,
    service_name: String,
) -> Result<Response<Body>, ServiceRouteError> {
    let endpoint = match load_endpoint(&state.store, &sandbox_name, &service_name).await {
        Ok(endpoint) => endpoint,
        Err(err) => {
            emit_service_http_failure(&state, &req, &sandbox_name, &service_name, None, &err);
            return Err(err);
        }
    };
    if !endpoint.domain || endpoint.target_port == 0 || endpoint.target_port > u32::from(u16::MAX) {
        let err = ServiceRouteError::endpoint_unavailable();
        emit_service_http_failure(
            &state,
            &req,
            &sandbox_name,
            &service_name,
            Some(&endpoint),
            &err,
        );
        return Err(err);
    }

    let sandbox = match state
        .store
        .get_message::<Sandbox>(&endpoint.sandbox_id)
        .await
    {
        Ok(Some(sandbox)) => sandbox,
        Ok(None) => {
            let err = ServiceRouteError::endpoint_unavailable();
            emit_service_http_failure(
                &state,
                &req,
                &sandbox_name,
                &service_name,
                Some(&endpoint),
                &err,
            );
            return Err(err);
        }
        Err(err) => {
            warn!(error = %err, sandbox_id = %endpoint.sandbox_id, "sandbox service routing: failed to load sandbox");
            let route_err = ServiceRouteError::internal_error();
            emit_service_http_failure(
                &state,
                &req,
                &sandbox_name,
                &service_name,
                Some(&endpoint),
                &route_err,
            );
            return Err(route_err);
        }
    };
    if SandboxPhase::try_from(sandbox.phase).ok() != Some(SandboxPhase::Ready) {
        let err = ServiceRouteError::sandbox_not_ready();
        emit_service_http_failure(
            &state,
            &req,
            &sandbox_name,
            &service_name,
            Some(&endpoint),
            &err,
        );
        return Err(err);
    }
    let Ok(target_port) = u16::try_from(endpoint.target_port) else {
        let err = ServiceRouteError::endpoint_unavailable();
        emit_service_http_failure(
            &state,
            &req,
            &sandbox_name,
            &service_name,
            Some(&endpoint),
            &err,
        );
        return Err(err);
    };
    if upstream_uri_path(&req).is_err() {
        let err = ServiceRouteError::invalid_request();
        emit_service_http_failure(
            &state,
            &req,
            &sandbox_name,
            &service_name,
            Some(&endpoint),
            &err,
        );
        return Err(err);
    }

    let websocket_upgrade = is_websocket_upgrade(&req);
    let downstream_upgrade = websocket_upgrade.then(|| hyper::upgrade::on(&mut req));

    let (_channel_id, relay_rx) = state
        .supervisor_sessions
        .open_relay_with_target(
            sandbox.object_id(),
            relay_open::Target::Tcp(TcpRelayTarget {
                host: RELAY_TARGET_HOST.to_string(),
                port: u32::from(target_port),
            }),
            endpoint.object_id().to_string(),
            Duration::from_secs(15),
        )
        .await
        .map_err(|err| {
            warn!(error = %err, sandbox_id = %endpoint.sandbox_id, "sandbox service routing: supervisor relay unavailable");
            let route_err = ServiceRouteError::service_unreachable();
            emit_service_relay_failure(&endpoint, target_port, route_err.reason);
            route_err
        })?;

    let relay = tokio::time::timeout(Duration::from_secs(10), relay_rx)
        .await
        .map_err(|_| {
            let err = ServiceRouteError::service_unreachable();
            emit_service_relay_failure(&endpoint, target_port, "relay claim timed out");
            err
        })?
        .map_err(|_| {
            let err = ServiceRouteError::service_unreachable();
            emit_service_relay_failure(&endpoint, target_port, "relay claim canceled");
            err
        })?
        .map_err(|err| {
            warn!(error = %err, "sandbox service routing: relay target open failed");
            let route_err = ServiceRouteError::service_unreachable();
            emit_service_relay_failure(&endpoint, target_port, route_err.reason);
            route_err
        })?;

    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(relay))
        .await
        .map_err(|err| {
            warn!(error = %err, "sandbox service routing: failed to start upstream HTTP client");
            let route_err = ServiceRouteError::service_unreachable();
            emit_service_relay_failure(&endpoint, target_port, route_err.reason);
            route_err
        })?;

    if websocket_upgrade {
        tokio::spawn(async move {
            if let Err(err) = conn.with_upgrades().await {
                warn!(error = %err, "sandbox service routing: upstream WebSocket connection failed");
            }
        });
    } else {
        tokio::spawn(async move {
            if let Err(err) = conn.await {
                warn!(error = %err, "sandbox service routing: upstream HTTP connection failed");
            }
        });
    }

    let upstream = build_upstream_request(req, target_port, websocket_upgrade)?;
    let mut response = sender.send_request(upstream).await.map_err(|err| {
        warn!(error = %err, "sandbox service routing: upstream HTTP request failed");
        let route_err = ServiceRouteError::service_unreachable();
        emit_service_relay_failure(&endpoint, target_port, route_err.reason);
        route_err
    })?;

    if websocket_upgrade && response.status() == StatusCode::SWITCHING_PROTOCOLS {
        let upstream_upgrade = hyper::upgrade::on(&mut response);
        let downstream_upgrade = downstream_upgrade.ok_or_else(|| {
            let err = ServiceRouteError::service_unreachable();
            emit_service_relay_failure(&endpoint, target_port, "websocket upgrade unavailable");
            err
        })?;
        tokio::spawn(async move {
            match (downstream_upgrade.await, upstream_upgrade.await) {
                (Ok(downstream), Ok(upstream)) => {
                    let mut downstream = TokioIo::new(downstream);
                    let mut upstream = TokioIo::new(upstream);
                    let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
                    let _ = downstream.shutdown().await;
                    let _ = upstream.shutdown().await;
                }
                (Err(err), _) => {
                    warn!(error = %err, "sandbox service routing: downstream WebSocket upgrade failed");
                }
                (_, Err(err)) => {
                    warn!(error = %err, "sandbox service routing: upstream WebSocket upgrade failed");
                }
            }
        });

        let (parts, _) = response.into_parts();
        return Ok(Response::from_parts(parts, Body::empty()));
    }

    let (parts, body) = response.into_parts();
    Ok(Response::from_parts(parts, Body::new(body)))
}

async fn load_endpoint(
    store: &Store,
    sandbox_name: &str,
    service_name: &str,
) -> Result<ServiceEndpoint, ServiceRouteError> {
    let key = endpoint_key(sandbox_name, service_name);
    store
        .get_message_by_name::<ServiceEndpoint>(&key)
        .await
        .map_err(|err| {
            warn!(error = %err, endpoint = %key, "sandbox service routing: failed to load service endpoint");
            ServiceRouteError::internal_error()
        })?
        .ok_or_else(ServiceRouteError::endpoint_not_found)
}

fn build_upstream_request(
    req: Request<Body>,
    target_port: u16,
    preserve_upgrade_headers: bool,
) -> Result<Request<Body>, ServiceRouteError> {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path_and_query().map_or("/", |path| path.as_str());
    let uri = path
        .parse::<http::Uri>()
        .map_err(|_| ServiceRouteError::invalid_request())?;

    let mut builder = Request::builder()
        .method(parts.method)
        .uri(uri)
        .version(http::Version::HTTP_11);

    let headers = builder
        .headers_mut()
        .ok_or_else(ServiceRouteError::internal_error)?;
    for (name, value) in &parts.headers {
        if (is_hop_by_hop_header(name)
            && !(preserve_upgrade_headers && is_websocket_hop_by_hop_header(name)))
            || is_gateway_auth_header(name)
        {
            continue;
        }
        if name == header::COOKIE {
            if let Some(cookie) = sanitize_cookie_header(value) {
                headers.append(name, cookie);
            }
            continue;
        }
        headers.append(name, value.clone());
    }
    headers.insert(
        header::HOST,
        format!("127.0.0.1:{target_port}").parse().unwrap(),
    );

    builder
        .body(body)
        .map_err(|_| ServiceRouteError::internal_error())
}

fn upstream_uri_path(req: &Request<Body>) -> Result<&str, ServiceRouteError> {
    let path = req.uri().path_and_query().map_or("/", |path| path.as_str());
    path.parse::<http::Uri>()
        .map(|_| path)
        .map_err(|_| ServiceRouteError::invalid_request())
}

fn host_header(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::HOST)?.to_str().ok()
}

pub fn request_host<B>(req: &Request<B>) -> Option<&str> {
    host_header(req.headers()).or_else(|| req.uri().authority().map(http::uri::Authority::as_str))
}

fn is_websocket_upgrade<B>(req: &Request<B>) -> bool {
    req.method() == Method::GET
        && header_value_is(req.headers(), header::UPGRADE, "websocket")
        && header_contains_token(req.headers(), header::CONNECTION, "upgrade")
}

fn header_value_is(headers: &HeaderMap, name: header::HeaderName, expected: &str) -> bool {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case(expected))
}

fn header_contains_token(headers: &HeaderMap, name: header::HeaderName, token: &str) -> bool {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
        })
}

fn is_hop_by_hop_header(name: &header::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "host"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn is_websocket_hop_by_hop_header(name: &header::HeaderName) -> bool {
    matches!(name.as_str(), "connection" | "upgrade")
}

fn is_gateway_auth_header(name: &header::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "authorization"
            | "cf-access-jwt-assertion"
            | "x-forwarded-client-cert"
            | "x-ssl-client-cert"
            | "x-client-cert"
    )
}

fn sanitize_cookie_header(value: &HeaderValue) -> Option<HeaderValue> {
    let value = value.to_str().ok()?;
    let cookies = value
        .split(';')
        .filter_map(|cookie| {
            let cookie = cookie.trim();
            let (name, _) = cookie.split_once('=')?;
            (!is_gateway_auth_cookie(name.trim())).then_some(cookie)
        })
        .collect::<Vec<_>>();

    if cookies.is_empty() {
        return None;
    }

    HeaderValue::from_str(&cookies.join("; ")).ok()
}

fn is_gateway_auth_cookie(name: &str) -> bool {
    name.eq_ignore_ascii_case("CF_Authorization") || name.eq_ignore_ascii_case("cf-authorization")
}

pub fn emit_service_endpoint_config_event(endpoint: &ServiceEndpoint, url: &str, created: bool) {
    let event = build_service_endpoint_config_event(endpoint, url, created);
    emit_gateway_ocsf_event(&endpoint.sandbox_id, event);
}

pub fn emit_service_endpoint_delete_event(endpoint: &ServiceEndpoint) {
    let event = build_service_endpoint_delete_event(endpoint);
    emit_gateway_ocsf_event(&endpoint.sandbox_id, event);
}

pub fn emit_cross_origin_service_http_rejection(state: &ServerState, req: &Request<Body>) {
    let Some(host) = request_host(req) else {
        return;
    };
    let Some((sandbox_name, service_name)) = parse_host(host, &state.config.service_routing) else {
        return;
    };
    let err = ServiceRouteError::new(
        StatusCode::FORBIDDEN,
        "Cross-origin service request rejected",
        "cross-origin service request rejected",
    );
    emit_service_http_failure(state, req, &sandbox_name, &service_name, None, &err);
}

fn emit_service_http_failure(
    state: &ServerState,
    req: &Request<Body>,
    sandbox_name: &str,
    service_name: &str,
    endpoint: Option<&ServiceEndpoint>,
    err: &ServiceRouteError,
) {
    let event = build_service_http_failure_event(
        state.config.bind_address.port(),
        req,
        sandbox_name,
        service_name,
        endpoint,
        err,
    );
    let sandbox_id = endpoint.map_or("", |endpoint| endpoint.sandbox_id.as_str());
    emit_gateway_ocsf_event(sandbox_id, event);
}

fn emit_service_relay_failure(endpoint: &ServiceEndpoint, target_port: u16, reason: &str) {
    let event = build_service_relay_failure_event(endpoint, target_port, reason);
    emit_gateway_ocsf_event(&endpoint.sandbox_id, event);
}

fn build_service_endpoint_config_event(
    endpoint: &ServiceEndpoint,
    url: &str,
    created: bool,
) -> OcsfEvent {
    let service_label = service_display_name(&endpoint.sandbox_name, &endpoint.service_name);
    let state_label = if created {
        "service_endpoint_created"
    } else {
        "service_endpoint_updated"
    };
    let ctx = gateway_ocsf_ctx(&endpoint.sandbox_id, &endpoint.sandbox_name);
    let mut builder = ConfigStateChangeBuilder::new(&ctx)
        .state(StateId::Enabled, state_label)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .message(format!(
            "Service endpoint exposed {service_label} -> {RELAY_TARGET_HOST}:{}",
            endpoint.target_port
        ))
        .unmapped("endpoint_name", endpoint_name(endpoint))
        .unmapped("service_name", endpoint.service_name.clone())
        .unmapped("target_port", u64::from(endpoint.target_port));

    if !url.is_empty() {
        builder = builder.unmapped("url", url.to_string());
    }

    builder.build()
}

fn build_service_endpoint_delete_event(endpoint: &ServiceEndpoint) -> OcsfEvent {
    let service_label = service_display_name(&endpoint.sandbox_name, &endpoint.service_name);
    ConfigStateChangeBuilder::new(&gateway_ocsf_ctx(
        &endpoint.sandbox_id,
        &endpoint.sandbox_name,
    ))
    .state(StateId::Disabled, "service_endpoint_deleted")
    .severity(SeverityId::Informational)
    .status(StatusId::Success)
    .message(format!("Service endpoint deleted {service_label}"))
    .unmapped("endpoint_name", endpoint_name(endpoint))
    .unmapped("service_name", endpoint.service_name.clone())
    .unmapped("target_port", u64::from(endpoint.target_port))
    .build()
}

fn build_service_http_failure_event(
    bind_port: u16,
    req: &Request<Body>,
    sandbox_name: &str,
    service_name: &str,
    endpoint: Option<&ServiceEndpoint>,
    err: &ServiceRouteError,
) -> OcsfEvent {
    let host = request_host(req).unwrap_or("unknown");
    let (hostname, port) = split_authority_for_event(host, bind_port);
    let ctx = gateway_ocsf_ctx(
        endpoint.map_or("", |endpoint| endpoint.sandbox_id.as_str()),
        sandbox_name,
    );
    HttpActivityBuilder::new(&ctx)
        .activity(http_activity_for_method(req.method()))
        .action(ActionId::Denied)
        .disposition(if err.status.is_server_error() {
            DispositionId::Error
        } else {
            DispositionId::Blocked
        })
        .severity(if err.status.is_server_error() {
            SeverityId::Low
        } else {
            SeverityId::Medium
        })
        .status(StatusId::Failure)
        .http_request(HttpRequest::new(
            req.method().as_str(),
            OcsfUrl::new("http", &hostname, req.uri().path(), port),
        ))
        .http_response(OcsfHttpResponse {
            code: err.status.as_u16(),
        })
        .dst_endpoint(Endpoint::from_domain(&hostname, port))
        .firewall_rule(ROUTING_RULE_NAME, ROUTING_RULE_TYPE)
        .status_detail(err.reason)
        .message(format!(
            "{}: {}",
            err.message,
            service_display_name(sandbox_name, service_name)
        ))
        .build()
}

fn build_service_relay_failure_event(
    endpoint: &ServiceEndpoint,
    target_port: u16,
    reason: &str,
) -> OcsfEvent {
    NetworkActivityBuilder::new(&gateway_ocsf_ctx(
        &endpoint.sandbox_id,
        &endpoint.sandbox_name,
    ))
    .activity(ActivityId::Open)
    .action(ActionId::Denied)
    .disposition(DispositionId::Error)
    .severity(SeverityId::Low)
    .status(StatusId::Failure)
    .dst_endpoint(Endpoint::from_ip_str(RELAY_TARGET_HOST, target_port))
    .firewall_rule(RELAY_RULE_NAME, ROUTING_RULE_TYPE)
    .status_detail(reason)
    .message(format!(
        "Service endpoint is not reachable: {}",
        service_display_name(&endpoint.sandbox_name, &endpoint.service_name)
    ))
    .unmapped("endpoint_name", endpoint_name(endpoint))
    .unmapped("service_name", endpoint.service_name.clone())
    .build()
}

fn emit_gateway_ocsf_event(sandbox_id: &str, event: OcsfEvent) {
    let message = event.format_shorthand();
    info!(
        target: OCSF_TARGET,
        sandbox_id = %sandbox_id,
        message = %message
    );
}

fn gateway_ocsf_ctx(sandbox_id: &str, sandbox_name: &str) -> SandboxContext {
    SandboxContext {
        sandbox_id: sandbox_id.to_string(),
        sandbox_name: sandbox_name.to_string(),
        container_image: "openshell/gateway".to_string(),
        hostname: "openshell-gateway".to_string(),
        product_version: VERSION.to_string(),
        proxy_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        proxy_port: 0,
    }
}

fn endpoint_name(endpoint: &ServiceEndpoint) -> String {
    endpoint.metadata.as_ref().map_or_else(
        || endpoint_key(&endpoint.sandbox_name, &endpoint.service_name),
        |metadata| metadata.name.clone(),
    )
}

fn service_display_name(sandbox_name: &str, service_name: &str) -> String {
    if service_name.is_empty() {
        sandbox_name.to_string()
    } else {
        format!("{sandbox_name}/{service_name}")
    }
}

fn split_authority_for_event(authority: &str, default_port: u16) -> (String, u16) {
    let authority = authority.trim();
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) => (
            host.trim_end_matches('.').to_ascii_lowercase(),
            port.parse().unwrap_or(default_port),
        ),
        _ => (
            authority.trim_end_matches('.').to_ascii_lowercase(),
            default_port,
        ),
    }
}

fn http_activity_for_method(method: &Method) -> ActivityId {
    match method.as_str() {
        "CONNECT" => ActivityId::Open,
        "DELETE" => ActivityId::Close,
        "GET" => ActivityId::Reset,
        "HEAD" => ActivityId::Fail,
        "OPTIONS" => ActivityId::Refuse,
        "POST" => ActivityId::Traffic,
        "PUT" => ActivityId::Listen,
        "TRACE" => ActivityId::Trace,
        "PATCH" => ActivityId::Patch,
        _ => ActivityId::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> ServiceEndpoint {
        ServiceEndpoint {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "endpoint-id".to_string(),
                name: "my-sandbox--web".to_string(),
                created_at_ms: 1_700_000_000_000,
                labels: std::collections::HashMap::default(),
            }),
            sandbox_id: "sandbox-id".to_string(),
            sandbox_name: "my-sandbox".to_string(),
            service_name: "web".to_string(),
            target_port: 8080,
            domain: true,
        }
    }

    fn config() -> ServiceRoutingConfig {
        ServiceRoutingConfig {
            base_domains: vec![
                "dev.openshell.localhost".to_string(),
                "svc.gateway.localhost".to_string(),
            ],
            ..ServiceRoutingConfig::default()
        }
    }

    fn tls_config() -> openshell_core::TlsConfig {
        openshell_core::TlsConfig {
            cert_path: "server.crt".into(),
            key_path: "server.key".into(),
            client_ca_path: "ca.crt".into(),
            allow_unauthenticated: false,
        }
    }

    #[test]
    fn endpoint_url_uses_plain_http_for_loopback_tls_gateway() {
        let cfg = openshell_core::Config::new(Some(tls_config()))
            .with_bind_address("127.0.0.1:8080".parse().unwrap())
            .with_server_sans(["*.dev.openshell.localhost"]);

        assert_eq!(
            endpoint_url(&cfg, "my-sandbox", "web").as_deref(),
            Some("http://my-sandbox--web.dev.openshell.localhost:8080/")
        );
    }

    #[test]
    fn endpoint_url_omits_service_label_for_empty_service_name() {
        let cfg = openshell_core::Config::new(Some(tls_config()))
            .with_bind_address("127.0.0.1:8080".parse().unwrap())
            .with_server_sans(["*.dev.openshell.localhost"]);

        assert_eq!(
            endpoint_url(&cfg, "my-sandbox", "").as_deref(),
            Some("http://my-sandbox.dev.openshell.localhost:8080/")
        );
    }

    #[test]
    fn endpoint_url_keeps_https_for_non_loopback_tls_gateway() {
        let cfg = openshell_core::Config::new(Some(tls_config()))
            .with_bind_address("0.0.0.0:8080".parse().unwrap())
            .with_server_sans(["*.dev.openshell.localhost"]);

        assert_eq!(
            endpoint_url(&cfg, "my-sandbox", "web").as_deref(),
            Some("https://my-sandbox--web.dev.openshell.localhost:8080/")
        );
    }

    #[test]
    fn endpoint_url_keeps_https_when_loopback_plaintext_http_is_disabled() {
        let cfg = openshell_core::Config::new(Some(tls_config()))
            .with_bind_address("127.0.0.1:8080".parse().unwrap())
            .with_server_sans(["*.dev.openshell.localhost"])
            .with_loopback_service_http(false);

        assert_eq!(
            endpoint_url(&cfg, "my-sandbox", "web").as_deref(),
            Some("https://my-sandbox--web.dev.openshell.localhost:8080/")
        );
    }

    #[test]
    fn parses_sandbox_service_host() {
        assert_eq!(
            parse_host("my-sandbox--web.dev.openshell.localhost", &config()),
            Some(("my-sandbox".to_string(), "web".to_string()))
        );
    }

    #[test]
    fn parses_sandbox_host_without_service_label() {
        assert_eq!(
            parse_host("my-sandbox.dev.openshell.localhost", &config()),
            Some(("my-sandbox".to_string(), String::new()))
        );
    }

    #[test]
    fn rejects_empty_service_label_separator() {
        assert_eq!(
            parse_host("my-sandbox--.dev.openshell.localhost", &config()),
            None
        );
    }

    #[test]
    fn parses_sandbox_service_host_with_port() {
        assert_eq!(
            parse_host("my-sandbox--web.dev.openshell.localhost:8080", &config()),
            Some(("my-sandbox".to_string(), "web".to_string()))
        );
    }

    #[test]
    fn parses_alternate_service_routing_domain() {
        assert_eq!(
            parse_host("my-sandbox--web.svc.gateway.localhost", &config()),
            Some(("my-sandbox".to_string(), "web".to_string()))
        );
    }

    #[test]
    fn rejects_unknown_base_domain() {
        assert_eq!(
            parse_host("my-sandbox--web.prod.openshell.localhost", &config()),
            None
        );
    }

    #[test]
    fn identifies_sandbox_service_request_from_host_header() {
        let request = Request::builder()
            .uri("/")
            .header(header::HOST, "my-sandbox--web.dev.openshell.localhost")
            .body(Body::empty())
            .unwrap();
        assert!(is_sandbox_service_request(&request, &config()));
    }

    #[test]
    fn identifies_sandbox_service_request_from_http2_authority() {
        let request = Request::builder()
            .uri("https://my-sandbox--web.dev.openshell.localhost/")
            .body(Body::empty())
            .unwrap();
        assert!(is_sandbox_service_request(&request, &config()));
    }

    #[test]
    fn ignores_non_sandbox_service_request() {
        let request = Request::builder()
            .uri("/")
            .header(header::HOST, "127.0.0.1:8080")
            .body(Body::empty())
            .unwrap();
        assert!(!is_sandbox_service_request(&request, &config()));
    }

    #[test]
    fn service_route_errors_return_plain_text() {
        let response = ServiceRouteError::sandbox_not_ready().into_response();

        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
    }

    #[test]
    fn service_endpoint_config_event_includes_endpoint_metadata() {
        let event =
            build_service_endpoint_config_event(&endpoint(), "http://my-sandbox--web.local/", true);
        let json = event.to_json().unwrap();

        assert_eq!(json["class_uid"], 5019);
        assert_eq!(json["unmapped"]["endpoint_name"], "my-sandbox--web");
        assert_eq!(json["unmapped"]["service_name"], "web");
        assert_eq!(json["unmapped"]["target_port"], 8080);
        assert!(
            event
                .format_shorthand()
                .contains("Service endpoint exposed my-sandbox/web")
        );
    }

    #[test]
    fn service_endpoint_delete_event_includes_endpoint_metadata() {
        let event = build_service_endpoint_delete_event(&endpoint());
        let json = event.to_json().unwrap();

        assert_eq!(json["class_uid"], 5019);
        assert_eq!(json["unmapped"]["endpoint_name"], "my-sandbox--web");
        assert_eq!(json["unmapped"]["service_name"], "web");
        assert_eq!(json["unmapped"]["target_port"], 8080);
        assert!(
            event
                .format_shorthand()
                .contains("Service endpoint deleted my-sandbox/web")
        );
    }

    #[test]
    fn service_http_failure_event_omits_query_strings() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/secret?token=should-not-log")
            .header(
                header::HOST,
                "my-sandbox--web.dev.openshell.localhost:18080",
            )
            .body(Body::empty())
            .unwrap();

        let err = ServiceRouteError::new(
            StatusCode::FORBIDDEN,
            "Cross-origin service request rejected",
            "cross-origin service request rejected",
        );
        let event =
            build_service_http_failure_event(18080, &request, "my-sandbox", "web", None, &err);
        let json = event.to_json().unwrap();

        assert_eq!(json["class_uid"], 4002);
        assert_eq!(json["http_request"]["url"]["path"], "/secret");
        assert_eq!(json["http_response"]["code"], 403);
        assert!(!event.format_shorthand().contains("should-not-log"));
    }

    #[test]
    fn service_relay_failure_event_records_loopback_target() {
        let event = build_service_relay_failure_event(&endpoint(), 8080, "relay unavailable");
        let json = event.to_json().unwrap();

        assert_eq!(json["class_uid"], 4001);
        assert_eq!(json["dst_endpoint"]["ip"], RELAY_TARGET_HOST);
        assert_eq!(json["dst_endpoint"]["port"], 8080);
        assert_eq!(json["unmapped"]["endpoint_name"], "my-sandbox--web");
    }

    #[test]
    fn strips_gateway_auth_headers_from_upstream_request() {
        let request = Request::builder()
            .uri("https://my-sandbox--web.dev.openshell.localhost/path")
            .header(header::AUTHORIZATION, "Bearer gateway-token")
            .header("cf-access-jwt-assertion", "edge-token")
            .header("x-forwarded-client-cert", "cert")
            .header(
                header::COOKIE,
                "theme=dark; CF_Authorization=edge-cookie; app=session",
            )
            .header("x-app-header", "kept")
            .body(Body::empty())
            .unwrap();

        let upstream = build_upstream_request(request, 8080, false).unwrap();

        assert_eq!(upstream.uri(), "/path");
        assert!(!upstream.headers().contains_key(header::AUTHORIZATION));
        assert!(!upstream.headers().contains_key("cf-access-jwt-assertion"));
        assert!(!upstream.headers().contains_key("x-forwarded-client-cert"));
        assert_eq!(
            upstream.headers()[header::COOKIE],
            "theme=dark; app=session"
        );
        assert_eq!(upstream.headers()["x-app-header"], "kept");
    }

    #[test]
    fn detects_websocket_upgrade_request() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/chat?session=main")
            .header(header::CONNECTION, "keep-alive, Upgrade")
            .header(header::UPGRADE, "websocket")
            .body(Body::empty())
            .unwrap();

        assert!(is_websocket_upgrade(&request));
    }

    #[test]
    fn preserves_websocket_upgrade_headers_for_upstream_request() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://my-sandbox--web.dev.openshell.localhost/chat?session=main")
            .header(header::CONNECTION, "Upgrade")
            .header(header::UPGRADE, "websocket")
            .header("sec-websocket-key", "abc")
            .body(Body::empty())
            .unwrap();

        let upstream = build_upstream_request(request, 8080, true).unwrap();

        assert_eq!(upstream.uri(), "/chat?session=main");
        assert_eq!(upstream.headers()[header::CONNECTION], "Upgrade");
        assert_eq!(upstream.headers()[header::UPGRADE], "websocket");
        assert_eq!(upstream.headers()["sec-websocket-key"], "abc");
        assert_eq!(upstream.headers()[header::HOST], "127.0.0.1:8080");
    }
}
