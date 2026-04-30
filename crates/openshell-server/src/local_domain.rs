// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Local-domain HTTP routing for sandbox service endpoints.

use axum::{body::Body, response::IntoResponse};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, header};
use hyper_util::rt::TokioIo;
use openshell_core::ObjectId;
use openshell_core::config::LocalDomainConfig;
use openshell_core::proto::{Sandbox, SandboxPhase, ServiceEndpoint};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tracing::warn;

use crate::ServerState;
use crate::persistence::{ObjectType, Store};

const ENDPOINT_OBJECT_TYPE: &str = "service_endpoint";

impl ObjectType for ServiceEndpoint {
    fn object_type() -> &'static str {
        ENDPOINT_OBJECT_TYPE
    }
}

pub fn endpoint_key(sandbox: &str, service: &str) -> String {
    format!("{sandbox}--{service}")
}

pub fn endpoint_url(
    config: &openshell_core::Config,
    sandbox: &str,
    service: &str,
) -> Option<String> {
    if !config.local_domain.enabled {
        return None;
    }
    let host = endpoint_host(&config.local_domain, sandbox, service)?;
    let scheme = if config.tls.is_some() {
        "https"
    } else {
        "http"
    };
    let port = config.bind_address.port();
    let include_port = !matches!((scheme, port), ("https", 443) | ("http", 80));
    Some(if include_port {
        format!("{scheme}://{host}:{port}/")
    } else {
        format!("{scheme}://{host}/")
    })
}

fn endpoint_host(config: &LocalDomainConfig, sandbox: &str, service: &str) -> Option<String> {
    if config.cluster.is_empty() || config.suffix.is_empty() {
        return None;
    }
    Some(format!(
        "{}--{}.{}.{}",
        sandbox, service, config.cluster, config.suffix
    ))
}

pub fn parse_host(host: &str, config: &LocalDomainConfig) -> Option<(String, String)> {
    if !config.enabled || config.cluster.is_empty() || config.suffix.is_empty() {
        return None;
    }

    let host = host.split_once(':').map_or(host, |(name, _)| name);
    let expected_suffix = format!(".{}.{}", config.cluster, config.suffix);
    let encoded = host.strip_suffix(&expected_suffix)?;
    let (sandbox, service) = encoded.split_once("--")?;
    if sandbox.is_empty() || service.is_empty() || sandbox.contains("--") || service.contains("--")
    {
        return None;
    }
    Some((sandbox.to_string(), service.to_string()))
}

pub fn is_local_domain_request<B>(req: &Request<B>, config: &LocalDomainConfig) -> bool {
    request_host(req).is_some_and(|host| parse_host(host, config).is_some())
}

pub async fn proxy_local_domain_request(
    state: Arc<ServerState>,
    req: Request<Body>,
) -> impl IntoResponse {
    let Some(host) = request_host(&req) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some((sandbox_name, service_name)) = parse_host(host, &state.config.local_domain) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    match proxy_to_endpoint(state, req, sandbox_name, service_name).await {
        Ok(response) => response.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn proxy_to_endpoint(
    state: Arc<ServerState>,
    mut req: Request<Body>,
    sandbox_name: String,
    service_name: String,
) -> Result<Response<Body>, StatusCode> {
    let endpoint = load_endpoint(&state.store, &sandbox_name, &service_name).await?;
    if !endpoint.domain || endpoint.target_port == 0 || endpoint.target_port > u32::from(u16::MAX) {
        return Err(StatusCode::NOT_FOUND);
    }

    let sandbox = state
        .store
        .get_message::<Sandbox>(&endpoint.sandbox_id)
        .await
        .map_err(|err| {
            warn!(error = %err, sandbox_id = %endpoint.sandbox_id, "local-domain: failed to load sandbox");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;
    if SandboxPhase::try_from(sandbox.phase).ok() != Some(SandboxPhase::Ready) {
        return Err(StatusCode::PRECONDITION_FAILED);
    }
    let target_port = u16::try_from(endpoint.target_port).map_err(|_| StatusCode::NOT_FOUND)?;

    let websocket_upgrade = is_websocket_upgrade(&req);
    let downstream_upgrade = websocket_upgrade.then(|| hyper::upgrade::on(&mut req));

    let (_channel_id, relay_rx) = state
        .supervisor_sessions
        .open_relay(
            sandbox.object_id(),
            Some(target_port),
            Duration::from_secs(15),
        )
        .await
        .map_err(|err| {
            warn!(error = %err, sandbox_id = %endpoint.sandbox_id, "local-domain: supervisor relay unavailable");
            StatusCode::BAD_GATEWAY
        })?;

    let relay = tokio::time::timeout(Duration::from_secs(10), relay_rx)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(relay))
        .await
        .map_err(|err| {
            warn!(error = %err, "local-domain: failed to start upstream HTTP client");
            StatusCode::BAD_GATEWAY
        })?;

    if websocket_upgrade {
        tokio::spawn(async move {
            if let Err(err) = conn.with_upgrades().await {
                warn!(error = %err, "local-domain: upstream WebSocket connection failed");
            }
        });
    } else {
        tokio::spawn(async move {
            if let Err(err) = conn.await {
                warn!(error = %err, "local-domain: upstream HTTP connection failed");
            }
        });
    }

    let upstream = build_upstream_request(req, target_port, websocket_upgrade)?;
    let mut response = sender.send_request(upstream).await.map_err(|err| {
        warn!(error = %err, "local-domain: upstream HTTP request failed");
        StatusCode::BAD_GATEWAY
    })?;

    if websocket_upgrade && response.status() == StatusCode::SWITCHING_PROTOCOLS {
        let upstream_upgrade = hyper::upgrade::on(&mut response);
        let downstream_upgrade = downstream_upgrade.ok_or(StatusCode::BAD_GATEWAY)?;
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
                    warn!(error = %err, "local-domain: downstream WebSocket upgrade failed");
                }
                (_, Err(err)) => {
                    warn!(error = %err, "local-domain: upstream WebSocket upgrade failed");
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
) -> Result<ServiceEndpoint, StatusCode> {
    let key = endpoint_key(sandbox_name, service_name);
    store
        .get_message_by_name::<ServiceEndpoint>(&key)
        .await
        .map_err(|err| {
            warn!(error = %err, endpoint = %key, "local-domain: failed to load service endpoint");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)
}

fn build_upstream_request(
    req: Request<Body>,
    target_port: u16,
    preserve_upgrade_headers: bool,
) -> Result<Request<Body>, StatusCode> {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path_and_query().map_or("/", |path| path.as_str());
    let uri = path
        .parse::<http::Uri>()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut builder = Request::builder()
        .method(parts.method)
        .uri(uri)
        .version(http::Version::HTTP_11);

    let headers = builder
        .headers_mut()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
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
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn host_header(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::HOST)?.to_str().ok()
}

fn request_host<B>(req: &Request<B>) -> Option<&str> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> LocalDomainConfig {
        LocalDomainConfig {
            enabled: true,
            cluster: "dev".to_string(),
            suffix: "openshell.localhost".to_string(),
        }
    }

    #[test]
    fn parses_local_domain_host() {
        assert_eq!(
            parse_host("my-sandbox--web.dev.openshell.localhost", &config()),
            Some(("my-sandbox".to_string(), "web".to_string()))
        );
    }

    #[test]
    fn parses_local_domain_host_with_port() {
        assert_eq!(
            parse_host("my-sandbox--web.dev.openshell.localhost:8080", &config()),
            Some(("my-sandbox".to_string(), "web".to_string()))
        );
    }

    #[test]
    fn rejects_wrong_cluster() {
        assert_eq!(
            parse_host("my-sandbox--web.prod.openshell.localhost", &config()),
            None
        );
    }

    #[test]
    fn identifies_local_domain_request_from_host_header() {
        let request = Request::builder()
            .uri("/")
            .header(header::HOST, "my-sandbox--web.dev.openshell.localhost")
            .body(Body::empty())
            .unwrap();
        assert!(is_local_domain_request(&request, &config()));
    }

    #[test]
    fn identifies_local_domain_request_from_http2_authority() {
        let request = Request::builder()
            .uri("https://my-sandbox--web.dev.openshell.localhost/")
            .body(Body::empty())
            .unwrap();
        assert!(is_local_domain_request(&request, &config()));
    }

    #[test]
    fn ignores_non_local_domain_request() {
        let request = Request::builder()
            .uri("/")
            .header(header::HOST, "127.0.0.1:8080")
            .body(Body::empty())
            .unwrap();
        assert!(!is_local_domain_request(&request, &config()));
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
