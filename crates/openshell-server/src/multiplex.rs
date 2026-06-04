// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Protocol multiplexing for gRPC and HTTP on the same port.
//!
//! This module implements connection-level multiplexing that routes requests
//! to either the gRPC service or HTTP endpoints based on the request headers.

use bytes::Bytes;
use http::{HeaderValue, Request, Response};
use http_body::Body;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use metrics::{counter, histogram};
use openshell_core::proto::{
    inference_server::InferenceServer, open_shell_server::OpenShellServer,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tower::ServiceExt;
use tower_http::request_id::{MakeRequestId, RequestId};
use tracing::Span;

use crate::{
    OpenShellService, ServerState,
    auth::authenticator::AuthenticatorChain,
    auth::authz::AuthzPolicy,
    auth::identity::Identity,
    auth::oidc::{self, OidcAuthenticator},
    auth::principal::{Principal, UserPrincipal},
    http_router,
    inference::InferenceService,
    service_http_router,
};

/// Request-ID generator that produces a UUID v4 for each inbound request.
#[derive(Clone)]
struct UuidRequestId;

impl MakeRequestId for UuidRequestId {
    fn make_request_id<B>(&mut self, _req: &Request<B>) -> Option<RequestId> {
        let id = uuid::Uuid::new_v4().to_string();
        Some(RequestId::new(HeaderValue::from_str(&id).unwrap()))
    }
}

/// Build a tracing span for an inbound request, recording the `request_id`
/// header (set by [`UuidRequestId`] or supplied by the client).
fn make_request_span<B>(req: &Request<B>) -> Span {
    let path = req.uri().path();
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-");

    if matches!(path, "/health" | "/healthz" | "/readyz") {
        tracing::debug_span!(
            "request",
            method = %req.method(),
            path,
            request_id,
        )
    } else {
        tracing::info_span!(
            "request",
            method = %req.method(),
            path,
            request_id,
        )
    }
}

/// Log response status and latency within the request span.
fn log_response<B>(res: &Response<B>, latency: Duration, _span: &Span) {
    tracing::info!(
        status = res.status().as_u16(),
        latency_ms = latency.as_millis(),
        "response"
    );
}

/// Wrap a service with the standard request-ID middleware stack.
///
/// Layer order: `SetRequestId` → `TraceLayer` → `PropagateRequestId`.
macro_rules! request_id_middleware {
    ($service:expr) => {{
        let x_request_id = ::http::HeaderName::from_static("x-request-id");
        ::tower::ServiceBuilder::new()
            .layer(::tower_http::request_id::SetRequestIdLayer::new(
                x_request_id.clone(),
                UuidRequestId,
            ))
            .layer(
                ::tower_http::trace::TraceLayer::new_for_http()
                    .make_span_with(make_request_span)
                    .on_request(())
                    .on_response(log_response),
            )
            .layer(::tower_http::request_id::PropagateRequestIdLayer::new(
                x_request_id,
            ))
            .service($service)
    }};
}

/// Maximum inbound gRPC message size (1 MB).
///
/// Replaces tonic's implicit 4 MB default with a conservative limit to
/// bound memory allocation from a single request. Sandbox creation is
/// the largest payload and well within this cap under normal use.
const MAX_GRPC_DECODE_SIZE: usize = 1_048_576;

/// Multiplexed gRPC/HTTP service.
#[derive(Clone)]
pub struct MultiplexService {
    state: Arc<ServerState>,
}

impl MultiplexService {
    /// Create a new multiplex service.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }

    /// Serve a connection, routing to gRPC or HTTP based on content-type.
    pub async fn serve<S>(&self, stream: S) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.serve_with_peer_identity(stream, None).await
    }

    /// Serve a TLS connection with an optional mTLS peer identity.
    pub async fn serve_with_peer_identity<S>(
        &self,
        stream: S,
        peer_identity: Option<Identity>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let openshell = OpenShellServer::new(OpenShellService::new(self.state.clone()))
            .max_decoding_message_size(MAX_GRPC_DECODE_SIZE);
        let inference = InferenceServer::new(InferenceService::new(self.state.clone()))
            .max_decoding_message_size(MAX_GRPC_DECODE_SIZE);
        let authz_policy = self.state.config.oidc.as_ref().map(|oidc| AuthzPolicy {
            admin_role: oidc.admin_role.clone(),
            user_role: oidc.user_role.clone(),
            scopes_enabled: !oidc.scopes_claim.is_empty(),
        });
        let authenticator_chain = build_authenticator_chain(&self.state);
        let grpc_service = AuthGrpcRouter::with_peer_identity(
            GrpcRouter::new(openshell, inference),
            authenticator_chain,
            authz_policy,
            self.state
                .config
                .mtls_auth
                .enabled
                .then_some(peer_identity)
                .flatten(),
            self.state.config.mtls_auth.enabled,
            self.state.config.auth.allow_unauthenticated_users,
        );
        let http_service = http_router(self.state.clone());

        let grpc_service = request_id_middleware!(grpc_service);
        let http_service = request_id_middleware!(http_service);

        let service = MultiplexedService::new(grpc_service, http_service);

        let mut builder = Builder::new(TokioExecutor::new());
        builder.http2().adaptive_window(true);

        builder
            .serve_connection_with_upgrades(TokioIo::new(stream), service)
            .await?;

        Ok(())
    }

    /// Serve a plaintext HTTP connection for sandbox service endpoints only.
    pub async fn serve_service_http<S>(
        &self,
        stream: S,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let http_service = TowerToHyperService::new(request_id_middleware!(service_http_router(
            self.state.clone()
        )));

        Builder::new(TokioExecutor::new())
            .serve_connection_with_upgrades(TokioIo::new(stream), http_service)
            .await?;

        Ok(())
    }
}

/// Combined gRPC service that routes between `OpenShell` and Inference services
/// based on the request path prefix.
#[derive(Clone)]
pub struct GrpcRouter<N, I> {
    openshell: N,
    inference: I,
}

impl<N, I> GrpcRouter<N, I> {
    fn new(openshell: N, inference: I) -> Self {
        Self {
            openshell,
            inference,
        }
    }
}

const INFERENCE_PATH_PREFIX: &str = "/openshell.inference.v1.Inference/";

impl<N, I, B> tower::Service<Request<B>> for GrpcRouter<N, I>
where
    N: tower::Service<Request<B>> + Clone + Send + 'static,
    N::Response: Send,
    N::Future: Send,
    N::Error: Send,
    I: tower::Service<Request<B>, Response = N::Response, Error = N::Error>
        + Clone
        + Send
        + 'static,
    I::Future: Send,
    B: Send + 'static,
{
    type Response = N::Response;
    type Error = N::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let is_inference = req.uri().path().starts_with(INFERENCE_PATH_PREFIX);

        if is_inference {
            let mut svc = self.inference.clone();
            Box::pin(async move { svc.ready().await?.call(req).await })
        } else {
            let mut svc = self.openshell.clone();
            Box::pin(async move { svc.ready().await?.call(req).await })
        }
    }
}

/// Assemble the authenticator chain for the gateway.
///
/// Chain order (first-match-wins):
/// 1. `K8sServiceAccountAuthenticator` (path-scoped to `IssueSandboxToken`)
///    — exchanges a projected SA token for a `Principal::Sandbox` so the
///    `IssueSandboxToken` handler can mint a gateway JWT. No-op on every
///    other path; only present when the gateway runs in-cluster.
/// 2. `SandboxJwtAuthenticator` — validates gateway-minted JWTs. Recognized
///    via a distinctive `kid` so non-matching Bearer tokens fall through.
/// 3. `OidcAuthenticator` — validates user Bearer tokens against the
///    configured OIDC issuer. Returns `Unauthenticated` for missing
///    Bearer headers so non-OIDC clients can't sneak through.
///
/// Once sandbox authentication is configured, callers must present an
/// explicit credential for authenticated gRPC methods. Missing bearer auth
/// is promoted to an mTLS user only when `mtls_auth.enabled` is configured
/// for local single-user gateways, or to an unsafe local developer user when
/// `auth.allow_unauthenticated_users` is explicitly enabled.
///
/// When neither OIDC nor gateway-minted JWTs are configured (a barebones
/// dev gateway), the chain is left as `None` so the router short-circuits
/// to pass-through.
fn build_authenticator_chain(state: &ServerState) -> Option<AuthenticatorChain> {
    let mut authenticators: Vec<Arc<dyn crate::auth::authenticator::Authenticator>> = Vec::new();
    if let Some(k8s) = state.k8s_sa_authenticator.clone() {
        authenticators.push(k8s);
    }
    if let Some(jwt) = state.sandbox_jwt_authenticator.clone() {
        authenticators.push(jwt);
    }
    if let Some(cache) = state.oidc_cache.clone() {
        authenticators.push(Arc::new(OidcAuthenticator::new(cache)));
    }
    if authenticators.is_empty() {
        return None;
    }
    Some(AuthenticatorChain::new(authenticators))
}

/// gRPC router wrapper that runs the [`AuthenticatorChain`] and inserts the
/// resulting [`Principal`] into the request's extensions.
///
/// Behavior:
/// - Strip any external `x-openshell-auth-source` marker first (so callers
///   cannot spoof a sandbox identity).
/// - Health probes / reflection bypass the chain entirely.
/// - When no chain is configured (OIDC not configured), forward without
///   authentication — preserves today's pass-through behavior.
/// - Otherwise, run the chain. The first match produces a `Principal`.
///   `Principal::User` is gated by the RBAC `AuthzPolicy`.
///   `Principal::Sandbox` is gated by a supervisor-method allowlist, then
///   handlers enforce same-sandbox scope on request bodies.
#[derive(Clone)]
pub struct AuthGrpcRouter<S> {
    inner: S,
    authenticator_chain: Option<AuthenticatorChain>,
    authz_policy: Option<AuthzPolicy>,
    /// mTLS peer identity extracted from the TLS handshake.
    peer_identity: Option<Identity>,
    mtls_auth_enabled: bool,
    allow_unauthenticated_users: bool,
}

impl<S> AuthGrpcRouter<S> {
    #[cfg(test)]
    fn new(
        inner: S,
        authenticator_chain: Option<AuthenticatorChain>,
        authz_policy: Option<AuthzPolicy>,
    ) -> Self {
        Self::with_peer_identity(inner, authenticator_chain, authz_policy, None, false, false)
    }

    fn with_peer_identity(
        inner: S,
        authenticator_chain: Option<AuthenticatorChain>,
        authz_policy: Option<AuthzPolicy>,
        peer_identity: Option<Identity>,
        mtls_auth_enabled: bool,
        allow_unauthenticated_users: bool,
    ) -> Self {
        Self {
            inner,
            authenticator_chain,
            authz_policy,
            peer_identity,
            mtls_auth_enabled,
            allow_unauthenticated_users,
        }
    }
}

fn unauthenticated_dev_user_principal() -> Principal {
    Principal::User(UserPrincipal {
        identity: Identity {
            subject: "unauthenticated-local-dev".to_string(),
            display_name: Some("Unauthenticated Local Dev".to_string()),
            roles: vec!["openshell-user".to_string(), "openshell-admin".to_string()],
            scopes: vec!["openshell:all".to_string()],
            provider: crate::auth::identity::IdentityProvider::LocalDev,
        },
    })
}

fn status_response(status: tonic::Status) -> Response<tonic::body::BoxBody> {
    let response = status.into_http();
    let (parts, body) = response.into_parts();
    let body = tonic::body::BoxBody::new(body);
    Response::from_parts(parts, body)
}

impl<S, B> tower::Service<Request<B>> for AuthGrpcRouter<S>
where
    S: tower::Service<Request<B>, Response = Response<tonic::body::BoxBody>>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
    S::Error: Send + Into<Box<dyn std::error::Error + Send + Sync>>,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let chain = self.authenticator_chain.clone();
        let authz_policy = self.authz_policy.clone();
        let peer_identity = self.peer_identity.clone();
        let mtls_auth_enabled = self.mtls_auth_enabled;
        let allow_unauthenticated_users = self.allow_unauthenticated_users;
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let mut req = req;

            let path = req.uri().path().to_string();

            // Health probes and reflection — truly unauthenticated.
            if oidc::is_unauthenticated_method(&path) {
                return inner.ready().await?.call(req).await;
            }

            let principal = if let Some(chain) = chain {
                match chain.authenticate(req.headers(), &path).await {
                    Ok(Some(p)) => p,
                    Ok(None) => match (mtls_auth_enabled, peer_identity) {
                        (true, Some(identity)) => Principal::User(UserPrincipal { identity }),
                        _ if allow_unauthenticated_users => unauthenticated_dev_user_principal(),
                        _ => {
                            return Ok(status_response(tonic::Status::unauthenticated(
                                "missing authorization header",
                            )));
                        }
                    },
                    Err(status) => return Ok(status_response(status)),
                }
            } else if mtls_auth_enabled {
                let Some(identity) = peer_identity else {
                    return Ok(status_response(tonic::Status::unauthenticated(
                        "missing client certificate",
                    )));
                };
                Principal::User(UserPrincipal { identity })
            } else if allow_unauthenticated_users {
                unauthenticated_dev_user_principal()
            } else {
                // No auth configured — pass through for dev /
                // fronting-proxy deployments.
                return inner.ready().await?.call(req).await;
            };

            match principal {
                Principal::User(ref user) => {
                    if !crate::auth::method_authz::is_user_callable(&path) {
                        return Ok(status_response(tonic::Status::permission_denied(
                            "this method requires a sandbox principal",
                        )));
                    }
                    if let Some(ref policy) = authz_policy
                        && let Err(status) = policy.check(&user.identity, &path)
                    {
                        return Ok(status_response(status));
                    }
                }
                Principal::Sandbox(_) => {
                    if !crate::auth::sandbox_methods::is_sandbox_callable(&path) {
                        return Ok(status_response(tonic::Status::permission_denied(
                            "sandbox principals may not call this method",
                        )));
                    }
                }
                Principal::Anonymous => {
                    return Ok(status_response(tonic::Status::unauthenticated(
                        "anonymous callers may not call authenticated methods",
                    )));
                }
            }

            req.extensions_mut().insert(principal);
            inner.ready().await?.call(req).await
        })
    }
}

/// Service that multiplexes between gRPC and HTTP.
#[derive(Clone)]
pub struct MultiplexedService<G, H> {
    grpc: G,
    http: H,
}

impl<G, H> MultiplexedService<G, H> {
    /// Create a new multiplexed service from gRPC and HTTP services.
    #[must_use]
    pub fn new(grpc: G, http: H) -> Self {
        Self { grpc, http }
    }
}

impl<G, H, GBody, HBody> hyper::service::Service<Request<Incoming>> for MultiplexedService<G, H>
where
    G: tower::Service<Request<BoxBody>, Response = Response<GBody>> + Clone + Send + 'static,
    G::Future: Send,
    G::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    GBody: Body<Data = Bytes> + Send + 'static,
    GBody::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    H: tower::Service<Request<BoxBody>, Response = Response<HBody>> + Clone + Send + 'static,
    H::Future: Send,
    H::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    HBody: Body<Data = Bytes> + Send + 'static,
    HBody::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = Response<BoxBody>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let is_grpc = req
            .headers()
            .get("content-type")
            .is_some_and(|v| v.as_bytes().starts_with(b"application/grpc"));

        if is_grpc {
            let method = grpc_method_from_path(req.uri().path());
            let start = Instant::now();
            let mut grpc = self.grpc.clone();
            Box::pin(async move {
                let (parts, body) = req.into_parts();
                let body = body.map_err(Into::into).boxed_unsync();
                let req = Request::from_parts(parts, BoxBody(body));

                let res = grpc
                    .ready()
                    .await
                    .map_err(Into::into)?
                    .call(req)
                    .await
                    .map_err(Into::into)?;

                let code = grpc_status_from_response(&res);
                let elapsed = start.elapsed().as_secs_f64();
                counter!("openshell_server_grpc_requests_total", "method" => method.clone(), "code" => code.clone()).increment(1);
                histogram!("openshell_server_grpc_request_duration_seconds", "method" => method, "code" => code).record(elapsed);

                let (parts, body) = res.into_parts();
                let body = body.map_err(Into::into).boxed_unsync();
                Ok(Response::from_parts(parts, BoxBody(body)))
            })
        } else {
            let path = normalize_http_path(req.uri().path());
            let start = Instant::now();
            let mut http = self.http.clone();
            Box::pin(async move {
                let (parts, body) = req.into_parts();
                let body = body.map_err(Into::into).boxed_unsync();
                let req = Request::from_parts(parts, BoxBody(body));

                let res = http
                    .ready()
                    .await
                    .map_err(Into::into)?
                    .call(req)
                    .await
                    .map_err(Into::into)?;

                let status = res.status().as_u16().to_string();
                let elapsed = start.elapsed().as_secs_f64();
                counter!("openshell_server_http_requests_total", "path" => path, "status" => status.clone()).increment(1);
                histogram!("openshell_server_http_request_duration_seconds", "path" => path, "status" => status).record(elapsed);

                let (parts, body) = res.into_parts();
                let body = body.map_err(Into::into).boxed_unsync();
                Ok(Response::from_parts(parts, BoxBody(body)))
            })
        }
    }
}

fn grpc_method_from_path(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

fn grpc_status_from_response<B>(res: &Response<B>) -> String {
    res.headers()
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .map_or_else(|| "0".to_string(), ToString::to_string)
}

fn normalize_http_path(path: &str) -> &'static str {
    match path {
        p if p.starts_with("/_ws_tunnel") => "/_ws_tunnel",
        p if p.starts_with("/auth/") => "/auth",
        _ => "unknown",
    }
}

/// Extract an [`Identity`] from the peer certificates presented during a TLS
/// handshake. Returns `None` if no client certificate was presented.
pub fn extract_peer_identity<S>(tls_stream: &tokio_rustls::server::TlsStream<S>) -> Option<Identity>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use crate::auth::identity::IdentityProvider;
    use x509_parser::prelude::*;

    let (_, server_conn) = tls_stream.get_ref();
    let certs = server_conn.peer_certificates()?;
    let first = certs.first()?;

    let (_, cert) = X509Certificate::from_der(first.as_ref()).ok()?;
    let subject = cert.subject();

    let cn = subject
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let roles: Vec<String> = subject
        .iter_organizational_unit()
        .filter_map(|attr| attr.as_str().ok().map(String::from))
        .collect();

    Some(Identity {
        subject: cn.clone(),
        display_name: Some(cn),
        roles,
        scopes: Vec::new(),
        provider: IdentityProvider::Mtls,
    })
}

/// Boxed body type for uniform handling.
pub struct BoxBody(
    http_body_util::combinators::UnsyncBoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>,
);

impl Body for BoxBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.0).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.0.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::Empty;
    use std::sync::Mutex;

    #[test]
    fn uuid_request_id_generates_valid_uuid() {
        let mut maker = UuidRequestId;
        let req = Request::builder().body(()).unwrap();
        let id = maker.make_request_id(&req).expect("should produce an ID");
        let value = id.header_value().to_str().unwrap();
        uuid::Uuid::parse_str(value).expect("should be a valid UUID");
    }

    #[test]
    fn uuid_request_id_generates_unique_ids() {
        let mut maker = UuidRequestId;
        let req = Request::builder().body(()).unwrap();
        let id1 = maker.make_request_id(&req).unwrap();
        let id2 = maker.make_request_id(&req).unwrap();
        assert_ne!(id1.header_value(), id2.header_value());
    }

    async fn test_health_store() -> Arc<crate::Store> {
        Arc::new(
            crate::Store::connect("sqlite::memory:")
                .await
                .expect("connect in-memory sqlite store for tests"),
        )
    }

    async fn start_http_server_with_middleware() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let http_service = crate::http::health_router(test_health_store().await);
        let http_service = request_id_middleware!(http_service);

        let service = MultiplexedService::new(http_service.clone(), http_service);

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let svc = service.clone();
                tokio::spawn(async move {
                    let _ = Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });

        addr
    }

    async fn http1_get(
        addr: std::net::SocketAddr,
        path: &str,
        headers: &[(&str, &str)],
    ) -> Response<Incoming> {
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let mut builder = Request::builder()
            .method("GET")
            .uri(format!("http://{addr}{path}"));
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let req = builder.body(Empty::<Bytes>::new()).unwrap();
        sender.send_request(req).await.unwrap()
    }

    #[tokio::test]
    async fn http_response_includes_request_id() {
        let addr = start_http_server_with_middleware().await;
        let resp = http1_get(addr, "/healthz", &[]).await;
        assert_eq!(resp.status(), 200);

        let request_id = resp
            .headers()
            .get("x-request-id")
            .expect("response should include x-request-id header");
        let id_str = request_id.to_str().unwrap();
        uuid::Uuid::parse_str(id_str).expect("should be a valid UUID");
    }

    #[tokio::test]
    async fn http_preserves_client_request_id() {
        let addr = start_http_server_with_middleware().await;
        let client_id = "my-custom-correlation-id";
        let resp = http1_get(addr, "/healthz", &[("x-request-id", client_id)]).await;
        assert_eq!(resp.status(), 200);

        let request_id = resp
            .headers()
            .get("x-request-id")
            .expect("response should include x-request-id header");
        assert_eq!(request_id.to_str().unwrap(), client_id);
    }

    #[tokio::test]
    async fn each_request_gets_unique_id() {
        let addr = start_http_server_with_middleware().await;

        let mut ids = Vec::new();
        for _ in 0..3 {
            let resp = http1_get(addr, "/healthz", &[]).await;
            let id = resp
                .headers()
                .get("x-request-id")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            ids.push(id);
        }

        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[1], ids[2]);
        assert_ne!(ids[0], ids[2]);
    }

    #[tokio::test]
    async fn grpc_path_includes_request_id() {
        let addr = start_http_server_with_middleware().await;
        let resp = http1_get(
            addr,
            "/openshell.v1.OpenShell/Health",
            &[
                ("content-type", "application/grpc"),
                ("x-request-id", "grpc-corr-id"),
            ],
        )
        .await;

        let request_id = resp
            .headers()
            .get("x-request-id")
            .expect("gRPC-routed response should include x-request-id header");
        assert_eq!(request_id.to_str().unwrap(), "grpc-corr-id");
    }

    #[derive(Clone)]
    struct TraceBuf(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for TraceBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn request_id_appears_in_trace_span() {
        use tracing_subscriber::fmt::format::FmtSpan;
        use tracing_subscriber::layer::SubscriberExt;

        let log_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let writer = TraceBuf(log_buf.clone());

        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_span_events(FmtSpan::CLOSE);

        let subscriber = tracing_subscriber::registry().with(fmt_layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        let req = Request::builder()
            .uri("/test-path")
            .header("x-request-id", "trace-test-id-12345")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let span = make_request_span(&req);
        drop(span.enter());
        drop(span);

        let output = String::from_utf8(log_buf.lock().unwrap().clone()).unwrap();
        assert!(
            output.contains("trace-test-id-12345"),
            "trace output should contain the request_id recorded in the span, got: {output}"
        );
    }

    #[test]
    fn grpc_method_extracts_last_segment() {
        assert_eq!(
            grpc_method_from_path("/openshell.v1.OpenShell/CreateSandbox"),
            "CreateSandbox"
        );
    }

    #[test]
    fn grpc_method_extracts_inference_service() {
        assert_eq!(
            grpc_method_from_path("/openshell.inference.v1.Inference/GetInferenceBundle"),
            "GetInferenceBundle"
        );
    }

    #[test]
    fn grpc_method_handles_bare_path() {
        assert_eq!(grpc_method_from_path("Health"), "Health");
    }

    #[test]
    fn grpc_method_handles_single_slash() {
        assert_eq!(grpc_method_from_path("/"), "");
    }

    #[test]
    fn grpc_method_handles_empty_string() {
        assert_eq!(grpc_method_from_path(""), "");
    }

    #[test]
    fn normalize_ws_tunnel() {
        assert_eq!(normalize_http_path("/_ws_tunnel"), "/_ws_tunnel");
    }

    #[test]
    fn normalize_ws_tunnel_with_trailing() {
        assert_eq!(normalize_http_path("/_ws_tunnel/foo"), "/_ws_tunnel");
    }

    #[test]
    fn normalize_auth_path() {
        assert_eq!(normalize_http_path("/auth/connect"), "/auth");
    }

    #[test]
    fn normalize_auth_with_query() {
        assert_eq!(
            normalize_http_path("/auth/connect?callback_port=12345&code=AB7-X9KM"),
            "/auth"
        );
    }

    #[test]
    fn normalize_unknown_path_collapses_to_unknown() {
        assert_eq!(normalize_http_path("/random/scanner/probe"), "unknown");
    }

    #[test]
    fn normalize_empty_path() {
        assert_eq!(normalize_http_path(""), "unknown");
    }

    #[test]
    fn normalize_root_path() {
        assert_eq!(normalize_http_path("/"), "unknown");
    }

    mod auth_router {
        use super::*;
        use crate::auth::authenticator::test_support::MockAuthenticator;
        use crate::auth::identity::{Identity, IdentityProvider};
        use crate::auth::principal::{
            Principal, SandboxIdentitySource, SandboxPrincipal, UserPrincipal,
        };
        use http_body_util::Full;
        use std::sync::Arc;
        use std::sync::Mutex;
        use tower::Service;

        type RecordedPrincipal = Arc<Mutex<Option<Principal>>>;

        /// Service that snapshots the `Principal` from request extensions
        /// and returns 200 OK. Used by router-level tests to assert the
        /// chain's effect on the downstream service.
        #[derive(Clone)]
        struct PrincipalRecorder {
            recorded: RecordedPrincipal,
        }

        impl PrincipalRecorder {
            fn new() -> (Self, RecordedPrincipal) {
                let recorded = Arc::new(Mutex::new(None));
                (
                    Self {
                        recorded: recorded.clone(),
                    },
                    recorded,
                )
            }
        }

        impl<B: Send + 'static> Service<Request<B>> for PrincipalRecorder {
            type Response = Response<tonic::body::BoxBody>;
            type Error = std::convert::Infallible;
            type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, req: Request<B>) -> Self::Future {
                let principal = req.extensions().get::<Principal>().cloned();
                *self.recorded.lock().unwrap() = principal;
                Box::pin(async move {
                    let body = tonic::body::BoxBody::new(
                        Full::new(Bytes::new())
                            .map_err(|never| match never {})
                            .boxed_unsync(),
                    );
                    Ok(Response::new(body))
                })
            }
        }

        fn empty_request(path: &str) -> Request<Full<Bytes>> {
            Request::builder()
                .uri(path)
                .body(Full::new(Bytes::new()))
                .unwrap()
        }

        fn grpc_status<B>(res: &Response<B>) -> Option<String> {
            res.headers()
                .get("grpc-status")
                .map(|v| v.to_str().unwrap().to_string())
        }

        fn user_principal(subject: &str) -> Principal {
            Principal::User(UserPrincipal {
                identity: Identity {
                    subject: subject.to_string(),
                    display_name: None,
                    roles: vec![],
                    scopes: vec![],
                    provider: IdentityProvider::Oidc,
                },
            })
        }

        fn mtls_identity(subject: &str) -> Identity {
            Identity {
                subject: subject.to_string(),
                display_name: Some(subject.to_string()),
                roles: vec!["openshell-user".to_string()],
                scopes: vec![],
                provider: IdentityProvider::Mtls,
            }
        }

        fn sandbox_principal() -> Principal {
            Principal::Sandbox(SandboxPrincipal {
                sandbox_id: "sandbox-a".to_string(),
                source: SandboxIdentitySource::BootstrapJwt {
                    issuer: "openshell-gateway:test".to_string(),
                },
                trust_domain: Some("openshell".to_string()),
            })
        }

        #[tokio::test]
        async fn mtls_peer_identity_fills_missing_principal_when_enabled() {
            let mock = Arc::new(MockAuthenticator::returning(Ok(None)));
            let chain = AuthenticatorChain::new(vec![mock]);
            let (recorder, seen) = PrincipalRecorder::new();
            let mut router = AuthGrpcRouter::with_peer_identity(
                recorder,
                Some(chain),
                None,
                Some(mtls_identity("openshell-client")),
                true,
                false,
            );

            let res = router
                .call(empty_request("/openshell.v1.OpenShell/ListSandboxes"))
                .await
                .unwrap();

            assert_eq!(res.status(), 200);
            let principal = seen.lock().unwrap().clone().expect("principal");
            match principal {
                Principal::User(u) => {
                    assert_eq!(u.identity.subject, "openshell-client");
                    assert_eq!(u.identity.provider, IdentityProvider::Mtls);
                }
                other => panic!("expected mTLS user principal, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn mtls_peer_identity_authenticates_without_chain_when_enabled() {
            let (recorder, seen) = PrincipalRecorder::new();
            let mut router = AuthGrpcRouter::with_peer_identity(
                recorder,
                None,
                None,
                Some(mtls_identity("openshell-client")),
                true,
                false,
            );

            let res = router
                .call(empty_request("/openshell.v1.OpenShell/ListSandboxes"))
                .await
                .unwrap();

            assert_eq!(res.status(), 200);
            assert!(matches!(
                seen.lock().unwrap().as_ref(),
                Some(Principal::User(_))
            ));
        }

        #[tokio::test]
        async fn mtls_auth_enabled_requires_peer_identity() {
            let (recorder, seen) = PrincipalRecorder::new();
            let mut router =
                AuthGrpcRouter::with_peer_identity(recorder, None, None, None, true, false);

            let res = router
                .call(empty_request("/openshell.v1.OpenShell/ListSandboxes"))
                .await
                .unwrap();

            assert!(seen.lock().unwrap().is_none());
            assert_eq!(grpc_status(&res).as_deref(), Some("16"));
        }

        #[tokio::test]
        async fn unauthenticated_dev_user_fills_missing_principal_when_enabled() {
            let mock = Arc::new(MockAuthenticator::returning(Ok(None)));
            let chain = AuthenticatorChain::new(vec![mock]);
            let (recorder, seen) = PrincipalRecorder::new();
            let mut router =
                AuthGrpcRouter::with_peer_identity(recorder, Some(chain), None, None, false, true);

            let res = router
                .call(empty_request("/openshell.v1.OpenShell/ListSandboxes"))
                .await
                .unwrap();

            assert_eq!(res.status(), 200);
            let principal = seen.lock().unwrap().clone().expect("principal");
            match principal {
                Principal::User(u) => {
                    assert_eq!(u.identity.subject, "unauthenticated-local-dev");
                    assert_eq!(u.identity.provider, IdentityProvider::LocalDev);
                }
                other => panic!("expected dev user principal, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn unauthenticated_dev_user_authenticates_without_chain_when_enabled() {
            let (recorder, seen) = PrincipalRecorder::new();
            let mut router =
                AuthGrpcRouter::with_peer_identity(recorder, None, None, None, false, true);

            let res = router
                .call(empty_request("/openshell.v1.OpenShell/ListSandboxes"))
                .await
                .unwrap();

            assert_eq!(res.status(), 200);
            assert!(matches!(
                seen.lock().unwrap().as_ref(),
                Some(Principal::User(user))
                    if user.identity.subject == "unauthenticated-local-dev"
            ));
        }

        #[tokio::test]
        async fn user_principal_lands_in_request_extensions() {
            let mock = Arc::new(MockAuthenticator::returning(Ok(Some(user_principal(
                "alice",
            )))));
            let chain = AuthenticatorChain::new(vec![mock]);
            let (recorder, seen) = PrincipalRecorder::new();
            let mut router = AuthGrpcRouter::new(recorder, Some(chain), None);
            let _ = router
                .call(empty_request("/openshell.v1.OpenShell/ListSandboxes"))
                .await
                .unwrap();
            let principal = seen.lock().unwrap().clone().expect("principal");
            match principal {
                Principal::User(u) => assert_eq!(u.identity.subject, "alice"),
                _ => panic!("expected user principal"),
            }
        }

        #[tokio::test]
        async fn sandbox_principal_lands_in_request_extensions() {
            let mock = Arc::new(MockAuthenticator::returning(Ok(Some(sandbox_principal()))));
            let chain = AuthenticatorChain::new(vec![mock]);
            let (recorder, seen) = PrincipalRecorder::new();
            let mut router = AuthGrpcRouter::new(recorder, Some(chain), None);
            let _ = router
                .call(empty_request("/openshell.v1.OpenShell/ReportPolicyStatus"))
                .await
                .unwrap();
            let captured = seen.lock().unwrap().clone();
            match captured {
                Some(Principal::Sandbox(p)) => assert_eq!(p.sandbox_id, "sandbox-a"),
                other => panic!("expected sandbox principal, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn sandbox_principal_can_call_allowlisted_method() {
            let mock = Arc::new(MockAuthenticator::returning(Ok(Some(sandbox_principal()))));
            let chain = AuthenticatorChain::new(vec![mock]);
            let (recorder, seen) = PrincipalRecorder::new();
            let mut router = AuthGrpcRouter::new(recorder, Some(chain), None);

            let res = router
                .call(empty_request("/openshell.v1.OpenShell/GetSandboxConfig"))
                .await
                .unwrap();

            assert_eq!(res.status(), 200);
            assert!(matches!(
                seen.lock().unwrap().as_ref(),
                Some(Principal::Sandbox(_))
            ));
        }

        #[tokio::test]
        async fn sandbox_principal_can_fetch_inference_bundle() {
            let mock = Arc::new(MockAuthenticator::returning(Ok(Some(sandbox_principal()))));
            let chain = AuthenticatorChain::new(vec![mock]);
            let (recorder, seen) = PrincipalRecorder::new();
            let mut router = AuthGrpcRouter::new(recorder, Some(chain), None);

            let res = router
                .call(empty_request(
                    "/openshell.inference.v1.Inference/GetInferenceBundle",
                ))
                .await
                .unwrap();

            assert_eq!(res.status(), 200);
            assert!(matches!(
                seen.lock().unwrap().as_ref(),
                Some(Principal::Sandbox(_))
            ));
        }

        /// A user principal — even one carrying `openshell:all` and the
        /// admin role — must not reach a `sandbox`-annotated method. The
        /// router enforces this from the per-handler auth-mode declarations
        /// independent of RBAC.
        #[tokio::test]
        async fn user_principal_is_denied_on_sandbox_only_methods() {
            fn admin_user() -> Principal {
                Principal::User(UserPrincipal {
                    identity: Identity {
                        subject: "admin".to_string(),
                        display_name: None,
                        roles: vec!["openshell-admin".to_string()],
                        scopes: vec!["openshell:all".to_string()],
                        provider: IdentityProvider::Oidc,
                    },
                })
            }

            let policy = AuthzPolicy {
                admin_role: "openshell-admin".to_string(),
                user_role: "openshell-user".to_string(),
                scopes_enabled: true,
            };

            for path in [
                "/openshell.v1.OpenShell/ReportPolicyStatus",
                "/openshell.v1.OpenShell/PushSandboxLogs",
                "/openshell.v1.OpenShell/SubmitPolicyAnalysis",
                "/openshell.v1.OpenShell/GetSandboxProviderEnvironment",
                "/openshell.v1.OpenShell/ConnectSupervisor",
                "/openshell.v1.OpenShell/RelayStream",
                "/openshell.v1.OpenShell/IssueSandboxToken",
                "/openshell.v1.OpenShell/RefreshSandboxToken",
                "/openshell.inference.v1.Inference/GetInferenceBundle",
            ] {
                let mock = Arc::new(MockAuthenticator::returning(Ok(Some(admin_user()))));
                let chain = AuthenticatorChain::new(vec![mock]);
                let (recorder, seen) = PrincipalRecorder::new();
                let mut router = AuthGrpcRouter::new(recorder, Some(chain), Some(policy.clone()));

                let res = router.call(empty_request(path)).await.unwrap();

                assert!(seen.lock().unwrap().is_none(), "{path} reached handler");
                // grpc-status=7 (PERMISSION_DENIED).
                assert_eq!(grpc_status(&res).as_deref(), Some("7"), "{path}");
            }
        }

        #[tokio::test]
        async fn sandbox_principal_is_denied_on_user_and_admin_methods() {
            for path in [
                "/openshell.v1.OpenShell/ListSandboxes",
                "/openshell.v1.OpenShell/DeleteSandbox",
                "/openshell.v1.OpenShell/CreateProvider",
                "/openshell.v1.OpenShell/ApproveDraftChunk",
                "/openshell.inference.v1.Inference/GetClusterInference",
                "/openshell.inference.v1.Inference/SetClusterInference",
            ] {
                let mock = Arc::new(MockAuthenticator::returning(Ok(Some(sandbox_principal()))));
                let chain = AuthenticatorChain::new(vec![mock]);
                let (recorder, seen) = PrincipalRecorder::new();
                let mut router = AuthGrpcRouter::new(recorder, Some(chain), None);

                let res = router.call(empty_request(path)).await.unwrap();

                assert!(seen.lock().unwrap().is_none(), "{path} reached handler");
                assert_eq!(grpc_status(&res).as_deref(), Some("7"), "{path}");
            }
        }

        #[tokio::test]
        async fn missing_principal_returns_unauthenticated() {
            let mock = Arc::new(MockAuthenticator::returning(Ok(None)));
            let chain = AuthenticatorChain::new(vec![mock]);
            let (recorder, seen) = PrincipalRecorder::new();
            let mut router = AuthGrpcRouter::new(recorder, Some(chain), None);
            let res = router
                .call(empty_request("/openshell.v1.OpenShell/ListSandboxes"))
                .await
                .unwrap();
            assert!(seen.lock().unwrap().is_none());
            // tonic sets grpc-status=16 (UNAUTHENTICATED) in trailers.
            assert_eq!(grpc_status(&res).as_deref(), Some("16"));
        }

        #[tokio::test]
        async fn authenticator_error_short_circuits() {
            let mock = Arc::new(MockAuthenticator::returning(Err(
                tonic::Status::unauthenticated("forged"),
            )));
            let chain = AuthenticatorChain::new(vec![mock]);
            let (recorder, seen) = PrincipalRecorder::new();
            let mut router = AuthGrpcRouter::new(recorder, Some(chain), None);
            let res = router
                .call(empty_request("/openshell.v1.OpenShell/ListSandboxes"))
                .await
                .unwrap();
            assert!(seen.lock().unwrap().is_none());
            assert_eq!(grpc_status(&res).as_deref(), Some("16"));
        }

        #[tokio::test]
        async fn health_methods_bypass_chain() {
            // Authenticator is wired to fail-closed; the request still gets
            // through because the path is exempt.
            let mock = Arc::new(MockAuthenticator::returning(Err(
                tonic::Status::unauthenticated("would reject"),
            )));
            let chain = AuthenticatorChain::new(vec![mock.clone()]);
            let (recorder, _) = PrincipalRecorder::new();
            let mut router = AuthGrpcRouter::new(recorder, Some(chain), None);
            let res = router
                .call(empty_request("/openshell.v1.OpenShell/Health"))
                .await
                .unwrap();
            assert_eq!(res.status(), 200);
            assert_eq!(mock.call_count(), 0, "health must not consult the chain");
        }
    }
}
