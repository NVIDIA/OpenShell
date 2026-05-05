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
    OpenShellService, ServerState, auth::authz::AuthzPolicy, auth::oidc, http_router,
    inference::InferenceService,
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
        let openshell = OpenShellServer::new(OpenShellService::new(self.state.clone()))
            .max_decoding_message_size(MAX_GRPC_DECODE_SIZE);
        let inference = InferenceServer::new(InferenceService::new(self.state.clone()))
            .max_decoding_message_size(MAX_GRPC_DECODE_SIZE);
        let authz_policy = self.state.config.oidc.as_ref().map(|oidc| AuthzPolicy {
            admin_role: oidc.admin_role.clone(),
            user_role: oidc.user_role.clone(),
            scopes_enabled: !oidc.scopes_claim.is_empty(),
        });
        let grpc_service = AuthGrpcRouter::new(
            GrpcRouter::new(openshell, inference),
            self.state.oidc_cache.clone(),
            authz_policy,
            self.state.config.ssh_handshake_secret.clone(),
        );
        let http_service = http_router(self.state.clone());

        let grpc_service = request_id_middleware!(grpc_service);
        let http_service = request_id_middleware!(http_service);

        let service = MultiplexedService::new(grpc_service, http_service);

        // HTTP/2 adaptive flow control. Default windows (64 KiB / 64 KiB)
        // throttle the RelayStream data plane to ~500 Mbps on LAN. Instead
        // of committing to a fixed large window (which worst-case pins
        // `max_concurrent_streams × stream_window` bytes per connection),
        // we let hyper/h2 auto-size based on the measured bandwidth-delay
        // product. Idle streams stay tiny; busy bulk streams grow as
        // needed. Overrides any fixed initial_*_window_size settings.
        let mut builder = Builder::new(TokioExecutor::new());
        builder.http2().adaptive_window(true);

        builder
            .serve_connection_with_upgrades(TokioIo::new(stream), service)
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

/// gRPC router wrapper that authenticates and authorizes requests.
///
/// When `oidc_cache` is `Some`, extracts the `authorization: Bearer <token>`
/// header, validates the JWT (authentication), then checks RBAC roles
/// (authorization) before forwarding to the inner gRPC router.
///
/// Authentication is provider-specific (currently OIDC via `oidc.rs`).
/// Authorization is provider-agnostic (via `authz.rs`). This separation
/// aligns with RFC 0001's control-plane identity design.
#[derive(Clone)]
pub struct AuthGrpcRouter<S> {
    inner: S,
    oidc_cache: Option<Arc<oidc::JwksCache>>,
    authz_policy: Option<AuthzPolicy>,
    /// SSH handshake secret used to validate sandbox-to-server RPCs.
    sandbox_secret: String,
}

impl<S> AuthGrpcRouter<S> {
    fn new(
        inner: S,
        oidc_cache: Option<Arc<oidc::JwksCache>>,
        authz_policy: Option<AuthzPolicy>,
        sandbox_secret: String,
    ) -> Self {
        Self {
            inner,
            oidc_cache,
            authz_policy,
            sandbox_secret,
        }
    }
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
        let oidc_cache = self.oidc_cache.clone();
        let authz_policy = self.authz_policy.clone();
        let sandbox_secret = self.sandbox_secret.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let mut req = req;
            oidc::clear_internal_auth_markers(req.headers_mut());

            // If OIDC is not configured, pass through directly.
            let Some(cache) = oidc_cache else {
                return inner.ready().await?.call(req).await;
            };

            let path = req.uri().path().to_string();

            // Health probes and reflection — truly unauthenticated.
            if oidc::is_unauthenticated_method(&path) {
                return inner.ready().await?.call(req).await;
            }

            // Sandbox-to-server RPCs — authenticated via shared secret,
            // not OIDC Bearer tokens.
            if oidc::is_sandbox_secret_method(&path) {
                if let Err(status) = oidc::validate_sandbox_secret(req.headers(), &sandbox_secret) {
                    let response = status.into_http();
                    let (parts, body) = response.into_parts();
                    let body = tonic::body::BoxBody::new(body);
                    return Ok(Response::from_parts(parts, body));
                }
                oidc::mark_sandbox_secret_authenticated(req.headers_mut());
                return inner.ready().await?.call(req).await;
            }

            // Dual-auth methods (e.g. UpdateConfig) — accept either a
            // Bearer token (CLI users) or sandbox secret (supervisor).
            if oidc::is_dual_auth_method(&path)
                && oidc::validate_sandbox_secret(req.headers(), &sandbox_secret).is_ok()
            {
                oidc::mark_sandbox_secret_authenticated(req.headers_mut());
                return inner.ready().await?.call(req).await;
            }
            // Fall through to Bearer token validation below.

            // Extract Bearer token from the authorization header.
            let token = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "));

            let Some(token) = token else {
                let status = tonic::Status::unauthenticated("missing authorization header");
                let response = status.into_http();
                // Convert the response body type.
                let (parts, body) = response.into_parts();
                let body = tonic::body::BoxBody::new(body);
                return Ok(Response::from_parts(parts, body));
            };

            // Authenticate: validate the JWT and produce an Identity.
            let identity = match cache.validate_token(token).await {
                Ok(id) => id,
                Err(status) => {
                    let response = status.into_http();
                    let (parts, body) = response.into_parts();
                    let body = tonic::body::BoxBody::new(body);
                    return Ok(Response::from_parts(parts, body));
                }
            };

            // Authorize: check RBAC roles against the method.
            if let Some(ref policy) = authz_policy
                && let Err(status) = policy.check(&identity, &path)
            {
                let response = status.into_http();
                let (parts, body) = response.into_parts();
                let body = tonic::body::BoxBody::new(body);
                return Ok(Response::from_parts(parts, body));
            }

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
        p if p.starts_with("/connect/ssh") => "/connect/ssh",
        p if p.starts_with("/_ws_tunnel") => "/_ws_tunnel",
        p if p.starts_with("/auth/") => "/auth",
        _ => "unknown",
    }
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

    async fn start_http_server_with_middleware() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let http_service = crate::http::health_router();
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
    fn normalize_ssh_path() {
        assert_eq!(normalize_http_path("/connect/ssh"), "/connect/ssh");
    }

    #[test]
    fn normalize_ssh_path_with_trailing_segments() {
        assert_eq!(
            normalize_http_path("/connect/ssh?token=abc"),
            "/connect/ssh"
        );
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
}
