// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Protocol multiplexing for gRPC and HTTP on the same port.
//!
//! This module implements connection-level multiplexing that routes requests
//! to either the gRPC service or HTTP endpoints based on the request headers.

use bytes::{Bytes, BytesMut};
use http::{Extensions, HeaderValue, Request, Response, StatusCode};
use http_body::Body;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited, StreamBody};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use metrics::{counter, histogram};
use openshell_core::proto::{
    inference_server::InferenceServer, open_shell_server::OpenShellServer,
};
use openshell_core::{
    Config,
    proto::{Provider, UpdateProviderRequest},
};
use openshell_gateway_interceptors::{EvaluationContext, GatewayInterceptorRuntime};
use openshell_otel::HeaderMapExtractor;
use opentelemetry::propagation::TextMapPropagator;
use opentelemetry::trace::TraceContextExt as _;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use prost::Message;
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tower::ServiceExt;
use tower_http::request_id::{MakeRequestId, RequestId};
use tracing::{Span, warn};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

use crate::{
    OpenShellService, ServerState,
    auth::authenticator::AuthenticatorChain,
    auth::authz::AuthzPolicy,
    auth::identity::Identity,
    auth::oidc::{self, OidcAuthenticator},
    auth::principal::{Principal, UserPrincipal},
    auth::workspace_authz::{MinWorkspaceRole, authorize_workspace},
    gateway_listener::GatewayListenerScope,
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

    // `otel.name` and `otel.kind` are consumed by `tracing-opentelemetry` to
    // set the exported span's name and kind; they are not emitted as
    // attributes. See [`otel_span_name`] for why the name cannot simply be
    // the callsite name.
    let otel_name = otel_span_name(req.method(), path);

    let span = if matches!(path, "/health" | "/healthz" | "/readyz") {
        tracing::debug_span!(
            "request",
            method = %req.method(),
            path,
            request_id,
            otel.name = %otel_name,
            otel.kind = "server",
            otel.status_code = tracing::field::Empty,
            http.response.status_code = tracing::field::Empty,
        )
    } else {
        let span = tracing::info_span!(
            "request",
            method = %req.method(),
            path,
            request_id,
            otel.name = %otel_name,
            otel.kind = "server",
            otel.status_code = tracing::field::Empty,
            http.response.status_code = tracing::field::Empty,
            rpc.system = tracing::field::Empty,
            rpc.service = tracing::field::Empty,
            rpc.method = tracing::field::Empty,
            rpc.grpc.status_code = tracing::field::Empty,
        );
        // RPC-aware backends build service maps from these; without them a
        // gRPC call is just an HTTP span.
        if let Some((service, method)) = grpc_service_method(path) {
            span.record("rpc.system", "grpc");
            span.record("rpc.service", service);
            span.record("rpc.method", method);
        }
        span
    };

    let propagator = TraceContextPropagator::new();
    let parent = propagator.extract_with_context(
        &opentelemetry::Context::new(),
        &HeaderMapExtractor::new(req.headers()),
    );
    if parent.span().span_context().is_valid() {
        let _ = span.set_parent(parent);
    }

    span
}

/// Log response status and latency, record protocol status, and mark failures.
fn log_response<B>(res: &Response<B>, latency: Duration, span: &Span) {
    let status = res.status();
    span.record("http.response.status_code", status.as_u16());
    record_grpc_status(res.headers(), span);
    if status.is_server_error() {
        crate::otel_tracing::mark_error(span);
    }
    tracing::info!(
        status = status.as_u16(),
        latency_ms = latency.as_millis(),
        "response"
    );
}

fn record_response_trailers(
    trailers: Option<&http::HeaderMap>,
    _stream_duration: Duration,
    span: &Span,
) {
    if let Some(trailers) = trailers {
        record_grpc_status(trailers, span);
    }
}

fn record_grpc_status(headers: &http::HeaderMap, span: &Span) {
    let Some(code) = headers
        .get("grpc-status")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
    else {
        return;
    };

    span.record("rpc.grpc.status_code", code);
    if code != 0 {
        crate::otel_tracing::mark_error(span);
    }
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
                    .on_response(log_response)
                    .on_eos(record_response_trailers),
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
const MAX_INTERCEPTED_GRPC_BODY_SIZE: usize = MAX_GRPC_DECODE_SIZE + 5;

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
        self.serve_on_listener(stream, GatewayListenerScope::Primary)
            .await
    }

    /// Serve a connection and preserve its listener scope in request
    /// extensions for downstream routing and policy decisions.
    pub(crate) async fn serve_on_listener<S>(
        &self,
        stream: S,
        listener_scope: GatewayListenerScope,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.serve_with_peer_identity_on_listener(stream, None, listener_scope)
            .await
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
        self.serve_with_peer_identity_on_listener(
            stream,
            peer_identity,
            GatewayListenerScope::Primary,
        )
        .await
    }

    /// Serve a TLS connection and preserve its listener scope in request
    /// extensions for downstream routing and policy decisions.
    pub(crate) async fn serve_with_peer_identity_on_listener<S>(
        &self,
        stream: S,
        peer_identity: Option<Identity>,
        listener_scope: GatewayListenerScope,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let openshell = OpenShellServer::new(OpenShellService::new(self.state.clone()))
            .max_decoding_message_size(MAX_GRPC_DECODE_SIZE);
        let openshell = GatewayInterceptorGrpcService::new(
            openshell,
            self.state.gateway_interceptors.clone(),
            Some(self.state.clone()),
        );
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
        let grpc_service =
            GrpcRateLimitService::new(grpc_service, self.state.grpc_rate_limiter.clone());
        let http_service = http_router(self.state.clone());

        let grpc_service = request_id_middleware!(grpc_service);
        let http_service = request_id_middleware!(http_service);

        let service = GatewayListenerContextService::new(
            MultiplexedService::new(grpc_service, http_service),
            listener_scope,
        );

        let mut builder = Builder::new(TokioExecutor::new());
        // Server-side HTTP/2 keepalive: supervisors hold long-lived sessions, and without
        // it the gateway never PINGs them, so idle/half-dead connections linger and orphan
        // in-flight relay execs. The timer is required — hyper panics on the keepalive
        // interval without one.
        builder
            .http2()
            .timer(TokioTimer::new())
            .adaptive_window(true)
            .keep_alive_interval(Some(Duration::from_secs(20)))
            .keep_alive_timeout(Duration::from_secs(10));

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
        self.serve_service_http_on_listener(stream, GatewayListenerScope::Primary)
            .await
    }

    /// Serve a plaintext service HTTP connection and preserve its listener
    /// scope in request extensions.
    pub(crate) async fn serve_service_http_on_listener<S>(
        &self,
        stream: S,
        listener_scope: GatewayListenerScope,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let http_service = GatewayListenerContextService::new(
            TowerToHyperService::new(request_id_middleware!(service_http_router(
                self.state.clone()
            ))),
            listener_scope,
        );

        Builder::new(TokioExecutor::new())
            .serve_connection_with_upgrades(TokioIo::new(stream), http_service)
            .await?;

        Ok(())
    }
}

/// Adds the immutable listener authorization scope to every served request.
#[derive(Clone)]
struct GatewayListenerContextService<S> {
    inner: S,
    listener_scope: GatewayListenerScope,
}

impl<S> GatewayListenerContextService<S> {
    fn new(inner: S, listener_scope: GatewayListenerScope) -> Self {
        Self {
            inner,
            listener_scope,
        }
    }
}

impl<S, B> hyper::service::Service<Request<B>> for GatewayListenerContextService<S>
where
    S: hyper::service::Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn call(&self, mut request: Request<B>) -> Self::Future {
        request.extensions_mut().insert(self.listener_scope);
        self.inner.call(request)
    }
}

/// `OpenShell` gRPC wrapper that applies configured gateway interceptors before
/// tonic dispatches to a specific RPC handler.
#[derive(Clone)]
struct GatewayInterceptorGrpcService<S> {
    inner: S,
    interceptors: Option<GatewayInterceptorRuntime>,
    state: Option<Arc<ServerState>>,
}

impl<S> GatewayInterceptorGrpcService<S> {
    fn new(
        inner: S,
        interceptors: Option<GatewayInterceptorRuntime>,
        state: Option<Arc<ServerState>>,
    ) -> Self {
        Self {
            inner,
            interceptors,
            state,
        }
    }
}

impl<S> tower::Service<Request<BoxBody>> for GatewayInterceptorGrpcService<S>
where
    S: tower::Service<Request<BoxBody>, Response = Response<tonic::body::Body>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<BoxBody>) -> Self::Future {
        let interceptors = self.interceptors.clone();
        let state = self.state.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let Some(interceptors) = interceptors else {
                return inner.ready().await?.call(req).await;
            };

            let path = req.uri().path().to_string();
            if !interceptors.should_intercept_path(&path) {
                return inner.ready().await?.call(req).await;
            }

            let context = gateway_interceptor_context(req.extensions());
            let principal = req.extensions().get::<Principal>().cloned();
            let (parts, body) = req.into_parts();
            let mut body = match collect_intercepted_grpc_body(body).await {
                Ok(body) => body,
                Err(status) => return Ok(status.into_http()),
            };
            if let Some(state) = state.as_ref() {
                body =
                    match hydrate_update_provider_identity(&path, body, state, principal.as_ref())
                        .await
                    {
                        Ok(body) => body,
                        Err(status) => return Ok(status.into_http()),
                    };
            }

            let intercepted = match interceptors.evaluate_request(&path, &body, &context).await {
                Ok(intercepted) => intercepted,
                Err(status) => return Ok(status.into_http()),
            };

            let req = Request::from_parts(
                parts,
                boxed_body_from_bytes(Bytes::from(intercepted.body.clone())),
            );
            let response = inner.ready().await?.call(req).await?;

            if grpc_status_from_response(&response) != "0"
                || !interceptors.has_post_commit(&intercepted)
            {
                return Ok(response);
            }

            let (response, observation) = observe_intercepted_grpc_response(response).await;
            let (response_body, trailers) = match observation {
                Ok(observation) => observation,
                Err(error) => {
                    warn!(
                        error = %error,
                        "gateway post-commit response observation failed; preserving committed response"
                    );
                    counter!(
                        "openshell_gateway_interceptor_post_commit_observation_failures_total",
                        "stage" => "response_body"
                    )
                    .increment(1);
                    return Ok(response);
                }
            };
            if grpc_status_from_response_and_trailers(&response, trailers.as_ref()) == "0"
                && let Err(status) = interceptors
                    .evaluate_post_commit(&intercepted, &response_body, &context)
                    .await
            {
                warn!(
                    error = %status,
                    "gateway post-commit evaluation failed; preserving committed response"
                );
                counter!(
                    "openshell_gateway_interceptor_post_commit_observation_failures_total",
                    "stage" => "evaluation"
                )
                .increment(1);
            }

            Ok(response)
        })
    }
}

const UPDATE_PROVIDER_PATH: &str = "/openshell.v1.OpenShell/UpdateProvider";
const GRPC_FRAME_HEADER_LEN: usize = 5;

/// Complete immutable provider identity before policy interception.
///
/// Update requests intentionally omit immutable fields. Loading them here keeps
/// `provider update` a write-only operation while giving policy interceptors a
/// canonical proposed operation derived from trusted gateway state.
async fn hydrate_update_provider_identity(
    path: &str,
    body: Bytes,
    state: &ServerState,
    principal: Option<&Principal>,
) -> Result<Bytes, tonic::Status> {
    if path != UPDATE_PROVIDER_PATH {
        return Ok(body);
    }

    let mut request = decode_unary_grpc_message::<UpdateProviderRequest>(&body)?;
    let Some(provider) = request.provider.as_mut() else {
        return Ok(body);
    };
    if !provider.r#type.is_empty() && !provider.profile_workspace.is_empty() {
        return Ok(body);
    }
    let name = provider
        .metadata
        .as_ref()
        .map(|metadata| metadata.name.as_str())
        .unwrap_or_default();
    if name.is_empty() {
        return Ok(body);
    }

    let principal =
        principal.ok_or_else(|| tonic::Status::unauthenticated("authentication required"))?;
    let authorized = authorize_workspace(
        state.store.as_ref(),
        &state.admin_role,
        principal,
        &request.workspace,
        MinWorkspaceRole::Admin,
    )
    .await?;
    let workspace =
        crate::grpc::workspace::resolve_workspace(state.store.as_ref(), &authorized.workspace)
            .await?
            .name;
    let existing = state
        .store
        .get_message_by_name::<Provider>(&workspace, name)
        .await
        .map_err(|error| tonic::Status::internal(format!("provider lookup failed: {error}")))?
        .ok_or_else(|| tonic::Status::not_found(format!("provider '{name}' not found")))?;

    if provider.r#type.is_empty() {
        provider.r#type = existing.r#type;
    }
    if provider.profile_workspace.is_empty() {
        provider.profile_workspace = existing.profile_workspace;
    }

    encode_unary_grpc_message(&request)
}

fn decode_unary_grpc_message<M>(body: &[u8]) -> Result<M, tonic::Status>
where
    M: Message + Default,
{
    if body.len() < GRPC_FRAME_HEADER_LEN {
        return Err(tonic::Status::invalid_argument("gRPC frame is too short"));
    }
    if body[0] != 0 {
        return Err(tonic::Status::unimplemented(
            "gateway interceptors do not support compressed gRPC frames",
        ));
    }
    let message_len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    if body.len() != GRPC_FRAME_HEADER_LEN + message_len {
        return Err(tonic::Status::invalid_argument(
            "gRPC body must contain exactly one frame",
        ));
    }
    M::decode(&body[GRPC_FRAME_HEADER_LEN..])
        .map_err(|error| tonic::Status::invalid_argument(format!("invalid gRPC message: {error}")))
}

fn encode_unary_grpc_message<M: Message>(message: &M) -> Result<Bytes, tonic::Status> {
    let message = message.encode_to_vec();
    let message_len = u32::try_from(message.len())
        .map_err(|_| tonic::Status::resource_exhausted("gRPC message exceeds u32"))?;
    let mut frame = Vec::with_capacity(GRPC_FRAME_HEADER_LEN + message.len());
    frame.push(0);
    frame.extend_from_slice(&message_len.to_be_bytes());
    frame.extend_from_slice(&message);
    Ok(Bytes::from(frame))
}

async fn collect_intercepted_grpc_body(body: BoxBody) -> Result<Bytes, tonic::Status> {
    Limited::new(body, MAX_INTERCEPTED_GRPC_BODY_SIZE)
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .map_err(|err| {
            if err.downcast_ref::<LengthLimitError>().is_some() {
                tonic::Status::resource_exhausted(format!(
                    "gRPC request body exceeds interceptor evaluation limit of {MAX_INTERCEPTED_GRPC_BODY_SIZE} bytes"
                ))
            } else {
                tonic::Status::internal(format!(
                    "failed to read gRPC request body for interceptor evaluation: {err}"
                ))
            }
        })
}

fn boxed_body_from_bytes(bytes: Bytes) -> BoxBody {
    let body = Full::new(bytes)
        .map_err(|never: Infallible| -> Box<dyn std::error::Error + Send + Sync> { match never {} })
        .boxed_unsync();
    BoxBody(body)
}

async fn observe_intercepted_grpc_response(
    response: Response<tonic::body::Body>,
) -> (
    Response<tonic::body::Body>,
    Result<(Bytes, Option<http::HeaderMap>), String>,
) {
    let (parts, mut body) = response.into_parts();
    let mut frames = Vec::new();
    let mut bytes = BytesMut::new();
    let mut trailers = None;

    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => {
                if let Some(data) = frame.data_ref() {
                    bytes.extend_from_slice(data);
                }
                if let Some(frame_trailers) = frame.trailers_ref() {
                    trailers = Some(frame_trailers.clone());
                }
                frames.push(Ok(frame));
            }
            Err(status) => {
                let error =
                    format!("failed to read gRPC response for post-commit evaluation: {status}");
                frames.push(Err(status));
                return (
                    Response::from_parts(parts, tonic_body_from_frames(frames)),
                    Err(error),
                );
            }
        }
    }

    (
        Response::from_parts(parts, tonic_body_from_frames(frames)),
        Ok((bytes.freeze(), trailers)),
    )
}

#[cfg(test)]
fn tonic_body_from_bytes_and_trailers(
    bytes: Bytes,
    trailers: Option<http::HeaderMap>,
) -> tonic::body::Body {
    let mut frames: Vec<Result<http_body::Frame<Bytes>, tonic::Status>> = Vec::with_capacity(2);
    if !bytes.is_empty() {
        frames.push(Ok(http_body::Frame::data(bytes)));
    }
    if let Some(trailers) = trailers {
        frames.push(Ok(http_body::Frame::trailers(trailers)));
    }
    tonic_body_from_frames(frames)
}

fn tonic_body_from_frames(
    frames: Vec<Result<http_body::Frame<Bytes>, tonic::Status>>,
) -> tonic::body::Body {
    tonic::body::Body::new(StreamBody::new(futures::stream::iter(frames)))
}

fn gateway_interceptor_context(extensions: &Extensions) -> EvaluationContext {
    EvaluationContext {
        principal: extensions
            .get::<Principal>()
            .map_or_else(unknown_gateway_principal, gateway_principal_fields),
        validate_current_state: None,
    }
}

fn gateway_principal_fields(principal: &Principal) -> BTreeMap<String, String> {
    use crate::auth::principal::SandboxIdentitySource;

    let mut fields = BTreeMap::new();
    match principal {
        Principal::User(user) => {
            fields.insert("kind".to_string(), "user".to_string());
            fields.insert("subject".to_string(), user.identity.subject.clone());
            if let Some(display_name) = &user.identity.display_name {
                fields.insert("display_name".to_string(), display_name.clone());
            }
            fields.insert(
                "provider".to_string(),
                identity_provider_name(user.identity.provider).to_string(),
            );
            if !user.identity.roles.is_empty() {
                fields.insert("roles".to_string(), user.identity.roles.join(","));
            }
            if !user.identity.scopes.is_empty() {
                fields.insert("scopes".to_string(), user.identity.scopes.join(","));
            }
        }
        Principal::Sandbox(sandbox) => {
            fields.insert("kind".to_string(), "sandbox".to_string());
            fields.insert("sandbox_id".to_string(), sandbox.sandbox_id.clone());
            fields.insert(
                "source".to_string(),
                match &sandbox.source {
                    SandboxIdentitySource::BootstrapJwt { .. } => "bootstrap_jwt",
                    SandboxIdentitySource::BootstrapCert { .. } => "bootstrap_cert",
                    SandboxIdentitySource::K8sServiceAccount { .. } => "k8s_service_account",
                }
                .to_string(),
            );
            if let Some(trust_domain) = &sandbox.trust_domain {
                fields.insert("trust_domain".to_string(), trust_domain.clone());
            }
        }
        Principal::Anonymous => {
            fields.insert("kind".to_string(), "anonymous".to_string());
        }
    }
    fields
}

fn unknown_gateway_principal() -> BTreeMap<String, String> {
    BTreeMap::from([("kind".to_string(), "unknown".to_string())])
}

fn identity_provider_name(provider: crate::auth::identity::IdentityProvider) -> &'static str {
    match provider {
        crate::auth::identity::IdentityProvider::Oidc => "oidc",
        crate::auth::identity::IdentityProvider::Mtls => "mtls",
        crate::auth::identity::IdentityProvider::CloudflareAccess => "cloudflare_access",
        crate::auth::identity::IdentityProvider::LocalDev => "local_dev",
    }
}

#[derive(Clone, Debug)]
pub struct GrpcRateLimiter {
    requests: u64,
    window: Duration,
    state: Arc<Mutex<GrpcRateLimitState>>,
}

#[derive(Debug)]
struct GrpcRateLimitState {
    window_started: Instant,
    remaining: u64,
}

impl GrpcRateLimiter {
    pub fn from_config(config: &Config) -> Option<Self> {
        let (requests, window) = config.grpc_rate_limit()?;
        Some(Self {
            requests,
            window,
            state: Arc::new(Mutex::new(GrpcRateLimitState {
                window_started: Instant::now(),
                remaining: requests,
            })),
        })
    }

    fn allow(&self) -> bool {
        let now = Instant::now();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if now.duration_since(state.window_started) >= self.window {
            state.window_started = now;
            state.remaining = self.requests;
        }
        if state.remaining == 0 {
            false
        } else {
            state.remaining -= 1;
            true
        }
    }

    /// Report whether the limiter currently has capacity without consuming a
    /// token, rolling the window over first so an elapsed window reports
    /// capacity again.
    ///
    /// Used by `poll_ready` so an exhausted limiter reports readiness instead
    /// of blocking on inner-service backpressure: `call` can then return
    /// `RESOURCE_EXHAUSTED` immediately rather than waiting for the inner gRPC
    /// service to become ready.
    fn has_capacity(&self) -> bool {
        let now = Instant::now();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if now.duration_since(state.window_started) >= self.window {
            state.window_started = now;
            state.remaining = self.requests;
        }
        state.remaining > 0
    }
}

#[derive(Clone)]
struct GrpcRateLimitService<S> {
    inner: S,
    limiter: Option<GrpcRateLimiter>,
    /// Set by `poll_ready` when it reports synthetic readiness for an
    /// exhausted limiter without polling the inner service. The paired `call`
    /// must then reject with `RESOURCE_EXHAUSTED` instead of forwarding to an
    /// inner service that never reported readiness — even if the rate-limit
    /// window rolls over in between. Reset whenever `poll_ready` defers to the
    /// inner service.
    rate_limited: bool,
}

impl<S> GrpcRateLimitService<S> {
    fn new(inner: S, limiter: Option<GrpcRateLimiter>) -> Self {
        Self {
            inner,
            limiter,
            rate_limited: false,
        }
    }
}

impl<S, B> tower::Service<Request<B>> for GrpcRateLimitService<S>
where
    S: tower::Service<Request<B>, Response = Response<tonic::body::Body>>,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // When the limiter is exhausted, report ready so `call` can return
        // RESOURCE_EXHAUSTED immediately. Delegating to the inner service here
        // would make rate-limited requests wait on inner backpressure (a
        // pending inner `poll_ready`) before they are rejected. The check is
        // non-consuming: the token is only consumed in `call` via `allow`.
        //
        // Crucially, this path does NOT poll the inner service, so the inner
        // service has not reported readiness. Record that decision so the
        // paired `call` rejects rather than forwarding to a service that never
        // became ready — even if the rate-limit window rolls over in between.
        if self
            .limiter
            .as_ref()
            .is_some_and(|limiter| !limiter.has_capacity())
        {
            self.rate_limited = true;
            return Poll::Ready(Ok(()));
        }
        self.rate_limited = false;
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        // If `poll_ready` short-circuited an exhausted limiter, it never polled
        // the inner service to readiness. Honor that decision regardless of the
        // limiter's current state (the window may have rolled over since): the
        // Tower contract forbids forwarding to an inner service that did not
        // report readiness.
        if std::mem::take(&mut self.rate_limited) {
            let response =
                tonic::Status::resource_exhausted("gRPC rate limit exceeded").into_http();
            return Box::pin(async move { Ok(response) });
        }
        if self
            .limiter
            .as_ref()
            .is_some_and(|limiter| !limiter.allow())
        {
            let response =
                tonic::Status::resource_exhausted("gRPC rate limit exceeded").into_http();
            return Box::pin(async move { Ok(response) });
        }
        let future = self.inner.call(req);
        Box::pin(future)
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
/// When neither OIDC nor sandbox credentials are configured (a barebones
/// dev gateway), the chain is left as `None` so the router short-circuits
/// to pass-through unless mTLS or local unauthenticated users are enabled.
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

fn status_response(status: tonic::Status) -> Response<tonic::body::Body> {
    status.into_http()
}

impl<S, B> tower::Service<Request<B>> for AuthGrpcRouter<S>
where
    S: tower::Service<Request<B>, Response = Response<tonic::body::Body>> + Clone + Send + 'static,
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
                // No auth configured — dev / fronting-proxy deployments.
                // Inject a local-dev principal so downstream handlers that
                // call extract_principal() always find one.
                unauthenticated_dev_user_principal()
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

fn listener_allows_request(
    listener_scope: Option<&GatewayListenerScope>,
    is_grpc: bool,
    path: &str,
) -> bool {
    match listener_scope {
        Some(GatewayListenerScope::ComputeDriverCallback) => {
            is_grpc && crate::auth::sandbox_methods::is_sandbox_callable(path)
        }
        Some(GatewayListenerScope::Primary) | None => true,
    }
}

fn callback_listener_rejection(is_grpc: bool) -> Response<BoxBody> {
    if is_grpc {
        let response: Response<tonic::body::Body> = tonic::Status::permission_denied(
            "compute-driver callback listeners accept sandbox callback RPCs only",
        )
        .into_http();
        let (parts, body) = response.into_parts();
        let body = body.map_err(Into::into).boxed_unsync();
        Response::from_parts(parts, BoxBody(body))
    } else {
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(boxed_body_from_bytes(Bytes::from_static(
                b"compute-driver callback listeners accept gRPC callbacks only",
            )))
            .expect("static callback listener rejection response must be valid")
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

        if !listener_allows_request(
            req.extensions().get::<GatewayListenerScope>(),
            is_grpc,
            req.uri().path(),
        ) {
            let response = callback_listener_rejection(is_grpc);
            return Box::pin(async move { Ok(response) });
        }

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

/// Name for the exported `OpenTelemetry` span, per the `OTel` semantic
/// conventions: `$service/$method` for RPCs and the method for plain HTTP.
///
/// The gateway cannot determine route templates for proxied sandbox
/// applications, so including the literal path would create high-cardinality
/// operation names. The path remains available as a span attribute.
///
/// The `tracing` callsite name is the constant `"request"` because `tracing`
/// requires `'static` span names, so the per-request name is carried in the
/// `otel.name` field instead.
fn otel_span_name(method: &http::Method, path: &str) -> String {
    grpc_service_method(path).map_or_else(
        || method.to_string(),
        |(service, rpc_method)| format!("{service}/{rpc_method}"),
    )
}

/// Split a gRPC path into its service and method.
///
/// A gRPC path is exactly "/package.Service/Method". Anything else — a health
/// check, /metrics, a sandbox service URL — is plain HTTP.
fn grpc_service_method(path: &str) -> Option<(&str, &str)> {
    let mut segments = path.strip_prefix('/')?.split('/');
    let service = segments.next()?;
    let method = segments.next()?;
    if segments.next().is_some() || !service.contains('.') || method.is_empty() {
        return None;
    }
    Some((service, method))
}

fn grpc_status_from_response<B>(res: &Response<B>) -> String {
    res.headers()
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .map_or_else(|| "0".to_string(), ToString::to_string)
}

fn grpc_status_from_response_and_trailers<B>(
    res: &Response<B>,
    trailers: Option<&http::HeaderMap>,
) -> String {
    trailers
        .and_then(|trailers| trailers.get("grpc-status"))
        .or_else(|| res.headers().get("grpc-status"))
        .and_then(|value| value.to_str().ok())
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
    use openshell_core::GatewayInterceptorConfig;
    use openshell_core::proto::CreateSandboxRequest;
    use openshell_core::proto::gateway_interceptor::v1::{
        DescribeRequest, GatewayInterceptorPhase, InterceptorBinding, InterceptorEvaluation,
        InterceptorManifest, InterceptorResult, InterceptorSelector, ProviderProfileSnapshot,
        ProviderProfileSnapshotRequest,
        gateway_interceptor_server::{GatewayInterceptor, GatewayInterceptorServer},
    };
    use std::convert::Infallible;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio_stream::wrappers::TcpListenerStream;
    use tower::Service;

    #[tokio::test]
    async fn listener_context_service_preserves_listener_scope() {
        let observed = Arc::new(Mutex::new(None));
        let captured = observed.clone();
        let inner = hyper::service::service_fn(move |request: Request<Empty<Bytes>>| {
            *captured.lock().unwrap() = request.extensions().get::<GatewayListenerScope>().copied();
            async move { Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new())) }
        });
        let service = GatewayListenerContextService::new(inner, GatewayListenerScope::Primary);
        hyper::service::Service::call(&service, Request::new(Empty::<Bytes>::new()))
            .await
            .unwrap();

        assert_eq!(
            *observed.lock().unwrap(),
            Some(GatewayListenerScope::Primary)
        );
    }

    fn callback_listener_scope() -> GatewayListenerScope {
        GatewayListenerScope::ComputeDriverCallback
    }

    #[test]
    fn callback_listener_allows_sandbox_callback_rpcs() {
        let scope = callback_listener_scope();
        let callback_paths = [
            "/openshell.v1.OpenShell/ConnectSupervisor",
            "/openshell.v1.OpenShell/RelayStream",
            "/openshell.v1.OpenShell/GetSandboxConfig",
            "/openshell.v1.OpenShell/ReportPolicyStatus",
            "/openshell.v1.OpenShell/PushSandboxLogs",
            "/openshell.v1.OpenShell/GetSandboxProviderEnvironment",
            "/openshell.v1.OpenShell/SubmitPolicyAnalysis",
            "/openshell.v1.OpenShell/RefreshSandboxToken",
            "/openshell.inference.v1.Inference/GetInferenceBundle",
        ];

        for path in callback_paths {
            assert!(
                listener_allows_request(Some(&scope), true, path),
                "callback listener should allow {path}"
            );
        }
    }

    #[test]
    fn callback_listener_surface_matches_rpc_auth_metadata() {
        let scope = callback_listener_scope();

        for path in crate::auth::method_authz::all_paths() {
            assert_eq!(
                listener_allows_request(Some(&scope), true, path),
                crate::auth::method_authz::is_sandbox_callable(path),
                "callback listener exposure must follow rpc_auth metadata for {path}"
            );
        }
    }

    #[test]
    fn callback_listener_rejects_non_callback_routes() {
        let scope = callback_listener_scope();
        let rejected_grpc_paths = [
            "/grpc.health.v1.Health/Check",
            "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
            "/openshell.v1.OpenShell/ListSandboxes",
            "/openshell.v1.OpenShell/DeleteSandbox",
            "/openshell.v1.OpenShell/CreateProvider",
            "/openshell.inference.v1.Inference/GetInferenceRoute",
            "/openshell.inference.v1.Inference/SetInferenceRoute",
        ];

        for path in rejected_grpc_paths {
            assert!(
                !listener_allows_request(Some(&scope), true, path),
                "callback listener should reject {path}"
            );
        }
        assert!(!listener_allows_request(Some(&scope), false, "/health"));
        assert!(!listener_allows_request(Some(&scope), false, "/service"));
    }

    #[test]
    fn primary_listener_routing_is_unchanged() {
        let primary = GatewayListenerScope::Primary;
        let paths = [
            "/grpc.health.v1.Health/Check",
            "/openshell.v1.OpenShell/ListSandboxes",
            "/openshell.inference.v1.Inference/GetInferenceRoute",
            "/health",
            "/service",
        ];

        for path in paths {
            assert!(listener_allows_request(Some(&primary), true, path));
            assert!(listener_allows_request(Some(&primary), false, path));
            assert!(listener_allows_request(None, true, path));
            assert!(listener_allows_request(None, false, path));
        }
    }

    #[test]
    fn callback_listener_rejections_use_protocol_appropriate_statuses() {
        let grpc = callback_listener_rejection(true);
        assert_eq!(grpc.status(), StatusCode::OK);
        assert_eq!(grpc.headers().get("grpc-status").unwrap(), "7");

        let http = callback_listener_rejection(false);
        assert_eq!(http.status(), StatusCode::FORBIDDEN);
    }

    #[derive(Clone)]
    struct PostCommitTestInterceptor;

    #[tonic::async_trait]
    impl GatewayInterceptor for PostCommitTestInterceptor {
        async fn describe(
            &self,
            _request: tonic::Request<DescribeRequest>,
        ) -> Result<tonic::Response<InterceptorManifest>, tonic::Status> {
            Ok(tonic::Response::new(InterceptorManifest {
                name: "post-commit-test".to_string(),
                failure_policy: "fail_open".to_string(),
                bindings: vec![InterceptorBinding {
                    id: "audit-create-sandbox".to_string(),
                    selector: Some(InterceptorSelector {
                        rpc: "openshell.v1.OpenShell/CreateSandbox".to_string(),
                        service: String::new(),
                        method: String::new(),
                    }),
                    phases: vec![GatewayInterceptorPhase::PostCommit as i32],
                    failure_policy: "fail_open".to_string(),
                }],
                provider_profiles: false,
                expected_audience: String::new(),
            }))
        }

        async fn evaluate(
            &self,
            _request: tonic::Request<InterceptorEvaluation>,
        ) -> Result<tonic::Response<InterceptorResult>, tonic::Status> {
            Ok(tonic::Response::new(InterceptorResult {
                allowed: true,
                ..InterceptorResult::default()
            }))
        }

        async fn snapshot_provider_profiles(
            &self,
            _request: tonic::Request<ProviderProfileSnapshotRequest>,
        ) -> Result<tonic::Response<ProviderProfileSnapshot>, tonic::Status> {
            Err(tonic::Status::unimplemented("not a profile source"))
        }
    }

    fn grpc_frame(message: &[u8]) -> Bytes {
        let mut frame = Vec::with_capacity(5 + message.len());
        frame.push(0);
        frame.extend_from_slice(&u32::try_from(message.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(message);
        Bytes::from(frame)
    }

    async fn post_commit_test_runtime() -> (GatewayInterceptorRuntime, tokio::task::JoinHandle<()>)
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(GatewayInterceptorServer::new(PostCommitTestInterceptor))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let runtime = openshell_gateway_interceptors::initialize(vec![GatewayInterceptorConfig {
            name: "post-commit-test".to_string(),
            grpc_endpoint: format!("http://{address}"),
            ..GatewayInterceptorConfig::default()
        }])
        .await
        .unwrap()
        .unwrap();
        (runtime, task)
    }

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
        start_http_server_with_middleware_on_listener(GatewayListenerScope::Primary).await
    }

    async fn start_http_server_with_middleware_on_listener(
        listener_scope: GatewayListenerScope,
    ) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let http_service = crate::http::health_router(test_health_store().await);
        let http_service = request_id_middleware!(http_service);

        let service = MultiplexedService::new(http_service.clone(), http_service);
        let service = GatewayListenerContextService::new(service, listener_scope);

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

    async fn http1_request(
        addr: std::net::SocketAddr,
        method: &str,
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
            .method(method)
            .uri(format!("http://{addr}{path}"));
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let req = builder.body(Empty::<Bytes>::new()).unwrap();
        sender.send_request(req).await.unwrap()
    }

    async fn http1_get(
        addr: std::net::SocketAddr,
        path: &str,
        headers: &[(&str, &str)],
    ) -> Response<Incoming> {
        http1_request(addr, "GET", path, headers).await
    }

    #[tokio::test]
    async fn callback_listener_filter_is_applied_before_route_dispatch() {
        let addr = start_http_server_with_middleware_on_listener(callback_listener_scope()).await;

        let health = http1_get(addr, "/healthz", &[]).await;
        assert_eq!(health.status(), StatusCode::FORBIDDEN);

        let admin = http1_request(
            addr,
            "POST",
            "/openshell.v1.OpenShell/ListSandboxes",
            &[("content-type", "application/grpc")],
        )
        .await;
        assert_eq!(admin.status(), StatusCode::OK);
        assert_eq!(admin.headers().get("grpc-status").unwrap(), "7");

        let callback = http1_request(
            addr,
            "POST",
            "/openshell.v1.OpenShell/ConnectSupervisor",
            &[("content-type", "application/grpc")],
        )
        .await;
        assert_ne!(
            callback
                .headers()
                .get("grpc-status")
                .and_then(|value| value.to_str().ok()),
            Some("7")
        );
    }

    #[tokio::test]
    async fn intercepted_grpc_body_collection_rejects_oversized_body() {
        let oversized = Bytes::from(vec![0_u8; MAX_INTERCEPTED_GRPC_BODY_SIZE + 1]);
        let status = collect_intercepted_grpc_body(boxed_body_from_bytes(oversized))
            .await
            .expect_err("oversized body should be rejected");

        assert_eq!(status.code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn update_provider_interception_hydrates_identity_from_trusted_state() {
        let state = crate::grpc::test_support::test_server_state().await;
        let existing = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "provider-id".to_string(),
                name: "managed-provider".to_string(),
                workspace: "default".to_string(),
                ..Default::default()
            }),
            r#type: "agent-tool-gateway".to_string(),
            profile_workspace: "default".to_string(),
            ..Default::default()
        };
        state.store.put_message(&existing).await.unwrap();

        let request = UpdateProviderRequest {
            provider: Some(Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    name: "managed-provider".to_string(),
                    workspace: "default".to_string(),
                    ..Default::default()
                }),
                credentials: std::collections::HashMap::from([(
                    "TOKEN".to_string(),
                    "rotated".to_string(),
                )]),
                ..Default::default()
            }),
            workspace: "default".to_string(),
            ..Default::default()
        };
        let authed = crate::grpc::test_support::authed_request(());
        let principal = authed.extensions().get::<Principal>().unwrap();

        let hydrated = hydrate_update_provider_identity(
            UPDATE_PROVIDER_PATH,
            grpc_frame(&request.encode_to_vec()),
            state.as_ref(),
            Some(principal),
        )
        .await
        .unwrap();
        let hydrated = decode_unary_grpc_message::<UpdateProviderRequest>(&hydrated).unwrap();
        let provider = hydrated.provider.unwrap();

        assert_eq!(provider.r#type, "agent-tool-gateway");
        assert_eq!(provider.profile_workspace, "default");
        assert_eq!(provider.credentials.get("TOKEN").unwrap(), "rotated");
    }

    #[tokio::test]
    async fn intercepted_grpc_response_preserves_body_and_trailers() {
        let bytes = Bytes::from_static(b"committed-response");
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        let response = Response::new(tonic_body_from_bytes_and_trailers(
            bytes.clone(),
            Some(trailers.clone()),
        ));

        let (response, observation) = observe_intercepted_grpc_response(response).await;
        let (observed, observed_trailers) = observation.unwrap();

        assert_eq!(observed, bytes);
        assert_eq!(observed_trailers.as_ref(), Some(&trailers));
        assert_eq!(
            grpc_status_from_response_and_trailers(&response, observed_trailers.as_ref()),
            "0"
        );

        let collected = response.into_body().collect().await.unwrap();
        assert_eq!(collected.trailers(), Some(&trailers));
        assert_eq!(collected.to_bytes(), bytes);
    }

    #[tokio::test]
    async fn intercepted_grpc_response_preserves_body_error() {
        let bytes = Bytes::from_static(b"committed-response-prefix");
        let response = Response::new(tonic_body_from_frames(vec![
            Ok(http_body::Frame::data(bytes.clone())),
            Err(tonic::Status::unavailable("response stream failed")),
        ]));

        let (response, observation) = observe_intercepted_grpc_response(response).await;

        let observation_error = observation.unwrap_err();
        assert!(observation_error.contains("failed to read gRPC response"));
        assert!(observation_error.contains("response stream failed"));
        let mut body = response.into_body();
        let data = body.frame().await.unwrap().unwrap();
        assert_eq!(data.data_ref(), Some(&bytes));
        let status = body.frame().await.unwrap().unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unavailable);
        assert_eq!(status.message(), "response stream failed");
        assert!(body.frame().await.is_none());
    }

    #[tokio::test]
    async fn post_commit_decode_failure_preserves_committed_response() {
        let (runtime, interceptor_task) = post_commit_test_runtime().await;
        let committed = Arc::new(AtomicUsize::new(0));
        let committed_for_service = committed.clone();
        let committed_body = Bytes::from_static(b"malformed committed gRPC response");
        let committed_body_for_service = committed_body.clone();
        let inner = tower::service_fn(move |_request: Request<BoxBody>| {
            let committed = committed_for_service.clone();
            let body = committed_body_for_service.clone();
            async move {
                committed.fetch_add(1, Ordering::SeqCst);
                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", HeaderValue::from_static("0"));
                Ok::<_, Infallible>(Response::new(tonic_body_from_bytes_and_trailers(
                    body,
                    Some(trailers),
                )))
            }
        });
        let mut service = GatewayInterceptorGrpcService::new(inner, Some(runtime), None);
        let request_body = grpc_frame(&CreateSandboxRequest::default().encode_to_vec());
        let request = Request::builder()
            .uri("/openshell.v1.OpenShell/CreateSandbox")
            .body(boxed_body_from_bytes(request_body))
            .unwrap();

        let response = service.ready().await.unwrap().call(request).await.unwrap();

        assert_eq!(committed.load(Ordering::SeqCst), 1);
        let collected = response.into_body().collect().await.unwrap();
        assert_eq!(collected.to_bytes(), committed_body);
        interceptor_task.abort();
    }

    #[test]
    fn grpc_trailer_status_takes_precedence_over_headers() {
        let response = Response::builder()
            .header("grpc-status", "0")
            .body(())
            .unwrap();
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("7"));

        assert_eq!(
            grpc_status_from_response_and_trailers(&response, Some(&trailers)),
            "7"
        );
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
    struct CountingGrpcService {
        calls: Arc<AtomicUsize>,
    }

    impl Service<Request<()>> for CountingGrpcService {
        type Response = Response<tonic::body::Body>;
        type Error = Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Request<()>) -> Self::Future {
            self.calls.fetch_add(1, Ordering::Relaxed);
            std::future::ready(Ok(Response::new(tonic::body::Body::empty())))
        }
    }

    /// Inner service that is never ready, used to prove the rate limiter does
    /// not wait on inner-service backpressure when it is already exhausted.
    /// Counts `call` invocations so tests can assert the limiter never forwards
    /// to an inner service that did not report readiness.
    #[derive(Clone)]
    struct PendingInnerService {
        calls: Arc<AtomicUsize>,
    }

    impl PendingInnerService {
        fn new() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl Service<Request<()>> for PendingInnerService {
        type Response = Response<tonic::body::Body>;
        type Error = Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn call(&mut self, _req: Request<()>) -> Self::Future {
            self.calls.fetch_add(1, Ordering::Relaxed);
            std::future::ready(Ok(Response::new(tonic::body::Body::empty())))
        }
    }

    #[tokio::test]
    async fn grpc_rate_limit_poll_ready_short_circuits_exhausted_limiter() {
        // An exhausted limiter must report ready even when the inner service is
        // pending, so `call` returns RESOURCE_EXHAUSTED instead of waiting on
        // inner backpressure.
        let config = Config::new(None).with_grpc_rate_limit(Some(1), Some(60));
        let limiter = GrpcRateLimiter::from_config(&config).expect("limiter should be enabled");
        // Consume the single token so the limiter is exhausted.
        assert!(limiter.allow());

        let mut exhausted = GrpcRateLimitService::new(PendingInnerService::new(), Some(limiter));
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(
            matches!(exhausted.poll_ready(&mut cx), Poll::Ready(Ok(()))),
            "exhausted limiter should report ready despite a pending inner service",
        );
        let response = exhausted.call(Request::new(())).await.unwrap();
        assert_eq!(grpc_status_from_response(&response), "8");

        // A limiter with capacity must still respect inner backpressure.
        let config = Config::new(None).with_grpc_rate_limit(Some(1), Some(60));
        let limiter = GrpcRateLimiter::from_config(&config);
        let mut with_capacity = GrpcRateLimitService::new(PendingInnerService::new(), limiter);
        assert!(
            with_capacity.poll_ready(&mut cx).is_pending(),
            "limiter with capacity should defer to the pending inner service",
        );
    }

    #[tokio::test]
    async fn grpc_rate_limit_call_rejects_after_poll_ready_short_circuit_despite_window_rollover() {
        // Regression: when `poll_ready` reports synthetic readiness for an
        // exhausted limiter, it does NOT poll the inner service. If the
        // rate-limit window then rolls over before `call`, the request must
        // still be rejected rather than forwarded to an inner service that
        // never reported readiness (a Tower contract violation).
        let config = Config::new(None).with_grpc_rate_limit(Some(1), Some(60));
        let limiter = GrpcRateLimiter::from_config(&config).expect("limiter should be enabled");
        // Exhaust the single token.
        assert!(limiter.allow());

        // Pending inner service: its `poll_ready` never reports ready and its
        // `call` increments a counter. A ready result from the wrapper
        // therefore proves the limiter short-circuited rather than delegating,
        // and `calls == 0` proves the wrapper never forwarded.
        let inner = PendingInnerService::new();
        let calls = inner.calls.clone();
        let mut service = GrpcRateLimitService::new(inner, Some(limiter.clone()));

        // poll_ready short-circuits the exhausted limiter and records synthetic
        // readiness without polling the inner service.
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(
            matches!(service.poll_ready(&mut cx), Poll::Ready(Ok(()))),
            "exhausted limiter should report ready despite a pending inner service",
        );

        // The window rolls over between poll_ready and call: the limiter now
        // has capacity again.
        {
            let mut state = limiter
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.window_started = state
                .window_started
                .checked_sub(Duration::from_secs(61))
                .expect("test window rewind should be valid");
        }

        let response = service.call(Request::new(())).await.unwrap();
        assert_eq!(grpc_status_from_response(&response), "8");
        assert_eq!(
            calls.load(Ordering::Relaxed),
            0,
            "inner service must not be called when poll_ready short-circuited the limiter",
        );
    }

    #[tokio::test]
    async fn grpc_rate_limit_returns_resource_exhausted_after_limit() {
        let config = Config::new(None).with_grpc_rate_limit(Some(1), Some(60));
        let limiter = GrpcRateLimiter::from_config(&config);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut service = GrpcRateLimitService::new(
            CountingGrpcService {
                calls: calls.clone(),
            },
            limiter,
        );

        let first = service
            .ready()
            .await
            .unwrap()
            .call(Request::new(()))
            .await
            .unwrap();
        assert_eq!(grpc_status_from_response(&first), "0");

        let second = service
            .ready()
            .await
            .unwrap()
            .call(Request::new(()))
            .await
            .unwrap();
        assert_eq!(grpc_status_from_response(&second), "8");
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn grpc_rate_limit_disabled_passes_requests_through() {
        let config = Config::new(None).with_grpc_rate_limit(Some(0), Some(60));
        let limiter = GrpcRateLimiter::from_config(&config);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut service = GrpcRateLimitService::new(
            CountingGrpcService {
                calls: calls.clone(),
            },
            limiter,
        );

        for _ in 0..3 {
            let response = service
                .ready()
                .await
                .unwrap()
                .call(Request::new(()))
                .await
                .unwrap();
            assert_eq!(grpc_status_from_response(&response), "0");
        }
        assert_eq!(calls.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn grpc_rate_limit_resets_after_window() {
        let config = Config::new(None).with_grpc_rate_limit(Some(1), Some(60));
        let limiter = GrpcRateLimiter::from_config(&config).expect("limiter should be enabled");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut service = GrpcRateLimitService::new(
            CountingGrpcService {
                calls: calls.clone(),
            },
            Some(limiter.clone()),
        );

        let first = service
            .ready()
            .await
            .unwrap()
            .call(Request::new(()))
            .await
            .unwrap();
        assert_eq!(grpc_status_from_response(&first), "0");

        {
            let mut state = limiter
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.window_started = state
                .window_started
                .checked_sub(Duration::from_secs(61))
                .expect("test window rewind should be valid");
        }

        let second = service
            .ready()
            .await
            .unwrap()
            .call(Request::new(()))
            .await
            .unwrap();
        assert_eq!(grpc_status_from_response(&second), "0");
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn grpc_rate_limit_state_is_shared_across_service_clones() {
        let config = Config::new(None).with_grpc_rate_limit(Some(1), Some(60));
        let limiter = GrpcRateLimiter::from_config(&config);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut first_service = GrpcRateLimitService::new(
            CountingGrpcService {
                calls: calls.clone(),
            },
            limiter.clone(),
        );
        let mut second_service = GrpcRateLimitService::new(
            CountingGrpcService {
                calls: calls.clone(),
            },
            limiter,
        );

        let first = first_service
            .ready()
            .await
            .unwrap()
            .call(Request::new(()))
            .await
            .unwrap();
        assert_eq!(grpc_status_from_response(&first), "0");

        let second = second_service
            .ready()
            .await
            .unwrap()
            .call(Request::new(()))
            .await
            .unwrap();
        assert_eq!(grpc_status_from_response(&second), "8");
        assert_eq!(calls.load(Ordering::Relaxed), 1);
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

        let log_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let writer = TraceBuf(log_buf.clone());

        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_span_events(FmtSpan::CLOSE);

        let subscriber = {
            use tracing_subscriber::layer::SubscriberExt as _;
            tracing_subscriber::registry().with(fmt_layer)
        };
        {
            let _traced = crate::otel_tracing::test_exporter::install_scoped(subscriber);

            let req = Request::builder()
                .uri("/test-path")
                .header("x-request-id", "trace-test-id-12345")
                .body(Empty::<Bytes>::new())
                .unwrap();
            let span = make_request_span(&req);
            drop(span.enter());
            drop(span);
        }

        let output = String::from_utf8(log_buf.lock().unwrap().clone()).unwrap();
        assert!(
            output.contains("trace-test-id-12345"),
            "trace output should contain the request_id recorded in the span, got: {output}"
        );
    }

    /// The `TraceLayer` creates the server span, so no gRPC handler needs
    /// `#[instrument]`. The request ID carries into it so a trace can be
    /// correlated with the gateway's logs.
    #[tokio::test]
    async fn request_span_exports_over_otlp_with_request_id() {
        use crate::otel_tracing::test_exporter;

        let traced = test_exporter::install_traced();
        let req = Request::builder()
            .uri("/openshell.v1.OpenShell/CreateSandbox")
            .header("x-request-id", "otlp-req-id-9876")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let span = make_request_span(&req);
        drop(span.enter());
        drop(span);

        let spans = traced.finished_spans();
        let span = spans
            .iter()
            .find(|s| s.name == "openshell.v1.OpenShell/CreateSandbox")
            .unwrap_or_else(|| {
                panic!(
                    "the per-request span is recorded under its RPC name, got {:?}",
                    spans.iter().map(|s| &s.name).collect::<Vec<_>>()
                )
            });
        assert_eq!(
            test_exporter::attribute(span, "request_id").as_deref(),
            Some("otlp-req-id-9876"),
        );
        assert_eq!(
            test_exporter::attribute(span, "path").as_deref(),
            Some("/openshell.v1.OpenShell/CreateSandbox"),
        );
        assert_eq!(
            span.span_kind,
            opentelemetry::trace::SpanKind::Server,
            "trace UIs lay this out as a served call, not an internal operation"
        );
        test_exporter::assert_is_root(span);
        assert_eq!(
            test_exporter::attribute(span, "rpc.system").as_deref(),
            Some("grpc"),
        );
        assert_eq!(
            test_exporter::attribute(span, "rpc.service").as_deref(),
            Some("openshell.v1.OpenShell"),
        );
        assert_eq!(
            test_exporter::attribute(span, "rpc.method").as_deref(),
            Some("CreateSandbox"),
        );
    }

    #[tokio::test]
    async fn request_span_continues_the_incoming_trace() {
        use crate::otel_tracing::test_exporter;

        let traced = test_exporter::install_traced();
        let req = Request::builder()
            .uri("/openshell.v1.OpenShell/CreateSandbox")
            .header(
                "traceparent",
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            )
            .body(Empty::<Bytes>::new())
            .unwrap();
        let span = make_request_span(&req);
        drop(span.enter());
        drop(span);

        let span = traced.span_with(
            "openshell.v1.OpenShell/CreateSandbox",
            "rpc.method",
            "CreateSandbox",
        );
        assert_eq!(
            span.span_context.trace_id().to_string(),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        assert_eq!(
            span.parent_span_id.to_string(),
            "00f067aa0ba902b7",
            "the server span is a child of the caller's span"
        );
    }

    /// A failed request must be distinguishable from a successful one in a
    /// trace UI, which keys off span status rather than a logged field.
    #[tokio::test]
    async fn request_spans_record_the_response_outcome() {
        use crate::otel_tracing::test_exporter;

        let traced = test_exporter::install_traced();
        for (path, status) in [
            ("/openshell.v1.OpenShell/CreateSandbox", 500),
            ("/openshell.v1.OpenShell/ListSandboxes", 200),
        ] {
            let req = Request::builder()
                .uri(path)
                .body(Empty::<Bytes>::new())
                .unwrap();
            let span = make_request_span(&req);
            let res = Response::builder()
                .status(status)
                .body(Empty::<Bytes>::new())
                .unwrap();
            let entered = span.enter();
            log_response(&res, Duration::from_millis(3), &span);
            drop(entered);
            drop(span);
        }

        let spans = traced.finished_spans();
        let failed = spans
            .iter()
            .find(|s| s.name == "openshell.v1.OpenShell/CreateSandbox")
            .expect("failed request span recorded");
        let succeeded = spans
            .iter()
            .find(|s| s.name == "openshell.v1.OpenShell/ListSandboxes")
            .expect("successful request span recorded");

        assert_eq!(
            test_exporter::attribute(failed, "http.response.status_code").as_deref(),
            Some("500"),
            "the response status is an attribute, not only a log field"
        );
        assert!(
            matches!(failed.status, opentelemetry::trace::Status::Error { .. }),
            "the span carries error status so trace UIs flag it, got {:?}",
            failed.status
        );
        assert!(
            !matches!(succeeded.status, opentelemetry::trace::Status::Error { .. }),
            "got {:?}",
            succeeded.status
        );
    }

    #[tokio::test]
    async fn request_span_records_grpc_status_from_trailers() {
        use crate::otel_tracing::test_exporter;

        let traced = test_exporter::install_traced();
        let req = Request::builder()
            .uri("/openshell.v1.OpenShell/CreateSandbox")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let span = make_request_span(&req);
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("13"));
        record_response_trailers(Some(&trailers), Duration::from_millis(3), &span);
        drop(span);

        let span = traced.span_with(
            "openshell.v1.OpenShell/CreateSandbox",
            "rpc.method",
            "CreateSandbox",
        );
        assert_eq!(
            test_exporter::attribute(&span, "rpc.grpc.status_code").as_deref(),
            Some("13")
        );
        assert!(
            matches!(span.status, opentelemetry::trace::Status::Error { .. }),
            "a non-OK gRPC trailer marks the span as failed"
        );
    }

    /// Without upstream trace context, each inbound entrypoint roots a trace
    /// named for its RPC or HTTP method.
    #[tokio::test]
    async fn each_entrypoint_gets_its_own_root_span() {
        use crate::otel_tracing::test_exporter;

        let paths = [
            "/openshell.v1.OpenShell/CreateSandbox",
            "/openshell.v1.OpenShell/ListSandboxes",
            "/openshell.v1.OpenShell/DeleteSandbox",
            "/openshell.inference.v1.Inference/GetInferenceBundle",
            "/metrics",
        ];

        let traced = test_exporter::install_traced();
        for path in paths {
            let req = Request::builder()
                .uri(path)
                .body(Empty::<Bytes>::new())
                .unwrap();
            let span = make_request_span(&req);
            drop(span.enter());
            drop(span);
        }

        let names: std::collections::BTreeSet<String> = traced
            .finished_spans()
            .iter()
            .map(|s| s.name.to_string())
            .collect();

        let expected = [
            "GET",
            "openshell.inference.v1.Inference/GetInferenceBundle",
            "openshell.v1.OpenShell/CreateSandbox",
            "openshell.v1.OpenShell/DeleteSandbox",
            "openshell.v1.OpenShell/ListSandboxes",
        ]
        .into_iter()
        .map(String::from)
        .collect::<std::collections::BTreeSet<_>>();

        assert!(
            expected.is_subset(&names),
            "each entrypoint exports under its own name, got {names:?}"
        );
        assert!(
            !names.contains("request"),
            "no entrypoint falls back to the generic callsite name, got {names:?}"
        );
    }

    /// gRPC spans are named for the RPC, per the OpenTelemetry RPC semantic
    /// conventions (`$service/$method`).
    #[test]
    fn grpc_request_spans_are_named_for_the_rpc() {
        assert_eq!(
            otel_span_name(&http::Method::POST, "/openshell.v1.OpenShell/CreateSandbox"),
            "openshell.v1.OpenShell/CreateSandbox"
        );
        assert_eq!(
            otel_span_name(
                &http::Method::POST,
                "/openshell.inference.v1.Inference/GetInferenceBundle"
            ),
            "openshell.inference.v1.Inference/GetInferenceBundle"
        );
    }

    /// Non-RPC paths use a low-cardinality method-only name because sandbox
    /// application routes are opaque to the gateway.
    #[test]
    fn http_request_spans_do_not_include_the_literal_path() {
        assert_eq!(otel_span_name(&http::Method::GET, "/users/12345"), "GET");
        assert_eq!(otel_span_name(&http::Method::GET, "/users/67890"), "GET");
    }

    /// A path with no service segment must not produce a span named after a
    /// stray slash or an empty string.
    #[test]
    fn bare_paths_fall_back_to_the_http_shape() {
        assert_eq!(otel_span_name(&http::Method::GET, "/"), "GET");
        assert_eq!(otel_span_name(&http::Method::POST, "/Foo"), "POST");
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
            type Response = Response<tonic::body::Body>;
            type Error = Infallible;
            type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, req: Request<B>) -> Self::Future {
                let principal = req.extensions().get::<Principal>().cloned();
                *self.recorded.lock().unwrap() = principal;
                Box::pin(async move { Ok(Response::new(tonic::body::Body::empty())) })
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

        fn provider_writer_principal() -> Principal {
            Principal::User(UserPrincipal {
                identity: Identity {
                    subject: "provider-rotation-job".to_string(),
                    display_name: None,
                    roles: vec!["openshell-admin".to_string()],
                    scopes: vec!["provider:write".to_string()],
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
        async fn provider_write_scope_allows_update_without_provider_read() {
            let policy = AuthzPolicy {
                admin_role: "openshell-admin".to_string(),
                user_role: "openshell-user".to_string(),
                scopes_enabled: true,
            };

            let mock = Arc::new(MockAuthenticator::returning(Ok(Some(
                provider_writer_principal(),
            ))));
            let chain = AuthenticatorChain::new(vec![mock]);
            let (recorder, seen) = PrincipalRecorder::new();
            let mut router = AuthGrpcRouter::new(recorder, Some(chain), Some(policy.clone()));
            let response = router
                .call(empty_request(UPDATE_PROVIDER_PATH))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert!(seen.lock().unwrap().is_some());

            let mock = Arc::new(MockAuthenticator::returning(Ok(Some(
                provider_writer_principal(),
            ))));
            let chain = AuthenticatorChain::new(vec![mock]);
            let (recorder, seen) = PrincipalRecorder::new();
            let mut router = AuthGrpcRouter::new(recorder, Some(chain), Some(policy));
            let response = router
                .call(empty_request("/openshell.v1.OpenShell/GetProvider"))
                .await
                .unwrap();
            assert_eq!(grpc_status(&response).as_deref(), Some("7"));
            assert!(seen.lock().unwrap().is_none());
        }

        #[tokio::test]
        async fn sandbox_principal_is_denied_on_user_and_admin_methods() {
            for path in [
                "/openshell.v1.OpenShell/ListSandboxes",
                "/openshell.v1.OpenShell/DeleteSandbox",
                "/openshell.v1.OpenShell/CreateProvider",
                "/openshell.v1.OpenShell/ApproveDraftChunk",
                "/openshell.inference.v1.Inference/GetInferenceRoute",
                "/openshell.inference.v1.Inference/SetInferenceRoute",
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
