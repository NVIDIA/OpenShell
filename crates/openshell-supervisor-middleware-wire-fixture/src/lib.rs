// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor middleware gRPC fixture built from the released v0.1.2 schema.
//!
//! `proto/v0.1.2/` holds byte-for-byte copies of `proto/supervisor_middleware.proto`
//! and `proto/extension.proto` at tag `v0.1.2`. The code generated from those
//! copies speaks exactly the wire contract that 0.1.x middleware services were
//! built against. Compatibility suites drive the current supervisor against
//! this fixture, so they fail when an in-tree legacy message, field number,
//! enum value, service, or RPC path drifts from the released contract.
//!
//! [`LegacyMiddlewareFixture`] describes one service: its manifest, one script
//! per RPC, and whether the response service is served at all.
//! [`LegacyMiddlewareFixture::spawn`] serves it on a loopback port and returns
//! a [`RunningFixture`] that exposes the endpoint, everything the service
//! received, and runtime switches for injected failures:
//!
//! - [`Reply::Fail`] and [`Reply::Delay`] script per-call errors and timeouts.
//! - [`RunningFixture::set_unimplemented`] answers `UNIMPLEMENTED` for an RPC
//!   after `Describe` has already advertised its binding, which is what a
//!   supervisor sees when a service is swapped for a build without that RPC.
//! - [`RunningFixture::hold_http_requests`] parks unary evaluations until
//!   released, so tests can hold middleware work capacity.
//!
//! `Describe` performs the same extension negotiation as the v0.1.2 content
//! guard example: it rejects a caller without protocol metadata and checks
//! both sides' required capabilities.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};

pub mod results;

/// Generated v0.1.2 protobuf types and gRPC services.
pub mod proto {
    #[allow(
        clippy::all,
        clippy::pedantic,
        clippy::nursery,
        dead_code,
        unused_imports,
        unused_qualifications,
        rust_2018_idioms
    )]
    mod generated {
        include!(concat!(env!("OUT_DIR"), "/v0_1_2.rs"));
    }

    pub use generated::openshell::extension::v1 as extension;
    pub use generated::openshell::middleware::v1 as middleware;
}

use proto::extension::{PeerMetadata, ProtocolVersion};
use proto::middleware::http_response_pre_return_server::{
    HttpResponsePreReturn, HttpResponsePreReturnServer,
};
use proto::middleware::supervisor_middleware_server::{
    SupervisorMiddleware, SupervisorMiddlewareServer,
};
use proto::middleware::{
    HttpRequestEvaluation, HttpRequestResult, HttpResponseBodyResult, HttpResponseBodyUnit,
    HttpResponseEvent, HttpResponseEventResult, HttpResponsePreflight, HttpResponsePreflightResult,
    HttpResponseTrailers, HttpResponseTrailersResult, MiddlewareBinding, MiddlewareDescribeRequest,
    MiddlewareManifest, MiddlewareSessionEndReason, SupervisorMiddlewareOperation,
    SupervisorMiddlewarePhase, ValidateConfigRequest, ValidateConfigResponse, WebSocketMessage,
    WebSocketMessageResult, WebSocketPreflight, WebSocketPreflightDecision, WebSocketSessionEvent,
    WebSocketSessionEventResult, http_response_event, http_response_event_result,
    web_socket_session_event, web_socket_session_event_result,
};

/// Protocol major version advertised by v0.1.2 extensions.
pub const PROTOCOL_MAJOR: u32 = 1;
/// Protocol minor version advertised by v0.1.2 extensions.
pub const PROTOCOL_MINOR: u32 = 0;
/// Contract capability every v0.1.2 supervisor middleware peer requires.
pub const CONTRACT_CAPABILITY: &str = "openshell.supervisor-middleware.contract";
/// Implementation version reported in the fixture's extension metadata.
pub const IMPLEMENTATION_VERSION: &str = "0.1.2";

type ResultStream<T> = std::pin::Pin<Box<dyn Stream<Item = Result<T, Status>> + Send + 'static>>;

/// How a scripted RPC answers one input.
#[derive(Debug, Clone)]
pub enum Reply<T> {
    /// Answer with this message.
    Respond(T),
    /// Fail the unary call, or end the stream, with this status.
    Fail(Status),
    /// Wait, then apply the inner reply.
    Delay(Duration, Box<Self>),
}

impl<T> Reply<T> {
    /// Apply this reply only after `delay`.
    #[must_use]
    pub fn after(self, delay: Duration) -> Self {
        Self::Delay(delay, Box::new(self))
    }

    fn map<U>(self, map: impl FnOnce(T) -> U) -> Reply<U> {
        match self {
            Self::Respond(value) => Reply::Respond(map(value)),
            Self::Fail(status) => Reply::Fail(status),
            Self::Delay(delay, inner) => Reply::Delay(delay, Box::new(inner.map(map))),
        }
    }

    async fn resolve(self) -> Result<T, Status> {
        let mut reply = self;
        loop {
            match reply {
                Self::Respond(value) => return Ok(value),
                Self::Fail(status) => return Err(status),
                Self::Delay(delay, inner) => {
                    tokio::time::sleep(delay).await;
                    reply = *inner;
                }
            }
        }
    }
}

impl<T> From<T> for Reply<T> {
    fn from(value: T) -> Self {
        Self::Respond(value)
    }
}

/// Script for unary `EvaluateHttpRequest` calls.
pub type RequestScript =
    Arc<dyn Fn(&HttpRequestEvaluation) -> Reply<HttpRequestResult> + Send + Sync>;
/// Script for the preflight event of an `HttpResponsePreReturn.Evaluate` stream.
pub type ResponsePreflightScript =
    Arc<dyn Fn(&HttpResponsePreflight) -> Reply<HttpResponsePreflightResult> + Send + Sync>;
/// Script for each body unit of an `HttpResponsePreReturn.Evaluate` stream.
pub type ResponseBodyScript =
    Arc<dyn Fn(&HttpResponseBodyUnit) -> Reply<HttpResponseBodyResult> + Send + Sync>;
/// Script for the trailers event of an `HttpResponsePreReturn.Evaluate` stream.
pub type ResponseTrailersScript =
    Arc<dyn Fn(&HttpResponseTrailers) -> Reply<HttpResponseTrailersResult> + Send + Sync>;
/// Script for the preflight event of an `EvaluateWebSocketSession` stream.
pub type WebSocketPreflightScript =
    Arc<dyn Fn(&WebSocketPreflight) -> Reply<WebSocketPreflightDecision> + Send + Sync>;
/// Script for each message event of an `EvaluateWebSocketSession` stream.
pub type WebSocketMessageScript =
    Arc<dyn Fn(&WebSocketMessage) -> Reply<WebSocketMessageResult> + Send + Sync>;
/// Script for `ValidateConfig` calls.
pub type ValidateConfigScript =
    Arc<dyn Fn(&ValidateConfigRequest) -> ValidateConfigResponse + Send + Sync>;

/// Legacy RPCs that can be switched to `UNIMPLEMENTED` at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyRpc {
    /// `SupervisorMiddleware.EvaluateHttpRequest`.
    EvaluateHttpRequest,
    /// `HttpResponsePreReturn.Evaluate`.
    HttpResponsePreReturn,
    /// `SupervisorMiddleware.EvaluateWebSocketSession`.
    EvaluateWebSocketSession,
}

impl LegacyRpc {
    const fn index(self) -> usize {
        match self {
            Self::EvaluateHttpRequest => 0,
            Self::HttpResponsePreReturn => 1,
            Self::EvaluateWebSocketSession => 2,
        }
    }
}

/// Build one manifest binding.
#[must_use]
pub fn binding(
    operation: SupervisorMiddlewareOperation,
    phase: SupervisorMiddlewarePhase,
    max_payload_bytes: u64,
) -> MiddlewareBinding {
    MiddlewareBinding {
        operation: operation as i32,
        phase: phase as i32,
        max_payload_bytes,
        request_timeout: None,
    }
}

/// `HTTP_REQUEST/PRE_CREDENTIALS` binding.
#[must_use]
pub fn http_request_binding(max_payload_bytes: u64) -> MiddlewareBinding {
    binding(
        SupervisorMiddlewareOperation::HttpRequest,
        SupervisorMiddlewarePhase::PreCredentials,
        max_payload_bytes,
    )
}

/// `HTTP_RESPONSE/PRE_RETURN` binding.
#[must_use]
pub fn http_response_binding(max_payload_bytes: u64) -> MiddlewareBinding {
    binding(
        SupervisorMiddlewareOperation::HttpResponse,
        SupervisorMiddlewarePhase::PreReturn,
        max_payload_bytes,
    )
}

/// `WEBSOCKET_MESSAGE/PRE_CREDENTIALS` binding.
#[must_use]
pub fn websocket_binding(max_payload_bytes: u64) -> MiddlewareBinding {
    binding(
        SupervisorMiddlewareOperation::WebsocketMessage,
        SupervisorMiddlewarePhase::PreCredentials,
        max_payload_bytes,
    )
}

/// Extension metadata a v0.1.2 middleware advertises, plus extra requirements.
#[must_use]
pub fn extension_metadata(
    implementation_name: &str,
    extra_required_capabilities: &[String],
) -> PeerMetadata {
    let mut required_capabilities = vec![CONTRACT_CAPABILITY.to_string()];
    required_capabilities.extend(extra_required_capabilities.iter().cloned());
    PeerMetadata {
        protocol_version: Some(ProtocolVersion {
            major: PROTOCOL_MAJOR,
            minor: PROTOCOL_MINOR,
        }),
        implementation_name: implementation_name.to_string(),
        implementation_version: IMPLEMENTATION_VERSION.to_string(),
        supported_capabilities: vec![CONTRACT_CAPABILITY.to_string()],
        required_capabilities,
    }
}

/// Configuration for one v0.1.2 middleware service.
///
/// Defaults: no bindings, extension metadata present, requests allowed
/// unchanged, response preflight skipped, response units and trailers passed
/// through, WebSocket sessions inspected and messages allowed, every config
/// valid.
#[derive(Clone)]
pub struct LegacyMiddlewareFixture {
    manifest_name: String,
    bindings: Vec<MiddlewareBinding>,
    extension: Option<PeerMetadata>,
    serve_response_service: bool,
    scripts: Scripts,
}

#[derive(Clone)]
struct Scripts {
    request: RequestScript,
    response_preflight: ResponsePreflightScript,
    response_body: ResponseBodyScript,
    response_trailers: ResponseTrailersScript,
    websocket_preflight: WebSocketPreflightScript,
    websocket_message: WebSocketMessageScript,
    validate_config: ValidateConfigScript,
}

impl LegacyMiddlewareFixture {
    /// Start a fixture whose manifest uses `manifest_name`.
    #[must_use]
    pub fn new(manifest_name: &str) -> Self {
        Self {
            manifest_name: manifest_name.to_string(),
            bindings: Vec::new(),
            extension: Some(extension_metadata(manifest_name, &[])),
            serve_response_service: true,
            scripts: Scripts {
                request: Arc::new(|_| results::allow().into()),
                response_preflight: Arc::new(|_| results::preflight_skip().into()),
                response_body: Arc::new(|unit| results::body_pass_through(unit.sequence).into()),
                response_trailers: Arc::new(|_| results::trailers_unchanged().into()),
                websocket_preflight: Arc::new(|_| results::websocket_inspect().into()),
                websocket_message: Arc::new(|message| {
                    results::message_allow(message.sequence).into()
                }),
                validate_config: Arc::new(|_| ValidateConfigResponse {
                    valid: true,
                    reason: String::new(),
                }),
            },
        }
    }

    /// Advertise one more binding.
    #[must_use]
    pub fn with_binding(mut self, binding: MiddlewareBinding) -> Self {
        self.bindings.push(binding);
        self
    }

    /// Require an extra capability from the caller during `Describe`.
    #[must_use]
    pub fn requiring_capability(mut self, capability: &str) -> Self {
        if let Some(extension) = self.extension.as_mut() {
            extension.required_capabilities.push(capability.to_string());
        }
        self
    }

    /// Omit extension metadata, as services built before negotiation did.
    #[must_use]
    pub fn without_extension_metadata(mut self) -> Self {
        self.extension = None;
        self
    }

    /// Do not register `HttpResponsePreReturn` with the gRPC router, so every
    /// call to it fails with the router's `UNIMPLEMENTED`.
    #[must_use]
    pub fn without_response_service(mut self) -> Self {
        self.serve_response_service = false;
        self
    }

    /// Script `EvaluateHttpRequest`.
    #[must_use]
    pub fn on_http_request(
        mut self,
        script: impl Fn(&HttpRequestEvaluation) -> Reply<HttpRequestResult> + Send + Sync + 'static,
    ) -> Self {
        self.scripts.request = Arc::new(script);
        self
    }

    /// Script the response preflight event.
    #[must_use]
    pub fn on_response_preflight(
        mut self,
        script: impl Fn(&HttpResponsePreflight) -> Reply<HttpResponsePreflightResult>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.scripts.response_preflight = Arc::new(script);
        self
    }

    /// Script each response body unit.
    #[must_use]
    pub fn on_response_body(
        mut self,
        script: impl Fn(&HttpResponseBodyUnit) -> Reply<HttpResponseBodyResult> + Send + Sync + 'static,
    ) -> Self {
        self.scripts.response_body = Arc::new(script);
        self
    }

    /// Script the response trailers event.
    #[must_use]
    pub fn on_response_trailers(
        mut self,
        script: impl Fn(&HttpResponseTrailers) -> Reply<HttpResponseTrailersResult>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.scripts.response_trailers = Arc::new(script);
        self
    }

    /// Script the WebSocket preflight event.
    #[must_use]
    pub fn on_websocket_preflight(
        mut self,
        script: impl Fn(&WebSocketPreflight) -> Reply<WebSocketPreflightDecision>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.scripts.websocket_preflight = Arc::new(script);
        self
    }

    /// Script each WebSocket message event.
    #[must_use]
    pub fn on_websocket_message(
        mut self,
        script: impl Fn(&WebSocketMessage) -> Reply<WebSocketMessageResult> + Send + Sync + 'static,
    ) -> Self {
        self.scripts.websocket_message = Arc::new(script);
        self
    }

    /// Script `ValidateConfig`.
    #[must_use]
    pub fn on_validate_config(
        mut self,
        script: impl Fn(&ValidateConfigRequest) -> ValidateConfigResponse + Send + Sync + 'static,
    ) -> Self {
        self.scripts.validate_config = Arc::new(script);
        self
    }

    /// Serve this fixture on an ephemeral loopback port.
    pub async fn spawn(self) -> std::io::Result<RunningFixture> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (hold_tx, hold_rx) = watch::channel(false);
        let state = Arc::new(FixtureState {
            manifest_name: self.manifest_name,
            bindings: RwLock::new(self.bindings),
            extension: self.extension,
            unimplemented: [
                AtomicBool::new(false),
                AtomicBool::new(false),
                AtomicBool::new(false),
            ],
            hold_tx,
            hold_rx,
            held_http_requests: AtomicUsize::new(0),
            record: Mutex::new(Record::default()),
        });
        let service = FixtureService {
            state: Arc::clone(&state),
            scripts: Arc::new(self.scripts),
        };
        let response_service = self
            .serve_response_service
            .then(|| HttpResponsePreReturnServer::new(service.clone()));
        let router = tonic::transport::Server::builder()
            .add_service(SupervisorMiddlewareServer::new(service))
            .add_optional_service(response_service);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _ = router
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                    let _ = shutdown_rx.await;
                })
                .await;
        });
        Ok(RunningFixture {
            address,
            state,
            shutdown_tx: Some(shutdown_tx),
            task,
        })
    }
}

#[derive(Default)]
struct Record {
    describe: Vec<MiddlewareDescribeRequest>,
    validate_config: Vec<ValidateConfigRequest>,
    http_requests: Vec<HttpRequestEvaluation>,
    response_sessions: Vec<Vec<HttpResponseEvent>>,
    websocket_sessions: Vec<Vec<WebSocketSessionEvent>>,
}

struct FixtureState {
    manifest_name: String,
    bindings: RwLock<Vec<MiddlewareBinding>>,
    extension: Option<PeerMetadata>,
    unimplemented: [AtomicBool; 3],
    hold_tx: watch::Sender<bool>,
    hold_rx: watch::Receiver<bool>,
    held_http_requests: AtomicUsize,
    record: Mutex<Record>,
}

impl FixtureState {
    fn record(&self) -> std::sync::MutexGuard<'_, Record> {
        self.record.lock().expect("fixture record lock")
    }

    fn check_implemented(&self, rpc: LegacyRpc) -> Result<(), Status> {
        if self.unimplemented[rpc.index()].load(Ordering::Acquire) {
            Err(Status::unimplemented(format!(
                "{rpc:?} is not implemented by this middleware build"
            )))
        } else {
            Ok(())
        }
    }

    fn manifest(&self) -> MiddlewareManifest {
        MiddlewareManifest {
            name: self.manifest_name.clone(),
            service_version: IMPLEMENTATION_VERSION.to_string(),
            bindings: self.bindings.read().expect("fixture bindings lock").clone(),
            expected_audience: String::new(),
            extension: self.extension.clone(),
        }
    }

    async fn wait_while_held(&self) {
        let mut hold = self.hold_rx.clone();
        if !*hold.borrow_and_update() {
            return;
        }
        // A cancelled call must not stay counted as held.
        let _held = HeldCall::enter(&self.held_http_requests);
        let _ = hold.wait_for(|held| !held).await;
    }
}

struct HeldCall<'a>(&'a AtomicUsize);

impl<'a> HeldCall<'a> {
    fn enter(count: &'a AtomicUsize) -> Self {
        count.fetch_add(1, Ordering::AcqRel);
        Self(count)
    }
}

impl Drop for HeldCall<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Record every inbound stream event as it arrives and hand it to the
/// responder in order. Recording continues while a scripted reply is delayed
/// and after the responder has failed, so tests see every event the caller sent.
fn spawn_recorder<E>(
    mut events: Streaming<E>,
    mut record: impl FnMut(E) + Send + 'static,
) -> mpsc::UnboundedReceiver<E>
where
    E: Clone + Send + 'static,
    Streaming<E>: Stream<Item = Result<E, Status>> + Send,
{
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(Ok(event)) = events.next().await {
            record(event.clone());
            let _ = events_tx.send(event);
        }
    });
    events_rx
}

/// A served fixture. Dropping it stops the server.
pub struct RunningFixture {
    address: SocketAddr,
    state: Arc<FixtureState>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl RunningFixture {
    /// Socket address the fixture listens on.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Plaintext gRPC endpoint for an operator registration.
    #[must_use]
    pub fn endpoint(&self) -> String {
        format!("http://{}", self.address)
    }

    /// Replace the advertised bindings for later `Describe` calls.
    pub fn replace_bindings(&self, bindings: Vec<MiddlewareBinding>) {
        *self.state.bindings.write().expect("fixture bindings lock") = bindings;
    }

    /// Answer `UNIMPLEMENTED` for `rpc` while `enabled` is true.
    pub fn set_unimplemented(&self, rpc: LegacyRpc, enabled: bool) {
        self.state.unimplemented[rpc.index()].store(enabled, Ordering::Release);
    }

    /// Park later `EvaluateHttpRequest` calls until [`Self::release_http_requests`].
    pub fn hold_http_requests(&self) {
        self.state.hold_tx.send_replace(true);
    }

    /// Release every parked `EvaluateHttpRequest` call.
    pub fn release_http_requests(&self) {
        self.state.hold_tx.send_replace(false);
    }

    /// Number of `EvaluateHttpRequest` calls currently parked.
    #[must_use]
    pub fn held_http_requests(&self) -> usize {
        self.state.held_http_requests.load(Ordering::Acquire)
    }

    /// `Describe` requests received, in order.
    #[must_use]
    pub fn describe_requests(&self) -> Vec<MiddlewareDescribeRequest> {
        self.state.record().describe.clone()
    }

    /// `ValidateConfig` requests received, in order.
    #[must_use]
    pub fn validate_config_requests(&self) -> Vec<ValidateConfigRequest> {
        self.state.record().validate_config.clone()
    }

    /// `EvaluateHttpRequest` requests received, in order.
    #[must_use]
    pub fn http_requests(&self) -> Vec<HttpRequestEvaluation> {
        self.state.record().http_requests.clone()
    }

    /// Events of each `HttpResponsePreReturn.Evaluate` stream, in arrival order.
    #[must_use]
    pub fn response_sessions(&self) -> Vec<Vec<HttpResponseEvent>> {
        self.state.record().response_sessions.clone()
    }

    /// Events of each `EvaluateWebSocketSession` stream, in arrival order.
    #[must_use]
    pub fn websocket_sessions(&self) -> Vec<Vec<WebSocketSessionEvent>> {
        self.state.record().websocket_sessions.clone()
    }

    /// The `session_end` reason recorded for response stream `index`, if any.
    #[must_use]
    pub fn response_session_end(&self, index: usize) -> Option<MiddlewareSessionEndReason> {
        self.state
            .record()
            .response_sessions
            .get(index)?
            .iter()
            .find_map(|event| match &event.event {
                Some(http_response_event::Event::SessionEnd(end)) => {
                    MiddlewareSessionEndReason::try_from(end.reason).ok()
                }
                _ => None,
            })
    }

    /// Poll `probe` until it returns `Some`, or give up after `timeout`.
    pub async fn wait_for<T>(
        &self,
        timeout: Duration,
        mut probe: impl FnMut(&Self) -> Option<T>,
    ) -> Option<T> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(value) = probe(self) {
                return Some(value);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Stop serving and wait for the server task to exit.
    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown_tx.take() {
            let _ = shutdown.send(());
        }
        self.state.hold_tx.send_replace(false);
        let _ = tokio::time::timeout(Duration::from_secs(1), &mut self.task).await;
        self.task.abort();
    }
}

impl Drop for RunningFixture {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown_tx.take() {
            let _ = shutdown.send(());
        }
        self.state.hold_tx.send_replace(false);
        self.task.abort();
    }
}

#[derive(Clone)]
struct FixtureService {
    state: Arc<FixtureState>,
    scripts: Arc<Scripts>,
}

impl FixtureService {
    fn validate_gateway(&self, gateway: Option<PeerMetadata>) -> Result<(), Status> {
        let Some(extension) = self.state.extension.as_ref() else {
            return Ok(());
        };
        let gateway = gateway.ok_or_else(|| {
            Status::failed_precondition(format!(
                "gateway did not provide protocol metadata to supervisor-middleware extension '{}'; upgrade the gateway and extension together",
                self.state.manifest_name
            ))
        })?;
        let gateway_major = gateway
            .protocol_version
            .as_ref()
            .map(|version| version.major)
            .ok_or_else(|| {
                Status::failed_precondition("gateway did not provide a protocol version")
            })?;
        if gateway_major != PROTOCOL_MAJOR {
            return Err(Status::failed_precondition(format!(
                "gateway uses unsupported protocol major {gateway_major}"
            )));
        }
        let missing = |required: &[String], supported: &[String]| {
            let supported: BTreeSet<&str> = supported.iter().map(String::as_str).collect();
            required
                .iter()
                .filter(|capability| !supported.contains(capability.as_str()))
                .cloned()
                .collect::<Vec<_>>()
        };
        let missing_extension = missing(
            &gateway.required_capabilities,
            &extension.supported_capabilities,
        );
        if !missing_extension.is_empty() {
            return Err(Status::failed_precondition(format!(
                "supervisor-middleware extension '{}' is missing required capabilities: {}",
                self.state.manifest_name,
                missing_extension.join(", ")
            )));
        }
        let missing_gateway = missing(
            &extension.required_capabilities,
            &gateway.supported_capabilities,
        );
        if !missing_gateway.is_empty() {
            return Err(Status::failed_precondition(format!(
                "gateway is missing capabilities required by supervisor-middleware extension '{}': {}",
                self.state.manifest_name,
                missing_gateway.join(", ")
            )));
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl SupervisorMiddleware for FixtureService {
    type EvaluateWebSocketSessionStream = ResultStream<WebSocketSessionEventResult>;

    async fn describe(
        &self,
        request: Request<MiddlewareDescribeRequest>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        let request = request.into_inner();
        self.state.record().describe.push(request.clone());
        self.validate_gateway(request.gateway)?;
        Ok(Response::new(self.state.manifest()))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        let request = request.into_inner();
        self.state.record().validate_config.push(request.clone());
        Ok(Response::new((self.scripts.validate_config)(&request)))
    }

    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        self.state
            .check_implemented(LegacyRpc::EvaluateHttpRequest)?;
        let request = request.into_inner();
        self.state.record().http_requests.push(request.clone());
        self.state.wait_while_held().await;
        (self.scripts.request)(&request)
            .resolve()
            .await
            .map(Response::new)
    }

    async fn evaluate_web_socket_session(
        &self,
        request: Request<Streaming<WebSocketSessionEvent>>,
    ) -> Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
        self.state
            .check_implemented(LegacyRpc::EvaluateWebSocketSession)?;
        let session = {
            let mut record = self.state.record();
            record.websocket_sessions.push(Vec::new());
            record.websocket_sessions.len() - 1
        };
        let state = Arc::clone(&self.state);
        let mut events = spawn_recorder(request.into_inner(), move |event| {
            state.record().websocket_sessions[session].push(event);
        });
        let (results_tx, results_rx) = mpsc::channel(4);
        let scripts = Arc::clone(&self.scripts);
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                let reply = match event.event {
                    Some(web_socket_session_event::Event::Preflight(preflight)) => {
                        (scripts.websocket_preflight)(&preflight)
                            .map(web_socket_session_event_result::Result::PreflightDecision)
                    }
                    Some(web_socket_session_event::Event::Message(message)) => {
                        (scripts.websocket_message)(&message)
                            .map(web_socket_session_event_result::Result::MessageResult)
                    }
                    Some(
                        web_socket_session_event::Event::SessionStart(_)
                        | web_socket_session_event::Event::SessionEnd(_),
                    )
                    | None => continue,
                };
                let result = reply
                    .resolve()
                    .await
                    .map(|result| WebSocketSessionEventResult {
                        result: Some(result),
                    });
                let failed = result.is_err();
                if results_tx.send(result).await.is_err() || failed {
                    break;
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(results_rx))))
    }
}

#[tonic::async_trait]
impl HttpResponsePreReturn for FixtureService {
    type EvaluateStream = ResultStream<HttpResponseEventResult>;

    async fn evaluate(
        &self,
        request: Request<Streaming<HttpResponseEvent>>,
    ) -> Result<Response<Self::EvaluateStream>, Status> {
        self.state
            .check_implemented(LegacyRpc::HttpResponsePreReturn)?;
        let session = {
            let mut record = self.state.record();
            record.response_sessions.push(Vec::new());
            record.response_sessions.len() - 1
        };
        let state = Arc::clone(&self.state);
        let mut events = spawn_recorder(request.into_inner(), move |event| {
            state.record().response_sessions[session].push(event);
        });
        let (results_tx, results_rx) = mpsc::channel(4);
        let scripts = Arc::clone(&self.scripts);
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                let reply = match event.event {
                    Some(http_response_event::Event::Preflight(preflight)) => {
                        (scripts.response_preflight)(&preflight)
                            .map(http_response_event_result::Result::PreflightResult)
                    }
                    Some(http_response_event::Event::Body(unit)) => (scripts.response_body)(&unit)
                        .map(http_response_event_result::Result::BodyResult),
                    Some(http_response_event::Event::Trailers(trailers)) => {
                        (scripts.response_trailers)(&trailers)
                            .map(http_response_event_result::Result::TrailersResult)
                    }
                    Some(http_response_event::Event::SessionEnd(_)) | None => continue,
                };
                let result = reply.resolve().await.map(|result| HttpResponseEventResult {
                    result: Some(result),
                });
                let failed = result.is_err();
                if results_tx.send(result).await.is_err() || failed {
                    break;
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(results_rx))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;

    /// Digests of `git show v0.1.2:proto/<file>`. A vendored copy that no
    /// longer matches the released bytes is not a v0.1.2 fixture.
    const RELEASED_PROTO_SHA256: [(&str, &str); 2] = [
        (
            "supervisor_middleware.proto",
            "bee96ac940303d8a7530e6e2283a98077bb428a05ef610b51d018ea18377bebd",
        ),
        (
            "extension.proto",
            "60f28ee9dc846d41152f4db7e82a439c78d024786efaceb464900d1d1ad129ad",
        ),
    ];

    #[test]
    fn vendored_protos_match_the_v0_1_2_release() {
        for (file, expected) in RELEASED_PROTO_SHA256 {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("proto/v0.1.2")
                .join(file);
            let bytes = std::fs::read(&path).expect("read vendored proto");
            let digest = Sha256::digest(&bytes)
                .iter()
                .fold(String::new(), |mut digest, byte| {
                    let _ = write!(digest, "{byte:02x}");
                    digest
                });
            assert_eq!(digest, expected, "{} differs from v0.1.2", path.display());
        }
    }

    #[tokio::test]
    async fn describe_negotiates_like_a_v0_1_2_service() {
        use proto::middleware::supervisor_middleware_client::SupervisorMiddlewareClient;

        let fixture = LegacyMiddlewareFixture::new("compat/fixture")
            .with_binding(http_request_binding(1024))
            .spawn()
            .await
            .expect("spawn fixture");
        let mut client = SupervisorMiddlewareClient::connect(fixture.endpoint())
            .await
            .expect("connect fixture");

        let missing = client
            .describe(MiddlewareDescribeRequest { gateway: None })
            .await
            .expect_err("Describe without gateway metadata");
        assert_eq!(missing.code(), tonic::Code::FailedPrecondition);

        let gateway = PeerMetadata {
            protocol_version: Some(ProtocolVersion { major: 1, minor: 0 }),
            implementation_name: "openshell/gateway".into(),
            implementation_version: "test".into(),
            supported_capabilities: vec![CONTRACT_CAPABILITY.into()],
            required_capabilities: vec![CONTRACT_CAPABILITY.into()],
        };
        let manifest = client
            .describe(MiddlewareDescribeRequest {
                gateway: Some(gateway.clone()),
            })
            .await
            .expect("Describe with gateway metadata")
            .into_inner();
        assert_eq!(manifest.name, "compat/fixture");
        assert_eq!(manifest.bindings, vec![http_request_binding(1024)]);
        assert_eq!(fixture.describe_requests().len(), 2);

        fixture.set_unimplemented(LegacyRpc::EvaluateHttpRequest, true);
        let unimplemented = client
            .evaluate_http_request(HttpRequestEvaluation::default())
            .await
            .expect_err("switched RPC answers UNIMPLEMENTED");
        assert_eq!(unimplemented.code(), tonic::Code::Unimplemented);

        let strict = LegacyMiddlewareFixture::new("compat/strict")
            .with_binding(http_request_binding(1024))
            .requiring_capability("openshell.supervisor-middleware.http-v2")
            .spawn()
            .await
            .expect("spawn strict fixture");
        let mut strict_client = SupervisorMiddlewareClient::connect(strict.endpoint())
            .await
            .expect("connect strict fixture");
        let refused = strict_client
            .describe(MiddlewareDescribeRequest {
                gateway: Some(gateway),
            })
            .await
            .expect_err("caller without the required capability");
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
        assert!(refused.message().contains("http-v2"));
    }
}
