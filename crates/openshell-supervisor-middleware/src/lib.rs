// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor middleware registration and chain execution.

pub mod headers;
mod remote;
mod request;
mod response;
mod websocket;

pub use request::{
    HttpRequestBodyInput, HttpRequestBodyOutput, HttpRequestDiagnostics, HttpRequestFinish,
    HttpRequestInvocation, HttpRequestInvocationOutcome, HttpRequestMiddlewareFailure,
    HttpRequestPreflightInput, HttpRequestPreflightOutcome, HttpRequestSession,
    MAX_HTTP_REQUEST_DEFERRED_BYTES, MAX_HTTP_REQUEST_STREAM_UNIT_BYTES,
};

pub use response::{
    HttpResponseDiagnostics, HttpResponseFinish, HttpResponseInvocation,
    HttpResponseInvocationOutcome, HttpResponseMiddlewareFailure, HttpResponsePreflightInput,
    HttpResponsePreflightOutcome, HttpResponseSession, MAX_HTTP_RESPONSE_RETAINED_BODY_BYTES,
    MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES, is_stale_http_response_integrity_header,
};

pub use websocket::{
    WebSocketCoverage, WebSocketCoverageState, WebSocketInvocation, WebSocketInvocationOutcome,
    WebSocketMessageAdmission, WebSocketMessageOutcome, WebSocketMessageType,
    WebSocketPreflightInput, WebSocketPreflightResult, WebSocketSession,
    WebSocketSessionStartOutcome,
};

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use miette::{Result, miette};
use prost::Message;

use openshell_core::extension_protocol::{
    ExtensionFamily, NegotiatedExtension, gateway_metadata, negotiate,
};
use openshell_core::proto::{
    Decision, Finding, HeaderMutation, HttpHeader, HttpRequestTarget, MiddlewareBinding,
    MiddlewareDescribeRequest, MiddlewareManifest, NetworkMiddlewareConfig, RequestContext,
    SandboxPolicy, SupervisorMiddlewareOperation, SupervisorMiddlewarePhase,
    SupervisorMiddlewareService, ValidateConfigRequest, ValidateConfigResponse,
};
use tokio::sync::{OnceCell, OwnedSemaphorePermit, Semaphore};
use tonic::Request;

pub use openshell_core::middleware::{
    HttpResultStream, InProcessMiddleware, SupervisorMiddlewareEndpoint, WebSocketResponseStream,
};
struct EndpointInProcessAdapter {
    endpoint: Arc<dyn SupervisorMiddlewareEndpoint>,
}

#[tonic::async_trait]
impl InProcessMiddleware for EndpointInProcessAdapter {
    async fn describe(&self) -> MiddlewareManifest {
        self.endpoint
            .describe(Request::new(MiddlewareDescribeRequest {
                gateway: Some(gateway_metadata(ExtensionFamily::SupervisorMiddleware)),
            }))
            .await
            .expect("in-process endpoint Describe failed")
            .into_inner()
    }

    async fn validate_config(
        &self,
        middleware_name: &str,
        config: &prost_types::Struct,
    ) -> Result<()> {
        let response = self
            .endpoint
            .validate_config(Request::new(ValidateConfigRequest {
                config: Some(config.clone()),
                middleware_name: middleware_name.to_string(),
            }))
            .await
            .map_err(|error| miette!("{error}"))?
            .into_inner();
        if response.valid {
            Ok(())
        } else {
            Err(miette!("{}", response.reason))
        }
    }

    async fn open_http_request_pre_credentials(
        &self,
        requests: tokio::sync::mpsc::Receiver<openshell_core::proto::HttpEvent>,
    ) -> std::result::Result<HttpResultStream, tonic::Status> {
        self.endpoint
            .open_http_request_pre_credentials(requests)
            .await
    }

    async fn open_websocket_session(
        &self,
        requests: tokio::sync::mpsc::Receiver<openshell_core::proto::WebSocketSessionEvent>,
    ) -> std::result::Result<WebSocketResponseStream, tonic::Status> {
        self.endpoint.open_websocket_session(requests).await
    }

    async fn open_http_response_pre_return(
        &self,
        requests: tokio::sync::mpsc::Receiver<openshell_core::proto::HttpEvent>,
    ) -> std::result::Result<HttpResultStream, tonic::Status> {
        self.endpoint.open_http_response_pre_return(requests).await
    }
}

/// Adapt a transport-neutral endpoint to the in-process registry contract.
///
/// Prefer implementing [`InProcessMiddleware`] directly. This compatibility
/// path preserves the request, response, and WebSocket event streams while
/// adapting configuration calls to the transport-neutral endpoint surface.
pub fn in_process_endpoint(
    endpoint: Arc<dyn SupervisorMiddlewareEndpoint>,
) -> Arc<dyn InProcessMiddleware> {
    Arc::new(EndpointInProcessAdapter { endpoint })
}

/// Maximum short-lived middleware work items allowed to wait for active
/// capacity.
///
/// Waiters do not buffer request or message bodies, so the queue can absorb a
/// larger burst without increasing the active payload-memory bound.
pub const MAX_QUEUED_MIDDLEWARE_WORK: usize = MAX_CONCURRENT_MIDDLEWARE_WORK * 2;

/// One slot in the shared middleware work budget.
///
/// Callers that buffer request or message bodies acquire this guard first and
/// retain it through evaluation, bounding aggregate buffered middleware input.
#[derive(Debug)]
pub struct MiddlewareWorkAdmission {
    _work: OwnedSemaphorePermit,
    saturated: bool,
}

impl MiddlewareWorkAdmission {
    pub fn saturated(&self) -> bool {
        self.saturated
    }
}

/// Result of attempting to enter the bounded middleware work queue.
///
/// Active-capacity saturation is ordinary backpressure: callers that obtain a
/// waiter slot eventually receive [`Self::Admitted`]. [`Self::QueueExhausted`]
/// is immediate load shedding after both active capacity and the waiter queue
/// are full.
#[derive(Debug)]
pub enum MiddlewareWorkAdmissionOutcome {
    Admitted(MiddlewareWorkAdmission),
    QueueExhausted,
}

impl MiddlewareWorkAdmissionOutcome {
    /// Preserve the existing failure behavior for protocols whose outer layer
    /// already translates middleware admission errors into a stable response
    /// or typed termination.
    pub fn into_admission(self) -> Result<MiddlewareWorkAdmission> {
        match self {
            Self::Admitted(admission) => Ok(admission),
            Self::QueueExhausted => Err(miette!(
                "middleware admission queue is full; refusing additional buffered work"
            )),
        }
    }
}

/// One slot in the shared persistent middleware session budget.
///
/// Protocol-specific session runners retain this guard while at least one
/// streaming stage remains active. Registry replacement preserves the shared
/// admission state so HTTP and WebSocket streams use the same process-wide
/// bound across registry replacement.
#[derive(Debug)]
struct MiddlewareSessionPermit {
    _session: OwnedSemaphorePermit,
}

enum MiddlewareSessionAdmission {
    Admitted(MiddlewareSessionPermit),
    AtCapacity,
}

pub use openshell_core::middleware::{
    DEFAULT_MIDDLEWARE_TIMEOUT, MAX_CONCURRENT_MIDDLEWARE_SESSIONS, MAX_CONCURRENT_MIDDLEWARE_WORK,
    MAX_MIDDLEWARE_CHAIN_FINDINGS, MAX_MIDDLEWARE_CHAIN_STAGES, MAX_MIDDLEWARE_CHAIN_TIMEOUT,
    MAX_MIDDLEWARE_CONFIGS, MAX_MIDDLEWARE_FINDINGS_PER_STAGE, MAX_MIDDLEWARE_PREFLIGHT_TIMEOUT,
    MAX_MIDDLEWARE_SELECTOR_PATTERNS, MAX_MIDDLEWARE_TIMEOUT, MIN_MIDDLEWARE_TIMEOUT,
    middleware_timeout_or_default, parse_middleware_timeout,
};

/// Largest logical payload or replacement accepted by the middleware platform.
pub const MAX_MIDDLEWARE_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
/// Largest encoded service-specific configuration attached to one evaluation.
pub const MAX_MIDDLEWARE_CONFIG_BYTES: usize = 64 * 1024;
/// Largest encoded request identity context attached to one evaluation.
pub const MAX_MIDDLEWARE_CONTEXT_BYTES: usize = 4 * 1024;
/// Largest encoded destination and request target attached to one evaluation.
pub const MAX_MIDDLEWARE_TARGET_BYTES: usize = 32 * 1024;
/// Largest number of request header lines exposed to one middleware.
pub const MAX_MIDDLEWARE_HEADERS: usize = 128;
/// Largest encoded request header collection exposed to one middleware.
pub const MAX_MIDDLEWARE_HEADER_BYTES: usize = 64 * 1024;
/// Largest operator-provided reason accepted in one middleware result.
pub const MAX_MIDDLEWARE_REASON_BYTES: usize = 4 * 1024;
/// Largest stable reason code accepted in one middleware result.
pub const MAX_MIDDLEWARE_REASON_CODE_BYTES: usize = 64;
/// Largest encoded individual finding accepted from one middleware stage.
pub const MAX_MIDDLEWARE_FINDING_BYTES: usize = 4 * 1024;
/// Largest number of metadata entries accepted from one middleware stage.
pub const MAX_MIDDLEWARE_METADATA_ENTRIES: usize = 64;
/// Largest combined metadata key/value payload accepted from one middleware stage.
pub const MAX_MIDDLEWARE_METADATA_BYTES: usize = 32 * 1024;

const MAX_MIDDLEWARE_HEADER_MUTATION_WIRE_BYTES: usize = 64 * 1024;
const MAX_MIDDLEWARE_PROTOBUF_OVERHEAD_BYTES: usize = 64 * 1024;
const MAX_MIDDLEWARE_REQUEST_ENVELOPE_BYTES: usize = MAX_MIDDLEWARE_CONFIG_BYTES
    + MAX_MIDDLEWARE_CONTEXT_BYTES
    + MAX_MIDDLEWARE_TARGET_BYTES
    + MAX_MIDDLEWARE_HEADER_BYTES
    + MAX_MIDDLEWARE_PROTOBUF_OVERHEAD_BYTES;
const MAX_MIDDLEWARE_RESPONSE_ENVELOPE_BYTES: usize = MAX_MIDDLEWARE_REASON_BYTES
    + MAX_MIDDLEWARE_REASON_CODE_BYTES
    + MAX_MIDDLEWARE_HEADER_MUTATION_WIRE_BYTES
    + MAX_MIDDLEWARE_FINDINGS_PER_STAGE * MAX_MIDDLEWARE_FINDING_BYTES
    + MAX_MIDDLEWARE_METADATA_BYTES
    + MAX_MIDDLEWARE_PROTOBUF_OVERHEAD_BYTES;
/// gRPC envelope headroom derived from every bounded non-payload component.
pub const MIDDLEWARE_GRPC_ENVELOPE_BYTES: usize =
    if MAX_MIDDLEWARE_REQUEST_ENVELOPE_BYTES > MAX_MIDDLEWARE_RESPONSE_ENVELOPE_BYTES {
        MAX_MIDDLEWARE_REQUEST_ENVELOPE_BYTES
    } else {
        MAX_MIDDLEWARE_RESPONSE_ENVELOPE_BYTES
    };
/// gRPC message limit derived from the payload and bounded protobuf components.
pub const MIDDLEWARE_GRPC_MESSAGE_BYTES: usize =
    MAX_MIDDLEWARE_PAYLOAD_BYTES + MIDDLEWARE_GRPC_ENVELOPE_BYTES;

const MAX_STABLE_IDENTIFIER_BYTES: usize = 128;
const EXTERNAL_FINDING_LABEL: &str = "External middleware finding";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnError {
    FailClosed,
    FailOpen,
}

impl OnError {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "" | "fail_closed" => Ok(Self::FailClosed),
            "fail_open" => Ok(Self::FailOpen),
            other => Err(miette!(
                "invalid middleware on_error '{other}', expected fail_closed or fail_open"
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChainEntry {
    pub name: String,
    pub implementation: String,
    pub order: i32,
    pub config: prost_types::Struct,
    pub on_error: OnError,
}

impl TryFrom<(&str, &NetworkMiddlewareConfig)> for ChainEntry {
    type Error = miette::Report;

    fn try_from((name, value): (&str, &NetworkMiddlewareConfig)) -> Result<Self> {
        if name.is_empty() {
            return Err(miette!("middleware config name cannot be empty"));
        }
        if value.middleware.is_empty() {
            return Err(miette!(
                "middleware config '{}' must reference a middleware",
                name
            ));
        }
        Ok(Self {
            name: name.to_string(),
            implementation: value.middleware.clone(),
            order: value.order,
            config: value.config.clone().unwrap_or_default(),
            on_error: OnError::parse(&value.on_error)?,
        })
    }
}

/// A policy-selected middleware config joined with metadata reported by its
/// service's `Describe` call.
///
/// An unregistered implementation is retained so `on_error` can decide whether
/// the request fails open or closed. A registered implementation without the
/// requested binding is not part of this chain.
#[derive(Clone)]
pub struct DescribedChainEntry {
    entry: ChainEntry,
    service: Option<Arc<MiddlewareServiceState>>,
    binding: Option<MiddlewareBinding>,
    max_payload_bytes: usize,
    timeout: Duration,
}

struct DescribedChain {
    entries: Vec<DescribedChainEntry>,
    unbound: Vec<ChainEntry>,
}

impl DescribedChainEntry {
    pub fn max_payload_bytes(&self) -> usize {
        self.max_payload_bytes
    }

    pub fn on_error(&self) -> OnError {
        self.entry.on_error
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// True when this entry resolved to a registered binding and will be
    /// evaluated. When false, the binding is absent from the current registry
    /// and the entry is handled entirely by its `on_error` policy, so it
    /// imposes no payload-buffering limit on the chain.
    pub fn is_resolved(&self) -> bool {
        self.binding.is_some()
    }

    pub fn supports_http_body_mode(&self, mode: openshell_core::proto::HttpBodyMode) -> bool {
        self.binding
            .as_ref()
            .is_some_and(|binding| binding.supported_http_body_modes.contains(&(mode as i32)))
    }

    pub fn supports_http_body_processing(&self) -> bool {
        self.binding
            .as_ref()
            .is_some_and(|binding| !binding.supported_http_body_modes.is_empty())
    }
}

/// Re-checks a middleware-transformed request body against sandbox policy.
///
/// Returns `Some(reason)` to deny the chain, `None` to proceed. Invoked after
/// each stage that replaces the body so neither a later stage nor the upstream
/// sees a payload the policy would reject. Protocols with no body-aware policy
/// select [`TransformedBodyPolicy::NotPolicyRelevant`] instead.
pub type TransformedBodyValidator<'a> = dyn Fn(&[u8]) -> Result<Option<String>> + Send + Sync + 'a;

/// Whether middleware body replacements affect the selected request policy.
///
/// The network pipeline must choose a mode explicitly. This avoids representing
/// a security-relevant re-evaluation requirement as an optional callback where
/// an omitted value is indistinguishable from an intentionally body-independent
/// protocol.
#[derive(Clone, Copy)]
pub enum TransformedBodyPolicy<'a> {
    /// The selected policy does not inspect the request body.
    NotPolicyRelevant,
    /// Re-evaluate every body replacement before the next stage runs.
    Reevaluate(&'a TransformedBodyValidator<'a>),
}

#[derive(Debug, Clone)]
pub struct HttpRequestInput {
    pub request_id: String,
    pub sandbox_id: String,
    pub sandbox_name: String,
    pub workspace: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub query: String,
    /// Lowercased request headers in wire order. Repeated header names are
    /// preserved as separate entries so middleware inspects every value the
    /// upstream will receive.
    pub headers: Vec<(String, String)>,
    /// Lowercased names nominated by the original request's `Connection`
    /// headers. Their values are not exposed to middleware, but mutations must
    /// still treat these dynamically hop-by-hop fields as protected.
    pub connection_nominated_headers: Vec<String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ChainOutcome {
    pub allowed: bool,
    pub reason: String,
    pub body: Vec<u8>,
    /// Ordered, validated mutations to replay against the original raw request.
    pub header_mutations: Vec<HeaderMutation>,
    pub findings: Vec<NamespacedFinding>,
    pub metadata: BTreeMap<String, BTreeMap<String, String>>,
    pub applied: Vec<MiddlewareInvocation>,
    /// Present only when a middleware completed successfully and explicitly
    /// denied the request. Fail-closed service errors and transformed-body
    /// policy denials are not represented as middleware decisions.
    pub denial: Option<MiddlewareDenial>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiddlewareDenial {
    /// Stable policy-local middleware config identity.
    pub config_name: String,
    /// Validated service-defined code. Free-form service reason text is never
    /// carried into client responses or security logs.
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespacedFinding {
    pub middleware: String,
    pub finding: Finding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiddlewareInvocation {
    pub name: String,
    pub implementation: String,
    pub decision: Decision,
    pub transformed: bool,
    /// True when the middleware could not be evaluated and `on_error` was applied
    /// (service error, malformed/unsafe response, etc.). The `decision` reflects
    /// the `on_error` outcome, not a decision the middleware actually returned.
    pub failed: bool,
}

#[derive(Clone)]
pub struct ChainRunner {
    registry: Arc<MiddlewareRegistry>,
}

#[derive(Clone)]
enum MiddlewareDispatch {
    /// Built-ins borrow the current request state and never construct protobuf.
    InProcess(Arc<dyn InProcessMiddleware>),
    /// Operator services receive an owned protobuf through the gRPC adapter.
    Grpc(remote::GrpcMiddlewareService),
}

impl MiddlewareDispatch {
    async fn describe(
        &self,
    ) -> std::result::Result<tonic::Response<MiddlewareManifest>, tonic::Status> {
        match self {
            Self::InProcess(service) => Ok(tonic::Response::new(service.describe().await)),
            Self::Grpc(service) => service.describe().await,
        }
    }

    async fn validate_config(
        &self,
        middleware_name: &str,
        config: &prost_types::Struct,
    ) -> std::result::Result<tonic::Response<ValidateConfigResponse>, tonic::Status> {
        match self {
            Self::InProcess(service) => Ok(tonic::Response::new(
                match service.validate_config(middleware_name, config).await {
                    Ok(()) => ValidateConfigResponse {
                        valid: true,
                        reason: String::new(),
                    },
                    Err(error) => ValidateConfigResponse {
                        valid: false,
                        reason: error.to_string(),
                    },
                },
            )),
            Self::Grpc(service) => service.validate_config(middleware_name, config).await,
        }
    }

    async fn open_http_request_pre_credentials(
        &self,
        receiver: tokio::sync::mpsc::Receiver<openshell_core::proto::HttpEvent>,
    ) -> std::result::Result<HttpResultStream, tonic::Status> {
        match self {
            Self::InProcess(service) => service.open_http_request_pre_credentials(receiver).await,
            Self::Grpc(service) => service.open_http_request_pre_credentials(receiver).await,
        }
    }

    async fn open_websocket_session(
        &self,
        receiver: tokio::sync::mpsc::Receiver<openshell_core::proto::WebSocketSessionEvent>,
    ) -> std::result::Result<WebSocketResponseStream, tonic::Status> {
        match self {
            Self::InProcess(service) => service.open_websocket_session(receiver).await,
            Self::Grpc(service) => service.open_websocket_session(receiver).await,
        }
    }

    async fn open_http_response_pre_return(
        &self,
        receiver: tokio::sync::mpsc::Receiver<openshell_core::proto::HttpEvent>,
    ) -> std::result::Result<HttpResultStream, tonic::Status> {
        match self {
            Self::InProcess(service) => service.open_http_response_pre_return(receiver).await,
            Self::Grpc(service) => service.open_http_response_pre_return(receiver).await,
        }
    }
}

struct MiddlewareServiceState {
    /// Policy-facing built-in name or operator-owned registration name. The
    /// single-service test constructor leaves this empty and uses the manifest
    /// name after Describe.
    attachment_name: Option<String>,
    service: MiddlewareDispatch,
    manifest: OnceCell<MiddlewareManifest>,
    diagnostic_policy: MiddlewareDiagnosticPolicy,
    operator_max_payload_bytes: Option<usize>,
    operator_timeout: Duration,
}

impl MiddlewareServiceState {
    fn timeout_for_binding(&self, binding: &MiddlewareBinding) -> Result<Duration> {
        if binding.request_timeout.is_none() {
            Ok(self.operator_timeout)
        } else {
            middleware_proto_timeout_or_default(binding.request_timeout.as_ref())
                .map(|binding_timeout| binding_timeout.min(self.operator_timeout))
                .map_err(|reason| miette!("middleware binding has invalid timeout: {reason}"))
        }
    }
}

async fn call_with_timeout<T>(
    timeout: Duration,
    operation: &'static str,
    future: impl Future<Output = std::result::Result<tonic::Response<T>, tonic::Status>>,
) -> std::result::Result<tonic::Response<T>, tonic::Status> {
    tokio::time::timeout(timeout, future).await.map_err(|_| {
        tonic::Status::deadline_exceeded(format!("middleware {operation} timed out"))
    })?
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MiddlewareDiagnosticPolicy {
    Preserve,
    Normalize,
}

impl MiddlewareDiagnosticPolicy {
    fn error_reason(self, error: &tonic::Status) -> String {
        match self {
            Self::Preserve => safe_reason(&error.to_string()),
            Self::Normalize => "external_service_error".to_string(),
        }
    }

    fn header_mutation_error_reason(self, error: &headers::HeaderMutationError) -> String {
        match self {
            Self::Preserve => safe_reason(&error.to_string()),
            Self::Normalize => error.code().to_string(),
        }
    }
}

/// Validated middleware services available to a gateway or one supervisor.
///
/// In-process services are supplied by the composition root; the generic
/// registry does not select concrete built-ins. All in-process and remote
/// services are described before construction succeeds, so callers never
/// observe a partially registered service set.
#[derive(Clone)]
pub struct MiddlewareRegistry {
    services: Arc<Vec<Arc<MiddlewareServiceState>>>,
    registered_services: Arc<Vec<RegisteredMiddlewareService>>,
    middleware_names: Arc<HashSet<String>>,
    negotiated_extensions: Arc<Vec<NegotiatedExtension>>,
    work_admission: Arc<Semaphore>,
    work_admission_waiters: Arc<Semaphore>,
    session_admission: Arc<Semaphore>,
}

impl std::fmt::Debug for MiddlewareRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MiddlewareRegistry")
            .field("service_count", &self.services.len())
            .field("registered_service_count", &self.registered_services.len())
            .field("middleware_count", &self.middleware_names.len())
            .field(
                "available_work_permits",
                &self.work_admission.available_permits(),
            )
            .field(
                "available_session_permits",
                &self.session_admission.available_permits(),
            )
            .finish()
    }
}

#[derive(Clone)]
struct RegisteredMiddlewareService {
    registration: SupervisorMiddlewareService,
}

impl Default for MiddlewareRegistry {
    fn default() -> Self {
        Self {
            services: Arc::new(Vec::new()),
            registered_services: Arc::new(Vec::new()),
            middleware_names: Arc::new(HashSet::new()),
            negotiated_extensions: Arc::new(Vec::new()),
            work_admission: Arc::new(Semaphore::new(MAX_CONCURRENT_MIDDLEWARE_WORK)),
            work_admission_waiters: Arc::new(Semaphore::new(MAX_QUEUED_MIDDLEWARE_WORK)),
            session_admission: Arc::new(Semaphore::new(MAX_CONCURRENT_MIDDLEWARE_SESSIONS)),
        }
    }
}

/// Validate one external middleware registration without opening its transport.
pub fn validate_registration_config(registration: &SupervisorMiddlewareService) -> Result<()> {
    validate_registration(registration).map(|_| ())
}

fn validate_registration(registration: &SupervisorMiddlewareService) -> Result<Duration> {
    if !is_stable_identifier(&registration.name) {
        return Err(miette!(
            "supervisor middleware registration names must be 1-{MAX_STABLE_IDENTIFIER_BYTES} bytes and contain only ASCII letters, digits, '.', '_', '-', or '/'"
        ));
    }
    if registration.name.starts_with("openshell/") {
        return Err(miette!(
            "middleware registration '{}' cannot claim the reserved openshell/ namespace",
            registration.name
        ));
    }
    if !registration.grpc_endpoint.starts_with("http://")
        && !registration.grpc_endpoint.starts_with("https://")
    {
        return Err(miette!(
            "middleware registration '{}' grpc_endpoint must use http:// or https://",
            registration.name
        ));
    }
    if registration.max_payload_bytes > MAX_MIDDLEWARE_PAYLOAD_BYTES as u64 {
        return Err(miette!(
            "middleware registration '{}' max_payload_bytes exceeds the platform maximum of {MAX_MIDDLEWARE_PAYLOAD_BYTES}",
            registration.name
        ));
    }
    middleware_proto_timeout_or_default(registration.request_timeout.as_ref()).map_err(|reason| {
        miette!(
            "middleware registration '{}' has invalid timeout: {reason}",
            registration.name
        )
    })
}

fn is_stable_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_STABLE_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
}

fn is_stable_reason_code(value: &str) -> bool {
    value.len() <= MAX_MIDDLEWARE_REASON_CODE_BYTES
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn middleware_denial_reason(config_name: &str, reason_code: Option<&str>) -> String {
    let config_id: String = config_name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .take(MAX_STABLE_IDENTIFIER_BYTES)
        .collect();
    reason_code.map_or_else(
        || format!("middleware_denied:{config_id}"),
        |code| format!("middleware_denied:{config_id}:{code}"),
    )
}

fn validate_payload_limit(
    source: &str,
    binding: &MiddlewareBinding,
    required: bool,
) -> Result<usize> {
    if required && binding.max_payload_bytes == 0 {
        return Err(miette!("{source} must advertise a non-zero payload limit"));
    }
    if binding.max_payload_bytes > MAX_MIDDLEWARE_PAYLOAD_BYTES as u64 {
        return Err(miette!(
            "{source} payload limit exceeds the platform maximum of {MAX_MIDDLEWARE_PAYLOAD_BYTES}"
        ));
    }
    usize::try_from(binding.max_payload_bytes)
        .map_err(|_| miette!("{source} reports a payload limit too large for this platform"))
}

fn binding_requires_payload_limit(binding: &MiddlewareBinding) -> bool {
    !matches!(
        SupervisorMiddlewareOperation::try_from(binding.operation).ok(),
        Some(
            SupervisorMiddlewareOperation::HttpRequest
                | SupervisorMiddlewareOperation::HttpResponse
        )
    ) || !binding.supported_http_body_modes.is_empty()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupportedBinding {
    HttpPreCredentials,
    HttpResponsePreReturn,
    WebSocketPreCredentials,
}

fn supported_binding(source: &str, binding: &MiddlewareBinding) -> Result<SupportedBinding> {
    match (
        SupervisorMiddlewareOperation::try_from(binding.operation).ok(),
        SupervisorMiddlewarePhase::try_from(binding.phase).ok(),
    ) {
        (
            Some(SupervisorMiddlewareOperation::HttpRequest),
            Some(SupervisorMiddlewarePhase::PreCredentials),
        ) => Ok(SupportedBinding::HttpPreCredentials),
        (
            Some(SupervisorMiddlewareOperation::HttpResponse),
            Some(SupervisorMiddlewarePhase::PreReturn),
        ) => Ok(SupportedBinding::HttpResponsePreReturn),
        (
            Some(SupervisorMiddlewareOperation::WebsocketMessage),
            Some(SupervisorMiddlewarePhase::PreCredentials),
        ) => Ok(SupportedBinding::WebSocketPreCredentials),
        (
            Some(SupervisorMiddlewareOperation::WebsocketMessage),
            Some(SupervisorMiddlewarePhase::PreReturn),
        ) => Err(miette!(
            "{source} advertises WEBSOCKET_MESSAGE/PRE_RETURN, which is not yet supported"
        )),
        _ => Err(miette!(
            "{source} advertises an unsupported middleware operation/phase pair"
        )),
    }
}

fn validate_manifest_bindings(
    source: &str,
    manifest: &MiddlewareManifest,
    operator_max_payload_bytes: Option<usize>,
) -> Result<()> {
    if manifest.bindings.is_empty() {
        return Err(miette!("{source} describes no bindings"));
    }

    let mut described_pairs = HashSet::with_capacity(manifest.bindings.len());
    for binding in &manifest.bindings {
        let supported = supported_binding(source, binding)?;
        if !described_pairs.insert((binding.operation, binding.phase)) {
            return Err(miette!(
                "{source} describes a duplicate middleware operation/phase pair"
            ));
        }
        let payload_limit_required = binding_requires_payload_limit(binding);
        let advertised = validate_payload_limit(source, binding, payload_limit_required)?;
        if binding.request_timeout.is_some() {
            middleware_proto_timeout_or_default(binding.request_timeout.as_ref())
                .map_err(|reason| miette!("{source} has invalid timeout for binding: {reason}"))?;
        }
        if payload_limit_required
            && operator_max_payload_bytes.is_some_and(|limit| limit > advertised)
        {
            return Err(miette!(
                "{source} max_payload_bytes ({}) exceeds the binding capability ({advertised})",
                operator_max_payload_bytes.expect("operator limit checked above")
            ));
        }
        if payload_limit_required && operator_max_payload_bytes == Some(0) {
            return Err(miette!(
                "{source} must configure max_payload_bytes for every payload-bearing binding"
            ));
        }
        match supported {
            SupportedBinding::HttpPreCredentials | SupportedBinding::HttpResponsePreReturn => {
                if binding.http_protocol_version != 1 {
                    return Err(miette!(
                        "{source} must advertise HTTP middleware protocol version 1"
                    ));
                }
                let mut modes = HashSet::new();
                for mode in &binding.supported_http_body_modes {
                    if !modes.insert(*mode)
                        || !matches!(
                            openshell_core::proto::HttpBodyMode::try_from(*mode).ok(),
                            Some(
                                openshell_core::proto::HttpBodyMode::Buffered
                                    | openshell_core::proto::HttpBodyMode::Stream
                            )
                        )
                    {
                        return Err(miette!(
                            "{source} advertises an invalid or duplicate HTTP body mode"
                        ));
                    }
                }
            }
            SupportedBinding::WebSocketPreCredentials => {
                if binding.http_protocol_version != 0
                    || !binding.supported_http_body_modes.is_empty()
                {
                    return Err(miette!(
                        "{source} sets HTTP protocol capabilities on a WebSocket binding"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn middleware_proto_timeout_or_default(
    value: Option<&prost_types::Duration>,
) -> std::result::Result<Duration, String> {
    let Some(value) = value else {
        return Ok(DEFAULT_MIDDLEWARE_TIMEOUT);
    };
    let timeout =
        openshell_core::time::duration_to_std(value).map_err(|error| error.to_string())?;
    if !(MIN_MIDDLEWARE_TIMEOUT..=MAX_MIDDLEWARE_TIMEOUT).contains(&timeout) {
        return Err(format!(
            "must be between {}ms and {}s",
            MIN_MIDDLEWARE_TIMEOUT.as_millis(),
            MAX_MIDDLEWARE_TIMEOUT.as_secs()
        ));
    }
    Ok(timeout)
}

fn validate_external_manifest(
    registration: &SupervisorMiddlewareService,
    manifest: &MiddlewareManifest,
    operator_max_payload_bytes: usize,
    authenticated: bool,
) -> Result<()> {
    validate_manifest_bindings(
        &format!("external middleware registration '{}'", registration.name),
        manifest,
        Some(operator_max_payload_bytes),
    )?;
    validate_expected_audience(
        &registration.name,
        &registration.audience,
        &manifest.expected_audience,
        authenticated && !registration.allow_insecure_transport,
    )
}

/// After authenticated Describe succeeds, reject a registration whose
/// configured audience differs from the one the service says it verifies.
///
/// This is a post-authentication consistency assertion, not audience discovery:
/// a strict verifier may reject an incorrect audience before returning its
/// manifest. A service that does not advertise an audience is accepted unchanged.
fn validate_expected_audience(
    registration_name: &str,
    configured: &str,
    advertised: &str,
    authenticated: bool,
) -> Result<()> {
    if !authenticated || advertised.is_empty() {
        return Ok(());
    }
    if advertised != configured {
        return Err(miette!(
            "middleware registration '{registration_name}' expects audience \
             '{advertised}' but OpenShell is configured to mint '{configured}'"
        ));
    }
    Ok(())
}

impl MiddlewareRegistry {
    /// Describe in-process services, then connect and validate every
    /// operator-provided service registration.
    pub async fn connect_services(
        in_process_services: Vec<Arc<dyn InProcessMiddleware>>,
        registrations: Vec<SupervisorMiddlewareService>,
    ) -> Result<Self> {
        Self::connect_services_inner(in_process_services, registrations, None).await
    }

    /// Connect services with optional refreshable credentials keyed by
    /// operator registration name. A configured credential is shared by all
    /// generated client clones and can rotate without rebuilding the registry.
    pub async fn connect_services_authenticated(
        in_process_services: Vec<Arc<dyn InProcessMiddleware>>,
        registrations: Vec<SupervisorMiddlewareService>,
        credentials: &HashMap<String, openshell_extension_core::BearerTokenSlot>,
    ) -> Result<Self> {
        Self::connect_services_inner(in_process_services, registrations, Some(credentials)).await
    }

    async fn connect_services_inner(
        in_process_services: Vec<Arc<dyn InProcessMiddleware>>,
        registrations: Vec<SupervisorMiddlewareService>,
        credentials: Option<&HashMap<String, openshell_extension_core::BearerTokenSlot>>,
    ) -> Result<Self> {
        let mut services = Vec::with_capacity(in_process_services.len() + registrations.len());
        let mut registered_services = Vec::with_capacity(registrations.len());
        let mut middleware_names = HashSet::new();
        let mut negotiated_extensions = Vec::new();
        let gateway = gateway_metadata(ExtensionFamily::SupervisorMiddleware);

        for service in in_process_services {
            let service = MiddlewareDispatch::InProcess(service);
            let manifest =
                call_with_timeout(DEFAULT_MIDDLEWARE_TIMEOUT, "Describe", service.describe())
                    .await
                    .map(tonic::Response::into_inner)
                    .map_err(|error| {
                        miette!(
                            "in-process middleware Describe failed: {}",
                            safe_reason(&error.to_string())
                        )
                    })?;
            let source = if manifest.name.trim().is_empty() {
                "in-process middleware service".to_string()
            } else {
                format!("in-process middleware service '{}'", manifest.name)
            };
            if !is_stable_identifier(&manifest.name) {
                return Err(miette!(
                    "in-process middleware names must be 1-{MAX_STABLE_IDENTIFIER_BYTES} bytes and contain only ASCII letters, digits, '.', '_', '-', or '/'"
                ));
            }
            if !middleware_names.insert(manifest.name.clone()) {
                return Err(miette!(
                    "duplicate supervisor middleware name '{}'",
                    manifest.name
                ));
            }
            validate_manifest_bindings(&source, &manifest, None)?;
            negotiated_extensions.push(
                negotiate(
                    ExtensionFamily::SupervisorMiddleware,
                    &manifest.name,
                    &gateway,
                    manifest.extension.clone(),
                )
                .map_err(|error| miette!(error.to_string()))?,
            );
            let attachment_name = manifest.name.clone();
            let manifest_cell = OnceCell::new();
            manifest_cell
                .set(manifest)
                .map_err(|_| miette!("middleware manifest cache initialized twice"))?;
            services.push(Arc::new(MiddlewareServiceState {
                attachment_name: Some(attachment_name),
                service,
                manifest: manifest_cell,
                diagnostic_policy: MiddlewareDiagnosticPolicy::Preserve,
                operator_max_payload_bytes: None,
                operator_timeout: DEFAULT_MIDDLEWARE_TIMEOUT,
            }));
        }

        for registration in registrations {
            let operator_timeout = validate_registration(&registration)?;
            if !middleware_names.insert(registration.name.clone()) {
                return Err(miette!(
                    "duplicate supervisor middleware registration name '{}'",
                    registration.name
                ));
            }

            let operator_max_payload_bytes = usize::try_from(registration.max_payload_bytes)
                .map_err(|_| {
                    miette!(
                        "middleware registration '{}' payload limit is too large for this platform",
                        registration.name
                    )
                })?;
            // A registration the operator opted out of extension
            // authentication carries no credential by design. Every other
            // registration must have one, or the connection fails closed
            // rather than silently downgrading to an unauthenticated call.
            let bearer = credentials
                .filter(|_| !registration.allow_insecure_transport)
                .map(|credentials| {
                    credentials.get(&registration.name).cloned().ok_or_else(|| {
                        miette!(
                            "middleware registration '{}' is missing its extension credential",
                            registration.name
                        )
                    })
                })
                .transpose()?;
            let authenticated = bearer.is_some();
            let service = MiddlewareDispatch::Grpc(
                remote::GrpcMiddlewareService::connect(
                    &registration.name,
                    &registration.grpc_endpoint,
                    &registration.tls_ca_cert_pem,
                    bearer,
                )
                .await?,
            );
            let manifest = call_with_timeout(operator_timeout, "Describe", service.describe())
                .await
                .map(tonic::Response::into_inner)
                .map_err(|error| {
                    miette!(
                        "middleware registration '{}' Describe failed: {}",
                        registration.name,
                        safe_reason(&error.to_string())
                    )
                })?;
            validate_external_manifest(
                &registration,
                &manifest,
                operator_max_payload_bytes,
                authenticated,
            )?;
            negotiated_extensions.push(
                negotiate(
                    ExtensionFamily::SupervisorMiddleware,
                    &registration.name,
                    &gateway,
                    manifest.extension.clone(),
                )
                .map_err(|error| miette!(error.to_string()))?,
            );
            let manifest_cell = OnceCell::new();
            manifest_cell
                .set(manifest)
                .map_err(|_| miette!("middleware manifest cache initialized twice"))?;
            services.push(Arc::new(MiddlewareServiceState {
                attachment_name: Some(registration.name.clone()),
                service,
                manifest: manifest_cell,
                diagnostic_policy: MiddlewareDiagnosticPolicy::Normalize,
                operator_max_payload_bytes: Some(operator_max_payload_bytes),
                operator_timeout,
            }));
            registered_services.push(RegisteredMiddlewareService { registration });
        }

        Ok(Self {
            services: Arc::new(services),
            registered_services: Arc::new(registered_services),
            middleware_names: Arc::new(middleware_names),
            negotiated_extensions: Arc::new(negotiated_extensions),
            work_admission: Arc::new(Semaphore::new(MAX_CONCURRENT_MIDDLEWARE_WORK)),
            work_admission_waiters: Arc::new(Semaphore::new(MAX_QUEUED_MIDDLEWARE_WORK)),
            session_admission: Arc::new(Semaphore::new(MAX_CONCURRENT_MIDDLEWARE_SESSIONS)),
        })
    }

    /// Validate implementation-owned configuration for every middleware entry.
    pub async fn validate_policy_configs(&self, policy: &SandboxPolicy) -> Result<()> {
        ensure_config_capacity(policy.network_middlewares.len())?;
        let runner = ChainRunner::from_registry(self.clone());
        let manifests = runner.manifests().await?;
        for (name, config) in &policy.network_middlewares {
            let entry = ChainEntry::try_from((name.as_str(), config))?;
            if entry.on_error == OnError::FailOpen
                && manifests.iter().any(|(state, manifest)| {
                    ChainRunner::attachment_name(state, manifest) == config.middleware
                        && manifest.bindings.iter().any(|binding| {
                            matches!(
                                SupervisorMiddlewareOperation::try_from(binding.operation).ok(),
                                Some(
                                    SupervisorMiddlewareOperation::HttpRequest
                                        | SupervisorMiddlewareOperation::HttpResponse
                                )
                            )
                        })
                })
            {
                return Err(miette!(
                    "middleware config '{name}' uses on_error=fail_open with an HTTP binding; HTTP middleware is fail-closed"
                ));
            }
            runner
                .validate_config(
                    &config.middleware,
                    config.config.clone().unwrap_or_default(),
                )
                .await
                .map_err(|error| {
                    miette!(
                        "middleware config '{}' is invalid: {}",
                        name,
                        safe_reason(&error.to_string())
                    )
                })?;
        }
        Ok(())
    }

    /// Check that every policy attachment still belongs to the current static
    /// registry without making a network call.
    pub fn ensure_policy_middlewares_registered(&self, policy: &SandboxPolicy) -> Result<()> {
        for (name, config) in &policy.network_middlewares {
            if !self.middleware_names.contains(&config.middleware) {
                return Err(miette!(
                    "middleware '{}' used by config '{}' is not registered",
                    config.middleware,
                    name
                ));
            }
        }
        Ok(())
    }

    /// Return only operator-registered services referenced by the effective policy.
    pub fn required_services(
        &self,
        policy: Option<&SandboxPolicy>,
    ) -> Vec<SupervisorMiddlewareService> {
        let Some(policy) = policy else {
            return Vec::new();
        };
        let selected: HashSet<&str> = policy
            .network_middlewares
            .values()
            .map(|config| config.middleware.as_str())
            .collect();
        self.registered_services
            .iter()
            .filter(|service| selected.contains(service.registration.name.as_str()))
            .map(|service| service.registration.clone())
            .collect()
    }

    #[must_use]
    pub fn negotiated_extensions(&self) -> &[NegotiatedExtension] {
        &self.negotiated_extensions
    }
}

impl Default for ChainRunner {
    fn default() -> Self {
        Self::from_registry(MiddlewareRegistry::default())
    }
}

impl ChainRunner {
    /// Construct a runner around one in-process middleware implementation.
    #[must_use]
    pub fn new(service: Arc<dyn InProcessMiddleware>) -> Self {
        Self::from_service(MiddlewareDispatch::InProcess(service))
    }

    /// Construct a runner around a legacy transport-neutral in-process endpoint.
    #[must_use]
    pub fn from_endpoint(endpoint: Arc<dyn SupervisorMiddlewareEndpoint>) -> Self {
        Self::new(in_process_endpoint(endpoint))
    }

    fn from_service(service: MiddlewareDispatch) -> Self {
        Self {
            registry: Arc::new(MiddlewareRegistry {
                services: Arc::new(vec![Arc::new(MiddlewareServiceState {
                    attachment_name: None,
                    service,
                    manifest: OnceCell::new(),
                    diagnostic_policy: MiddlewareDiagnosticPolicy::Preserve,
                    operator_max_payload_bytes: None,
                    operator_timeout: DEFAULT_MIDDLEWARE_TIMEOUT,
                })]),
                registered_services: Arc::new(Vec::new()),
                middleware_names: Arc::new(HashSet::new()),
                negotiated_extensions: Arc::new(Vec::new()),
                work_admission: Arc::new(Semaphore::new(MAX_CONCURRENT_MIDDLEWARE_WORK)),
                work_admission_waiters: Arc::new(Semaphore::new(MAX_QUEUED_MIDDLEWARE_WORK)),
                session_admission: Arc::new(Semaphore::new(MAX_CONCURRENT_MIDDLEWARE_SESSIONS)),
            }),
        }
    }

    pub fn from_registry(registry: MiddlewareRegistry) -> Self {
        Self {
            registry: Arc::new(registry),
        }
    }

    /// Build a runner for a replacement registry while preserving process-wide
    /// admission budgets across registry generations.
    #[must_use]
    pub fn with_replacement_registry(&self, mut registry: MiddlewareRegistry) -> Self {
        registry.work_admission = Arc::clone(&self.registry.work_admission);
        registry.work_admission_waiters = Arc::clone(&self.registry.work_admission_waiters);
        registry.session_admission = Arc::clone(&self.registry.session_admission);
        Self::from_registry(registry)
    }

    /// Reserve one unit of short-lived middleware work.
    ///
    /// The bounded waiter queue provides backpressure for work expected to
    /// complete promptly, such as HTTP evaluations, WebSocket messages, and
    /// streaming-session preflight.
    pub async fn reserve_middleware_work(&self) -> Result<MiddlewareWorkAdmissionOutcome> {
        if let Ok(permit) = Arc::clone(&self.registry.work_admission).try_acquire_owned() {
            Ok(MiddlewareWorkAdmissionOutcome::Admitted(
                MiddlewareWorkAdmission {
                    _work: permit,
                    saturated: false,
                },
            ))
        } else {
            let Ok(waiter) = Arc::clone(&self.registry.work_admission_waiters).try_acquire_owned()
            else {
                return Ok(MiddlewareWorkAdmissionOutcome::QueueExhausted);
            };
            let permit = Arc::clone(&self.registry.work_admission)
                .acquire_owned()
                .await
                .map_err(|_| miette!("middleware admission semaphore closed"))?;
            drop(waiter);
            Ok(MiddlewareWorkAdmissionOutcome::Admitted(
                MiddlewareWorkAdmission {
                    _work: permit,
                    saturated: true,
                },
            ))
        }
    }

    /// Reserve middleware work for a caller whose established external
    /// behavior treats queue exhaustion as a middleware processing failure.
    pub async fn reserve_middleware_work_admission(&self) -> Result<MiddlewareWorkAdmission> {
        self.reserve_middleware_work().await?.into_admission()
    }

    /// Attempt to reserve one persistent middleware session without waiting.
    ///
    /// Long-lived sessions have no useful queueing bound because their release
    /// time is unrelated to middleware latency. Protocol-specific runners apply
    /// their own `on_error` semantics when the shared session budget is full.
    fn try_reserve_middleware_session(&self) -> MiddlewareSessionAdmission {
        Arc::clone(&self.registry.session_admission)
            .try_acquire_owned()
            .map_or(MiddlewareSessionAdmission::AtCapacity, |permit| {
                MiddlewareSessionAdmission::Admitted(MiddlewareSessionPermit { _session: permit })
            })
    }

    async fn manifests(&self) -> Result<Vec<(Arc<MiddlewareServiceState>, MiddlewareManifest)>> {
        let mut manifests = Vec::with_capacity(self.registry.services.len());
        for state in self.registry.services.iter() {
            let manifest = state
                .manifest
                .get_or_try_init(|| async {
                    call_with_timeout(state.operator_timeout, "Describe", state.service.describe())
                        .await
                        .map(tonic::Response::into_inner)
                        .map_err(|error| {
                            miette!(
                                "middleware Describe failed: {}",
                                safe_reason(&error.to_string())
                            )
                        })
                })
                .await?;
            manifests.push((Arc::clone(state), manifest.clone()));
        }
        Ok(manifests)
    }

    fn attachment_name<'a>(
        state: &'a MiddlewareServiceState,
        manifest: &'a MiddlewareManifest,
    ) -> &'a str {
        state
            .attachment_name
            .as_deref()
            .unwrap_or(manifest.name.as_str())
    }

    fn binding(
        manifest: &MiddlewareManifest,
        operation: SupervisorMiddlewareOperation,
        phase: SupervisorMiddlewarePhase,
    ) -> Option<&MiddlewareBinding> {
        manifest
            .bindings
            .iter()
            .find(|binding| binding.operation == operation as i32 && binding.phase == phase as i32)
    }

    pub async fn describe_chain(&self, entries: &[ChainEntry]) -> Result<Vec<DescribedChainEntry>> {
        Ok(self
            .describe_chain_for(
                entries,
                SupervisorMiddlewareOperation::HttpRequest,
                SupervisorMiddlewarePhase::PreCredentials,
            )
            .await?
            .entries)
    }

    pub async fn describe_websocket_chain(
        &self,
        entries: &[ChainEntry],
    ) -> Result<Vec<DescribedChainEntry>> {
        Ok(self
            .describe_chain_for(
                entries,
                SupervisorMiddlewareOperation::WebsocketMessage,
                SupervisorMiddlewarePhase::PreCredentials,
            )
            .await?
            .entries)
    }

    pub async fn describe_http_response_chain(
        &self,
        entries: &[ChainEntry],
    ) -> Result<Vec<DescribedChainEntry>> {
        Ok(self
            .describe_chain_for(
                entries,
                SupervisorMiddlewareOperation::HttpResponse,
                SupervisorMiddlewarePhase::PreReturn,
            )
            .await?
            .entries)
    }

    async fn describe_chain_for(
        &self,
        entries: &[ChainEntry],
        operation: SupervisorMiddlewareOperation,
        phase: SupervisorMiddlewarePhase,
    ) -> Result<DescribedChain> {
        ensure_chain_capacity(entries.len())?;
        let manifests = self.manifests().await?;
        let mut entries = entries.to_vec();
        sort_chain_entries(&mut entries);
        let mut described_entries = Vec::with_capacity(entries.len());
        let mut unbound = Vec::new();
        for entry in entries {
            let Some((state, manifest)) = manifests.iter().find(|(state, manifest)| {
                Self::attachment_name(state, manifest) == entry.implementation
            }) else {
                described_entries.push(DescribedChainEntry {
                    entry,
                    service: None,
                    binding: None,
                    max_payload_bytes: 0,
                    timeout: DEFAULT_MIDDLEWARE_TIMEOUT,
                });
                continue;
            };
            let Some(binding) = Self::binding(manifest, operation, phase).cloned() else {
                // The config remains globally ordered, but it does not
                // participate in this exact operation/phase chain.
                unbound.push(entry);
                continue;
            };
            let timeout = state.timeout_for_binding(&binding)?;
            let payload_limit_required = binding_requires_payload_limit(&binding);
            let advertised =
                validate_payload_limit("middleware manifest", &binding, payload_limit_required)?;
            let max_payload_bytes = if payload_limit_required {
                state.operator_max_payload_bytes.unwrap_or(advertised)
            } else {
                0
            };
            described_entries.push(DescribedChainEntry {
                entry,
                service: Some(Arc::clone(state)),
                binding: Some(binding),
                max_payload_bytes,
                timeout,
            });
        }
        ensure_chain_capacity(described_entries.len())?;
        Ok(DescribedChain {
            entries: described_entries,
            unbound,
        })
    }

    pub async fn validate_config(
        &self,
        middleware_name: &str,
        config: prost_types::Struct,
    ) -> Result<()> {
        if config.encoded_len() > MAX_MIDDLEWARE_CONFIG_BYTES {
            return Err(miette!(
                "middleware config exceeds the platform maximum of {MAX_MIDDLEWARE_CONFIG_BYTES} encoded bytes"
            ));
        }
        let manifests = self.manifests().await?;
        let Some((state, _manifest)) = manifests
            .iter()
            .find(|(state, manifest)| Self::attachment_name(state, manifest) == middleware_name)
        else {
            return Err(miette!("middleware '{middleware_name}' is not registered"));
        };
        let response = call_with_timeout(
            state.operator_timeout,
            "ValidateConfig",
            state.service.validate_config(middleware_name, &config),
        )
        .await
        .map(tonic::Response::into_inner)
        .map_err(|error| {
            miette!(
                "middleware ValidateConfig failed: {}",
                safe_reason(&error.to_string())
            )
        })?;
        if response.valid {
            Ok(())
        } else {
            Err(miette!("{}", safe_reason(&response.reason)))
        }
    }

    pub async fn evaluate(
        &self,
        entries: &[ChainEntry],
        input: HttpRequestInput,
    ) -> Result<ChainOutcome> {
        let entries = self.describe_chain(entries).await?;
        self.evaluate_described(&entries, input).await
    }

    pub async fn evaluate_described(
        &self,
        entries: &[DescribedChainEntry],
        input: HttpRequestInput,
    ) -> Result<ChainOutcome> {
        self.evaluate_described_with_policy(
            entries,
            input,
            TransformedBodyPolicy::NotPolicyRelevant,
        )
        .await
    }

    /// Evaluate a described chain, re-checking the request body against sandbox
    /// policy after every stage that replaces it. Policy runs on the original
    /// body before the chain, so without this a stage could hand the next stage
    /// (or the upstream) a payload the policy rejects. When the evaluator returns
    /// a deny reason the chain stops with that reason, so no later stage ever
    /// sees a non-compliant body. Body-independent protocols must select
    /// [`TransformedBodyPolicy::NotPolicyRelevant`] explicitly.
    pub async fn evaluate_described_with_policy(
        &self,
        entries: &[DescribedChainEntry],
        input: HttpRequestInput,
        transformed_body_policy: TransformedBodyPolicy<'_>,
    ) -> Result<ChainOutcome> {
        let admission = if entries.is_empty() {
            None
        } else {
            Some(self.reserve_middleware_work_admission().await?)
        };
        self.evaluate_described_with_policy_admitted(
            entries,
            input,
            transformed_body_policy,
            admission,
        )
        .await
    }

    /// Evaluate a chain using capacity reserved before its request body was
    /// buffered. The guard is retained until the ordered chain completes.
    pub async fn evaluate_described_with_policy_admitted(
        &self,
        entries: &[DescribedChainEntry],
        input: HttpRequestInput,
        transformed_body_policy: TransformedBodyPolicy<'_>,
        admission: Option<MiddlewareWorkAdmission>,
    ) -> Result<ChainOutcome> {
        ensure_chain_capacity(entries.len())?;
        let HttpRequestInput {
            request_id,
            sandbox_id,
            sandbox_name,
            workspace,
            scheme,
            host,
            port,
            method,
            path,
            query,
            headers,
            connection_nominated_headers,
            body,
        } = input;
        let context = RequestContext {
            request_id,
            sandbox_id,
            sandbox: sandbox_name,
            workspace,
            originating_process: None,
        };
        let target = HttpRequestTarget {
            scheme,
            host,
            port: u32::from(port),
            method,
            path,
            query,
        };
        let mut headers = headers
            .into_iter()
            .map(|(name, value)| HttpHeader { name, value })
            .collect::<Vec<_>>();
        let mut body = body;
        let mut header_mutations = Vec::new();
        let mut findings = Vec::new();
        let mut metadata = BTreeMap::new();
        let mut applied = Vec::new();
        // The request session budget now bounds the streaming lifecycle, so a
        // compatibility caller's pre-buffer admission can be released before
        // opening the stage stream.
        drop(admission);

        // The compatibility collector evaluates one stage at a time so
        // body-aware protocols can re-run policy after every accepted
        // replacement. The HTTP relay uses the streaming session API directly
        // and does not collect a complete request in memory.
        for entry in entries {
            let preflight = self
                .preflight_described_http_request(
                    vec![entry.clone()],
                    HttpRequestPreflightInput {
                        context: context.clone(),
                        target: target.clone(),
                        declared_body_length: Some(body.len() as u64),
                        headers: headers.clone(),
                        connection_nominated_headers: connection_nominated_headers.clone(),
                    },
                )
                .await?;

            findings.extend(preflight.findings.clone());
            metadata.extend(preflight.metadata.clone());
            let mut stage_failed = preflight.invocations.iter().any(|item| item.failed);
            let headers_transformed = preflight.headers != headers;
            headers = preflight.headers;
            header_mutations.extend(preflight.header_mutations);

            if !preflight.allowed {
                applied.push(MiddlewareInvocation {
                    name: entry.entry.name.clone(),
                    implementation: entry.entry.implementation.clone(),
                    decision: Decision::Deny,
                    transformed: false,
                    failed: preflight.denial.is_none(),
                });
                return Ok(ChainOutcome {
                    allowed: false,
                    reason: preflight.reason,
                    body,
                    header_mutations,
                    findings,
                    metadata,
                    applied,
                    denial: preflight.denial,
                });
            }

            let mut body_transformed = false;
            if let Some(mut session) = preflight.session {
                let original_body = body.clone();
                let mut output = Vec::new();
                let unit_limit = session.stream_unit_limit();
                let mut failed = None;
                for chunk in body.chunks(unit_limit) {
                    match session.push_body(chunk.to_vec()) {
                        Ok(units) => output.extend(units),
                        Err(error) => {
                            failed = Some(error);
                            break;
                        }
                    }
                }
                if let Some(error) = failed {
                    findings.extend(error.diagnostics.findings);
                    metadata.extend(error.diagnostics.metadata);
                    applied.push(MiddlewareInvocation {
                        name: entry.entry.name.clone(),
                        implementation: entry.entry.implementation.clone(),
                        decision: Decision::Deny,
                        transformed: false,
                        failed: error.denial.is_none(),
                    });
                    return Ok(ChainOutcome {
                        allowed: false,
                        reason: error.reason,
                        body: original_body,
                        header_mutations,
                        findings,
                        metadata,
                        applied,
                        denial: error.denial,
                    });
                }
                match session.finish(Vec::new()).await {
                    Ok(finish) => {
                        output.extend(finish.body_units);
                        body_transformed = finish.body_transformed;
                        stage_failed |= finish.invocations.iter().any(|item| item.failed);
                        findings.extend(finish.findings);
                        metadata.extend(finish.metadata);
                        body = output.concat();
                    }
                    Err(error) => {
                        findings.extend(error.diagnostics.findings);
                        metadata.extend(error.diagnostics.metadata);
                        applied.push(MiddlewareInvocation {
                            name: entry.entry.name.clone(),
                            implementation: entry.entry.implementation.clone(),
                            decision: Decision::Deny,
                            transformed: false,
                            failed: error.denial.is_none(),
                        });
                        return Ok(ChainOutcome {
                            allowed: false,
                            reason: error.reason,
                            body: original_body,
                            header_mutations,
                            findings,
                            metadata,
                            applied,
                            denial: error.denial,
                        });
                    }
                }
            }

            applied.push(MiddlewareInvocation {
                name: entry.entry.name.clone(),
                implementation: entry.entry.implementation.clone(),
                decision: Decision::Allow,
                transformed: body_transformed || headers_transformed,
                failed: stage_failed,
            });

            if body_transformed
                && let TransformedBodyPolicy::Reevaluate(validate) = transformed_body_policy
            {
                let denied = match validate(&body) {
                    Ok(reason) => reason,
                    Err(error) => Some(format!(
                        "transformed_body_policy_evaluation_failed: {}",
                        safe_reason(&error.to_string())
                    )),
                };
                if let Some(reason) = denied {
                    return Ok(ChainOutcome {
                        allowed: false,
                        reason,
                        body,
                        header_mutations,
                        findings,
                        metadata,
                        applied,
                        denial: None,
                    });
                }
            }
        }

        Ok(ChainOutcome {
            allowed: true,
            reason: String::new(),
            body,
            header_mutations,
            findings,
            metadata,
            applied,
            denial: None,
        })
    }
}

/// Sort middleware by policy-defined priority. Valid policies have unique order
/// values; the name comparison only keeps direct internal callers deterministic.
pub fn sort_chain_entries(entries: &mut [ChainEntry]) {
    entries.sort_by(|left, right| {
        left.order
            .cmp(&right.order)
            .then_with(|| left.name.cmp(&right.name))
    });
}

fn ensure_config_capacity(count: usize) -> Result<()> {
    if count > MAX_MIDDLEWARE_CONFIGS {
        return Err(miette!(
            "middleware config count {count} exceeds platform maximum {MAX_MIDDLEWARE_CONFIGS}"
        ));
    }
    Ok(())
}

fn ensure_chain_capacity(count: usize) -> Result<()> {
    if count > MAX_MIDDLEWARE_CHAIN_STAGES {
        return Err(miette!(
            "selected middleware stage count {count} exceeds platform maximum {MAX_MIDDLEWARE_CHAIN_STAGES}"
        ));
    }
    Ok(())
}

pub(crate) fn safe_reason(reason: &str) -> String {
    reason
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | ':' | ' '))
        .take(160)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::HttpBodyMode;

    fn binding(
        operation: SupervisorMiddlewareOperation,
        phase: SupervisorMiddlewarePhase,
        modes: Vec<HttpBodyMode>,
    ) -> MiddlewareBinding {
        MiddlewareBinding {
            operation: operation as i32,
            phase: phase as i32,
            max_payload_bytes: 1024,
            request_timeout: None,
            http_protocol_version: u32::from(matches!(
                operation,
                SupervisorMiddlewareOperation::HttpRequest
                    | SupervisorMiddlewareOperation::HttpResponse
            )),
            supported_http_body_modes: modes.into_iter().map(i32::from).collect(),
        }
    }

    fn manifest(binding: MiddlewareBinding) -> MiddlewareManifest {
        MiddlewareManifest {
            name: "test/middleware".into(),
            service_version: "1".into(),
            bindings: vec![binding],
            expected_audience: String::new(),
            extension: Some(openshell_core::extension_protocol::extension_metadata(
                ExtensionFamily::SupervisorMiddleware,
                "openshell/test-middleware",
                "test",
                [],
            )),
        }
    }

    #[test]
    fn accepts_two_mode_http_capabilities() {
        for operation in [
            SupervisorMiddlewareOperation::HttpRequest,
            SupervisorMiddlewareOperation::HttpResponse,
        ] {
            let phase = if operation == SupervisorMiddlewareOperation::HttpRequest {
                SupervisorMiddlewarePhase::PreCredentials
            } else {
                SupervisorMiddlewarePhase::PreReturn
            };
            validate_manifest_bindings(
                "test service",
                &manifest(binding(
                    operation,
                    phase,
                    vec![HttpBodyMode::Buffered, HttpBodyMode::Stream],
                )),
                None,
            )
            .expect("valid HTTP capability");
        }
    }

    #[test]
    fn rejects_missing_http_protocol_version() {
        let mut candidate = binding(
            SupervisorMiddlewareOperation::HttpRequest,
            SupervisorMiddlewarePhase::PreCredentials,
            vec![HttpBodyMode::Buffered],
        );
        candidate.http_protocol_version = 0;
        assert!(
            validate_manifest_bindings("test service", &manifest(candidate), None)
                .unwrap_err()
                .to_string()
                .contains("protocol version 1")
        );
    }

    #[test]
    fn accepts_preflight_only_http_capability_without_payload_limit() {
        for operation in [
            SupervisorMiddlewareOperation::HttpRequest,
            SupervisorMiddlewareOperation::HttpResponse,
        ] {
            let phase = if operation == SupervisorMiddlewareOperation::HttpRequest {
                SupervisorMiddlewarePhase::PreCredentials
            } else {
                SupervisorMiddlewarePhase::PreReturn
            };
            let mut candidate = binding(operation, phase, Vec::new());
            candidate.max_payload_bytes = 0;
            for operator_limit in [None, Some(0), Some(4096)] {
                validate_manifest_bindings(
                    "test service",
                    &manifest(candidate.clone()),
                    operator_limit,
                )
                .expect("valid preflight-only HTTP capability");
            }
        }
    }

    #[test]
    fn payload_bearing_binding_requires_non_zero_payload_limit() {
        for mut candidate in [
            binding(
                SupervisorMiddlewareOperation::HttpRequest,
                SupervisorMiddlewarePhase::PreCredentials,
                vec![HttpBodyMode::Buffered],
            ),
            binding(
                SupervisorMiddlewareOperation::WebsocketMessage,
                SupervisorMiddlewarePhase::PreCredentials,
                Vec::new(),
            ),
        ] {
            candidate.max_payload_bytes = 0;
            assert!(
                validate_manifest_bindings("test service", &manifest(candidate), None)
                    .unwrap_err()
                    .to_string()
                    .contains("non-zero payload limit")
            );
        }
    }

    #[test]
    fn rejects_duplicate_or_unspecified_body_modes() {
        for modes in [
            vec![HttpBodyMode::Buffered, HttpBodyMode::Buffered],
            vec![HttpBodyMode::Unspecified],
        ] {
            let candidate = binding(
                SupervisorMiddlewareOperation::HttpRequest,
                SupervisorMiddlewarePhase::PreCredentials,
                modes,
            );
            assert!(
                validate_manifest_bindings("test service", &manifest(candidate), None)
                    .unwrap_err()
                    .to_string()
                    .contains("invalid or duplicate")
            );
        }
    }

    #[test]
    fn websocket_binding_cannot_advertise_http_capabilities() {
        let mut candidate = binding(
            SupervisorMiddlewareOperation::WebsocketMessage,
            SupervisorMiddlewarePhase::PreCredentials,
            Vec::new(),
        );
        validate_manifest_bindings("test service", &manifest(candidate.clone()), None)
            .expect("plain WebSocket binding");

        candidate.http_protocol_version = 1;
        candidate.supported_http_body_modes = vec![HttpBodyMode::Buffered as i32];
        assert!(
            validate_manifest_bindings("test service", &manifest(candidate), None)
                .unwrap_err()
                .to_string()
                .contains("WebSocket binding")
        );
    }

    #[test]
    fn rejects_removed_post_credentials_phase_number() {
        let mut candidate = binding(
            SupervisorMiddlewareOperation::HttpRequest,
            SupervisorMiddlewarePhase::PreCredentials,
            vec![HttpBodyMode::Buffered],
        );
        candidate.phase = 3;
        assert!(
            validate_manifest_bindings("test service", &manifest(candidate), None)
                .unwrap_err()
                .to_string()
                .contains("unsupported")
        );
    }

    #[test]
    fn external_body_phase_failures_use_platform_owned_diagnostics() {
        let status = tonic::Status::internal("operator detail with request content");
        assert_eq!(
            MiddlewareDiagnosticPolicy::Normalize.error_reason(&status),
            "external_service_error"
        );

        let mutation = headers::HeaderMutationError::Protected {
            name: "set-cookie".into(),
        };
        assert_eq!(
            MiddlewareDiagnosticPolicy::Normalize.header_mutation_error_reason(&mutation),
            "header_mutation_protected_header"
        );
        assert!(
            MiddlewareDiagnosticPolicy::Preserve
                .header_mutation_error_reason(&mutation)
                .contains("set-cookie")
        );
    }
}
