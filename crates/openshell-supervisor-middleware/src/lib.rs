// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor middleware registration and chain execution.

mod headers;
mod remote;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use miette::{Result, miette};
use prost::Message;

use openshell_core::proto::{
    Decision, Finding, HeaderMutation, HttpHeader, HttpRequestTarget, MiddlewareBinding,
    MiddlewareManifest, NetworkMiddlewareConfig, RequestContext, SandboxPolicy,
    SupervisorMiddlewareOperation, SupervisorMiddlewarePhase, SupervisorMiddlewareService,
    ValidateConfigResponse,
};
use tokio::sync::OnceCell;

#[cfg(test)]
use openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddleware;
#[cfg(test)]
use openshell_core::proto::{HttpRequestEvaluation, ValidateConfigRequest};
#[cfg(test)]
use tonic::Request;

pub use openshell_core::middleware::{
    DEFAULT_MIDDLEWARE_TIMEOUT, HttpRequestView, InProcessMiddleware,
    MAX_MIDDLEWARE_CHAIN_FINDINGS, MAX_MIDDLEWARE_CHAIN_STAGES, MAX_MIDDLEWARE_CONFIGS,
    MAX_MIDDLEWARE_FINDINGS_PER_STAGE, MAX_MIDDLEWARE_SELECTOR_PATTERNS, MAX_MIDDLEWARE_TIMEOUT,
    MIN_MIDDLEWARE_TIMEOUT, middleware_timeout_or_default, parse_middleware_timeout,
};

/// Largest request or replacement body accepted by the middleware platform.
pub const MAX_MIDDLEWARE_BODY_BYTES: usize = 4 * 1024 * 1024;
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
/// gRPC envelope headroom derived from every bounded non-body component.
pub const MIDDLEWARE_GRPC_ENVELOPE_BYTES: usize =
    if MAX_MIDDLEWARE_REQUEST_ENVELOPE_BYTES > MAX_MIDDLEWARE_RESPONSE_ENVELOPE_BYTES {
        MAX_MIDDLEWARE_REQUEST_ENVELOPE_BYTES
    } else {
        MAX_MIDDLEWARE_RESPONSE_ENVELOPE_BYTES
    };
/// gRPC message limit derived from the body and bounded protobuf components.
pub const MIDDLEWARE_GRPC_MESSAGE_BYTES: usize =
    MAX_MIDDLEWARE_BODY_BYTES + MIDDLEWARE_GRPC_ENVELOPE_BYTES;

const HTTP_REQUEST_OPERATION: SupervisorMiddlewareOperation =
    SupervisorMiddlewareOperation::HttpRequest;
const PRE_CREDENTIALS_PHASE: SupervisorMiddlewarePhase = SupervisorMiddlewarePhase::PreCredentials;
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
/// service's `Describe` call. A missing binding is retained so `on_error` can
/// decide whether the request fails open or closed.
#[derive(Clone)]
pub struct DescribedChainEntry {
    entry: ChainEntry,
    service: Option<Arc<MiddlewareServiceState>>,
    binding: Option<MiddlewareBinding>,
    max_body_bytes: usize,
    timeout: Duration,
}

impl DescribedChainEntry {
    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
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
    /// imposes no body-buffering limit on the chain.
    pub fn is_resolved(&self) -> bool {
        self.binding.is_some()
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

enum OnErrorAction {
    /// `fail_open`: skip this middleware, leaving the request unchanged.
    FailOpen,
    /// `fail_closed`: short-circuit the chain and deny with the given reason.
    FailClosed(String),
}

/// Apply a middleware entry's `on_error` policy after a failure (service error or
/// malformed response). Records a `failed` invocation for telemetry in both cases.
fn apply_on_error(
    entry: &DescribedChainEntry,
    reason: &str,
    applied: &mut Vec<MiddlewareInvocation>,
) -> OnErrorAction {
    match entry.entry.on_error {
        OnError::FailOpen => {
            applied.push(MiddlewareInvocation {
                name: entry.entry.name.clone(),
                implementation: entry.entry.implementation.clone(),
                decision: Decision::Allow,
                transformed: false,
                failed: true,
            });
            OnErrorAction::FailOpen
        }
        OnError::FailClosed => {
            applied.push(MiddlewareInvocation {
                name: entry.entry.name.clone(),
                implementation: entry.entry.implementation.clone(),
                decision: Decision::Deny,
                transformed: false,
                failed: true,
            });
            OnErrorAction::FailClosed(format!("middleware_failed: {reason}"))
        }
    }
}

#[derive(Clone)]
pub struct ChainRunner {
    registry: Arc<MiddlewareRegistry>,
}

enum MiddlewareService {
    /// Built-ins borrow the current request state and never construct protobuf.
    InProcess(Arc<dyn InProcessMiddleware>),
    /// Operator services receive an owned protobuf through the gRPC adapter.
    Grpc(remote::GrpcMiddlewareService),
}

impl MiddlewareService {
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

    async fn evaluate_http_request(
        &self,
        request: HttpRequestView<'_>,
    ) -> std::result::Result<tonic::Response<openshell_core::proto::HttpRequestResult>, tonic::Status>
    {
        match self {
            Self::InProcess(service) => service
                .evaluate_http_request(request)
                .await
                .map(tonic::Response::new)
                .map_err(|error| tonic::Status::invalid_argument(error.to_string())),
            Self::Grpc(service) => service.evaluate_http_request(request).await,
        }
    }
}

struct MiddlewareServiceState {
    /// Policy-facing built-in name or operator-owned registration name. The
    /// single-service test constructor leaves this empty and uses the manifest
    /// name after Describe.
    attachment_name: Option<String>,
    service: MiddlewareService,
    manifest: OnceCell<MiddlewareManifest>,
    diagnostic_policy: MiddlewareDiagnosticPolicy,
    operator_max_body_bytes: Option<usize>,
    operator_timeout: Duration,
}

impl MiddlewareServiceState {
    fn timeout_for_binding(&self, binding: &MiddlewareBinding) -> Result<Duration> {
        if binding.timeout.trim().is_empty() {
            Ok(self.operator_timeout)
        } else {
            parse_middleware_timeout(&binding.timeout)
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

    fn process_result(
        self,
        middleware_name: &str,
        result: &mut openshell_core::proto::HttpRequestResult,
    ) {
        if self == Self::Normalize {
            normalize_untrusted_diagnostics(middleware_name, result);
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
}

impl std::fmt::Debug for MiddlewareRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MiddlewareRegistry")
            .field("service_count", &self.services.len())
            .field("registered_service_count", &self.registered_services.len())
            .field("middleware_count", &self.middleware_names.len())
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
        }
    }
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
    if registration.max_body_bytes == 0 {
        return Err(miette!(
            "middleware registration '{}' max_body_bytes must be greater than zero",
            registration.name
        ));
    }
    if registration.max_body_bytes > MAX_MIDDLEWARE_BODY_BYTES as u64 {
        return Err(miette!(
            "middleware registration '{}' max_body_bytes exceeds the platform maximum of {MAX_MIDDLEWARE_BODY_BYTES}",
            registration.name
        ));
    }
    middleware_timeout_or_default(&registration.timeout).map_err(|reason| {
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

fn validate_body_limit(source: &str, binding: &MiddlewareBinding) -> Result<usize> {
    if binding.max_body_bytes == 0 {
        return Err(miette!("{source} must advertise a non-zero body limit"));
    }
    if binding.max_body_bytes > MAX_MIDDLEWARE_BODY_BYTES as u64 {
        return Err(miette!(
            "{source} body limit exceeds the platform maximum of {MAX_MIDDLEWARE_BODY_BYTES}"
        ));
    }
    usize::try_from(binding.max_body_bytes)
        .map_err(|_| miette!("{source} reports a body limit too large for this platform"))
}

fn validate_manifest_bindings(
    source: &str,
    manifest: &MiddlewareManifest,
    operator_max_body_bytes: Option<usize>,
) -> Result<()> {
    if manifest.bindings.is_empty() {
        return Err(miette!("{source} describes no bindings"));
    }

    let mut described_pairs = HashSet::with_capacity(manifest.bindings.len());
    for binding in &manifest.bindings {
        if binding.operation != HTTP_REQUEST_OPERATION as i32
            || binding.phase != PRE_CREDENTIALS_PHASE as i32
        {
            return Err(miette!(
                "{source} must support HTTP_REQUEST/PRE_CREDENTIALS"
            ));
        }
        if !described_pairs.insert((binding.operation, binding.phase)) {
            return Err(miette!(
                "{source} describes more than one binding for HTTP_REQUEST/PRE_CREDENTIALS"
            ));
        }
        let advertised = validate_body_limit(source, binding)?;
        if !binding.timeout.trim().is_empty() {
            parse_middleware_timeout(&binding.timeout)
                .map_err(|reason| miette!("{source} has invalid timeout for binding: {reason}"))?;
        }
        if operator_max_body_bytes.is_some_and(|limit| limit > advertised) {
            return Err(miette!(
                "{source} max_body_bytes ({}) exceeds the binding capability ({advertised})",
                operator_max_body_bytes.expect("operator limit checked above")
            ));
        }
    }
    Ok(())
}

fn validate_external_manifest(
    registration: &SupervisorMiddlewareService,
    manifest: &MiddlewareManifest,
    operator_max_body_bytes: usize,
    authenticated: bool,
) -> Result<()> {
    validate_manifest_bindings(
        &format!("external middleware registration '{}'", registration.name),
        manifest,
        Some(operator_max_body_bytes),
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

/// External diagnostic text is untrusted and may contain request data. Keep
/// only values derived from the validated, operator-owned registration name
/// and numeric finding counts; do not carry per-request free-form text into
/// logs.
fn normalize_untrusted_diagnostics(
    middleware_name: &str,
    result: &mut openshell_core::proto::HttpRequestResult,
) {
    let reason_id: String = middleware_name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .collect();
    result.reason = format!("middleware_denied:{reason_id}");
    result.metadata.clear();
    for finding in &mut result.findings {
        finding.r#type = format!("{middleware_name}.finding");
        finding.label = EXTERNAL_FINDING_LABEL.to_string();
        finding.confidence.clear();
        finding.severity = match finding.severity.as_str() {
            "low" => "low",
            "high" => "high",
            _ => "medium",
        }
        .to_string();
    }
}

fn validate_request_view(request: HttpRequestView<'_>) -> std::result::Result<(), &'static str> {
    if request.body().len() > MAX_MIDDLEWARE_BODY_BYTES {
        return Err("request_body_over_capacity");
    }
    if request.config().encoded_len() > MAX_MIDDLEWARE_CONFIG_BYTES {
        return Err("request_config_over_capacity");
    }
    if request.context().encoded_len() > MAX_MIDDLEWARE_CONTEXT_BYTES {
        return Err("request_context_over_capacity");
    }
    if request.target().encoded_len() > MAX_MIDDLEWARE_TARGET_BYTES {
        return Err("request_target_over_capacity");
    }
    if request.headers().len() > MAX_MIDDLEWARE_HEADERS {
        return Err("request_header_count_over_capacity");
    }
    let header_bytes = request.headers().iter().fold(0usize, |total, header| {
        total.saturating_add(header.encoded_len())
    });
    if header_bytes > MAX_MIDDLEWARE_HEADER_BYTES {
        return Err("request_header_bytes_over_capacity");
    }
    Ok(())
}

fn validate_response_envelope(
    result: &openshell_core::proto::HttpRequestResult,
) -> std::result::Result<(), &'static str> {
    if result.body.len() > MAX_MIDDLEWARE_BODY_BYTES {
        return Err("response_body_over_capacity");
    }
    if result.reason.len() > MAX_MIDDLEWARE_REASON_BYTES {
        return Err("response_reason_over_capacity");
    }
    if !result.reason_code.is_empty() && !is_stable_reason_code(&result.reason_code) {
        return Err("response_reason_code_invalid");
    }
    if result.header_mutations.len() > headers::MAX_HEADER_MUTATIONS {
        return Err("header_mutation_count_over_capacity");
    }
    let mutation_bytes = result
        .header_mutations
        .iter()
        .fold(0usize, |total, mutation| {
            total.saturating_add(mutation.encoded_len())
        });
    if mutation_bytes > MAX_MIDDLEWARE_HEADER_MUTATION_WIRE_BYTES {
        return Err("header_mutation_bytes_over_capacity");
    }
    if result.findings.len() > MAX_MIDDLEWARE_FINDINGS_PER_STAGE {
        return Err("response_findings_over_capacity");
    }
    if result
        .findings
        .iter()
        .any(|finding| finding.encoded_len() > MAX_MIDDLEWARE_FINDING_BYTES)
    {
        return Err("response_finding_over_capacity");
    }
    if result.metadata.len() > MAX_MIDDLEWARE_METADATA_ENTRIES {
        return Err("response_metadata_count_over_capacity");
    }
    let metadata_bytes = result.metadata.iter().fold(0usize, |total, (key, value)| {
        total.saturating_add(key.len()).saturating_add(value.len())
    });
    if metadata_bytes > MAX_MIDDLEWARE_METADATA_BYTES {
        return Err("response_metadata_bytes_over_capacity");
    }
    if result.encoded_len() > MIDDLEWARE_GRPC_MESSAGE_BYTES {
        return Err("response_envelope_over_capacity");
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

        for service in in_process_services {
            let service = MiddlewareService::InProcess(service);
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
                operator_max_body_bytes: None,
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

            let operator_max_body_bytes =
                usize::try_from(registration.max_body_bytes).map_err(|_| {
                    miette!(
                        "middleware registration '{}' body limit is too large for this platform",
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
            let service = MiddlewareService::Grpc(
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
                operator_max_body_bytes,
                authenticated,
            )?;
            let manifest_cell = OnceCell::new();
            manifest_cell
                .set(manifest)
                .map_err(|_| miette!("middleware manifest cache initialized twice"))?;
            services.push(Arc::new(MiddlewareServiceState {
                attachment_name: Some(registration.name.clone()),
                service,
                manifest: manifest_cell,
                diagnostic_policy: MiddlewareDiagnosticPolicy::Normalize,
                operator_max_body_bytes: Some(operator_max_body_bytes),
                operator_timeout,
            }));
            registered_services.push(RegisteredMiddlewareService { registration });
        }

        Ok(Self {
            services: Arc::new(services),
            registered_services: Arc::new(registered_services),
            middleware_names: Arc::new(middleware_names),
        })
    }

    /// Validate implementation-owned configuration for every middleware entry.
    pub async fn validate_policy_configs(&self, policy: &SandboxPolicy) -> Result<()> {
        ensure_config_capacity(policy.network_middlewares.len())?;
        let runner = ChainRunner::from_registry(self.clone());
        for (name, config) in &policy.network_middlewares {
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
        Self::from_service(MiddlewareService::InProcess(service))
    }

    fn from_service(service: MiddlewareService) -> Self {
        Self {
            registry: Arc::new(MiddlewareRegistry {
                services: Arc::new(vec![Arc::new(MiddlewareServiceState {
                    attachment_name: None,
                    service,
                    manifest: OnceCell::new(),
                    diagnostic_policy: MiddlewareDiagnosticPolicy::Preserve,
                    operator_max_body_bytes: None,
                    operator_timeout: DEFAULT_MIDDLEWARE_TIMEOUT,
                })]),
                registered_services: Arc::new(Vec::new()),
                middleware_names: Arc::new(HashSet::new()),
            }),
        }
    }

    #[cfg(test)]
    fn new_protobuf_for_tests(service: Arc<dyn SupervisorMiddleware>) -> Self {
        Self::from_service(MiddlewareService::Grpc(
            remote::GrpcMiddlewareService::from_service(service),
        ))
    }

    pub fn from_registry(registry: MiddlewareRegistry) -> Self {
        Self {
            registry: Arc::new(registry),
        }
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

    fn http_pre_credentials_binding(manifest: &MiddlewareManifest) -> Option<&MiddlewareBinding> {
        manifest.bindings.iter().find(|binding| {
            binding.operation == HTTP_REQUEST_OPERATION as i32
                && binding.phase == PRE_CREDENTIALS_PHASE as i32
        })
    }

    pub async fn describe_chain(&self, entries: &[ChainEntry]) -> Result<Vec<DescribedChainEntry>> {
        ensure_chain_capacity(entries.len())?;
        let manifests = self.manifests().await?;
        let mut entries = entries.to_vec();
        sort_chain_entries(&mut entries);
        entries
            .iter()
            .map(|entry| {
                let described = manifests
                    .iter()
                    .find(|(state, manifest)| {
                        Self::attachment_name(state, manifest) == entry.implementation
                    })
                    .and_then(|(state, manifest)| {
                        Self::http_pre_credentials_binding(manifest)
                            .cloned()
                            .map(|binding| (Arc::clone(state), binding))
                    });
                let (service, binding) = described.map_or((None, None), |(service, binding)| {
                    (Some(service), Some(binding))
                });
                let max_body_bytes = binding
                    .as_ref()
                    .map(|binding| {
                        let advertised = validate_body_limit("middleware manifest", binding)?;
                        Ok::<_, miette::Report>(
                            service
                                .as_ref()
                                .and_then(|state| state.operator_max_body_bytes)
                                .unwrap_or(advertised),
                        )
                    })
                    .transpose()?
                    .unwrap_or(0);
                let timeout = service
                    .as_ref()
                    .zip(binding.as_ref())
                    .map(|(state, binding)| state.timeout_for_binding(binding))
                    .transpose()?
                    .unwrap_or(DEFAULT_MIDDLEWARE_TIMEOUT);
                Ok(DescribedChainEntry {
                    entry: entry.clone(),
                    service,
                    binding,
                    max_body_bytes,
                    timeout,
                })
            })
            .collect()
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
        let Some((state, binding)) = manifests.iter().find_map(|(state, manifest)| {
            (Self::attachment_name(state, manifest) == middleware_name)
                .then(|| Self::http_pre_credentials_binding(manifest))
                .flatten()
                .map(|binding| (state, binding))
        }) else {
            return Err(miette!("middleware '{middleware_name}' is not registered"));
        };
        let response = call_with_timeout(
            state.timeout_for_binding(binding)?,
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
        ensure_chain_capacity(entries.len())?;
        let HttpRequestInput {
            request_id,
            sandbox_id,
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
        // The request envelope is moved into one stable chain state. Built-ins
        // borrow these values for every stage; only the gRPC adapter clones them
        // when an operator service requires an owned protobuf message.
        let context = RequestContext {
            request_id,
            sandbox_id,
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
        let mut headers: Vec<HttpHeader> = headers
            .into_iter()
            .map(|(name, value)| HttpHeader { name, value })
            .collect();
        let mut body = body;
        let mut header_mutations = Vec::new();
        let mut findings = Vec::new();
        let mut metadata = BTreeMap::new();
        let mut applied = Vec::new();

        for entry in entries {
            let Some(_binding) = entry.binding.as_ref() else {
                match apply_on_error(entry, "binding_not_described", &mut applied) {
                    OnErrorAction::FailOpen => continue,
                    OnErrorAction::FailClosed(reason) => {
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
            };
            if body.len() > entry.max_body_bytes {
                match apply_on_error(entry, "request_body_over_capacity", &mut applied) {
                    OnErrorAction::FailOpen => continue,
                    OnErrorAction::FailClosed(reason) => {
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
            let request = HttpRequestView::new(
                PRE_CREDENTIALS_PHASE,
                &context,
                &entry.entry.config,
                &target,
                &headers,
                &body,
                &entry.entry.implementation,
            );
            if let Err(reason) = validate_request_view(request) {
                match apply_on_error(entry, reason, &mut applied) {
                    OnErrorAction::FailOpen => continue,
                    OnErrorAction::FailClosed(reason) => {
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
            let Some(service) = entry.service.as_ref() else {
                unreachable!("described binding always has a service")
            };
            let mut result = match call_with_timeout(
                entry.timeout,
                "EvaluateHttpRequest",
                service.service.evaluate_http_request(request),
            )
            .await
            {
                Ok(result) => result.into_inner(),
                Err(err) => {
                    let reason = if err.code() == tonic::Code::DeadlineExceeded {
                        "middleware_timeout".to_string()
                    } else {
                        service.diagnostic_policy.error_reason(&err)
                    };
                    match apply_on_error(entry, &reason, &mut applied) {
                        OnErrorAction::FailOpen => continue,
                        OnErrorAction::FailClosed(reason) => {
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
            };

            if let Err(reason) = validate_response_envelope(&result) {
                match apply_on_error(entry, reason, &mut applied) {
                    OnErrorAction::FailOpen => continue,
                    OnErrorAction::FailClosed(reason) => {
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

            service
                .diagnostic_policy
                .process_result(&entry.entry.implementation, &mut result);

            let decision = match Decision::try_from(result.decision) {
                Ok(decision @ (Decision::Allow | Decision::Deny)) => decision,
                Ok(Decision::Unspecified) | Err(_) => {
                    match apply_on_error(entry, "invalid_response_decision", &mut applied) {
                        OnErrorAction::FailOpen => continue,
                        OnErrorAction::FailClosed(reason) => {
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
            };

            if decision == Decision::Deny {
                let reason_code =
                    (!result.reason_code.is_empty()).then(|| result.reason_code.clone());
                let denial = MiddlewareDenial {
                    config_name: entry.entry.name.clone(),
                    reason_code,
                };
                for finding in result.findings {
                    findings.push(NamespacedFinding {
                        middleware: entry.entry.name.clone(),
                        finding,
                    });
                }
                if !result.metadata.is_empty() {
                    metadata.insert(
                        entry.entry.name.clone(),
                        result.metadata.into_iter().collect(),
                    );
                }
                applied.push(MiddlewareInvocation {
                    name: entry.entry.name.clone(),
                    implementation: entry.entry.implementation.clone(),
                    decision,
                    transformed: false,
                    failed: false,
                });
                return Ok(ChainOutcome {
                    allowed: false,
                    reason: middleware_denial_reason(
                        &denial.config_name,
                        denial.reason_code.as_deref(),
                    ),
                    body,
                    header_mutations,
                    findings,
                    metadata,
                    applied,
                    denial: Some(denial),
                });
            }

            if result.has_body && result.body.len() > entry.max_body_bytes {
                match apply_on_error(entry, "response_body_over_capacity", &mut applied) {
                    OnErrorAction::FailOpen => continue,
                    OnErrorAction::FailClosed(reason) => {
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

            // Validate and apply the entire stage atomically. Under fail-open,
            // one malformed mutation must not leave earlier mutations from the
            // same response visible to later middleware.
            let updated_headers = if result.header_mutations.is_empty() {
                None
            } else {
                match headers::apply(
                    &headers,
                    &connection_nominated_headers,
                    &result.header_mutations,
                ) {
                    Ok(updated) => Some(updated),
                    Err(error) => {
                        let reason = service
                            .diagnostic_policy
                            .header_mutation_error_reason(&error);
                        match apply_on_error(entry, &reason, &mut applied) {
                            OnErrorAction::FailOpen => continue,
                            OnErrorAction::FailClosed(reason) => {
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
                }
            };
            let headers_transformed = updated_headers
                .as_ref()
                .is_some_and(|updated| updated != &headers);
            if let Some(updated) = updated_headers {
                headers = updated;
            }
            header_mutations.extend(std::mem::take(&mut result.header_mutations));

            let body_transformed = result.has_body;
            if body_transformed {
                body = std::mem::take(&mut result.body);
            }
            for finding in result.findings {
                findings.push(NamespacedFinding {
                    middleware: entry.entry.name.clone(),
                    finding,
                });
            }
            if !result.metadata.is_empty() {
                metadata.insert(
                    entry.entry.name.clone(),
                    result.metadata.into_iter().collect(),
                );
            }
            applied.push(MiddlewareInvocation {
                name: entry.entry.name.clone(),
                implementation: entry.entry.implementation.clone(),
                decision,
                transformed: body_transformed || headers_transformed,
                failed: false,
            });

            // The stage ran successfully but its output must still satisfy the
            // sandbox policy the original body was admitted under. Re-check now,
            // before the next stage or the upstream sees the replaced body. A
            // policy deny here is a hard deny, independent of `on_error`.
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
    use openshell_core::proto::middleware::v1::supervisor_middleware_server::{
        SupervisorMiddleware, SupervisorMiddlewareServer,
    };
    use openshell_core::proto::{ExistingHeaderAction, header_mutation};
    use openshell_supervisor_middleware_builtins::{BUILTIN_REGEX, services};
    use tokio_stream::wrappers::TcpListenerStream;

    #[test]
    fn advertised_audience_mismatch_fails_registration() {
        let configured = "urn:openshell:extension:middleware:content-guard";

        // Matching and unadvertised audiences both pass.
        validate_expected_audience("content-guard", configured, "", true)
            .expect("unadvertised audience is accepted");
        validate_expected_audience("content-guard", configured, configured, true)
            .expect("matching audience is accepted");

        // Once authenticated Describe succeeds, reject a manifest that
        // contradicts the operator-owned audience configuration.
        let error =
            validate_expected_audience("content-guard", configured, "urn:example:stale", true)
                .expect_err("mismatched audience must fail closed");
        let message = error.to_string();
        assert!(message.contains("urn:example:stale"));
        assert!(message.contains(configured));

        // The check does not apply where no credential is attached at all,
        // whether because the registration opted out or because the gateway
        // has no signing key configured.
        validate_expected_audience("content-guard", configured, "urn:example:stale", false)
            .expect("an unauthenticated call has no audience to mismatch");
    }

    fn builtin_runner() -> ChainRunner {
        ChainRunner::new(
            services()
                .into_iter()
                .next()
                .expect("built-in middleware service"),
        )
    }

    fn entry(name: &str, on_error: OnError) -> ChainEntry {
        ChainEntry {
            name: name.into(),
            implementation: BUILTIN_REGEX.into(),
            order: 0,
            config: prost_types::Struct {
                fields: std::iter::once((
                    "mode".into(),
                    prost_types::Value {
                        kind: Some(prost_types::value::Kind::StringValue("redact".into())),
                    },
                ))
                .collect(),
            },
            on_error,
        }
    }

    fn input(body: &str) -> HttpRequestInput {
        HttpRequestInput {
            request_id: "req".into(),
            sandbox_id: "sbx".into(),
            scheme: "https".into(),
            host: "api.example.com".into(),
            port: 443,
            method: "POST".into(),
            path: "/v1".into(),
            query: String::new(),
            headers: Vec::new(),
            connection_nominated_headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    fn write_header(name: &str, value: &str, on_existing: ExistingHeaderAction) -> HeaderMutation {
        HeaderMutation {
            operation: Some(header_mutation::Operation::Write(
                openshell_core::proto::WriteHeader {
                    name: name.into(),
                    value: value.into(),
                    on_existing: on_existing as i32,
                },
            )),
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RequestAddresses {
        phase: SupervisorMiddlewarePhase,
        context: usize,
        request_id: usize,
        config: usize,
        target: usize,
        host: usize,
        headers: usize,
        first_header_name: usize,
        body: usize,
        originating_process_present: bool,
        middleware_name: String,
    }

    /// Records borrowed addresses so the test can detect an owned envelope
    /// being reconstructed between otherwise no-op in-process stages.
    struct BorrowedRecordingService {
        manifest_name: String,
        received: std::sync::Mutex<Vec<RequestAddresses>>,
    }

    #[tonic::async_trait]
    impl InProcessMiddleware for BorrowedRecordingService {
        async fn describe(&self) -> MiddlewareManifest {
            MiddlewareManifest {
                name: self.manifest_name.clone(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_body_bytes: 4096,
                    timeout: String::new(),
                }],
                expected_audience: String::new(),
            }
        }

        async fn validate_config(
            &self,
            _middleware_name: &str,
            _config: &prost_types::Struct,
        ) -> Result<()> {
            Ok(())
        }

        async fn evaluate_http_request(
            &self,
            request: HttpRequestView<'_>,
        ) -> Result<openshell_core::proto::HttpRequestResult> {
            let addresses = RequestAddresses {
                phase: request.phase(),
                context: std::ptr::from_ref(request.context()).addr(),
                request_id: request.context().request_id.as_ptr().addr(),
                config: std::ptr::from_ref(request.config()).addr(),
                target: std::ptr::from_ref(request.target()).addr(),
                host: request.target().host.as_ptr().addr(),
                headers: request.headers().as_ptr().addr(),
                first_header_name: request
                    .headers()
                    .first()
                    .map_or(0, |header| header.name.as_ptr().addr()),
                body: request.body().as_ptr().addr(),
                originating_process_present: request.context().originating_process.is_some(),
                middleware_name: request.middleware_name().to_string(),
            };
            self.received
                .lock()
                .expect("borrowed request recorder lock")
                .push(addresses);
            Ok(allow_result())
        }
    }

    #[tokio::test]
    async fn in_process_stages_share_one_borrowed_request_envelope() {
        let service = Arc::new(BorrowedRecordingService {
            manifest_name: "acme/redactor".into(),
            received: std::sync::Mutex::new(Vec::new()),
        });
        let runner = ChainRunner::new(service.clone());
        let entries = [
            ChainEntry {
                name: "first".into(),
                implementation: "acme/redactor".into(),
                order: 0,
                config: prost_types::Struct::default(),
                on_error: OnError::FailClosed,
            },
            ChainEntry {
                name: "second".into(),
                implementation: "acme/redactor".into(),
                order: 10,
                config: prost_types::Struct::default(),
                on_error: OnError::FailClosed,
            },
        ];
        let described = runner
            .describe_chain(&entries)
            .await
            .expect("describe chain");
        let expected_configs: Vec<_> = described
            .iter()
            .map(|entry| std::ptr::from_ref(&entry.entry.config).addr())
            .collect();
        let mut request = input("payload");
        request.headers = vec![("x-test".into(), "value".into())];
        let expected_body = request.body.as_ptr().addr();
        let expected_request_id = request.request_id.as_ptr().addr();
        let expected_host = request.host.as_ptr().addr();
        let expected_header_name = request.headers[0].0.as_ptr().addr();

        let outcome = runner
            .evaluate_described(&described, request)
            .await
            .expect("evaluate borrowed chain");
        let received = service.received.lock().expect("borrowed requests");

        assert!(outcome.allowed);
        assert_eq!(outcome.body.as_ptr().addr(), expected_body);
        assert_eq!(received.len(), 2);
        assert_eq!(received[0].phase, SupervisorMiddlewarePhase::PreCredentials);
        assert!(!received[0].originating_process_present);
        assert_eq!(received[0].request_id, expected_request_id);
        assert_eq!(received[0].host, expected_host);
        assert_eq!(received[0].first_header_name, expected_header_name);
        assert_eq!(received[0].body, expected_body);
        assert_eq!(received[0].config, expected_configs[0]);
        assert_eq!(received[1].config, expected_configs[1]);
        assert_eq!(received[0].context, received[1].context);
        assert_eq!(received[0].target, received[1].target);
        assert_eq!(received[0].headers, received[1].headers);
        assert_eq!(received[0].body, received[1].body);
        assert!(
            received
                .iter()
                .all(|request| request.middleware_name == "acme/redactor")
        );
    }

    const TEST_REPLACEMENT_BODY: &[u8] = b"stage-one-replacement";

    /// Records both sides of a successful body replacement so the test can
    /// distinguish ownership transfer from a content-preserving body copy.
    #[derive(Debug, Default)]
    struct ReplacementTransferRecord {
        invocations: usize,
        returned_body: Option<usize>,
        second_body: Option<usize>,
        second_body_bytes: Vec<u8>,
    }

    /// Replaces the first request body and observes the body borrowed by the
    /// second stage without replacing it again.
    struct ReplacementTransferService {
        record: std::sync::Mutex<ReplacementTransferRecord>,
    }

    #[tonic::async_trait]
    impl InProcessMiddleware for ReplacementTransferService {
        async fn describe(&self) -> MiddlewareManifest {
            MiddlewareManifest {
                name: "test/replacement-transfer".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_body_bytes: 4096,
                    timeout: String::new(),
                }],
                expected_audience: String::new(),
            }
        }

        async fn validate_config(
            &self,
            _middleware_name: &str,
            _config: &prost_types::Struct,
        ) -> Result<()> {
            Ok(())
        }

        async fn evaluate_http_request(
            &self,
            request: HttpRequestView<'_>,
        ) -> Result<openshell_core::proto::HttpRequestResult> {
            let mut record = self.record.lock().expect("replacement transfer record");
            let invocation = record.invocations;
            record.invocations += 1;

            if invocation == 0 {
                let replacement = TEST_REPLACEMENT_BODY.to_vec();
                record.returned_body = Some(replacement.as_ptr().addr());
                let mut result = allow_result();
                result.body = replacement;
                result.has_body = true;
                Ok(result)
            } else {
                record.second_body = Some(request.body().as_ptr().addr());
                record.second_body_bytes = request.body().to_vec();
                Ok(allow_result())
            }
        }
    }

    #[tokio::test]
    async fn replacement_body_allocation_moves_through_next_stage_and_outcome() {
        let service = Arc::new(ReplacementTransferService {
            record: std::sync::Mutex::new(ReplacementTransferRecord::default()),
        });
        let runner = ChainRunner::new(service.clone());
        let entries = [
            ChainEntry {
                name: "replace".into(),
                implementation: "test/replacement-transfer".into(),
                order: 0,
                config: prost_types::Struct::default(),
                on_error: OnError::FailClosed,
            },
            ChainEntry {
                name: "observe".into(),
                implementation: "test/replacement-transfer".into(),
                order: 10,
                config: prost_types::Struct::default(),
                on_error: OnError::FailClosed,
            },
        ];

        let outcome = runner
            .evaluate(&entries, input("original-body"))
            .await
            .expect("evaluate replacement transfer chain");
        let record = service.record.lock().expect("replacement transfer record");
        let returned_body = record
            .returned_body
            .expect("first-stage replacement pointer");

        assert!(outcome.allowed);
        assert_eq!(record.invocations, 2);
        assert_eq!(record.second_body_bytes, TEST_REPLACEMENT_BODY);
        assert_eq!(record.second_body, Some(returned_body));
        assert_eq!(outcome.body, TEST_REPLACEMENT_BODY);
        assert_eq!(outcome.body.as_ptr().addr(), returned_body);
    }

    /// An in-process service that yields forever so the runtime must enforce
    /// the binding timeout around borrowed validation and evaluation futures.
    struct PendingInProcessService;

    #[tonic::async_trait]
    impl InProcessMiddleware for PendingInProcessService {
        async fn describe(&self) -> MiddlewareManifest {
            MiddlewareManifest {
                name: "test/pending".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_body_bytes: 4096,
                    timeout: "10ms".into(),
                }],
                expected_audience: String::new(),
            }
        }

        async fn validate_config(
            &self,
            _middleware_name: &str,
            _config: &prost_types::Struct,
        ) -> Result<()> {
            std::future::pending().await
        }

        async fn evaluate_http_request(
            &self,
            _request: HttpRequestView<'_>,
        ) -> Result<openshell_core::proto::HttpRequestResult> {
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn in_process_evaluation_remains_interruptible_by_stage_timeout() {
        let runner = ChainRunner::new(Arc::new(PendingInProcessService));
        let entry = |on_error| ChainEntry {
            name: "pending".into(),
            implementation: "test/pending".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error,
        };
        let closed = runner
            .evaluate(&[entry(OnError::FailClosed)], input("payload"))
            .await
            .expect("timed-out in-process evaluation");
        let open = runner
            .evaluate(&[entry(OnError::FailOpen)], input("payload"))
            .await
            .expect("fail-open timed-out in-process evaluation");

        assert!(!closed.allowed);
        assert_eq!(closed.reason, "middleware_failed: middleware_timeout");
        assert!(closed.applied[0].failed);
        assert!(open.allowed);
        assert!(open.applied[0].failed);
    }

    #[tokio::test]
    async fn in_process_validation_remains_interruptible_by_binding_timeout() {
        let runner = ChainRunner::new(Arc::new(PendingInProcessService));
        let error = runner
            .validate_config("test/pending", prost_types::Struct::default())
            .await
            .expect_err("timed-out in-process validation");

        assert!(error.to_string().contains("ValidateConfig failed"));
        assert!(error.to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn applies_fixed_regex_replacements() {
        let outcome = builtin_runner()
            .evaluate(
                &[entry("redact", OnError::FailClosed)],
                input(r#"{"api_key":"sk-1234567890abcdef"}"#),
            )
            .await
            .expect("evaluate");
        assert!(outcome.allowed);
        assert_eq!(
            String::from_utf8(outcome.body).expect("utf8"),
            r#"{"api_key":"[REDACTED]"}"#
        );
        assert_eq!(outcome.findings[0].finding.count, 1);
    }

    #[tokio::test]
    async fn transformed_body_feeds_next_stage() {
        let entries = [
            entry("first", OnError::FailClosed),
            entry("second", OnError::FailClosed),
        ];
        let outcome = builtin_runner()
            .evaluate(&entries, input(r#"token="sk-ABCDEFGHIJKLMNOP""#))
            .await
            .expect("evaluate");
        assert!(outcome.allowed);
        assert_eq!(
            String::from_utf8(outcome.body).expect("utf8"),
            r#"token="[REDACTED]""#
        );
        assert_eq!(outcome.applied.len(), 2);
        assert_eq!(
            [
                outcome.applied[0].transformed,
                outcome.applied[1].transformed,
            ],
            [true, false]
        );
    }

    #[tokio::test]
    async fn describe_chain_sorts_by_order_then_name() {
        let mut later = entry("later", OnError::FailClosed);
        later.order = 20;
        let mut beta = entry("beta", OnError::FailClosed);
        beta.order = 10;
        let mut alpha = entry("alpha", OnError::FailClosed);
        alpha.order = 10;

        let described = builtin_runner()
            .describe_chain(&[later, beta, alpha])
            .await
            .expect("describe ordered chain");
        let names: Vec<_> = described
            .iter()
            .map(|entry| entry.entry.name.as_str())
            .collect();
        assert_eq!(names, vec!["alpha", "beta", "later"]);
    }

    #[tokio::test]
    async fn describe_chain_accepts_maximum_selected_stages() {
        let entries: Vec<_> = (0..MAX_MIDDLEWARE_CHAIN_STAGES)
            .map(|index| entry(&format!("stage-{index}"), OnError::FailClosed))
            .collect();

        let described = builtin_runner()
            .describe_chain(&entries)
            .await
            .expect("maximum selected stage count");
        assert_eq!(described.len(), MAX_MIDDLEWARE_CHAIN_STAGES);
    }

    #[tokio::test]
    async fn describe_chain_rejects_selected_stages_over_capacity() {
        let entries: Vec<_> = (0..=MAX_MIDDLEWARE_CHAIN_STAGES)
            .map(|index| entry(&format!("stage-{index}"), OnError::FailClosed))
            .collect();

        let error = builtin_runner()
            .describe_chain(&entries)
            .await
            .err()
            .expect("selected stage count over capacity");
        assert!(
            error
                .to_string()
                .contains("selected middleware stage count 11 exceeds platform maximum 10")
        );
    }

    #[tokio::test]
    async fn fail_open_allows_unavailable_middleware() {
        let unavailable = ChainEntry {
            name: "missing".into(),
            implementation: "third-party/missing".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailOpen,
        };
        let outcome = builtin_runner()
            .evaluate(&[unavailable], input("hello"))
            .await
            .expect("evaluate");
        assert!(outcome.allowed);
        assert_eq!(outcome.body, b"hello");
    }

    #[tokio::test]
    async fn fail_closed_denies_unavailable_middleware() {
        let unavailable = ChainEntry {
            name: "missing".into(),
            implementation: "third-party/missing".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        };
        let outcome = builtin_runner()
            .evaluate(&[unavailable], input("hello"))
            .await
            .expect("evaluate");
        assert!(!outcome.allowed);
        assert!(outcome.reason.starts_with("middleware_failed:"));
    }

    #[tokio::test]
    async fn injected_service_names_drive_registration_checks() {
        let registry = MiddlewareRegistry::connect_services(services(), Vec::new())
            .await
            .expect("connect built-in service");
        let policy = SandboxPolicy {
            network_middlewares: HashMap::from([(
                "redactor".into(),
                NetworkMiddlewareConfig {
                    middleware: BUILTIN_REGEX.into(),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        registry
            .ensure_policy_middlewares_registered(&policy)
            .expect("described middleware is registered");
    }

    #[tokio::test]
    async fn injected_services_cannot_duplicate_middleware_names() {
        let first: Arc<dyn InProcessMiddleware> = Arc::new(BorrowedRecordingService {
            manifest_name: "openshell/test".into(),
            received: std::sync::Mutex::new(Vec::new()),
        });
        let second: Arc<dyn InProcessMiddleware> = Arc::new(BorrowedRecordingService {
            manifest_name: "openshell/test".into(),
            received: std::sync::Mutex::new(Vec::new()),
        });

        let error = MiddlewareRegistry::connect_services(vec![first, second], Vec::new())
            .await
            .expect_err("duplicate injected middleware name must fail registry construction");
        assert!(
            error
                .to_string()
                .contains("duplicate supervisor middleware name")
        );
    }

    /// A mock middleware that returns a fixed, caller-supplied result for every
    /// evaluation. Used to exercise chain behavior the built-in cannot produce
    /// (explicit deny, metadata, findings, unsafe header mutations).
    struct ScriptedService {
        manifest_name: String,
        max_body_bytes: u64,
        result: openshell_core::proto::HttpRequestResult,
    }

    #[tonic::async_trait]
    impl SupervisorMiddleware for ScriptedService {
        async fn describe(
            &self,
            _request: Request<()>,
        ) -> std::result::Result<tonic::Response<MiddlewareManifest>, tonic::Status> {
            Ok(tonic::Response::new(MiddlewareManifest {
                name: self.manifest_name.clone(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_body_bytes: self.max_body_bytes,
                    timeout: String::new(),
                }],
                expected_audience: String::new(),
            }))
        }

        async fn validate_config(
            &self,
            _request: Request<ValidateConfigRequest>,
        ) -> std::result::Result<tonic::Response<ValidateConfigResponse>, tonic::Status> {
            Ok(tonic::Response::new(ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            }))
        }

        async fn evaluate_http_request(
            &self,
            _request: Request<HttpRequestEvaluation>,
        ) -> std::result::Result<
            tonic::Response<openshell_core::proto::HttpRequestResult>,
            tonic::Status,
        > {
            Ok(tonic::Response::new(self.result.clone()))
        }
    }

    struct SlowService {
        delay: Duration,
        binding_timeout: String,
    }

    #[tonic::async_trait]
    impl SupervisorMiddleware for SlowService {
        async fn describe(
            &self,
            _request: Request<()>,
        ) -> std::result::Result<tonic::Response<MiddlewareManifest>, tonic::Status> {
            Ok(tonic::Response::new(MiddlewareManifest {
                name: "test/slow".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_body_bytes: 4096,
                    timeout: self.binding_timeout.clone(),
                }],
                expected_audience: String::new(),
            }))
        }

        async fn validate_config(
            &self,
            _request: Request<ValidateConfigRequest>,
        ) -> std::result::Result<tonic::Response<ValidateConfigResponse>, tonic::Status> {
            tokio::time::sleep(self.delay).await;
            Ok(tonic::Response::new(ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            }))
        }

        async fn evaluate_http_request(
            &self,
            _request: Request<HttpRequestEvaluation>,
        ) -> std::result::Result<
            tonic::Response<openshell_core::proto::HttpRequestResult>,
            tonic::Status,
        > {
            tokio::time::sleep(self.delay).await;
            Ok(tonic::Response::new(allow_result()))
        }
    }

    /// A middleware attached twice for exercising per-stage validation. The
    /// first policy config requests a body transformation; the second records
    /// that it ran and allows.
    struct TwoStageService {
        second_ran: Arc<std::sync::atomic::AtomicBool>,
    }

    #[tonic::async_trait]
    impl SupervisorMiddleware for TwoStageService {
        async fn describe(
            &self,
            _request: Request<()>,
        ) -> std::result::Result<tonic::Response<MiddlewareManifest>, tonic::Status> {
            Ok(tonic::Response::new(MiddlewareManifest {
                name: "test/two-stage".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_body_bytes: 256 * 1024,
                    timeout: String::new(),
                }],
                expected_audience: String::new(),
            }))
        }

        async fn validate_config(
            &self,
            _request: Request<ValidateConfigRequest>,
        ) -> std::result::Result<tonic::Response<ValidateConfigResponse>, tonic::Status> {
            Ok(tonic::Response::new(ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            }))
        }

        async fn evaluate_http_request(
            &self,
            request: Request<HttpRequestEvaluation>,
        ) -> std::result::Result<
            tonic::Response<openshell_core::proto::HttpRequestResult>,
            tonic::Status,
        > {
            let evaluation = request.into_inner();
            let mut result = allow_result();
            if evaluation.config.as_ref().is_some_and(|config| {
                config.fields.get("transform").is_some_and(|value| {
                    matches!(
                        value.kind.as_ref(),
                        Some(prost_types::value::Kind::BoolValue(true))
                    )
                })
            }) {
                result.body = b"TRANSFORMED".to_vec();
                result.has_body = true;
            } else {
                self.second_ran
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(tonic::Response::new(result))
        }
    }

    #[tokio::test]
    async fn per_stage_validation_denies_before_the_next_stage_runs() {
        // The validator rejects the first stage's transformed body. The chain
        // must stop there: the second stage never runs, so it never sees a
        // payload the policy would reject.
        let second_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let service: Arc<dyn SupervisorMiddleware> = Arc::new(TwoStageService {
            second_ran: Arc::clone(&second_ran),
        });
        let runner = ChainRunner::new_protobuf_for_tests(service);
        let transform = ChainEntry {
            name: "transform".into(),
            implementation: "test/two-stage".into(),
            order: 0,
            config: prost_types::Struct {
                fields: std::iter::once((
                    "transform".into(),
                    prost_types::Value {
                        kind: Some(prost_types::value::Kind::BoolValue(true)),
                    },
                ))
                .collect(),
            },
            on_error: OnError::FailClosed,
        };
        let second = ChainEntry {
            name: "second".into(),
            implementation: "test/two-stage".into(),
            order: 10,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        };
        let described = runner
            .describe_chain(&[transform, second])
            .await
            .expect("describe two-stage chain");

        let validator: Box<TransformedBodyValidator<'_>> = Box::new(|body: &[u8]| {
            if body == b"TRANSFORMED" {
                Ok(Some("transformed body denied by policy".to_string()))
            } else {
                Ok(None)
            }
        });
        let outcome = runner
            .evaluate_described_with_policy(
                &described,
                input("original"),
                TransformedBodyPolicy::Reevaluate(&*validator),
            )
            .await
            .expect("evaluate two-stage chain");

        assert!(!outcome.allowed);
        assert_eq!(outcome.reason, "transformed body denied by policy");
        assert_eq!(outcome.applied.len(), 1, "only the first stage should run");
        assert_eq!(outcome.applied[0].name, "transform");
        assert!(
            !second_ran.load(std::sync::atomic::Ordering::SeqCst),
            "second stage must not run after a policy deny"
        );
    }

    #[tokio::test]
    async fn per_stage_validator_allows_compliant_transformations() {
        // A validator that accepts every body lets both stages run; the second
        // stage sees the first stage's output.
        let second_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let service: Arc<dyn SupervisorMiddleware> = Arc::new(TwoStageService {
            second_ran: Arc::clone(&second_ran),
        });
        let runner = ChainRunner::new_protobuf_for_tests(service);
        let transform = ChainEntry {
            name: "transform".into(),
            implementation: "test/two-stage".into(),
            order: 0,
            config: prost_types::Struct {
                fields: std::iter::once((
                    "transform".into(),
                    prost_types::Value {
                        kind: Some(prost_types::value::Kind::BoolValue(true)),
                    },
                ))
                .collect(),
            },
            on_error: OnError::FailClosed,
        };
        let second = ChainEntry {
            name: "second".into(),
            implementation: "test/two-stage".into(),
            order: 10,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        };
        let described = runner
            .describe_chain(&[transform, second])
            .await
            .expect("describe two-stage chain");

        let validator: Box<TransformedBodyValidator<'_>> = Box::new(|_body: &[u8]| Ok(None));
        let outcome = runner
            .evaluate_described_with_policy(
                &described,
                input("original"),
                TransformedBodyPolicy::Reevaluate(&*validator),
            )
            .await
            .expect("evaluate two-stage chain");

        assert!(outcome.allowed);
        assert_eq!(outcome.applied.len(), 2);
        assert!(
            second_ran.load(std::sync::atomic::Ordering::SeqCst),
            "second stage should run when the transformation is compliant"
        );
    }

    #[tokio::test]
    async fn per_stage_validator_error_becomes_structured_denial() {
        let second_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let service: Arc<dyn SupervisorMiddleware> = Arc::new(TwoStageService {
            second_ran: Arc::clone(&second_ran),
        });
        let runner = ChainRunner::new_protobuf_for_tests(service);
        let entries = [
            ChainEntry {
                name: "transform".into(),
                implementation: "test/two-stage".into(),
                order: 0,
                config: prost_types::Struct {
                    fields: std::iter::once((
                        "transform".into(),
                        prost_types::Value {
                            kind: Some(prost_types::value::Kind::BoolValue(true)),
                        },
                    ))
                    .collect(),
                },
                on_error: OnError::FailClosed,
            },
            ChainEntry {
                name: "second".into(),
                implementation: "test/two-stage".into(),
                order: 10,
                config: prost_types::Struct::default(),
                on_error: OnError::FailClosed,
            },
        ];
        let described = runner
            .describe_chain(&entries)
            .await
            .expect("describe two-stage chain");
        let validator: Box<TransformedBodyValidator<'_>> =
            Box::new(|_body: &[u8]| Err(miette!("OPA engine unavailable")));

        let outcome = runner
            .evaluate_described_with_policy(
                &described,
                input("original"),
                TransformedBodyPolicy::Reevaluate(&*validator),
            )
            .await
            .expect("policy evaluator failure should be a chain outcome");

        assert!(!outcome.allowed);
        assert!(
            outcome
                .reason
                .starts_with("transformed_body_policy_evaluation_failed:"),
            "{}",
            outcome.reason
        );
        assert_eq!(outcome.applied.len(), 1);
        assert!(!second_ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    fn scripted_service(result: openshell_core::proto::HttpRequestResult) -> ScriptedService {
        ScriptedService {
            manifest_name: BUILTIN_REGEX.into(),
            max_body_bytes: 256 * 1024,
            result,
        }
    }

    fn allow_result() -> openshell_core::proto::HttpRequestResult {
        openshell_core::proto::HttpRequestResult {
            decision: Decision::Allow as i32,
            reason: String::new(),
            body: Vec::new(),
            has_body: false,
            header_mutations: Vec::new(),
            findings: Vec::new(),
            metadata: HashMap::new(),
            reason_code: String::new(),
        }
    }

    /// A middleware that records every evaluation it receives and allows the
    /// request, for asserting what the supervisor actually sends to services.
    struct RecordingService {
        validated: std::sync::Mutex<Vec<ValidateConfigRequest>>,
        received: std::sync::Mutex<Vec<HttpRequestEvaluation>>,
    }

    #[tonic::async_trait]
    impl SupervisorMiddleware for RecordingService {
        async fn describe(
            &self,
            _request: Request<()>,
        ) -> std::result::Result<tonic::Response<MiddlewareManifest>, tonic::Status> {
            Ok(tonic::Response::new(MiddlewareManifest {
                name: "test/recorder".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_body_bytes: 4096,
                    timeout: String::new(),
                }],
                expected_audience: String::new(),
            }))
        }

        async fn validate_config(
            &self,
            request: Request<ValidateConfigRequest>,
        ) -> std::result::Result<tonic::Response<ValidateConfigResponse>, tonic::Status> {
            self.validated
                .lock()
                .expect("validated config lock")
                .push(request.into_inner());
            Ok(tonic::Response::new(ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            }))
        }

        async fn evaluate_http_request(
            &self,
            request: Request<HttpRequestEvaluation>,
        ) -> std::result::Result<
            tonic::Response<openshell_core::proto::HttpRequestResult>,
            tonic::Status,
        > {
            self.received
                .lock()
                .expect("recording lock")
                .push(request.into_inner());
            Ok(tonic::Response::new(allow_result()))
        }
    }

    /// Three-stage service used to verify that each stage observes the header
    /// state produced by all preceding stages.
    struct HeaderChainService {
        second_action: ExistingHeaderAction,
        received: std::sync::Mutex<Vec<HttpRequestEvaluation>>,
    }

    #[tonic::async_trait]
    impl SupervisorMiddleware for HeaderChainService {
        async fn describe(
            &self,
            _request: Request<()>,
        ) -> std::result::Result<tonic::Response<MiddlewareManifest>, tonic::Status> {
            Ok(tonic::Response::new(MiddlewareManifest {
                name: "test/header-chain".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_body_bytes: 4096,
                    timeout: String::new(),
                }],
                expected_audience: String::new(),
            }))
        }

        async fn validate_config(
            &self,
            _request: Request<ValidateConfigRequest>,
        ) -> std::result::Result<tonic::Response<ValidateConfigResponse>, tonic::Status> {
            Ok(tonic::Response::new(ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            }))
        }

        async fn evaluate_http_request(
            &self,
            request: Request<HttpRequestEvaluation>,
        ) -> std::result::Result<
            tonic::Response<openshell_core::proto::HttpRequestResult>,
            tonic::Status,
        > {
            let evaluation = request.into_inner();
            let invocation = {
                let mut received = self.received.lock().expect("header chain lock");
                let invocation = received.len();
                received.push(evaluation);
                invocation
            };
            let mut result = allow_result();
            if invocation == 0 {
                result.header_mutations.push(write_header(
                    "x-openshell-middleware-chain",
                    "first",
                    ExistingHeaderAction::Overwrite,
                ));
            } else if invocation == 1 {
                result.header_mutations.push(write_header(
                    "x-openshell-middleware-chain",
                    "second",
                    self.second_action,
                ));
            }
            Ok(tonic::Response::new(result))
        }
    }

    #[tokio::test]
    async fn later_middleware_observes_prior_header_mutations() {
        for (action, expected) in [
            (ExistingHeaderAction::Append, vec!["first", "second"]),
            (ExistingHeaderAction::Overwrite, vec!["second"]),
            (ExistingHeaderAction::Skip, vec!["first"]),
        ] {
            let service = Arc::new(HeaderChainService {
                second_action: action,
                received: std::sync::Mutex::new(Vec::new()),
            });
            let runner = ChainRunner::new_protobuf_for_tests(service.clone());
            let entries = [
                ChainEntry {
                    name: "first".into(),
                    implementation: "test/header-chain".into(),
                    order: 0,
                    config: prost_types::Struct::default(),
                    on_error: OnError::FailClosed,
                },
                ChainEntry {
                    name: "second".into(),
                    implementation: "test/header-chain".into(),
                    order: 10,
                    config: prost_types::Struct::default(),
                    on_error: OnError::FailClosed,
                },
                ChainEntry {
                    name: "observer".into(),
                    implementation: "test/header-chain".into(),
                    order: 20,
                    config: prost_types::Struct::default(),
                    on_error: OnError::FailClosed,
                },
            ];

            let outcome = runner
                .evaluate(&entries, input("payload"))
                .await
                .expect("evaluate header chain");
            assert!(outcome.allowed);
            let received = service.received.lock().expect("recorded header chain");
            let observed: Vec<&str> = received[2]
                .headers
                .iter()
                .filter(|header| header.name == "x-openshell-middleware-chain")
                .map(|header| header.value.as_str())
                .collect();
            assert_eq!(observed, expected, "action {action:?}");
        }
    }

    #[tokio::test]
    async fn repeated_request_headers_reach_middleware_in_wire_order() {
        // A map contract would collapse repeated header names to one value
        // while the upstream still receives every original value, creating an
        // inspection differential. The service must see each entry in wire
        // order.
        let service = Arc::new(RecordingService {
            validated: std::sync::Mutex::new(Vec::new()),
            received: std::sync::Mutex::new(Vec::new()),
        });
        let recorder: Arc<dyn SupervisorMiddleware> = service.clone();
        let runner = ChainRunner::new_protobuf_for_tests(recorder);
        let validation_config = prost_types::Struct {
            fields: std::iter::once((
                "required".into(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue("present".into())),
                },
            ))
            .collect(),
        };
        runner
            .validate_config("test/recorder", validation_config.clone())
            .await
            .expect("validate recorder config");
        let evaluation_config = prost_types::Struct {
            fields: std::iter::once((
                "evaluation".into(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue("preserved".into())),
                },
            ))
            .collect(),
        };
        let recorder_entry = ChainEntry {
            name: "recorder".into(),
            implementation: "test/recorder".into(),
            order: 0,
            config: evaluation_config.clone(),
            on_error: OnError::FailClosed,
        };
        let mut request = input("payload");
        request.headers = vec![
            ("x-api-key".into(), "first-value".into()),
            ("accept".into(), "application/json".into()),
            ("x-api-key".into(), "second-value".into()),
        ];
        request.query = "page=2".into();
        let original_body = request.body.as_ptr().addr();

        let outcome = runner
            .evaluate(&[recorder_entry], request)
            .await
            .expect("evaluate recording chain");
        assert!(outcome.allowed);

        let validated = service.validated.lock().expect("validated configs");
        assert_eq!(validated.len(), 1);
        assert_eq!(validated[0].middleware_name, "test/recorder");
        assert_eq!(validated[0].config.as_ref(), Some(&validation_config));
        drop(validated);

        let received = service.received.lock().expect("recorded evaluations");
        assert_eq!(received.len(), 1);
        assert_eq!(outcome.body.as_ptr().addr(), original_body);
        assert_ne!(received[0].body.as_ptr().addr(), original_body);
        assert_eq!(received[0].body, b"payload");
        assert_eq!(
            received[0].phase,
            SupervisorMiddlewarePhase::PreCredentials as i32
        );
        assert_eq!(received[0].middleware_name, "test/recorder");
        assert_eq!(received[0].config.as_ref(), Some(&evaluation_config));
        let context = received[0].context.as_ref().expect("request context");
        assert_eq!(context.request_id, "req");
        assert_eq!(context.sandbox_id, "sbx");
        assert!(context.originating_process.is_none());
        let target = received[0].target.as_ref().expect("request target");
        assert_eq!(target.scheme, "https");
        assert_eq!(target.host, "api.example.com");
        assert_eq!(target.port, 443);
        assert_eq!(target.method, "POST");
        assert_eq!(target.path, "/v1");
        assert_eq!(target.query, "page=2");
        let headers: Vec<(&str, &str)> = received[0]
            .headers
            .iter()
            .map(|header| (header.name.as_str(), header.value.as_str()))
            .collect();
        assert_eq!(
            headers,
            vec![
                ("x-api-key", "first-value"),
                ("accept", "application/json"),
                ("x-api-key", "second-value"),
            ]
        );
    }

    fn external_registration(max_body_bytes: u64) -> SupervisorMiddlewareService {
        SupervisorMiddlewareService {
            name: "local-guard-service".into(),
            grpc_endpoint: "http://127.0.0.1:50051".into(),
            max_body_bytes,
            ..Default::default()
        }
    }

    async fn registry_with_external(
        service: Arc<dyn SupervisorMiddleware>,
        registration: SupervisorMiddlewareService,
    ) -> MiddlewareRegistry {
        let builtin_service = services()
            .into_iter()
            .next()
            .expect("built-in middleware service");
        let builtin_manifest = builtin_service.describe().await;
        validate_manifest_bindings("test built-in service", &builtin_manifest, None)
            .expect("valid built-in manifest");
        let builtin_name = builtin_manifest.name.clone();
        let builtin_manifest_cell = OnceCell::new();
        builtin_manifest_cell
            .set(builtin_manifest)
            .expect("built-in manifest cache");

        let manifest = service
            .describe(Request::new(()))
            .await
            .expect("describe test service")
            .into_inner();
        let operator_max_body_bytes = usize::try_from(registration.max_body_bytes).unwrap();
        let operator_timeout = validate_registration(&registration).expect("valid registration");
        validate_external_manifest(&registration, &manifest, operator_max_body_bytes, false)
            .expect("valid external manifest");
        let manifest_cell = OnceCell::new();
        manifest_cell.set(manifest).expect("manifest cache");
        let registration_name = registration.name.clone();
        MiddlewareRegistry {
            services: Arc::new(vec![
                Arc::new(MiddlewareServiceState {
                    attachment_name: Some(builtin_name.clone()),
                    service: MiddlewareService::InProcess(builtin_service),
                    manifest: builtin_manifest_cell,
                    diagnostic_policy: MiddlewareDiagnosticPolicy::Preserve,
                    operator_max_body_bytes: None,
                    operator_timeout: DEFAULT_MIDDLEWARE_TIMEOUT,
                }),
                Arc::new(MiddlewareServiceState {
                    attachment_name: Some(registration_name.clone()),
                    service: MiddlewareService::Grpc(remote::GrpcMiddlewareService::from_service(
                        service,
                    )),
                    manifest: manifest_cell,
                    diagnostic_policy: MiddlewareDiagnosticPolicy::Normalize,
                    operator_max_body_bytes: Some(operator_max_body_bytes),
                    operator_timeout,
                }),
            ]),
            registered_services: Arc::new(vec![RegisteredMiddlewareService { registration }]),
            middleware_names: Arc::new(HashSet::from([builtin_name, registration_name])),
        }
    }

    #[tokio::test]
    async fn describe_chain_marks_resolved_and_unresolved_entries() {
        let unresolved = ChainEntry {
            name: "missing".into(),
            implementation: "third-party/missing".into(),
            order: 10,
            config: prost_types::Struct::default(),
            on_error: OnError::FailOpen,
        };
        let described = builtin_runner()
            .describe_chain(&[entry("redact", OnError::FailClosed), unresolved])
            .await
            .expect("describe chain");
        // The built-in resolves and reports its real limit; the missing binding
        // does not resolve and must not contribute a body limit.
        assert!(described[0].is_resolved());
        assert_eq!(described[0].max_body_bytes(), 256 * 1024);
        assert!(!described[1].is_resolved());
    }

    #[tokio::test]
    async fn descriptors_are_resolved_from_any_middleware_service() {
        let runner = ChainRunner::new_protobuf_for_tests(Arc::new(ScriptedService {
            manifest_name: "test/middleware".into(),
            max_body_bytes: 4096,
            result: allow_result(),
        }));
        let entry = ChainEntry {
            name: "external".into(),
            implementation: "test/middleware".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        };

        let described = runner
            .describe_chain(std::slice::from_ref(&entry))
            .await
            .expect("describe external middleware");
        assert_eq!(described[0].max_body_bytes(), 4096);
        assert_eq!(
            described[0]
                .binding
                .as_ref()
                .expect("described binding")
                .phase,
            SupervisorMiddlewarePhase::PreCredentials as i32
        );

        let outcome = runner
            .evaluate_described(&described, input("hello"))
            .await
            .expect("evaluate external middleware");
        assert!(outcome.allowed);
    }

    #[tokio::test]
    async fn mixed_builtin_and_external_chain_uses_operator_limit() {
        let external = Arc::new(ScriptedService {
            manifest_name: "test/middleware".into(),
            max_body_bytes: 4096,
            result: allow_result(),
        });
        let registry = registry_with_external(external, external_registration(1024)).await;
        let runner = ChainRunner::from_registry(registry);
        let external_entry = ChainEntry {
            name: "external".into(),
            implementation: "local-guard-service".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        };
        let entries = [entry("builtin", OnError::FailClosed), external_entry];

        let described = runner
            .describe_chain(&entries)
            .await
            .expect("describe chain");
        assert_eq!(described[0].max_body_bytes(), 256 * 1024);
        assert_eq!(described[1].max_body_bytes(), 1024);

        let outcome = runner
            .evaluate_described(&described, input(r#"token="sk-ABCDEFGHIJKLMNOP""#))
            .await
            .expect("evaluate mixed chain");
        assert!(outcome.allowed);
        assert_eq!(outcome.applied.len(), 2);
        assert_eq!(
            String::from_utf8(outcome.body).expect("utf8"),
            r#"token="[REDACTED]""#
        );
    }

    #[tokio::test]
    async fn undersized_stage_fails_open_while_later_stage_runs() {
        // A body over one stage's limit must fail only that stage through its
        // own `on_error`, not the whole chain: the 1 KiB fail-open guard is
        // skipped while the 256 KiB fail-closed redactor still runs.
        let external = Arc::new(ScriptedService {
            manifest_name: "test/middleware".into(),
            max_body_bytes: 4096,
            result: allow_result(),
        });
        let registry = registry_with_external(external, external_registration(1024)).await;
        let runner = ChainRunner::from_registry(registry);
        let guard_entry = ChainEntry {
            name: "guard".into(),
            implementation: "local-guard-service".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailOpen,
        };
        let mut redact_entry = entry("redact", OnError::FailClosed);
        redact_entry.order = 10;
        let entries = [guard_entry, redact_entry];

        let body = format!("{}token=\"sk-ABCDEFGHIJKLMNOP\"", "x".repeat(1500));
        let outcome = runner
            .evaluate(&entries, input(&body))
            .await
            .expect("evaluate mixed-limit chain");

        assert!(outcome.allowed);
        assert_eq!(outcome.applied.len(), 2);
        assert!(
            outcome.applied[0].failed,
            "undersized guard must be skipped"
        );
        assert_eq!(outcome.applied[0].decision, Decision::Allow);
        assert!(!outcome.applied[1].failed);
        assert!(outcome.applied[1].transformed);
        let body = String::from_utf8(outcome.body).expect("utf8");
        assert!(body.contains("[REDACTED]"));
        assert!(!body.contains("sk-ABCDEFGHIJKLMNOP"));
    }

    #[tokio::test]
    async fn transformed_body_still_over_later_stage_capacity_honors_on_error() {
        // Per-stage capacity applies to the current body: the redactor's
        // replacement is still over the 1 KiB guard limit, so the fail-closed
        // guard denies through its own `on_error` after the redactor ran.
        let external = Arc::new(ScriptedService {
            manifest_name: "test/middleware".into(),
            max_body_bytes: 4096,
            result: allow_result(),
        });
        let registry = registry_with_external(external, external_registration(1024)).await;
        let runner = ChainRunner::from_registry(registry);
        let guard_entry = ChainEntry {
            name: "guard".into(),
            implementation: "local-guard-service".into(),
            order: 10,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        };
        let entries = [entry("redact", OnError::FailClosed), guard_entry];

        let body = format!("{}token=\"sk-ABCDEFGHIJKLMNOP\"", "x".repeat(1500));
        let outcome = runner
            .evaluate(&entries, input(&body))
            .await
            .expect("evaluate mixed-limit chain");

        assert!(!outcome.allowed);
        assert_eq!(
            outcome.reason,
            "middleware_failed: request_body_over_capacity"
        );
        assert_eq!(outcome.applied.len(), 2);
        assert!(
            outcome.applied[0].transformed,
            "redactor ran before the deny"
        );
        assert!(outcome.applied[1].failed);
    }

    #[test]
    fn external_manifest_rejects_operator_limit_above_capability() {
        let registration = external_registration(4097);
        let manifest = MiddlewareManifest {
            name: "example/service".into(),
            service_version: "test".into(),
            bindings: vec![MiddlewareBinding {
                operation: HTTP_REQUEST_OPERATION as i32,
                phase: PRE_CREDENTIALS_PHASE as i32,
                max_body_bytes: 4096,
                timeout: String::new(),
            }],
            expected_audience: String::new(),
        };
        let error = validate_external_manifest(&registration, &manifest, 4097, false)
            .expect_err("operator limit must fit capability");
        assert!(error.to_string().contains("exceeds"));
    }

    #[test]
    fn external_registration_rejects_body_limit_above_platform_maximum() {
        let registration = external_registration(u64::MAX);
        let error = validate_registration(&registration)
            .expect_err("extreme body limit must be rejected before allocation");
        assert!(error.to_string().contains("platform maximum"));
    }

    #[test]
    fn manifest_rejects_body_limit_above_platform_maximum() {
        let registration = external_registration(4096);
        let manifest = MiddlewareManifest {
            name: "example/service".into(),
            service_version: "test".into(),
            bindings: vec![MiddlewareBinding {
                operation: HTTP_REQUEST_OPERATION as i32,
                phase: PRE_CREDENTIALS_PHASE as i32,
                max_body_bytes: u64::MAX,
                timeout: String::new(),
            }],
            expected_audience: String::new(),
        };
        let error = validate_external_manifest(&registration, &manifest, 4096, false)
            .expect_err("extreme advertised body limit must be rejected");
        assert!(error.to_string().contains("platform maximum"));
    }

    #[test]
    fn manifest_rejects_duplicate_operation_phase_pairs() {
        let registration = external_registration(4096);
        let binding = || MiddlewareBinding {
            operation: HTTP_REQUEST_OPERATION as i32,
            phase: PRE_CREDENTIALS_PHASE as i32,
            max_body_bytes: 4096,
            timeout: String::new(),
        };
        let manifest = MiddlewareManifest {
            name: "example/service".into(),
            service_version: "test".into(),
            bindings: vec![binding(), binding()],
            expected_audience: String::new(),
        };

        let error = validate_external_manifest(&registration, &manifest, 4096, false)
            .expect_err("one service cannot advertise two bindings for the same pair");
        assert!(
            error
                .to_string()
                .contains("more than one binding for HTTP_REQUEST/PRE_CREDENTIALS")
        );
    }

    #[test]
    fn external_registration_accepts_http_and_https_grpc_endpoints() {
        for grpc_endpoint in [
            "http://127.0.0.1:50051",
            "https://middleware.example.com:443",
        ] {
            let mut registration = external_registration(4096);
            registration.grpc_endpoint = grpc_endpoint.into();
            validate_registration(&registration).expect("supported gRPC endpoint scheme");
        }
    }

    #[test]
    fn external_registration_rejects_unsupported_grpc_endpoint_scheme() {
        let mut registration = external_registration(4096);
        registration.grpc_endpoint = "ftp://middleware.example.com".into();
        let error = validate_registration(&registration).expect_err("unsupported scheme");
        assert!(error.to_string().contains("http:// or https://"));
    }

    #[test]
    fn external_registration_name_is_stable_and_cannot_shadow_builtins() {
        for name in ["", "guard\nforged", "openshell/regex"] {
            let mut registration = external_registration(4096);
            registration.name = name.into();
            assert!(
                validate_registration(&registration).is_err(),
                "registration name {name:?} must be rejected"
            );
        }
    }

    #[test]
    fn registration_timeout_uses_default_and_operator_override() {
        let registration = external_registration(4096);
        let timeout = validate_registration(&registration).expect("default timeout");
        assert_eq!(timeout, DEFAULT_MIDDLEWARE_TIMEOUT);

        let mut registration = external_registration(4096);
        registration.timeout = "2s".into();
        let timeout = validate_registration(&registration).expect("operator timeout");
        assert_eq!(timeout, Duration::from_secs(2));
    }

    #[test]
    fn registration_timeout_enforces_bounds() {
        for timeout in ["9ms", "31s"] {
            let mut registration = external_registration(4096);
            registration.timeout = timeout.into();
            assert!(validate_registration(&registration).is_err());
        }
    }

    #[test]
    fn manifest_binding_timeout_enforces_bounds() {
        let registration = external_registration(4096);
        for timeout in ["9ms", "31s"] {
            let manifest = MiddlewareManifest {
                name: "example/service".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: HTTP_REQUEST_OPERATION as i32,
                    phase: PRE_CREDENTIALS_PHASE as i32,
                    max_body_bytes: 4096,
                    timeout: timeout.into(),
                }],
                expected_audience: String::new(),
            };
            let error = validate_external_manifest(&registration, &manifest, 4096, false)
                .expect_err("out-of-bounds binding timeout must be rejected");
            assert!(error.to_string().contains("invalid timeout"));
        }
    }

    #[tokio::test]
    async fn binding_timeout_override_controls_evaluation_and_on_error() {
        let mut registration = external_registration(4096);
        registration.timeout = "2s".into();
        let registry = registry_with_external(
            Arc::new(SlowService {
                delay: Duration::from_millis(50),
                binding_timeout: "10ms".into(),
            }),
            registration,
        )
        .await;
        let runner = ChainRunner::from_registry(registry);
        let slow_entry = |on_error| ChainEntry {
            name: "slow".into(),
            implementation: "local-guard-service".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error,
        };

        let described = runner
            .describe_chain(&[slow_entry(OnError::FailClosed)])
            .await
            .expect("describe slow binding");
        assert_eq!(described[0].timeout(), Duration::from_millis(10));

        let closed = runner
            .evaluate(&[slow_entry(OnError::FailClosed)], input("payload"))
            .await
            .expect("fail-closed timeout outcome");
        assert!(!closed.allowed);
        assert_eq!(closed.reason, "middleware_failed: middleware_timeout");

        let open = runner
            .evaluate(&[slow_entry(OnError::FailOpen)], input("payload"))
            .await
            .expect("fail-open timeout outcome");
        assert!(open.allowed);
        assert!(open.applied[0].failed);
    }

    #[tokio::test]
    async fn operator_timeout_controls_binding_without_manifest_override() {
        let mut registration = external_registration(4096);
        registration.timeout = "10ms".into();
        let registry = registry_with_external(
            Arc::new(SlowService {
                delay: Duration::from_millis(50),
                binding_timeout: String::new(),
            }),
            registration,
        )
        .await;
        let runner = ChainRunner::from_registry(registry);
        let slow_entry = ChainEntry {
            name: "slow".into(),
            implementation: "local-guard-service".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        };

        let described = runner
            .describe_chain(std::slice::from_ref(&slow_entry))
            .await
            .expect("describe slow binding");
        assert_eq!(described[0].timeout(), Duration::from_millis(10));

        let outcome = runner
            .evaluate(&[slow_entry], input("payload"))
            .await
            .expect("operator timeout outcome");
        assert!(!outcome.allowed);
        assert_eq!(outcome.reason, "middleware_failed: middleware_timeout");
    }

    #[tokio::test]
    async fn operator_timeout_caps_longer_binding_timeout_for_validation_and_evaluation() {
        let mut registration = external_registration(4096);
        registration.timeout = "10ms".into();
        let registry = registry_with_external(
            Arc::new(SlowService {
                delay: Duration::from_millis(50),
                binding_timeout: "2s".into(),
            }),
            registration,
        )
        .await;
        let runner = ChainRunner::from_registry(registry);
        let slow_entry = ChainEntry {
            name: "slow".into(),
            implementation: "local-guard-service".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        };

        let described = runner
            .describe_chain(std::slice::from_ref(&slow_entry))
            .await
            .expect("describe slow binding");
        assert_eq!(described[0].timeout(), Duration::from_millis(10));

        let validation_error = runner
            .validate_config("local-guard-service", prost_types::Struct::default())
            .await
            .expect_err("operator timeout must cap ValidateConfig");
        assert!(
            validation_error
                .to_string()
                .contains("ValidateConfig failed")
        );
        assert!(validation_error.to_string().contains("timed out"));

        let outcome = runner
            .evaluate(&[slow_entry], input("payload"))
            .await
            .expect("operator-capped evaluation outcome");
        assert!(!outcome.allowed);
        assert_eq!(outcome.reason, "middleware_failed: middleware_timeout");
    }

    #[tokio::test]
    async fn external_registry_attaches_same_service_under_multiple_names() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test middleware");
        let address = listener.local_addr().expect("test middleware address");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tonic::transport::Server::builder()
            .add_service(SupervisorMiddlewareServer::new(ScriptedService {
                manifest_name: "test/middleware".into(),
                max_body_bytes: 4096,
                result: allow_result(),
            }))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            });
        let server_task = tokio::spawn(server);

        let mut registration = external_registration(1024);
        registration.grpc_endpoint = format!("http://{address}");
        let mut second_registration = registration.clone();
        second_registration.name = "secondary-guard-service".into();
        let registry = MiddlewareRegistry::connect_services(
            Vec::new(),
            vec![registration.clone(), second_registration.clone()],
        )
        .await
        .expect("connect the same external middleware binding under two names");
        let policy = SandboxPolicy {
            network_middlewares: HashMap::from([(
                "guard".into(),
                NetworkMiddlewareConfig {
                    name: String::new(),
                    middleware: "local-guard-service".into(),
                    order: 0,
                    config: Some(prost_types::Struct::default()),
                    on_error: "fail_closed".into(),
                    endpoints: None,
                },
            )]),
            ..Default::default()
        };

        registry
            .validate_policy_configs(&policy)
            .await
            .expect("remote config validates");
        assert_eq!(
            registry.required_services(Some(&policy)),
            vec![registration.clone()]
        );

        let outcome = ChainRunner::from_registry(registry)
            .evaluate(
                &[
                    ChainEntry {
                        name: "primary".into(),
                        implementation: "local-guard-service".into(),
                        order: 0,
                        config: prost_types::Struct::default(),
                        on_error: OnError::FailClosed,
                    },
                    ChainEntry {
                        name: "secondary".into(),
                        implementation: "secondary-guard-service".into(),
                        order: 10,
                        config: prost_types::Struct::default(),
                        on_error: OnError::FailClosed,
                    },
                ],
                input("hello"),
            )
            .await
            .expect("remote evaluation");
        assert!(outcome.allowed);
        assert_eq!(outcome.applied.len(), 2);
        assert_eq!(outcome.applied[0].implementation, registration.name);
        assert_eq!(outcome.applied[1].implementation, second_registration.name);

        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("join test middleware")
            .expect("serve");
    }

    #[tokio::test]
    async fn remote_transport_accepts_maximum_bounded_request_and_response_envelopes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test middleware");
        let address = listener.local_addr().expect("test middleware address");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let response_findings = (0..MAX_MIDDLEWARE_FINDINGS_PER_STAGE)
            .map(|_| Finding {
                r#type: "f".repeat(1024),
                label: "finding".into(),
                count: 1,
                confidence: "medium".into(),
                severity: "medium".into(),
            })
            .collect();
        let server = tonic::transport::Server::builder()
            .add_service(
                SupervisorMiddlewareServer::new(ScriptedService {
                    manifest_name: "test/middleware".into(),
                    max_body_bytes: MAX_MIDDLEWARE_BODY_BYTES as u64,
                    result: openshell_core::proto::HttpRequestResult {
                        reason: "r".repeat(MAX_MIDDLEWARE_REASON_BYTES - 128),
                        reason_code: "r".repeat(MAX_MIDDLEWARE_REASON_CODE_BYTES),
                        body: vec![b'x'; MAX_MIDDLEWARE_BODY_BYTES],
                        has_body: true,
                        header_mutations: vec![write_header(
                            "x-openshell-middleware-envelope",
                            &"h".repeat(headers::MAX_HEADER_MUTATION_BYTES - 128),
                            ExistingHeaderAction::Append,
                        )],
                        findings: response_findings,
                        metadata: std::iter::once((
                            "diagnostic".into(),
                            "m".repeat(MAX_MIDDLEWARE_METADATA_BYTES - 128),
                        ))
                        .collect(),
                        ..allow_result()
                    },
                })
                .max_decoding_message_size(MIDDLEWARE_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MIDDLEWARE_GRPC_MESSAGE_BYTES),
            )
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            });
        let server_task = tokio::spawn(server);

        let mut registration = external_registration(MAX_MIDDLEWARE_BODY_BYTES as u64);
        registration.grpc_endpoint = format!("http://{address}");
        let registry = MiddlewareRegistry::connect_services(Vec::new(), vec![registration])
            .await
            .expect("connect external middleware");
        let config = prost_types::Struct {
            fields: std::iter::once((
                "payload".into(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue(
                        "c".repeat(MAX_MIDDLEWARE_CONFIG_BYTES - 256),
                    )),
                },
            ))
            .collect(),
        };
        assert!(config.encoded_len() <= MAX_MIDDLEWARE_CONFIG_BYTES);
        let mut request = input("");
        request.request_id = "r".repeat(MAX_MIDDLEWARE_CONTEXT_BYTES - 256);
        request.path = format!("/{}", "p".repeat(MAX_MIDDLEWARE_TARGET_BYTES - 512));
        request.headers = vec![(
            "x-large-envelope".into(),
            "v".repeat(MAX_MIDDLEWARE_HEADER_BYTES - 256),
        )];
        request.body = vec![b'b'; MAX_MIDDLEWARE_BODY_BYTES];
        let outcome = ChainRunner::from_registry(registry)
            .evaluate(
                &[ChainEntry {
                    name: "guard".into(),
                    implementation: "local-guard-service".into(),
                    order: 0,
                    config,
                    on_error: OnError::FailClosed,
                }],
                request,
            )
            .await
            .expect("maximum bounded envelopes should fit configured transport limit");

        assert!(outcome.allowed);
        assert_eq!(outcome.body.len(), MAX_MIDDLEWARE_BODY_BYTES);
        assert_eq!(outcome.header_mutations.len(), 1);
        assert_eq!(outcome.findings.len(), MAX_MIDDLEWARE_FINDINGS_PER_STAGE);
        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("join test middleware")
            .expect("serve");
    }

    #[test]
    fn grpc_envelope_headroom_matches_bounded_components() {
        assert_eq!(MIDDLEWARE_GRPC_ENVELOPE_BYTES, 292 * 1024 + 64);
        assert_eq!(
            MIDDLEWARE_GRPC_MESSAGE_BYTES,
            MAX_MIDDLEWARE_BODY_BYTES + 292 * 1024 + 64
        );
    }

    #[tokio::test]
    async fn external_diagnostics_are_normalized_before_reaching_logs() {
        let secret = "sk-secret-request-value";
        let registration = external_registration(4096);
        let service = Arc::new(ScriptedService {
            manifest_name: "test/middleware".into(),
            max_body_bytes: 4096,
            result: openshell_core::proto::HttpRequestResult {
                decision: Decision::Deny as i32,
                reason: format!("denied body={secret}\nFINDING:FORGED"),
                reason_code: "content_match".into(),
                findings: vec![Finding {
                    r#type: format!("secret.{secret}\nforged"),
                    label: format!("matched {secret}\nFINDING:FORGED"),
                    count: 1,
                    confidence: secret.into(),
                    severity: "high\nFINDING:FORGED".into(),
                }],
                metadata: std::iter::once(("request".into(), secret.into())).collect(),
                ..allow_result()
            },
        });
        let registry = registry_with_external(service, registration).await;
        let outcome = ChainRunner::from_registry(registry)
            .evaluate(
                &[ChainEntry {
                    name: "guard".into(),
                    implementation: "local-guard-service".into(),
                    order: 0,
                    config: prost_types::Struct::default(),
                    on_error: OnError::FailClosed,
                }],
                input("hello"),
            )
            .await
            .expect("evaluate external middleware");

        assert_eq!(outcome.reason, "middleware_denied:guard:content_match");
        assert_eq!(
            outcome.denial,
            Some(MiddlewareDenial {
                config_name: "guard".into(),
                reason_code: Some("content_match".into()),
            })
        );
        assert_eq!(
            outcome.findings[0].finding.r#type,
            "local-guard-service.finding"
        );
        assert_eq!(outcome.findings[0].finding.label, EXTERNAL_FINDING_LABEL);
        assert_eq!(outcome.findings[0].finding.severity, "medium");
        assert!(outcome.metadata.is_empty());
        assert!(!format!("{outcome:?}").contains(secret));
        assert!(!format!("{outcome:?}").contains("FINDING:FORGED"));
    }

    #[tokio::test]
    async fn invalid_reason_code_is_a_middleware_failure() {
        let runner = ChainRunner::new_protobuf_for_tests(Arc::new(scripted_service(
            openshell_core::proto::HttpRequestResult {
                decision: Decision::Deny as i32,
                reason_code: "Secret value!".into(),
                ..allow_result()
            },
        )));
        let outcome = runner
            .evaluate(
                &[entry("content-guard", OnError::FailClosed)],
                input("hello"),
            )
            .await
            .expect("evaluate invalid reason code");

        assert!(!outcome.allowed);
        assert_eq!(
            outcome.reason,
            "middleware_failed: response_reason_code_invalid"
        );
        assert!(outcome.denial.is_none());
        assert!(outcome.applied[0].failed);
    }

    #[tokio::test]
    async fn external_header_mutation_failure_uses_platform_reason() {
        let secret = "sk-secret-request-value";
        let registration = external_registration(4096);
        let service = Arc::new(ScriptedService {
            manifest_name: "test/middleware".into(),
            max_body_bytes: 4096,
            result: openshell_core::proto::HttpRequestResult {
                header_mutations: vec![write_header(
                    &format!("x-openshell-middleware-invalid\n{secret}"),
                    "value",
                    ExistingHeaderAction::Append,
                )],
                ..allow_result()
            },
        });
        let registry = registry_with_external(service, registration).await;
        let outcome = ChainRunner::from_registry(registry)
            .evaluate(
                &[ChainEntry {
                    name: "guard".into(),
                    implementation: "local-guard-service".into(),
                    order: 0,
                    config: prost_types::Struct::default(),
                    on_error: OnError::FailClosed,
                }],
                input("hello"),
            )
            .await
            .expect("evaluate external middleware");

        assert!(!outcome.allowed);
        assert_eq!(
            outcome.reason,
            "middleware_failed: header_mutation_invalid_name"
        );
        assert!(outcome.findings.is_empty());
        assert!(!format!("{outcome:?}").contains(secret));
    }

    #[tokio::test]
    async fn connection_nominated_write_and_remove_are_rejected_after_filtering() {
        let mutations = [
            write_header(
                "x-openshell-middleware-tag",
                "value",
                ExistingHeaderAction::Append,
            ),
            HeaderMutation {
                operation: Some(header_mutation::Operation::Remove(
                    openshell_core::proto::RemoveHeader {
                        name: "x-openshell-middleware-tag".into(),
                    },
                )),
            },
        ];

        for mutation in mutations {
            let service = Arc::new(ScriptedService {
                manifest_name: "test/middleware".into(),
                max_body_bytes: 4096,
                result: openshell_core::proto::HttpRequestResult {
                    header_mutations: vec![mutation],
                    ..allow_result()
                },
            });
            let registry = registry_with_external(service, external_registration(4096)).await;
            let mut request = input("hello");
            request.connection_nominated_headers = vec!["x-openshell-middleware-tag".into()];

            let outcome = ChainRunner::from_registry(registry)
                .evaluate(
                    &[ChainEntry {
                        name: "guard".into(),
                        implementation: "local-guard-service".into(),
                        order: 0,
                        config: prost_types::Struct::default(),
                        on_error: OnError::FailClosed,
                    }],
                    request,
                )
                .await
                .expect("evaluate external middleware");

            assert!(!outcome.allowed);
            assert_eq!(
                outcome.reason,
                "middleware_failed: header_mutation_hop_by_hop_header"
            );
        }
    }

    #[tokio::test]
    async fn finding_overflow_is_an_invalid_response_governed_by_on_error() {
        let registration = external_registration(4096);
        let service = Arc::new(ScriptedService {
            manifest_name: "test/middleware".into(),
            max_body_bytes: 4096,
            result: openshell_core::proto::HttpRequestResult {
                findings: vec![Finding::default(); MAX_MIDDLEWARE_FINDINGS_PER_STAGE + 1],
                ..allow_result()
            },
        });
        let registry = registry_with_external(service, registration).await;
        let runner = ChainRunner::from_registry(registry);

        for (on_error, allowed) in [(OnError::FailClosed, false), (OnError::FailOpen, true)] {
            let outcome = runner
                .evaluate(
                    &[ChainEntry {
                        name: "guard".into(),
                        implementation: "local-guard-service".into(),
                        order: 0,
                        config: prost_types::Struct::default(),
                        on_error,
                    }],
                    input("hello"),
                )
                .await
                .expect("evaluate finding overflow");

            assert_eq!(outcome.allowed, allowed);
            assert!(outcome.findings.is_empty());
            assert_eq!(outcome.applied.len(), 1);
            assert!(outcome.applied[0].failed);
            if !allowed {
                assert_eq!(
                    outcome.reason,
                    "middleware_failed: response_findings_over_capacity"
                );
            }
        }
    }

    #[tokio::test]
    async fn maximum_chain_retains_findings_from_every_stage() {
        let runner = ChainRunner::new_protobuf_for_tests(Arc::new(ScriptedService {
            manifest_name: "test/middleware".into(),
            max_body_bytes: 4096,
            result: openshell_core::proto::HttpRequestResult {
                findings: vec![
                    Finding {
                        r#type: "example.finding".into(),
                        label: "Example finding".into(),
                        count: 1,
                        confidence: String::new(),
                        severity: "medium".into(),
                    };
                    MAX_MIDDLEWARE_FINDINGS_PER_STAGE
                ],
                ..allow_result()
            },
        }));
        let entries: Vec<_> = (0..MAX_MIDDLEWARE_CHAIN_STAGES)
            .map(|index| ChainEntry {
                name: format!("guard-{index}"),
                implementation: "test/middleware".into(),
                order: i32::try_from(index).expect("bounded stage index"),
                config: prost_types::Struct::default(),
                on_error: OnError::FailClosed,
            })
            .collect();

        let outcome = runner
            .evaluate(&entries, input("hello"))
            .await
            .expect("evaluate maximum chain");

        assert!(outcome.allowed);
        assert_eq!(outcome.applied.len(), MAX_MIDDLEWARE_CHAIN_STAGES);
        assert_eq!(outcome.findings.len(), MAX_MIDDLEWARE_CHAIN_FINDINGS);
        for (stage, findings) in outcome
            .findings
            .chunks_exact(MAX_MIDDLEWARE_FINDINGS_PER_STAGE)
            .enumerate()
        {
            assert!(
                findings
                    .iter()
                    .all(|finding| finding.middleware == format!("guard-{stage}"))
            );
        }
    }

    #[tokio::test]
    async fn deny_decision_short_circuits_chain() {
        let runner = ChainRunner::new_protobuf_for_tests(Arc::new(scripted_service(
            openshell_core::proto::HttpRequestResult {
                decision: Decision::Deny as i32,
                reason: "blocked_by_policy".into(),
                ..allow_result()
            },
        )));
        let outcome = runner
            .evaluate(
                &[
                    entry("first", OnError::FailClosed),
                    entry("second", OnError::FailClosed),
                ],
                input("hello"),
            )
            .await
            .expect("evaluate");
        assert!(!outcome.allowed);
        assert_eq!(outcome.reason, "middleware_denied:first");
        assert_eq!(
            outcome.denial,
            Some(MiddlewareDenial {
                config_name: "first".into(),
                reason_code: None,
            })
        );
        assert!(!format!("{outcome:?}").contains("blocked_by_policy"));
        // The deny short-circuits the chain: the second middleware never runs.
        assert_eq!(outcome.applied.len(), 1);
        assert_eq!(outcome.applied[0].decision, Decision::Deny);
        assert!(!outcome.applied[0].failed);
    }

    #[tokio::test]
    async fn deny_decision_ignores_unsafe_mutations_under_fail_open() {
        let runner = ChainRunner::new_protobuf_for_tests(Arc::new(scripted_service(
            openshell_core::proto::HttpRequestResult {
                decision: Decision::Deny as i32,
                reason: "blocked_by_policy".into(),
                header_mutations: vec![write_header(
                    "x-openshell-middleware-inject",
                    "ok\r\nHost: evil",
                    ExistingHeaderAction::Append,
                )],
                ..allow_result()
            },
        )));

        let outcome = runner
            .evaluate(&[entry("guard", OnError::FailOpen)], input("hello"))
            .await
            .expect("evaluate");

        assert!(!outcome.allowed);
        assert_eq!(outcome.reason, "middleware_denied:guard");
        assert!(outcome.header_mutations.is_empty());
        assert_eq!(outcome.applied.len(), 1);
        assert_eq!(outcome.applied[0].decision, Decision::Deny);
        assert!(!outcome.applied[0].failed);
    }

    #[tokio::test]
    async fn deny_decision_ignores_oversized_replacement_under_fail_open() {
        let runner = ChainRunner::new_protobuf_for_tests(Arc::new(ScriptedService {
            manifest_name: BUILTIN_REGEX.into(),
            max_body_bytes: 4,
            result: openshell_core::proto::HttpRequestResult {
                decision: Decision::Deny as i32,
                reason: "blocked_by_policy".into(),
                body: b"too large".to_vec(),
                has_body: true,
                ..allow_result()
            },
        }));

        let outcome = runner
            .evaluate(&[entry("guard", OnError::FailOpen)], input("safe"))
            .await
            .expect("evaluate");

        assert!(!outcome.allowed);
        assert_eq!(outcome.reason, "middleware_denied:guard");
        assert_eq!(outcome.body, b"safe");
        assert_eq!(outcome.applied.len(), 1);
        assert_eq!(outcome.applied[0].decision, Decision::Deny);
        assert!(!outcome.applied[0].transformed);
        assert!(!outcome.applied[0].failed);
    }

    #[tokio::test]
    async fn metadata_and_findings_are_namespaced_per_config() {
        let runner = ChainRunner::new_protobuf_for_tests(Arc::new(scripted_service(
            openshell_core::proto::HttpRequestResult {
                findings: vec![Finding {
                    r#type: "pii.email".into(),
                    label: "email address".into(),
                    count: 2,
                    confidence: "high".into(),
                    severity: "medium".into(),
                }],
                metadata: std::iter::once(("sensitivity".to_string(), "high".to_string()))
                    .collect(),
                ..allow_result()
            },
        )));
        let outcome = runner
            .evaluate(
                &[
                    entry("alpha", OnError::FailClosed),
                    entry("beta", OnError::FailClosed),
                ],
                input("hello"),
            )
            .await
            .expect("evaluate");
        assert!(outcome.allowed);
        // Metadata is bucketed under each config's local name, so two configs
        // emitting the same key do not collide.
        assert_eq!(outcome.metadata["alpha"]["sensitivity"], "high");
        assert_eq!(outcome.metadata["beta"]["sensitivity"], "high");
        // Findings are tagged with the emitting config's name.
        assert_eq!(outcome.findings.len(), 2);
        assert_eq!(outcome.findings[0].middleware, "alpha");
        assert_eq!(outcome.findings[1].middleware, "beta");
        assert_eq!(outcome.findings[0].finding.r#type, "pii.email");
        assert_eq!(outcome.findings[0].finding.count, 2);
    }

    fn unsafe_header_service() -> ScriptedService {
        scripted_service(openshell_core::proto::HttpRequestResult {
            header_mutations: vec![
                write_header(
                    "x-openshell-middleware-safe",
                    "safe",
                    ExistingHeaderAction::Append,
                ),
                write_header(
                    "x-openshell-middleware-inject",
                    "ok\r\nHost: evil",
                    ExistingHeaderAction::Append,
                ),
            ],
            ..allow_result()
        })
    }

    #[tokio::test]
    async fn malformed_response_headers_fail_closed_denies() {
        let runner = ChainRunner::new_protobuf_for_tests(Arc::new(unsafe_header_service()));
        let outcome = runner
            .evaluate(&[entry("redact", OnError::FailClosed)], input("hello"))
            .await
            .expect("evaluate");
        assert!(!outcome.allowed);
        assert!(outcome.reason.starts_with("middleware_failed:"));
        // The deny reason names the offending header so operators can fix the
        // service without reading supervisor source.
        assert!(
            outcome.reason.contains("x-openshell-middleware-inject"),
            "reason should name the offending header: {}",
            outcome.reason
        );
        assert!(outcome.applied.iter().any(|inv| inv.failed));
        // The stage is atomic: neither the unsafe mutation nor the safe
        // mutation preceding it is forwarded.
        assert!(outcome.header_mutations.is_empty());
    }

    #[tokio::test]
    async fn malformed_response_headers_fail_open_continues() {
        let runner = ChainRunner::new_protobuf_for_tests(Arc::new(unsafe_header_service()));
        let outcome = runner
            .evaluate(&[entry("redact", OnError::FailOpen)], input("hello"))
            .await
            .expect("evaluate");
        assert!(outcome.allowed);
        assert_eq!(outcome.body, b"hello");
        assert!(outcome.header_mutations.is_empty());
        assert_eq!(outcome.applied.len(), 1);
        assert!(outcome.applied[0].failed);
    }

    #[tokio::test]
    async fn oversized_replacement_body_honors_on_error() {
        let runner = ChainRunner::new_protobuf_for_tests(Arc::new(ScriptedService {
            manifest_name: BUILTIN_REGEX.into(),
            max_body_bytes: 4,
            result: openshell_core::proto::HttpRequestResult {
                body: b"too large".to_vec(),
                has_body: true,
                ..allow_result()
            },
        }));
        let fail_open = entry("small", OnError::FailOpen);
        let mut fail_closed = fail_open.clone();
        fail_closed.on_error = OnError::FailClosed;

        let open_outcome = runner
            .evaluate(&[fail_open], input("safe"))
            .await
            .expect("fail-open evaluation");
        assert!(open_outcome.allowed);
        assert_eq!(open_outcome.body, b"safe");
        assert!(open_outcome.applied[0].failed);

        let closed_outcome = runner
            .evaluate(&[fail_closed], input("safe"))
            .await
            .expect("fail-closed evaluation");
        assert!(!closed_outcome.allowed);
        assert_eq!(
            closed_outcome.reason,
            "middleware_failed: response_body_over_capacity"
        );
        assert!(closed_outcome.applied[0].failed);
    }

    #[tokio::test]
    async fn oversized_request_body_honors_on_error() {
        let runner = ChainRunner::new_protobuf_for_tests(Arc::new(ScriptedService {
            manifest_name: BUILTIN_REGEX.into(),
            max_body_bytes: 4,
            result: allow_result(),
        }));
        let fail_open = entry("small", OnError::FailOpen);
        let mut fail_closed = fail_open.clone();
        fail_closed.on_error = OnError::FailClosed;

        let open_outcome = runner
            .evaluate(&[fail_open], input("hello"))
            .await
            .expect("fail-open evaluation");
        assert!(open_outcome.allowed);
        assert_eq!(open_outcome.body, b"hello");
        assert!(open_outcome.applied[0].failed);

        let closed_outcome = runner
            .evaluate(&[fail_closed], input("hello"))
            .await
            .expect("fail-closed evaluation");
        assert!(!closed_outcome.allowed);
        assert_eq!(
            closed_outcome.reason,
            "middleware_failed: request_body_over_capacity"
        );
        assert!(closed_outcome.applied[0].failed);
    }

    #[tokio::test]
    async fn unspecified_decision_uses_fail_closed() {
        let runner = ChainRunner::new_protobuf_for_tests(Arc::new(scripted_service(
            openshell_core::proto::HttpRequestResult {
                decision: Decision::Unspecified as i32,
                ..allow_result()
            },
        )));

        let outcome = runner
            .evaluate(&[entry("redact", OnError::FailClosed)], input("hello"))
            .await
            .expect("evaluate");

        assert!(!outcome.allowed);
        assert_eq!(
            outcome.reason,
            "middleware_failed: invalid_response_decision"
        );
        assert!(outcome.applied[0].failed);
    }
}
