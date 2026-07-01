// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor middleware registration and chain execution.

mod builtins;
mod remote;
mod service;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, LazyLock};

use miette::{Result, miette};
pub use service::InProcessMiddlewareService;

use openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddleware;
use openshell_core::proto::{
    Decision, Finding, HttpRequestEvaluation, HttpRequestTarget, MiddlewareBinding,
    MiddlewareManifest, NetworkMiddlewareConfig, RequestContext, SandboxPolicy,
    SupervisorMiddlewareService, ValidateConfigRequest,
};
use tokio::sync::OnceCell;
use tonic::Request;

pub const API_VERSION: &str = "openshell.middleware.v1";
pub const BUILTIN_SECRETS: &str = builtins::secrets::BINDING_ID;
const HTTP_REQUEST_OPERATION: &str = "HttpRequest";
const PRE_CREDENTIALS_PHASE: &str = "pre_credentials";

/// Validate the configuration for an in-process middleware implementation.
///
/// Policy admission uses this same implementation-specific validation before a
/// configuration can reach the request path.
pub fn validate_builtin_config(implementation: &str, config: &prost_types::Struct) -> Result<()> {
    builtins::validate_config(implementation, config)
}

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
    pub config: prost_types::Struct,
    pub on_error: OnError,
}

impl TryFrom<&NetworkMiddlewareConfig> for ChainEntry {
    type Error = miette::Report;

    fn try_from(value: &NetworkMiddlewareConfig) -> Result<Self> {
        if value.name.is_empty() {
            return Err(miette!("middleware config name cannot be empty"));
        }
        if value.middleware.is_empty() {
            return Err(miette!(
                "middleware config '{}' must name an implementation",
                value.name
            ));
        }
        Ok(Self {
            name: value.name.clone(),
            implementation: value.middleware.clone(),
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
}

impl DescribedChainEntry {
    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    pub fn on_error(&self) -> OnError {
        self.entry.on_error
    }

    /// True when this entry resolved to a registered binding and will be
    /// evaluated. When false, the binding is absent from the current registry
    /// and the entry is handled entirely by its `on_error` policy, so it
    /// imposes no body-buffering limit on the chain.
    pub fn is_resolved(&self) -> bool {
        self.binding.is_some()
    }
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
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ChainOutcome {
    pub allowed: bool,
    pub reason: String,
    pub body: Vec<u8>,
    pub added_headers: BTreeMap<String, String>,
    pub findings: Vec<NamespacedFinding>,
    pub metadata: BTreeMap<String, BTreeMap<String, String>>,
    pub applied: Vec<MiddlewareInvocation>,
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

struct MiddlewareServiceState {
    service: Arc<dyn SupervisorMiddleware>,
    manifest: OnceCell<MiddlewareManifest>,
    operator_max_body_bytes: Option<usize>,
}

static IN_PROCESS_SERVICE: LazyLock<Arc<MiddlewareServiceState>> = LazyLock::new(|| {
    Arc::new(MiddlewareServiceState {
        service: Arc::new(InProcessMiddlewareService),
        manifest: OnceCell::new(),
        operator_max_body_bytes: None,
    })
});

/// Validated middleware services available to a gateway or one supervisor.
///
/// The registry always contains the in-process built-ins. Operator-registered
/// services are connected and described before construction succeeds, so callers never
/// observe a partially registered service set.
#[derive(Clone)]
pub struct MiddlewareRegistry {
    services: Arc<Vec<Arc<MiddlewareServiceState>>>,
    registered_services: Arc<Vec<RegisteredMiddlewareService>>,
}

impl std::fmt::Debug for MiddlewareRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MiddlewareRegistry")
            .field("service_count", &self.services.len())
            .field("registered_service_count", &self.registered_services.len())
            .finish()
    }
}

#[derive(Clone)]
struct RegisteredMiddlewareService {
    registration: SupervisorMiddlewareService,
    binding_ids: Vec<String>,
}

impl Default for MiddlewareRegistry {
    fn default() -> Self {
        Self {
            services: Arc::new(vec![Arc::clone(&IN_PROCESS_SERVICE)]),
            registered_services: Arc::new(Vec::new()),
        }
    }
}

fn validate_registration(registration: &SupervisorMiddlewareService) -> Result<()> {
    if registration.name.trim().is_empty() {
        return Err(miette!(
            "supervisor middleware registration name cannot be empty"
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
    Ok(())
}

fn validate_external_manifest(
    registration: &SupervisorMiddlewareService,
    manifest: &MiddlewareManifest,
    operator_max_body_bytes: usize,
    known_binding_ids: &mut HashSet<String>,
) -> Result<Vec<String>> {
    if manifest.api_version != API_VERSION {
        return Err(miette!(
            "middleware registration '{}' reports unsupported API version '{}'",
            registration.name,
            manifest.api_version
        ));
    }
    if manifest.bindings.is_empty() {
        return Err(miette!(
            "middleware registration '{}' describes no bindings",
            registration.name
        ));
    }

    let mut described_ids = Vec::with_capacity(manifest.bindings.len());
    for binding in &manifest.bindings {
        if binding.id.trim().is_empty() {
            return Err(miette!(
                "middleware registration '{}' describes an empty binding id",
                registration.name
            ));
        }
        if binding.id.starts_with("openshell/") {
            return Err(miette!(
                "external middleware registration '{}' cannot claim reserved binding '{}'",
                registration.name,
                binding.id
            ));
        }
        if binding.operation != HTTP_REQUEST_OPERATION || binding.phase != PRE_CREDENTIALS_PHASE {
            return Err(miette!(
                "middleware binding '{}' must support {HTTP_REQUEST_OPERATION}/{PRE_CREDENTIALS_PHASE}",
                binding.id
            ));
        }
        let advertised = usize::try_from(binding.max_body_bytes).map_err(|_| {
            miette!(
                "middleware binding '{}' reports a body limit too large for this platform",
                binding.id
            )
        })?;
        if advertised == 0 {
            return Err(miette!(
                "middleware binding '{}' must advertise a non-zero body limit",
                binding.id
            ));
        }
        if operator_max_body_bytes > advertised {
            return Err(miette!(
                "middleware registration '{}' max_body_bytes ({operator_max_body_bytes}) exceeds binding '{}' capability ({advertised})",
                registration.name,
                binding.id
            ));
        }
        if !known_binding_ids.insert(binding.id.clone()) {
            return Err(miette!(
                "middleware binding '{}' is described by more than one service",
                binding.id
            ));
        }
        described_ids.push(binding.id.clone());
    }
    Ok(described_ids)
}

impl MiddlewareRegistry {
    /// Connect and validate every operator-provided service registration.
    pub async fn connect_services(registrations: Vec<SupervisorMiddlewareService>) -> Result<Self> {
        let mut services = vec![Arc::clone(&IN_PROCESS_SERVICE)];
        let mut registered_services = Vec::with_capacity(registrations.len());
        let mut registration_names = HashSet::new();
        let mut binding_ids = HashSet::from([BUILTIN_SECRETS.to_string()]);

        for registration in registrations {
            validate_registration(&registration)?;
            if !registration_names.insert(registration.name.clone()) {
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
            let service = Arc::new(
                remote::RemoteMiddlewareService::connect(
                    &registration.name,
                    &registration.grpc_endpoint,
                )
                .await?,
            );
            let manifest = service
                .describe(Request::new(()))
                .await
                .map(tonic::Response::into_inner)
                .map_err(|error| {
                    miette!(
                        "middleware registration '{}' Describe failed: {}",
                        registration.name,
                        safe_reason(&error.to_string())
                    )
                })?;
            let described_ids = validate_external_manifest(
                &registration,
                &manifest,
                operator_max_body_bytes,
                &mut binding_ids,
            )?;
            let manifest_cell = OnceCell::new();
            manifest_cell
                .set(manifest)
                .map_err(|_| miette!("middleware manifest cache initialized twice"))?;
            services.push(Arc::new(MiddlewareServiceState {
                service,
                manifest: manifest_cell,
                operator_max_body_bytes: Some(operator_max_body_bytes),
            }));
            registered_services.push(RegisteredMiddlewareService {
                registration,
                binding_ids: described_ids,
            });
        }

        Ok(Self {
            services: Arc::new(services),
            registered_services: Arc::new(registered_services),
        })
    }

    /// Validate implementation-owned configuration for every middleware entry.
    pub async fn validate_policy_configs(&self, policy: &SandboxPolicy) -> Result<()> {
        let runner = ChainRunner::from_registry(self.clone());
        for config in &policy.network_middlewares {
            runner
                .validate_config(
                    &config.middleware,
                    config.config.clone().unwrap_or_default(),
                )
                .await
                .map_err(|error| {
                    miette!(
                        "middleware config '{}' is invalid: {}",
                        config.name,
                        safe_reason(&error.to_string())
                    )
                })?;
        }
        Ok(())
    }

    /// Check that every policy binding still belongs to the current static
    /// registry without making a network call.
    pub fn ensure_policy_bindings_registered(&self, policy: &SandboxPolicy) -> Result<()> {
        for config in &policy.network_middlewares {
            let registered = config.middleware == BUILTIN_SECRETS
                || self.registered_services.iter().any(|service| {
                    service
                        .binding_ids
                        .iter()
                        .any(|binding| binding == &config.middleware)
                });
            if !registered {
                return Err(miette!(
                    "middleware binding '{}' used by config '{}' is not registered",
                    config.middleware,
                    config.name
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
            .iter()
            .map(|config| config.middleware.as_str())
            .collect();
        self.registered_services
            .iter()
            .filter(|service| {
                service
                    .binding_ids
                    .iter()
                    .any(|binding| selected.contains(binding.as_str()))
            })
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
    pub fn new(service: Arc<dyn SupervisorMiddleware>) -> Self {
        Self {
            registry: Arc::new(MiddlewareRegistry {
                services: Arc::new(vec![Arc::new(MiddlewareServiceState {
                    service,
                    manifest: OnceCell::new(),
                    operator_max_body_bytes: None,
                })]),
                registered_services: Arc::new(Vec::new()),
            }),
        }
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
                    state
                        .service
                        .describe(Request::new(()))
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

    pub async fn describe_chain(&self, entries: &[ChainEntry]) -> Result<Vec<DescribedChainEntry>> {
        let manifests = self.manifests().await?;
        entries
            .iter()
            .map(|entry| {
                let described = manifests.iter().find_map(|(state, manifest)| {
                    manifest
                        .bindings
                        .iter()
                        .find(|binding| binding.id == entry.implementation)
                        .cloned()
                        .map(|binding| (Arc::clone(state), binding))
                });
                let (service, binding) = described.map_or((None, None), |(service, binding)| {
                    (Some(service), Some(binding))
                });
                let max_body_bytes = binding
                    .as_ref()
                    .map(|binding| {
                        let advertised = usize::try_from(binding.max_body_bytes).map_err(|_| {
                            miette!(
                                "middleware binding '{}' reports a body limit too large for this platform",
                                binding.id
                            )
                        })?;
                        Ok::<_, miette::Report>(service
                            .as_ref()
                            .and_then(|state| state.operator_max_body_bytes)
                            .unwrap_or(advertised))
                    })
                    .transpose()?
                    .unwrap_or(0);
                Ok(DescribedChainEntry {
                    entry: entry.clone(),
                    service,
                    binding,
                    max_body_bytes,
                })
            })
            .collect()
    }

    pub async fn validate_config(
        &self,
        implementation: &str,
        config: prost_types::Struct,
    ) -> Result<()> {
        let manifests = self.manifests().await?;
        let Some((state, _)) = manifests.iter().find(|(_, manifest)| {
            manifest
                .bindings
                .iter()
                .any(|binding| binding.id == implementation)
        }) else {
            return Err(miette!(
                "middleware binding '{implementation}' is not registered"
            ));
        };
        let response = state
            .service
            .validate_config(Request::new(ValidateConfigRequest {
                api_version: API_VERSION.into(),
                binding_id: implementation.into(),
                config: Some(config),
            }))
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
        let mut headers = input.headers.clone();
        let mut body = input.body.clone();
        let mut added_headers = BTreeMap::new();
        let mut findings = Vec::new();
        let mut metadata = BTreeMap::new();
        let mut applied = Vec::new();

        for entry in entries {
            let Some(binding) = entry.binding.as_ref() else {
                match apply_on_error(entry, "binding_not_described", &mut applied) {
                    OnErrorAction::FailOpen => continue,
                    OnErrorAction::FailClosed(reason) => {
                        return Ok(ChainOutcome {
                            allowed: false,
                            reason,
                            body,
                            added_headers,
                            findings,
                            metadata,
                            applied,
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
                            added_headers,
                            findings,
                            metadata,
                            applied,
                        });
                    }
                }
            }
            let evaluation = build_evaluation(entry, binding, &input, &headers, &body);
            let Some(service) = entry.service.as_ref() else {
                unreachable!("described binding always has a service")
            };
            let result = match service
                .service
                .evaluate_http_request(Request::new(evaluation))
                .await
            {
                Ok(result) => result.into_inner(),
                Err(err) => {
                    match apply_on_error(entry, &safe_reason(&err.to_string()), &mut applied) {
                        OnErrorAction::FailOpen => continue,
                        OnErrorAction::FailClosed(reason) => {
                            return Ok(ChainOutcome {
                                allowed: false,
                                reason,
                                body,
                                added_headers,
                                findings,
                                metadata,
                                applied,
                            });
                        }
                    }
                }
            };

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
                                added_headers,
                                findings,
                                metadata,
                                applied,
                            });
                        }
                    }
                }
            };

            if result.has_body && result.body.len() > entry.max_body_bytes {
                match apply_on_error(entry, "response_body_over_capacity", &mut applied) {
                    OnErrorAction::FailOpen => continue,
                    OnErrorAction::FailClosed(reason) => {
                        return Ok(ChainOutcome {
                            allowed: false,
                            reason,
                            body,
                            added_headers,
                            findings,
                            metadata,
                            applied,
                        });
                    }
                }
            }

            // A result proposing unsafe header mutations is a malformed response:
            // route it through `on_error` instead of applying any of it.
            if validate_header_mutations(&headers, &result.add_headers).is_err() {
                match apply_on_error(entry, "unsafe_response_headers", &mut applied) {
                    OnErrorAction::FailOpen => continue,
                    OnErrorAction::FailClosed(reason) => {
                        return Ok(ChainOutcome {
                            allowed: false,
                            reason,
                            body,
                            added_headers,
                            findings,
                            metadata,
                            applied,
                        });
                    }
                }
            }
            for (name, value) in &result.add_headers {
                headers.insert(name.to_ascii_lowercase(), value.clone());
                added_headers.insert(name.to_ascii_lowercase(), value.clone());
            }
            let transformed = result.has_body;
            if result.has_body {
                result.body.clone_into(&mut body);
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
                    result.metadata.clone().into_iter().collect(),
                );
            }
            applied.push(MiddlewareInvocation {
                name: entry.entry.name.clone(),
                implementation: entry.entry.implementation.clone(),
                decision,
                transformed,
                failed: false,
            });
            if decision == Decision::Deny {
                return Ok(ChainOutcome {
                    allowed: false,
                    reason: safe_reason(&result.reason),
                    body,
                    added_headers,
                    findings,
                    metadata,
                    applied,
                });
            }
        }

        Ok(ChainOutcome {
            allowed: true,
            reason: String::new(),
            body,
            added_headers,
            findings,
            metadata,
            applied,
        })
    }
}

fn build_evaluation(
    entry: &DescribedChainEntry,
    binding: &MiddlewareBinding,
    input: &HttpRequestInput,
    headers: &BTreeMap<String, String>,
    body: &[u8],
) -> HttpRequestEvaluation {
    HttpRequestEvaluation {
        api_version: API_VERSION.into(),
        binding_id: binding.id.clone(),
        phase: binding.phase.clone(),
        context: Some(RequestContext {
            request_id: input.request_id.clone(),
            sandbox_id: input.sandbox_id.clone(),
            originating_process: None,
        }),
        config: Some(entry.entry.config.clone()),
        target: Some(HttpRequestTarget {
            scheme: input.scheme.clone(),
            host: input.host.clone(),
            port: u32::from(input.port),
            method: input.method.clone(),
            path: input.path.clone(),
            query: input.query.clone(),
        }),
        headers: headers.clone().into_iter().collect(),
        body: body.to_vec(),
    }
}

fn validate_header_mutations(
    existing_headers: &BTreeMap<String, String>,
    mutations: &HashMap<String, String>,
) -> Result<()> {
    let mut seen = HashSet::new();
    for (name, value) in mutations {
        let lower = name.to_ascii_lowercase();
        if !seen.insert(lower.clone()) || existing_headers.contains_key(&lower) {
            return Err(miette!(
                "middleware cannot rewrite existing header '{name}'"
            ));
        }
        if !is_safe_append_header(&lower) {
            return Err(miette!("middleware cannot append unsafe header '{name}'"));
        }
        // Reject CR/LF and other control characters in the value: writing them
        // verbatim into the upstream header block would enable header injection
        // and request smuggling past the credential boundary.
        if !is_safe_header_value(value) {
            return Err(miette!(
                "middleware cannot append header '{name}' with an unsafe value"
            ));
        }
    }
    Ok(())
}

/// A header value is safe to append only if it contains no control characters.
/// Horizontal tab, printable ASCII, and obs-text (>= 0x80) are permitted; CR, LF,
/// NUL, and other control bytes are rejected.
fn is_safe_header_value(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b) || b >= 0x80)
}

fn is_safe_append_header(name: &str) -> bool {
    if name.is_empty()
        || name.contains(':')
        || name.bytes().any(|b| b <= 0x20 || b >= 0x7f)
        || matches!(
            name,
            "authorization" | "cookie" | "host" | "content-length" | "transfer-encoding"
        )
        || name.starts_with("x-amz-")
        || name.starts_with("x-openshell-credential")
    {
        return false;
    }
    name.starts_with("x-openshell-middleware-")
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
    use tokio_stream::wrappers::TcpListenerStream;

    fn entry(name: &str, on_error: OnError) -> ChainEntry {
        ChainEntry {
            name: name.into(),
            implementation: BUILTIN_SECRETS.into(),
            config: prost_types::Struct {
                fields: std::iter::once((
                    "secrets".into(),
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
            headers: BTreeMap::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[tokio::test]
    async fn phase_one_evaluation_omits_originating_process() {
        let entries = ChainRunner::default()
            .describe_chain(&[entry("redact", OnError::FailClosed)])
            .await
            .expect("describe chain");
        let entry = &entries[0];
        let binding = entry.binding.as_ref().expect("described binding");
        let input = input("payload");
        let evaluation = build_evaluation(entry, binding, &input, &BTreeMap::new(), b"payload");

        assert!(
            evaluation
                .context
                .expect("request context")
                .originating_process
                .is_none()
        );
    }

    #[tokio::test]
    async fn redacts_common_secret_patterns() {
        let outcome = ChainRunner::default()
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
        let outcome = ChainRunner::default()
            .evaluate(&entries, input(r#"password="top-secret""#))
            .await
            .expect("evaluate");
        assert!(outcome.allowed);
        assert_eq!(
            String::from_utf8(outcome.body).expect("utf8"),
            r#"password="[REDACTED]""#
        );
        assert_eq!(outcome.applied.len(), 2);
    }

    #[tokio::test]
    async fn fail_open_allows_unavailable_middleware() {
        let unavailable = ChainEntry {
            name: "missing".into(),
            implementation: "third-party/missing".into(),
            config: prost_types::Struct::default(),
            on_error: OnError::FailOpen,
        };
        let outcome = ChainRunner::default()
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
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        };
        let outcome = ChainRunner::default()
            .evaluate(&[unavailable], input("hello"))
            .await
            .expect("evaluate");
        assert!(!outcome.allowed);
        assert!(outcome.reason.starts_with("middleware_failed:"));
    }

    #[tokio::test]
    async fn in_process_service_describes_builtin_binding() {
        let manifest = InProcessMiddlewareService
            .describe(Request::new(()))
            .await
            .expect("describe")
            .into_inner();
        assert_eq!(manifest.api_version, API_VERSION);
        assert_eq!(manifest.bindings[0].id, BUILTIN_SECRETS);
        assert_eq!(manifest.bindings[0].operation, "HttpRequest");
        assert_eq!(manifest.bindings[0].phase, "pre_credentials");
        assert_eq!(manifest.bindings[0].max_body_bytes, 256 * 1024);
    }

    #[test]
    fn unsafe_header_mutation_is_rejected() {
        let err = validate_header_mutations(
            &BTreeMap::new(),
            &std::iter::once(("Authorization".into(), "Bearer nope".into())).collect(),
        )
        .expect_err("unsafe header");
        assert!(err.to_string().contains("unsafe header"));
    }

    #[test]
    fn header_value_with_crlf_is_rejected() {
        // A safe header *name* with a CRLF-bearing value must still be rejected,
        // otherwise it would inject extra headers into the upstream request.
        let err = validate_header_mutations(
            &BTreeMap::new(),
            &std::iter::once((
                "x-openshell-middleware-inject".into(),
                "ok\r\nAuthorization: Bearer evil".into(),
            ))
            .collect(),
        )
        .expect_err("crlf value");
        assert!(err.to_string().contains("unsafe value"));
    }

    /// A mock middleware that returns a fixed, caller-supplied result for every
    /// evaluation. Used to exercise chain behavior the built-in cannot produce
    /// (explicit deny, metadata, findings, unsafe header mutations).
    struct ScriptedService {
        binding_id: String,
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
                api_version: API_VERSION.into(),
                name: "test/middleware".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    id: self.binding_id.clone(),
                    operation: "HttpRequest".into(),
                    phase: "pre_credentials".into(),
                    max_body_bytes: self.max_body_bytes,
                }],
            }))
        }

        async fn validate_config(
            &self,
            _request: Request<ValidateConfigRequest>,
        ) -> std::result::Result<
            tonic::Response<openshell_core::proto::ValidateConfigResponse>,
            tonic::Status,
        > {
            Ok(tonic::Response::new(
                openshell_core::proto::ValidateConfigResponse {
                    valid: true,
                    reason: String::new(),
                },
            ))
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

    fn scripted_service(result: openshell_core::proto::HttpRequestResult) -> ScriptedService {
        ScriptedService {
            binding_id: BUILTIN_SECRETS.into(),
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
            add_headers: HashMap::new(),
            findings: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    fn external_registration(max_body_bytes: u64) -> SupervisorMiddlewareService {
        SupervisorMiddlewareService {
            name: "local-guard-service".into(),
            grpc_endpoint: "http://127.0.0.1:50051".into(),
            max_body_bytes,
        }
    }

    async fn registry_with_external(
        service: Arc<dyn SupervisorMiddleware>,
        registration: SupervisorMiddlewareService,
    ) -> MiddlewareRegistry {
        let manifest = service
            .describe(Request::new(()))
            .await
            .expect("describe test service")
            .into_inner();
        let operator_max_body_bytes = usize::try_from(registration.max_body_bytes).unwrap();
        let mut known = HashSet::from([BUILTIN_SECRETS.to_string()]);
        let binding_ids = validate_external_manifest(
            &registration,
            &manifest,
            operator_max_body_bytes,
            &mut known,
        )
        .expect("valid external manifest");
        let manifest_cell = OnceCell::new();
        manifest_cell.set(manifest).expect("manifest cache");
        MiddlewareRegistry {
            services: Arc::new(vec![
                Arc::clone(&IN_PROCESS_SERVICE),
                Arc::new(MiddlewareServiceState {
                    service,
                    manifest: manifest_cell,
                    operator_max_body_bytes: Some(operator_max_body_bytes),
                }),
            ]),
            registered_services: Arc::new(vec![RegisteredMiddlewareService {
                registration,
                binding_ids,
            }]),
        }
    }

    #[tokio::test]
    async fn describe_chain_marks_resolved_and_unresolved_entries() {
        let unresolved = ChainEntry {
            name: "missing".into(),
            implementation: "third-party/missing".into(),
            config: prost_types::Struct::default(),
            on_error: OnError::FailOpen,
        };
        let described = ChainRunner::default()
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
        let runner = ChainRunner::new(Arc::new(ScriptedService {
            binding_id: "example/redactor".into(),
            max_body_bytes: 4096,
            result: allow_result(),
        }));
        let entry = ChainEntry {
            name: "external".into(),
            implementation: "example/redactor".into(),
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
            "pre_credentials"
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
            binding_id: "example/content-guard".into(),
            max_body_bytes: 4096,
            result: allow_result(),
        });
        let registry = registry_with_external(external, external_registration(1024)).await;
        let runner = ChainRunner::from_registry(registry);
        let external_entry = ChainEntry {
            name: "external".into(),
            implementation: "example/content-guard".into(),
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
            .evaluate_described(&described, input(r#"password="top-secret""#))
            .await
            .expect("evaluate mixed chain");
        assert!(outcome.allowed);
        assert_eq!(outcome.applied.len(), 2);
        assert_eq!(
            String::from_utf8(outcome.body).expect("utf8"),
            r#"password="[REDACTED]""#
        );
    }

    #[test]
    fn external_manifest_rejects_operator_limit_above_capability() {
        let registration = external_registration(4097);
        let manifest = MiddlewareManifest {
            api_version: API_VERSION.into(),
            name: "example/service".into(),
            service_version: "test".into(),
            bindings: vec![MiddlewareBinding {
                id: "example/content-guard".into(),
                operation: HTTP_REQUEST_OPERATION.into(),
                phase: PRE_CREDENTIALS_PHASE.into(),
                max_body_bytes: 4096,
            }],
        };
        let error = validate_external_manifest(
            &registration,
            &manifest,
            4097,
            &mut HashSet::from([BUILTIN_SECRETS.to_string()]),
        )
        .expect_err("operator limit must fit capability");
        assert!(error.to_string().contains("exceeds"));
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

    #[tokio::test]
    async fn external_registry_invokes_remote_service_over_grpc() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test middleware");
        let address = listener.local_addr().expect("test middleware address");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tonic::transport::Server::builder()
            .add_service(SupervisorMiddlewareServer::new(ScriptedService {
                binding_id: "example/content-guard".into(),
                max_body_bytes: 4096,
                result: allow_result(),
            }))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            });
        let server_task = tokio::spawn(server);

        let mut registration = external_registration(1024);
        registration.grpc_endpoint = format!("http://{address}");
        let registry = MiddlewareRegistry::connect_services(vec![registration.clone()])
            .await
            .expect("connect external middleware");
        let policy = SandboxPolicy {
            network_middlewares: vec![NetworkMiddlewareConfig {
                name: "guard".into(),
                middleware: "example/content-guard".into(),
                config: Some(prost_types::Struct::default()),
                on_error: "fail_closed".into(),
                endpoints: None,
            }],
            ..Default::default()
        };

        registry
            .validate_policy_configs(&policy)
            .await
            .expect("remote config validates");
        assert_eq!(
            registry.required_services(Some(&policy)),
            vec![registration]
        );

        let outcome = ChainRunner::from_registry(registry)
            .evaluate(
                &[ChainEntry {
                    name: "guard".into(),
                    implementation: "example/content-guard".into(),
                    config: prost_types::Struct::default(),
                    on_error: OnError::FailClosed,
                }],
                input("hello"),
            )
            .await
            .expect("remote evaluation");
        assert!(outcome.allowed);

        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("join test middleware")
            .expect("serve");
    }

    #[tokio::test]
    async fn deny_decision_short_circuits_chain() {
        let runner = ChainRunner::new(Arc::new(scripted_service(
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
        assert_eq!(outcome.reason, "blocked_by_policy");
        // The deny short-circuits the chain: the second middleware never runs.
        assert_eq!(outcome.applied.len(), 1);
        assert_eq!(outcome.applied[0].decision, Decision::Deny);
        assert!(!outcome.applied[0].failed);
    }

    #[tokio::test]
    async fn metadata_and_findings_are_namespaced_per_config() {
        let runner = ChainRunner::new(Arc::new(scripted_service(
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
            add_headers: std::iter::once((
                "x-openshell-middleware-inject".to_string(),
                "ok\r\nHost: evil".to_string(),
            ))
            .collect(),
            ..allow_result()
        })
    }

    #[tokio::test]
    async fn malformed_response_headers_fail_closed_denies() {
        let runner = ChainRunner::new(Arc::new(unsafe_header_service()));
        let outcome = runner
            .evaluate(&[entry("redact", OnError::FailClosed)], input("hello"))
            .await
            .expect("evaluate");
        assert!(!outcome.allowed);
        assert!(outcome.reason.starts_with("middleware_failed:"));
        assert!(outcome.applied.iter().any(|inv| inv.failed));
        // The unsafe header is never forwarded.
        assert!(outcome.added_headers.is_empty());
    }

    #[tokio::test]
    async fn malformed_response_headers_fail_open_continues() {
        let runner = ChainRunner::new(Arc::new(unsafe_header_service()));
        let outcome = runner
            .evaluate(&[entry("redact", OnError::FailOpen)], input("hello"))
            .await
            .expect("evaluate");
        assert!(outcome.allowed);
        assert_eq!(outcome.body, b"hello");
        assert!(outcome.added_headers.is_empty());
        assert_eq!(outcome.applied.len(), 1);
        assert!(outcome.applied[0].failed);
    }

    #[tokio::test]
    async fn oversized_replacement_body_honors_on_error() {
        let runner = ChainRunner::new(Arc::new(ScriptedService {
            binding_id: BUILTIN_SECRETS.into(),
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
        let runner = ChainRunner::new(Arc::new(ScriptedService {
            binding_id: BUILTIN_SECRETS.into(),
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
        let runner = ChainRunner::new(Arc::new(scripted_service(
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
