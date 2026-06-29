// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway interceptor framework.
//!
//! The gateway integrates this crate once at the gRPC routing boundary. The
//! runtime uses the generated protobuf descriptor set to decode unary
//! `openshell.v1.OpenShell` request frames into protobuf-JSON-shaped values,
//! apply interceptor decisions, and re-encode the request before tonic reaches
//! the handler. Handler modules do not need per-method interceptor hooks.

#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use hyper_util::rt::TokioIo;
use json_patch::{PatchOperation, patch};
use metrics::{counter, histogram};
use openshell_core::config::{
    GatewayInterceptorBindingOverride, GatewayInterceptorConfig, GatewayInterceptorFailurePolicy,
    GatewayInterceptorPhaseConfig,
};
use openshell_core::proto::gateway_interceptor::v1::{
    DescribeRequest, GatewayInterceptorPhase, InterceptorBinding, InterceptorEvaluation,
    InterceptorResult, InterceptorSelector, JsonPatch,
    gateway_interceptor_client::GatewayInterceptorClient,
};
use prost::Message as _;
use prost_types::{
    DescriptorProto, EnumDescriptorProto, FieldDescriptorProto, FileDescriptorProto,
    FileDescriptorSet, Struct,
    field_descriptor_proto::{Label, Type},
};
use serde_json::{Map, Number, Value};
use tokio::net::UnixStream;
use tonic::codegen::http::Uri;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request, Status};
use tower::service_fn;
use tracing::{info, warn};

pub mod routes;

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(500);
const DEFAULT_MAX_RESPONSE_BYTES: usize = 1_048_576;
const DEFAULT_MAX_PATCHES: usize = 32;
const GRPC_HEADER_LEN: usize = 5;

#[derive(Debug, thiserror::Error)]
pub enum InterceptorError {
    #[error("invalid interceptor config: {0}")]
    Config(String),
    #[error("interceptor transport error: {0}")]
    Transport(String),
    #[error("invalid interceptor result: {0}")]
    InvalidResult(String),
    #[error("protobuf transcode error: {0}")]
    Transcode(String),
}

pub type Result<T> = std::result::Result<T, InterceptorError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Phase {
    ModifyOperation,
    Validate,
    PostCommit,
}

impl Phase {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ModifyOperation => "modify_operation",
            Self::Validate => "validate",
            Self::PostCommit => "post_commit",
        }
    }

    #[must_use]
    pub const fn to_proto(self) -> GatewayInterceptorPhase {
        match self {
            Self::ModifyOperation => GatewayInterceptorPhase::ModifyOperation,
            Self::Validate => GatewayInterceptorPhase::Validate,
            Self::PostCommit => GatewayInterceptorPhase::PostCommit,
        }
    }
}

impl TryFrom<GatewayInterceptorPhase> for Phase {
    type Error = InterceptorError;

    fn try_from(value: GatewayInterceptorPhase) -> Result<Self> {
        match value {
            GatewayInterceptorPhase::ModifyOperation => Ok(Self::ModifyOperation),
            GatewayInterceptorPhase::Validate => Ok(Self::Validate),
            GatewayInterceptorPhase::PostCommit => Ok(Self::PostCommit),
            GatewayInterceptorPhase::Unspecified => Err(InterceptorError::Config(
                "binding phase must not be unspecified".to_string(),
            )),
        }
    }
}

impl From<GatewayInterceptorPhaseConfig> for Phase {
    fn from(value: GatewayInterceptorPhaseConfig) -> Self {
        match value {
            GatewayInterceptorPhaseConfig::ModifyOperation => Self::ModifyOperation,
            GatewayInterceptorPhaseConfig::Validate => Self::Validate,
            GatewayInterceptorPhaseConfig::PostCommit => Self::PostCommit,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailurePolicy {
    FailClosed,
    FailOpen,
}

impl FailurePolicy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::FailOpen => "fail_open",
        }
    }
}

impl From<GatewayInterceptorFailurePolicy> for FailurePolicy {
    fn from(value: GatewayInterceptorFailurePolicy) -> Self {
        match value {
            GatewayInterceptorFailurePolicy::FailClosed => Self::FailClosed,
            GatewayInterceptorFailurePolicy::FailOpen => Self::FailOpen,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RpcSelector {
    pub service: String,
    pub method: String,
}

impl RpcSelector {
    #[must_use]
    pub fn new(service: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            method: method.into(),
        }
    }

    #[must_use]
    pub fn rpc(&self) -> String {
        format!("{}/{}", self.service, self.method)
    }

    #[must_use]
    pub fn from_grpc_path(path: &str) -> Option<Self> {
        let path = path.strip_prefix('/').unwrap_or(path);
        let (service, method) = path.rsplit_once('/')?;
        Some(Self::new(service, method))
    }
}

#[derive(Clone)]
struct BindingPlan {
    interceptor_name: String,
    binding_id: String,
    selector: RpcSelector,
    phase: Phase,
    failure_policy: FailurePolicy,
    timeout: Duration,
    max_response_bytes: usize,
    max_patches: usize,
    client: GatewayInterceptorClient<Channel>,
}

impl std::fmt::Debug for BindingPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BindingPlan")
            .field("interceptor_name", &self.interceptor_name)
            .field("binding_id", &self.binding_id)
            .field("selector", &self.selector)
            .field("phase", &self.phase)
            .field("failure_policy", &self.failure_policy)
            .field("timeout", &self.timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_patches", &self.max_patches)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct GatewayInterceptorRuntime {
    bindings: Arc<BTreeMap<(RpcSelector, Phase), Vec<BindingPlan>>>,
    routes: Arc<routes::OpenShellRouteIndex>,
    descriptors: Arc<ProtoDescriptors>,
}

#[derive(Debug, Clone)]
pub struct EvaluationContext {
    pub principal: BTreeMap<String, String>,
    pub current_state: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct InterceptedRequest {
    pub body: Vec<u8>,
    selector: RpcSelector,
    operation: Value,
}

/// Return `None` when no interceptors are configured.
pub async fn initialize(
    configs: Vec<GatewayInterceptorConfig>,
) -> Result<Option<GatewayInterceptorRuntime>> {
    if configs.is_empty() {
        return Ok(None);
    }
    let runtime = GatewayInterceptorRuntime::build(configs).await?;
    Ok(Some(runtime))
}

impl GatewayInterceptorRuntime {
    async fn build(mut configs: Vec<GatewayInterceptorConfig>) -> Result<Self> {
        configs.sort_by(|a, b| a.order.cmp(&b.order).then_with(|| a.name.cmp(&b.name)));

        let routes =
            routes::OpenShellRouteIndex::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET)?;
        let descriptors =
            ProtoDescriptors::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET)?;
        let mut bindings: BTreeMap<(RpcSelector, Phase), Vec<BindingPlan>> = BTreeMap::new();

        for config in configs {
            validate_service_config(&config)?;
            let channel = connect_endpoint(&config.grpc_endpoint).await?;
            let timeout = match config.timeout.as_deref() {
                Some(timeout) => parse_duration(timeout)?,
                None => DEFAULT_TIMEOUT,
            };
            let mut client = GatewayInterceptorClient::new(channel.clone())
                .max_decoding_message_size(
                    config
                        .max_response_bytes
                        .unwrap_or(DEFAULT_MAX_RESPONSE_BYTES),
                );
            let manifest =
                tokio::time::timeout(timeout, client.describe(Request::new(DescribeRequest {})))
                    .await
                    .map_err(|_| {
                        InterceptorError::Transport(format!(
                            "Describe timed out for '{}'",
                            config.name
                        ))
                    })?
                    .map_err(|status| {
                        InterceptorError::Transport(format!(
                            "Describe failed for '{}': {status}",
                            config.name
                        ))
                    })?
                    .into_inner();
            let manifest_default = parse_optional_failure_policy(&manifest.failure_policy)?;
            let service_default = config
                .failure_policy
                .map(FailurePolicy::from)
                .or(manifest_default)
                .unwrap_or(FailurePolicy::FailClosed);
            let max_response_bytes = config
                .max_response_bytes
                .unwrap_or(DEFAULT_MAX_RESPONSE_BYTES);
            let max_patches = config.max_patches.unwrap_or(DEFAULT_MAX_PATCHES);

            let override_index = OverrideIndex::new(&config.bindings)?;
            for manifest_binding in &manifest.bindings {
                let normalized = normalize_binding(
                    &config.name,
                    manifest_binding,
                    service_default,
                    &override_index,
                )?;
                let Some(normalized) = normalized else {
                    continue;
                };
                if !routes
                    .is_interceptable(&normalized.selector.service, &normalized.selector.method)
                {
                    return Err(InterceptorError::Config(format!(
                        "interceptor '{}' binding '{}' targets non-interceptable RPC '{}'",
                        config.name,
                        normalized.binding_id,
                        normalized.selector.rpc()
                    )));
                }
                for phase in normalized.phases {
                    let plan = BindingPlan {
                        interceptor_name: config.name.clone(),
                        binding_id: normalized.binding_id.clone(),
                        selector: normalized.selector.clone(),
                        phase,
                        failure_policy: normalized.failure_policy,
                        timeout,
                        max_response_bytes,
                        max_patches,
                        client: GatewayInterceptorClient::new(channel.clone())
                            .max_decoding_message_size(max_response_bytes),
                    };
                    bindings
                        .entry((normalized.selector.clone(), phase))
                        .or_default()
                        .push(plan);
                }
            }
        }

        let count: usize = bindings.values().map(Vec::len).sum();
        info!(bindings = count, "gateway interceptors initialized");
        Ok(Self {
            bindings: Arc::new(bindings),
            routes: Arc::new(routes),
            descriptors: Arc::new(descriptors),
        })
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    #[must_use]
    pub fn should_intercept_path(&self, path: &str) -> bool {
        let Some(selector) = RpcSelector::from_grpc_path(path) else {
            return false;
        };
        self.routes
            .is_interceptable(&selector.service, &selector.method)
            && [Phase::ModifyOperation, Phase::Validate, Phase::PostCommit]
                .iter()
                .any(|phase| self.bindings.contains_key(&(selector.clone(), *phase)))
    }

    pub async fn evaluate_request(
        &self,
        path: &str,
        body: &[u8],
        context: &EvaluationContext,
    ) -> std::result::Result<InterceptedRequest, Status> {
        let selector = RpcSelector::from_grpc_path(path)
            .ok_or_else(|| Status::invalid_argument("invalid gRPC method path"))?;
        let input_type = self
            .routes
            .input_type(&selector.service, &selector.method)
            .ok_or_else(|| Status::invalid_argument("unknown OpenShell method"))?
            .to_string();
        let frame = GrpcFrame::decode(body)?;
        let mut operation = self
            .descriptors
            .decode_message_to_json(&input_type, &frame.message)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;

        operation = self
            .evaluate_phase(&selector, Phase::ModifyOperation, operation, context)
            .await?;
        operation = self
            .evaluate_phase(&selector, Phase::Validate, operation, context)
            .await?;

        let message = self
            .descriptors
            .encode_json_to_message(&input_type, &operation)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        let body = GrpcFrame {
            compressed: false,
            message,
        }
        .encode()
        .map_err(|err| Status::invalid_argument(err.to_string()))?;

        Ok(InterceptedRequest {
            body,
            selector,
            operation,
        })
    }

    pub async fn evaluate_post_commit(
        &self,
        intercepted: &InterceptedRequest,
        context: &EvaluationContext,
    ) -> std::result::Result<(), Status> {
        self.evaluate_phase(
            &intercepted.selector,
            Phase::PostCommit,
            intercepted.operation.clone(),
            context,
        )
        .await
        .map(|_| ())
    }

    async fn evaluate_phase(
        &self,
        selector: &RpcSelector,
        phase: Phase,
        operation: Value,
        context: &EvaluationContext,
    ) -> std::result::Result<Value, Status> {
        let Some(plans) = self.bindings.get(&(selector.clone(), phase)) else {
            return Ok(operation);
        };

        let mut operation = operation;
        for plan in plans {
            let result = evaluate_plan(plan, operation.clone(), context).await;
            let result = match result {
                Ok(result) => result,
                Err(err) => {
                    apply_failure_policy(plan, &err)?;
                    continue;
                }
            };

            if let Err(err) = validate_result_contract(plan, &result) {
                apply_failure_policy(plan, &err)?;
                continue;
            }

            if !result.allowed {
                let reason = if result.reason.trim().is_empty() {
                    "operation denied by gateway interceptor".to_string()
                } else {
                    result.reason.clone()
                };
                emit_evaluation_metrics(plan, "deny", 0);
                emit_evaluation_log(plan, &result, "deny", 0);
                return Err(status_from_result(&result, reason));
            }

            if phase == Phase::ModifyOperation && !result.patches.is_empty() {
                let patch_count = result.patches.len();
                match apply_json_patches(&operation, &result.patches) {
                    Ok(patched) => {
                        operation = patched;
                        emit_evaluation_metrics(plan, "allow", patch_count);
                        emit_evaluation_log(plan, &result, "allow", patch_count);
                    }
                    Err(err) => {
                        apply_failure_policy(plan, &err)?;
                    }
                }
            } else {
                emit_evaluation_metrics(plan, "allow", 0);
                emit_evaluation_log(plan, &result, "allow", 0);
            }
        }
        Ok(operation)
    }
}

#[derive(Debug, Clone)]
struct NormalizedBinding {
    binding_id: String,
    selector: RpcSelector,
    phases: Vec<Phase>,
    failure_policy: FailurePolicy,
}

#[derive(Debug)]
struct OverrideIndex<'a> {
    by_id: HashMap<&'a str, &'a GatewayInterceptorBindingOverride>,
    by_selector: HashMap<String, &'a GatewayInterceptorBindingOverride>,
}

impl<'a> OverrideIndex<'a> {
    fn new(overrides: &'a [GatewayInterceptorBindingOverride]) -> Result<Self> {
        let mut by_id = HashMap::new();
        let mut by_selector = HashMap::new();
        for override_cfg in overrides {
            if let Some(id) = override_cfg.id.as_deref()
                && by_id.insert(id, override_cfg).is_some()
            {
                return Err(InterceptorError::Config(format!(
                    "duplicate interceptor binding override id '{id}'"
                )));
            }
            if let Some(selector) = override_selector(override_cfg)?
                && by_selector.insert(selector.rpc(), override_cfg).is_some()
            {
                return Err(InterceptorError::Config(format!(
                    "duplicate interceptor binding override selector '{}'",
                    selector.rpc()
                )));
            }
        }
        Ok(Self { by_id, by_selector })
    }

    fn get(
        &self,
        binding_id: &str,
        selector: &RpcSelector,
    ) -> Option<&'a GatewayInterceptorBindingOverride> {
        self.by_id
            .get(binding_id)
            .or_else(|| self.by_selector.get(&selector.rpc()))
            .copied()
    }
}

fn validate_service_config(config: &GatewayInterceptorConfig) -> Result<()> {
    if config.name.trim().is_empty() {
        return Err(InterceptorError::Config(
            "interceptor name must not be empty".to_string(),
        ));
    }
    if config.grpc_endpoint.trim().is_empty() {
        return Err(InterceptorError::Config(format!(
            "interceptor '{}' grpc_endpoint must not be empty",
            config.name
        )));
    }
    if let Some(timeout) = config.timeout.as_deref() {
        parse_duration(timeout)?;
    }
    Ok(())
}

fn normalize_binding(
    interceptor_name: &str,
    binding: &InterceptorBinding,
    service_default: FailurePolicy,
    overrides: &OverrideIndex<'_>,
) -> Result<Option<NormalizedBinding>> {
    let binding_id = binding.id.trim();
    if binding_id.is_empty() {
        return Err(InterceptorError::Config(format!(
            "interceptor '{interceptor_name}' declared a binding without id"
        )));
    }

    let selector = selector_from_proto(binding.selector.as_ref())?;
    let mut phases = binding
        .phases
        .iter()
        .map(|phase| {
            GatewayInterceptorPhase::try_from(*phase)
                .map_err(|_| InterceptorError::Config("unknown binding phase".to_string()))
                .and_then(Phase::try_from)
        })
        .collect::<Result<Vec<_>>>()?;
    phases.sort_unstable();
    phases.dedup();
    if phases.is_empty() {
        return Err(InterceptorError::Config(format!(
            "interceptor '{interceptor_name}' binding '{binding_id}' declares no phases"
        )));
    }

    let mut failure_policy =
        parse_optional_failure_policy(&binding.failure_policy)?.unwrap_or(service_default);

    if let Some(override_cfg) = overrides.get(binding_id, &selector) {
        if let Some(override_selector) = override_selector(override_cfg)?
            && override_selector != selector
        {
            return Err(InterceptorError::Config(format!(
                "override for binding '{binding_id}' cannot widen selector '{}' to '{}'",
                selector.rpc(),
                override_selector.rpc()
            )));
        }
        if override_cfg.disabled {
            return Ok(None);
        }
        if let Some(override_phases) = &override_cfg.phases {
            let override_set: BTreeSet<Phase> =
                override_phases.iter().copied().map(Phase::from).collect();
            let declared: BTreeSet<Phase> = phases.iter().copied().collect();
            if !override_set.is_subset(&declared) {
                return Err(InterceptorError::Config(format!(
                    "override for binding '{binding_id}' cannot add phases not declared by the manifest"
                )));
            }
            phases = override_set.into_iter().collect();
        }
        if let Some(policy) = override_cfg.failure_policy {
            failure_policy = policy.into();
        }
    }

    Ok(Some(NormalizedBinding {
        binding_id: binding_id.to_string(),
        selector,
        phases,
        failure_policy,
    }))
}

fn selector_from_proto(selector: Option<&InterceptorSelector>) -> Result<RpcSelector> {
    let selector = selector
        .ok_or_else(|| InterceptorError::Config("binding selector is required".to_string()))?;
    if !selector.rpc.trim().is_empty() {
        return parse_rpc_selector(&selector.rpc);
    }
    if selector.service.trim().is_empty() || selector.method.trim().is_empty() {
        return Err(InterceptorError::Config(
            "binding selector requires rpc or service+method".to_string(),
        ));
    }
    Ok(RpcSelector::new(
        selector.service.trim(),
        selector.method.trim(),
    ))
}

fn override_selector(
    override_cfg: &GatewayInterceptorBindingOverride,
) -> Result<Option<RpcSelector>> {
    if let Some(rpc) = override_cfg.rpc.as_deref()
        && !rpc.trim().is_empty()
    {
        return parse_rpc_selector(rpc).map(Some);
    }
    match (
        override_cfg
            .service
            .as_deref()
            .filter(|v| !v.trim().is_empty()),
        override_cfg
            .method
            .as_deref()
            .filter(|v| !v.trim().is_empty()),
    ) {
        (Some(service), Some(method)) => Ok(Some(RpcSelector::new(service.trim(), method.trim()))),
        (None, None) => Ok(None),
        _ => Err(InterceptorError::Config(
            "binding override selector requires both service and method".to_string(),
        )),
    }
}

fn parse_rpc_selector(value: &str) -> Result<RpcSelector> {
    let (service, method) = value.trim().split_once('/').ok_or_else(|| {
        InterceptorError::Config(format!(
            "RPC selector '{value}' must have form service/method"
        ))
    })?;
    if service.is_empty() || method.is_empty() || method.contains('/') {
        return Err(InterceptorError::Config(format!(
            "RPC selector '{value}' must have form service/method"
        )));
    }
    Ok(RpcSelector::new(service, method))
}

fn parse_optional_failure_policy(value: &str) -> Result<Option<FailurePolicy>> {
    match value.trim() {
        "" => Ok(None),
        "fail_closed" => Ok(Some(FailurePolicy::FailClosed)),
        "fail_open" => Ok(Some(FailurePolicy::FailOpen)),
        other => Err(InterceptorError::Config(format!(
            "unsupported failure_policy '{other}'"
        ))),
    }
}

pub fn parse_duration(value: &str) -> Result<Duration> {
    let value = value.trim();
    if value.is_empty() {
        return Err(InterceptorError::Config(
            "timeout must not be empty".to_string(),
        ));
    }
    if let Some(ms) = value.strip_suffix("ms") {
        let millis = ms
            .parse::<u64>()
            .map_err(|_| InterceptorError::Config(format!("invalid timeout '{value}'")))?;
        return Ok(Duration::from_millis(millis));
    }
    if let Some(seconds) = value.strip_suffix('s') {
        let seconds = seconds
            .parse::<u64>()
            .map_err(|_| InterceptorError::Config(format!("invalid timeout '{value}'")))?;
        return Ok(Duration::from_secs(seconds));
    }
    Err(InterceptorError::Config(format!(
        "invalid timeout '{value}'; expected suffix ms or s"
    )))
}

async fn connect_endpoint(endpoint: &str) -> Result<Channel> {
    let endpoint = endpoint.trim();
    if let Some(path) = endpoint.strip_prefix("unix://") {
        return connect_unix_endpoint(PathBuf::from(path)).await;
    }
    Endpoint::from_shared(endpoint.to_string())
        .map_err(|e| {
            InterceptorError::Config(format!("invalid interceptor endpoint '{endpoint}': {e}"))
        })?
        .connect()
        .await
        .map_err(|e| InterceptorError::Transport(format!("connect {endpoint}: {e}")))
}

#[cfg(unix)]
async fn connect_unix_endpoint(path: PathBuf) -> Result<Channel> {
    let display = path.display().to_string();
    Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move { UnixStream::connect(path).await.map(TokioIo::new) }
        }))
        .await
        .map_err(|e| InterceptorError::Transport(format!("connect unix://{display}: {e}")))
}

#[cfg(not(unix))]
async fn connect_unix_endpoint(path: PathBuf) -> Result<Channel> {
    Err(InterceptorError::Config(format!(
        "unix interceptor endpoints are not supported on this platform: {}",
        path.display()
    )))
}

async fn evaluate_plan(
    plan: &BindingPlan,
    operation: Value,
    context: &EvaluationContext,
) -> Result<InterceptorResult> {
    let operation = json_to_struct(operation)?;
    let current_state = context
        .current_state
        .clone()
        .map(json_to_struct)
        .transpose()?
        .unwrap_or_default();
    let request = InterceptorEvaluation {
        interceptor_name: plan.interceptor_name.clone(),
        binding_id: plan.binding_id.clone(),
        service: plan.selector.service.clone(),
        method: plan.selector.method.clone(),
        phase: plan.phase.to_proto() as i32,
        operation: Some(operation),
        current_state: Some(current_state),
        principal: context.principal.clone().into_iter().collect(),
    };

    let start = Instant::now();
    let result = tokio::time::timeout(
        plan.timeout,
        plan.client.clone().evaluate(Request::new(request)),
    )
    .await
    .map_err(|_| InterceptorError::Transport("evaluation timed out".to_string()))?
    .map_err(|status| InterceptorError::Transport(status.to_string()))?
    .into_inner();
    let encoded_len = result.encoded_len();
    histogram!("openshell_gateway_interceptor_latency_seconds")
        .record(start.elapsed().as_secs_f64());
    if encoded_len > plan.max_response_bytes {
        return Err(InterceptorError::InvalidResult(format!(
            "interceptor response exceeded max_response_bytes ({} > {})",
            encoded_len, plan.max_response_bytes
        )));
    }
    Ok(result)
}

fn apply_failure_policy(
    plan: &BindingPlan,
    err: &InterceptorError,
) -> std::result::Result<(), Status> {
    match plan.failure_policy {
        FailurePolicy::FailClosed => {
            warn!(
                interceptor = %plan.interceptor_name,
                binding_id = %plan.binding_id,
                phase = plan.phase.as_str(),
                error = %err,
                "gateway interceptor failed closed"
            );
            counter!("openshell_gateway_interceptor_fail_closed_total").increment(1);
            Err(Status::permission_denied(format!(
                "gateway interceptor '{}' failed closed: {err}",
                plan.interceptor_name
            )))
        }
        FailurePolicy::FailOpen => {
            warn!(
                interceptor = %plan.interceptor_name,
                binding_id = %plan.binding_id,
                phase = plan.phase.as_str(),
                error = %err,
                "gateway interceptor failed open"
            );
            counter!("openshell_gateway_interceptor_fail_open_total").increment(1);
            Ok(())
        }
    }
}

fn validate_result_contract(plan: &BindingPlan, result: &InterceptorResult) -> Result<()> {
    if result.patches.len() > plan.max_patches {
        return Err(InterceptorError::InvalidResult(format!(
            "interceptor returned too many patches ({} > {})",
            result.patches.len(),
            plan.max_patches
        )));
    }
    if plan.phase != Phase::ModifyOperation && !result.patches.is_empty() {
        return Err(InterceptorError::InvalidResult(format!(
            "patches are invalid during {}",
            plan.phase.as_str()
        )));
    }
    if plan.phase == Phase::PostCommit && (!result.allowed || !result.patches.is_empty()) {
        return Err(InterceptorError::InvalidResult(
            "post_commit cannot deny or mutate operations".to_string(),
        ));
    }
    Ok(())
}

fn status_from_result(result: &InterceptorResult, reason: String) -> Status {
    let code = grpc_code_from_name(&result.status_code).unwrap_or(Code::PermissionDenied);
    Status::new(code, reason)
}

fn grpc_code_from_name(value: &str) -> Option<Code> {
    match value.trim().to_ascii_uppercase().as_str() {
        "OK" => Some(Code::Ok),
        "CANCELLED" => Some(Code::Cancelled),
        "UNKNOWN" => Some(Code::Unknown),
        "INVALID_ARGUMENT" => Some(Code::InvalidArgument),
        "DEADLINE_EXCEEDED" => Some(Code::DeadlineExceeded),
        "NOT_FOUND" => Some(Code::NotFound),
        "ALREADY_EXISTS" => Some(Code::AlreadyExists),
        "PERMISSION_DENIED" => Some(Code::PermissionDenied),
        "RESOURCE_EXHAUSTED" => Some(Code::ResourceExhausted),
        "FAILED_PRECONDITION" => Some(Code::FailedPrecondition),
        "ABORTED" => Some(Code::Aborted),
        "OUT_OF_RANGE" => Some(Code::OutOfRange),
        "UNIMPLEMENTED" => Some(Code::Unimplemented),
        "INTERNAL" => Some(Code::Internal),
        "UNAVAILABLE" => Some(Code::Unavailable),
        "DATA_LOSS" => Some(Code::DataLoss),
        "UNAUTHENTICATED" => Some(Code::Unauthenticated),
        _ => None,
    }
}

fn json_patch_operations(patches: &[JsonPatch]) -> Result<Vec<PatchOperation>> {
    let mut raw = Vec::with_capacity(patches.len());
    for patch in patches {
        let mut op = Map::new();
        op.insert("op".to_string(), Value::String(patch.op.clone()));
        op.insert("path".to_string(), Value::String(patch.path.clone()));
        if !patch.from.is_empty() {
            op.insert("from".to_string(), Value::String(patch.from.clone()));
        }
        if let Some(value) = patch.value.as_ref() {
            op.insert("value".to_string(), protobuf_value_to_json(value));
        }
        raw.push(Value::Object(op));
    }
    serde_json::from_value(Value::Array(raw))
        .map_err(|e| InterceptorError::InvalidResult(format!("invalid JSON patch: {e}")))
}

fn apply_json_patches(operation: &Value, patches: &[JsonPatch]) -> Result<Value> {
    let patch_ops = json_patch_operations(patches)?;
    let mut candidate = operation.clone();
    patch(&mut candidate, &patch_ops)
        .map_err(|err| InterceptorError::InvalidResult(format!("invalid JSON patch: {err}")))?;
    Ok(candidate)
}

fn emit_evaluation_metrics(plan: &BindingPlan, result: &str, patch_count: usize) {
    counter!(
        "openshell_gateway_interceptor_evaluations_total",
        "decision" => result.to_string(),
        "interceptor" => plan.interceptor_name.clone(),
        "binding_id" => plan.binding_id.clone(),
    )
    .increment(1);
    if patch_count > 0 {
        counter!(
            "openshell_gateway_interceptor_patches_total",
            "interceptor" => plan.interceptor_name.clone(),
            "binding_id" => plan.binding_id.clone(),
        )
        .increment(patch_count as u64);
    }
}

fn emit_evaluation_log(
    plan: &BindingPlan,
    result: &InterceptorResult,
    decision: &str,
    patch_count: usize,
) {
    info!(
        interceptor = %plan.interceptor_name,
        binding_id = %plan.binding_id,
        phase = plan.phase.as_str(),
        service = %plan.selector.service,
        method = %plan.selector.method,
        decision,
        patch_count,
        log_annotations = ?result.log_annotations,
        "gateway interceptor evaluated"
    );
}

#[derive(Debug, Clone)]
struct GrpcFrame {
    compressed: bool,
    message: Vec<u8>,
}

impl GrpcFrame {
    fn decode(body: &[u8]) -> std::result::Result<Self, Status> {
        if body.len() < GRPC_HEADER_LEN {
            return Err(Status::invalid_argument("gRPC request frame is too short"));
        }
        let compressed = body[0] != 0;
        if compressed {
            return Err(Status::unimplemented(
                "gateway interceptors do not support compressed gRPC requests",
            ));
        }
        let len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
        if body.len() != GRPC_HEADER_LEN + len {
            return Err(Status::invalid_argument(
                "gRPC request must contain exactly one frame",
            ));
        }
        Ok(Self {
            compressed,
            message: body[GRPC_HEADER_LEN..].to_vec(),
        })
    }

    fn encode(&self) -> Result<Vec<u8>> {
        if self.compressed {
            return Err(InterceptorError::Transcode(
                "compressed gRPC frames are not supported".to_string(),
            ));
        }
        let len = u32::try_from(self.message.len())
            .map_err(|_| InterceptorError::Transcode("message exceeds u32".to_string()))?;
        let mut out = Vec::with_capacity(GRPC_HEADER_LEN + self.message.len());
        out.push(0);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.message);
        Ok(out)
    }
}

#[derive(Debug, Clone, Default)]
struct ProtoDescriptors {
    messages: HashMap<String, MessageDesc>,
    enums: HashMap<String, EnumDesc>,
}

impl ProtoDescriptors {
    fn from_descriptor_set(bytes: &[u8]) -> Result<Self> {
        let set = FileDescriptorSet::decode(bytes)
            .map_err(|e| InterceptorError::Config(format!("decode descriptor set: {e}")))?;
        let mut descriptors = Self::default();
        for file in &set.file {
            descriptors.add_file(file)?;
        }
        Ok(descriptors)
    }

    fn add_file(&mut self, file: &FileDescriptorProto) -> Result<()> {
        let package = file.package.as_deref().unwrap_or("");
        for message in &file.message_type {
            self.add_message(package, None, message)?;
        }
        for enum_desc in &file.enum_type {
            self.add_enum(package, None, enum_desc);
        }
        Ok(())
    }

    fn add_message(
        &mut self,
        package: &str,
        parent: Option<&str>,
        message: &DescriptorProto,
    ) -> Result<()> {
        let name = message.name.as_deref().unwrap_or("");
        let full_name = join_type_name(package, parent, name);
        let map_entry = message
            .options
            .as_ref()
            .is_some_and(prost_types::MessageOptions::map_entry);
        let mut fields = BTreeMap::new();
        let mut fields_by_json = HashMap::new();
        for field in &message.field {
            let field_desc = FieldDesc::from_proto(field)?;
            fields_by_json.insert(field_desc.json_name.clone(), field_desc.number);
            fields_by_json.insert(field_desc.name.clone(), field_desc.number);
            fields.insert(field_desc.number, field_desc);
        }
        self.messages.insert(
            full_name.clone(),
            MessageDesc {
                fields,
                fields_by_json,
                map_entry,
            },
        );
        for nested in &message.nested_type {
            self.add_message(package, Some(&full_name), nested)?;
        }
        for enum_desc in &message.enum_type {
            self.add_enum(package, Some(&full_name), enum_desc);
        }
        Ok(())
    }

    fn add_enum(&mut self, package: &str, parent: Option<&str>, enum_desc: &EnumDescriptorProto) {
        let name = enum_desc.name.as_deref().unwrap_or("");
        let full_name = join_type_name(package, parent, name);
        let mut names_by_number = HashMap::new();
        let mut numbers_by_name = HashMap::new();
        for value in &enum_desc.value {
            let Some(name) = value.name.as_ref() else {
                continue;
            };
            let number = value.number();
            names_by_number.insert(number, name.clone());
            numbers_by_name.insert(name.clone(), number);
        }
        self.enums.insert(
            full_name,
            EnumDesc {
                names_by_number,
                numbers_by_name,
            },
        );
    }

    fn message(&self, name: &str) -> Result<&MessageDesc> {
        self.messages
            .get(trim_type_name(name))
            .ok_or_else(|| InterceptorError::Transcode(format!("unknown message type '{name}'")))
    }

    fn field_is_map(&self, field: &FieldDesc) -> bool {
        field.repeated
            && field.kind == FieldKind::Message
            && field
                .type_name
                .as_ref()
                .and_then(|name| self.messages.get(name))
                .is_some_and(|message| message.map_entry)
    }

    fn decode_message_to_json(&self, type_name: &str, bytes: &[u8]) -> Result<Value> {
        if let Some(value) = decode_well_known_json(type_name, bytes) {
            return value;
        }

        let message = self.message(type_name)?;
        let mut values: HashMap<u32, Vec<Value>> = HashMap::new();
        let mut input = bytes;
        while !input.is_empty() {
            let key = decode_varint(&mut input)?;
            let field_number = u32::try_from(key >> 3)
                .map_err(|_| InterceptorError::Transcode("field number overflow".to_string()))?;
            let wire_type = u8::try_from(key & 0x07)
                .map_err(|_| InterceptorError::Transcode("wire type overflow".to_string()))?;
            let Some(field) = message.fields.get(&field_number) else {
                skip_unknown(wire_type, &mut input)?;
                continue;
            };
            let decoded = self.decode_field_value(field, wire_type, &mut input)?;
            values.entry(field_number).or_default().extend(decoded);
        }

        let mut out = Map::new();
        for field in message.fields.values() {
            let field_values = values.remove(&field.number).unwrap_or_default();
            if field_values.is_empty() && !field.repeated {
                continue;
            }
            let value = if self.field_is_map(field) {
                Self::map_values_to_json(field, field_values)?
            } else if field.repeated {
                Value::Array(field_values)
            } else {
                field_values.last().cloned().expect("empty values skipped")
            };
            out.insert(field.json_name.clone(), value);
        }
        Ok(Value::Object(out))
    }

    fn decode_field_value(
        &self,
        field: &FieldDesc,
        wire_type: u8,
        input: &mut &[u8],
    ) -> Result<Vec<Value>> {
        if wire_type == 2 && field.repeated && field.is_packable() {
            let bytes = decode_length_delimited(input)?;
            let mut packed = bytes.as_slice();
            let mut values = Vec::new();
            while !packed.is_empty() {
                values.push(self.decode_scalar_json(
                    field,
                    field.packed_wire_type(),
                    &mut packed,
                )?);
            }
            return Ok(values);
        }
        Ok(vec![self.decode_scalar_json(field, wire_type, input)?])
    }

    fn decode_scalar_json(
        &self,
        field: &FieldDesc,
        wire_type: u8,
        input: &mut &[u8],
    ) -> Result<Value> {
        match field.kind {
            FieldKind::Double => {
                expect_wire(wire_type, 1)?;
                Ok(number_json(f64::from_bits(decode_fixed64(input)?)))
            }
            FieldKind::Float => {
                expect_wire(wire_type, 5)?;
                Ok(number_json(f64::from(f32::from_bits(decode_fixed32(
                    input,
                )?))))
            }
            FieldKind::Int64 | FieldKind::Sfixed64 | FieldKind::Sint64 => {
                let value = if field.kind == FieldKind::Sfixed64 {
                    expect_wire(wire_type, 1)?;
                    decode_fixed64(input)?.cast_signed()
                } else if field.kind == FieldKind::Sint64 {
                    expect_wire(wire_type, 0)?;
                    decode_zigzag64(decode_varint(input)?)
                } else {
                    expect_wire(wire_type, 0)?;
                    decode_varint(input)?.cast_signed()
                };
                Ok(Value::String(value.to_string()))
            }
            FieldKind::Uint64 | FieldKind::Fixed64 => {
                let value = if field.kind == FieldKind::Fixed64 {
                    expect_wire(wire_type, 1)?;
                    decode_fixed64(input)?
                } else {
                    expect_wire(wire_type, 0)?;
                    decode_varint(input)?
                };
                Ok(Value::String(value.to_string()))
            }
            FieldKind::Int32 | FieldKind::Sint32 | FieldKind::Sfixed32 => {
                let value = if field.kind == FieldKind::Sfixed32 {
                    expect_wire(wire_type, 5)?;
                    decode_fixed32(input)?.cast_signed()
                } else if field.kind == FieldKind::Sint32 {
                    expect_wire(wire_type, 0)?;
                    let raw = u32::try_from(decode_varint(input)?).map_err(|_| {
                        InterceptorError::Transcode(format!("{} exceeds sint32", field.name))
                    })?;
                    decode_zigzag32(raw)
                } else {
                    expect_wire(wire_type, 0)?;
                    i32::try_from(decode_varint(input)?).map_err(|_| {
                        InterceptorError::Transcode(format!("{} exceeds int32", field.name))
                    })?
                };
                Ok(Value::Number(Number::from(value)))
            }
            FieldKind::Uint32 | FieldKind::Fixed32 => {
                let value = if field.kind == FieldKind::Fixed32 {
                    expect_wire(wire_type, 5)?;
                    decode_fixed32(input)?
                } else {
                    expect_wire(wire_type, 0)?;
                    u32::try_from(decode_varint(input)?).map_err(|_| {
                        InterceptorError::Transcode(format!("{} exceeds u32", field.name))
                    })?
                };
                Ok(Value::Number(Number::from(value)))
            }
            FieldKind::Bool => {
                expect_wire(wire_type, 0)?;
                Ok(Value::Bool(decode_varint(input)? != 0))
            }
            FieldKind::String => {
                expect_wire(wire_type, 2)?;
                let bytes = decode_length_delimited(input)?;
                String::from_utf8(bytes)
                    .map(Value::String)
                    .map_err(|e| InterceptorError::Transcode(format!("invalid UTF-8: {e}")))
            }
            FieldKind::Bytes => {
                expect_wire(wire_type, 2)?;
                let bytes = decode_length_delimited(input)?;
                Ok(Value::String(
                    base64::engine::general_purpose::STANDARD.encode(bytes),
                ))
            }
            FieldKind::Enum => {
                expect_wire(wire_type, 0)?;
                let number = i32::try_from(decode_varint(input)?).map_err(|_| {
                    InterceptorError::Transcode(format!("{} exceeds enum int32", field.name))
                })?;
                if let Some(enum_type) = field
                    .type_name
                    .as_ref()
                    .and_then(|name| self.enums.get(name))
                    && let Some(name) = enum_type.names_by_number.get(&number)
                {
                    return Ok(Value::String(name.clone()));
                }
                Ok(Value::Number(Number::from(number)))
            }
            FieldKind::Message => {
                expect_wire(wire_type, 2)?;
                let bytes = decode_length_delimited(input)?;
                let type_name = field.type_name.as_deref().ok_or_else(|| {
                    InterceptorError::Transcode(format!(
                        "message field {} lacks type_name",
                        field.name
                    ))
                })?;
                self.decode_message_to_json(type_name, &bytes)
            }
        }
    }

    fn map_values_to_json(_field: &FieldDesc, values: Vec<Value>) -> Result<Value> {
        let mut map = Map::new();
        for value in values {
            let Value::Object(mut entry) = value else {
                return Err(InterceptorError::Transcode(
                    "map entry was not object".to_string(),
                ));
            };
            let key = entry
                .remove("key")
                .ok_or_else(|| InterceptorError::Transcode("map entry missing key".to_string()))?;
            let key = match key {
                Value::String(value) => value,
                Value::Number(value) => value.to_string(),
                Value::Bool(value) => value.to_string(),
                other => {
                    return Err(InterceptorError::Transcode(format!(
                        "unsupported map key value {other:?}"
                    )));
                }
            };
            let value = entry.remove("value").unwrap_or(Value::Null);
            map.insert(key, value);
        }
        Ok(Value::Object(map))
    }

    fn encode_json_to_message(&self, type_name: &str, value: &Value) -> Result<Vec<u8>> {
        if let Some(encoded) = encode_well_known_json(type_name, value) {
            return encoded;
        }

        let message = self.message(type_name)?;
        let Value::Object(map) = value else {
            return Err(InterceptorError::Transcode(format!(
                "{type_name} JSON must be an object"
            )));
        };
        let mut out = Vec::new();
        for (json_name, value) in map {
            if value.is_null() {
                continue;
            }
            let Some(number) = message.fields_by_json.get(json_name) else {
                return Err(InterceptorError::Transcode(format!(
                    "unknown field '{json_name}' on {type_name}"
                )));
            };
            let field = message.fields.get(number).expect("field index is valid");
            if self.field_is_map(field) {
                self.encode_map_field(field, value, &mut out)?;
            } else if field.repeated {
                let Value::Array(values) = value else {
                    return Err(InterceptorError::Transcode(format!(
                        "repeated field '{}' must be an array",
                        field.json_name
                    )));
                };
                for item in values {
                    self.encode_field(field, item, &mut out)?;
                }
            } else {
                self.encode_field(field, value, &mut out)?;
            }
        }
        Ok(out)
    }

    fn encode_map_field(&self, field: &FieldDesc, value: &Value, out: &mut Vec<u8>) -> Result<()> {
        let Value::Object(map) = value else {
            return Err(InterceptorError::Transcode(format!(
                "map field '{}' must be an object",
                field.json_name
            )));
        };
        let entry_type = field.type_name.as_deref().ok_or_else(|| {
            InterceptorError::Transcode(format!("map field '{}' lacks entry type", field.name))
        })?;
        for (key, value) in map {
            let entry = Value::Object(Map::from_iter([
                ("key".to_string(), Value::String(key.clone())),
                ("value".to_string(), value.clone()),
            ]));
            let encoded = self.encode_json_to_message(entry_type, &entry)?;
            encode_key(field.number, 2, out);
            encode_length_delimited(&encoded, out)?;
        }
        Ok(())
    }

    fn encode_field(&self, field: &FieldDesc, value: &Value, out: &mut Vec<u8>) -> Result<()> {
        match field.kind {
            FieldKind::Double => {
                encode_key(field.number, 1, out);
                out.extend_from_slice(&json_f64(value, &field.json_name)?.to_bits().to_le_bytes());
            }
            FieldKind::Float => {
                encode_key(field.number, 5, out);
                out.extend_from_slice(&json_f32(value, &field.json_name)?.to_bits().to_le_bytes());
            }
            FieldKind::Int64 => {
                encode_key(field.number, 0, out);
                encode_varint(json_i64(value, &field.json_name)?.cast_unsigned(), out);
            }
            FieldKind::Uint64 => {
                encode_key(field.number, 0, out);
                encode_varint(json_u64(value, &field.json_name)?, out);
            }
            FieldKind::Int32 => {
                encode_key(field.number, 0, out);
                encode_varint(
                    u64::from(json_i32(value, &field.json_name)?.cast_unsigned()),
                    out,
                );
            }
            FieldKind::Fixed64 => {
                encode_key(field.number, 1, out);
                out.extend_from_slice(&json_u64(value, &field.json_name)?.to_le_bytes());
            }
            FieldKind::Fixed32 => {
                encode_key(field.number, 5, out);
                out.extend_from_slice(&json_u32(value, &field.json_name)?.to_le_bytes());
            }
            FieldKind::Bool => {
                encode_key(field.number, 0, out);
                encode_varint(u64::from(json_bool(value, &field.json_name)?), out);
            }
            FieldKind::String => {
                encode_key(field.number, 2, out);
                let value = json_string(value, &field.json_name)?;
                encode_length_delimited(value.as_bytes(), out)?;
            }
            FieldKind::Bytes => {
                encode_key(field.number, 2, out);
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(json_string(value, &field.json_name)?)
                    .map_err(|e| {
                        InterceptorError::Transcode(format!("invalid base64 bytes: {e}"))
                    })?;
                encode_length_delimited(&decoded, out)?;
            }
            FieldKind::Uint32 => {
                encode_key(field.number, 0, out);
                encode_varint(u64::from(json_u32(value, &field.json_name)?), out);
            }
            FieldKind::Enum => {
                encode_key(field.number, 0, out);
                let number = self.json_enum_number(field, value)?;
                encode_varint(u64::from(number.cast_unsigned()), out);
            }
            FieldKind::Sfixed32 => {
                encode_key(field.number, 5, out);
                out.extend_from_slice(&json_i32(value, &field.json_name)?.to_le_bytes());
            }
            FieldKind::Sfixed64 => {
                encode_key(field.number, 1, out);
                out.extend_from_slice(&json_i64(value, &field.json_name)?.to_le_bytes());
            }
            FieldKind::Sint32 => {
                encode_key(field.number, 0, out);
                encode_varint(
                    u64::from(encode_zigzag32(json_i32(value, &field.json_name)?)),
                    out,
                );
            }
            FieldKind::Sint64 => {
                encode_key(field.number, 0, out);
                encode_varint(encode_zigzag64(json_i64(value, &field.json_name)?), out);
            }
            FieldKind::Message => {
                let type_name = field.type_name.as_deref().ok_or_else(|| {
                    InterceptorError::Transcode(format!(
                        "message field {} lacks type_name",
                        field.name
                    ))
                })?;
                let encoded = self.encode_json_to_message(type_name, value)?;
                encode_key(field.number, 2, out);
                encode_length_delimited(&encoded, out)?;
            }
        }
        Ok(())
    }

    fn json_enum_number(&self, field: &FieldDesc, value: &Value) -> Result<i32> {
        match value {
            Value::String(name) => {
                let type_name = field.type_name.as_deref().ok_or_else(|| {
                    InterceptorError::Transcode(format!(
                        "enum field {} lacks type_name",
                        field.name
                    ))
                })?;
                self.enums
                    .get(type_name)
                    .and_then(|desc| desc.numbers_by_name.get(name))
                    .copied()
                    .ok_or_else(|| {
                        InterceptorError::Transcode(format!(
                            "unknown enum value '{name}' for {}",
                            field.json_name
                        ))
                    })
            }
            Value::Number(number) => number
                .as_i64()
                .and_then(|value| i32::try_from(value).ok())
                .ok_or_else(|| {
                    InterceptorError::Transcode(format!("{} must be enum", field.json_name))
                }),
            _ => Err(InterceptorError::Transcode(format!(
                "{} must be enum string or number",
                field.json_name
            ))),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct MessageDesc {
    fields: BTreeMap<u32, FieldDesc>,
    fields_by_json: HashMap<String, u32>,
    map_entry: bool,
}

#[derive(Debug, Clone)]
struct FieldDesc {
    name: String,
    json_name: String,
    number: u32,
    repeated: bool,
    kind: FieldKind,
    type_name: Option<String>,
}

impl FieldDesc {
    fn from_proto(field: &FieldDescriptorProto) -> Result<Self> {
        let name = field.name.clone().unwrap_or_default();
        let json_name = field
            .json_name
            .clone()
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| snake_to_lower_camel(&name));
        let number = u32::try_from(field.number())
            .map_err(|_| InterceptorError::Config(format!("field '{name}' has invalid number")))?;
        let repeated = field.label() == Label::Repeated;
        let kind = FieldKind::from_type(field.r#type())?;
        let type_name = field
            .type_name
            .as_ref()
            .map(|name| trim_type_name(name).to_string());
        Ok(Self {
            name,
            json_name,
            number,
            repeated,
            kind,
            type_name,
        })
    }

    fn is_packable(&self) -> bool {
        !matches!(
            self.kind,
            FieldKind::String | FieldKind::Bytes | FieldKind::Message
        )
    }

    fn packed_wire_type(&self) -> u8 {
        match self.kind {
            FieldKind::Double | FieldKind::Fixed64 | FieldKind::Sfixed64 => 1,
            FieldKind::Float | FieldKind::Fixed32 | FieldKind::Sfixed32 => 5,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldKind {
    Double,
    Float,
    Int64,
    Uint64,
    Int32,
    Fixed64,
    Fixed32,
    Bool,
    String,
    Message,
    Bytes,
    Uint32,
    Enum,
    Sfixed32,
    Sfixed64,
    Sint32,
    Sint64,
}

impl FieldKind {
    fn from_type(value: Type) -> Result<Self> {
        match value {
            Type::Double => Ok(Self::Double),
            Type::Float => Ok(Self::Float),
            Type::Int64 => Ok(Self::Int64),
            Type::Uint64 => Ok(Self::Uint64),
            Type::Int32 => Ok(Self::Int32),
            Type::Fixed64 => Ok(Self::Fixed64),
            Type::Fixed32 => Ok(Self::Fixed32),
            Type::Bool => Ok(Self::Bool),
            Type::String => Ok(Self::String),
            Type::Group => Err(InterceptorError::Transcode(
                "protobuf groups are not supported".to_string(),
            )),
            Type::Message => Ok(Self::Message),
            Type::Bytes => Ok(Self::Bytes),
            Type::Uint32 => Ok(Self::Uint32),
            Type::Enum => Ok(Self::Enum),
            Type::Sfixed32 => Ok(Self::Sfixed32),
            Type::Sfixed64 => Ok(Self::Sfixed64),
            Type::Sint32 => Ok(Self::Sint32),
            Type::Sint64 => Ok(Self::Sint64),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct EnumDesc {
    names_by_number: HashMap<i32, String>,
    numbers_by_name: HashMap<String, i32>,
}

fn join_type_name(package: &str, parent: Option<&str>, name: &str) -> String {
    parent.map_or_else(
        || {
            if package.is_empty() {
                name.to_string()
            } else {
                format!("{package}.{name}")
            }
        },
        |parent| format!("{parent}.{name}"),
    )
}

fn trim_type_name(name: &str) -> &str {
    name.strip_prefix('.').unwrap_or(name)
}

fn snake_to_lower_camel(value: &str) -> String {
    let mut out = String::new();
    let mut uppercase = false;
    for ch in value.chars() {
        if ch == '_' {
            uppercase = true;
        } else if uppercase {
            out.extend(ch.to_uppercase());
            uppercase = false;
        } else {
            out.push(ch);
        }
    }
    out
}

fn json_to_struct(value: Value) -> Result<Struct> {
    match value {
        Value::Object(fields) => Ok(Struct {
            fields: fields
                .into_iter()
                .map(|(key, value)| json_to_protobuf_value(value).map(|value| (key, value)))
                .collect::<Result<_>>()?,
        }),
        _ => Err(InterceptorError::Transcode(
            "operation JSON must be an object".to_string(),
        )),
    }
}

fn json_to_list_value(value: Value) -> Result<prost_types::ListValue> {
    match value {
        Value::Array(values) => Ok(prost_types::ListValue {
            values: values
                .into_iter()
                .map(json_to_protobuf_value)
                .collect::<Result<_>>()?,
        }),
        _ => Err(InterceptorError::Transcode(
            "google.protobuf.ListValue JSON must be an array".to_string(),
        )),
    }
}

fn json_to_protobuf_value(value: Value) -> Result<prost_types::Value> {
    let kind = match value {
        Value::Null => prost_types::value::Kind::NullValue(0),
        Value::Bool(value) => prost_types::value::Kind::BoolValue(value),
        Value::Number(value) => prost_types::value::Kind::NumberValue(
            value
                .as_f64()
                .ok_or_else(|| InterceptorError::Transcode("invalid JSON number".to_string()))?,
        ),
        Value::String(value) => prost_types::value::Kind::StringValue(value),
        Value::Array(values) => prost_types::value::Kind::ListValue(prost_types::ListValue {
            values: values
                .into_iter()
                .map(json_to_protobuf_value)
                .collect::<Result<_>>()?,
        }),
        Value::Object(fields) => prost_types::value::Kind::StructValue(Struct {
            fields: fields
                .into_iter()
                .map(|(key, value)| json_to_protobuf_value(value).map(|value| (key, value)))
                .collect::<Result<_>>()?,
        }),
    };
    Ok(prost_types::Value { kind: Some(kind) })
}

fn decode_well_known_json(type_name: &str, bytes: &[u8]) -> Option<Result<Value>> {
    match trim_type_name(type_name) {
        "google.protobuf.Struct" => Some(
            Struct::decode(bytes)
                .map(|value| protobuf_struct_to_json(&value))
                .map_err(|err| {
                    InterceptorError::Transcode(format!(
                        "invalid google.protobuf.Struct bytes: {err}"
                    ))
                }),
        ),
        "google.protobuf.Value" => Some(
            prost_types::Value::decode(bytes)
                .map(|value| protobuf_value_to_json(&value))
                .map_err(|err| {
                    InterceptorError::Transcode(format!(
                        "invalid google.protobuf.Value bytes: {err}"
                    ))
                }),
        ),
        "google.protobuf.ListValue" => Some(
            prost_types::ListValue::decode(bytes)
                .map(|value| protobuf_list_value_to_json(&value))
                .map_err(|err| {
                    InterceptorError::Transcode(format!(
                        "invalid google.protobuf.ListValue bytes: {err}"
                    ))
                }),
        ),
        _ => None,
    }
}

fn encode_well_known_json(type_name: &str, value: &Value) -> Option<Result<Vec<u8>>> {
    match trim_type_name(type_name) {
        "google.protobuf.Struct" => {
            Some(json_to_struct(value.clone()).map(|value| value.encode_to_vec()))
        }
        "google.protobuf.Value" => {
            Some(json_to_protobuf_value(value.clone()).map(|value| value.encode_to_vec()))
        }
        "google.protobuf.ListValue" => {
            Some(json_to_list_value(value.clone()).map(|value| value.encode_to_vec()))
        }
        _ => None,
    }
}

fn protobuf_struct_to_json(value: &Struct) -> Value {
    Value::Object(
        value
            .fields
            .iter()
            .map(|(key, value)| (key.clone(), protobuf_value_to_json(value)))
            .collect(),
    )
}

fn protobuf_list_value_to_json(value: &prost_types::ListValue) -> Value {
    Value::Array(value.values.iter().map(protobuf_value_to_json).collect())
}

fn protobuf_value_to_json(value: &prost_types::Value) -> Value {
    match value.kind.as_ref() {
        Some(prost_types::value::Kind::NullValue(_)) | None => Value::Null,
        Some(prost_types::value::Kind::NumberValue(value)) => number_json(*value),
        Some(prost_types::value::Kind::StringValue(value)) => Value::String(value.clone()),
        Some(prost_types::value::Kind::BoolValue(value)) => Value::Bool(*value),
        Some(prost_types::value::Kind::StructValue(value)) => protobuf_struct_to_json(value),
        Some(prost_types::value::Kind::ListValue(value)) => protobuf_list_value_to_json(value),
    }
}

fn number_json(value: f64) -> Value {
    Number::from_f64(value).map_or(Value::Null, Value::Number)
}

fn expect_wire(actual: u8, expected: u8) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(InterceptorError::Transcode(format!(
            "wire type mismatch: got {actual}, expected {expected}"
        )))
    }
}

fn decode_varint(input: &mut &[u8]) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let Some((&byte, rest)) = input.split_first() else {
            return Err(InterceptorError::Transcode("truncated varint".to_string()));
        };
        *input = rest;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(InterceptorError::Transcode("varint overflow".to_string()))
}

fn decode_fixed32(input: &mut &[u8]) -> Result<u32> {
    if input.len() < 4 {
        return Err(InterceptorError::Transcode("truncated fixed32".to_string()));
    }
    let (bytes, rest) = input.split_at(4);
    *input = rest;
    Ok(u32::from_le_bytes(
        bytes.try_into().expect("length checked"),
    ))
}

fn decode_fixed64(input: &mut &[u8]) -> Result<u64> {
    if input.len() < 8 {
        return Err(InterceptorError::Transcode("truncated fixed64".to_string()));
    }
    let (bytes, rest) = input.split_at(8);
    *input = rest;
    Ok(u64::from_le_bytes(
        bytes.try_into().expect("length checked"),
    ))
}

fn decode_length_delimited(input: &mut &[u8]) -> Result<Vec<u8>> {
    let len = usize::try_from(decode_varint(input)?)
        .map_err(|_| InterceptorError::Transcode("length overflow".to_string()))?;
    if input.len() < len {
        return Err(InterceptorError::Transcode(
            "truncated length-delimited field".to_string(),
        ));
    }
    let (bytes, rest) = input.split_at(len);
    *input = rest;
    Ok(bytes.to_vec())
}

fn skip_unknown(wire_type: u8, input: &mut &[u8]) -> Result<()> {
    match wire_type {
        0 => {
            decode_varint(input)?;
        }
        1 => {
            decode_fixed64(input)?;
        }
        2 => {
            decode_length_delimited(input)?;
        }
        5 => {
            decode_fixed32(input)?;
        }
        other => {
            return Err(InterceptorError::Transcode(format!(
                "unsupported unknown wire type {other}"
            )));
        }
    }
    Ok(())
}

fn decode_zigzag32(value: u32) -> i32 {
    (value >> 1).cast_signed() ^ -((value & 1).cast_signed())
}

fn decode_zigzag64(value: u64) -> i64 {
    (value >> 1).cast_signed() ^ -((value & 1).cast_signed())
}

fn encode_zigzag32(value: i32) -> u32 {
    ((value << 1) ^ (value >> 31)).cast_unsigned()
}

fn encode_zigzag64(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)).cast_unsigned()
}

fn encode_key(field_number: u32, wire_type: u8, out: &mut Vec<u8>) {
    encode_varint((u64::from(field_number) << 3) | u64::from(wire_type), out);
}

fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        let byte = u8::try_from(value & 0x7f).expect("masked varint byte fits u8");
        out.push(byte | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value).expect("final varint byte fits u8"));
}

fn encode_length_delimited(bytes: &[u8], out: &mut Vec<u8>) -> Result<()> {
    encode_varint(
        u64::try_from(bytes.len())
            .map_err(|_| InterceptorError::Transcode("length overflow".to_string()))?,
        out,
    );
    out.extend_from_slice(bytes);
    Ok(())
}

fn json_string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .as_str()
        .ok_or_else(|| InterceptorError::Transcode(format!("{field} must be a string")))
}

fn json_bool(value: &Value, field: &str) -> Result<bool> {
    value
        .as_bool()
        .ok_or_else(|| InterceptorError::Transcode(format!("{field} must be a bool")))
}

fn json_f64(value: &Value, field: &str) -> Result<f64> {
    value
        .as_f64()
        .ok_or_else(|| InterceptorError::Transcode(format!("{field} must be a number")))
}

#[allow(clippy::cast_possible_truncation)]
fn json_f32(value: &Value, field: &str) -> Result<f32> {
    let value = json_f64(value, field)?;
    if value.is_finite() && value >= f64::from(f32::MIN) && value <= f64::from(f32::MAX) {
        Ok(value as f32)
    } else {
        Err(InterceptorError::Transcode(format!(
            "{field} must be a finite float"
        )))
    }
}

fn json_i64(value: &Value, field: &str) -> Result<i64> {
    match value {
        Value::String(value) => value
            .parse()
            .map_err(|_| InterceptorError::Transcode(format!("{field} must be int64 string"))),
        Value::Number(value) => value
            .as_i64()
            .or_else(|| integral_f64(value).and_then(|value| i64::try_from(value).ok()))
            .ok_or_else(|| InterceptorError::Transcode(format!("{field} must be int64"))),
        _ => Err(InterceptorError::Transcode(format!(
            "{field} must be int64"
        ))),
    }
}

fn json_u64(value: &Value, field: &str) -> Result<u64> {
    match value {
        Value::String(value) => value
            .parse()
            .map_err(|_| InterceptorError::Transcode(format!("{field} must be uint64 string"))),
        Value::Number(value) => value
            .as_u64()
            .or_else(|| integral_f64(value).and_then(|value| u64::try_from(value).ok()))
            .ok_or_else(|| InterceptorError::Transcode(format!("{field} must be uint64"))),
        _ => Err(InterceptorError::Transcode(format!(
            "{field} must be uint64"
        ))),
    }
}

fn integral_f64(value: &Number) -> Option<i128> {
    let value = value.as_f64()?;
    if value.fract() == 0.0 && value.is_finite() {
        format!("{value:.0}").parse().ok()
    } else {
        None
    }
}

fn json_i32(value: &Value, field: &str) -> Result<i32> {
    i32::try_from(json_i64(value, field)?)
        .map_err(|_| InterceptorError::Transcode(format!("{field} exceeds int32")))
}

fn json_u32(value: &Value, field: &str) -> Result<u32> {
    u32::try_from(json_u64(value, field)?)
        .map_err(|_| InterceptorError::Transcode(format!("{field} exceeds uint32")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{
        CreateSandboxRequest, SandboxSpec, SandboxTemplate, UpdateConfigRequest,
    };
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::layer::SubscriberExt;

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
    fn parses_timeout_suffixes() {
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("2s").unwrap(), Duration::from_secs(2));
        assert!(parse_duration("2").is_err());
    }

    #[test]
    fn service_default_failure_policy_rejects_ignore() {
        let err = parse_optional_failure_policy("ignore").unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid interceptor config: unsupported failure_policy 'ignore'"
        );
    }

    #[test]
    fn binding_failure_policy_rejects_ignore() {
        let overrides = Vec::new();
        let override_index = OverrideIndex::new(&overrides).unwrap();
        let binding = InterceptorBinding {
            id: "binding".to_string(),
            selector: Some(InterceptorSelector {
                rpc: "openshell.v1.OpenShell/CreateSandbox".to_string(),
                service: String::new(),
                method: String::new(),
            }),
            phases: vec![GatewayInterceptorPhase::Validate as i32],
            failure_policy: "ignore".to_string(),
        };

        let err = normalize_binding("test", &binding, FailurePolicy::FailClosed, &override_index)
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid interceptor config: unsupported failure_policy 'ignore'"
        );
    }

    #[tokio::test]
    async fn evaluation_log_emits_structured_log_annotations() {
        let log_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let writer = TraceBuf(log_buf.clone());
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .without_time();
        let subscriber = tracing_subscriber::registry().with(fmt_layer);
        let dispatch = tracing::Dispatch::new(subscriber);
        let plan = BindingPlan {
            interceptor_name: "test".to_string(),
            binding_id: "binding".to_string(),
            selector: RpcSelector {
                service: "openshell.v1.OpenShell".to_string(),
                method: "CreateSandbox".to_string(),
            },
            phase: Phase::ModifyOperation,
            failure_policy: FailurePolicy::FailClosed,
            timeout: DEFAULT_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_patches: DEFAULT_MAX_PATCHES,
            client: GatewayInterceptorClient::new(
                Channel::from_static("http://127.0.0.1:1").connect_lazy(),
            ),
        };
        let result = InterceptorResult {
            allowed: true,
            log_annotations: HashMap::from([
                (
                    "correlation_id".to_string(),
                    "governance:create-sandbox:demo".to_string(),
                ),
                ("policy_hash".to_string(), "abc123".to_string()),
            ]),
            ..InterceptorResult::default()
        };

        tracing::dispatcher::with_default(&dispatch, || {
            emit_evaluation_log(&plan, &result, "allow", 2);
        });

        let output = String::from_utf8(log_buf.lock().unwrap().clone()).unwrap();
        assert!(output.contains("gateway interceptor evaluated"));
        assert!(output.contains("log_annotations"));
        assert!(output.contains("correlation_id"));
        assert!(output.contains("governance:create-sandbox:demo"));
        assert!(output.contains("policy_hash"));
    }

    #[test]
    fn dynamic_create_sandbox_round_trip_uses_json_names() {
        let descriptors =
            ProtoDescriptors::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
        let request = CreateSandboxRequest {
            spec: Some(SandboxSpec {
                providers: vec!["github".to_string()],
                ..SandboxSpec::default()
            }),
            name: "demo".to_string(),
            labels: HashMap::from([("team".to_string(), "agent".to_string())]),
            annotations: HashMap::new(),
        };
        let bytes = request.encode_to_vec();
        let json = descriptors
            .decode_message_to_json("openshell.v1.CreateSandboxRequest", &bytes)
            .unwrap();
        assert_eq!(json["spec"]["providers"][0], "github");
        assert_eq!(json["labels"]["team"], "agent");
        let encoded = descriptors
            .encode_json_to_message("openshell.v1.CreateSandboxRequest", &json)
            .unwrap();
        let decoded = CreateSandboxRequest::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn dynamic_update_config_round_trip_preserves_annotations() {
        let descriptors =
            ProtoDescriptors::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
        let request = UpdateConfigRequest {
            name: "demo".to_string(),
            annotations: HashMap::from([(
                "openshell.nvidia.com/policy-signature".to_string(),
                "signed".to_string(),
            )]),
            ..Default::default()
        };
        let bytes = request.encode_to_vec();
        let json = descriptors
            .decode_message_to_json("openshell.v1.UpdateConfigRequest", &bytes)
            .unwrap();
        assert_eq!(
            json["annotations"]["openshell.nvidia.com/policy-signature"],
            "signed"
        );
        let encoded = descriptors
            .encode_json_to_message("openshell.v1.UpdateConfigRequest", &json)
            .unwrap();
        let decoded = UpdateConfigRequest::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn dynamic_round_trip_uses_protobuf_json_for_struct_fields() {
        let descriptors =
            ProtoDescriptors::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
        let request = CreateSandboxRequest {
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    resources: Some(
                        json_to_struct(json!({
                            "limits": {
                                "cpu": "2",
                                "memory": "4Gi"
                            }
                        }))
                        .unwrap(),
                    ),
                    driver_config: Some(
                        json_to_struct(json!({
                            "docker": {
                                "userns": "host"
                            }
                        }))
                        .unwrap(),
                    ),
                    ..SandboxTemplate::default()
                }),
                ..SandboxSpec::default()
            }),
            name: "demo".to_string(),
            labels: HashMap::new(),
            annotations: HashMap::new(),
        };

        let bytes = request.encode_to_vec();
        let json = descriptors
            .decode_message_to_json("openshell.v1.CreateSandboxRequest", &bytes)
            .unwrap();

        assert_eq!(json["spec"]["template"]["resources"]["limits"]["cpu"], "2");
        assert_eq!(
            json["spec"]["template"]["driverConfig"]["docker"]["userns"],
            "host"
        );
        assert!(
            json["spec"]["template"]["resources"]
                .get("fields")
                .is_none()
        );

        let encoded = descriptors
            .encode_json_to_message("openshell.v1.CreateSandboxRequest", &json)
            .unwrap();
        let decoded = CreateSandboxRequest::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded, request);
    }

    #[tokio::test]
    async fn invalid_modify_patch_honors_fail_open_without_mutating_operation() {
        let plan = BindingPlan {
            interceptor_name: "test".to_string(),
            binding_id: "binding".to_string(),
            selector: RpcSelector {
                service: "openshell.v1.OpenShell".to_string(),
                method: "CreateSandbox".to_string(),
            },
            phase: Phase::ModifyOperation,
            failure_policy: FailurePolicy::FailOpen,
            timeout: DEFAULT_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_patches: DEFAULT_MAX_PATCHES,
            client: GatewayInterceptorClient::new(
                Channel::from_static("http://127.0.0.1:1").connect_lazy(),
            ),
        };
        let operation = json!({ "name": "demo" });
        let result = InterceptorResult {
            allowed: true,
            patches: vec![JsonPatch {
                op: "replace".to_string(),
                path: "/missing".to_string(),
                value: Some(prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue("value".to_string())),
                }),
                from: String::new(),
            }],
            ..InterceptorResult::default()
        };

        let err = apply_json_patches(&operation, &result.patches).unwrap_err();
        apply_failure_policy(&plan, &err).unwrap();
        assert_eq!(operation, json!({ "name": "demo" }));
    }
}
