// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Interceptor configuration and immutable execution planning.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::time::Duration;

use hyper_util::rt::TokioIo;
use openshell_core::config::{
    GatewayInterceptorBindingOverride, GatewayInterceptorConfig, GatewayInterceptorFailurePolicy,
    GatewayInterceptorPhaseConfig,
};
use openshell_core::proto::gateway_interceptor::v1::{
    DescribeRequest, GatewayInterceptorPhase, InterceptorBinding, InterceptorSelector,
    gateway_interceptor_client::GatewayInterceptorClient,
};
use tokio::net::UnixStream;
use tonic::Request;
use tonic::codegen::http::Uri;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;
use tracing::info;

use crate::profile_source::GatewayInterceptorProfileSource;
use crate::routes::OpenShellRouteIndex;
use crate::{InterceptorError, Result};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(500);
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const DEFAULT_MAX_PATCHES: usize = 32;

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
pub struct BindingPlan {
    pub(crate) interceptor_name: String,
    pub(crate) binding_id: String,
    pub(crate) selector: RpcSelector,
    pub(crate) phase: Phase,
    pub(crate) failure_policy: FailurePolicy,
    pub(crate) timeout: Duration,
    pub(crate) max_response_bytes: usize,
    pub(crate) max_patches: usize,
    pub(crate) client: GatewayInterceptorClient<Channel>,
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

#[derive(Debug)]
pub struct ExecutionPlan {
    bindings: BTreeMap<(RpcSelector, Phase), Vec<BindingPlan>>,
    profile_sources: BTreeMap<String, GatewayInterceptorProfileSource>,
    routes: OpenShellRouteIndex,
}

impl ExecutionPlan {
    #[cfg(test)]
    pub(crate) fn empty(routes: OpenShellRouteIndex) -> Self {
        Self {
            bindings: BTreeMap::new(),
            profile_sources: BTreeMap::new(),
            routes,
        }
    }

    pub(crate) async fn load(
        mut configs: Vec<GatewayInterceptorConfig>,
        routes: OpenShellRouteIndex,
    ) -> Result<Self> {
        validate_interceptor_configs(&configs)?;
        configs.sort_by(|a, b| a.order.cmp(&b.order).then_with(|| a.name.cmp(&b.name)));

        let mut bindings: BTreeMap<(RpcSelector, Phase), Vec<BindingPlan>> = BTreeMap::new();
        let mut profile_sources = BTreeMap::new();

        for config in configs {
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

            if manifest.provider_profiles {
                let source_id = format!("interceptor/{}", config.name);
                profile_sources.insert(
                    config.name.clone(),
                    GatewayInterceptorProfileSource::new(
                        config.name.clone(),
                        source_id,
                        timeout,
                        GatewayInterceptorClient::new(channel.clone())
                            .max_decoding_message_size(max_response_bytes),
                    ),
                );
            }
        }

        let count: usize = bindings.values().map(Vec::len).sum();
        info!(
            bindings = count,
            profile_sources = profile_sources.len(),
            "gateway interceptors initialized"
        );
        Ok(Self {
            bindings,
            profile_sources,
            routes,
        })
    }

    pub(crate) fn profile_source(
        &self,
        interceptor_name: &str,
    ) -> Option<GatewayInterceptorProfileSource> {
        self.profile_sources.get(interceptor_name).cloned()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.bindings.is_empty() && self.profile_sources.is_empty()
    }

    pub(crate) fn should_intercept(&self, selector: &RpcSelector) -> bool {
        self.routes
            .is_interceptable(&selector.service, &selector.method)
            && [Phase::ModifyOperation, Phase::Validate, Phase::PostCommit]
                .iter()
                .any(|phase| self.bindings.contains_key(&(selector.clone(), *phase)))
    }

    pub(crate) fn input_type(&self, selector: &RpcSelector) -> Option<&str> {
        self.routes.input_type(&selector.service, &selector.method)
    }

    pub(crate) fn output_type(&self, selector: &RpcSelector) -> Option<&str> {
        self.routes.output_type(&selector.service, &selector.method)
    }

    pub(crate) fn bindings(&self, selector: &RpcSelector, phase: Phase) -> Option<&[BindingPlan]> {
        self.bindings
            .get(&(selector.clone(), phase))
            .map(Vec::as_slice)
    }

    pub(crate) fn has_binding(&self, selector: &RpcSelector, phase: Phase) -> bool {
        self.bindings.contains_key(&(selector.clone(), phase))
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

fn validate_interceptor_configs(configs: &[GatewayInterceptorConfig]) -> Result<()> {
    let mut names = BTreeSet::new();
    for config in configs {
        validate_service_config(config)?;
        if !names.insert(config.name.clone()) {
            return Err(InterceptorError::Config(format!(
                "duplicate interceptor instance name '{}'",
                config.name
            )));
        }
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

    if phases.contains(&Phase::PostCommit) && failure_policy != FailurePolicy::FailOpen {
        return Err(InterceptorError::Config(format!(
            "interceptor '{interceptor_name}' binding '{binding_id}' uses failure_policy={} for post_commit; post_commit must use fail_open",
            failure_policy.as_str()
        )));
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

#[cfg(test)]
mod tests {
    use openshell_core::config::GatewayInterceptorConfig;
    use openshell_core::proto::gateway_interceptor::v1::{
        GatewayInterceptorPhase, InterceptorBinding, InterceptorSelector,
    };

    use super::*;

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
    fn duplicate_interceptor_instance_names_are_invalid() {
        let config = GatewayInterceptorConfig {
            name: "governance".to_string(),
            grpc_endpoint: "http://127.0.0.1:18081".to_string(),
            ..GatewayInterceptorConfig::default()
        };
        let err = validate_interceptor_configs(&[config.clone(), config]).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid interceptor config: duplicate interceptor instance name 'governance'"
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

    #[test]
    fn post_commit_binding_rejects_fail_closed() {
        let overrides = Vec::new();
        let override_index = OverrideIndex::new(&overrides).unwrap();
        let binding = InterceptorBinding {
            id: "audit-create-sandbox".to_string(),
            selector: Some(InterceptorSelector {
                rpc: "openshell.v1.OpenShell/CreateSandbox".to_string(),
                service: String::new(),
                method: String::new(),
            }),
            phases: vec![GatewayInterceptorPhase::PostCommit as i32],
            failure_policy: "fail_closed".to_string(),
        };

        let err = normalize_binding(
            "audit",
            &binding,
            FailurePolicy::FailClosed,
            &override_index,
        )
        .expect_err("post_commit must not fail closed after an operation commits");

        assert_eq!(
            err.to_string(),
            "invalid interceptor config: interceptor 'audit' binding 'audit-create-sandbox' uses failure_policy=fail_closed for post_commit; post_commit must use fail_open"
        );
    }

    #[test]
    fn post_commit_binding_accepts_fail_open() {
        let overrides = Vec::new();
        let override_index = OverrideIndex::new(&overrides).unwrap();
        let binding = InterceptorBinding {
            id: "audit-create-sandbox".to_string(),
            selector: Some(InterceptorSelector {
                rpc: "openshell.v1.OpenShell/CreateSandbox".to_string(),
                service: String::new(),
                method: String::new(),
            }),
            phases: vec![GatewayInterceptorPhase::PostCommit as i32],
            failure_policy: "fail_open".to_string(),
        };

        let normalized = normalize_binding(
            "audit",
            &binding,
            FailurePolicy::FailClosed,
            &override_index,
        )
        .expect("fail-open post_commit binding should be valid")
        .expect("binding should be enabled");

        assert_eq!(normalized.failure_policy, FailurePolicy::FailOpen);
    }
}
