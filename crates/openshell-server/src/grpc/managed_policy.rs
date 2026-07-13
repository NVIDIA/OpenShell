// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use openshell_core::VERSION;
use openshell_core::proto::{
    DeleteManagedMaximumPolicyRequest, DeleteManagedMaximumPolicyResponse,
    GetManagedMaximumPolicyRequest, ManagedMaximumPolicyResponse, Sandbox, SandboxPolicy,
    SetManagedMaximumPolicyRequest,
};
use sha2::{Digest, Sha256};
use tonic::{Request, Response, Status};
use tracing::info;

use openshell_ocsf::{
    ConfigStateChangeBuilder, OCSF_TARGET, OcsfEvent, SandboxContext, SeverityId, StateId, StatusId,
};

use super::policy::{POLICY_SETTING_KEY, load_global_settings, save_global_settings};
use super::{MAX_POLICY_SIZE, StoredSettingValue};
use crate::ServerState;
use crate::managed_policy::{
    AdmissionDecision, AdmissionSource, ManagedPolicyConfig, PermissionMode, admit,
};

pub(super) const MANAGED_MAXIMUM_SETTING_KEY: &str = "managed_maximum_policy";
pub(super) const MANAGED_PERMISSION_MODE_LABEL: &str =
    openshell_core::driver_utils::LABEL_PERMISSION_MODE;

pub(super) async fn resolve_create_permission_mode(
    state: &ServerState,
    requested: &str,
) -> Result<Option<PermissionMode>, Status> {
    let Some(config) = load_managed_policy_config(state).await? else {
        if requested.trim().is_empty() {
            return Ok(None);
        }
        return Err(Status::failed_precondition(
            "--permission-mode requires a managed maximum policy on the gateway",
        ));
    };

    let mode = if requested.trim().is_empty() {
        config.default_mode
    } else {
        PermissionMode::parse(requested).map_err(Status::invalid_argument)?
    };
    if !config.allowed_modes.contains(&mode) {
        return Err(Status::failed_precondition(format!(
            "permission mode '{}' is not allowed by managed maximum {}@{}; allowed modes: {}",
            mode.as_str(),
            config.id,
            config.version,
            config
                .allowed_modes
                .iter()
                .map(|mode| mode.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    Ok(Some(mode))
}

pub(super) fn permission_mode_for_sandbox(
    sandbox: &Sandbox,
) -> Result<Option<PermissionMode>, Status> {
    let Some(value) = sandbox
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.labels.get(MANAGED_PERMISSION_MODE_LABEL))
    else {
        return Ok(None);
    };
    PermissionMode::parse(value).map(Some).map_err(|error| {
        Status::internal(format!(
            "stored managed permission mode is invalid: {error}"
        ))
    })
}

pub(super) async fn load_managed_policy_config(
    state: &ServerState,
) -> Result<Option<ManagedPolicyConfig>, Status> {
    let settings = load_global_settings(state.store.as_ref()).await?;
    let stored = settings.settings.get(MANAGED_MAXIMUM_SETTING_KEY);
    if stored.is_some() {
        require_managed_storage(state.store.is_single_replica())?;
    }
    stored
        .map(decode_stored_yaml)
        .transpose()?
        .map(|yaml| parse_stored_config(&yaml))
        .transpose()
}

pub(super) struct ManagedAuthorityRequest<'a> {
    pub mode: Option<PermissionMode>,
    pub source: AdmissionSource,
    pub sandbox_id: &'a str,
    pub sandbox_name: &'a str,
    pub current: Option<(&'a SandboxPolicy, &'a [String])>,
    pub candidate: (&'a SandboxPolicy, &'a [String]),
    pub requested_delta: (&'a SandboxPolicy, &'a [String]),
}

pub(super) async fn decide_managed_authority(
    state: &ServerState,
    request: ManagedAuthorityRequest<'_>,
) -> Result<AdmissionDecision, Status> {
    let ManagedAuthorityRequest {
        mode,
        source,
        sandbox_id,
        sandbox_name,
        current,
        candidate,
        requested_delta,
    } = request;
    let Some(config) = load_managed_policy_config(state).await? else {
        return Ok(AdmissionDecision::Unmanaged);
    };
    let mode = mode.ok_or_else(|| {
        Status::failed_precondition(
            "sandbox is missing its immutable managed permission mode; recreate the sandbox",
        )
    })?;

    let current = match current {
        Some((policy, providers)) => Some(parse_effective_policy(state, policy, providers).await?),
        None => None,
    };
    let candidate = parse_effective_policy(state, candidate.0, candidate.1).await?;
    let requested_delta =
        parse_effective_policy(state, requested_delta.0, requested_delta.1).await?;
    let decision = add_decision_context(
        admit(
            Some(&config.boundary()),
            mode,
            source,
            current.as_ref(),
            &candidate,
            &requested_delta,
        ),
        &config,
        mode,
        source,
    );
    emit_managed_admission_audit(sandbox_id, sandbox_name, &config, mode, source, &decision);
    Ok(decision)
}

fn add_decision_context(
    decision: AdmissionDecision,
    config: &ManagedPolicyConfig,
    mode: PermissionMode,
    source: AdmissionSource,
) -> AdmissionDecision {
    let context = format!(
        "maximum={}@{} mode={} source={}",
        config.id,
        config.version,
        mode.as_str(),
        source.as_str()
    );
    match decision {
        AdmissionDecision::Ask {
            reason,
            counterexample,
        } => AdmissionDecision::Ask {
            reason: format!("{reason}; {context}"),
            counterexample,
        },
        AdmissionDecision::Reject {
            reason,
            counterexample,
        } => AdmissionDecision::Reject {
            reason: format!("{reason}; {context}"),
            counterexample,
        },
        other => other,
    }
}

async fn parse_effective_policy(
    state: &ServerState,
    base: &SandboxPolicy,
    provider_names: &[String],
) -> Result<openshell_prover::policy::PolicyModel, Status> {
    let layers =
        super::policy::managed_profile_provider_policy_layers(state.store.as_ref(), provider_names)
            .await?;
    let effective = openshell_policy::compose_effective_policy(base, &layers);
    let yaml = openshell_policy::serialize_sandbox_policy(&effective)
        .map_err(|error| Status::internal(format!("serialize candidate policy failed: {error}")))?;
    openshell_prover::policy::parse_policy_str(&yaml)
        .map_err(|error| Status::internal(format!("parse candidate policy failed: {error}")))
}

fn emit_managed_admission_audit(
    sandbox_id: &str,
    sandbox_name: &str,
    config: &ManagedPolicyConfig,
    mode: PermissionMode,
    source: AdmissionSource,
    decision: &AdmissionDecision,
) {
    let (decision_name, reason, severity, status) = match decision {
        AdmissionDecision::Unmanaged => return,
        AdmissionDecision::Apply => (
            "apply",
            "candidate is within the managed maximum".to_owned(),
            SeverityId::Informational,
            StatusId::Success,
        ),
        AdmissionDecision::Ask {
            reason,
            counterexample,
        } => (
            "ask",
            decision_message(reason, counterexample.as_ref()),
            SeverityId::Informational,
            StatusId::Success,
        ),
        AdmissionDecision::Reject {
            reason,
            counterexample,
        } => (
            "reject",
            decision_message(reason, counterexample.as_ref()),
            SeverityId::Medium,
            StatusId::Failure,
        ),
    };
    let ctx = SandboxContext {
        sandbox_id: sandbox_id.to_owned(),
        sandbox_name: sandbox_name.to_owned(),
        container_image: "openshell/gateway".to_owned(),
        hostname: "openshell-gateway".to_owned(),
        product_version: VERSION.to_owned(),
        proxy_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        proxy_port: 0,
    };
    let event: OcsfEvent = ConfigStateChangeBuilder::new(&ctx)
        .state(StateId::Other, decision_name)
        .severity(severity)
        .status(status)
        .message(format!("managed admission {decision_name}: {reason}"))
        .unmapped("managed_policy_id", config.id.clone())
        .unmapped("managed_policy_version", config.version.to_string())
        .unmapped("managed_audit_label", config.audit_label.clone())
        .unmapped("permission_mode", mode.as_str())
        .unmapped("source", source.as_str())
        .unmapped("decision", decision_name)
        .build();
    info!(
        target: OCSF_TARGET,
        sandbox_id,
        message = %event.format_shorthand()
    );
}

fn emit_managed_config_audit(action: &str, config: &ManagedPolicyConfig, policy_hash: &str) {
    let ctx = SandboxContext {
        sandbox_id: String::new(),
        sandbox_name: String::new(),
        container_image: "openshell/gateway".to_owned(),
        hostname: "openshell-gateway".to_owned(),
        product_version: VERSION.to_owned(),
        proxy_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        proxy_port: 0,
    };
    let event: OcsfEvent = ConfigStateChangeBuilder::new(&ctx)
        .state(StateId::Other, action)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .message(format!(
            "managed maximum {action}: {}@{}",
            config.id, config.version
        ))
        .unmapped("managed_policy_id", config.id.clone())
        .unmapped("managed_policy_version", config.version.to_string())
        .unmapped("managed_audit_label", config.audit_label.clone())
        .unmapped("policy_hash", policy_hash)
        .build();
    info!(target: OCSF_TARGET, message = %event.format_shorthand());
}

pub(super) fn require_applied(decision: AdmissionDecision) -> Result<(), Status> {
    match decision {
        AdmissionDecision::Unmanaged | AdmissionDecision::Apply => Ok(()),
        AdmissionDecision::Ask {
            reason,
            counterexample,
        } => Err(Status::failed_precondition(decision_message(
            &reason,
            counterexample.as_ref(),
        ))),
        AdmissionDecision::Reject {
            reason,
            counterexample,
        } => Err(Status::permission_denied(decision_message(
            &reason,
            counterexample.as_ref(),
        ))),
    }
}

fn decision_message(
    reason: &str,
    counterexample: Option<&openshell_prover::envelope::PolicyCounterexample>,
) -> String {
    counterexample.map_or_else(
        || reason.to_owned(),
        |counterexample| {
            format!(
                "{reason}: protocol={} host={} port={} binary={} method={} path={}",
                counterexample.protocol,
                counterexample.host,
                counterexample.port,
                counterexample.binary,
                counterexample.method,
                counterexample.path
            )
        },
    )
}

pub(super) async fn handle_set_managed_maximum_policy(
    state: &Arc<ServerState>,
    request: Request<SetManagedMaximumPolicyRequest>,
) -> Result<Response<ManagedMaximumPolicyResponse>, Status> {
    require_managed_storage(state.store.is_single_replica())?;
    let policy_yaml = request.into_inner().policy_yaml;
    if policy_yaml.is_empty() {
        return Err(Status::invalid_argument("policy_yaml is required"));
    }
    if policy_yaml.len() > MAX_POLICY_SIZE {
        return Err(Status::invalid_argument(format!(
            "managed maximum policy exceeds maximum size ({MAX_POLICY_SIZE} bytes)"
        )));
    }
    let yaml = std::str::from_utf8(&policy_yaml)
        .map_err(|_| Status::invalid_argument("managed maximum policy must be UTF-8 YAML"))?;
    let config = ManagedPolicyConfig::parse(yaml).map_err(Status::invalid_argument)?;

    let _settings_guard = state.settings_mutex.lock().await;
    require_no_sandboxes(state).await?;
    let mut settings = load_global_settings(state.store.as_ref()).await?;
    if settings.settings.contains_key(POLICY_SETTING_KEY) {
        return Err(Status::failed_precondition(
            "managed maximum policy cannot coexist with the global policy override",
        ));
    }

    let stored = StoredSettingValue::Bytes(hex::encode(&policy_yaml));
    if let Some(existing) = settings.settings.get(MANAGED_MAXIMUM_SETTING_KEY) {
        if existing == &stored {
            return Ok(Response::new(config_response(
                &config,
                policy_yaml,
                settings.revision,
            )));
        }
        let existing_yaml = decode_stored_yaml(existing)?;
        let existing = parse_stored_config(&existing_yaml)?;
        if existing.id == config.id && config.version <= existing.version {
            return Err(Status::failed_precondition(format!(
                "replacement for managed maximum '{}' must increase version above {}",
                config.id, existing.version
            )));
        }
    }

    settings
        .settings
        .insert(MANAGED_MAXIMUM_SETTING_KEY.to_owned(), stored);
    settings.revision = settings.revision.wrapping_add(1);
    save_global_settings(state.store.as_ref(), &settings).await?;

    emit_managed_config_audit("set", &config, &hex::encode(Sha256::digest(&policy_yaml)));

    Ok(Response::new(config_response(
        &config,
        policy_yaml,
        settings.revision,
    )))
}

fn require_managed_storage(is_single_replica: bool) -> Result<(), Status> {
    if is_single_replica {
        Ok(())
    } else {
        Err(Status::failed_precondition(
            "managed maximum policies currently require single-replica SQLite storage; PostgreSQL/HA support requires database-backed admission coordination",
        ))
    }
}

pub(super) async fn handle_get_managed_maximum_policy(
    state: &Arc<ServerState>,
    _request: Request<GetManagedMaximumPolicyRequest>,
) -> Result<Response<ManagedMaximumPolicyResponse>, Status> {
    let settings = load_global_settings(state.store.as_ref()).await?;
    let Some(stored) = settings.settings.get(MANAGED_MAXIMUM_SETTING_KEY) else {
        return Ok(Response::new(ManagedMaximumPolicyResponse {
            configured: false,
            settings_revision: settings.revision,
            ..Default::default()
        }));
    };
    let policy_yaml = decode_stored_yaml(stored)?;
    let config = parse_stored_config(&policy_yaml)?;
    Ok(Response::new(config_response(
        &config,
        policy_yaml,
        settings.revision,
    )))
}

pub(super) async fn handle_delete_managed_maximum_policy(
    state: &Arc<ServerState>,
    _request: Request<DeleteManagedMaximumPolicyRequest>,
) -> Result<Response<DeleteManagedMaximumPolicyResponse>, Status> {
    let _settings_guard = state.settings_mutex.lock().await;
    require_no_sandboxes(state).await?;
    let mut settings = load_global_settings(state.store.as_ref()).await?;
    let removed = settings.settings.remove(MANAGED_MAXIMUM_SETTING_KEY);
    let deleted = removed.is_some();
    if deleted {
        settings.revision = settings.revision.wrapping_add(1);
        save_global_settings(state.store.as_ref(), &settings).await?;
    }
    if let Some(stored) = removed {
        let yaml = decode_stored_yaml(&stored)?;
        let config = parse_stored_config(&yaml)?;
        emit_managed_config_audit("delete", &config, &hex::encode(Sha256::digest(&yaml)));
    }
    Ok(Response::new(DeleteManagedMaximumPolicyResponse {
        deleted,
        settings_revision: settings.revision,
    }))
}

async fn require_no_sandboxes(state: &ServerState) -> Result<(), Status> {
    let sandboxes: Vec<Sandbox> = state
        .store
        .list_messages(1, 0)
        .await
        .map_err(|error| Status::internal(format!("list sandboxes failed: {error}")))?;
    if sandboxes.is_empty() {
        Ok(())
    } else {
        Err(Status::failed_precondition(
            "managed maximum policy can change only when no sandboxes exist",
        ))
    }
}

fn decode_stored_yaml(value: &StoredSettingValue) -> Result<Vec<u8>, Status> {
    let StoredSettingValue::Bytes(value) = value else {
        return Err(Status::internal(
            "stored managed maximum has invalid value type",
        ));
    };
    hex::decode(value)
        .map_err(|error| Status::internal(format!("decode managed maximum failed: {error}")))
}

fn parse_stored_config(policy_yaml: &[u8]) -> Result<ManagedPolicyConfig, Status> {
    let yaml = std::str::from_utf8(policy_yaml)
        .map_err(|_| Status::internal("stored managed maximum is not UTF-8"))?;
    ManagedPolicyConfig::parse(yaml)
        .map_err(|error| Status::internal(format!("stored managed maximum is invalid: {error}")))
}

fn config_response(
    config: &ManagedPolicyConfig,
    policy_yaml: Vec<u8>,
    settings_revision: u64,
) -> ManagedMaximumPolicyResponse {
    ManagedMaximumPolicyResponse {
        configured: true,
        policy_hash: hex::encode(Sha256::digest(&policy_yaml)),
        policy_yaml,
        policy_id: config.id.clone(),
        version: config.version,
        allowed_modes: config
            .allowed_modes
            .iter()
            .map(|mode| mode.as_str().to_owned())
            .collect(),
        default_mode: config.default_mode.as_str().to_owned(),
        audit_label: config.audit_label.clone(),
        settings_revision,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::test_support::test_server_state;
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::{
        AttachSandboxProviderRequest, CreateSandboxRequest, Provider, SandboxPolicy, SandboxSpec,
        UpdateConfigRequest,
    };
    use tonic::Code;

    fn maximum(version: u64) -> Vec<u8> {
        format!(
            r"version: 1
metadata:
  policy_id: engineering
  version: {version}
  allowed_modes: [ask, auto]
  default_mode: auto
network_policies:
  github:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
    binaries:
      - path: /usr/bin/gh
"
        )
        .into_bytes()
    }

    async fn configure_maximum(state: &Arc<ServerState>) {
        handle_set_managed_maximum_policy(
            state,
            Request::new(SetManagedMaximumPolicyRequest {
                policy_yaml: maximum(1),
            }),
        )
        .await
        .expect("maximum should configure");
    }

    #[test]
    fn managed_maximum_requires_single_replica_storage() {
        require_managed_storage(true).expect("SQLite should support managed maximums");
        let error = require_managed_storage(false)
            .expect_err("multi-replica storage must fail closed until admission is coordinated");
        assert_eq!(error.code(), Code::FailedPrecondition);
        assert!(error.message().contains("single-replica SQLite"));
    }

    fn outside_policy() -> SandboxPolicy {
        openshell_policy::parse_sandbox_policy(
            r"version: 1
network_policies:
  github:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow: { method: DELETE, path: /repos/acme/project }
    binaries:
      - path: /usr/bin/gh
",
        )
        .expect("candidate should parse")
    }

    async fn put_managed_sandbox(
        state: &ServerState,
        policy: Option<SandboxPolicy>,
        providers: Vec<String>,
    ) {
        state
            .store
            .put_message(&Sandbox {
                metadata: Some(ObjectMeta {
                    id: "sandbox-id".to_owned(),
                    name: "sandbox".to_owned(),
                    labels: std::collections::HashMap::from([(
                        MANAGED_PERMISSION_MODE_LABEL.to_owned(),
                        "auto".to_owned(),
                    )]),
                    ..Default::default()
                }),
                spec: Some(SandboxSpec {
                    policy,
                    providers,
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await
            .expect("sandbox should persist");
    }

    async fn put_unmodeled_provider(state: &ServerState) {
        state
            .store
            .put_message(&Provider {
                metadata: Some(ObjectMeta {
                    id: "provider-id".to_owned(),
                    name: "unmodeled".to_owned(),
                    ..Default::default()
                }),
                r#type: "unknown-provider-type".to_owned(),
                credentials: std::collections::HashMap::from([(
                    "TOKEN".to_owned(),
                    "never-log-this-secret".to_owned(),
                )]),
                ..Default::default()
            })
            .await
            .expect("provider should persist");
    }

    #[tokio::test]
    async fn managed_maximum_round_trips_and_deletes() {
        let state = test_server_state().await;
        let set = handle_set_managed_maximum_policy(
            &state,
            Request::new(SetManagedMaximumPolicyRequest {
                policy_yaml: maximum(1),
            }),
        )
        .await
        .expect("set should succeed")
        .into_inner();
        assert!(set.configured);
        assert_eq!(set.policy_id, "engineering");
        assert_eq!(set.version, 1);
        assert_eq!(set.settings_revision, 1);

        let get = handle_get_managed_maximum_policy(
            &state,
            Request::new(GetManagedMaximumPolicyRequest {}),
        )
        .await
        .expect("get should succeed")
        .into_inner();
        assert_eq!(get.policy_yaml, maximum(1));
        assert_eq!(get.policy_hash, set.policy_hash);

        let deleted = handle_delete_managed_maximum_policy(
            &state,
            Request::new(DeleteManagedMaximumPolicyRequest {}),
        )
        .await
        .expect("delete should succeed")
        .into_inner();
        assert!(deleted.deleted);
        assert_eq!(deleted.settings_revision, 2);
    }

    #[tokio::test]
    async fn managed_maximum_replacement_requires_increasing_version() {
        let state = test_server_state().await;
        handle_set_managed_maximum_policy(
            &state,
            Request::new(SetManagedMaximumPolicyRequest {
                policy_yaml: maximum(2),
            }),
        )
        .await
        .expect("initial set should succeed");

        let error = handle_set_managed_maximum_policy(
            &state,
            Request::new(SetManagedMaximumPolicyRequest {
                policy_yaml: maximum(1),
            }),
        )
        .await
        .expect_err("version rollback should fail");
        assert_eq!(error.code(), Code::FailedPrecondition);
        assert!(error.message().contains("increase version"));
    }

    #[tokio::test]
    async fn create_permission_mode_uses_managed_default_and_validates_override() {
        let state = test_server_state().await;
        configure_maximum(&state).await;

        assert_eq!(
            resolve_create_permission_mode(&state, "").await.unwrap(),
            Some(PermissionMode::Auto)
        );
        assert_eq!(
            resolve_create_permission_mode(&state, "ask").await.unwrap(),
            Some(PermissionMode::Ask)
        );
    }

    #[tokio::test]
    async fn explicit_permission_mode_requires_managed_maximum() {
        let state = test_server_state().await;
        let error = resolve_create_permission_mode(&state, "auto")
            .await
            .expect_err("mode without maximum should fail");
        assert_eq!(error.code(), Code::FailedPrecondition);
        assert!(error.message().contains("requires a managed maximum"));
    }

    #[tokio::test]
    async fn create_permission_mode_rejects_mode_outside_allowed_set() {
        let state = test_server_state().await;
        let auto_only = String::from_utf8(maximum(1))
            .unwrap()
            .replace("allowed_modes: [ask, auto]", "allowed_modes: [auto]");
        handle_set_managed_maximum_policy(
            &state,
            Request::new(SetManagedMaximumPolicyRequest {
                policy_yaml: auto_only.into_bytes(),
            }),
        )
        .await
        .expect("maximum should be configured");

        let error = resolve_create_permission_mode(&state, "ask")
            .await
            .expect_err("disallowed mode should fail");
        assert_eq!(error.code(), Code::FailedPrecondition);
        assert!(error.message().contains("allowed modes: auto"));
    }

    #[tokio::test]
    async fn managed_maximum_mutation_rejects_when_sandbox_exists() {
        let state = test_server_state().await;
        put_managed_sandbox(&state, None, Vec::new()).await;

        let error = handle_set_managed_maximum_policy(
            &state,
            Request::new(SetManagedMaximumPolicyRequest {
                policy_yaml: maximum(1),
            }),
        )
        .await
        .expect_err("set with sandbox should fail");
        assert_eq!(error.code(), Code::FailedPrecondition);
        assert!(error.message().contains("no sandboxes"));
    }

    #[tokio::test]
    async fn sandbox_create_rejects_authority_outside_managed_maximum() {
        let state = test_server_state().await;
        configure_maximum(&state).await;
        let error = super::super::sandbox::handle_create_sandbox(
            &state,
            Request::new(CreateSandboxRequest {
                name: "outside-maximum".to_owned(),
                spec: Some(SandboxSpec {
                    policy: Some(outside_policy()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        )
        .await
        .expect_err("outside authority should reject create");
        assert_eq!(error.code(), Code::PermissionDenied);
        assert!(error.message().contains("exceeds managed maximum"));
        assert!(error.message().contains("DELETE"));
    }

    #[tokio::test]
    async fn sandbox_create_rejects_provider_without_resolvable_profile() {
        let state = test_server_state().await;
        configure_maximum(&state).await;
        put_unmodeled_provider(&state).await;

        let error = super::super::sandbox::handle_create_sandbox(
            &state,
            Request::new(CreateSandboxRequest {
                name: "unmodeled-provider".to_owned(),
                spec: Some(SandboxSpec {
                    policy: Some(SandboxPolicy::default()),
                    providers: vec!["unmodeled".to_owned()],
                    ..Default::default()
                }),
                ..Default::default()
            }),
        )
        .await
        .expect_err("unmodeled provider authority must reject create");

        assert_eq!(error.code(), Code::FailedPrecondition);
        assert!(error.message().contains("no resolvable policy profile"));
        assert!(!error.message().contains("never-log-this-secret"));
    }

    #[tokio::test]
    async fn sandbox_attach_rejects_provider_without_resolvable_profile() {
        let state = test_server_state().await;
        configure_maximum(&state).await;
        put_unmodeled_provider(&state).await;
        put_managed_sandbox(&state, Some(SandboxPolicy::default()), Vec::new()).await;

        let error = super::super::sandbox::handle_attach_sandbox_provider(
            &state,
            Request::new(AttachSandboxProviderRequest {
                sandbox_name: "sandbox".to_owned(),
                provider_name: "unmodeled".to_owned(),
                expected_resource_version: 0,
            }),
        )
        .await
        .expect_err("unmodeled provider authority must reject attach");

        assert_eq!(error.code(), Code::FailedPrecondition);
        assert!(error.message().contains("no resolvable policy profile"));
        assert!(!error.message().contains("never-log-this-secret"));
    }

    #[tokio::test]
    async fn rejected_first_policy_backfill_does_not_mutate_sandbox_spec() {
        let state = test_server_state().await;
        configure_maximum(&state).await;
        put_managed_sandbox(&state, None, Vec::new()).await;
        let error = super::super::policy::handle_update_config(
            &state,
            Request::new(UpdateConfigRequest {
                name: "sandbox".to_owned(),
                policy: Some(outside_policy()),
                ..Default::default()
            }),
        )
        .await
        .expect_err("outside backfill should fail");
        assert_eq!(error.code(), Code::PermissionDenied);

        let stored = state
            .store
            .get_message::<Sandbox>("sandbox-id")
            .await
            .expect("sandbox lookup should succeed")
            .expect("sandbox should still exist");
        assert!(
            stored.spec.and_then(|spec| spec.policy).is_none(),
            "rejected admission must not persist the discovered policy"
        );
    }

    #[tokio::test]
    async fn attached_managed_provider_allows_value_rotation_but_rejects_new_credential_reach() {
        let state = test_server_state().await;
        configure_maximum(&state).await;

        state
            .store
            .put_message(&Provider {
                metadata: Some(ObjectMeta {
                    id: "provider-id".to_owned(),
                    name: "work-github".to_owned(),
                    ..Default::default()
                }),
                r#type: "github".to_owned(),
                credentials: std::collections::HashMap::from([(
                    "GH_TOKEN".to_owned(),
                    "old-secret".to_owned(),
                )]),
                ..Default::default()
            })
            .await
            .unwrap();
        put_managed_sandbox(&state, None, vec!["work-github".to_owned()]).await;

        super::super::provider::update_provider_record(
            state.store.as_ref(),
            Provider {
                metadata: Some(ObjectMeta {
                    name: "work-github".to_owned(),
                    ..Default::default()
                }),
                credentials: std::collections::HashMap::from([(
                    "GH_TOKEN".to_owned(),
                    "rotated-secret".to_owned(),
                )]),
                ..Default::default()
            },
        )
        .await
        .expect("same-key credential rotation should succeed");

        let error = super::super::provider::update_provider_record(
            state.store.as_ref(),
            Provider {
                metadata: Some(ObjectMeta {
                    name: "work-github".to_owned(),
                    ..Default::default()
                }),
                credentials: std::collections::HashMap::from([(
                    "NEW_TOKEN".to_owned(),
                    "new-secret".to_owned(),
                )]),
                ..Default::default()
            },
        )
        .await
        .expect_err("new credential key should be rejected while attached");
        assert_eq!(error.code(), Code::FailedPrecondition);
        assert!(error.message().contains("only credential-value rotation"));
        assert!(!error.message().contains("new-secret"));
    }
}
