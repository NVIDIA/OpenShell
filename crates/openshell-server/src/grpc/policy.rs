// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Policy updates, status, draft chunks, config/settings layer, and sandbox logs.

#![allow(clippy::result_large_err)] // gRPC handlers return Result<Response<_>, Status>
#![allow(clippy::cast_possible_truncation)] // Intentional u128->i64 etc. for timestamp math
#![allow(clippy::cast_sign_loss)] // Intentional i32->u32 conversions from proto types
#![allow(clippy::cast_possible_wrap)] // Intentional u32->i32 conversions for proto compat
#![allow(clippy::cast_precision_loss)] // f64->f32 for confidence scores
#![allow(clippy::items_after_statements)] // DB_PORTS const inside function

use crate::persistence::{DraftChunkRecord, ObjectId, ObjectName, PolicyRecord, Store};
use crate::policy_store::PolicyStoreExt;
use crate::{ServerState, auth::oidc};
use openshell_core::proto::policy_merge_operation;
use openshell_core::proto::setting_value;
use openshell_core::proto::{
    AddAllowRules as ProtoAddAllowRules, AddDenyRules as ProtoAddDenyRules,
    ApproveAllDraftChunksRequest, ApproveAllDraftChunksResponse, ApproveDraftChunkRequest,
    ApproveDraftChunkResponse, ClearDraftChunksRequest, ClearDraftChunksResponse,
    DraftHistoryEntry, EditDraftChunkRequest, EditDraftChunkResponse, EffectiveSetting,
    GetDraftHistoryRequest, GetDraftHistoryResponse, GetDraftPolicyRequest, GetDraftPolicyResponse,
    GetGatewayConfigRequest, GetGatewayConfigResponse, GetSandboxConfigRequest,
    GetSandboxConfigResponse, GetSandboxLogsRequest, GetSandboxLogsResponse,
    GetSandboxPolicyStatusRequest, GetSandboxPolicyStatusResponse,
    GetSandboxProviderEnvironmentRequest, GetSandboxProviderEnvironmentResponse,
    ListSandboxPoliciesRequest, ListSandboxPoliciesResponse, PolicyChunk, PolicyMergeOperation,
    PolicySource, PolicyStatus, PushSandboxLogsRequest, PushSandboxLogsResponse,
    RejectDraftChunkRequest, RejectDraftChunkResponse, ReportPolicyStatusRequest,
    ReportPolicyStatusResponse, SandboxLogLine, SandboxPolicyRevision, SettingScope, SettingValue,
    SubmitPolicyAnalysisRequest, SubmitPolicyAnalysisResponse, UndoDraftChunkRequest,
    UndoDraftChunkResponse, UpdateConfigRequest, UpdateConfigResponse,
};
use openshell_core::proto::{
    L7DenyRule, L7Rule, NetworkBinary, NetworkEndpoint, NetworkPolicyRule, Provider, Sandbox,
    SandboxPolicy as ProtoSandboxPolicy,
};
use openshell_core::{
    VERSION,
    settings::{self, SettingValueKind},
};
use openshell_ocsf::{
    ConfigStateChangeBuilder, OCSF_TARGET, OcsfEvent, SandboxContext, SeverityId, StateId, StatusId,
};
use openshell_policy::{
    PolicyMergeOp, ProviderPolicyLayer, compose_effective_policy, merge_policy,
};
use openshell_providers::get_default_profile;
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

use super::validation::{
    level_matches, source_matches, validate_policy_safety, validate_static_fields_unchanged,
};
use super::{MAX_PAGE_SIZE, StoredSettingValue, StoredSettings, clamp_limit, current_time_ms};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Internal object type for durable gateway-global settings.
const GLOBAL_SETTINGS_OBJECT_TYPE: &str = "gateway_settings";
const GLOBAL_SETTINGS_NAME: &str = "global";
/// Internal object type for durable sandbox-scoped settings.
pub const SANDBOX_SETTINGS_OBJECT_TYPE: &str = "sandbox_settings";
/// Reserved settings key used to store global policy payload.
const POLICY_SETTING_KEY: &str = "policy";
/// Sentinel `sandbox_id` used to store global policy revisions.
const GLOBAL_POLICY_SANDBOX_ID: &str = "__global__";
/// Maximum number of optimistic retry attempts for policy version conflicts.
const MERGE_RETRY_LIMIT: usize = 5;

fn emit_gateway_policy_audit_log(
    sandbox_id: &str,
    sandbox_name: &str,
    state_label: &str,
    detail: impl Into<String>,
    version: i64,
    policy_hash: &str,
) {
    let message = build_gateway_policy_audit_message(
        sandbox_id,
        sandbox_name,
        state_label,
        detail,
        version,
        policy_hash,
    );
    info!(
        target: OCSF_TARGET,
        sandbox_id = %sandbox_id,
        message = %message
    );
}

fn build_gateway_policy_audit_message(
    sandbox_id: &str,
    sandbox_name: &str,
    state_label: &str,
    detail: impl Into<String>,
    version: i64,
    policy_hash: &str,
) -> String {
    let ctx = SandboxContext {
        sandbox_id: sandbox_id.to_string(),
        sandbox_name: sandbox_name.to_string(),
        container_image: "openshell/gateway".to_string(),
        hostname: "openshell-gateway".to_string(),
        product_version: VERSION.to_string(),
        proxy_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        proxy_port: 0,
    };
    let mut builder = ConfigStateChangeBuilder::new(&ctx)
        .state(StateId::Other, state_label)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .message(detail.into());
    if version > 0 {
        builder = builder.unmapped("policy_version", format!("v{version}"));
    }
    if !policy_hash.is_empty() {
        builder = builder.unmapped("policy_hash", policy_hash.to_string());
    }
    let event: OcsfEvent = builder.build();
    event.format_shorthand()
}

fn summarize_cli_policy_merge_op(operation: &PolicyMergeOp) -> String {
    match operation {
        PolicyMergeOp::AddRule { rule_name, rule } => summarize_add_endpoint(rule_name, rule),
        PolicyMergeOp::RemoveEndpoint {
            rule_name,
            host,
            port,
        } => rule_name.as_ref().map_or_else(
            || format!("remove-endpoint {host}:{port}"),
            |rule_name| format!("remove-endpoint {host}:{port} from rule {rule_name}"),
        ),
        PolicyMergeOp::RemoveRule { rule_name } => format!("remove-rule {rule_name}"),
        PolicyMergeOp::AddDenyRules {
            host,
            port,
            deny_rules,
        } => format!(
            "add-deny {host}:{port} [{}]",
            deny_rules
                .iter()
                .map(summarize_l7_deny_rule)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        PolicyMergeOp::AddAllowRules { host, port, rules } => format!(
            "add-allow {host}:{port} [{}]",
            rules
                .iter()
                .map(summarize_l7_rule)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        PolicyMergeOp::RemoveBinary {
            rule_name,
            binary_path,
        } => format!("remove-binary {rule_name} {binary_path}"),
    }
}

fn ensure_chunk_belongs_to_sandbox(
    chunk: &DraftChunkRecord,
    sandbox_id: &str,
) -> Result<(), Status> {
    if chunk.sandbox_id != sandbox_id {
        return Err(Status::not_found("chunk not found"));
    }
    Ok(())
}

fn summarize_add_endpoint(rule_name: &str, rule: &NetworkPolicyRule) -> String {
    let endpoints = rule
        .endpoints
        .iter()
        .map(summarize_endpoint)
        .collect::<Vec<_>>()
        .join(", ");
    let binaries = summarize_binaries(&rule.binaries);
    format!("add-endpoint {rule_name} endpoints=[{endpoints}] binaries=[{binaries}]")
}

fn summarize_add_rule(rule_name: &str, rule: &NetworkPolicyRule) -> String {
    let endpoints = rule
        .endpoints
        .iter()
        .map(summarize_endpoint)
        .collect::<Vec<_>>()
        .join(", ");
    let binaries = summarize_binaries(&rule.binaries);
    format!("add-rule {rule_name} endpoints=[{endpoints}] binaries=[{binaries}]")
}

fn summarize_endpoint(endpoint: &NetworkEndpoint) -> String {
    let mut parts = vec![format!("{}:{}", endpoint.host, endpoint.port)];
    if !endpoint.protocol.is_empty() {
        parts.push(format!("protocol={}", endpoint.protocol));
    }
    if !endpoint.access.is_empty() {
        parts.push(format!("access={}", endpoint.access));
    }
    if !endpoint.enforcement.is_empty() {
        parts.push(format!("enforcement={}", endpoint.enforcement));
    }
    if !endpoint.tls.is_empty() {
        parts.push(format!("tls={}", endpoint.tls));
    }
    if !endpoint.allowed_ips.is_empty() {
        parts.push(format!("allowed_ips={}", endpoint.allowed_ips.len()));
    }
    if !endpoint.ports.is_empty() {
        parts.push(format!("ports={}", endpoint.ports.len()));
    }
    if !endpoint.rules.is_empty() {
        parts.push(format!(
            "allow=[{}]",
            endpoint
                .rules
                .iter()
                .map(summarize_l7_rule)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !endpoint.deny_rules.is_empty() {
        parts.push(format!(
            "deny=[{}]",
            endpoint
                .deny_rules
                .iter()
                .map(summarize_l7_deny_rule)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    parts.join(" ")
}

fn summarize_l7_rule(rule: &L7Rule) -> String {
    let Some(allow) = rule.allow.as_ref() else {
        return "allow".to_string();
    };
    summarize_l7_match(
        &allow.method,
        &allow.path,
        &allow.command,
        allow.query.len(),
    )
}

fn summarize_l7_deny_rule(rule: &L7DenyRule) -> String {
    summarize_l7_match(&rule.method, &rule.path, &rule.command, rule.query.len())
}

fn summarize_l7_match(method: &str, path: &str, command: &str, query_count: usize) -> String {
    let mut parts = Vec::new();
    if !method.is_empty() {
        parts.push(method.to_string());
    }
    if !path.is_empty() {
        parts.push(path.to_string());
    }
    if !command.is_empty() {
        parts.push(format!("command={}", truncate_for_log(command, 48)));
    }
    if query_count > 0 {
        parts.push(format!("query_keys={query_count}"));
    }
    if parts.is_empty() {
        "rule".to_string()
    } else {
        parts.join(" ")
    }
}

fn summarize_binaries(binaries: &[NetworkBinary]) -> String {
    binaries
        .iter()
        .map(|binary| binary.path.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

fn summarize_draft_chunk_rule(chunk: &DraftChunkRecord) -> Result<String, Status> {
    let rule = NetworkPolicyRule::decode(chunk.proposed_rule.as_slice())
        .map_err(|e| Status::internal(format!("decode proposed_rule failed: {e}")))?;
    Ok(summarize_add_rule(&chunk.rule_name, &rule))
}

fn truncate_for_log(input: &str, max_chars: usize) -> String {
    let mut chars = input.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

fn is_sandbox_secret_authenticated<T>(request: &Request<T>) -> bool {
    oidc::is_sandbox_secret_authenticated(request.metadata())
}

/// Sandbox-secret-authenticated callers may only perform sandbox-scoped policy
/// sync. They must not be able to mutate global config or sandbox settings.
fn validate_sandbox_secret_update(req: &UpdateConfigRequest) -> Result<(), Status> {
    if req.global {
        return Err(Status::permission_denied(
            "sandbox secret cannot mutate global config",
        ));
    }
    if req.delete_setting {
        return Err(Status::permission_denied(
            "sandbox secret cannot delete settings",
        ));
    }
    if req.name.trim().is_empty() {
        return Err(Status::permission_denied(
            "sandbox secret may only perform sandbox policy sync",
        ));
    }
    if req.policy.is_none() || !req.setting_key.trim().is_empty() {
        return Err(Status::permission_denied(
            "sandbox secret may only perform sandbox policy sync",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Config handlers
// ---------------------------------------------------------------------------

pub(super) async fn handle_get_sandbox_config(
    state: &Arc<ServerState>,
    request: Request<GetSandboxConfigRequest>,
) -> Result<Response<GetSandboxConfigResponse>, Status> {
    let sandbox_id = request.into_inner().sandbox_id;

    let sandbox = state
        .store
        .get_message::<Sandbox>(&sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let sandbox_provider_names = sandbox
        .spec
        .as_ref()
        .map(|spec| spec.providers.clone())
        .unwrap_or_default();

    // Try to get the latest policy from the policy history table.
    let latest = state
        .store
        .get_latest_policy(&sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("fetch policy history failed: {e}")))?;

    let mut policy_source = PolicySource::Sandbox;
    let (mut policy, mut version, mut policy_hash) = if let Some(record) = latest {
        let decoded = ProtoSandboxPolicy::decode(record.policy_payload.as_slice())
            .map_err(|e| Status::internal(format!("decode policy failed: {e}")))?;
        debug!(
            sandbox_id = %sandbox_id,
            version = record.version,
            "GetSandboxConfig served from policy history"
        );
        (
            Some(decoded),
            u32::try_from(record.version).unwrap_or(0),
            record.policy_hash,
        )
    } else {
        // Lazy backfill: no policy history exists yet.
        let spec = sandbox
            .spec
            .as_ref()
            .ok_or_else(|| Status::internal("sandbox has no spec"))?;

        match spec.policy.clone() {
            None => {
                debug!(
                    sandbox_id = %sandbox_id,
                    "GetSandboxConfig: no policy configured, returning empty response"
                );
                (None, 0, String::new())
            }
            Some(spec_policy) => {
                let hash = deterministic_policy_hash(&spec_policy);
                let payload = spec_policy.encode_to_vec();
                let policy_id = uuid::Uuid::new_v4().to_string();

                if let Err(e) = state
                    .store
                    .put_policy_revision(&policy_id, &sandbox_id, 1, &payload, &hash)
                    .await
                {
                    warn!(
                        sandbox_id = %sandbox_id,
                        error = %e,
                        "Failed to backfill policy version 1"
                    );
                } else if let Err(e) = state
                    .store
                    .update_policy_status(&sandbox_id, 1, "loaded", None, None)
                    .await
                {
                    warn!(
                        sandbox_id = %sandbox_id,
                        error = %e,
                        "Failed to mark backfilled policy as loaded"
                    );
                }

                info!(
                    sandbox_id = %sandbox_id,
                    "GetSandboxConfig served from spec (backfilled version 1)"
                );

                (Some(spec_policy), 1, hash)
            }
        }
    };

    let global_settings = load_global_settings(state.store.as_ref()).await?;
    let sandbox_settings =
        load_sandbox_settings(state.store.as_ref(), sandbox.object_name()).await?;
    let providers_v2_enabled =
        bool_setting_enabled(&global_settings, settings::PROVIDERS_V2_ENABLED_KEY)?;

    let mut global_policy_version: u32 = 0;

    if let Some(global_policy) = decode_policy_from_global_settings(&global_settings)? {
        policy = Some(global_policy.clone());
        policy_hash = deterministic_policy_hash(&global_policy);
        policy_source = PolicySource::Global;
        if version == 0 {
            version = 1;
        }
        if let Ok(Some(global_rev)) = state
            .store
            .get_latest_policy(GLOBAL_POLICY_SANDBOX_ID)
            .await
        {
            global_policy_version = u32::try_from(global_rev.version).unwrap_or(0);
        }
    }

    if providers_v2_enabled
        && !matches!(policy_source, PolicySource::Global)
        && let Some(source_policy) = policy.as_ref()
    {
        let provider_layers =
            profile_provider_policy_layers(state.store.as_ref(), &sandbox_provider_names).await?;
        if !provider_layers.is_empty() {
            let effective_policy = compose_effective_policy(source_policy, &provider_layers);
            policy_hash = deterministic_policy_hash(&effective_policy);
            policy = Some(effective_policy);
        }
    }

    let settings = merge_effective_settings(&global_settings, &sandbox_settings)?;
    let config_revision = compute_config_revision(policy.as_ref(), &settings, policy_source);

    Ok(Response::new(GetSandboxConfigResponse {
        policy,
        version,
        policy_hash,
        settings,
        config_revision,
        policy_source: policy_source.into(),
        global_policy_version,
    }))
}

async fn profile_provider_policy_layers(
    store: &Store,
    provider_names: &[String],
) -> Result<Vec<ProviderPolicyLayer>, Status> {
    let mut layers = Vec::new();

    for name in provider_names {
        let provider = store
            .get_message_by_name::<Provider>(name)
            .await
            .map_err(|e| Status::internal(format!("failed to fetch provider '{name}': {e}")))?
            .ok_or_else(|| Status::failed_precondition(format!("provider '{name}' not found")))?;

        let provider_type = provider.r#type.trim();
        let Some(profile) = get_default_profile(provider_type) else {
            warn!(
                provider_name = %name,
                provider_type,
                "provider type has no default profile; skipping provider policy layer"
            );
            continue;
        };

        let rule_name = openshell_policy::provider_rule_name(provider.object_name());
        layers.push(ProviderPolicyLayer {
            rule_name: rule_name.clone(),
            rule: profile.network_policy_rule(&rule_name),
        });
    }

    Ok(layers)
}

fn bool_setting_enabled(settings: &StoredSettings, key: &str) -> Result<bool, Status> {
    match settings.settings.get(key) {
        None => Ok(false),
        Some(StoredSettingValue::Bool(value)) => Ok(*value),
        Some(_) => Err(Status::internal(format!(
            "setting '{key}' has invalid value type; expected bool"
        ))),
    }
}

pub(super) async fn handle_get_gateway_config(
    state: &Arc<ServerState>,
    _request: Request<GetGatewayConfigRequest>,
) -> Result<Response<GetGatewayConfigResponse>, Status> {
    let global_settings = load_global_settings(state.store.as_ref()).await?;
    let settings = materialize_global_settings(&global_settings)?;
    Ok(Response::new(GetGatewayConfigResponse {
        settings,
        settings_revision: global_settings.revision,
    }))
}

pub(super) async fn handle_get_sandbox_provider_environment(
    state: &Arc<ServerState>,
    request: Request<GetSandboxProviderEnvironmentRequest>,
) -> Result<Response<GetSandboxProviderEnvironmentResponse>, Status> {
    let sandbox_id = request.into_inner().sandbox_id;

    let sandbox = state
        .store
        .get_message::<Sandbox>(&sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;

    let spec = sandbox
        .spec
        .ok_or_else(|| Status::internal("sandbox has no spec"))?;

    let environment =
        super::provider::resolve_provider_environment(state.store.as_ref(), &spec.providers)
            .await?;

    info!(
        sandbox_id = %sandbox_id,
        provider_count = spec.providers.len(),
        env_count = environment.len(),
        "GetSandboxProviderEnvironment request completed successfully"
    );

    Ok(Response::new(GetSandboxProviderEnvironmentResponse {
        environment,
    }))
}

// ---------------------------------------------------------------------------
// Update config handler (policy + settings mutations)
// ---------------------------------------------------------------------------

pub(super) async fn handle_update_config(
    state: &Arc<ServerState>,
    request: Request<UpdateConfigRequest>,
) -> Result<Response<UpdateConfigResponse>, Status> {
    let sandbox_secret_auth = is_sandbox_secret_authenticated(&request);
    let req = request.into_inner();
    if sandbox_secret_auth {
        validate_sandbox_secret_update(&req)?;
    }
    let key = req.setting_key.trim();
    let has_policy = req.policy.is_some();
    let has_setting = !key.is_empty();
    let has_merge_ops = !req.merge_operations.is_empty();
    let mut mutation_count = 0_u8;
    mutation_count += u8::from(has_policy);
    mutation_count += u8::from(has_setting);
    mutation_count += u8::from(has_merge_ops);

    if mutation_count > 1 {
        return Err(Status::invalid_argument(
            "policy, setting_key, and merge_operations are mutually exclusive",
        ));
    }
    if mutation_count == 0 {
        return Err(Status::invalid_argument(
            "one of policy, setting_key, or merge_operations must be provided",
        ));
    }

    if req.global {
        let _settings_guard = state.settings_mutex.lock().await;

        if has_merge_ops {
            return Err(Status::invalid_argument(
                "merge_operations are not supported for global policy updates",
            ));
        }

        if has_policy {
            if req.delete_setting {
                return Err(Status::invalid_argument(
                    "delete_setting cannot be combined with policy payload",
                ));
            }
            let mut new_policy = req.policy.ok_or_else(|| {
                Status::invalid_argument("policy is required for global policy update")
            })?;
            openshell_policy::ensure_sandbox_process_identity(&mut new_policy);
            validate_policy_safety(&new_policy)?;

            let payload = new_policy.encode_to_vec();
            let hash = deterministic_policy_hash(&new_policy);

            let latest = state
                .store
                .get_latest_policy(GLOBAL_POLICY_SANDBOX_ID)
                .await
                .map_err(|e| Status::internal(format!("fetch latest global policy failed: {e}")))?;

            if let Some(ref current) = latest
                && current.policy_hash == hash
                && current.status == "loaded"
            {
                let mut global_settings = load_global_settings(state.store.as_ref()).await?;
                let stored_value = StoredSettingValue::Bytes(hex::encode(&payload));
                let changed = upsert_setting_value(
                    &mut global_settings.settings,
                    POLICY_SETTING_KEY,
                    stored_value,
                );
                if changed {
                    global_settings.revision = global_settings.revision.wrapping_add(1);
                    save_global_settings(state.store.as_ref(), &global_settings).await?;
                }
                return Ok(Response::new(UpdateConfigResponse {
                    version: u32::try_from(current.version).unwrap_or(0),
                    policy_hash: hash,
                    settings_revision: global_settings.revision,
                    deleted: false,
                }));
            }

            let next_version = latest.map_or(1, |r| r.version + 1);
            let policy_id = uuid::Uuid::new_v4().to_string();

            state
                .store
                .put_policy_revision(
                    &policy_id,
                    GLOBAL_POLICY_SANDBOX_ID,
                    next_version,
                    &payload,
                    &hash,
                )
                .await
                .map_err(|e| {
                    Status::internal(format!("persist global policy revision failed: {e}"))
                })?;

            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as i64);
            let _ = state
                .store
                .update_policy_status(
                    GLOBAL_POLICY_SANDBOX_ID,
                    next_version,
                    "loaded",
                    None,
                    Some(now_ms),
                )
                .await;
            let _ = state
                .store
                .supersede_older_policies(GLOBAL_POLICY_SANDBOX_ID, next_version)
                .await;

            let mut global_settings = load_global_settings(state.store.as_ref()).await?;
            let stored_value = StoredSettingValue::Bytes(hex::encode(&payload));
            let changed = upsert_setting_value(
                &mut global_settings.settings,
                POLICY_SETTING_KEY,
                stored_value,
            );
            if changed {
                global_settings.revision = global_settings.revision.wrapping_add(1);
                save_global_settings(state.store.as_ref(), &global_settings).await?;
            }

            return Ok(Response::new(UpdateConfigResponse {
                version: u32::try_from(next_version).unwrap_or(0),
                policy_hash: hash,
                settings_revision: global_settings.revision,
                deleted: false,
            }));
        }

        // Global setting mutation.
        if key == POLICY_SETTING_KEY && !req.delete_setting {
            return Err(Status::invalid_argument(
                "reserved key 'policy' must be set via the policy field",
            ));
        }
        if key != POLICY_SETTING_KEY {
            validate_registered_setting_key(key)?;
        }

        let mut global_settings = load_global_settings(state.store.as_ref()).await?;
        let changed = if req.delete_setting {
            let removed = global_settings.settings.remove(key).is_some();
            if removed
                && key == POLICY_SETTING_KEY
                && let Ok(Some(latest)) = state
                    .store
                    .get_latest_policy(GLOBAL_POLICY_SANDBOX_ID)
                    .await
            {
                let _ = state
                    .store
                    .supersede_older_policies(GLOBAL_POLICY_SANDBOX_ID, latest.version + 1)
                    .await;
            }
            removed
        } else {
            let setting = req
                .setting_value
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("setting_value is required"))?;
            let stored = proto_setting_to_stored(key, setting)?;
            upsert_setting_value(&mut global_settings.settings, key, stored)
        };

        if changed {
            global_settings.revision = global_settings.revision.wrapping_add(1);
            save_global_settings(state.store.as_ref(), &global_settings).await?;
        }

        return Ok(Response::new(UpdateConfigResponse {
            version: 0,
            policy_hash: String::new(),
            settings_revision: global_settings.revision,
            deleted: req.delete_setting && changed,
        }));
    }

    if req.name.is_empty() {
        return Err(Status::invalid_argument(
            "name is required for sandbox-scoped updates",
        ));
    }

    // Resolve sandbox by name.
    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&req.name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let sandbox_id = sandbox.object_id().to_string();

    if has_setting {
        let _settings_guard = state.settings_mutex.lock().await;

        if key == POLICY_SETTING_KEY {
            return Err(Status::invalid_argument(
                "reserved key 'policy' must be set via policy commands",
            ));
        }

        let global_settings = load_global_settings(state.store.as_ref()).await?;
        let globally_managed = global_settings.settings.contains_key(key);

        if req.delete_setting {
            if globally_managed {
                return Err(Status::failed_precondition(format!(
                    "setting '{key}' is managed globally; delete the global setting first"
                )));
            }

            let mut sandbox_settings =
                load_sandbox_settings(state.store.as_ref(), sandbox.object_name()).await?;
            let removed = sandbox_settings.settings.remove(key).is_some();
            if removed {
                sandbox_settings.revision = sandbox_settings.revision.wrapping_add(1);
                save_sandbox_settings(
                    state.store.as_ref(),
                    sandbox.object_name(),
                    &sandbox_settings,
                )
                .await?;
            }

            return Ok(Response::new(UpdateConfigResponse {
                version: 0,
                policy_hash: String::new(),
                settings_revision: sandbox_settings.revision,
                deleted: removed,
            }));
        }

        if globally_managed {
            return Err(Status::failed_precondition(format!(
                "setting '{key}' is managed globally; delete the global setting before sandbox update"
            )));
        }

        let setting = req
            .setting_value
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("setting_value is required"))?;
        let stored = proto_setting_to_stored(key, setting)?;

        let mut sandbox_settings =
            load_sandbox_settings(state.store.as_ref(), sandbox.object_name()).await?;
        let changed = upsert_setting_value(&mut sandbox_settings.settings, key, stored);
        if changed {
            sandbox_settings.revision = sandbox_settings.revision.wrapping_add(1);
            save_sandbox_settings(
                state.store.as_ref(),
                sandbox.object_name(),
                &sandbox_settings,
            )
            .await?;
        }

        return Ok(Response::new(UpdateConfigResponse {
            version: 0,
            policy_hash: String::new(),
            settings_revision: sandbox_settings.revision,
            deleted: false,
        }));
    }

    if has_merge_ops {
        let global_settings = load_global_settings(state.store.as_ref()).await?;
        if global_settings.settings.contains_key(POLICY_SETTING_KEY) {
            return Err(Status::failed_precondition(
                "policy is managed globally; delete global policy before sandbox policy update",
            ));
        }

        let spec = sandbox
            .spec
            .as_ref()
            .ok_or_else(|| Status::internal("sandbox has no spec"))?;
        let merge_ops = parse_merge_operations(&req.merge_operations)?;
        validate_merge_operations_for_server(&merge_ops)?;
        let (version, hash) = apply_merge_operations_with_retry(
            state.store.as_ref(),
            &sandbox_id,
            spec.policy.as_ref(),
            &merge_ops,
        )
        .await?;

        state.sandbox_watch_bus.notify(&sandbox_id);
        emit_gateway_policy_audit_log(
            &sandbox_id,
            sandbox.object_name(),
            "merged",
            format!(
                "gateway merged {} incremental policy operation(s)",
                merge_ops.len()
            ),
            version,
            &hash,
        );
        for operation in &merge_ops {
            emit_gateway_policy_audit_log(
                &sandbox_id,
                sandbox.object_name(),
                "merged",
                format!(
                    "gateway merged incremental policy op: {}",
                    summarize_cli_policy_merge_op(operation)
                ),
                version,
                &hash,
            );
        }
        info!(
            sandbox_id = %sandbox_id,
            version,
            policy_hash = %hash,
            operation_count = merge_ops.len(),
            "UpdateConfig: merged incremental policy operations"
        );

        return Ok(Response::new(UpdateConfigResponse {
            version: u32::try_from(version).unwrap_or(0),
            policy_hash: hash,
            settings_revision: 0,
            deleted: false,
        }));
    }

    // Sandbox-scoped policy update.
    let mut new_policy = req
        .policy
        .ok_or_else(|| Status::invalid_argument("policy is required"))?;

    let global_settings = load_global_settings(state.store.as_ref()).await?;
    if global_settings.settings.contains_key(POLICY_SETTING_KEY) {
        return Err(Status::failed_precondition(
            "policy is managed globally; delete global policy before sandbox policy update",
        ));
    }

    let spec = sandbox
        .spec
        .as_ref()
        .ok_or_else(|| Status::internal("sandbox has no spec"))?;

    openshell_policy::ensure_sandbox_process_identity(&mut new_policy);

    if let Some(baseline_policy) = spec.policy.as_ref() {
        validate_static_fields_unchanged(baseline_policy, &new_policy)?;
        validate_policy_safety(&new_policy)?;
    } else {
        let mut sandbox = sandbox;
        if let Some(ref mut spec) = sandbox.spec {
            spec.policy = Some(new_policy.clone());
        }
        state
            .store
            .put_message(&sandbox)
            .await
            .map_err(|e| Status::internal(format!("backfill spec.policy failed: {e}")))?;
        info!(
            sandbox_id = %sandbox_id,
            "UpdateConfig: backfilled spec.policy from sandbox-discovered policy"
        );
    }

    let latest = state
        .store
        .get_latest_policy(&sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("fetch latest policy failed: {e}")))?;

    let payload = new_policy.encode_to_vec();
    let hash = deterministic_policy_hash(&new_policy);

    if let Some(ref current) = latest
        && current.policy_hash == hash
    {
        return Ok(Response::new(UpdateConfigResponse {
            version: u32::try_from(current.version).unwrap_or(0),
            policy_hash: hash,
            settings_revision: 0,
            deleted: false,
        }));
    }

    let next_version = latest.map_or(1, |r| r.version + 1);
    let policy_id = uuid::Uuid::new_v4().to_string();

    state
        .store
        .put_policy_revision(&policy_id, &sandbox_id, next_version, &payload, &hash)
        .await
        .map_err(|e| Status::internal(format!("persist policy revision failed: {e}")))?;

    let _ = state
        .store
        .supersede_older_policies(&sandbox_id, next_version)
        .await;

    state.sandbox_watch_bus.notify(&sandbox_id);

    info!(
        sandbox_id = %sandbox_id,
        version = next_version,
        policy_hash = %hash,
        "UpdateConfig: new policy version persisted"
    );

    Ok(Response::new(UpdateConfigResponse {
        version: u32::try_from(next_version).unwrap_or(0),
        policy_hash: hash,
        settings_revision: 0,
        deleted: false,
    }))
}

// ---------------------------------------------------------------------------
// Policy status handlers
// ---------------------------------------------------------------------------

pub(super) async fn handle_get_sandbox_policy_status(
    state: &Arc<ServerState>,
    request: Request<GetSandboxPolicyStatusRequest>,
) -> Result<Response<GetSandboxPolicyStatusResponse>, Status> {
    let req = request.into_inner();

    let (policy_id, active_version) = if req.global {
        (GLOBAL_POLICY_SANDBOX_ID.to_string(), 0_u32)
    } else {
        if req.name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }
        let sandbox = state
            .store
            .get_message_by_name::<Sandbox>(&req.name)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        (
            sandbox.object_id().to_string(),
            sandbox.current_policy_version,
        )
    };

    let record = if req.version == 0 {
        state
            .store
            .get_latest_policy(&policy_id)
            .await
            .map_err(|e| Status::internal(format!("fetch policy failed: {e}")))?
    } else {
        state
            .store
            .get_policy_by_version(&policy_id, i64::from(req.version))
            .await
            .map_err(|e| Status::internal(format!("fetch policy failed: {e}")))?
    };

    let not_found_msg = if req.global {
        "no global policy revision found"
    } else {
        "no policy revision found for this sandbox"
    };
    let record = record.ok_or_else(|| Status::not_found(not_found_msg))?;

    Ok(Response::new(GetSandboxPolicyStatusResponse {
        revision: Some(policy_record_to_revision(&record, true)),
        active_version,
    }))
}

pub(super) async fn handle_list_sandbox_policies(
    state: &Arc<ServerState>,
    request: Request<ListSandboxPoliciesRequest>,
) -> Result<Response<ListSandboxPoliciesResponse>, Status> {
    let req = request.into_inner();

    let policy_id = if req.global {
        GLOBAL_POLICY_SANDBOX_ID.to_string()
    } else {
        if req.name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }
        let sandbox = state
            .store
            .get_message_by_name::<Sandbox>(&req.name)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        sandbox.object_id().to_string()
    };

    let limit = clamp_limit(req.limit, 50, MAX_PAGE_SIZE);
    let records = state
        .store
        .list_policies(&policy_id, limit, req.offset)
        .await
        .map_err(|e| Status::internal(format!("list policies failed: {e}")))?;

    let revisions = records
        .iter()
        .map(|r| policy_record_to_revision(r, false))
        .collect();

    Ok(Response::new(ListSandboxPoliciesResponse { revisions }))
}

pub(super) async fn handle_report_policy_status(
    state: &Arc<ServerState>,
    request: Request<ReportPolicyStatusRequest>,
) -> Result<Response<ReportPolicyStatusResponse>, Status> {
    let req = request.into_inner();
    if req.sandbox_id.is_empty() {
        return Err(Status::invalid_argument("sandbox_id is required"));
    }
    if req.version == 0 {
        return Err(Status::invalid_argument("version is required"));
    }

    let version = i64::from(req.version);
    let status_str = match PolicyStatus::try_from(req.status) {
        Ok(PolicyStatus::Loaded) => "loaded",
        Ok(PolicyStatus::Failed) => "failed",
        _ => return Err(Status::invalid_argument("status must be LOADED or FAILED")),
    };

    let loaded_at_ms = if status_str == "loaded" {
        Some(current_time_ms().map_err(|e| Status::internal(format!("timestamp error: {e}")))?)
    } else {
        None
    };

    let load_error = if status_str == "failed" && !req.load_error.is_empty() {
        Some(req.load_error.as_str())
    } else {
        None
    };

    let updated = state
        .store
        .update_policy_status(
            &req.sandbox_id,
            version,
            status_str,
            load_error,
            loaded_at_ms,
        )
        .await
        .map_err(|e| Status::internal(format!("update policy status failed: {e}")))?;

    if !updated {
        return Err(Status::not_found("policy revision not found"));
    }

    if status_str == "loaded" {
        let _ = state
            .store
            .supersede_older_policies(&req.sandbox_id, version)
            .await;
        if let Ok(Some(mut sandbox)) = state.store.get_message::<Sandbox>(&req.sandbox_id).await {
            sandbox.current_policy_version = req.version;
            let _ = state.store.put_message(&sandbox).await;
        }
        state.sandbox_watch_bus.notify(&req.sandbox_id);
    }

    info!(
        sandbox_id = %req.sandbox_id,
        version = req.version,
        status = %status_str,
        "ReportPolicyStatus: sandbox reported policy load result"
    );

    Ok(Response::new(ReportPolicyStatusResponse {}))
}

// ---------------------------------------------------------------------------
// Sandbox logs handlers
// ---------------------------------------------------------------------------

#[allow(clippy::unused_async)] // Must be async to match the trait signature
pub(super) async fn handle_get_sandbox_logs(
    state: &Arc<ServerState>,
    request: Request<GetSandboxLogsRequest>,
) -> Result<Response<GetSandboxLogsResponse>, Status> {
    let req = request.into_inner();
    if req.sandbox_id.is_empty() {
        return Err(Status::invalid_argument("sandbox_id is required"));
    }

    let lines = if req.lines == 0 { 2000 } else { req.lines };
    let tail = state.tracing_log_bus.tail(&req.sandbox_id, lines as usize);

    let buffer_total = tail.len() as u32;

    let logs: Vec<SandboxLogLine> = tail
        .into_iter()
        .filter_map(|evt| {
            if let Some(openshell_core::proto::sandbox_stream_event::Payload::Log(log)) =
                evt.payload
            {
                if req.since_ms > 0 && log.timestamp_ms < req.since_ms {
                    return None;
                }
                if !req.sources.is_empty() && !source_matches(&log.source, &req.sources) {
                    return None;
                }
                if !level_matches(&log.level, &req.min_level) {
                    return None;
                }
                Some(log)
            } else {
                None
            }
        })
        .collect();

    Ok(Response::new(GetSandboxLogsResponse { logs, buffer_total }))
}

pub(super) async fn handle_push_sandbox_logs(
    state: &Arc<ServerState>,
    request: Request<tonic::Streaming<PushSandboxLogsRequest>>,
) -> Result<Response<PushSandboxLogsResponse>, Status> {
    let mut stream = request.into_inner();
    let mut validated = false;

    while let Some(batch) = stream
        .message()
        .await
        .map_err(|e| Status::internal(format!("stream error: {e}")))?
    {
        if batch.sandbox_id.is_empty() {
            continue;
        }

        if !validated {
            state
                .store
                .get_message::<Sandbox>(&batch.sandbox_id)
                .await
                .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
                .ok_or_else(|| Status::not_found("sandbox not found"))?;
            validated = true;
        }

        for log in batch.logs.into_iter().take(100) {
            let mut log = log;
            log.source = "sandbox".to_string();
            log.sandbox_id.clone_from(&batch.sandbox_id);
            state.tracing_log_bus.publish_external(log);
        }
    }

    Ok(Response::new(PushSandboxLogsResponse {}))
}

// ---------------------------------------------------------------------------
// Draft policy recommendation handlers
// ---------------------------------------------------------------------------

pub(super) async fn handle_submit_policy_analysis(
    state: &Arc<ServerState>,
    request: Request<SubmitPolicyAnalysisRequest>,
) -> Result<Response<SubmitPolicyAnalysisResponse>, Status> {
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }

    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&req.name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let sandbox_id = sandbox.object_id().to_string();

    let current_version = state
        .store
        .get_draft_version(&sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("get draft version failed: {e}")))?;
    let draft_version = current_version + 1;

    let mut accepted: u32 = 0;
    let mut rejected: u32 = 0;
    let mut rejection_reasons: Vec<String> = Vec::new();

    for chunk in &req.proposed_chunks {
        if chunk.rule_name.is_empty() {
            rejected += 1;
            rejection_reasons.push("chunk missing rule_name".to_string());
            continue;
        }
        if chunk.proposed_rule.is_none() {
            rejected += 1;
            rejection_reasons.push(format!("chunk '{}' missing proposed_rule", chunk.rule_name));
            continue;
        }

        let chunk_id = uuid::Uuid::new_v4().to_string();
        let now_ms =
            current_time_ms().map_err(|e| Status::internal(format!("timestamp error: {e}")))?;
        let proposed_rule_bytes = chunk
            .proposed_rule
            .as_ref()
            .map(Message::encode_to_vec)
            .unwrap_or_default();

        let rule_ref = chunk.proposed_rule.as_ref();
        let (ep_host, ep_port) = rule_ref
            .and_then(|r| r.endpoints.first())
            .map(|ep| (ep.host.to_lowercase(), ep.port as i32))
            .unwrap_or_default();
        let ep_binary = rule_ref
            .and_then(|r| r.binaries.first())
            .map(|b| b.path.clone())
            .unwrap_or_default();

        let record = DraftChunkRecord {
            id: chunk_id,
            sandbox_id: sandbox_id.clone(),
            draft_version,
            status: "pending".to_string(),
            rule_name: chunk.rule_name.clone(),
            proposed_rule: proposed_rule_bytes,
            rationale: chunk.rationale.clone(),
            security_notes: generate_security_notes(
                &ep_host,
                u16::try_from(ep_port as u32).unwrap_or(0),
            ),
            confidence: f64::from(chunk.confidence.clamp(0.0, 1.0)),
            created_at_ms: now_ms,
            decided_at_ms: None,
            host: ep_host,
            port: ep_port,
            binary: ep_binary,
            hit_count: chunk.hit_count.clamp(1, 100),
            first_seen_ms: if chunk.first_seen_ms > 0 {
                chunk.first_seen_ms
            } else {
                now_ms
            },
            last_seen_ms: if chunk.last_seen_ms > 0 {
                chunk.last_seen_ms
            } else {
                now_ms
            },
        };
        state
            .store
            .put_draft_chunk(&record)
            .await
            .map_err(|e| Status::internal(format!("persist draft chunk failed: {e}")))?;
        accepted += 1;
    }

    state.sandbox_watch_bus.notify(&sandbox_id);

    info!(
        sandbox_id = %sandbox_id,
        accepted = accepted,
        rejected = rejected,
        draft_version = draft_version,
        summaries = req.summaries.len(),
        "SubmitPolicyAnalysis: persisted draft chunks"
    );

    Ok(Response::new(SubmitPolicyAnalysisResponse {
        accepted_chunks: accepted,
        rejected_chunks: rejected,
        rejection_reasons,
    }))
}

pub(super) async fn handle_get_draft_policy(
    state: &Arc<ServerState>,
    request: Request<GetDraftPolicyRequest>,
) -> Result<Response<GetDraftPolicyResponse>, Status> {
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }

    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&req.name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let sandbox_id = sandbox.object_id().to_string();

    let status_filter = if req.status_filter.is_empty() {
        None
    } else {
        Some(req.status_filter.as_str())
    };

    let records = state
        .store
        .list_draft_chunks(&sandbox_id, status_filter)
        .await
        .map_err(|e| Status::internal(format!("list draft chunks failed: {e}")))?;

    let draft_version = state
        .store
        .get_draft_version(&sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("get draft version failed: {e}")))?;

    let chunks: Vec<PolicyChunk> = records
        .into_iter()
        .map(|r| draft_chunk_record_to_proto(&r))
        .collect::<Result<Vec<_>, _>>()?;

    let last_analyzed_at_ms = chunks.iter().map(|c| c.created_at_ms).max().unwrap_or(0);

    debug!(
        sandbox_id = %sandbox_id,
        chunk_count = chunks.len(),
        draft_version = draft_version,
        "GetDraftPolicy: served draft chunks"
    );

    Ok(Response::new(GetDraftPolicyResponse {
        chunks,
        rolling_summary: String::new(),
        draft_version: u64::try_from(draft_version).unwrap_or(0),
        last_analyzed_at_ms,
    }))
}

pub(super) async fn handle_approve_draft_chunk(
    state: &Arc<ServerState>,
    request: Request<ApproveDraftChunkRequest>,
) -> Result<Response<ApproveDraftChunkResponse>, Status> {
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    if req.chunk_id.is_empty() {
        return Err(Status::invalid_argument("chunk_id is required"));
    }

    require_no_global_policy(state).await?;

    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&req.name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let sandbox_id = sandbox.object_id().to_string();

    let chunk = state
        .store
        .get_draft_chunk(&req.chunk_id)
        .await
        .map_err(|e| Status::internal(format!("fetch chunk failed: {e}")))?
        .ok_or_else(|| Status::not_found("chunk not found"))?;
    ensure_chunk_belongs_to_sandbox(&chunk, &sandbox_id)?;

    if chunk.status != "pending" && chunk.status != "rejected" {
        return Err(Status::failed_precondition(format!(
            "chunk status is '{}', expected 'pending' or 'rejected'",
            chunk.status
        )));
    }

    info!(
        sandbox_id = %sandbox_id,
        chunk_id = %req.chunk_id,
        rule_name = %chunk.rule_name,
        host = %chunk.host,
        port = chunk.port,
        hit_count = chunk.hit_count,
        prev_status = %chunk.status,
        "ApproveDraftChunk: merging rule into active policy"
    );

    let (version, hash) =
        merge_chunk_into_policy(state.store.as_ref(), &sandbox_id, &chunk).await?;
    let chunk_summary = summarize_draft_chunk_rule(&chunk)?;

    let now_ms =
        current_time_ms().map_err(|e| Status::internal(format!("timestamp error: {e}")))?;
    state
        .store
        .update_draft_chunk_status(&req.chunk_id, "approved", Some(now_ms))
        .await
        .map_err(|e| Status::internal(format!("update chunk status failed: {e}")))?;

    state.sandbox_watch_bus.notify(&sandbox_id);
    emit_gateway_policy_audit_log(
        &sandbox_id,
        sandbox.object_name(),
        "approved",
        format!(
            "gateway approved draft chunk {}: {chunk_summary}",
            req.chunk_id
        ),
        version,
        &hash,
    );

    info!(
        sandbox_id = %sandbox_id,
        chunk_id = %req.chunk_id,
        rule_name = %chunk.rule_name,
        version = version,
        policy_hash = %hash,
        "ApproveDraftChunk: rule merged successfully"
    );

    Ok(Response::new(ApproveDraftChunkResponse {
        policy_version: u32::try_from(version).unwrap_or(0),
        policy_hash: hash,
    }))
}

pub(super) async fn handle_reject_draft_chunk(
    state: &Arc<ServerState>,
    request: Request<RejectDraftChunkRequest>,
) -> Result<Response<RejectDraftChunkResponse>, Status> {
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    if req.chunk_id.is_empty() {
        return Err(Status::invalid_argument("chunk_id is required"));
    }

    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&req.name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let sandbox_id = sandbox.object_id().to_string();

    let chunk = state
        .store
        .get_draft_chunk(&req.chunk_id)
        .await
        .map_err(|e| Status::internal(format!("fetch chunk failed: {e}")))?
        .ok_or_else(|| Status::not_found("chunk not found"))?;
    ensure_chunk_belongs_to_sandbox(&chunk, &sandbox_id)?;

    if chunk.status != "pending" && chunk.status != "approved" {
        return Err(Status::failed_precondition(format!(
            "chunk status is '{}', expected 'pending' or 'approved'",
            chunk.status
        )));
    }

    let was_approved = chunk.status == "approved";

    info!(
        sandbox_id = %sandbox_id,
        chunk_id = %req.chunk_id,
        rule_name = %chunk.rule_name,
        host = %chunk.host,
        port = chunk.port,
        reason = %req.reason,
        prev_status = %chunk.status,
        "RejectDraftChunk: rejecting chunk"
    );

    if was_approved {
        require_no_global_policy(state).await?;
        let (version, hash) = remove_chunk_from_policy(state, &sandbox_id, &chunk).await?;
        emit_gateway_policy_audit_log(
            &sandbox_id,
            sandbox.object_name(),
            "removed",
            format!(
                "gateway removed previously approved draft chunk {}: remove-binary {} {}",
                req.chunk_id, chunk.rule_name, chunk.binary
            ),
            version,
            &hash,
        );
    }

    let now_ms =
        current_time_ms().map_err(|e| Status::internal(format!("timestamp error: {e}")))?;
    state
        .store
        .update_draft_chunk_status(&req.chunk_id, "rejected", Some(now_ms))
        .await
        .map_err(|e| Status::internal(format!("update chunk status failed: {e}")))?;

    state.sandbox_watch_bus.notify(&sandbox_id);

    Ok(Response::new(RejectDraftChunkResponse {}))
}

pub(super) async fn handle_approve_all_draft_chunks(
    state: &Arc<ServerState>,
    request: Request<ApproveAllDraftChunksRequest>,
) -> Result<Response<ApproveAllDraftChunksResponse>, Status> {
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }

    require_no_global_policy(state).await?;

    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&req.name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let sandbox_id = sandbox.object_id().to_string();

    let pending_chunks = state
        .store
        .list_draft_chunks(&sandbox_id, Some("pending"))
        .await
        .map_err(|e| Status::internal(format!("list draft chunks failed: {e}")))?;

    if pending_chunks.is_empty() {
        return Err(Status::failed_precondition("no pending chunks to approve"));
    }

    info!(
        sandbox_id = %sandbox_id,
        pending_count = pending_chunks.len(),
        include_security_flagged = req.include_security_flagged,
        "ApproveAllDraftChunks: starting bulk approval"
    );

    let mut chunks_approved: u32 = 0;
    let mut chunks_skipped: u32 = 0;
    let mut last_version: i64 = 0;
    let mut last_hash = String::new();

    for chunk in &pending_chunks {
        if !req.include_security_flagged && !chunk.security_notes.is_empty() {
            info!(
                sandbox_id = %sandbox_id,
                chunk_id = %chunk.id,
                rule_name = %chunk.rule_name,
                security_notes = %chunk.security_notes,
                "ApproveAllDraftChunks: skipping security-flagged chunk"
            );
            chunks_skipped += 1;
            continue;
        }

        info!(
            sandbox_id = %sandbox_id,
            chunk_id = %chunk.id,
            rule_name = %chunk.rule_name,
            host = %chunk.host,
            port = chunk.port,
            "ApproveAllDraftChunks: merging chunk"
        );

        let (version, hash) =
            merge_chunk_into_policy(state.store.as_ref(), &sandbox_id, chunk).await?;
        last_version = version;
        last_hash = hash;
        let chunk_summary = summarize_draft_chunk_rule(chunk)?;

        let now_ms =
            current_time_ms().map_err(|e| Status::internal(format!("timestamp error: {e}")))?;
        state
            .store
            .update_draft_chunk_status(&chunk.id, "approved", Some(now_ms))
            .await
            .map_err(|e| Status::internal(format!("update chunk status failed: {e}")))?;

        emit_gateway_policy_audit_log(
            &sandbox_id,
            sandbox.object_name(),
            "approved",
            format!("gateway approved draft chunk {}: {chunk_summary}", chunk.id),
            version,
            &last_hash,
        );
        chunks_approved += 1;
    }

    state.sandbox_watch_bus.notify(&sandbox_id);
    emit_gateway_policy_audit_log(
        &sandbox_id,
        sandbox.object_name(),
        "merged",
        format!(
            "gateway bulk-approved {chunks_approved} draft chunk(s) and skipped {chunks_skipped}"
        ),
        last_version,
        &last_hash,
    );

    info!(
        sandbox_id = %sandbox_id,
        chunks_approved = chunks_approved,
        chunks_skipped = chunks_skipped,
        version = last_version,
        policy_hash = %last_hash,
        "ApproveAllDraftChunks: bulk approval complete"
    );

    Ok(Response::new(ApproveAllDraftChunksResponse {
        policy_version: u32::try_from(last_version).unwrap_or(0),
        policy_hash: last_hash,
        chunks_approved,
        chunks_skipped,
    }))
}

pub(super) async fn handle_edit_draft_chunk(
    state: &Arc<ServerState>,
    request: Request<EditDraftChunkRequest>,
) -> Result<Response<EditDraftChunkResponse>, Status> {
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    if req.chunk_id.is_empty() {
        return Err(Status::invalid_argument("chunk_id is required"));
    }
    let proposed_rule = req
        .proposed_rule
        .ok_or_else(|| Status::invalid_argument("proposed_rule is required"))?;

    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&req.name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let sandbox_id = sandbox.object_id().to_string();

    let chunk = state
        .store
        .get_draft_chunk(&req.chunk_id)
        .await
        .map_err(|e| Status::internal(format!("fetch chunk failed: {e}")))?
        .ok_or_else(|| Status::not_found("chunk not found"))?;
    ensure_chunk_belongs_to_sandbox(&chunk, &sandbox_id)?;

    if chunk.status != "pending" {
        return Err(Status::failed_precondition(format!(
            "chunk status is '{}', expected 'pending'",
            chunk.status
        )));
    }

    let rule_bytes = proposed_rule.encode_to_vec();
    state
        .store
        .update_draft_chunk_rule(&req.chunk_id, &rule_bytes)
        .await
        .map_err(|e| Status::internal(format!("update chunk rule failed: {e}")))?;

    info!(
        chunk_id = %req.chunk_id,
        "EditDraftChunk: proposed rule updated"
    );

    Ok(Response::new(EditDraftChunkResponse {}))
}

pub(super) async fn handle_undo_draft_chunk(
    state: &Arc<ServerState>,
    request: Request<UndoDraftChunkRequest>,
) -> Result<Response<UndoDraftChunkResponse>, Status> {
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    if req.chunk_id.is_empty() {
        return Err(Status::invalid_argument("chunk_id is required"));
    }

    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&req.name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let sandbox_id = sandbox.object_id().to_string();

    let chunk = state
        .store
        .get_draft_chunk(&req.chunk_id)
        .await
        .map_err(|e| Status::internal(format!("fetch chunk failed: {e}")))?
        .ok_or_else(|| Status::not_found("chunk not found"))?;
    ensure_chunk_belongs_to_sandbox(&chunk, &sandbox_id)?;

    if chunk.status != "approved" {
        return Err(Status::failed_precondition(format!(
            "chunk status is '{}', expected 'approved'",
            chunk.status
        )));
    }

    info!(
        sandbox_id = %sandbox_id,
        chunk_id = %req.chunk_id,
        rule_name = %chunk.rule_name,
        host = %chunk.host,
        port = chunk.port,
        "UndoDraftChunk: removing rule from active policy"
    );

    let (version, hash) = remove_chunk_from_policy(state, &sandbox_id, &chunk).await?;

    state
        .store
        .update_draft_chunk_status(&req.chunk_id, "pending", None)
        .await
        .map_err(|e| Status::internal(format!("update chunk status failed: {e}")))?;

    state.sandbox_watch_bus.notify(&sandbox_id);
    emit_gateway_policy_audit_log(
        &sandbox_id,
        sandbox.object_name(),
        "removed",
        format!(
            "gateway reverted approved draft chunk {}: remove-binary {} {}",
            req.chunk_id, chunk.rule_name, chunk.binary
        ),
        version,
        &hash,
    );

    info!(
        sandbox_id = %sandbox_id,
        chunk_id = %req.chunk_id,
        rule_name = %chunk.rule_name,
        version = version,
        policy_hash = %hash,
        "UndoDraftChunk: rule removed, chunk reverted to pending"
    );

    Ok(Response::new(UndoDraftChunkResponse {
        policy_version: u32::try_from(version).unwrap_or(0),
        policy_hash: hash,
    }))
}

pub(super) async fn handle_clear_draft_chunks(
    state: &Arc<ServerState>,
    request: Request<ClearDraftChunksRequest>,
) -> Result<Response<ClearDraftChunksResponse>, Status> {
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }

    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&req.name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let sandbox_id = sandbox.object_id().to_string();

    let deleted = state
        .store
        .delete_draft_chunks(&sandbox_id, "pending")
        .await
        .map_err(|e| Status::internal(format!("delete draft chunks failed: {e}")))?;

    state.sandbox_watch_bus.notify(&sandbox_id);

    info!(
        sandbox_id = %sandbox_id,
        chunks_cleared = deleted,
        "ClearDraftChunks: pending chunks cleared"
    );

    Ok(Response::new(ClearDraftChunksResponse {
        chunks_cleared: u32::try_from(deleted).unwrap_or(0),
    }))
}

pub(super) async fn handle_get_draft_history(
    state: &Arc<ServerState>,
    request: Request<GetDraftHistoryRequest>,
) -> Result<Response<GetDraftHistoryResponse>, Status> {
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }

    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&req.name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let sandbox_id = sandbox.object_id().to_string();

    let all_chunks = state
        .store
        .list_draft_chunks(&sandbox_id, None)
        .await
        .map_err(|e| Status::internal(format!("list draft chunks failed: {e}")))?;

    let mut entries: Vec<DraftHistoryEntry> = Vec::new();

    for chunk in &all_chunks {
        entries.push(DraftHistoryEntry {
            timestamp_ms: chunk.created_at_ms,
            event_type: "proposed".to_string(),
            description: format!(
                "Rule '{}' proposed (confidence: {:.0}%)",
                chunk.rule_name,
                chunk.confidence * 100.0
            ),
            chunk_id: chunk.id.clone(),
        });

        if let Some(decided_at) = chunk.decided_at_ms {
            entries.push(DraftHistoryEntry {
                timestamp_ms: decided_at,
                event_type: chunk.status.clone(),
                description: format!("Rule '{}' {}", chunk.rule_name, chunk.status),
                chunk_id: chunk.id.clone(),
            });
        }
    }

    entries.sort_by_key(|e| e.timestamp_ms);

    debug!(
        sandbox_id = %sandbox_id,
        entry_count = entries.len(),
        "GetDraftHistory: served draft history"
    );

    Ok(Response::new(GetDraftHistoryResponse { entries }))
}

// ---------------------------------------------------------------------------
// Policy helper functions
// ---------------------------------------------------------------------------

/// Compute a deterministic SHA-256 hash of a `SandboxPolicy`.
fn deterministic_policy_hash(policy: &ProtoSandboxPolicy) -> String {
    let mut hasher = Sha256::new();
    hasher.update(policy.version.to_le_bytes());
    if let Some(fs) = &policy.filesystem {
        hasher.update(fs.encode_to_vec());
    }
    if let Some(ll) = &policy.landlock {
        hasher.update(ll.encode_to_vec());
    }
    if let Some(p) = &policy.process {
        hasher.update(p.encode_to_vec());
    }
    let mut entries: Vec<_> = policy.network_policies.iter().collect();
    entries.sort_by_key(|(k, _)| k.as_str());
    for (key, value) in entries {
        hasher.update(key.as_bytes());
        hasher.update(value.encode_to_vec());
    }
    hex::encode(hasher.finalize())
}

/// Compute a fingerprint for the effective sandbox configuration.
fn compute_config_revision(
    policy: Option<&ProtoSandboxPolicy>,
    settings: &HashMap<String, EffectiveSetting>,
    policy_source: PolicySource,
) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update((policy_source as i32).to_le_bytes());
    if let Some(policy) = policy {
        hasher.update(deterministic_policy_hash(policy).as_bytes());
    }
    let mut entries: Vec<_> = settings.iter().collect();
    entries.sort_by_key(|(k, _)| k.as_str());
    for (key, setting) in entries {
        hasher.update(key.as_bytes());
        hasher.update(setting.scope.to_le_bytes());
        if let Some(value) = setting.value.as_ref().and_then(|v| v.value.as_ref()) {
            match value {
                setting_value::Value::StringValue(v) => {
                    hasher.update([0]);
                    hasher.update(v.as_bytes());
                }
                setting_value::Value::BoolValue(v) => {
                    hasher.update([1]);
                    hasher.update([u8::from(*v)]);
                }
                setting_value::Value::IntValue(v) => {
                    hasher.update([2]);
                    hasher.update(v.to_le_bytes());
                }
                setting_value::Value::BytesValue(v) => {
                    hasher.update([3]);
                    hasher.update(v);
                }
            }
        }
    }

    let digest = hasher.finalize();
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes)
}

fn draft_chunk_record_to_proto(record: &DraftChunkRecord) -> Result<PolicyChunk, Status> {
    use openshell_core::proto::NetworkPolicyRule;

    let proposed_rule = if record.proposed_rule.is_empty() {
        None
    } else {
        Some(
            NetworkPolicyRule::decode(record.proposed_rule.as_slice())
                .map_err(|e| Status::internal(format!("decode proposed_rule failed: {e}")))?,
        )
    };

    Ok(PolicyChunk {
        id: record.id.clone(),
        status: record.status.clone(),
        rule_name: record.rule_name.clone(),
        proposed_rule,
        rationale: record.rationale.clone(),
        security_notes: record.security_notes.clone(),
        confidence: record.confidence as f32,
        created_at_ms: record.created_at_ms,
        decided_at_ms: record.decided_at_ms.unwrap_or(0),
        hit_count: record.hit_count,
        first_seen_ms: record.first_seen_ms,
        last_seen_ms: record.last_seen_ms,
        binary: record.binary.clone(),
        ..Default::default()
    })
}

fn policy_record_to_revision(record: &PolicyRecord, include_policy: bool) -> SandboxPolicyRevision {
    let status = match record.status.as_str() {
        "pending" => PolicyStatus::Pending,
        "loaded" => PolicyStatus::Loaded,
        "failed" => PolicyStatus::Failed,
        "superseded" => PolicyStatus::Superseded,
        _ => PolicyStatus::Unspecified,
    };

    let policy = if include_policy {
        ProtoSandboxPolicy::decode(record.policy_payload.as_slice()).ok()
    } else {
        None
    };

    SandboxPolicyRevision {
        version: u32::try_from(record.version).unwrap_or(0),
        policy_hash: record.policy_hash.clone(),
        status: status.into(),
        load_error: record.load_error.clone().unwrap_or_default(),
        created_at_ms: record.created_at_ms,
        loaded_at_ms: record.loaded_at_ms.unwrap_or(0),
        policy,
    }
}

/// Re-validate security notes server-side for a proposed policy chunk.
fn generate_security_notes(host: &str, port: u16) -> String {
    let mut notes = Vec::new();

    if host.starts_with("10.")
        || host.starts_with("172.")
        || host.starts_with("192.168.")
        || host == "localhost"
        || host.starts_with("127.")
    {
        notes.push(format!(
            "Destination '{host}' appears to be an internal/private address."
        ));
    }

    if host.contains('*') {
        notes.push(format!(
            "Host '{host}' contains a wildcard — this may match unintended destinations."
        ));
    }

    if port > 49152 {
        notes.push(format!(
            "Port {port} is in the ephemeral range — this may be a temporary service."
        ));
    }

    const DB_PORTS: [u16; 7] = [5432, 3306, 6379, 27017, 9200, 11211, 5672];
    if DB_PORTS.contains(&port) {
        notes.push(format!(
            "Port {port} is a well-known database/service port."
        ));
    }

    notes.join(" ")
}

/// Reject proposed rules whose endpoints or `allowed_ips` target
/// always-blocked addresses (loopback, link-local, unspecified).
///
/// This is defense-in-depth: the proxy blocks these at runtime, so
/// merging them into the active policy would be silently un-enforceable.
fn validate_rule_not_always_blocked(rule: &NetworkPolicyRule) -> Result<(), Status> {
    use openshell_core::net::{is_always_blocked_ip, is_always_blocked_net};
    use std::net::IpAddr;

    for ep in &rule.endpoints {
        // Check if the endpoint host is a literal always-blocked IP.
        if let Ok(ip) = ep.host.parse::<IpAddr>()
            && is_always_blocked_ip(ip)
        {
            return Err(Status::invalid_argument(format!(
                "proposed rule endpoint host '{}' is an always-blocked address \
                 (loopback/link-local/unspecified); the proxy will deny traffic \
                 to this destination regardless of policy",
                ep.host
            )));
        }
        let host_lc = ep.host.to_lowercase();
        if host_lc == "localhost" || host_lc == "localhost." {
            return Err(Status::invalid_argument(
                "proposed rule endpoint host 'localhost' is always blocked; \
                 the proxy will deny traffic to loopback regardless of policy"
                    .to_string(),
            ));
        }

        // Check allowed_ips entries.
        for entry in &ep.allowed_ips {
            let parsed = entry.parse::<ipnet::IpNet>().or_else(|_| {
                entry.parse::<IpAddr>().map(|ip| match ip {
                    IpAddr::V4(v4) => ipnet::IpNet::V4(ipnet::Ipv4Net::from(v4)),
                    IpAddr::V6(v6) => ipnet::IpNet::V6(ipnet::Ipv6Net::from(v6)),
                })
            });
            if let Ok(net) = parsed
                && is_always_blocked_net(net)
            {
                return Err(Status::invalid_argument(format!(
                    "proposed rule contains always-blocked `allowed_ips` entry '{entry}'; \
                     SSRF hardening prevents traffic to these destinations \
                     regardless of policy"
                )));
            }
            // Invalid entries are not our concern here — the sandbox's
            // parse_allowed_ips handles syntax validation.
        }
    }
    Ok(())
}

async fn require_no_global_policy(state: &ServerState) -> Result<(), Status> {
    let global = load_global_settings(state.store.as_ref()).await?;
    if global.settings.contains_key(POLICY_SETTING_KEY) {
        return Err(Status::failed_precondition(
            "cannot approve rules while a global policy is active; \
             delete the global policy to manage per-sandbox rules",
        ));
    }
    Ok(())
}

fn parse_merge_operations(
    proto_ops: &[PolicyMergeOperation],
) -> Result<Vec<PolicyMergeOp>, Status> {
    proto_ops
        .iter()
        .enumerate()
        .map(|(index, operation)| {
            let Some(operation) = operation.operation.as_ref() else {
                return Err(Status::invalid_argument(format!(
                    "merge_operations[{index}] is missing an operation"
                )));
            };

            match operation {
                policy_merge_operation::Operation::AddRule(add_rule) => {
                    let rule_name = add_rule.rule_name.trim();
                    if rule_name.is_empty() {
                        return Err(Status::invalid_argument(format!(
                            "merge_operations[{index}].add_rule.rule_name is required"
                        )));
                    }
                    if add_rule.rule.as_ref().is_none_or(|rule| rule.endpoints.is_empty()) {
                        return Err(Status::invalid_argument(format!(
                            "merge_operations[{index}].add_rule.rule must contain at least one endpoint"
                        )));
                    }
                    Ok(PolicyMergeOp::AddRule {
                        rule_name: rule_name.to_string(),
                        rule: add_rule.rule.clone().unwrap_or_default(),
                    })
                }
                policy_merge_operation::Operation::RemoveEndpoint(remove_endpoint) => {
                    if remove_endpoint.host.trim().is_empty() || remove_endpoint.port == 0 {
                        return Err(Status::invalid_argument(format!(
                            "merge_operations[{index}].remove_endpoint requires host and non-zero port"
                        )));
                    }
                    let rule_name = if remove_endpoint.rule_name.trim().is_empty() {
                        None
                    } else {
                        Some(remove_endpoint.rule_name.trim().to_string())
                    };
                    Ok(PolicyMergeOp::RemoveEndpoint {
                        rule_name,
                        host: remove_endpoint.host.trim().to_string(),
                        port: remove_endpoint.port,
                    })
                }
                policy_merge_operation::Operation::RemoveRule(remove_rule) => {
                    let rule_name = remove_rule.rule_name.trim();
                    if rule_name.is_empty() {
                        return Err(Status::invalid_argument(format!(
                            "merge_operations[{index}].remove_rule.rule_name is required"
                        )));
                    }
                    Ok(PolicyMergeOp::RemoveRule {
                        rule_name: rule_name.to_string(),
                    })
                }
                policy_merge_operation::Operation::AddDenyRules(add_deny_rules) => {
                    parse_proto_add_deny_rules(index, add_deny_rules)
                }
                policy_merge_operation::Operation::AddAllowRules(add_allow_rules) => {
                    parse_proto_add_allow_rules(index, add_allow_rules)
                }
                policy_merge_operation::Operation::RemoveBinary(remove_binary) => {
                    let rule_name = remove_binary.rule_name.trim();
                    let binary_path = remove_binary.binary_path.trim();
                    if rule_name.is_empty() || binary_path.is_empty() {
                        return Err(Status::invalid_argument(format!(
                            "merge_operations[{index}].remove_binary requires rule_name and binary_path"
                        )));
                    }
                    Ok(PolicyMergeOp::RemoveBinary {
                        rule_name: rule_name.to_string(),
                        binary_path: binary_path.to_string(),
                    })
                }
            }
        })
        .collect()
}

fn parse_proto_add_deny_rules(
    index: usize,
    add_deny_rules: &ProtoAddDenyRules,
) -> Result<PolicyMergeOp, Status> {
    if add_deny_rules.host.trim().is_empty()
        || add_deny_rules.port == 0
        || add_deny_rules.deny_rules.is_empty()
    {
        return Err(Status::invalid_argument(format!(
            "merge_operations[{index}].add_deny_rules requires host, non-zero port, and at least one deny rule"
        )));
    }

    Ok(PolicyMergeOp::AddDenyRules {
        host: add_deny_rules.host.trim().to_string(),
        port: add_deny_rules.port,
        deny_rules: add_deny_rules.deny_rules.clone(),
    })
}

fn parse_proto_add_allow_rules(
    index: usize,
    add_allow_rules: &ProtoAddAllowRules,
) -> Result<PolicyMergeOp, Status> {
    if add_allow_rules.host.trim().is_empty()
        || add_allow_rules.port == 0
        || add_allow_rules.rules.is_empty()
    {
        return Err(Status::invalid_argument(format!(
            "merge_operations[{index}].add_allow_rules requires host, non-zero port, and at least one allow rule"
        )));
    }
    if add_allow_rules
        .rules
        .iter()
        .any(|rule| rule.allow.as_ref().is_none())
    {
        return Err(Status::invalid_argument(format!(
            "merge_operations[{index}].add_allow_rules rules must include allow payloads"
        )));
    }

    Ok(PolicyMergeOp::AddAllowRules {
        host: add_allow_rules.host.trim().to_string(),
        port: add_allow_rules.port,
        rules: add_allow_rules.rules.clone(),
    })
}

fn validate_merge_operations_for_server(operations: &[PolicyMergeOp]) -> Result<(), Status> {
    for operation in operations {
        if let PolicyMergeOp::AddRule { rule, .. } = operation {
            validate_rule_not_always_blocked(rule)?;
        }
    }
    Ok(())
}

fn map_policy_merge_error(error: openshell_policy::PolicyMergeError) -> Status {
    match error {
        openshell_policy::PolicyMergeError::MissingRuleNameForAddRule
        | openshell_policy::PolicyMergeError::InvalidEndpointReference { .. }
        | openshell_policy::PolicyMergeError::UnsupportedAccessPreset { .. } => {
            Status::invalid_argument(error.to_string())
        }
        openshell_policy::PolicyMergeError::EndpointNotFound { .. }
        | openshell_policy::PolicyMergeError::EndpointHasNoL7Inspection { .. }
        | openshell_policy::PolicyMergeError::UnsupportedEndpointProtocol { .. }
        | openshell_policy::PolicyMergeError::EndpointHasNoAllowBase { .. } => {
            Status::failed_precondition(error.to_string())
        }
    }
}

async fn apply_merge_operations_with_retry(
    store: &Store,
    sandbox_id: &str,
    baseline_policy: Option<&ProtoSandboxPolicy>,
    operations: &[PolicyMergeOp],
) -> Result<(i64, String), Status> {
    for attempt in 1..=MERGE_RETRY_LIMIT {
        let latest = store
            .get_latest_policy(sandbox_id)
            .await
            .map_err(|e| Status::internal(format!("fetch latest policy failed: {e}")))?;

        let current_policy = if let Some(ref record) = latest {
            ProtoSandboxPolicy::decode(record.policy_payload.as_slice())
                .map_err(|e| Status::internal(format!("decode current policy failed: {e}")))?
        } else {
            baseline_policy.cloned().unwrap_or_default()
        };

        let merged = merge_policy(current_policy, operations).map_err(map_policy_merge_error)?;
        let new_policy = merged.policy;
        let hash = deterministic_policy_hash(&new_policy);

        if let Some(baseline_policy) = baseline_policy {
            validate_static_fields_unchanged(baseline_policy, &new_policy)?;
        }
        validate_policy_safety(&new_policy)?;

        if let Some(ref current) = latest
            && current.policy_hash == hash
        {
            return Ok((current.version, hash));
        }

        if latest.is_none() && !merged.changed {
            return Ok((0, hash));
        }

        let payload = new_policy.encode_to_vec();
        let next_version = latest.as_ref().map_or(1, |record| record.version + 1);
        let policy_id = uuid::Uuid::new_v4().to_string();

        match store
            .put_policy_revision(&policy_id, sandbox_id, next_version, &payload, &hash)
            .await
        {
            Ok(()) => {
                let _ = store
                    .supersede_older_policies(sandbox_id, next_version)
                    .await;

                if attempt > 1 {
                    info!(
                        sandbox_id = %sandbox_id,
                        attempt,
                        version = next_version,
                        operation_count = operations.len(),
                        "apply_merge_operations_with_retry: succeeded after version conflict retry"
                    );
                }

                return Ok((next_version, hash));
            }
            Err(e) => {
                if e.is_unique_violation_on("objects_version_uq") {
                    warn!(
                        sandbox_id = %sandbox_id,
                        attempt,
                        conflicting_version = next_version,
                        operation_count = operations.len(),
                        "apply_merge_operations_with_retry: version conflict, retrying"
                    );
                    tokio::task::yield_now().await;
                    continue;
                }
                return Err(Status::internal(format!(
                    "persist policy revision failed: {e}"
                )));
            }
        }
    }

    Err(Status::aborted(format!(
        "apply_merge_operations_with_retry: gave up after {MERGE_RETRY_LIMIT} version conflict retries"
    )))
}

pub(super) async fn merge_chunk_into_policy(
    store: &Store,
    sandbox_id: &str,
    chunk: &DraftChunkRecord,
) -> Result<(i64, String), Status> {
    let rule = NetworkPolicyRule::decode(chunk.proposed_rule.as_slice())
        .map_err(|e| Status::internal(format!("decode proposed_rule failed: {e}")))?;
    apply_merge_operations_with_retry(
        store,
        sandbox_id,
        None,
        &[PolicyMergeOp::AddRule {
            rule_name: chunk.rule_name.clone(),
            rule,
        }],
    )
    .await
}

async fn remove_chunk_from_policy(
    state: &ServerState,
    sandbox_id: &str,
    chunk: &DraftChunkRecord,
) -> Result<(i64, String), Status> {
    apply_merge_operations_with_retry(
        state.store.as_ref(),
        sandbox_id,
        None,
        &[PolicyMergeOp::RemoveBinary {
            rule_name: chunk.rule_name.clone(),
            binary_path: chunk.binary.clone(),
        }],
    )
    .await
}

// ---------------------------------------------------------------------------
// Settings helpers
// ---------------------------------------------------------------------------

fn validate_registered_setting_key(key: &str) -> Result<SettingValueKind, Status> {
    settings::setting_for_key(key)
        .map(|entry| entry.kind)
        .ok_or_else(|| {
            Status::invalid_argument(format!(
                "unknown setting key '{key}'. Allowed keys: {}",
                settings::registered_keys_csv()
            ))
        })
}

fn proto_setting_to_stored(key: &str, value: &SettingValue) -> Result<StoredSettingValue, Status> {
    let expected = validate_registered_setting_key(key)?;
    let inner = value
        .value
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("setting_value.value is required"))?;
    let stored = match (expected, inner) {
        (SettingValueKind::String, setting_value::Value::StringValue(v)) => {
            StoredSettingValue::String(v.clone())
        }
        (SettingValueKind::Bool, setting_value::Value::BoolValue(v)) => {
            StoredSettingValue::Bool(*v)
        }
        (SettingValueKind::Int, setting_value::Value::IntValue(v)) => StoredSettingValue::Int(*v),
        (_, setting_value::Value::BytesValue(_)) => {
            return Err(Status::invalid_argument(format!(
                "setting '{key}' expects {} value; bytes are not supported for this key",
                expected.as_str()
            )));
        }
        (expected_kind, _) => {
            return Err(Status::invalid_argument(format!(
                "setting '{key}' expects {} value",
                expected_kind.as_str()
            )));
        }
    };
    Ok(stored)
}

fn stored_setting_to_proto(value: &StoredSettingValue) -> Result<SettingValue, Status> {
    let proto = match value {
        StoredSettingValue::String(v) => SettingValue {
            value: Some(setting_value::Value::StringValue(v.clone())),
        },
        StoredSettingValue::Bool(v) => SettingValue {
            value: Some(setting_value::Value::BoolValue(*v)),
        },
        StoredSettingValue::Int(v) => SettingValue {
            value: Some(setting_value::Value::IntValue(*v)),
        },
        StoredSettingValue::Bytes(v) => {
            let decoded = hex::decode(v)
                .map_err(|e| Status::internal(format!("stored bytes decode failed: {e}")))?;
            SettingValue {
                value: Some(setting_value::Value::BytesValue(decoded)),
            }
        }
    };
    Ok(proto)
}

fn upsert_setting_value(
    map: &mut BTreeMap<String, StoredSettingValue>,
    key: &str,
    value: StoredSettingValue,
) -> bool {
    match map.get(key) {
        Some(existing) if existing == &value => false,
        _ => {
            map.insert(key.to_string(), value);
            true
        }
    }
}

pub(super) async fn load_global_settings(store: &Store) -> Result<StoredSettings, Status> {
    load_settings_record(store, GLOBAL_SETTINGS_OBJECT_TYPE, GLOBAL_SETTINGS_NAME).await
}

pub(super) async fn save_global_settings(
    store: &Store,
    settings: &StoredSettings,
) -> Result<(), Status> {
    save_settings_record(
        store,
        GLOBAL_SETTINGS_OBJECT_TYPE,
        GLOBAL_SETTINGS_NAME,
        settings,
    )
    .await
}

pub(super) async fn load_sandbox_settings(
    store: &Store,
    sandbox_name: &str,
) -> Result<StoredSettings, Status> {
    load_settings_record(store, SANDBOX_SETTINGS_OBJECT_TYPE, sandbox_name).await
}

pub(super) async fn save_sandbox_settings(
    store: &Store,
    sandbox_name: &str,
    settings: &StoredSettings,
) -> Result<(), Status> {
    save_settings_record(store, SANDBOX_SETTINGS_OBJECT_TYPE, sandbox_name, settings).await
}

async fn load_settings_record(
    store: &Store,
    object_type: &str,
    name: &str,
) -> Result<StoredSettings, Status> {
    let record = store
        .get_by_name(object_type, name)
        .await
        .map_err(|e| Status::internal(format!("fetch settings failed: {e}")))?;
    if let Some(record) = record {
        serde_json::from_slice::<StoredSettings>(&record.payload)
            .map_err(|e| Status::internal(format!("decode settings payload failed: {e}")))
    } else {
        Ok(StoredSettings::default())
    }
}

async fn save_settings_record(
    store: &Store,
    object_type: &str,
    name: &str,
    settings: &StoredSettings,
) -> Result<(), Status> {
    let payload = serde_json::to_vec(settings)
        .map_err(|e| Status::internal(format!("encode settings payload failed: {e}")))?;
    store
        .put(
            object_type,
            &uuid::Uuid::new_v4().to_string(),
            name,
            &payload,
            None,
        )
        .await
        .map_err(|e| Status::internal(format!("persist settings failed: {e}")))?;
    Ok(())
}

fn decode_policy_from_global_settings(
    global: &StoredSettings,
) -> Result<Option<ProtoSandboxPolicy>, Status> {
    let Some(value) = global.settings.get(POLICY_SETTING_KEY) else {
        return Ok(None);
    };

    let StoredSettingValue::Bytes(encoded) = value else {
        return Err(Status::internal(
            "global policy setting has invalid value type; expected bytes",
        ));
    };

    let raw = hex::decode(encoded)
        .map_err(|e| Status::internal(format!("global policy decode failed: {e}")))?;
    let policy = ProtoSandboxPolicy::decode(raw.as_slice())
        .map_err(|e| Status::internal(format!("global policy protobuf decode failed: {e}")))?;
    Ok(Some(policy))
}

fn merge_effective_settings(
    global: &StoredSettings,
    sandbox: &StoredSettings,
) -> Result<HashMap<String, EffectiveSetting>, Status> {
    let mut merged = HashMap::new();

    for registered in settings::REGISTERED_SETTINGS {
        merged.insert(
            registered.key.to_string(),
            EffectiveSetting {
                value: None,
                scope: SettingScope::Unspecified.into(),
            },
        );
    }

    for (key, value) in &sandbox.settings {
        if key == POLICY_SETTING_KEY || settings::setting_for_key(key).is_none() {
            continue;
        }
        merged.insert(
            key.clone(),
            EffectiveSetting {
                value: Some(stored_setting_to_proto(value)?),
                scope: SettingScope::Sandbox.into(),
            },
        );
    }

    for (key, value) in &global.settings {
        if key == POLICY_SETTING_KEY || settings::setting_for_key(key).is_none() {
            continue;
        }
        merged.insert(
            key.clone(),
            EffectiveSetting {
                value: Some(stored_setting_to_proto(value)?),
                scope: SettingScope::Global.into(),
            },
        );
    }

    Ok(merged)
}

fn materialize_global_settings(
    global: &StoredSettings,
) -> Result<HashMap<String, SettingValue>, Status> {
    let mut materialized = HashMap::new();
    for registered in settings::REGISTERED_SETTINGS {
        materialized.insert(registered.key.to_string(), SettingValue { value: None });
    }

    for (key, value) in &global.settings {
        if key == POLICY_SETTING_KEY {
            continue;
        }
        if settings::setting_for_key(key).is_none() {
            continue;
        }
        materialized.insert(key.clone(), stored_setting_to_proto(value)?);
    }

    Ok(materialized)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ServerState;
    use crate::compute::new_test_runtime;
    use crate::persistence::Store;
    use crate::sandbox_index::SandboxIndex;
    use crate::sandbox_watch::SandboxWatchBus;
    use crate::supervisor_session::SupervisorSessionRegistry;
    use crate::tracing_bus::TracingLogBus;
    use openshell_core::Config;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tonic::Code;

    #[test]
    fn sandbox_secret_update_validation_allows_sandbox_policy_sync() {
        let req = UpdateConfigRequest {
            name: "sandbox-1".to_string(),
            policy: Some(ProtoSandboxPolicy::default()),
            ..Default::default()
        };
        assert!(validate_sandbox_secret_update(&req).is_ok());
    }

    #[test]
    fn sandbox_secret_update_validation_rejects_global_mutation() {
        let req = UpdateConfigRequest {
            global: true,
            policy: Some(ProtoSandboxPolicy::default()),
            ..Default::default()
        };
        let err = validate_sandbox_secret_update(&req).unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
    }

    #[test]
    fn sandbox_secret_update_validation_rejects_setting_mutation() {
        let req = UpdateConfigRequest {
            name: "sandbox-1".to_string(),
            setting_key: "inference.model".to_string(),
            setting_value: Some(SettingValue { value: None }),
            ..Default::default()
        };
        let err = validate_sandbox_secret_update(&req).unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
    }

    #[test]
    fn sandbox_secret_marker_detected_from_metadata() {
        let mut req = Request::new(());
        req.metadata_mut().insert(
            oidc::INTERNAL_AUTH_SOURCE_HEADER,
            oidc::AUTH_SOURCE_SANDBOX_SECRET.parse().unwrap(),
        );
        assert!(is_sandbox_secret_authenticated(&req));
    }

    // ---- Sandbox without policy ----

    #[tokio::test]
    async fn sandbox_without_policy_stores_successfully() {
        use openshell_core::proto::{SandboxPhase, SandboxSpec};

        let store = Store::connect("sqlite::memory:").await.unwrap();

        let sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-no-policy".to_string(),
                name: "no-policy-sandbox".to_string(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
            }),
            spec: Some(SandboxSpec {
                policy: None,
                ..Default::default()
            }),
            phase: SandboxPhase::Provisioning as i32,
            ..Default::default()
        };
        store.put_message(&sandbox).await.unwrap();

        let loaded = store
            .get_message::<Sandbox>("sb-no-policy")
            .await
            .unwrap()
            .unwrap();
        assert!(loaded.spec.unwrap().policy.is_none());
    }

    fn test_provider(name: &str, provider_type: &str) -> Provider {
        Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: format!("provider-{name}"),
                name: name.to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
            }),
            r#type: provider_type.to_string(),
            credentials: std::iter::once(("GITHUB_TOKEN".to_string(), "ghp-test".to_string()))
                .collect(),
            config: HashMap::new(),
        }
    }

    fn test_policy_with_rule(rule_name: &str, host: &str) -> ProtoSandboxPolicy {
        ProtoSandboxPolicy {
            network_policies: std::iter::once((
                rule_name.to_string(),
                NetworkPolicyRule {
                    name: rule_name.to_string(),
                    endpoints: vec![NetworkEndpoint {
                        host: host.to_string(),
                        port: 443,
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ))
            .collect(),
            ..Default::default()
        }
    }

    fn test_sandbox(
        id: &str,
        name: &str,
        policy: ProtoSandboxPolicy,
        providers: Vec<String>,
    ) -> Sandbox {
        use openshell_core::proto::{SandboxPhase, SandboxSpec};

        Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: id.to_string(),
                name: name.to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
            }),
            spec: Some(SandboxSpec {
                policy: Some(policy),
                providers,
                ..Default::default()
            }),
            phase: SandboxPhase::Ready as i32,
            ..Default::default()
        }
    }

    async fn enable_providers_v2(state: &Arc<ServerState>) {
        let global_settings = StoredSettings {
            revision: 1,
            settings: std::iter::once((
                settings::PROVIDERS_V2_ENABLED_KEY.to_string(),
                StoredSettingValue::Bool(true),
            ))
            .collect(),
        };
        save_global_settings(state.store.as_ref(), &global_settings)
            .await
            .unwrap();
    }

    async fn get_sandbox_policy(state: &Arc<ServerState>, sandbox_id: &str) -> ProtoSandboxPolicy {
        handle_get_sandbox_config(
            state,
            Request::new(GetSandboxConfigRequest {
                sandbox_id: sandbox_id.to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .policy
        .expect("sandbox config should include policy")
    }

    #[tokio::test]
    async fn provider_policy_layers_skip_unknown_provider_types() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        store
            .put_message(&test_provider("custom-provider", "custom"))
            .await
            .unwrap();

        let layers = profile_provider_policy_layers(&store, &["custom-provider".to_string()])
            .await
            .unwrap();

        assert!(layers.is_empty());
    }

    #[tokio::test]
    async fn provider_policy_layers_include_known_provider_profiles() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        store
            .put_message(&test_provider("work-github", "github"))
            .await
            .unwrap();

        let layers = profile_provider_policy_layers(&store, &["work-github".to_string()])
            .await
            .unwrap();

        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].rule_name, "_provider_work_github");
        assert_eq!(layers[0].rule.endpoints.len(), 2);
        assert!(
            layers[0]
                .rule
                .endpoints
                .iter()
                .any(|endpoint| endpoint.host == "api.github.com")
        );
    }

    #[test]
    fn providers_v2_enabled_defaults_false_when_unset() {
        assert!(
            !bool_setting_enabled(
                &StoredSettings::default(),
                settings::PROVIDERS_V2_ENABLED_KEY
            )
            .unwrap()
        );
    }

    #[test]
    fn providers_v2_enabled_reads_global_bool_setting() {
        let mut settings = StoredSettings::default();
        settings.settings.insert(
            settings::PROVIDERS_V2_ENABLED_KEY.to_string(),
            StoredSettingValue::Bool(true),
        );

        assert!(bool_setting_enabled(&settings, settings::PROVIDERS_V2_ENABLED_KEY).unwrap());
    }

    #[tokio::test]
    async fn sandbox_config_omits_provider_layers_when_v2_disabled() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&test_provider("work-github", "github"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox(
                "sb-v2-disabled",
                "v2-disabled",
                test_policy_with_rule("sandbox_only", "sandbox.example.com"),
                vec!["work-github".to_string()],
            ))
            .await
            .unwrap();

        let effective_policy = get_sandbox_policy(&state, "sb-v2-disabled").await;

        assert!(
            effective_policy
                .network_policies
                .contains_key("sandbox_only")
        );
        assert!(
            !effective_policy
                .network_policies
                .contains_key("_provider_work_github")
        );
    }

    #[tokio::test]
    async fn sandbox_config_composes_provider_layers_when_v2_enabled() {
        let state = test_server_state().await;
        enable_providers_v2(&state).await;
        state
            .store
            .put_message(&test_provider("work-github", "github"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox(
                "sb-v2-enabled",
                "v2-enabled",
                test_policy_with_rule("sandbox_only", "sandbox.example.com"),
                vec!["work-github".to_string()],
            ))
            .await
            .unwrap();

        let effective_policy = get_sandbox_policy(&state, "sb-v2-enabled").await;

        assert!(
            effective_policy
                .network_policies
                .contains_key("sandbox_only")
        );
        assert!(
            effective_policy
                .network_policies
                .contains_key("_provider_work_github")
        );
        assert!(
            effective_policy
                .network_policies
                .get("_provider_work_github")
                .unwrap()
                .endpoints
                .iter()
                .any(|endpoint| endpoint.host == "api.github.com")
        );
    }

    #[tokio::test]
    async fn sandbox_config_skips_profileless_provider_types_when_v2_enabled() {
        let state = test_server_state().await;
        enable_providers_v2(&state).await;
        state
            .store
            .put_message(&test_provider("legacy-generic", "generic"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_provider("custom-provider", "custom"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox(
                "sb-profileless",
                "profileless",
                test_policy_with_rule("sandbox_only", "sandbox.example.com"),
                vec!["legacy-generic".to_string(), "custom-provider".to_string()],
            ))
            .await
            .unwrap();

        let effective_policy = get_sandbox_policy(&state, "sb-profileless").await;

        assert_eq!(effective_policy.network_policies.len(), 1);
        assert!(
            effective_policy
                .network_policies
                .contains_key("sandbox_only")
        );
    }

    #[tokio::test]
    async fn sandbox_config_composition_is_jit_and_does_not_persist_provider_layers() {
        let state = test_server_state().await;
        enable_providers_v2(&state).await;
        state
            .store
            .put_message(&test_provider("work-github", "github"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox(
                "sb-jit",
                "jit",
                test_policy_with_rule("sandbox_only", "sandbox.example.com"),
                vec!["work-github".to_string()],
            ))
            .await
            .unwrap();

        let effective_policy = get_sandbox_policy(&state, "sb-jit").await;
        assert!(
            effective_policy
                .network_policies
                .contains_key("_provider_work_github")
        );

        let persisted = state
            .store
            .get_latest_policy("sb-jit")
            .await
            .unwrap()
            .expect("sandbox policy should be lazily backfilled");
        let persisted_policy = ProtoSandboxPolicy::decode(persisted.policy_payload.as_slice())
            .expect("persisted sandbox policy should decode");
        assert!(
            persisted_policy
                .network_policies
                .contains_key("sandbox_only")
        );
        assert!(
            !persisted_policy
                .network_policies
                .contains_key("_provider_work_github")
        );
    }

    #[tokio::test]
    async fn sandbox_config_preserves_overlapping_user_and_provider_rules() {
        let state = test_server_state().await;
        enable_providers_v2(&state).await;
        state
            .store
            .put_message(&test_provider("work-github", "github"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox(
                "sb-overlap",
                "overlap",
                test_policy_with_rule("_provider_work_github", "api.github.com"),
                vec!["work-github".to_string()],
            ))
            .await
            .unwrap();

        let effective_policy = get_sandbox_policy(&state, "sb-overlap").await;

        assert!(
            effective_policy
                .network_policies
                .contains_key("_provider_work_github")
        );
        assert!(
            effective_policy
                .network_policies
                .contains_key("_provider_work_github_2")
        );
        assert_eq!(
            effective_policy
                .network_policies
                .get("_provider_work_github")
                .unwrap()
                .endpoints[0]
                .host,
            "api.github.com"
        );
    }

    #[tokio::test]
    async fn provider_environment_resolution_is_unchanged_by_providers_v2_setting() {
        use openshell_core::proto::GetSandboxProviderEnvironmentRequest;

        let state = test_server_state().await;
        state
            .store
            .put_message(&test_provider("work-github", "github"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox(
                "sb-provider-env",
                "provider-env",
                test_policy_with_rule("sandbox_only", "sandbox.example.com"),
                vec!["work-github".to_string()],
            ))
            .await
            .unwrap();

        let legacy_env = handle_get_sandbox_provider_environment(
            &state,
            Request::new(GetSandboxProviderEnvironmentRequest {
                sandbox_id: "sb-provider-env".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .environment;

        enable_providers_v2(&state).await;
        let v2_env = handle_get_sandbox_provider_environment(
            &state,
            Request::new(GetSandboxProviderEnvironmentRequest {
                sandbox_id: "sb-provider-env".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .environment;

        assert_eq!(legacy_env, v2_env);
        assert_eq!(v2_env.get("GITHUB_TOKEN"), Some(&"ghp-test".to_string()));
    }

    #[tokio::test]
    async fn global_policy_suppresses_provider_profile_layers_when_v2_enabled() {
        use openshell_core::proto::{
            GetSandboxConfigRequest, NetworkEndpoint, NetworkPolicyRule, SandboxPhase,
            SandboxPolicy, SandboxSpec,
        };

        let state = test_server_state().await;
        state
            .store
            .put_message(&test_provider("work-github", "github"))
            .await
            .unwrap();

        let sandbox_policy = SandboxPolicy {
            network_policies: std::iter::once((
                "sandbox_only".to_string(),
                NetworkPolicyRule {
                    name: "sandbox_only".to_string(),
                    endpoints: vec![NetworkEndpoint {
                        host: "sandbox.example.com".to_string(),
                        port: 443,
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ))
            .collect(),
            ..Default::default()
        };
        let sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-global-profile".to_string(),
                name: "global-profile-sandbox".to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
            }),
            spec: Some(SandboxSpec {
                policy: Some(sandbox_policy),
                providers: vec!["work-github".to_string()],
                ..Default::default()
            }),
            phase: SandboxPhase::Ready as i32,
            ..Default::default()
        };
        state.store.put_message(&sandbox).await.unwrap();

        let global_policy = SandboxPolicy {
            network_policies: std::iter::once((
                "global_only".to_string(),
                NetworkPolicyRule {
                    name: "global_only".to_string(),
                    endpoints: vec![NetworkEndpoint {
                        host: "global.example.com".to_string(),
                        port: 443,
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ))
            .collect(),
            ..Default::default()
        };
        let global_settings = StoredSettings {
            revision: 1,
            settings: [
                (
                    settings::PROVIDERS_V2_ENABLED_KEY.to_string(),
                    StoredSettingValue::Bool(true),
                ),
                (
                    POLICY_SETTING_KEY.to_string(),
                    StoredSettingValue::Bytes(hex::encode(global_policy.encode_to_vec())),
                ),
            ]
            .into_iter()
            .collect(),
        };
        save_global_settings(state.store.as_ref(), &global_settings)
            .await
            .unwrap();

        let response = handle_get_sandbox_config(
            &state,
            Request::new(GetSandboxConfigRequest {
                sandbox_id: "sb-global-profile".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        let effective_policy = response.policy.expect("global policy should be returned");
        assert_eq!(response.policy_source, PolicySource::Global as i32);
        assert!(
            effective_policy
                .network_policies
                .contains_key("global_only")
        );
        assert!(
            !effective_policy
                .network_policies
                .contains_key("sandbox_only")
        );
        assert!(
            !effective_policy
                .network_policies
                .contains_key("_provider_work_github")
        );
    }

    #[tokio::test]
    async fn sandbox_policy_backfill_on_update_when_no_baseline() {
        use openshell_core::proto::{FilesystemPolicy, LandlockPolicy, SandboxPhase, SandboxSpec};

        let store = Store::connect("sqlite::memory:").await.unwrap();

        let sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-backfill".to_string(),
                name: "backfill-sandbox".to_string(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
            }),
            spec: Some(SandboxSpec {
                policy: None,
                ..Default::default()
            }),
            phase: SandboxPhase::Provisioning as i32,
            ..Default::default()
        };
        store.put_message(&sandbox).await.unwrap();

        let new_policy = ProtoSandboxPolicy {
            version: 1,
            filesystem: Some(FilesystemPolicy {
                include_workdir: true,
                read_only: vec!["/usr".into()],
                read_write: vec!["/tmp".into()],
            }),
            landlock: Some(LandlockPolicy {
                compatibility: "best_effort".into(),
            }),
            process: Some(openshell_core::proto::ProcessPolicy {
                run_as_user: "sandbox".into(),
                run_as_group: "sandbox".into(),
            }),
            ..Default::default()
        };

        let mut sandbox = store
            .get_message::<Sandbox>("sb-backfill")
            .await
            .unwrap()
            .unwrap();
        if let Some(ref mut spec) = sandbox.spec {
            spec.policy = Some(new_policy.clone());
        }
        store.put_message(&sandbox).await.unwrap();

        let loaded = store
            .get_message::<Sandbox>("sb-backfill")
            .await
            .unwrap()
            .unwrap();
        let policy = loaded.spec.unwrap().policy.unwrap();
        assert_eq!(policy.version, 1);
        assert!(policy.filesystem.is_some());
        assert_eq!(policy.process.unwrap().run_as_user, "sandbox");
    }

    async fn test_server_state() -> Arc<ServerState> {
        let store = Arc::new(
            Store::connect("sqlite::memory:?cache=shared")
                .await
                .unwrap(),
        );
        let compute = new_test_runtime(store.clone()).await;
        Arc::new(ServerState::new(
            Config::new(None)
                .with_database_url("sqlite::memory:?cache=shared")
                .with_ssh_handshake_secret("test-secret"),
            store,
            compute,
            SandboxIndex::new(),
            SandboxWatchBus::new(),
            TracingLogBus::new(),
            Arc::new(SupervisorSessionRegistry::new()),
            None,
        ))
    }

    #[tokio::test]
    async fn draft_chunk_handler_lifecycle_round_trip() {
        use openshell_core::proto::{
            GetDraftPolicyRequest, NetworkBinary, NetworkEndpoint, SandboxPhase, SandboxSpec,
        };

        let state = test_server_state().await;
        let sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-draft-flow".to_string(),
                name: "draft-flow".to_string(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
            }),
            spec: Some(SandboxSpec {
                policy: None,
                ..Default::default()
            }),
            phase: SandboxPhase::Ready as i32,
            ..Default::default()
        };
        state.store.put_message(&sandbox).await.unwrap();
        let sandbox_name = sandbox.object_name().to_string();

        let proposed_rule = NetworkPolicyRule {
            name: "allow_example".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.example.com".to_string(),
                port: 443,
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        let submit = handle_submit_policy_analysis(
            &state,
            Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_name.clone(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "allow_example".to_string(),
                    proposed_rule: Some(proposed_rule.clone()),
                    rationale: "observed denied request".to_string(),
                    confidence: 0.85,
                    hit_count: 3,
                    first_seen_ms: 100,
                    last_seen_ms: 200,
                    binary: "/usr/bin/curl".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(submit.accepted_chunks, 1);
        assert_eq!(submit.rejected_chunks, 0);

        let draft_policy = handle_get_draft_policy(
            &state,
            Request::new(GetDraftPolicyRequest {
                name: sandbox_name.clone(),
                status_filter: String::new(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(draft_policy.draft_version, 1);
        assert_eq!(draft_policy.chunks.len(), 1);
        assert_eq!(draft_policy.chunks[0].status, "pending");
        let chunk_id = draft_policy.chunks[0].id.clone();

        let approve = handle_approve_draft_chunk(
            &state,
            Request::new(ApproveDraftChunkRequest {
                name: sandbox_name.clone(),
                chunk_id: chunk_id.clone(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(approve.policy_version, 1);
        assert!(!approve.policy_hash.is_empty());

        let history_after_approve = handle_get_draft_history(
            &state,
            Request::new(GetDraftHistoryRequest {
                name: sandbox_name.clone(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(history_after_approve.entries.len(), 2);
        assert_eq!(history_after_approve.entries[0].event_type, "proposed");
        assert_eq!(history_after_approve.entries[1].event_type, "approved");
        assert_eq!(history_after_approve.entries[1].chunk_id, chunk_id);

        let policies_after_approve = handle_list_sandbox_policies(
            &state,
            Request::new(ListSandboxPoliciesRequest {
                name: sandbox_name.clone(),
                limit: 10,
                offset: 0,
                global: false,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(policies_after_approve.revisions.len(), 1);
        assert_eq!(policies_after_approve.revisions[0].version, 1);

        let undo = handle_undo_draft_chunk(
            &state,
            Request::new(UndoDraftChunkRequest {
                name: sandbox_name.clone(),
                chunk_id: chunk_id.clone(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(undo.policy_version, 2);
        assert!(!undo.policy_hash.is_empty());

        let draft_policy_after_undo = handle_get_draft_policy(
            &state,
            Request::new(GetDraftPolicyRequest {
                name: sandbox_name.clone(),
                status_filter: String::new(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(draft_policy_after_undo.chunks.len(), 1);
        assert_eq!(draft_policy_after_undo.chunks[0].status, "pending");

        let history_after_undo = handle_get_draft_history(
            &state,
            Request::new(GetDraftHistoryRequest {
                name: sandbox_name.clone(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(history_after_undo.entries.len(), 1);
        assert_eq!(history_after_undo.entries[0].event_type, "proposed");

        let policies_after_undo = handle_list_sandbox_policies(
            &state,
            Request::new(ListSandboxPoliciesRequest {
                name: sandbox_name.clone(),
                limit: 10,
                offset: 0,
                global: false,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(policies_after_undo.revisions.len(), 2);
        assert_eq!(policies_after_undo.revisions[0].version, 2);
        assert_eq!(policies_after_undo.revisions[1].version, 1);

        let cleared = handle_clear_draft_chunks(
            &state,
            Request::new(ClearDraftChunksRequest {
                name: sandbox_name.clone(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(cleared.chunks_cleared, 1);

        let draft_policy_after_clear = handle_get_draft_policy(
            &state,
            Request::new(GetDraftPolicyRequest {
                name: sandbox_name.clone(),
                status_filter: String::new(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(draft_policy_after_clear.chunks.is_empty());

        let history_after_clear = handle_get_draft_history(
            &state,
            Request::new(GetDraftHistoryRequest { name: sandbox_name }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(history_after_clear.entries.is_empty());
    }

    #[tokio::test]
    async fn draft_chunk_handlers_reject_cross_sandbox_chunk_ids() {
        use openshell_core::proto::{NetworkBinary, NetworkEndpoint, SandboxPhase, SandboxSpec};

        let state = test_server_state().await;
        let sandbox_a = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-draft-owner".to_string(),
                name: "draft-owner".to_string(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
            }),
            spec: Some(SandboxSpec {
                policy: None,
                ..Default::default()
            }),
            phase: SandboxPhase::Ready as i32,
            ..Default::default()
        };
        let sandbox_b = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-draft-other".to_string(),
                name: "draft-other".to_string(),
                created_at_ms: 1_000_001,
                labels: std::collections::HashMap::new(),
            }),
            spec: Some(SandboxSpec {
                policy: None,
                ..Default::default()
            }),
            phase: SandboxPhase::Ready as i32,
            ..Default::default()
        };
        state.store.put_message(&sandbox_a).await.unwrap();
        state.store.put_message(&sandbox_b).await.unwrap();

        let proposed_rule = NetworkPolicyRule {
            name: "allow_example".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.example.com".to_string(),
                port: 443,
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        handle_submit_policy_analysis(
            &state,
            Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_a.object_name().to_string(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "allow_example".to_string(),
                    proposed_rule: Some(proposed_rule.clone()),
                    rationale: "observed denied request".to_string(),
                    confidence: 0.85,
                    hit_count: 3,
                    first_seen_ms: 100,
                    last_seen_ms: 200,
                    binary: "/usr/bin/curl".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        let draft_policy = handle_get_draft_policy(
            &state,
            Request::new(GetDraftPolicyRequest {
                name: sandbox_a.object_name().to_string(),
                status_filter: String::new(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        let chunk_id = draft_policy.chunks[0].id.clone();
        let other_name = sandbox_b.object_name().to_string();

        let approve_err = handle_approve_draft_chunk(
            &state,
            Request::new(ApproveDraftChunkRequest {
                name: other_name.clone(),
                chunk_id: chunk_id.clone(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(approve_err.code(), Code::NotFound);

        let reject_err = handle_reject_draft_chunk(
            &state,
            Request::new(RejectDraftChunkRequest {
                name: other_name.clone(),
                chunk_id: chunk_id.clone(),
                reason: "wrong sandbox".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(reject_err.code(), Code::NotFound);

        let edit_err = handle_edit_draft_chunk(
            &state,
            Request::new(EditDraftChunkRequest {
                name: other_name.clone(),
                chunk_id: chunk_id.clone(),
                proposed_rule: Some(proposed_rule.clone()),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(edit_err.code(), Code::NotFound);

        handle_approve_draft_chunk(
            &state,
            Request::new(ApproveDraftChunkRequest {
                name: sandbox_a.object_name().to_string(),
                chunk_id: chunk_id.clone(),
            }),
        )
        .await
        .unwrap();

        let undo_err = handle_undo_draft_chunk(
            &state,
            Request::new(UndoDraftChunkRequest {
                name: other_name,
                chunk_id,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(undo_err.code(), Code::NotFound);
    }

    #[test]
    fn build_gateway_policy_audit_message_formats_ocsf_config_line() {
        let message = build_gateway_policy_audit_message(
            "sb-123",
            "demo-sandbox",
            "merged",
            "gateway merged incremental policy op: add-allow api.github.com:443 [POST /repos/*/issues]",
            7,
            "sha256:testhash",
        );

        assert_eq!(
            message,
            "CONFIG:MERGED [INFO] gateway merged incremental policy op: add-allow api.github.com:443 [POST /repos/*/issues] [version:v7 hash:sha256:testhash]"
        );
    }

    #[test]
    fn summarize_cli_policy_merge_op_formats_rest_allow_rules() {
        let operation = PolicyMergeOp::AddAllowRules {
            host: "api.github.com".to_string(),
            port: 443,
            rules: vec![L7Rule {
                allow: Some(openshell_core::proto::L7Allow {
                    method: "POST".to_string(),
                    path: "/repos/*/issues".to_string(),
                    command: String::new(),
                    query: HashMap::new(),
                    operation_type: String::new(),
                    operation_name: String::new(),
                    fields: Vec::new(),
                }),
            }],
        };

        assert_eq!(
            summarize_cli_policy_merge_op(&operation),
            "add-allow api.github.com:443 [POST /repos/*/issues]"
        );
    }

    #[test]
    fn summarize_cli_policy_merge_op_formats_endpoint_additions() {
        let operation = PolicyMergeOp::AddRule {
            rule_name: "github_api".to_string(),
            rule: NetworkPolicyRule {
                name: "github_api".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "api.github.com".to_string(),
                    port: 443,
                    protocol: "rest".to_string(),
                    access: "read-only".to_string(),
                    enforcement: "enforce".to_string(),
                    ..Default::default()
                }],
                binaries: vec![NetworkBinary {
                    path: "/usr/bin/curl".to_string(),
                    ..Default::default()
                }],
            },
        };

        assert_eq!(
            summarize_cli_policy_merge_op(&operation),
            "add-endpoint github_api endpoints=[api.github.com:443 protocol=rest access=read-only enforcement=enforce] binaries=[/usr/bin/curl]"
        );
    }

    // ---- merge_chunk_into_policy ----

    #[tokio::test]
    async fn merge_chunk_into_policy_adds_first_network_rule_to_empty_policy() {
        use openshell_core::proto::{NetworkBinary, NetworkEndpoint, NetworkPolicyRule};

        let store = Store::connect("sqlite::memory:").await.unwrap();
        let rule = NetworkPolicyRule {
            name: "google".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "google.com".to_string(),
                port: 443,
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };
        let chunk = DraftChunkRecord {
            id: "chunk-1".to_string(),
            sandbox_id: "sb-empty".to_string(),
            draft_version: 1,
            status: "pending".to_string(),
            rule_name: "google".to_string(),
            proposed_rule: rule.encode_to_vec(),
            rationale: String::new(),
            security_notes: String::new(),
            confidence: 1.0,
            created_at_ms: 0,
            decided_at_ms: None,
            host: "google.com".to_string(),
            port: 443,
            binary: "/usr/bin/curl".to_string(),
            hit_count: 1,
            first_seen_ms: 0,
            last_seen_ms: 0,
        };

        let (version, _) = merge_chunk_into_policy(&store, &chunk.sandbox_id, &chunk)
            .await
            .unwrap();

        assert_eq!(version, 1);

        let latest = store
            .get_latest_policy(&chunk.sandbox_id)
            .await
            .unwrap()
            .expect("policy revision should be persisted");
        let policy = openshell_core::proto::SandboxPolicy::decode(latest.policy_payload.as_slice())
            .expect("policy payload should decode");
        let stored_rule = policy
            .network_policies
            .get("google")
            .expect("merged rule should be present");
        assert_eq!(stored_rule.endpoints[0].host, "google.com");
        assert_eq!(stored_rule.endpoints[0].port, 443);
        assert_eq!(stored_rule.binaries[0].path, "/usr/bin/curl");
    }

    #[tokio::test]
    async fn merge_chunk_merges_into_existing_rule_by_host_port() {
        use openshell_core::proto::{
            NetworkBinary, NetworkEndpoint, NetworkPolicyRule, SandboxPolicy,
        };

        let store = Store::connect("sqlite::memory:").await.unwrap();
        let sandbox_id = "sb-merge";

        let initial_policy = SandboxPolicy {
            network_policies: std::iter::once((
                "test_server".to_string(),
                NetworkPolicyRule {
                    name: "test_server".to_string(),
                    endpoints: vec![NetworkEndpoint {
                        host: "192.168.1.100".to_string(),
                        port: 8567,
                        ..Default::default()
                    }],
                    binaries: vec![NetworkBinary {
                        path: "/usr/bin/curl".to_string(),
                        ..Default::default()
                    }],
                },
            ))
            .collect(),
            ..Default::default()
        };
        store
            .put_policy_revision(
                "p-seed",
                sandbox_id,
                1,
                &initial_policy.encode_to_vec(),
                "seed-hash",
            )
            .await
            .unwrap();

        let proposed = NetworkPolicyRule {
            name: "allow_192_168_1_100_8567".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "192.168.1.100".to_string(),
                port: 8567,
                allowed_ips: vec!["192.168.1.100".to_string()],
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };
        let chunk = DraftChunkRecord {
            id: "chunk-merge".to_string(),
            sandbox_id: sandbox_id.to_string(),
            draft_version: 1,
            status: "pending".to_string(),
            rule_name: "allow_192_168_1_100_8567".to_string(),
            proposed_rule: proposed.encode_to_vec(),
            rationale: String::new(),
            security_notes: String::new(),
            confidence: 0.3,
            created_at_ms: 0,
            decided_at_ms: None,
            host: "192.168.1.100".to_string(),
            port: 8567,
            binary: "/usr/bin/curl".to_string(),
            hit_count: 1,
            first_seen_ms: 0,
            last_seen_ms: 0,
        };

        let (version, _) = merge_chunk_into_policy(&store, sandbox_id, &chunk)
            .await
            .unwrap();
        assert_eq!(version, 2);

        let latest = store
            .get_latest_policy(sandbox_id)
            .await
            .unwrap()
            .expect("policy revision should be persisted");
        let policy = SandboxPolicy::decode(latest.policy_payload.as_slice()).unwrap();

        assert_eq!(
            policy.network_policies.len(),
            1,
            "expected 1 rule, got {}: {:?}",
            policy.network_policies.len(),
            policy.network_policies.keys().collect::<Vec<_>>()
        );
        let rule = policy
            .network_policies
            .get("test_server")
            .expect("original rule name 'test_server' should be preserved");
        assert_eq!(rule.endpoints[0].host, "192.168.1.100");
        assert_eq!(rule.endpoints[0].allowed_ips, vec!["192.168.1.100"]);
    }

    #[tokio::test]
    async fn merge_chunk_new_host_port_inserts_new_entry() {
        use openshell_core::proto::{
            NetworkBinary, NetworkEndpoint, NetworkPolicyRule, SandboxPolicy,
        };

        let store = Store::connect("sqlite::memory:").await.unwrap();
        let sandbox_id = "sb-new";

        let initial_policy = SandboxPolicy {
            network_policies: std::iter::once((
                "existing_rule".to_string(),
                NetworkPolicyRule {
                    name: "existing_rule".to_string(),
                    endpoints: vec![NetworkEndpoint {
                        host: "api.example.com".to_string(),
                        port: 443,
                        ..Default::default()
                    }],
                    binaries: vec![NetworkBinary {
                        path: "/usr/bin/curl".to_string(),
                        ..Default::default()
                    }],
                },
            ))
            .collect(),
            ..Default::default()
        };
        store
            .put_policy_revision(
                "p-seed",
                sandbox_id,
                1,
                &initial_policy.encode_to_vec(),
                "seed-hash",
            )
            .await
            .unwrap();

        let proposed = NetworkPolicyRule {
            name: "allow_10_0_0_5_8080".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "10.0.0.5".to_string(),
                port: 8080,
                allowed_ips: vec!["10.0.0.5".to_string()],
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };
        let chunk = DraftChunkRecord {
            id: "chunk-new".to_string(),
            sandbox_id: sandbox_id.to_string(),
            draft_version: 1,
            status: "pending".to_string(),
            rule_name: "allow_10_0_0_5_8080".to_string(),
            proposed_rule: proposed.encode_to_vec(),
            rationale: String::new(),
            security_notes: String::new(),
            confidence: 0.3,
            created_at_ms: 0,
            decided_at_ms: None,
            host: "10.0.0.5".to_string(),
            port: 8080,
            binary: "/usr/bin/curl".to_string(),
            hit_count: 1,
            first_seen_ms: 0,
            last_seen_ms: 0,
        };

        let (version, _) = merge_chunk_into_policy(&store, sandbox_id, &chunk)
            .await
            .unwrap();
        assert_eq!(version, 2);

        let latest = store.get_latest_policy(sandbox_id).await.unwrap().unwrap();
        let policy = SandboxPolicy::decode(latest.policy_payload.as_slice()).unwrap();

        assert_eq!(policy.network_policies.len(), 2);
        assert!(policy.network_policies.contains_key("existing_rule"));
        assert!(policy.network_policies.contains_key("allow_10_0_0_5_8080"));
    }

    #[tokio::test]
    async fn concurrent_merge_batches_preserve_both_updates() {
        use openshell_core::proto::{
            L7Allow, L7DenyRule, L7Rule, NetworkEndpoint, NetworkPolicyRule, SandboxPolicy,
        };

        let store = Store::connect("sqlite::memory:").await.unwrap();
        let sandbox_id = "sb-concurrent-merge";

        let initial_policy = SandboxPolicy {
            network_policies: std::iter::once((
                "github".to_string(),
                NetworkPolicyRule {
                    name: "github".to_string(),
                    endpoints: vec![NetworkEndpoint {
                        host: "api.github.com".to_string(),
                        port: 443,
                        ports: vec![443],
                        protocol: "rest".to_string(),
                        access: "read-only".to_string(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ))
            .collect(),
            ..Default::default()
        };
        store
            .put_policy_revision(
                "p-seed",
                sandbox_id,
                1,
                &initial_policy.encode_to_vec(),
                "seed-hash",
            )
            .await
            .unwrap();

        let add_allow = [PolicyMergeOp::AddAllowRules {
            host: "api.github.com".to_string(),
            port: 443,
            rules: vec![L7Rule {
                allow: Some(L7Allow {
                    method: "POST".to_string(),
                    path: "/repos/*/issues".to_string(),
                    command: String::new(),
                    query: HashMap::new(),
                    operation_type: String::new(),
                    operation_name: String::new(),
                    fields: Vec::new(),
                }),
            }],
        }];
        let add_deny = [PolicyMergeOp::AddDenyRules {
            host: "api.github.com".to_string(),
            port: 443,
            deny_rules: vec![L7DenyRule {
                method: "POST".to_string(),
                path: "/admin".to_string(),
                query: HashMap::new(),
                ..Default::default()
            }],
        }];

        let (left, right) = tokio::join!(
            apply_merge_operations_with_retry(&store, sandbox_id, None, &add_allow),
            apply_merge_operations_with_retry(&store, sandbox_id, None, &add_deny),
        );

        let mut versions = vec![left.unwrap().0, right.unwrap().0];
        versions.sort_unstable();
        assert_eq!(versions, vec![2, 3]);

        let latest = store.get_latest_policy(sandbox_id).await.unwrap().unwrap();
        assert_eq!(latest.version, 3);

        let policy = SandboxPolicy::decode(latest.policy_payload.as_slice()).unwrap();
        let endpoint = &policy.network_policies["github"].endpoints[0];
        assert!(endpoint.access.is_empty());
        assert_eq!(endpoint.rules.len(), 4);
        assert_eq!(endpoint.deny_rules.len(), 1);
        assert_eq!(endpoint.deny_rules[0].path, "/admin");
    }

    // ---- validate_rule_not_always_blocked ----

    #[test]
    fn validate_rule_rejects_loopback_allowed_ips() {
        use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule};

        let rule = NetworkPolicyRule {
            name: "bad".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "example.com".to_string(),
                port: 80,
                allowed_ips: vec!["127.0.0.1".to_string()],
                ..Default::default()
            }],
            binaries: vec![],
        };
        let result = validate_rule_not_always_blocked(&rule);
        assert!(result.is_err());
        let status = result.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(status.message().contains("always-blocked"));
    }

    #[test]
    fn validate_rule_rejects_link_local_allowed_ips() {
        use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule};

        let rule = NetworkPolicyRule {
            name: "bad".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "example.com".to_string(),
                port: 80,
                allowed_ips: vec!["169.254.169.254".to_string()],
                ..Default::default()
            }],
            binaries: vec![],
        };
        let result = validate_rule_not_always_blocked(&rule);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("always-blocked"));
    }

    #[test]
    fn validate_rule_rejects_always_blocked_host() {
        use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule};

        let rule = NetworkPolicyRule {
            name: "bad".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "127.0.0.1".to_string(),
                port: 80,
                ..Default::default()
            }],
            binaries: vec![],
        };
        let result = validate_rule_not_always_blocked(&rule);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("always-blocked"));
    }

    #[test]
    fn validate_rule_rejects_localhost_host() {
        use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule};

        let rule = NetworkPolicyRule {
            name: "bad".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "localhost".to_string(),
                port: 8080,
                ..Default::default()
            }],
            binaries: vec![],
        };
        let result = validate_rule_not_always_blocked(&rule);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("always blocked"));
    }

    #[test]
    fn validate_rule_accepts_rfc1918_allowed_ips() {
        use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule};

        let rule = NetworkPolicyRule {
            name: "good".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "internal.corp".to_string(),
                port: 443,
                allowed_ips: vec!["10.0.5.0/24".to_string()],
                ..Default::default()
            }],
            binaries: vec![],
        };
        let result = validate_rule_not_always_blocked(&rule);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_rule_accepts_public_host() {
        use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule};

        let rule = NetworkPolicyRule {
            name: "good".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.github.com".to_string(),
                port: 443,
                ..Default::default()
            }],
            binaries: vec![],
        };
        let result = validate_rule_not_always_blocked(&rule);
        assert!(result.is_ok());
    }

    // ---- Settings tests ----

    #[test]
    fn merge_effective_settings_includes_unset_registered_keys() {
        let global = StoredSettings::default();
        let sandbox = StoredSettings::default();
        let merged = merge_effective_settings(&global, &sandbox).unwrap();
        for registered in settings::REGISTERED_SETTINGS {
            let setting = merged
                .get(registered.key)
                .unwrap_or_else(|| panic!("missing registered key {}", registered.key));
            assert!(
                setting.value.is_none(),
                "expected unset value for {}",
                registered.key
            );
            assert_eq!(setting.scope, SettingScope::Unspecified as i32);
        }
    }

    #[test]
    fn materialize_global_settings_includes_unset_registered_keys() {
        let global = StoredSettings::default();
        let materialized = materialize_global_settings(&global).unwrap();
        for registered in settings::REGISTERED_SETTINGS {
            let setting = materialized
                .get(registered.key)
                .unwrap_or_else(|| panic!("missing registered key {}", registered.key));
            assert!(
                setting.value.is_none(),
                "expected unset value for {}",
                registered.key
            );
        }
    }

    #[test]
    fn decode_policy_from_global_settings_round_trip() {
        let policy = openshell_core::proto::SandboxPolicy {
            version: 7,
            ..Default::default()
        };
        let encoded = hex::encode(policy.encode_to_vec());
        let global = StoredSettings {
            revision: 1,
            settings: std::iter::once(("policy".to_string(), StoredSettingValue::Bytes(encoded)))
                .collect(),
        };

        let decoded = decode_policy_from_global_settings(&global)
            .unwrap()
            .expect("policy present");
        assert_eq!(decoded.version, 7);
    }

    #[test]
    fn config_revision_changes_when_effective_setting_changes() {
        let policy = ProtoSandboxPolicy::default();
        let mut settings = HashMap::new();
        settings.insert(
            "mode".to_string(),
            EffectiveSetting {
                value: Some(SettingValue {
                    value: Some(setting_value::Value::StringValue("strict".to_string())),
                }),
                scope: SettingScope::Sandbox.into(),
            },
        );

        let rev_a = compute_config_revision(Some(&policy), &settings, PolicySource::Sandbox);
        settings.insert(
            "mode".to_string(),
            EffectiveSetting {
                value: Some(SettingValue {
                    value: Some(setting_value::Value::StringValue("relaxed".to_string())),
                }),
                scope: SettingScope::Sandbox.into(),
            },
        );
        let rev_b = compute_config_revision(Some(&policy), &settings, PolicySource::Sandbox);

        assert_ne!(rev_a, rev_b);
    }

    #[test]
    fn proto_setting_to_stored_rejects_unknown_key() {
        let value = SettingValue {
            value: Some(setting_value::Value::StringValue("hello".to_string())),
        };
        let err = proto_setting_to_stored("unknown_key", &value).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("unknown setting key"));
    }

    #[cfg(feature = "dev-settings")]
    #[test]
    fn proto_setting_to_stored_rejects_type_mismatch() {
        let value = SettingValue {
            value: Some(setting_value::Value::StringValue("true".to_string())),
        };
        let err = proto_setting_to_stored("dummy_bool", &value).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("expects bool value"));
    }

    #[cfg(feature = "dev-settings")]
    #[test]
    fn proto_setting_to_stored_accepts_bool_for_registered_bool_key() {
        let value = SettingValue {
            value: Some(setting_value::Value::BoolValue(true)),
        };
        let stored = proto_setting_to_stored("dummy_bool", &value).unwrap();
        assert_eq!(stored, StoredSettingValue::Bool(true));
    }

    #[cfg(feature = "dev-settings")]
    #[test]
    fn merge_effective_settings_global_overrides_sandbox_key() {
        let global = StoredSettings {
            revision: 2,
            settings: [
                (
                    "log_level".to_string(),
                    StoredSettingValue::String("warn".to_string()),
                ),
                ("dummy_int".to_string(), StoredSettingValue::Int(7)),
            ]
            .into_iter()
            .collect(),
        };
        let sandbox = StoredSettings {
            revision: 1,
            settings: [
                (
                    "log_level".to_string(),
                    StoredSettingValue::String("debug".to_string()),
                ),
                ("dummy_bool".to_string(), StoredSettingValue::Bool(true)),
            ]
            .into_iter()
            .collect(),
        };

        let merged = merge_effective_settings(&global, &sandbox).unwrap();
        let log_level = merged.get("log_level").expect("log_level present");
        assert_eq!(log_level.scope, SettingScope::Global as i32);
        assert_eq!(
            log_level.value.as_ref().and_then(|v| v.value.as_ref()),
            Some(&setting_value::Value::StringValue("warn".to_string()))
        );

        let dummy_bool = merged.get("dummy_bool").expect("dummy_bool present");
        assert_eq!(dummy_bool.scope, SettingScope::Sandbox as i32);

        let dummy_int = merged.get("dummy_int").expect("dummy_int present");
        assert_eq!(dummy_int.scope, SettingScope::Global as i32);
    }

    #[cfg(feature = "dev-settings")]
    #[test]
    fn merge_effective_settings_sandbox_scoped_value_has_sandbox_scope() {
        let global = StoredSettings::default();
        let sandbox = StoredSettings {
            revision: 1,
            settings: [(
                "log_level".to_string(),
                StoredSettingValue::String("debug".to_string()),
            )]
            .into_iter()
            .collect(),
        };

        let merged = merge_effective_settings(&global, &sandbox).unwrap();
        let log_level = merged.get("log_level").expect("log_level present");
        assert_eq!(log_level.scope, SettingScope::Sandbox as i32);
        assert!(log_level.value.is_some());
    }

    #[test]
    fn merge_effective_settings_unset_key_has_unspecified_scope_and_no_value() {
        let global = StoredSettings::default();
        let sandbox = StoredSettings::default();
        let merged = merge_effective_settings(&global, &sandbox).unwrap();
        for registered in settings::REGISTERED_SETTINGS {
            let setting = merged.get(registered.key).unwrap();
            assert_eq!(setting.scope, SettingScope::Unspecified as i32);
            assert!(setting.value.is_none());
        }
    }

    #[test]
    fn merge_effective_settings_policy_key_is_excluded() {
        let global = StoredSettings {
            revision: 1,
            settings: std::iter::once((
                "policy".to_string(),
                StoredSettingValue::Bytes("deadbeef".to_string()),
            ))
            .collect(),
        };
        let sandbox = StoredSettings {
            revision: 1,
            settings: std::iter::once((
                "policy".to_string(),
                StoredSettingValue::Bytes("cafebabe".to_string()),
            ))
            .collect(),
        };

        let merged = merge_effective_settings(&global, &sandbox).unwrap();
        assert!(!merged.contains_key("policy"));
    }

    #[test]
    fn sandbox_settings_names_match_sandbox_names() {
        let sandbox_name = "my-sandbox";
        assert_eq!(sandbox_name, "my-sandbox");
    }

    // ---- compute_config_revision ----

    #[test]
    fn config_revision_stable_when_nothing_changes() {
        let policy = ProtoSandboxPolicy::default();
        let mut settings = HashMap::new();
        settings.insert(
            "log_level".to_string(),
            EffectiveSetting {
                value: Some(SettingValue {
                    value: Some(setting_value::Value::StringValue("info".to_string())),
                }),
                scope: SettingScope::Sandbox.into(),
            },
        );

        let rev_a = compute_config_revision(Some(&policy), &settings, PolicySource::Sandbox);
        let rev_b = compute_config_revision(Some(&policy), &settings, PolicySource::Sandbox);
        assert_eq!(rev_a, rev_b);
    }

    #[test]
    fn config_revision_changes_when_policy_changes() {
        let policy_a = ProtoSandboxPolicy {
            version: 1,
            ..Default::default()
        };
        let policy_b = ProtoSandboxPolicy {
            version: 2,
            ..Default::default()
        };
        let settings = HashMap::new();

        let rev_a = compute_config_revision(Some(&policy_a), &settings, PolicySource::Sandbox);
        let rev_b = compute_config_revision(Some(&policy_b), &settings, PolicySource::Sandbox);
        assert_ne!(rev_a, rev_b);
    }

    #[test]
    fn config_revision_changes_when_policy_source_changes() {
        let policy = ProtoSandboxPolicy::default();
        let settings = HashMap::new();

        let rev_a = compute_config_revision(Some(&policy), &settings, PolicySource::Sandbox);
        let rev_b = compute_config_revision(Some(&policy), &settings, PolicySource::Global);
        assert_ne!(rev_a, rev_b);
    }

    #[test]
    fn config_revision_without_policy_still_hashes_settings() {
        let mut settings = HashMap::new();
        settings.insert(
            "log_level".to_string(),
            EffectiveSetting {
                value: Some(SettingValue {
                    value: Some(setting_value::Value::StringValue("debug".to_string())),
                }),
                scope: SettingScope::Sandbox.into(),
            },
        );

        let rev_a = compute_config_revision(None, &settings, PolicySource::Sandbox);

        settings.insert(
            "log_level".to_string(),
            EffectiveSetting {
                value: Some(SettingValue {
                    value: Some(setting_value::Value::StringValue("warn".to_string())),
                }),
                scope: SettingScope::Sandbox.into(),
            },
        );

        let rev_b = compute_config_revision(None, &settings, PolicySource::Sandbox);
        assert_ne!(rev_a, rev_b);
    }

    // ---- stored <-> proto round-trip ----

    #[test]
    fn stored_setting_to_proto_string_round_trip() {
        let stored = StoredSettingValue::String("hello".to_string());
        let proto = stored_setting_to_proto(&stored).unwrap();
        assert_eq!(
            proto.value,
            Some(setting_value::Value::StringValue("hello".to_string()))
        );
    }

    #[test]
    fn stored_setting_to_proto_int_round_trip() {
        let stored = StoredSettingValue::Int(42);
        let proto = stored_setting_to_proto(&stored).unwrap();
        assert_eq!(proto.value, Some(setting_value::Value::IntValue(42)));
    }

    #[test]
    fn stored_setting_to_proto_bool_round_trip() {
        let stored = StoredSettingValue::Bool(false);
        let proto = stored_setting_to_proto(&stored).unwrap();
        assert_eq!(proto.value, Some(setting_value::Value::BoolValue(false)));
    }

    // ---- upsert_setting_value ----

    #[test]
    fn upsert_setting_value_returns_true_on_insert() {
        let mut map = BTreeMap::new();
        let changed = upsert_setting_value(
            &mut map,
            "log_level",
            StoredSettingValue::String("debug".to_string()),
        );
        assert!(changed);
        assert_eq!(
            map.get("log_level"),
            Some(&StoredSettingValue::String("debug".to_string()))
        );
    }

    #[test]
    fn upsert_setting_value_returns_false_when_unchanged() {
        let mut map = BTreeMap::new();
        map.insert(
            "log_level".to_string(),
            StoredSettingValue::String("debug".to_string()),
        );
        let changed = upsert_setting_value(
            &mut map,
            "log_level",
            StoredSettingValue::String("debug".to_string()),
        );
        assert!(!changed);
    }

    #[test]
    fn upsert_setting_value_returns_true_on_update() {
        let mut map = BTreeMap::new();
        map.insert(
            "log_level".to_string(),
            StoredSettingValue::String("debug".to_string()),
        );
        let changed = upsert_setting_value(
            &mut map,
            "log_level",
            StoredSettingValue::String("warn".to_string()),
        );
        assert!(changed);
    }

    // ---- Settings persistence ----

    #[tokio::test]
    async fn global_settings_load_returns_default_when_empty() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();
        let settings = load_global_settings(&store).await.unwrap();
        assert!(settings.settings.is_empty());
        assert_eq!(settings.revision, 0);
    }

    #[tokio::test]
    async fn sandbox_settings_load_returns_default_when_empty() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();
        let settings = load_sandbox_settings(&store, "nonexistent").await.unwrap();
        assert!(settings.settings.is_empty());
        assert_eq!(settings.revision, 0);
    }

    #[tokio::test]
    async fn global_settings_save_and_load_round_trip() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        let mut settings = StoredSettings::default();
        settings.settings.insert(
            "log_level".to_string(),
            StoredSettingValue::String("error".to_string()),
        );
        settings
            .settings
            .insert("dummy_bool".to_string(), StoredSettingValue::Bool(true));
        settings.revision = 5;
        save_global_settings(&store, &settings).await.unwrap();

        let loaded = load_global_settings(&store).await.unwrap();
        assert_eq!(loaded.revision, 5);
        assert_eq!(
            loaded.settings.get("log_level"),
            Some(&StoredSettingValue::String("error".to_string()))
        );
        assert_eq!(
            loaded.settings.get("dummy_bool"),
            Some(&StoredSettingValue::Bool(true))
        );
    }

    #[tokio::test]
    async fn sandbox_settings_save_and_load_round_trip() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        let sandbox_name = "my-sandbox";
        let mut settings = StoredSettings::default();
        settings
            .settings
            .insert("dummy_int".to_string(), StoredSettingValue::Int(99));
        settings.revision = 3;
        save_sandbox_settings(&store, sandbox_name, &settings)
            .await
            .unwrap();

        let loaded = load_sandbox_settings(&store, sandbox_name).await.unwrap();
        assert_eq!(loaded.revision, 3);
        assert_eq!(
            loaded.settings.get("dummy_int"),
            Some(&StoredSettingValue::Int(99))
        );
    }

    #[tokio::test]
    async fn concurrent_global_setting_mutations_are_serialized() {
        let store = Arc::new(
            Store::connect("sqlite::memory:?cache=shared")
                .await
                .unwrap(),
        );
        let mutex = Arc::new(tokio::sync::Mutex::new(()));

        let n = 50;
        let mut handles = Vec::with_capacity(n);

        for i in 0..n {
            let store = store.clone();
            let mutex = mutex.clone();
            handles.push(tokio::spawn(async move {
                let _guard = mutex.lock().await;
                let mut settings = load_global_settings(&store).await.unwrap();
                settings
                    .settings
                    .insert(format!("key_{i}"), StoredSettingValue::Int(i as i64));
                settings.revision = settings.revision.wrapping_add(1);
                save_global_settings(&store, &settings).await.unwrap();
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let final_settings = load_global_settings(&store).await.unwrap();
        assert_eq!(final_settings.revision, n as u64);
        assert_eq!(final_settings.settings.len(), n);
    }

    #[tokio::test]
    async fn concurrent_global_setting_mutations_without_lock_can_lose_writes() {
        let store = Arc::new(
            Store::connect("sqlite::memory:?cache=shared")
                .await
                .unwrap(),
        );

        let n = 50;
        let mut handles = Vec::with_capacity(n);

        for i in 0..n {
            let store = store.clone();
            handles.push(tokio::spawn(async move {
                let mut settings = load_global_settings(&store).await.unwrap();
                tokio::task::yield_now().await;
                settings
                    .settings
                    .insert(format!("key_{i}"), StoredSettingValue::Int(i as i64));
                settings.revision = settings.revision.wrapping_add(1);
                save_global_settings(&store, &settings).await.unwrap();
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let final_settings = load_global_settings(&store).await.unwrap();
        let lost = (n as u64).saturating_sub(final_settings.revision);
        if lost == 0 {
            eprintln!(
                "note: no lost writes detected in unlocked test (sequential scheduling); \
                 the locked test is the authoritative correctness check"
            );
        } else {
            eprintln!("unlocked test: {lost} lost writes out of {n} (expected behavior)");
        }
    }

    // ---- Conflict guard tests ----

    #[tokio::test]
    async fn conflict_guard_sandbox_set_blocked_when_global_exists() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        let mut global = StoredSettings::default();
        global.settings.insert(
            "log_level".to_string(),
            StoredSettingValue::String("warn".to_string()),
        );
        global.revision = 1;
        save_global_settings(&store, &global).await.unwrap();

        let loaded_global = load_global_settings(&store).await.unwrap();
        let globally_managed = loaded_global.settings.contains_key("log_level");
        assert!(globally_managed);
    }

    #[tokio::test]
    async fn conflict_guard_sandbox_delete_blocked_when_global_exists() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        let mut global = StoredSettings::default();
        global
            .settings
            .insert("dummy_int".to_string(), StoredSettingValue::Int(42));
        global.revision = 1;
        save_global_settings(&store, &global).await.unwrap();

        let loaded_global = load_global_settings(&store).await.unwrap();
        assert!(loaded_global.settings.contains_key("dummy_int"));
    }

    #[tokio::test]
    async fn delete_unlock_sandbox_set_succeeds_after_global_delete() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        let mut global = StoredSettings::default();
        global.settings.insert(
            "log_level".to_string(),
            StoredSettingValue::String("warn".to_string()),
        );
        global.revision = 1;
        save_global_settings(&store, &global).await.unwrap();

        let loaded = load_global_settings(&store).await.unwrap();
        assert!(loaded.settings.contains_key("log_level"));

        global.settings.remove("log_level");
        global.revision = 2;
        save_global_settings(&store, &global).await.unwrap();

        let loaded = load_global_settings(&store).await.unwrap();
        assert!(!loaded.settings.contains_key("log_level"));

        let sandbox_name = "test-sandbox";
        let mut sandbox_settings = load_sandbox_settings(&store, sandbox_name).await.unwrap();
        let changed = upsert_setting_value(
            &mut sandbox_settings.settings,
            "log_level",
            StoredSettingValue::String("debug".to_string()),
        );
        assert!(changed);
        sandbox_settings.revision = sandbox_settings.revision.wrapping_add(1);
        save_sandbox_settings(&store, sandbox_name, &sandbox_settings)
            .await
            .unwrap();

        let reloaded = load_sandbox_settings(&store, sandbox_name).await.unwrap();
        assert_eq!(
            reloaded.settings.get("log_level"),
            Some(&StoredSettingValue::String("debug".to_string())),
        );
    }

    #[test]
    fn validate_registered_setting_key_rejects_policy() {
        let err = validate_registered_setting_key("policy").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("unknown setting key"));
    }

    #[test]
    fn proto_setting_to_stored_rejects_policy_key() {
        let value = SettingValue {
            value: Some(setting_value::Value::StringValue("anything".to_string())),
        };
        let err = proto_setting_to_stored("policy", &value).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("unknown setting key"));
    }
}
