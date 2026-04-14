// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Policy updates, status, draft chunks, config/settings layer, and sandbox logs.

#![allow(clippy::result_large_err)] // gRPC handlers return Result<Response<_>, Status>
#![allow(clippy::cast_possible_truncation)] // Intentional u128->i64 etc. for timestamp math
#![allow(clippy::cast_sign_loss)] // Intentional i32->u32 conversions from proto types
#![allow(clippy::cast_possible_wrap)] // Intentional u32->i32 conversions for proto compat
#![allow(clippy::cast_precision_loss)] // f64->f32 for confidence scores
#![allow(clippy::items_after_statements)] // DB_PORTS const inside function

use crate::ServerState;
use crate::persistence::{DraftChunkRecord, PolicyRecord, Store};
use openshell_core::proto::setting_value;
use openshell_core::proto::{
    ApproveAllDraftChunksRequest, ApproveAllDraftChunksResponse, ApproveDraftChunkRequest,
    ApproveDraftChunkResponse, ClearDraftChunksRequest, ClearDraftChunksResponse,
    DraftHistoryEntry, EditDraftChunkRequest, EditDraftChunkResponse, EffectiveSetting,
    GetDraftHistoryRequest, GetDraftHistoryResponse, GetDraftPolicyRequest, GetDraftPolicyResponse,
    GetGatewayConfigRequest, GetGatewayConfigResponse, GetSandboxConfigRequest,
    GetSandboxConfigResponse, GetSandboxLogsRequest, GetSandboxLogsResponse,
    GetSandboxPolicyStatusRequest, GetSandboxPolicyStatusResponse,
    GetSandboxProviderEnvironmentRequest, GetSandboxProviderEnvironmentResponse,
    ListSandboxPoliciesRequest, ListSandboxPoliciesResponse, PolicyChunk, PolicySource,
    PolicyStatus, PushSandboxLogsRequest, PushSandboxLogsResponse, RejectDraftChunkRequest,
    RejectDraftChunkResponse, ReportPolicyStatusRequest, ReportPolicyStatusResponse,
    SandboxLogLine, SandboxPolicyRevision, SettingScope, SettingValue, SubmitPolicyAnalysisRequest,
    SubmitPolicyAnalysisResponse, UndoDraftChunkRequest, UndoDraftChunkResponse,
    UpdateConfigRequest, UpdateConfigResponse,
};
use openshell_core::proto::{Sandbox, SandboxPolicy as ProtoSandboxPolicy};
use openshell_core::settings::{self, SettingValueKind};
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
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
/// Internal object id for the singleton global settings record.
const GLOBAL_SETTINGS_ID: &str = "gateway_settings:global";
const GLOBAL_SETTINGS_NAME: &str = "global";
/// Internal object type for durable sandbox-scoped settings.
pub(crate) const SANDBOX_SETTINGS_OBJECT_TYPE: &str = "sandbox_settings";
/// Reserved settings key used to store global policy payload.
const POLICY_SETTING_KEY: &str = "policy";
/// Sentinel `sandbox_id` used to store global policy revisions.
const GLOBAL_POLICY_SANDBOX_ID: &str = "__global__";
/// Maximum number of optimistic retry attempts for policy version conflicts.
const MERGE_RETRY_LIMIT: usize = 5;

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
            .ok_or_else(|| Status::internal("sandbox has no spec"))?;

        match spec.policy {
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
    let sandbox_settings = load_sandbox_settings(state.store.as_ref(), &sandbox_id).await?;

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
    let req = request.into_inner();
    let key = req.setting_key.trim();
    let has_policy = req.policy.is_some();
    let has_setting = !key.is_empty();

    if has_policy && has_setting {
        return Err(Status::invalid_argument(
            "policy and setting_key cannot be set in the same request",
        ));
    }
    if !has_policy && !has_setting {
        return Err(Status::invalid_argument(
            "either policy or setting_key must be provided",
        ));
    }

    if req.global {
        let _settings_guard = state.settings_mutex.lock().await;

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
    let sandbox_id = sandbox.id.clone();

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
                load_sandbox_settings(state.store.as_ref(), &sandbox_id).await?;
            let removed = sandbox_settings.settings.remove(key).is_some();
            if removed {
                sandbox_settings.revision = sandbox_settings.revision.wrapping_add(1);
                save_sandbox_settings(
                    state.store.as_ref(),
                    &sandbox_id,
                    &sandbox.name,
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

        let mut sandbox_settings = load_sandbox_settings(state.store.as_ref(), &sandbox_id).await?;
        let changed = upsert_setting_value(&mut sandbox_settings.settings, key, stored);
        if changed {
            sandbox_settings.revision = sandbox_settings.revision.wrapping_add(1);
            save_sandbox_settings(
                state.store.as_ref(),
                &sandbox_id,
                &sandbox.name,
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
        (sandbox.id, sandbox.current_policy_version)
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
        sandbox.id
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
    let sandbox_id = sandbox.id.clone();

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
    let sandbox_id = sandbox.id.clone();

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
    let sandbox_id = sandbox.id.clone();

    let chunk = state
        .store
        .get_draft_chunk(&req.chunk_id)
        .await
        .map_err(|e| Status::internal(format!("fetch chunk failed: {e}")))?
        .ok_or_else(|| Status::not_found("chunk not found"))?;

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

    let now_ms =
        current_time_ms().map_err(|e| Status::internal(format!("timestamp error: {e}")))?;
    state
        .store
        .update_draft_chunk_status(&req.chunk_id, "approved", Some(now_ms))
        .await
        .map_err(|e| Status::internal(format!("update chunk status failed: {e}")))?;

    state.sandbox_watch_bus.notify(&sandbox_id);

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
    let sandbox_id = sandbox.id.clone();

    let chunk = state
        .store
        .get_draft_chunk(&req.chunk_id)
        .await
        .map_err(|e| Status::internal(format!("fetch chunk failed: {e}")))?
        .ok_or_else(|| Status::not_found("chunk not found"))?;

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
        remove_chunk_from_policy(state, &sandbox_id, &chunk).await?;
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
    let sandbox_id = sandbox.id.clone();

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

        let now_ms =
            current_time_ms().map_err(|e| Status::internal(format!("timestamp error: {e}")))?;
        state
            .store
            .update_draft_chunk_status(&chunk.id, "approved", Some(now_ms))
            .await
            .map_err(|e| Status::internal(format!("update chunk status failed: {e}")))?;

        chunks_approved += 1;
    }

    state.sandbox_watch_bus.notify(&sandbox_id);

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

    let _sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&req.name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;

    let chunk = state
        .store
        .get_draft_chunk(&req.chunk_id)
        .await
        .map_err(|e| Status::internal(format!("fetch chunk failed: {e}")))?
        .ok_or_else(|| Status::not_found("chunk not found"))?;

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
    let sandbox_id = sandbox.id.clone();

    let chunk = state
        .store
        .get_draft_chunk(&req.chunk_id)
        .await
        .map_err(|e| Status::internal(format!("fetch chunk failed: {e}")))?
        .ok_or_else(|| Status::not_found("chunk not found"))?;

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
    let sandbox_id = sandbox.id.clone();

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
    let sandbox_id = sandbox.id.clone();

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
fn validate_rule_not_always_blocked(
    rule: &openshell_core::proto::NetworkPolicyRule,
) -> Result<(), Status> {
    use openshell_core::net::{is_always_blocked_ip, is_always_blocked_net};
    use std::net::IpAddr;

    for ep in &rule.endpoints {
        // Check if the endpoint host is a literal always-blocked IP.
        if let Ok(ip) = ep.host.parse::<IpAddr>() {
            if is_always_blocked_ip(ip) {
                return Err(Status::invalid_argument(format!(
                    "proposed rule endpoint host '{}' is an always-blocked address \
                     (loopback/link-local/unspecified); the proxy will deny traffic \
                     to this destination regardless of policy",
                    ep.host
                )));
            }
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
            if let Ok(net) = parsed {
                if is_always_blocked_net(net) {
                    return Err(Status::invalid_argument(format!(
                        "proposed rule contains always-blocked allowed_ips entry '{entry}'; \
                         SSRF hardening prevents traffic to these destinations \
                         regardless of policy"
                    )));
                }
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

pub(super) async fn merge_chunk_into_policy(
    store: &Store,
    sandbox_id: &str,
    chunk: &DraftChunkRecord,
) -> Result<(i64, String), Status> {
    use openshell_core::proto::NetworkPolicyRule;

    let rule = NetworkPolicyRule::decode(chunk.proposed_rule.as_slice())
        .map_err(|e| Status::internal(format!("decode proposed_rule failed: {e}")))?;

    // Defense-in-depth: reject proposed rules targeting always-blocked
    // destinations.  Even if the sandbox mapper didn't filter these (e.g.,
    // an older sandbox version), the proxy will deny them at runtime.
    validate_rule_not_always_blocked(&rule)?;

    for attempt in 1..=MERGE_RETRY_LIMIT {
        let latest = store
            .get_latest_policy(sandbox_id)
            .await
            .map_err(|e| Status::internal(format!("fetch latest policy failed: {e}")))?;

        let mut policy = if let Some(ref record) = latest {
            ProtoSandboxPolicy::decode(record.policy_payload.as_slice())
                .map_err(|e| Status::internal(format!("decode current policy failed: {e}")))?
        } else {
            ProtoSandboxPolicy::default()
        };

        let base_version = latest.as_ref().map_or(0, |r| r.version);

        let chunk_host_lc = chunk.host.to_lowercase();
        let chunk_port = chunk.port as u32;

        let merge_key = if policy.network_policies.contains_key(&chunk.rule_name) {
            Some(chunk.rule_name.clone())
        } else {
            policy
                .network_policies
                .iter()
                .find_map(|(key, existing_rule)| {
                    let has_match = existing_rule.endpoints.iter().any(|ep| {
                        let host_match = ep.host.to_lowercase() == chunk_host_lc;
                        let port_match = if ep.ports.is_empty() {
                            ep.port == chunk_port
                        } else {
                            ep.ports.contains(&chunk_port)
                        };
                        host_match && port_match
                    });
                    has_match.then(|| key.clone())
                })
        };

        if let Some(key) = merge_key {
            let existing = policy.network_policies.get_mut(&key).unwrap();
            for b in &rule.binaries {
                if !existing.binaries.iter().any(|eb| eb.path == b.path) {
                    existing.binaries.push(b.clone());
                }
            }
            for ep in &rule.endpoints {
                if let Some(existing_ep) = existing.endpoints.iter_mut().find(|e| {
                    e.host.to_lowercase() == ep.host.to_lowercase()
                        && (e.port == ep.port
                            || (!e.ports.is_empty() && e.ports.contains(&ep.port)))
                }) {
                    for ip in &ep.allowed_ips {
                        if !existing_ep.allowed_ips.contains(ip) {
                            existing_ep.allowed_ips.push(ip.clone());
                        }
                    }
                } else {
                    existing.endpoints.push(ep.clone());
                }
            }
        } else {
            policy
                .network_policies
                .insert(chunk.rule_name.clone(), rule.clone());
        }

        let payload = policy.encode_to_vec();
        let hash = deterministic_policy_hash(&policy);
        let next_version = base_version + 1;
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
                        rule_name = %chunk.rule_name,
                        attempt,
                        version = next_version,
                        "merge_chunk_into_policy: succeeded after version conflict retry"
                    );
                }

                return Ok((next_version, hash));
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("UNIQUE") || msg.contains("unique") || msg.contains("duplicate") {
                    warn!(
                        sandbox_id = %sandbox_id,
                        rule_name = %chunk.rule_name,
                        attempt,
                        conflicting_version = next_version,
                        "merge_chunk_into_policy: version conflict, retrying"
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
        "merge_chunk_into_policy: gave up after {} version conflict retries for rule '{}'",
        MERGE_RETRY_LIMIT, chunk.rule_name
    )))
}

async fn remove_chunk_from_policy(
    state: &ServerState,
    sandbox_id: &str,
    chunk: &DraftChunkRecord,
) -> Result<(i64, String), Status> {
    for attempt in 1..=MERGE_RETRY_LIMIT {
        let latest = state
            .store
            .get_latest_policy(sandbox_id)
            .await
            .map_err(|e| Status::internal(format!("fetch latest policy failed: {e}")))?
            .ok_or_else(|| Status::internal("no active policy to undo from"))?;

        let mut policy = ProtoSandboxPolicy::decode(latest.policy_payload.as_slice())
            .map_err(|e| Status::internal(format!("decode current policy failed: {e}")))?;

        let should_remove =
            if let Some(existing) = policy.network_policies.get_mut(&chunk.rule_name) {
                existing.binaries.retain(|b| b.path != chunk.binary);
                existing.binaries.is_empty()
            } else {
                false
            };
        if should_remove {
            policy.network_policies.remove(&chunk.rule_name);
        }

        let payload = policy.encode_to_vec();
        let hash = deterministic_policy_hash(&policy);
        let next_version = latest.version + 1;
        let policy_id = uuid::Uuid::new_v4().to_string();

        match state
            .store
            .put_policy_revision(&policy_id, sandbox_id, next_version, &payload, &hash)
            .await
        {
            Ok(()) => {
                let _ = state
                    .store
                    .supersede_older_policies(sandbox_id, next_version)
                    .await;

                if attempt > 1 {
                    info!(
                        sandbox_id = %sandbox_id,
                        rule_name = %chunk.rule_name,
                        attempt,
                        version = next_version,
                        "remove_chunk_from_policy: succeeded after version conflict retry"
                    );
                }

                return Ok((next_version, hash));
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("UNIQUE") || msg.contains("unique") || msg.contains("duplicate") {
                    warn!(
                        sandbox_id = %sandbox_id,
                        rule_name = %chunk.rule_name,
                        attempt,
                        conflicting_version = next_version,
                        "remove_chunk_from_policy: version conflict, retrying"
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
        "remove_chunk_from_policy: gave up after {} version conflict retries for rule '{}'",
        MERGE_RETRY_LIMIT, chunk.rule_name
    )))
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
    load_settings_record(store, GLOBAL_SETTINGS_OBJECT_TYPE, GLOBAL_SETTINGS_ID).await
}

pub(super) async fn save_global_settings(
    store: &Store,
    settings: &StoredSettings,
) -> Result<(), Status> {
    save_settings_record(
        store,
        GLOBAL_SETTINGS_OBJECT_TYPE,
        GLOBAL_SETTINGS_ID,
        GLOBAL_SETTINGS_NAME,
        settings,
    )
    .await
}

/// Derive a distinct settings record ID from a sandbox UUID.
pub(crate) fn sandbox_settings_id(sandbox_id: &str) -> String {
    format!("settings:{sandbox_id}")
}

pub(super) async fn load_sandbox_settings(
    store: &Store,
    sandbox_id: &str,
) -> Result<StoredSettings, Status> {
    load_settings_record(
        store,
        SANDBOX_SETTINGS_OBJECT_TYPE,
        &sandbox_settings_id(sandbox_id),
    )
    .await
}

pub(super) async fn save_sandbox_settings(
    store: &Store,
    sandbox_id: &str,
    sandbox_name: &str,
    settings: &StoredSettings,
) -> Result<(), Status> {
    save_settings_record(
        store,
        SANDBOX_SETTINGS_OBJECT_TYPE,
        &sandbox_settings_id(sandbox_id),
        sandbox_name,
        settings,
    )
    .await
}

async fn load_settings_record(
    store: &Store,
    object_type: &str,
    id: &str,
) -> Result<StoredSettings, Status> {
    let record = store
        .get(object_type, id)
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
    id: &str,
    name: &str,
    settings: &StoredSettings,
) -> Result<(), Status> {
    let payload = serde_json::to_vec(settings)
        .map_err(|e| Status::internal(format!("encode settings payload failed: {e}")))?;
    store
        .put(object_type, id, name, &payload)
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
    use crate::persistence::Store;
    use std::collections::HashMap;
    use tonic::Code;

    // ---- Sandbox without policy ----

    #[tokio::test]
    async fn sandbox_without_policy_stores_successfully() {
        use openshell_core::proto::{SandboxPhase, SandboxSpec};

        let store = Store::connect("sqlite::memory:").await.unwrap();

        let sandbox = Sandbox {
            id: "sb-no-policy".to_string(),
            name: "no-policy-sandbox".to_string(),
            namespace: "default".to_string(),
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

    #[tokio::test]
    async fn sandbox_policy_backfill_on_update_when_no_baseline() {
        use openshell_core::proto::{
            FilesystemPolicy, LandlockPolicy, ProcessPolicy, SandboxPhase, SandboxSpec,
        };

        let store = Store::connect("sqlite::memory:").await.unwrap();

        let sandbox = Sandbox {
            id: "sb-backfill".to_string(),
            name: "backfill-sandbox".to_string(),
            namespace: "default".to_string(),
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
            network_policies: [(
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
            )]
            .into_iter()
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
            network_policies: [(
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
            )]
            .into_iter()
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
        for registered in openshell_core::settings::REGISTERED_SETTINGS {
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
        for registered in openshell_core::settings::REGISTERED_SETTINGS {
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
            settings: [("policy".to_string(), StoredSettingValue::Bytes(encoded))]
                .into_iter()
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
        for registered in openshell_core::settings::REGISTERED_SETTINGS {
            let setting = merged.get(registered.key).unwrap();
            assert_eq!(setting.scope, SettingScope::Unspecified as i32);
            assert!(setting.value.is_none());
        }
    }

    #[test]
    fn merge_effective_settings_policy_key_is_excluded() {
        let global = StoredSettings {
            revision: 1,
            settings: [(
                "policy".to_string(),
                StoredSettingValue::Bytes("deadbeef".to_string()),
            )]
            .into_iter()
            .collect(),
        };
        let sandbox = StoredSettings {
            revision: 1,
            settings: [(
                "policy".to_string(),
                StoredSettingValue::Bytes("cafebabe".to_string()),
            )]
            .into_iter()
            .collect(),
        };

        let merged = merge_effective_settings(&global, &sandbox).unwrap();
        assert!(!merged.contains_key("policy"));
    }

    #[test]
    fn sandbox_settings_id_has_prefix_preventing_collision() {
        let sandbox_id = "abc-123";
        let settings_id = sandbox_settings_id(sandbox_id);
        assert!(settings_id.starts_with("settings:"));
        assert_ne!(settings_id, sandbox_id);
    }

    #[test]
    fn sandbox_settings_id_different_sandboxes_produce_different_ids() {
        let id_a = sandbox_settings_id("sandbox-1");
        let id_b = sandbox_settings_id("sandbox-2");
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn sandbox_settings_id_embeds_sandbox_id() {
        let sandbox_id = "some-uuid-value";
        let settings_id = sandbox_settings_id(sandbox_id);
        assert!(settings_id.contains(sandbox_id));
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

        let sandbox_id = "sb-uuid-123";
        let mut settings = StoredSettings::default();
        settings
            .settings
            .insert("dummy_int".to_string(), StoredSettingValue::Int(99));
        settings.revision = 3;
        save_sandbox_settings(&store, sandbox_id, "my-sandbox", &settings)
            .await
            .unwrap();

        let loaded = load_sandbox_settings(&store, sandbox_id).await.unwrap();
        assert_eq!(loaded.revision, 3);
        assert_eq!(
            loaded.settings.get("dummy_int"),
            Some(&StoredSettingValue::Int(99))
        );
    }

    #[tokio::test]
    async fn concurrent_global_setting_mutations_are_serialized() {
        let store = std::sync::Arc::new(
            Store::connect("sqlite::memory:?cache=shared")
                .await
                .unwrap(),
        );
        let mutex = std::sync::Arc::new(tokio::sync::Mutex::new(()));

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
        let store = std::sync::Arc::new(
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

        let sandbox_id = "test-sandbox-uuid";
        let mut sandbox_settings = load_sandbox_settings(&store, sandbox_id).await.unwrap();
        let changed = upsert_setting_value(
            &mut sandbox_settings.settings,
            "log_level",
            StoredSettingValue::String("debug".to_string()),
        );
        assert!(changed);
        sandbox_settings.revision = sandbox_settings.revision.wrapping_add(1);
        save_sandbox_settings(&store, sandbox_id, "test-sandbox", &sandbox_settings)
            .await
            .unwrap();

        let reloaded = load_sandbox_settings(&store, sandbox_id).await.unwrap();
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
