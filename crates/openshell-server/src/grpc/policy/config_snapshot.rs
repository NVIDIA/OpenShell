// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Effective sandbox configuration snapshots.
//!
//! A sandbox's configuration has two parts: the policy and settings snapshot
//! (`GetSandboxConfigResponse`) and the provider environment
//! (`GetSandboxProviderEnvironmentResponse`). Both are built from one load of
//! their shared inputs. The polling RPCs and pushed delivery use the same
//! loader and builders, so a pushed snapshot is byte-for-byte what a poll at
//! the same moment would return.

use std::time::Instant;

use openshell_core::policy_identity::deterministic_policy_hash;
use openshell_core::proto::{
    GetSandboxConfigResponse, GetSandboxProviderEnvironmentResponse, PolicySource,
    ProviderReadinessReason, Sandbox, SandboxPolicy as ProtoSandboxPolicy,
};
use prost::Message as _;
use tonic::Status;
use tracing::{debug, info, warn};

use super::super::StoredSettings;
use super::super::provider::ProviderEnvironmentRecord;
use super::super::validation::{validate_and_canonicalize_policy, validate_policy_safety};
use super::{
    GLOBAL_POLICY_SANDBOX_ID, POLICY_SETTING_KEY, STORED_POLICY_SOURCE_SPEC,
    apply_captured_policy_context, bounded_configuration_diagnostic,
    canonical_policy_record_identity, clear_provider_credentialed_markers,
    compute_config_revision_with_validation_mode,
    compute_provider_env_revision_from_records_and_policy_bindings,
    decode_policy_from_global_settings, extend_credentialed_scopes_from_policy_bindings,
    load_global_settings, load_sandbox_settings, merge_effective_settings,
    policy_static_credential_endpoint_bindings, provider_policy_context_from_records,
    stamp_provider_credentialed_endpoints, validate_policy_credential_binding_context,
    validate_uninspected_credentialed_endpoints,
};
use crate::ServerState;
use crate::gateway_metrics::{BuildTrigger, ConfigPart, record_config_build};
use crate::persistence::{ObjectId, ObjectName, ObjectWorkspace, PolicyRecord};
use crate::policy_store::PolicyStoreExt as _;
use crate::provider_profile_sources::EffectiveProviderProfileCatalog;
use openshell_policy::compose_effective_policy;

/// Everything both configuration parts read from the store, loaded once.
///
/// Callers must authorize access to `sandbox` before loading.
pub struct SandboxConfigInputs {
    pub sandbox: Sandbox,
    catalog: EffectiveProviderProfileCatalog,
    global_settings: StoredSettings,
    latest_policy: Option<PolicyRecord>,
    /// Version of the latest global policy revision. Zero unless a global
    /// policy is configured and its history row could be read.
    global_policy_version: u32,
    sandbox_settings: StoredSettings,
    provider_records: Vec<ProviderEnvironmentRecord>,
}

impl SandboxConfigInputs {
    /// Object ids of the providers the sandbox attaches, as loaded.
    pub fn provider_ids(&self) -> impl Iterator<Item = &str> {
        self.provider_records
            .iter()
            .map(|record| record.object_id.as_str())
    }
}

/// Load the inputs shared by both configuration parts.
///
/// Independent reads run concurrently. The global policy revision is read only
/// when a global policy is configured.
pub async fn load_sandbox_config_inputs(
    state: &ServerState,
    sandbox: Sandbox,
) -> Result<SandboxConfigInputs, Status> {
    let sandbox_id = sandbox.object_id().to_string();
    let workspace = sandbox.object_workspace().to_string();
    let provider_names = sandbox
        .spec
        .as_ref()
        .map(|spec| spec.providers.clone())
        .unwrap_or_default();
    let store = state.store.as_ref();

    let (catalog, global_settings, latest_policy, sandbox_settings, provider_records) = tokio::try_join!(
        state
            .provider_profile_sources
            .snapshot_catalog(store, &workspace),
        load_global_settings(store),
        async {
            store
                .get_latest_policy(&sandbox_id)
                .await
                .map_err(|e| Status::internal(format!("fetch policy history failed: {e}")))
        },
        load_sandbox_settings(store, &workspace, sandbox.object_name()),
        super::super::provider::load_provider_environment_records(
            store,
            &workspace,
            &provider_names
        ),
    )?;

    let global_policy_version = if global_settings.settings.contains_key(POLICY_SETTING_KEY) {
        match store.get_latest_policy(GLOBAL_POLICY_SANDBOX_ID).await {
            Ok(Some(record)) => u32::try_from(record.version).unwrap_or(0),
            _ => 0,
        }
    } else {
        0
    };

    Ok(SandboxConfigInputs {
        sandbox,
        catalog,
        global_settings,
        latest_policy,
        global_policy_version,
        sandbox_settings,
        provider_records,
    })
}

/// Load inputs and build the policy and settings snapshot, recording the
/// build duration.
pub async fn load_and_build_sandbox_config(
    state: &ServerState,
    sandbox: &Sandbox,
    trigger: BuildTrigger,
) -> Result<GetSandboxConfigResponse, Status> {
    let started = Instant::now();
    let result = async {
        let inputs = load_sandbox_config_inputs(state, sandbox.clone()).await?;
        build_sandbox_config(state, &inputs).await
    }
    .await;
    record_config_build(
        ConfigPart::SandboxConfig,
        trigger,
        result.is_ok(),
        started.elapsed(),
    );
    result
}

/// Load inputs and build the provider environment, recording the build
/// duration.
pub async fn load_and_build_provider_environment(
    state: &ServerState,
    sandbox: &Sandbox,
    supports_static_credential_bindings: bool,
    trigger: BuildTrigger,
) -> Result<GetSandboxProviderEnvironmentResponse, Status> {
    let started = Instant::now();
    let result = async {
        let inputs = load_sandbox_config_inputs(state, sandbox.clone()).await?;
        build_provider_environment(state, &inputs, supports_static_credential_bindings).await
    }
    .await;
    record_config_build(
        ConfigPart::ProviderEnvironment,
        trigger,
        result.is_ok(),
        started.elapsed(),
    );
    result
}

/// Build the effective policy and settings snapshot from loaded inputs.
///
/// When no policy history exists yet, a valid `spec.policy` is backfilled as
/// version 1. That write is the only store access this function makes.
pub async fn build_sandbox_config(
    state: &ServerState,
    inputs: &SandboxConfigInputs,
) -> Result<GetSandboxConfigResponse, Status> {
    let sandbox = &inputs.sandbox;
    let sandbox_id = sandbox.object_id().to_string();
    let workspace = sandbox.object_workspace().to_string();
    let provider_profile_catalog = &inputs.catalog;
    let provider_records = &inputs.provider_records;

    let global_policy = decode_policy_from_global_settings(&inputs.global_settings)?;

    let (mut policy, version, mut policy_hash, policy_source) = if let Some(global_policy) =
        global_policy
    {
        // Under a global override, only the sandbox version metadata is
        // observed; the dormant payload is neither decoded nor validated.
        let version = inputs
            .latest_policy
            .as_ref()
            .map(|record| u32::try_from(record.version).unwrap_or(0))
            .filter(|version| *version > 0)
            .unwrap_or(1);
        let hash = deterministic_policy_hash(&global_policy);
        (Some(global_policy), version, hash, PolicySource::Global)
    } else if let Some(record) = inputs.latest_policy.as_ref() {
        let (policy, hash) = canonical_policy_record_identity(record)?;
        debug!(
            sandbox_id = %sandbox_id,
            version = record.version,
            "GetSandboxConfig served from policy history"
        );
        (
            Some(policy),
            u32::try_from(record.version).unwrap_or(0),
            hash,
            PolicySource::Sandbox,
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
                (None, 0, String::new(), PolicySource::Sandbox)
            }
            Some(spec_policy) => {
                // Stored specs may predate the current schema. Validate before
                // creating policy history so malformed state is never copied or
                // marked loaded, and hash the canonical representation.
                let spec_policy = super::validate_and_canonicalize_stored_policy(
                    spec_policy,
                    STORED_POLICY_SOURCE_SPEC,
                )?;
                let hash = deterministic_policy_hash(&spec_policy);
                let payload = spec_policy.encode_to_vec();
                let policy_id = uuid::Uuid::new_v4().to_string();

                if let Err(e) = state
                    .store
                    .put_policy_revision(&policy_id, &sandbox_id, &workspace, 1, &payload, &hash)
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

                (Some(spec_policy), 1, hash, PolicySource::Sandbox)
            }
        }
    };

    let mut provider_policy_context =
        provider_policy_context_from_records(provider_profile_catalog, provider_records);
    let global_policy_version = if matches!(policy_source, PolicySource::Global) {
        inputs.global_policy_version
    } else {
        0
    };

    if let Some(source_policy) = policy.as_mut() {
        // Never trust provenance supplied by a persisted/user-authored policy.
        // The gateway derives it from the attached provider catalog below.
        clear_provider_credentialed_markers(source_policy);
    }

    if !matches!(policy_source, PolicySource::Global)
        && let Some(source_policy) = policy.as_ref()
        && !provider_policy_context.layers.is_empty()
    {
        let effective_policy =
            compose_effective_policy(source_policy, &provider_policy_context.layers);
        let effective_policy =
            validate_and_canonicalize_policy(effective_policy).map_err(|error| {
                Status::failed_precondition(format!(
                    "provider composition produced an invalid effective policy: {}",
                    error.message()
                ))
            })?;
        validate_policy_safety(&effective_policy).map_err(|error| {
            Status::failed_precondition(format!(
                "provider composition produced an invalid effective policy: {}",
                error.message()
            ))
        })?;
        policy_hash = deterministic_policy_hash(&effective_policy);
        policy = Some(effective_policy);
    }

    let policy_credential_bindings = policy_static_credential_endpoint_bindings(policy.as_ref())?;
    extend_credentialed_scopes_from_policy_bindings(
        &mut provider_policy_context.credentialed_scopes,
        &policy_credential_bindings,
        &provider_policy_context.endpointless_provider_names,
    );
    let mut configuration_error = String::new();
    if let Some(effective_policy) = policy.as_mut() {
        stamp_provider_credentialed_endpoints(
            effective_policy,
            &provider_policy_context.credentialed_scopes,
        );
        if matches!(policy_source, PolicySource::Global) {
            openshell_core::policy_identity::stamp_global_token_grant_owners(effective_policy);
        }
        if let Err(error) = validate_uninspected_credentialed_endpoints(effective_policy) {
            configuration_error = bounded_configuration_diagnostic(error.message());
        }
        policy_hash = deterministic_policy_hash(effective_policy);
    }

    if let Some(policy) = policy.as_ref() {
        state
            .middleware_registry
            .ensure_policy_middlewares_registered(policy)
            .map_err(|error| {
                Status::failed_precondition(format!(
                    "effective policy middleware registration is invalid: {error}"
                ))
            })?;
    }

    let settings = merge_effective_settings(&inputs.global_settings, &inputs.sandbox_settings)?;
    let supervisor_middleware_services =
        state.middleware_registry.required_services(policy.as_ref());
    let config_revision = compute_config_revision_with_validation_mode(
        policy.as_ref(),
        &settings,
        policy_source,
        &supervisor_middleware_services,
        state.config.policy_validation_failure_mode,
        state.extension_jwt_issuer.is_some(),
    );
    if let Some(policy) = policy.as_ref() {
        validate_policy_credential_binding_context(
            provider_profile_catalog,
            provider_records,
            policy,
            &policy_credential_bindings,
        )?;
    }
    let provider_env_revision = compute_provider_env_revision_from_records_and_policy_bindings(
        provider_profile_catalog,
        provider_records,
        &policy_credential_bindings,
        policy
            .as_ref()
            .filter(|_| matches!(policy_source, PolicySource::Global)),
    )?;

    Ok(GetSandboxConfigResponse {
        configuration_instance_id: sandbox
            .status
            .as_ref()
            .and_then(|status| status.configuration_admission.as_ref())
            .map_or_else(String::new, |admission| admission.instance_id.clone()),
        configuration_admitted: policy.is_some() && configuration_error.is_empty(),
        configuration_error,
        policy,
        version,
        policy_hash,
        settings,
        config_revision,
        policy_source: policy_source.into(),
        global_policy_version,
        provider_env_revision,
        supervisor_middleware_services,
        workspace,
        policy_validation_failure_mode: state
            .config
            .policy_validation_failure_mode
            .as_str()
            .to_string(),
        extension_authentication_enabled: state.extension_jwt_issuer.is_some(),
        provider_attachment_epoch: sandbox
            .spec
            .as_ref()
            .map(|spec| spec.provider_attachment_epoch.clone())
            .unwrap_or_default(),
    })
}

/// Whether a build error means the stored configuration is invalid, rather
/// than that the gateway failed to read it.
pub fn is_configuration_error(error: &Status) -> bool {
    matches!(
        error.code(),
        tonic::Code::FailedPrecondition | tonic::Code::InvalidArgument
    )
}

/// The snapshot served to a supervisor whose stored configuration failed
/// validation. A malformed stored candidate must not prevent a supervisor
/// from registering and waiting for repair, and the response never exposes
/// parser payloads or copies malformed policy history.
pub fn not_admitted_sandbox_config(sandbox: &Sandbox, error: &Status) -> GetSandboxConfigResponse {
    GetSandboxConfigResponse {
        configuration_admitted: false,
        configuration_error: super::configuration_failure_diagnostic(error).to_string(),
        configuration_instance_id: sandbox
            .status
            .as_ref()
            .and_then(|status| status.configuration_admission.as_ref())
            .map_or_else(String::new, |admission| admission.instance_id.clone()),
        workspace: sandbox.object_workspace().to_string(),
        ..Default::default()
    }
}

/// Effective policy used to bind provider credentials, from loaded inputs.
///
/// A global policy is the complete effective policy. Dormant sandbox history
/// and specs may predate the current schema, but they must not prevent the
/// valid global policy from being served.
fn provider_binding_policy(
    inputs: &SandboxConfigInputs,
) -> Result<(ProtoSandboxPolicy, PolicySource), Status> {
    let provider_context =
        provider_policy_context_from_records(&inputs.catalog, &inputs.provider_records);
    if let Some(global_policy) = decode_policy_from_global_settings(&inputs.global_settings)? {
        return apply_captured_policy_context(
            provider_context,
            global_policy,
            PolicySource::Global,
        )
        .map(|policy| (policy, PolicySource::Global));
    }

    let policy = if let Some(record) = inputs.latest_policy.as_ref() {
        canonical_policy_record_identity(record)?.0
    } else {
        match inputs
            .sandbox
            .spec
            .as_ref()
            .and_then(|spec| spec.policy.clone())
        {
            Some(policy) => {
                super::validate_and_canonicalize_stored_policy(policy, STORED_POLICY_SOURCE_SPEC)?
            }
            None => ProtoSandboxPolicy::default(),
        }
    };

    apply_captured_policy_context(provider_context, policy, PolicySource::Sandbox)
        .map(|policy| (policy, PolicySource::Sandbox))
}

/// Materialize a privileged provider snapshot from loaded inputs. Omission
/// reasons remain separate from a legitimately empty snapshot.
pub async fn build_provider_environment(
    state: &ServerState,
    inputs: &SandboxConfigInputs,
    supports_static_credential_bindings: bool,
) -> Result<GetSandboxProviderEnvironmentResponse, Status> {
    let sandbox = &inputs.sandbox;
    let sandbox_id = sandbox.object_id().to_string();
    let spec = sandbox
        .spec
        .as_ref()
        .ok_or_else(|| Status::internal("sandbox has no spec"))?;
    let provider_profile_catalog = &inputs.catalog;
    let provider_records = &inputs.provider_records;

    let (effective_policy, policy_source) = provider_binding_policy(inputs)?;
    let policy_credential_bindings =
        policy_static_credential_endpoint_bindings(Some(&effective_policy))?;
    validate_policy_credential_binding_context(
        provider_profile_catalog,
        provider_records,
        &effective_policy,
        &policy_credential_bindings,
    )?;
    let provider_env_revision = compute_provider_env_revision_from_records_and_policy_bindings(
        provider_profile_catalog,
        provider_records,
        &policy_credential_bindings,
        matches!(policy_source, PolicySource::Global).then_some(&effective_policy),
    )?;
    let mut provider_environment =
        super::super::provider::resolve_provider_environment_from_records_with_policy_bindings_and_credentials(
            provider_profile_catalog,
            provider_records,
            &policy_credential_bindings,
            &state.credentials,
            Some(&sandbox_id),
        )
        .await?;

    if matches!(policy_source, PolicySource::Global) {
        // A global policy replaces provider ACLs. Grants retain their profile
        // destination selectors, but only the selected global endpoint may
        // authorize their use. Keeping every global owner avoids reimplementing
        // host/path intersection here; the relay checks both selectors.
        let mut owners: Vec<_> = effective_policy
            .network_policies
            .values()
            .flat_map(|rule| &rule.endpoints)
            .map(|endpoint| endpoint.token_grant_owner.clone())
            .filter(|owner| !owner.is_empty())
            .collect();
        owners.sort();
        owners.dedup();
        for credential in provider_environment.dynamic_credentials.values_mut() {
            credential.token_grant_owners.clone_from(&owners);
        }
    }

    let mut readiness_reason = provider_environment.readiness_reason;

    if supports_static_credential_bindings {
        let unbound_static_keys = provider_environment
            .static_credential_keys
            .iter()
            .filter(|key| {
                !provider_environment
                    .static_credential_bindings
                    .contains_key(*key)
            })
            .cloned()
            .collect::<Vec<_>>();
        if !unbound_static_keys.is_empty() {
            readiness_reason = ProviderReadinessReason::CredentialsWithheld;
        }
        for key in unbound_static_keys {
            warn!(
                sandbox_id = %sandbox_id,
                key = %key,
                "withholding unbound static provider credential from binding-capable supervisor"
            );
            provider_environment.environment.remove(&key);
            provider_environment
                .credential_expiration_times
                .remove(&key);
            provider_environment.static_credential_keys.remove(&key);
        }
    } else {
        if !provider_environment.static_credential_keys.is_empty() {
            readiness_reason = ProviderReadinessReason::UnsupportedSupervisor;
        }
        for key in &provider_environment.static_credential_keys {
            provider_environment.environment.remove(key);
            provider_environment.credential_expiration_times.remove(key);
        }
        provider_environment.static_credential_bindings.clear();
    }

    info!(
        sandbox_id = %sandbox_id,
        provider_count = spec.providers.len(),
        env_count = provider_environment.environment.len(),
        provider_env_revision,
        "Provider environment snapshot built"
    );

    let non_secret_environment_keys = provider_environment
        .environment
        .keys()
        .filter(|key| !provider_environment.static_credential_keys.contains(*key))
        .cloned()
        .collect();

    let credential_expiration_times = provider_environment
        .credential_expiration_times
        .into_iter()
        .filter_map(|(key, value)| {
            openshell_core::time::optional_timestamp_from_legacy_millis(value)
                .ok()
                .flatten()
                .map(|timestamp| (key, timestamp))
        })
        .collect();
    Ok(GetSandboxProviderEnvironmentResponse {
        environment: provider_environment.environment,
        files: provider_environment.files,
        provider_env_revision,
        credential_expiration_times,
        dynamic_credentials: provider_environment.dynamic_credentials,
        static_credential_bindings: provider_environment.static_credential_bindings,
        non_secret_environment_keys,
        provider_attachment_epoch: spec.provider_attachment_epoch.clone(),
        policy_hash: deterministic_policy_hash(&effective_policy),
        readiness_reason: readiness_reason.into(),
    })
}
