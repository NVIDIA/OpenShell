// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime gateway configuration: applies polled and streamed sandbox
//! configuration and provider environments after startup, and reports apply
//! results back to the gateway.

use std::sync::atomic::AtomicBool;
use std::time::Duration;

use miette::Result;
use openshell_core::PolicyValidationFailureMode;
use openshell_core::proposals::AgentProposals;
use openshell_core::proto::ProviderReadinessReason;
use openshell_ocsf::{ConfigStateChangeBuilder, SeverityId, StateId, StatusId, ocsf_emit};
use openshell_supervisor_network::opa::PolicyGenerationGuard;
use openshell_supervisor_process::skills;
use openshell_supervisor_process::supervisor_session::{
    ConfigApplyRequest, config_admission, config_apply_result, provider_config_revision,
    sandbox_config_revision,
};
use tracing::{debug, info, warn};

use crate::provider_readiness::EnvironmentIdentity;
use crate::{
    CapturedProviderEnvironment, FailedRuntimeRevision, GatewayRuntimeFailureDisposition,
    InitialPollDisposition, LoadedPolicyOrigin, MiddlewareAuthentication,
    MiddlewareRegistryReconciliation, MiddlewareRegistryStatus, MiddlewareReloadContext,
    PolicyGatewayClient, PolicyPollLoopContext, PolicyStatusUpdate, RejectedPolicyGeneration,
    apply_gateway_runtime_reload_failure, apply_policy_validation_failure,
    emit_policy_validation_failure, emit_transparent_tcp_expansion_rejection, endpoint_status,
    enqueue_policy_status, gateway_policy_runtime_needs_reconciliation, initial_poll_disposition,
    middleware_registry_needs_rebuild, next_poll_delay, ocsf_ctx,
    provider_environment_is_installable, reconcile_middleware_registry,
    reload_gateway_configuration_runtime, retain_extension_credentials, run_policy_status_reporter,
    unchanged_policy_revision_candidate, unchanged_policy_revision_ready_to_ack,
};

async fn receive_config_apply(
    receiver: &mut Option<tokio::sync::mpsc::Receiver<ConfigApplyRequest>>,
) -> Option<ConfigApplyRequest> {
    match receiver {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

pub fn config_apply_result_activates(
    result: &openshell_core::proto::ConfigComponentApplyResult,
) -> bool {
    use openshell_core::proto::ConfigApplyOutcome;

    matches!(
        ConfigApplyOutcome::try_from(result.outcome),
        Ok(ConfigApplyOutcome::Applied
            | ConfigApplyOutcome::IgnoredDuplicate
            | ConfigApplyOutcome::RetainedLocalOverride
            | ConfigApplyOutcome::Degraded)
    )
}

fn is_awaiting_component(result: &openshell_core::proto::ConfigComponentApplyResult) -> bool {
    result.outcome == i32::from(openshell_core::proto::ConfigApplyOutcome::AwaitingComponent)
}

/// A provider snapshot staged for its sandbox configuration is applied once
/// that configuration activates with it.
fn provider_applied_with_sandbox(
    provider: openshell_core::proto::ConfigComponentApplyResult,
    sandbox: &openshell_core::proto::ConfigComponentApplyResult,
    provider_consumed: bool,
) -> openshell_core::proto::ConfigComponentApplyResult {
    if is_awaiting_component(&provider)
        && provider_consumed
        && config_apply_result_activates(sandbox)
    {
        config_apply_result(
            openshell_core::proto::ConfigComponent::ProviderEnvironment,
            provider.requested_revision.clone(),
            provider.requested_revision,
            openshell_core::proto::ConfigApplyOutcome::Applied,
            None,
        )
    } else {
        provider
    }
}

/// Session result for a bootstrap, from its component results.
pub fn bootstrap_result(
    provider: Option<openshell_core::proto::ConfigComponentApplyResult>,
    sandbox: Option<(
        openshell_core::proto::ConfigComponentApplyResult,
        openshell_core::proto::SandboxConfigurationAdmission,
    )>,
    provider_consumed: bool,
) -> openshell_core::proto::ConfigBootstrapResult {
    let (sandbox, admission) = sandbox.unzip();
    let provider = provider.map(|provider| match sandbox.as_ref() {
        Some(sandbox) => provider_applied_with_sandbox(provider, sandbox, provider_consumed),
        None => provider,
    });
    openshell_core::proto::ConfigBootstrapResult {
        results: provider.into_iter().chain(sandbox).collect(),
        admission,
    }
}

#[derive(Debug)]
struct RejectedStreamSandbox {
    configuration_instance_id: String,
    requested_revision: openshell_core::proto::ConfigSnapshotRevision,
    environment: EnvironmentIdentity,
    error: String,
    failure_mode: PolicyValidationFailureMode,
    result: openshell_core::proto::ConfigComponentApplyResult,
}

impl RejectedStreamSandbox {
    fn matches(
        &self,
        snapshot: &openshell_core::grpc_client::SettingsPollResult,
        requested_revision: &openshell_core::proto::ConfigSnapshotRevision,
        environment: &EnvironmentIdentity,
    ) -> bool {
        self.configuration_instance_id == snapshot.configuration_instance_id
            && self.requested_revision == *requested_revision
            && self.environment == *environment
            && self.error == snapshot.configuration_error
            && self.failure_mode == snapshot.policy_validation_failure_mode
    }
}

/// Snapshots delivered over the supervisor session. Each component arrives
/// separately, so a sandbox configuration and the provider environment it
/// names wait for each other before either is installed.
#[derive(Default)]
struct StreamConfigurationState {
    /// Provider environment installed from the last activated delivery.
    active_environment: EnvironmentIdentity,
    /// Provider snapshot waiting for its matching sandbox configuration.
    pending_provider: Option<CapturedProviderEnvironment>,
    /// Sandbox configuration waiting for its matching provider snapshot.
    pending_sandbox: Option<Box<openshell_core::grpc_client::SettingsPollResult>>,
    /// Last rejected configuration, so a redelivery does not quarantine the
    /// runtime again.
    rejected_sandbox: Option<Box<RejectedStreamSandbox>>,
    /// Startup configuration whose middleware could not connect. A poll
    /// retries the registry on every interval; session delivery has no later
    /// snapshot to carry that retry, so the idle loop retries this one until
    /// it connects or a later configuration reconciles.
    degraded_startup: Option<Box<openshell_core::grpc_client::SettingsPollResult>>,
}

/// Where a reconciled sandbox configuration's provider environment comes from.
enum ProviderSource {
    /// Policy polling fetches the environment when the requested one changed
    /// or the last installation needs a retry.
    Fetch,
    /// Session delivery already staged the matching environment, or `None`
    /// when the installed environment matches.
    Delivered(Option<CapturedProviderEnvironment>),
}

/// Why a sandbox configuration snapshot was not activated.
struct ConfigRejection {
    /// Stable failure code reported on the supervisor session.
    code: &'static str,
    /// Diagnostic reported on the supervisor session.
    detail: String,
    /// Error reported with the rejected configuration admission.
    admission_error: String,
}

enum ReconcileOutcome {
    /// The runtime already enforces the snapshot.
    Unchanged,
    /// The runtime now enforces the snapshot.
    Applied,
    Rejected(ConfigRejection),
}

struct Reconciled {
    outcome: ReconcileOutcome,
    /// Policy load status for `ReportPolicyStatus`. Session delivery reports
    /// the same status through its acknowledgement instead.
    policy_status: Option<PolicyStatusUpdate>,
}

impl Reconciled {
    fn rejected(code: &'static str, detail: String, admission_error: String) -> Self {
        Self {
            outcome: ReconcileOutcome::Rejected(ConfigRejection {
                code,
                detail,
                admission_error,
            }),
            policy_status: None,
        }
    }
}

/// Configuration the supervisor runtime has applied.
///
/// Policy polling and session delivery share this state and one reconcile
/// path. They differ only in where snapshots and provider environments come
/// from and in how results reach the gateway.
struct ConfigRuntime {
    reloads_gateway_policy: bool,
    config_revision: u64,
    /// Last applied sandbox revision. A failed delivery reports it as the
    /// retained revision while its policy remains enforced.
    applied_revision: Option<openshell_core::proto::ConfigSnapshotRevision>,
    provider_env_revision: u64,
    policy_version: u32,
    policy_hash: String,
    policy_generation: Option<PolicyGenerationGuard>,
    endpoint_policy: Option<openshell_core::proto::SandboxPolicy>,
    middleware_services: Vec<openshell_core::proto::SupervisorMiddlewareService>,
    extension_authentication_enabled: bool,
    middleware_registry_status: MiddlewareRegistryStatus,
    settings: std::collections::HashMap<String, openshell_core::proto::EffectiveSetting>,
    last_failed_runtime_revision: Option<FailedRuntimeRevision>,
    rejected_policy_generation: Option<RejectedPolicyGeneration>,
    has_last_valid_policy: bool,
    stream: StreamConfigurationState,
}

impl ConfigRuntime {
    /// Seed the trackers from startup. A stream bootstrap already initialized
    /// the runtime, so an admitted one is treated as applied.
    fn new(
        ctx: &PolicyPollLoopContext,
        initial: Option<&openshell_core::grpc_client::SettingsPollResult>,
    ) -> Self {
        let admitted = initial.filter(|snapshot| snapshot.configuration_admitted);
        let reloads_gateway_policy = ctx.loaded_policy_origin.allows_gateway_policy_reload();
        Self {
            reloads_gateway_policy,
            config_revision: initial.map_or(0, |snapshot| snapshot.config_revision),
            applied_revision: admitted
                .filter(|_| reloads_gateway_policy)
                .map(sandbox_config_revision),
            provider_env_revision: ctx.provider_credentials.snapshot().revision,
            policy_version: admitted.map_or(0, |snapshot| snapshot.version),
            policy_hash: admitted.map_or_else(String::new, |snapshot| snapshot.policy_hash.clone()),
            policy_generation: None,
            endpoint_policy: ctx.endpoint_policy.clone(),
            middleware_services: admitted.map_or_else(Vec::new, |snapshot| {
                snapshot.supervisor_middleware_services.clone()
            }),
            extension_authentication_enabled: admitted
                .map_or(ctx.extension_authentication_enabled, |snapshot| {
                    snapshot.extension_authentication_enabled
                }),
            middleware_registry_status: ctx.middleware_registry_status,
            settings: admitted.map_or_else(std::collections::HashMap::new, |snapshot| {
                snapshot.settings.clone()
            }),
            last_failed_runtime_revision: None,
            rejected_policy_generation: None,
            has_last_valid_policy: ctx.loaded_policy_origin.has_last_valid_policy(),
            stream: StreamConfigurationState {
                active_environment: admitted
                    .map(EnvironmentIdentity::from_settings)
                    .unwrap_or_default(),
                degraded_startup: admitted
                    .filter(|_| {
                        ctx.middleware_registry_status
                            == MiddlewareRegistryStatus::NeedsReconciliation
                    })
                    .map(|snapshot| Box::new(snapshot.clone())),
                ..StreamConfigurationState::default()
            },
        }
    }

    /// Bring the runtime to one sandbox configuration snapshot.
    ///
    /// The caller reports the outcome, then records an applied snapshot with
    /// [`Self::commit`]. A failed report leaves it to be reconciled again.
    async fn reconcile<C: PolicyGatewayClient>(
        &mut self,
        ctx: &PolicyPollLoopContext,
        client: &C,
        result: &openshell_core::grpc_client::SettingsPollResult,
        provider: ProviderSource,
    ) -> Result<Reconciled> {
        use openshell_core::proto::PolicySource;
        use std::sync::atomic::Ordering;

        let reloads_gateway_policy = self.reloads_gateway_policy;
        let mut policy_status = None;

        // Reuse installed per-service credentials, rotating only when one is
        // missing or due. Rotation happens on the existing gateway channel and
        // updates slots in place, so it is independent of config revision and
        // registry equality.
        let middleware_credentials = if result.extension_authentication_enabled {
            match client
                .extension_credentials_for(&result.supervisor_middleware_services)
                .await
            {
                Ok(credentials) => credentials,
                Err(error) => {
                    warn!(error = %error, "Settings poll: extension credential refresh failed");
                    std::collections::HashMap::new()
                }
            }
        } else {
            std::collections::HashMap::new()
        };

        if reloads_gateway_policy && !result.configuration_admitted {
            let disposition = apply_policy_validation_failure(
                &ctx.opa_engine,
                result.policy_validation_failure_mode,
                self.has_last_valid_policy,
                result.version,
                &result.configuration_error,
            )?;
            emit_policy_validation_failure(
                &disposition,
                result.version,
                &result.policy_hash,
                &result.configuration_error,
            );
            self.rejected_policy_generation = Some(RejectedPolicyGeneration {
                version: result.version,
                policy_hash: result.policy_hash.clone(),
                validation_error: result.configuration_error.clone(),
                configured_mode: result.policy_validation_failure_mode,
            });
            return Ok(Reconciled::rejected(
                "configuration_rejected",
                result.configuration_error.clone(),
                result.configuration_error.clone(),
            ));
        }

        let config_changed = result.config_revision != self.config_revision;
        let desired_identity = EnvironmentIdentity::from_settings(result);
        let provider_env_changed = match &provider {
            ProviderSource::Fetch => {
                result.provider_env_revision != self.provider_env_revision
                    || ctx.provider_readiness.needs_environment(&desired_identity)
            }
            ProviderSource::Delivered(provider) => provider.is_some(),
        };
        let policy_changed = result.policy_hash != self.policy_hash;
        let extension_authentication_changed =
            self.extension_authentication_enabled != result.extension_authentication_enabled;
        let middleware_registry_changed = extension_authentication_changed
            || middleware_registry_needs_rebuild(
                self.middleware_registry_status,
                &self.middleware_services,
                &result.supervisor_middleware_services,
            );
        // A valid candidate may intentionally restore byte-for-byte policy
        // content that was active before a rejected update. Its hash then
        // equals `policy_hash`, but the runtime is still quarantined and must
        // reload (or it would remain deny-all indefinitely).
        let recovering_rejected_policy = reloads_gateway_policy
            && self.rejected_policy_generation.is_some()
            && result.configuration_admitted;
        let policy_runtime_changed = (reloads_gateway_policy
            && (provider_env_changed
                || self
                    .policy_generation
                    .as_ref()
                    .is_some_and(PolicyGenerationGuard::is_stale)))
            || recovering_rejected_policy
            || extension_authentication_changed
            || gateway_policy_runtime_needs_reconciliation(
                reloads_gateway_policy,
                &self.policy_hash,
                &result.policy_hash,
                &self.middleware_services,
                &result.supervisor_middleware_services,
                self.middleware_registry_status,
            );
        // Recovery already has its own acknowledgement path below. Giving it
        // precedence here prevents a restored last-known-good policy from
        // also being acknowledged as an ordinary same-hash revision.
        let unchanged_policy_revision = unchanged_policy_revision_candidate(
            reloads_gateway_policy,
            recovering_rejected_policy,
            self.policy_version,
            &self.policy_hash,
            result,
        );
        let mut policy_runtime_reconciled = false;

        // A local policy override is not coupled to the gateway policy
        // snapshot, so its service registry can still be reconciled alone.
        // Gateway policy snapshots, however, must install policy and registry
        // as one generation below.
        if !reloads_gateway_policy {
            reconcile_middleware_registry(
                &ctx.opa_engine,
                &ctx.middleware_connector,
                MiddlewareRegistryReconciliation {
                    desired_services: &result.supervisor_middleware_services,
                    authentication: MiddlewareAuthentication {
                        credentials: middleware_credentials.clone(),
                        enabled: result.extension_authentication_enabled,
                    },
                    registry_changed: middleware_registry_changed,
                    extension_credentials: &ctx.extension_credentials,
                    current_services: &mut self.middleware_services,
                    status: &mut self.middleware_registry_status,
                },
            )
            .await;
            if self.middleware_registry_status == MiddlewareRegistryStatus::Synchronized {
                self.extension_authentication_enabled = result.extension_authentication_enabled;
            }
        }

        if !config_changed
            && !provider_env_changed
            && !policy_runtime_changed
            && unchanged_policy_revision.is_none()
        {
            return Ok(Reconciled {
                outcome: ReconcileOutcome::Unchanged,
                policy_status: None,
            });
        }

        if config_changed || provider_env_changed {
            // Log which settings changed.
            log_setting_changes(&self.settings, &result.settings);

            // A posture change after a rejected update takes effect immediately.
            // The compiled last-known-good engine remains available beneath a
            // fail-closed quarantine, so an explicit retain_last_valid selection
            // can reactivate it without accepting any part of the invalid policy.
            if !policy_changed && let Some(rejected) = self.rejected_policy_generation.as_mut() {
                let mode = result.policy_validation_failure_mode;
                if mode != rejected.configured_mode {
                    let disposition = apply_policy_validation_failure(
                        &ctx.opa_engine,
                        mode,
                        self.has_last_valid_policy,
                        rejected.version,
                        &rejected.validation_error,
                    )?;
                    emit_policy_validation_failure(
                        &disposition,
                        rejected.version,
                        &rejected.policy_hash,
                        &rejected.validation_error,
                    );
                    rejected.configured_mode = mode;
                }
            }

            ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .state(StateId::Other, "detected")
                .unmapped("old_config_revision", serde_json::json!(self.config_revision))
                .unmapped("new_config_revision", serde_json::json!(result.config_revision))
                .unmapped("policy_changed", serde_json::json!(policy_changed))
                .unmapped("provider_env_changed", serde_json::json!(provider_env_changed))
                .message(format!(
                    "Settings poll: config change detected [old_revision:{} new_revision:{} policy_changed:{policy_changed} provider_env_changed:{provider_env_changed}]",
                    self.config_revision,
                    result.config_revision
                ))
                .build());
        }

        // Prepare the matching environment before activation. Failed refreshes
        // revoke static credentials while preserving independently bound dynamic grants.
        let prepared_provider = match provider {
            _ if !provider_env_changed => None,
            ProviderSource::Fetch => {
                match self
                    .fetch_provider_environment(ctx, client, result, &desired_identity)
                    .await
                {
                    Ok(prepared) => Some(prepared),
                    Err(rejection) => {
                        return Ok(Reconciled {
                            outcome: ReconcileOutcome::Rejected(rejection),
                            policy_status: None,
                        });
                    }
                }
            }
            ProviderSource::Delivered(provider) => provider,
        };

        let mut runtime_error = String::new();
        if policy_runtime_changed {
            let pid = ctx.entrypoint_pid.load(Ordering::Acquire);
            let runtime_result = reload_gateway_configuration_runtime(
                &ctx.opa_engine,
                result.policy.as_ref(),
                pid,
                MiddlewareReloadContext {
                    desired_services: &result.supervisor_middleware_services,
                    authentication: &MiddlewareAuthentication {
                        credentials: middleware_credentials.clone(),
                        enabled: result.extension_authentication_enabled,
                    },
                    registry_changed: middleware_registry_changed,
                    connector: &ctx.middleware_connector,
                },
                ctx.transparent_tcp,
                ctx.vm_identity,
                || {
                    if let Some(prepared) = prepared_provider.as_ref() {
                        ctx.provider_credentials
                            .install_prepared(&prepared.credentials);
                    }
                },
            )
            .await;

            match runtime_result {
                Ok(generation) => {
                    policy_runtime_reconciled = true;
                    if let Some(prepared) = prepared_provider.as_ref() {
                        ctx.provider_readiness.credentials_installed(
                            prepared.identity.clone(),
                            &ctx.provider_credentials,
                            prepared.expires_at_ms,
                        );
                    }
                    ctx.provider_readiness.policy_activated(
                        &desired_identity,
                        result.config_revision,
                        generation.clone(),
                    );
                    self.policy_generation = Some(generation);
                    let policy = result
                        .policy
                        .as_ref()
                        .expect("successful runtime reload requires a policy payload");
                    self.has_last_valid_policy = true;
                    self.rejected_policy_generation = None;
                    if policy_changed {
                        if let Some(policy_local_ctx) = ctx.policy_local_ctx.as_ref() {
                            policy_local_ctx.set_current_policy(policy.clone()).await;
                        }
                        if result.global_policy_version > 0 {
                            ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                                .severity(SeverityId::Informational)
                                .status(StatusId::Success)
                                .state(StateId::Enabled, "loaded")
                                .unmapped("policy_hash", serde_json::json!(&result.policy_hash))
                                .unmapped("global_version", serde_json::json!(result.global_policy_version))
                                .message(format!(
                                    "Policy reloaded successfully (global) [policy_hash:{} global_version:{}]",
                                    result.policy_hash,
                                    result.global_policy_version
                                ))
                                .build());
                        } else {
                            ocsf_emit!(
                                ConfigStateChangeBuilder::new(ocsf_ctx())
                                    .severity(SeverityId::Informational)
                                    .status(StatusId::Success)
                                    .state(StateId::Enabled, "loaded")
                                    .unmapped("policy_hash", serde_json::json!(&result.policy_hash))
                                    .message(format!(
                                        "Policy reloaded successfully [policy_hash:{}]",
                                        result.policy_hash
                                    ))
                                    .build()
                            );
                        }
                        if result.version > 0 && result.policy_source == PolicySource::Sandbox {
                            policy_status = Some(PolicyStatusUpdate::loaded(result.version));
                            self.policy_version = result.version;
                        }
                    } else if recovering_rejected_policy
                        && result.version > 0
                        && result.policy_source == PolicySource::Sandbox
                    {
                        ocsf_emit!(
                            ConfigStateChangeBuilder::new(ocsf_ctx())
                                .severity(SeverityId::Informational)
                                .status(StatusId::Success)
                                .state(StateId::Enabled, "loaded")
                                .unmapped("policy_hash", serde_json::json!(&result.policy_hash))
                                .message(format!(
                                    "Policy reloaded successfully and fail-closed quarantine cleared [policy_hash:{}]",
                                    result.policy_hash
                                ))
                                .build()
                        );
                        policy_status = Some(PolicyStatusUpdate::loaded(result.version));
                        self.policy_version = result.version;
                    }

                    if middleware_registry_changed {
                        ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                            .severity(SeverityId::Informational)
                            .status(StatusId::Success)
                            .state(StateId::Enabled, "loaded")
                            .unmapped(
                                "supervisor_middleware_service_count",
                                serde_json::json!(result.supervisor_middleware_services.len())
                            )
                            .message(format!(
                                "Supervisor policy runtime reloaded atomically [service_count:{}]",
                                result.supervisor_middleware_services.len()
                            ))
                            .build());
                    }

                    self.policy_hash.clone_from(&result.policy_hash);
                    self.endpoint_policy.clone_from(&result.policy);
                    self.middleware_services
                        .clone_from(&result.supervisor_middleware_services);
                    self.extension_authentication_enabled = result.extension_authentication_enabled;
                    retain_extension_credentials(
                        &ctx.extension_credentials,
                        &result.supervisor_middleware_services,
                        result.extension_authentication_enabled,
                    );
                    self.middleware_registry_status = MiddlewareRegistryStatus::Synchronized;
                    self.last_failed_runtime_revision = None;
                }
                Err(failure) => {
                    runtime_error = failure.to_string();
                    ctx.provider_readiness
                        .policy_install_failed(desired_identity.clone(), result.config_revision);
                    let failed_revision = FailedRuntimeRevision::new(
                        result.config_revision,
                        &result.policy_hash,
                        &failure,
                    );
                    if self.last_failed_runtime_revision.as_ref() != Some(&failed_revision) {
                        let failure_mode = result.policy_validation_failure_mode;
                        match apply_gateway_runtime_reload_failure(
                            &ctx.opa_engine,
                            failure,
                            failure_mode,
                            self.has_last_valid_policy,
                            result.version,
                        )? {
                            GatewayRuntimeFailureDisposition::PolicyRejected {
                                error,
                                disposition,
                            } => {
                                emit_policy_validation_failure(
                                    &disposition,
                                    result.version,
                                    &result.policy_hash,
                                    &error,
                                );
                                self.rejected_policy_generation = Some(RejectedPolicyGeneration {
                                    version: result.version,
                                    policy_hash: result.policy_hash.clone(),
                                    validation_error: error.clone(),
                                    configured_mode: failure_mode,
                                });
                                if policy_changed
                                    && result.version > 0
                                    && result.policy_source == PolicySource::Sandbox
                                {
                                    policy_status =
                                        Some(PolicyStatusUpdate::failed(result.version, error));
                                }
                            }
                            GatewayRuntimeFailureDisposition::MiddlewareUnavailable { error } => {
                                ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                                    .severity(SeverityId::Medium)
                                    .status(StatusId::Failure)
                                    .state(StateId::Other, "failed")
                                    .unmapped("version", serde_json::json!(result.version))
                                    .unmapped("error", serde_json::json!(&error))
                                    .unmapped("previous_policy_active", serde_json::json!(true))
                                    .message(format!(
                                        "Supervisor middleware registry unavailable, keeping last-known-good policy runtime active [version:{} error:{error}]",
                                        result.version
                                    ))
                                    .build());
                            }
                            GatewayRuntimeFailureDisposition::TransparentTcpExpansionRejected {
                                error,
                                active_generation,
                            } => {
                                emit_transparent_tcp_expansion_rejection(
                                    result.version,
                                    &result.policy_hash,
                                    active_generation,
                                    &error,
                                );
                                if policy_changed
                                    && result.version > 0
                                    && result.policy_source == PolicySource::Sandbox
                                {
                                    policy_status =
                                        Some(PolicyStatusUpdate::failed(result.version, error));
                                }
                            }
                        }
                    }
                    self.last_failed_runtime_revision = Some(failed_revision);
                    // Nothing was installed, so the registry status still
                    // describes the live registry. The retry is driven by the
                    // persisting hash/service-set mismatch (or an existing
                    // NeedsReconciliation), not by degrading the status here.
                }
            }
        }

        if policy_runtime_changed && !policy_runtime_reconciled {
            return Ok(Reconciled {
                outcome: ReconcileOutcome::Rejected(ConfigRejection {
                    code: "runtime_apply_failed",
                    detail: runtime_error,
                    admission_error: "Effective configuration failed runtime preparation; prior credentials remain installed".to_string(),
                }),
                policy_status,
            });
        }
        if !reloads_gateway_policy && let Some(prepared) = prepared_provider.as_ref() {
            ctx.provider_credentials
                .install_prepared(&prepared.credentials);
            ctx.provider_readiness.credentials_installed(
                prepared.identity.clone(),
                &ctx.provider_credentials,
                prepared.expires_at_ms,
            );
        }
        if provider_env_changed || policy_runtime_reconciled {
            self.provider_env_revision = result.provider_env_revision;
        }

        if let Some(version) = unchanged_policy_revision_ready_to_ack(
            unchanged_policy_revision,
            policy_runtime_changed,
            policy_runtime_reconciled,
        ) {
            policy_status = Some(PolicyStatusUpdate::unchanged_loaded(
                version,
                result.policy_hash.clone(),
            ));
            self.policy_version = version;
        }

        if reloads_gateway_policy
            && !policy_runtime_changed
            && let Some(generation) = self
                .policy_generation
                .as_ref()
                .filter(|generation| !generation.is_stale())
        {
            // The same installed policy may serve a new attachment/configuration
            // identity. Its generation is retained, never inferred from a cursor.
            ctx.provider_readiness.policy_activated(
                &desired_identity,
                result.config_revision,
                generation.clone(),
            );
        }

        if policy_runtime_reconciled || provider_env_changed {
            endpoint_status::reset(
                ctx.endpoint_observation_tx.as_ref(),
                self.endpoint_policy.as_ref(),
                &self.policy_hash,
                ctx.provider_credentials.snapshot().revision,
            )
            .await;
        }

        // Apply OCSF JSON toggle from the `ocsf_json_enabled` setting.
        apply_ocsf_json_setting(&ctx.ocsf_enabled, &result.settings);
        apply_ocsf_schema_version_setting(&ctx.ocsf_schema_version, &result.settings);

        // Apply the agent-proposals feature toggle. On a false→true transition
        // we lazily install the skill so a sandbox that started with the flag
        // off picks up the surface without a recreate. We never uninstall on
        // a true→false transition: stale skill content on disk is harmless
        // because route_request and agent_next_steps both gate on the live
        // shared flag, so the agent that reads the skill will see 404s and an
        // empty `next_steps` array regardless.
        apply_agent_proposals_enabled(
            &ctx.agent_proposals,
            agent_proposals_enabled_from_settings(&result.settings),
            "settings poll",
            Some(result.config_revision),
            skills::install_static_skills,
        );

        Ok(Reconciled {
            outcome: ReconcileOutcome::Applied,
            policy_status,
        })
    }

    /// Record a reconciled snapshot as applied.
    fn commit(&mut self, result: openshell_core::grpc_client::SettingsPollResult) {
        if self.reloads_gateway_policy {
            self.applied_revision = Some(sandbox_config_revision(&result));
        }
        self.config_revision = result.config_revision;
        if !self.reloads_gateway_policy {
            self.policy_hash = result.policy_hash;
        }
        self.settings = result.settings;
    }

    /// Fetch and prepare the provider environment a polled snapshot requests.
    async fn fetch_provider_environment<C: PolicyGatewayClient>(
        &self,
        ctx: &PolicyPollLoopContext,
        client: &C,
        result: &openshell_core::grpc_client::SettingsPollResult,
        desired_identity: &EnvironmentIdentity,
    ) -> std::result::Result<CapturedProviderEnvironment, ConfigRejection> {
        ctx.provider_readiness.credentials_failed(
            desired_identity.clone(),
            ProviderReadinessReason::WaitingForCredentials,
        );
        let provider = match client
            .fetch_provider_environment(&ctx.endpoint, &ctx.sandbox_id)
            .await
        {
            Ok(provider)
                if EnvironmentIdentity::from_environment(&provider) == *desired_identity
                    && provider_environment_is_installable(provider.readiness_reason) =>
            {
                provider
            }
            failed => {
                let reason = match failed {
                    Ok(provider)
                        if provider.readiness_reason != ProviderReadinessReason::Unspecified =>
                    {
                        provider.readiness_reason
                    }
                    Ok(_) => ProviderReadinessReason::SnapshotMismatch,
                    Err(_) => ProviderReadinessReason::CredentialInstallFailed,
                };
                self.revoke_provider_environment(
                    ctx,
                    desired_identity.clone(),
                    reason,
                    result.provider_env_revision,
                )
                .await;
                let error = "Provider environment is unavailable or changed during preparation";
                return Err(ConfigRejection {
                    code: "provider_environment_unavailable",
                    detail: error.to_string(),
                    admission_error: error.to_string(),
                });
            }
        };
        if let Ok(prepared) = CapturedProviderEnvironment::prepare(&provider) {
            return Ok(prepared);
        }
        self.reject_provider_bindings(ctx, desired_identity.clone(), provider)
            .await;
        let error = "Provider environment bindings failed validation";
        Err(ConfigRejection {
            code: "invalid_provider_environment",
            detail: error.to_string(),
            admission_error: error.to_string(),
        })
    }

    /// Revoke static provider credentials after the requested environment
    /// could not be obtained. Previous dynamic grants remain active.
    async fn revoke_provider_environment(
        &self,
        ctx: &PolicyPollLoopContext,
        identity: EnvironmentIdentity,
        reason: ProviderReadinessReason,
        revision: u64,
    ) {
        ctx.provider_readiness.credentials_failed(identity, reason);
        ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
            .severity(SeverityId::High)
            .status(StatusId::Failure)
            .state(StateId::Disabled, "fail_closed")
            .message("Provider environment refresh failed; static credentials were revoked and previous dynamic grants remain active")
            .build());
        ctx.provider_credentials
            .revoke_static_provider_environment(revision);
        endpoint_status::reset(
            ctx.endpoint_observation_tx.as_ref(),
            self.endpoint_policy.as_ref(),
            &self.policy_hash,
            revision,
        )
        .await;
    }

    /// Revoke static credentials whose bindings failed validation while
    /// keeping the environment's dynamic grants.
    async fn reject_provider_bindings(
        &self,
        ctx: &PolicyPollLoopContext,
        identity: EnvironmentIdentity,
        provider: openshell_core::grpc_client::ProviderEnvironmentResult,
    ) {
        ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
            .severity(SeverityId::High)
            .status(StatusId::Failure)
            .state(StateId::Disabled, "fail_closed")
            .message("Provider environment bindings failed validation; static credentials were revoked and fetched dynamic grants remain active")
            .build());
        ctx.provider_readiness
            .credentials_failed(identity, ProviderReadinessReason::CredentialInstallFailed);
        let revision = provider.provider_env_revision;
        // Repeat the rejected binding validation on the live state to
        // revoke static material and retain the fetched dynamic grants.
        let _ = ctx.provider_credentials.install_bound_environment(
            provider.provider_env_revision,
            provider.environment,
            provider.credential_expires_at_ms,
            provider.dynamic_credentials,
            provider.static_credential_bindings,
            provider.non_secret_environment_keys,
        );
        endpoint_status::reset(
            ctx.endpoint_observation_tx.as_ref(),
            self.endpoint_policy.as_ref(),
            &self.policy_hash,
            revision,
        )
        .await;
    }

    /// Apply one payload delivered over the supervisor session and answer it.
    async fn apply_delivered<C: PolicyGatewayClient>(
        &mut self,
        ctx: &PolicyPollLoopContext,
        client: &C,
        request: ConfigApplyRequest,
    ) {
        use openshell_core::proto::config_update;

        match request {
            ConfigApplyRequest::Bootstrap {
                bootstrap,
                response,
            } => {
                let provider = match bootstrap.provider_environment {
                    Some(snapshot) => Some(self.stage_delivered_provider(ctx, snapshot).await),
                    None => None,
                };
                let sandbox = match bootstrap.sandbox_config {
                    Some(snapshot) => Some(
                        self.apply_delivered_sandbox(ctx, client, snapshot.into())
                            .await,
                    ),
                    None => None,
                };
                let _ = response.send(bootstrap_result(
                    provider,
                    sandbox,
                    self.stream.pending_provider.is_none(),
                ));
            }
            ConfigApplyRequest::Update { update, response } => {
                let (result, admission) = match update.component {
                    Some(config_update::Component::SandboxConfig(snapshot)) => {
                        let (result, admission) = self
                            .apply_delivered_sandbox(ctx, client, snapshot.into())
                            .await;
                        (result, Some(admission))
                    }
                    Some(config_update::Component::ProviderEnvironment(snapshot)) => {
                        let mut result = self.stage_delivered_provider(ctx, snapshot).await;
                        if is_awaiting_component(&result)
                            && let Some(sandbox) = self.stream.pending_sandbox.take()
                        {
                            let (sandbox_result, _) =
                                self.apply_delivered_sandbox(ctx, client, *sandbox).await;
                            result = provider_applied_with_sandbox(
                                result,
                                &sandbox_result,
                                self.stream.pending_provider.is_none(),
                            );
                        }
                        (result, None)
                    }
                    None => (
                        config_apply_result(
                            openshell_core::proto::ConfigComponent::Unspecified,
                            None,
                            None,
                            openshell_core::proto::ConfigApplyOutcome::Unsupported,
                            Some((
                                "unsupported_component",
                                "configuration update has no supported component",
                                false,
                            )),
                        ),
                        None,
                    ),
                };
                let _ = response.send(openshell_core::proto::ConfigUpdateResult {
                    update_id: update.update_id,
                    component_sequence: update.component_sequence,
                    result: Some(result),
                    admission,
                });
            }
        }
    }

    /// Apply a delivered sandbox configuration. Unless the provider
    /// environment it names is installed, it waits for that snapshot.
    async fn apply_delivered_sandbox<C: PolicyGatewayClient>(
        &mut self,
        ctx: &PolicyPollLoopContext,
        client: &C,
        snapshot: openshell_core::grpc_client::SettingsPollResult,
    ) -> (
        openshell_core::proto::ConfigComponentApplyResult,
        openshell_core::proto::SandboxConfigurationAdmission,
    ) {
        use openshell_core::proto::{ConfigApplyOutcome, ConfigComponent};

        let requested_revision = sandbox_config_revision(&snapshot);
        let desired_environment = EnvironmentIdentity::from_settings(&snapshot);
        let provider = if !snapshot.configuration_admitted {
            // A rejected generation supersedes one waiting for its provider.
            self.stream.pending_sandbox = None;
            if self.reloads_gateway_policy
                && let Some(rejected) = self.stream.rejected_sandbox.as_ref()
                && rejected.matches(&snapshot, &requested_revision, &desired_environment)
            {
                return (rejected.result.clone(), config_admission(&snapshot, false));
            }
            None
        } else if desired_environment == self.stream.active_environment {
            None
        } else if let Some(provider) = self
            .stream
            .pending_provider
            .as_ref()
            .filter(|provider| provider.identity == desired_environment)
        {
            Some(provider.clone())
        } else {
            let admission = config_admission(&snapshot, false);
            self.stream.pending_sandbox = Some(Box::new(snapshot));
            return (
                config_apply_result(
                    ConfigComponent::SandboxConfig,
                    Some(requested_revision),
                    None,
                    ConfigApplyOutcome::AwaitingComponent,
                    None,
                ),
                admission,
            );
        };

        // Once a later configuration reconciles, its result governs the
        // runtime. The startup retry must never reinstall the startup
        // configuration over it or lift a quarantine it established.
        if self
            .stream
            .degraded_startup
            .as_deref()
            .is_some_and(|startup| sandbox_config_revision(startup) != requested_revision)
        {
            self.stream.degraded_startup = None;
        }
        let consumes_provider = provider.is_some();
        let rejection = match self
            .reconcile(ctx, client, &snapshot, ProviderSource::Delivered(provider))
            .await
        {
            Ok(Reconciled {
                outcome: ReconcileOutcome::Rejected(rejection),
                ..
            }) => rejection,
            Ok(Reconciled { outcome, .. }) => {
                if consumes_provider {
                    self.stream.active_environment = desired_environment;
                    self.stream.pending_provider = None;
                }
                self.stream.pending_sandbox = None;
                self.stream.rejected_sandbox = None;
                self.stream.degraded_startup = None;
                let _ = ctx.workspace_tx.send(snapshot.workspace.clone());
                let (outcome, applied_revision) = if !self.reloads_gateway_policy {
                    (ConfigApplyOutcome::RetainedLocalOverride, None)
                } else if matches!(outcome, ReconcileOutcome::Unchanged) {
                    (
                        ConfigApplyOutcome::IgnoredDuplicate,
                        Some(requested_revision.clone()),
                    )
                } else {
                    (
                        ConfigApplyOutcome::Applied,
                        Some(requested_revision.clone()),
                    )
                };
                let admission = config_admission(&snapshot, true);
                self.commit(snapshot);
                let result = config_apply_result(
                    ConfigComponent::SandboxConfig,
                    Some(requested_revision),
                    applied_revision,
                    outcome,
                    None,
                );
                return (result, admission);
            }
            Err(error) => {
                // Polling ends its loop on this error; session delivery
                // reports it instead, so record it here.
                ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::High)
                    .status(StatusId::Failure)
                    .state(StateId::Other, "failed")
                    .unmapped("config_revision", serde_json::json!(snapshot.config_revision))
                    .unmapped("policy_hash", serde_json::json!(&snapshot.policy_hash))
                    .message(format!(
                        "Pushed sandbox configuration failed to apply [config_revision:{} error:{error}]",
                        snapshot.config_revision
                    ))
                    .build());
                let result = config_apply_result(
                    ConfigComponent::SandboxConfig,
                    Some(requested_revision),
                    None,
                    ConfigApplyOutcome::FailedClosed,
                    Some(("configuration_rejected", &error.to_string(), true)),
                );
                return (result, config_admission(&snapshot, false));
            }
        };

        // The previous revision is retained only while its policy is enforced.
        let retained_revision = self
            .applied_revision
            .clone()
            .filter(|_| ctx.opa_engine.fail_closed_reason().is_none());
        let outcome = match retained_revision.as_ref() {
            // The requested configuration is still the enforced one, so only
            // its runtime upgrade failed, as at a degraded startup.
            Some(retained) if *retained == requested_revision => ConfigApplyOutcome::Degraded,
            Some(_) => ConfigApplyOutcome::FailedRetainedLastKnownGood,
            None => ConfigApplyOutcome::FailedClosed,
        };
        let detail = if rejection.detail.is_empty() {
            "effective configuration was rejected by the gateway"
        } else {
            &rejection.detail
        };
        let (failure, admission) = if outcome == ConfigApplyOutcome::Degraded {
            self.rebind_enforced_generation(ctx, &snapshot);
            (None, config_admission(&snapshot, true))
        } else {
            (
                Some((rejection.code, detail, true)),
                config_admission(&snapshot, false),
            )
        };
        let result = config_apply_result(
            ConfigComponent::SandboxConfig,
            Some(requested_revision.clone()),
            retained_revision,
            outcome,
            failure,
        );
        if !snapshot.configuration_admitted {
            self.stream.rejected_sandbox = Some(Box::new(RejectedStreamSandbox {
                configuration_instance_id: snapshot.configuration_instance_id.clone(),
                requested_revision,
                environment: desired_environment,
                error: snapshot.configuration_error.clone(),
                failure_mode: snapshot.policy_validation_failure_mode,
                result: result.clone(),
            }));
        } else if consumes_provider {
            // Retry when the matching provider snapshot is delivered again.
            self.stream.pending_sandbox = Some(Box::new(snapshot));
        }
        (result, admission)
    }

    /// Stage a delivered provider environment until the sandbox configuration
    /// that names it arrives. An environment that cannot be installed revokes
    /// static credentials, as a failed refresh does when polling.
    async fn stage_delivered_provider(
        &mut self,
        ctx: &PolicyPollLoopContext,
        snapshot: openshell_core::proto::ProviderEnvironmentSnapshot,
    ) -> openshell_core::proto::ConfigComponentApplyResult {
        use openshell_core::proto::{ConfigApplyOutcome, ConfigComponent};

        let requested_revision = provider_config_revision(snapshot.provider_env_revision);
        let identity = EnvironmentIdentity {
            attachment_epoch: snapshot.provider_attachment_epoch.clone(),
            revision: snapshot.provider_env_revision,
            policy_hash: snapshot.policy_hash.clone(),
        };
        if identity == self.stream.active_environment {
            return config_apply_result(
                ConfigComponent::ProviderEnvironment,
                Some(requested_revision.clone()),
                Some(requested_revision),
                ConfigApplyOutcome::IgnoredDuplicate,
                None,
            );
        }
        // A newer component delivery supersedes any older unmatched provider
        // snapshot. Never let a later sandbox delivery commit stale credentials.
        self.stream.pending_provider = None;
        let revision = identity.revision;
        let failure =
            match openshell_core::grpc_client::ProviderEnvironmentResult::try_from(snapshot) {
                Err(error) => {
                    self.revoke_provider_environment(
                        ctx,
                        identity,
                        ProviderReadinessReason::CredentialInstallFailed,
                        revision,
                    )
                    .await;
                    ("invalid_provider_environment", error.to_string(), false)
                }
                Ok(provider) if !provider_environment_is_installable(provider.readiness_reason) => {
                    self.revoke_provider_environment(
                        ctx,
                        identity,
                        provider.readiness_reason,
                        revision,
                    )
                    .await;
                    (
                        "provider_environment_unavailable",
                        "provider environment is not ready for installation".to_string(),
                        true,
                    )
                }
                Ok(provider) => match CapturedProviderEnvironment::prepare(&provider) {
                    Ok(prepared) => {
                        self.stream.pending_provider = Some(prepared);
                        // The provider environment waits for its matching
                        // admitted sandbox configuration.
                        return config_apply_result(
                            ConfigComponent::ProviderEnvironment,
                            Some(requested_revision),
                            None,
                            ConfigApplyOutcome::AwaitingComponent,
                            None,
                        );
                    }
                    Err(error) => {
                        self.reject_provider_bindings(ctx, identity, provider).await;
                        ("invalid_provider_environment", error.to_string(), false)
                    }
                },
            };
        // The revoked credentials no longer match any delivered environment.
        self.stream.active_environment = EnvironmentIdentity::default();
        let (code, message, retryable) = failure;
        config_apply_result(
            ConfigComponent::ProviderEnvironment,
            Some(requested_revision),
            None,
            ConfigApplyOutcome::FailedClosed,
            Some((code, &message, retryable)),
        )
    }

    /// Retry the middleware registry of a startup configuration that could
    /// not reach its services, while it remains the latest one reconciled.
    async fn retry_degraded_startup<C: PolicyGatewayClient>(
        &mut self,
        ctx: &PolicyPollLoopContext,
        client: &C,
    ) {
        let Some(snapshot) = self.stream.degraded_startup.take() else {
            return;
        };
        if let Ok(Reconciled {
            outcome: ReconcileOutcome::Applied | ReconcileOutcome::Unchanged,
            ..
        }) = self
            .reconcile(ctx, client, &snapshot, ProviderSource::Delivered(None))
            .await
        {
            self.commit(*snapshot);
        } else {
            self.rebind_enforced_generation(ctx, &snapshot);
            self.stream.degraded_startup = Some(snapshot);
        }
    }

    /// A failed upgrade of the configuration the runtime already enforces
    /// leaves that configuration active, so readiness stays bound to the
    /// generation that enforces it rather than reporting a failed policy.
    fn rebind_enforced_generation(
        &self,
        ctx: &PolicyPollLoopContext,
        snapshot: &openshell_core::grpc_client::SettingsPollResult,
    ) {
        if let Some(generation) = self
            .policy_generation
            .as_ref()
            .filter(|generation| !generation.is_stale())
        {
            ctx.provider_readiness.policy_activated(
                &EnvironmentIdentity::from_settings(snapshot),
                snapshot.config_revision,
                generation.clone(),
            );
        }
    }
}

pub async fn run_policy_poll_loop(ctx: PolicyPollLoopContext) -> Result<()> {
    let client = openshell_core::grpc_client::CachedOpenShellClient::connect_with_credentials(
        &ctx.endpoint,
        ctx.extension_credentials.clone(),
    )
    .await?;
    run_policy_poll_loop_with_client(ctx, client).await
}

async fn report_runtime_configuration(
    ctx: &PolicyPollLoopContext,
    snapshot: &openshell_core::grpc_client::SettingsPollResult,
    accepted: bool,
    error: &str,
) -> bool {
    let LoadedPolicyOrigin::Gateway {
        revision: Some(revision),
        ..
    } = &ctx.loaded_policy_origin
    else {
        return true;
    };
    let Some(instance_id) = revision.admission_instance_id.as_deref() else {
        return true;
    };
    let state = if accepted {
        openshell_core::proto::ConfigurationAdmissionState::Accepted
    } else {
        openshell_core::proto::ConfigurationAdmissionState::Rejected
    };
    if !accepted {
        ocsf_emit!(
            ConfigStateChangeBuilder::new(ocsf_ctx())
                .severity(SeverityId::High)
                .status(StatusId::Failure)
                .state(StateId::Other, "configuration_error")
                .message(error)
                .build()
        );
    }
    openshell_core::grpc_client::report_sandbox_configuration(
        &ctx.endpoint,
        &ctx.sandbox_id,
        instance_id,
        Some(snapshot),
        state,
        error,
    )
    .await
    .is_ok()
}

async fn run_policy_poll_loop_with_client<C: PolicyGatewayClient>(
    mut ctx: PolicyPollLoopContext,
    client: C,
) -> Result<()> {
    let mut config_apply_rx = ctx.config_apply_rx.take();
    let (status_sender, status_receiver) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(run_policy_status_reporter(
        client.clone(),
        ctx.sandbox_id.clone(),
        status_receiver,
    ));
    if let Some(endpoint_status_receiver) = ctx.endpoint_status_rx.take() {
        tokio::spawn(endpoint_status::run_reporter(
            client.clone(),
            ctx.sandbox_id.clone(),
            endpoint_status_receiver,
            ctx.supervisor_session_id.clone(),
        ));
    }

    let initial_stream_snapshot = ctx.initial_stream_snapshot.take();
    let stream_started = initial_stream_snapshot.is_some();
    // A stream-started runtime stays stream-authoritative only while its
    // current session applies configuration. A reconnect to a gateway that
    // does not enable config push, such as after a rollback to poll mode, resumes
    // polling. Keep the last value if the session task ends.
    let mut config_push_updates = ctx.config_push_enabled.take();
    let mut config_push_enabled = config_push_updates
        .as_ref()
        .is_none_or(|updates| *updates.borrow());
    let mut runtime = ConfigRuntime::new(&ctx, initial_stream_snapshot.as_ref());

    // A first poll that does not match the policy already loaded into OPA must
    // pass through the normal reconciliation path immediately. It must never
    // seed the applied-state trackers before OPA actually loads it.
    let mut pending_result = None;
    // Bind startup evidence before awaiting the gateway. A generation changed
    // during that request no longer proves which policy startup installed.
    let initial_generation = ctx
        .opa_engine
        .generation_guard(ctx.opa_engine.current_generation())
        .ok();

    // Initialize revision from the first poll and acknowledge the initial
    // policy revision the supervisor actually loaded. A mismatched result is
    // reconciled below instead of being recorded as already applied.
    if let Some(snapshot) = initial_stream_snapshot.as_ref() {
        let _ = ctx.workspace_tx.send(snapshot.workspace.clone());
        if snapshot.configuration_admitted
            && let Some(generation) = initial_generation
        {
            ctx.provider_readiness.policy_activated(
                &EnvironmentIdentity::from_settings(snapshot),
                snapshot.config_revision,
                generation.clone(),
            );
            runtime.policy_generation = Some(generation);
        }
        apply_ocsf_json_setting(&ctx.ocsf_enabled, &snapshot.settings);
        apply_ocsf_schema_version_setting(&ctx.ocsf_schema_version, &snapshot.settings);
        if snapshot.configuration_admitted {
            endpoint_status::reset(
                ctx.endpoint_observation_tx.as_ref(),
                runtime.endpoint_policy.as_ref(),
                &runtime.policy_hash,
                ctx.provider_credentials.snapshot().revision,
            )
            .await;
        }
    } else {
        match client.poll_settings(&ctx.sandbox).await {
            Ok(result) => {
                let _ = ctx.workspace_tx.send(client.workspace());
                match (
                    initial_poll_disposition(&ctx.loaded_policy_origin, &result),
                    initial_generation.as_ref(),
                ) {
                    (InitialPollDisposition::Acknowledge(candidate), Some(generation))
                        if runtime.middleware_registry_status
                            == MiddlewareRegistryStatus::Synchronized
                            && !generation.is_stale() =>
                    {
                        ctx.provider_readiness.policy_activated(
                            &EnvironmentIdentity::from_settings(&result),
                            result.config_revision,
                            generation.clone(),
                        );
                        runtime.policy_generation = Some(generation.clone());
                        apply_ocsf_json_setting(&ctx.ocsf_enabled, &result.settings);
                        apply_ocsf_schema_version_setting(
                            &ctx.ocsf_schema_version,
                            &result.settings,
                        );
                        apply_agent_proposals_enabled(
                            &ctx.agent_proposals,
                            agent_proposals_enabled_from_settings(&result.settings),
                            "initial settings poll",
                            Some(candidate.config_revision),
                            skills::install_static_skills,
                        );
                        runtime.config_revision = candidate.config_revision;
                        runtime.policy_version = candidate.version;
                        runtime.policy_hash.clone_from(&candidate.policy_hash);
                        runtime.endpoint_policy.clone_from(&result.policy);
                        endpoint_status::reset(
                            ctx.endpoint_observation_tx.as_ref(),
                            runtime.endpoint_policy.as_ref(),
                            &runtime.policy_hash,
                            ctx.provider_credentials.snapshot().revision,
                        )
                        .await;
                        runtime.middleware_services = result.supervisor_middleware_services;
                        runtime.extension_authentication_enabled =
                            result.extension_authentication_enabled;
                        runtime.settings = result.settings;
                        enqueue_policy_status(
                            &status_sender,
                            PolicyStatusUpdate::initial_loaded(&candidate),
                        );
                        debug!(
                            config_revision = runtime.config_revision,
                            "Settings poll: initial policy matches loaded revision"
                        );
                    }
                    (
                        InitialPollDisposition::Acknowledge(_) | InitialPollDisposition::Reconcile,
                        _,
                    ) => {
                        // Matching policy bytes cannot prove an unavailable registry
                        // or a replaced generation. Install this snapshot immediately.
                        pending_result = Some(result);
                    }
                    (InitialPollDisposition::TrackOnly, _) => {
                        apply_ocsf_json_setting(&ctx.ocsf_enabled, &result.settings);
                        apply_ocsf_schema_version_setting(
                            &ctx.ocsf_schema_version,
                            &result.settings,
                        );
                        apply_agent_proposals_enabled(
                            &ctx.agent_proposals,
                            agent_proposals_enabled_from_settings(&result.settings),
                            "initial settings poll",
                            Some(result.config_revision),
                            skills::install_static_skills,
                        );
                        runtime.config_revision = result.config_revision;
                        runtime.policy_hash = result.policy_hash.clone();
                        runtime.middleware_services = result.supervisor_middleware_services;
                        runtime.extension_authentication_enabled =
                            result.extension_authentication_enabled;
                        runtime.settings = result.settings;
                        debug!(
                            config_revision = runtime.config_revision,
                            "Settings poll: tracking gateway config while preserving local policy override"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "Settings poll: failed to fetch initial version, will retry");
            }
        }
    }

    let interval = Duration::from_secs(ctx.interval_secs);
    loop {
        if let Some(updates) = config_push_updates.as_ref() {
            config_push_enabled = *updates.borrow();
        }
        if stream_started && config_push_enabled {
            let delay = next_poll_delay(&ctx.extension_credentials, interval);
            tokio::select! {
                changed = async {
                    match config_push_updates.as_mut() {
                        Some(updates) => updates.changed().await.is_ok(),
                        None => std::future::pending().await,
                    }
                } => {
                    if !changed {
                        config_push_updates = None;
                    }
                }
                request = receive_config_apply(&mut config_apply_rx) => {
                    let Some(request) = request else {
                        return Err(miette::miette!("stream configuration apply channel closed"));
                    };
                    runtime.apply_delivered(&ctx, &client, request).await;
                }
                () = tokio::time::sleep(delay) => {
                    if runtime.extension_authentication_enabled
                        && let Err(error) = client.refresh_installed_extension_credentials().await
                    {
                        warn!(error = %error, "Extension credential refresh failed");
                    }
                    runtime.retry_degraded_startup(&ctx, &client).await;
                }
            }
            continue;
        }
        let result = if let Some(result) = pending_result.take() {
            result
        } else {
            let delay = next_poll_delay(&ctx.extension_credentials, interval);
            tokio::select! {
                request = receive_config_apply(&mut config_apply_rx) => {
                    if let Some(request) = request {
                        runtime.apply_delivered(&ctx, &client, request).await;
                        continue;
                    }
                }
                () = tokio::time::sleep(delay) => {}
            }
            match client.poll_settings(&ctx.sandbox).await {
                Ok(result) => {
                    let _ = ctx.workspace_tx.send(client.workspace());
                    result
                }
                Err(e) => {
                    debug!(error = %e, "Settings poll: server unreachable, will retry");
                    if runtime.extension_authentication_enabled
                        && let Err(refresh_error) =
                            client.refresh_installed_extension_credentials().await
                    {
                        warn!(
                            error = %refresh_error,
                            "Settings poll: extension credential refresh failed while configuration was unavailable"
                        );
                    }
                    continue;
                }
            }
        };

        let reconciled = runtime
            .reconcile(&ctx, &client, &result, ProviderSource::Fetch)
            .await?;
        if let Some(status) = reconciled.policy_status {
            enqueue_policy_status(&status_sender, status);
        }
        match reconciled.outcome {
            ReconcileOutcome::Unchanged => {}
            ReconcileOutcome::Rejected(rejection) => {
                report_runtime_configuration(&ctx, &result, false, &rejection.admission_error)
                    .await;
            }
            // Retry the exact status tuple on the next poll before advancing
            // the observed revision; an old instance cannot claim readiness.
            ReconcileOutcome::Applied => {
                if report_runtime_configuration(&ctx, &result, true, "").await {
                    runtime.commit(result);
                }
            }
        }
    }
}

fn apply_ocsf_json_setting(
    enabled: &AtomicBool,
    settings: &std::collections::HashMap<String, openshell_core::proto::EffectiveSetting>,
) {
    use std::sync::atomic::Ordering;

    let new_ocsf = extract_bool_setting(settings, "ocsf_json_enabled").unwrap_or(false);
    let prev_ocsf = enabled.swap(new_ocsf, Ordering::Relaxed);
    if new_ocsf != prev_ocsf {
        info!(ocsf_json_enabled = new_ocsf, "OCSF JSONL logging toggled");
    }
}

/// Extract a bool value from an effective setting, if present.
fn extract_bool_setting(
    settings: &std::collections::HashMap<String, openshell_core::proto::EffectiveSetting>,
    key: &str,
) -> Option<bool> {
    use openshell_core::proto::setting_value;
    settings
        .get(key)
        .and_then(|es| es.value.as_ref())
        .and_then(|sv| sv.value.as_ref())
        .and_then(|v| match v {
            setting_value::Value::BoolValue(b) => Some(*b),
            _ => None,
        })
}

fn apply_ocsf_schema_version_setting(
    version: &std::sync::Mutex<String>,
    settings: &std::collections::HashMap<String, openshell_core::proto::EffectiveSetting>,
) {
    let new_version = extract_string_setting(settings, "ocsf_schema_version").unwrap_or_default();
    if let Ok(mut current) = version.lock()
        && *current != new_version
    {
        info!(
            ocsf_schema_version = %new_version,
            "OCSF schema version target changed"
        );
        *current = new_version;
    }
}

/// Extract a string value from an effective setting, if present.
fn extract_string_setting(
    settings: &std::collections::HashMap<String, openshell_core::proto::EffectiveSetting>,
    key: &str,
) -> Option<String> {
    use openshell_core::proto::setting_value;
    settings
        .get(key)
        .and_then(|es| es.value.as_ref())
        .and_then(|sv| sv.value.as_ref())
        .and_then(|v| match v {
            setting_value::Value::StringValue(value) => Some(value.clone()),
            _ => None,
        })
}

pub fn agent_proposals_enabled_from_settings(
    settings: &std::collections::HashMap<String, openshell_core::proto::EffectiveSetting>,
) -> bool {
    extract_bool_setting(
        settings,
        openshell_core::settings::AGENT_POLICY_PROPOSALS_ENABLED_KEY,
    )
    .unwrap_or(false)
}

fn apply_agent_proposals_enabled(
    agent_proposals: &AgentProposals,
    enabled: bool,
    source: &'static str,
    config_revision: Option<u64>,
    install_static_skills: impl FnOnce() -> Result<skills::InstalledSkills>,
) {
    let previously_enabled = agent_proposals.swap_enabled(enabled);
    if enabled == previously_enabled {
        return;
    }

    info!(
        agent_policy_proposals_enabled = enabled,
        source, config_revision, "agent-driven policy proposals toggled"
    );

    if enabled && !previously_enabled {
        match install_static_skills() {
            Ok(installed) => info!(
                path = %installed.policy_advisor.display(),
                "Installed sandbox agent skill on toggle-on"
            ),
            Err(error) => warn!(
                error = %error,
                "Failed to install sandbox agent skill on toggle-on"
            ),
        }
    }
}

/// Log individual setting changes between two snapshots.
fn log_setting_changes(
    old: &std::collections::HashMap<String, openshell_core::proto::EffectiveSetting>,
    new: &std::collections::HashMap<String, openshell_core::proto::EffectiveSetting>,
) {
    for (key, new_es) in new {
        let new_val = format_setting_value(new_es);
        match old.get(key) {
            Some(old_es) => {
                let old_val = format_setting_value(old_es);
                if old_val != new_val {
                    ocsf_emit!(
                        ConfigStateChangeBuilder::new(ocsf_ctx())
                            .severity(SeverityId::Informational)
                            .status(StatusId::Success)
                            .state(StateId::Enabled, "updated")
                            .unmapped("key", serde_json::json!(key))
                            .unmapped("old", serde_json::json!(old_val.clone()))
                            .unmapped("new", serde_json::json!(new_val.clone()))
                            .message(format!(
                                "Setting changed [key:{key} old:{old_val} new:{new_val}]"
                            ))
                            .build()
                    );
                }
            }
            None => {
                ocsf_emit!(
                    ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::Informational)
                        .status(StatusId::Success)
                        .state(StateId::Enabled, "enabled")
                        .unmapped("key", serde_json::json!(key))
                        .unmapped("value", serde_json::json!(new_val.clone()))
                        .message(format!("Setting added [key:{key} value:{new_val}]"))
                        .build()
                );
            }
        }
    }
    for key in old.keys() {
        if !new.contains_key(key) {
            ocsf_emit!(
                ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::Informational)
                    .status(StatusId::Success)
                    .state(StateId::Disabled, "disabled")
                    .unmapped("key", serde_json::json!(key))
                    .message(format!("Setting removed [key:{key}]"))
                    .build()
            );
        }
    }
}

/// Format an `EffectiveSetting` value for log display.
fn format_setting_value(es: &openshell_core::proto::EffectiveSetting) -> String {
    use openshell_core::proto::setting_value;
    match es.value.as_ref().and_then(|sv| sv.value.as_ref()) {
        None => "<unset>".to_string(),
        Some(setting_value::Value::StringValue(v)) => v.clone(),
        Some(setting_value::Value::BoolValue(v)) => v.to_string(),
        Some(setting_value::Value::IntValue(v)) => v.to_string(),
        Some(setting_value::Value::BytesValue(_)) => "<bytes>".to_string(),
    }
}

#[cfg(test)]
#[allow(
    clippy::needless_raw_string_hashes,
    clippy::iter_on_single_items,
    clippy::similar_names,
    clippy::manual_string_new,
    clippy::doc_markdown,
    reason = "Test code: test fixtures often use idiomatic forms not flagged in production."
)]
mod tests {
    use super::*;
    use crate::tests::{
        proto_policy_fixture, proto_tcp_policy_fixture, settings_poll_result, startup_provider,
    };
    use crate::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn effective_bool(value: bool) -> openshell_core::proto::EffectiveSetting {
        openshell_core::proto::EffectiveSetting {
            value: Some(openshell_core::proto::SettingValue {
                value: Some(openshell_core::proto::setting_value::Value::BoolValue(
                    value,
                )),
            }),
            scope: openshell_core::proto::SettingScope::Global.into(),
        }
    }

    #[test]
    fn apply_agent_proposals_enabled_installs_only_on_false_to_true() {
        let agent_proposals = AgentProposals::default();
        let installs = AtomicUsize::new(0);

        apply_agent_proposals_enabled(&agent_proposals, true, "test", Some(1), || {
            installs.fetch_add(1, Ordering::Relaxed);
            Ok(skills::InstalledSkills {
                policy_advisor: std::path::PathBuf::from("/tmp/policy_advisor.md"),
                policy_advisor_skill: std::path::PathBuf::from("/tmp/SKILL.md"),
                agents: None,
            })
        });
        assert!(agent_proposals.enabled());
        assert_eq!(installs.load(Ordering::Relaxed), 1);

        apply_agent_proposals_enabled(&agent_proposals, true, "test", Some(2), || {
            installs.fetch_add(1, Ordering::Relaxed);
            Ok(skills::InstalledSkills {
                policy_advisor: std::path::PathBuf::from("/tmp/policy_advisor.md"),
                policy_advisor_skill: std::path::PathBuf::from("/tmp/SKILL.md"),
                agents: None,
            })
        });
        assert_eq!(installs.load(Ordering::Relaxed), 1);

        apply_agent_proposals_enabled(&agent_proposals, false, "test", Some(3), || {
            installs.fetch_add(1, Ordering::Relaxed);
            Ok(skills::InstalledSkills {
                policy_advisor: std::path::PathBuf::from("/tmp/policy_advisor.md"),
                policy_advisor_skill: std::path::PathBuf::from("/tmp/SKILL.md"),
                agents: None,
            })
        });
        assert!(!agent_proposals.enabled());
        assert_eq!(installs.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn apply_ocsf_json_setting_enables_from_initial_settings_snapshot() {
        let enabled = AtomicBool::new(false);
        let mut settings = std::collections::HashMap::new();
        settings.insert("ocsf_json_enabled".to_string(), effective_bool(true));

        apply_ocsf_json_setting(&enabled, &settings);

        assert!(enabled.load(Ordering::Relaxed));
    }

    #[test]
    fn apply_ocsf_json_setting_disables_when_setting_is_unset() {
        let enabled = AtomicBool::new(true);
        let settings = std::collections::HashMap::new();

        apply_ocsf_json_setting(&enabled, &settings);

        assert!(!enabled.load(Ordering::Relaxed));
    }

    #[test]
    fn apply_ocsf_schema_version_setting_updates_from_initial_settings_snapshot() {
        let version = std::sync::Mutex::new(String::new());
        let mut settings = std::collections::HashMap::new();
        settings.insert(
            "ocsf_schema_version".to_string(),
            openshell_core::proto::EffectiveSetting {
                value: Some(openshell_core::proto::SettingValue {
                    value: Some(openshell_core::proto::setting_value::Value::StringValue(
                        "1.3".into(),
                    )),
                }),
                scope: openshell_core::proto::SettingScope::Sandbox.into(),
            },
        );

        apply_ocsf_schema_version_setting(&version, &settings);

        assert_eq!(*version.lock().unwrap(), "1.3");
    }

    #[test]
    fn apply_ocsf_schema_version_setting_clears_when_setting_is_unset() {
        let version = std::sync::Mutex::new("1.1".to_string());
        let settings = std::collections::HashMap::new();

        apply_ocsf_schema_version_setting(&version, &settings);

        assert_eq!(*version.lock().unwrap(), "");
    }

    #[test]
    fn agent_proposals_setting_enables_from_initial_settings_snapshot() {
        let mut settings = std::collections::HashMap::new();
        settings.insert(
            openshell_core::settings::AGENT_POLICY_PROPOSALS_ENABLED_KEY.to_string(),
            effective_bool(true),
        );

        assert!(agent_proposals_enabled_from_settings(&settings));
    }

    #[test]
    fn agent_proposals_setting_defaults_false_when_unset() {
        let settings = std::collections::HashMap::new();

        assert!(!agent_proposals_enabled_from_settings(&settings));
    }

    // ---- Policy disk discovery tests ----

    #[derive(Clone)]
    struct ScriptedPolicyGateway {
        polls: Arc<
            tokio::sync::Mutex<
                tokio::sync::mpsc::UnboundedReceiver<
                    openshell_core::grpc_client::SettingsPollResult,
                >,
            >,
        >,
        reports: UnboundedSender<(u32, bool, String)>,
        environment_identity: Arc<std::sync::Mutex<EnvironmentIdentity>>,
        poll_calls: Arc<AtomicUsize>,
        polled_sandboxes: Arc<tokio::sync::Mutex<Vec<String>>>,
    }

    #[tonic::async_trait]
    impl PolicyGatewayClient for ScriptedPolicyGateway {
        async fn poll_settings(
            &self,
            sandbox: &str,
        ) -> Result<openshell_core::grpc_client::SettingsPollResult> {
            self.poll_calls.fetch_add(1, Ordering::SeqCst);
            self.polled_sandboxes.lock().await.push(sandbox.to_string());
            let result = self
                .polls
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| miette::miette!("scripted policy poll channel closed"))?;
            *self.environment_identity.lock().unwrap() =
                EnvironmentIdentity::from_settings(&result);
            Ok(result)
        }

        async fn fetch_provider_environment(
            &self,
            _endpoint: &str,
            _sandbox_id: &str,
        ) -> Result<openshell_core::grpc_client::ProviderEnvironmentResult> {
            let identity = self.environment_identity.lock().unwrap().clone();
            let mut provider = startup_provider(identity.revision);
            provider.provider_attachment_epoch = identity.attachment_epoch;
            provider.policy_hash = identity.policy_hash;
            if provider.policy_hash.is_empty() {
                provider.readiness_reason = ProviderReadinessReason::SnapshotMismatch;
            }
            Ok(provider)
        }

        async fn report_policy_status(
            &self,
            _sandbox_id: &str,
            version: u32,
            loaded: bool,
            error: &str,
        ) -> Result<()> {
            self.reports
                .send((version, loaded, error.to_string()))
                .map_err(|_| miette::miette!("scripted policy report channel closed"))
        }

        fn workspace(&self) -> String {
            "test-workspace".to_string()
        }
    }

    #[derive(Clone)]
    struct CredentialRejectingPolicyGateway {
        inner: ScriptedPolicyGateway,
        credential_requests: Arc<AtomicUsize>,
    }

    #[tonic::async_trait]
    impl PolicyGatewayClient for CredentialRejectingPolicyGateway {
        async fn poll_settings(
            &self,
            sandbox: &str,
        ) -> Result<openshell_core::grpc_client::SettingsPollResult> {
            self.inner.poll_settings(sandbox).await
        }

        async fn fetch_provider_environment(
            &self,
            endpoint: &str,
            sandbox_id: &str,
        ) -> Result<openshell_core::grpc_client::ProviderEnvironmentResult> {
            self.inner
                .fetch_provider_environment(endpoint, sandbox_id)
                .await
        }

        async fn report_policy_status(
            &self,
            sandbox_id: &str,
            version: u32,
            loaded: bool,
            error: &str,
        ) -> Result<()> {
            self.inner
                .report_policy_status(sandbox_id, version, loaded, error)
                .await
        }

        async fn extension_credentials_for(
            &self,
            _services: &[openshell_core::proto::SupervisorMiddlewareService],
        ) -> Result<std::collections::HashMap<String, openshell_extension_core::BearerTokenSlot>>
        {
            self.credential_requests.fetch_add(1, Ordering::SeqCst);
            Err(miette::miette!(
                "gateway extension authentication is unavailable"
            ))
        }

        fn workspace(&self) -> String {
            self.inner.workspace()
        }
    }

    fn scripted_policy_gateway() -> (
        ScriptedPolicyGateway,
        UnboundedSender<openshell_core::grpc_client::SettingsPollResult>,
        tokio::sync::mpsc::UnboundedReceiver<(u32, bool, String)>,
    ) {
        let (poll_tx, poll_rx) = tokio::sync::mpsc::unbounded_channel();
        let (report_tx, report_rx) = tokio::sync::mpsc::unbounded_channel();
        (
            ScriptedPolicyGateway {
                polls: Arc::new(tokio::sync::Mutex::new(poll_rx)),
                reports: report_tx,
                environment_identity: Arc::new(std::sync::Mutex::new(
                    EnvironmentIdentity::default(),
                )),
                poll_calls: Arc::new(AtomicUsize::new(0)),
                polled_sandboxes: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            },
            poll_tx,
            report_rx,
        )
    }

    fn static_provider_environment(
        revision: u64,
        value: Option<&str>,
    ) -> openshell_core::grpc_client::ProviderEnvironmentResult {
        use openshell_core::proto::{StaticCredentialBinding, StaticCredentialEndpointBinding};
        use std::collections::HashMap;

        let mut result = openshell_core::grpc_client::ProviderEnvironmentResult {
            files: HashMap::new(),
            environment: HashMap::new(),
            provider_env_revision: revision,
            provider_attachment_epoch: String::new(),
            policy_hash: "hash-v1".to_string(),
            readiness_reason: ProviderReadinessReason::Unspecified,
            credential_expires_at_ms: HashMap::new(),
            dynamic_credentials: HashMap::new(),
            static_credential_bindings: HashMap::new(),
            non_secret_environment_keys: Vec::new(),
        };
        if let Some(value) = value {
            result
                .environment
                .insert("EXTERNAL_TOKEN".into(), value.into());
            result.static_credential_bindings.insert(
                "EXTERNAL_TOKEN".into(),
                StaticCredentialBinding {
                    endpoints: vec![StaticCredentialEndpointBinding {
                        host: "tools.example.com".into(),
                        port: 443,
                        path: "/v1/**".into(),
                    }],
                    credential_identity: "provider-a:EXTERNAL_TOKEN".into(),
                    workload_credential_handle: String::new(),
                },
            );
        }
        result
    }

    #[test]
    fn initial_provider_credentials_preserve_revision_scoped_delivery() {
        let readiness = ProviderReadinessTracker::new();
        let state = initial_provider_credentials(
            static_provider_environment(1, Some("initial")),
            &readiness,
        );
        let (revision, child_env) = state.child_env_snapshot_with_gcp_resolved().unwrap();
        let reference = &child_env["EXTERNAL_TOKEN"];
        assert_eq!(revision, 1);
        assert_eq!(reference, "openshell:resolve:env:v1_EXTERNAL_TOKEN");
        assert_eq!(
            state
                .resolver_for_endpoint("tools.example.com", 443, "/v1/chat")
                .unwrap()
                .resolve_placeholder(reference),
            Some("initial"),
        );
        assert!(readiness.observation(&state).credentials_installed);
        assert!(!readiness.observation(&state).launch_environment_installed);
        // The boundary receives the prepared snapshot without gaining resolver authority.
        let boundary =
            ProviderCredentialState::from_child_env_snapshot(revision, child_env.clone());
        assert_eq!(boundary.snapshot().child_env, child_env);
        assert!(boundary.resolver().is_none());

        let mut invalid = static_provider_environment(2, Some("invalid"));
        invalid.static_credential_bindings.clear();
        let rejected = initial_provider_credentials(invalid, &readiness);
        assert!(rejected.snapshot().child_env.is_empty());
        assert!(rejected.resolver().is_none());
        assert_eq!(
            readiness.observation(&rejected).reason,
            i32::from(ProviderReadinessReason::CredentialInstallFailed)
        );
    }

    type ProviderFetchRequest = tokio::sync::oneshot::Sender<
        Result<openshell_core::grpc_client::ProviderEnvironmentResult>,
    >;

    #[derive(Clone)]
    struct ScriptedProviderGateway {
        policy: ScriptedPolicyGateway,
        requests: UnboundedSender<ProviderFetchRequest>,
    }

    #[tonic::async_trait]
    impl PolicyGatewayClient for ScriptedProviderGateway {
        async fn poll_settings(
            &self,
            sandbox: &str,
        ) -> Result<openshell_core::grpc_client::SettingsPollResult> {
            self.policy.poll_settings(sandbox).await
        }

        async fn report_policy_status(
            &self,
            sandbox_id: &str,
            version: u32,
            loaded: bool,
            error: &str,
        ) -> Result<()> {
            self.policy
                .report_policy_status(sandbox_id, version, loaded, error)
                .await
        }

        async fn fetch_provider_environment(
            &self,
            _endpoint: &str,
            sandbox_id: &str,
        ) -> Result<openshell_core::grpc_client::ProviderEnvironmentResult> {
            assert_eq!(sandbox_id, "sandbox-test");
            let (response, received) = tokio::sync::oneshot::channel();
            self.requests
                .send(response)
                .map_err(|_| miette::miette!("provider request channel closed"))?;
            received
                .await
                .map_err(|_| miette::miette!("provider response channel closed"))?
        }

        fn workspace(&self) -> String {
            self.policy.workspace()
        }
    }

    #[tokio::test]
    async fn provider_readiness_initial_poll_waits_for_middleware_reconciliation() {
        let policy = proto_policy_fixture();
        let mut settings = settings_poll_result(
            Some(policy.clone()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        settings.provider_attachment_epoch = "epoch".to_string();
        settings.provider_env_revision = 9;
        settings.supervisor_middleware_services =
            vec![openshell_core::proto::SupervisorMiddlewareService {
                name: "scripted-guard".to_string(),
                grpc_endpoint: "http://scripted.invalid".to_string(),
                ..Default::default()
            }];
        let (attempt_tx, mut attempts) = tokio::sync::mpsc::unbounded_channel();
        let (complete, completions) = tokio::sync::mpsc::unbounded_channel::<bool>();
        let completions = Arc::new(tokio::sync::Mutex::new(completions));
        let connector: MiddlewareConnector = Arc::new(move |services, _authentication| {
            assert_eq!(services.len(), 1);
            assert_eq!(services[0].name, "scripted-guard");
            attempt_tx.send(()).unwrap();
            let completions = completions.clone();
            Box::pin(async move {
                if completions.lock().await.recv().await.unwrap() {
                    connect_middleware_registry(&[], &MiddlewareAuthentication::default()).await
                } else {
                    Err(miette::miette!("scripted middleware connection failure"))
                }
            })
        });
        let engine = Arc::new(OpaEngine::from_proto(&policy).unwrap());
        let mut context = policy_poll_test_context(
            engine.clone(),
            LoadedPolicyOrigin::Gateway {
                revision: Some(LoadedPolicyRevision::from_snapshot(&settings)),
                has_last_valid_policy: true,
            },
            connector,
        );
        context.middleware_registry_status = MiddlewareRegistryStatus::NeedsReconciliation;
        context.provider_credentials = ProviderCredentialState::from_child_env_snapshot(
            9,
            std::collections::HashMap::default(),
        );
        let credentials = context.provider_credentials.clone();
        let tracker = context.provider_readiness.clone();
        tracker.credentials_installed(
            EnvironmentIdentity::from_settings(&settings),
            &credentials,
            None,
        );
        let (gateway, polls, mut reports) = scripted_policy_gateway();
        let task = tokio::spawn(run_policy_poll_loop_with_client(context, gateway));
        polls.send(settings.clone()).unwrap();
        timeout(Duration::from_secs(1), attempts.recv())
            .await
            .expect("initial snapshot must reconcile without a second poll")
            .unwrap();
        let observed = tracker.observation(&credentials);
        assert!(observed.credentials_installed);
        assert!(!observed.policy_active);
        assert!(
            !observed.launch_environment_installed,
            "process evidence requires its own boundary acknowledgment"
        );
        expect_no_policy_report(&mut reports).await;

        complete.send(false).unwrap();
        timeout(Duration::from_secs(1), async {
            while tracker.observation(&credentials).reason
                != i32::from(ProviderReadinessReason::PolicyActivationFailed)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!tracker.observation(&credentials).policy_active);
        assert_eq!(engine.current_generation(), 0);
        expect_no_policy_report(&mut reports).await;

        polls.send(settings).unwrap();
        timeout(Duration::from_secs(1), attempts.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(!tracker.observation(&credentials).policy_active);
        complete.send(true).unwrap();
        expect_policy_report(&mut reports, 1).await;
        assert!(tracker.observation(&credentials).policy_active);
        assert_eq!(engine.current_generation(), 1);
        task.abort();
        let _ = task.await;
    }

    #[derive(Clone)]
    struct GenerationChangingPolicyGateway {
        inner: ScriptedPolicyGateway,
        engine: Arc<OpaEngine>,
        first_poll: Arc<AtomicBool>,
    }

    #[tonic::async_trait]
    impl PolicyGatewayClient for GenerationChangingPolicyGateway {
        async fn poll_settings(
            &self,
            sandbox: &str,
        ) -> Result<openshell_core::grpc_client::SettingsPollResult> {
            let result = self.inner.poll_settings(sandbox).await?;
            if self.first_poll.swap(false, Ordering::SeqCst) {
                self.engine
                    .enter_fail_closed("generation replaced while first poll was pending")?;
            }
            Ok(result)
        }

        async fn fetch_provider_environment(
            &self,
            endpoint: &str,
            sandbox_id: &str,
        ) -> Result<openshell_core::grpc_client::ProviderEnvironmentResult> {
            self.inner
                .fetch_provider_environment(endpoint, sandbox_id)
                .await
        }

        async fn report_policy_status(
            &self,
            sandbox_id: &str,
            version: u32,
            loaded: bool,
            error: &str,
        ) -> Result<()> {
            self.inner
                .report_policy_status(sandbox_id, version, loaded, error)
                .await
        }

        fn workspace(&self) -> String {
            self.inner.workspace()
        }
    }

    #[tokio::test]
    async fn provider_readiness_initial_poll_reconciles_a_replaced_policy_generation() {
        let policy = proto_policy_fixture();
        let settings = settings_poll_result(
            Some(policy.clone()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let engine = Arc::new(OpaEngine::from_proto(&policy).unwrap());
        let context = policy_poll_test_context(
            engine.clone(),
            LoadedPolicyOrigin::Gateway {
                revision: Some(LoadedPolicyRevision::from_snapshot(&settings)),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        let credentials = context.provider_credentials.clone();
        let tracker = context.provider_readiness.clone();
        tracker.credentials_installed(
            EnvironmentIdentity::from_settings(&settings),
            &credentials,
            None,
        );
        let (inner, polls, mut reports) = scripted_policy_gateway();
        let gateway = GenerationChangingPolicyGateway {
            inner,
            engine: engine.clone(),
            first_poll: Arc::new(AtomicBool::new(true)),
        };
        let task = tokio::spawn(run_policy_poll_loop_with_client(context, gateway));
        polls.send(settings).unwrap();
        expect_policy_report(&mut reports, 1).await;
        assert!(
            engine.fail_closed_reason().is_none(),
            "the delivered policy must replace the intervening quarantine before acknowledgment"
        );
        assert_eq!(
            engine.current_generation(),
            2,
            "generation 1 was not the policy startup installed"
        );
        assert!(tracker.observation(&credentials).policy_active);
        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn provider_readiness_poll_waits_for_installation_and_retries_same_fingerprint() {
        let engine = Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).unwrap());
        let mut initial = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        initial.provider_env_revision = 6;
        let ctx = policy_poll_test_context(
            engine.clone(),
            LoadedPolicyOrigin::Gateway {
                revision: Some(LoadedPolicyRevision::from_snapshot(&initial)),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        let credentials = ctx.provider_credentials.clone();
        let tracker = ctx.provider_readiness.clone();
        let (policy, polls, mut reports) = scripted_policy_gateway();
        let (requests, mut received) = tokio::sync::mpsc::unbounded_channel();
        polls.send(initial.clone()).unwrap();
        let task = tokio::spawn(run_policy_poll_loop_with_client(
            ctx,
            ScriptedProviderGateway { policy, requests },
        ));
        expect_policy_report(&mut reports, 1).await;

        polls.send(initial.clone()).unwrap();
        let response = timeout(Duration::from_secs(1), received.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            !tracker.observation(&credentials).credentials_installed,
            "fetching desired credentials does not install them"
        );
        assert!(response.send(Err(miette::miette!("unavailable"))).is_ok());
        timeout(Duration::from_secs(1), async {
            while tracker.observation(&credentials).reason
                != i32::from(ProviderReadinessReason::CredentialInstallFailed)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let failed_id = credentials.snapshot().installation_id.clone();

        polls.send(initial.clone()).unwrap();
        let response = timeout(Duration::from_secs(1), received.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            response
                .send(Ok(static_provider_environment(6, Some("repaired"))))
                .is_ok()
        );
        timeout(Duration::from_secs(1), async {
            while !tracker.observation(&credentials).credentials_installed {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let observed = tracker.observation(&credentials);
        assert_ne!(failed_id, credentials.snapshot().installation_id);
        assert!(observed.policy_active);
        assert!(
            !observed.launch_environment_installed,
            "a separate boundary acknowledgment is still required"
        );

        // A policy change can preserve the provider content fingerprint while
        // changing the credential authority. Fetch and install that identity too.
        let mut changed = initial;
        changed.version = 2;
        changed.config_revision = 200;
        changed.policy_hash = "hash-v2".to_string();
        polls.send(changed).unwrap();
        let response = timeout(Duration::from_secs(1), received.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(!tracker.observation(&credentials).policy_active);
        let mut environment = static_provider_environment(6, Some("repaired"));
        environment.policy_hash = "hash-v2".to_string();
        assert!(response.send(Ok(environment)).is_ok());
        expect_policy_report(&mut reports, 2).await;
        let observed = tracker.observation(&credentials);
        assert!(observed.credentials_installed && observed.policy_active);
        assert_eq!(observed.provider_env_revision, 6);
        assert_eq!(observed.config_revision, 200);
        assert_eq!(observed.policy_hash, "hash-v2");
        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn provider_readiness_startup_environment_avoids_unchanged_refresh() {
        let policy = proto_policy_fixture();
        let mut settings = settings_poll_result(
            Some(policy.clone()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        settings.provider_env_revision = 6;
        let engine = Arc::new(OpaEngine::from_proto(&policy).unwrap());
        let mut ctx = policy_poll_test_context(
            engine.clone(),
            LoadedPolicyOrigin::Gateway {
                revision: Some(LoadedPolicyRevision::from_snapshot(&settings)),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        let mut provider = static_provider_environment(6, Some("initial"));
        provider.policy_hash.clone_from(&settings.policy_hash);
        let credentials = prepare_provider_environment(&provider).unwrap();
        ctx.provider_credentials = CapturedProviderEnvironment::new(credentials, &provider)
            .install(&ctx.provider_readiness);
        let generation = engine.current_generation();
        let guard = engine.generation_guard(generation).unwrap();
        let (policy_gateway, polls, mut reports) = scripted_policy_gateway();
        let observed_polls = policy_gateway.polled_sandboxes.clone();
        let (requests, mut received) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(run_policy_poll_loop_with_client(
            ctx,
            ScriptedProviderGateway {
                policy: policy_gateway,
                requests,
            },
        ));

        polls.send(settings.clone()).unwrap();
        expect_policy_report(&mut reports, 1).await;
        polls.send(settings).unwrap();
        timeout(Duration::from_secs(1), async {
            while observed_polls.lock().await.len() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        assert!(
            timeout(Duration::from_millis(50), received.recv())
                .await
                .is_err(),
            "unchanged settings must not refetch the startup environment"
        );
        assert_eq!(engine.current_generation(), generation);
        assert!(!guard.is_stale());
        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn provider_poll_installs_fail_closed_environment_and_acknowledges_policy() {
        let policy = proto_policy_fixture();
        let initial = settings_poll_result(
            Some(policy.clone()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let engine = Arc::new(OpaEngine::from_proto(&policy).unwrap());
        let ctx = policy_poll_test_context(
            engine,
            LoadedPolicyOrigin::Gateway {
                revision: Some(LoadedPolicyRevision::from_snapshot(&initial)),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        let credentials = ctx.provider_credentials.clone();
        let (policy_gateway, polls, mut reports) = scripted_policy_gateway();
        let (requests, mut received) = tokio::sync::mpsc::unbounded_channel();
        polls.send(initial).unwrap();
        let task = tokio::spawn(run_policy_poll_loop_with_client(
            ctx,
            ScriptedProviderGateway {
                policy: policy_gateway,
                requests,
            },
        ));
        expect_policy_report(&mut reports, 1).await;

        let mut changed = settings_poll_result(
            Some(policy),
            2,
            openshell_core::proto::PolicySource::Sandbox,
        );
        changed.provider_env_revision = 1;
        polls.send(changed).unwrap();
        let response = timeout(Duration::from_secs(1), received.recv())
            .await
            .expect("provider refresh requested")
            .expect("poll loop active");
        let mut withheld = static_provider_environment(1, None);
        withheld.policy_hash = "hash-v2".to_string();
        withheld.readiness_reason = ProviderReadinessReason::CredentialsWithheld;
        withheld
            .environment
            .insert("PROJECT_ID".to_string(), "example-project".to_string());
        withheld
            .non_secret_environment_keys
            .push("PROJECT_ID".to_string());
        assert!(response.send(Ok(withheld)).is_ok());

        expect_policy_report(&mut reports, 2).await;
        assert_eq!(credentials.revision(), 1);
        assert!(
            credentials.snapshot().child_env.contains_key("PROJECT_ID"),
            "the reduced snapshot retains non-secret provider configuration"
        );

        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn provider_poll_preserves_static_references_across_rotation_failure_and_detach() {
        let engine = Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).unwrap());
        let initial = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let ctx = policy_poll_test_context(
            engine,
            LoadedPolicyOrigin::Gateway {
                revision: Some(LoadedPolicyRevision::from_snapshot(&initial)),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        let state = ctx.provider_credentials.clone();
        let tracker = ctx.provider_readiness.clone();
        let (policy, polls, mut reports) = scripted_policy_gateway();
        let (requests, mut received) = tokio::sync::mpsc::unbounded_channel();
        polls.send(initial.clone()).unwrap();
        let task = tokio::spawn(run_policy_poll_loop_with_client(
            ctx,
            ScriptedProviderGateway { policy, requests },
        ));
        expect_policy_report(&mut reports, 1).await;

        // Rotation gives future processes a new reference; the retained old
        // reference continues to resolve its original value until revocation.
        let old_reference = "openshell:resolve:env:v1_EXTERNAL_TOKEN";
        for (revision, value, fail) in [
            (1, Some("initial"), false),
            (2, Some("rotated"), false),
            (3, None, true),
            (3, Some("recovered"), false),
            (4, None, false),
            (5, None, false),
        ] {
            let mut poll = initial.clone();
            poll.provider_env_revision = revision;
            polls.send(poll).unwrap();
            let response = timeout(Duration::from_secs(5), received.recv())
                .await
                .expect("provider refresh requested")
                .expect("poll loop active");
            let result = if fail {
                Err(miette::miette!("provider snapshot unavailable"))
            } else {
                Ok(static_provider_environment(revision, value))
            };
            assert!(response.send(result).is_ok());
            let reference = format!("openshell:resolve:env:v{revision}_EXTERNAL_TOKEN");
            timeout(Duration::from_secs(5), async {
                loop {
                    let resolved = state
                        .resolver_for_endpoint("tools.example.com", 443, "/v1/chat")
                        .and_then(|resolver| {
                            resolver.resolve_placeholder(&reference).map(str::to_owned)
                        });
                    let observed = tracker.observation(&state);
                    if state.revision() == revision
                        && resolved.as_deref() == value
                        && (fail || observed.credentials_installed)
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("provider snapshot installed or revoked");
            if value.is_some() {
                assert_eq!(state.snapshot().child_env["EXTERNAL_TOKEN"], reference);
                if revision == 2 {
                    assert_ne!(reference, old_reference);
                    assert_eq!(
                        state
                            .resolver_for_endpoint("tools.example.com", 443, "/v1/chat")
                            .unwrap()
                            .resolve_placeholder(old_reference),
                        Some("initial")
                    );
                }
            } else {
                assert!(state.snapshot().child_env.is_empty());
                assert!(state.resolver().is_none());
            }
        }
        task.abort();
        let _ = task.await;
    }

    fn policy_poll_test_context(
        opa_engine: Arc<OpaEngine>,
        loaded_policy_origin: LoadedPolicyOrigin,
        middleware_connector: MiddlewareConnector,
    ) -> PolicyPollLoopContext {
        let (workspace_tx, _workspace_rx) = tokio::sync::watch::channel(String::new());
        let provider_credentials =
            ProviderCredentialState::from_child_env_snapshot(0, std::collections::HashMap::new());
        let provider_readiness = ProviderReadinessTracker::new();
        // This fixture models a successfully installed initial launch snapshot.
        if let LoadedPolicyOrigin::Gateway {
            revision: Some(revision),
            ..
        } = &loaded_policy_origin
        {
            provider_readiness.credentials_installed(
                EnvironmentIdentity {
                    revision: 0,
                    attachment_epoch: String::new(),
                    policy_hash: revision.policy_hash.clone(),
                },
                &provider_credentials,
                None,
            );
        }
        PolicyPollLoopContext {
            endpoint: String::new(),
            sandbox_id: "sandbox-test".to_string(),
            sandbox: "sandbox-test-name".to_string(),
            opa_engine,
            loaded_policy_origin,
            vm_identity: None,
            entrypoint_pid: Arc::new(AtomicU32::new(0)),
            interval_secs: 0,
            ocsf_enabled: Arc::new(AtomicBool::new(false)),
            ocsf_schema_version: Arc::new(std::sync::Mutex::new(String::new())),
            provider_credentials,
            provider_readiness,
            policy_local_ctx: None,
            agent_proposals: AgentProposals::default(),
            middleware_registry_status: MiddlewareRegistryStatus::Synchronized,
            workspace_tx,
            extension_credentials: openshell_extension_core::ExtensionCredentialStore::new(),
            extension_authentication_enabled: false,
            middleware_connector,
            transparent_tcp: TransparentTcpReloadState::default(),
            config_apply_rx: None,
            initial_stream_snapshot: None,
            config_push_enabled: None,
            endpoint_observation_tx: None,
            endpoint_status_rx: None,
            endpoint_policy: None,
            supervisor_session_id: tokio::sync::watch::channel(None).1,
        }
    }

    async fn expect_policy_report(
        reports: &mut tokio::sync::mpsc::UnboundedReceiver<(u32, bool, String)>,
        version: u32,
    ) {
        let report = timeout(Duration::from_secs(1), reports.recv())
            .await
            .expect("policy report timed out")
            .expect("policy reporter stopped");
        assert_eq!(report, (version, true, String::new()));
    }

    async fn expect_no_policy_report(
        reports: &mut tokio::sync::mpsc::UnboundedReceiver<(u32, bool, String)>,
    ) {
        assert!(
            timeout(Duration::from_millis(50), reports.recv())
                .await
                .is_err(),
            "unexpected policy status report"
        );
    }

    #[tokio::test]
    async fn same_hash_poll_revision_is_acknowledged_once_without_opa_reload() {
        let mut v1 = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        v1.policy_hash = "same-policy".to_string();
        let mut v2 = v1.clone();
        v2.version = 2;
        v2.config_revision = 200;

        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let loaded_revision = LoadedPolicyRevision::from_snapshot(&v1);
        let ctx = policy_poll_test_context(
            engine.clone(),
            LoadedPolicyOrigin::Gateway {
                revision: Some(loaded_revision),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        let (client, polls, mut reports) = scripted_policy_gateway();
        let observed_client = client.clone();
        polls.send(v1).unwrap();

        let handle = tokio::spawn(run_policy_poll_loop_with_client(ctx, client));
        expect_policy_report(&mut reports, 1).await;
        assert_eq!(
            observed_client.polled_sandboxes.lock().await.as_slice(),
            &["sandbox-test-name"],
            "settings polling must use the canonical sandbox reference, not its ID"
        );

        polls.send(v2.clone()).unwrap();
        expect_policy_report(&mut reports, 2).await;
        polls.send(v2).unwrap();
        expect_no_policy_report(&mut reports).await;

        assert_eq!(
            engine.current_generation(),
            0,
            "same-hash acknowledgement must not reload OPA"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn poll_rejects_first_tcp_expansion_and_reports_previous_policy_active() {
        let v1 = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let v2 = settings_poll_result(
            Some(proto_tcp_policy_fixture()),
            2,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let active_generation = engine.current_generation();
        let loaded_revision = LoadedPolicyRevision::from_snapshot(&v1);
        let mut ctx = policy_poll_test_context(
            engine.clone(),
            LoadedPolicyOrigin::Gateway {
                revision: Some(loaded_revision),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        ctx.transparent_tcp = TransparentTcpReloadState {
            capable: true,
            substrate_ready: false,
        };
        let (client, polls, mut reports) = scripted_policy_gateway();
        polls.send(v1).unwrap();

        let handle = tokio::spawn(run_policy_poll_loop_with_client(ctx, client));
        expect_policy_report(&mut reports, 1).await;
        polls.send(v2).unwrap();
        let report = timeout(Duration::from_secs(1), reports.recv())
            .await
            .expect("TCP rejection report timed out")
            .expect("policy reporter stopped");

        assert_eq!(report.0, 2);
        assert!(!report.1);
        assert!(report.2.contains("recreate the sandbox"), "{}", report.2);
        assert!(report.2.contains("previous policy remains active"));
        assert_eq!(engine.current_generation(), active_generation);
        assert!(engine.fail_closed_reason().is_none());
        handle.abort();
    }

    #[tokio::test]
    async fn same_hash_ack_waits_for_failed_middleware_reconciliation_and_retries_once() {
        let mut v1 = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        v1.policy_hash = "same-policy".to_string();
        let mut v2 = v1.clone();
        v2.version = 2;
        v2.config_revision = 200;
        v2.supervisor_middleware_services =
            vec![openshell_core::proto::SupervisorMiddlewareService {
                name: "scripted-guard".to_string(),
                grpc_endpoint: "http://scripted.invalid".to_string(),
                ..Default::default()
            }];

        let connector_attempts = Arc::new(AtomicUsize::new(0));
        let (attempt_tx, mut attempt_rx) = tokio::sync::mpsc::unbounded_channel();
        let middleware_connector: MiddlewareConnector = {
            let connector_attempts = connector_attempts.clone();
            Arc::new(move |_services, _authentication| {
                let attempt = connector_attempts.fetch_add(1, Ordering::SeqCst) + 1;
                attempt_tx.send(attempt).unwrap();
                Box::pin(async move {
                    if attempt == 1 {
                        Err(miette::miette!("scripted middleware connection failure"))
                    } else {
                        connect_middleware_registry(&[], &MiddlewareAuthentication::default()).await
                    }
                })
            })
        };

        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let loaded_revision = LoadedPolicyRevision::from_snapshot(&v1);
        let ctx = policy_poll_test_context(
            engine.clone(),
            LoadedPolicyOrigin::Gateway {
                revision: Some(loaded_revision),
                has_last_valid_policy: true,
            },
            middleware_connector,
        );
        let (client, polls, mut reports) = scripted_policy_gateway();
        polls.send(v1).unwrap();

        let handle = tokio::spawn(run_policy_poll_loop_with_client(ctx, client));
        expect_policy_report(&mut reports, 1).await;

        polls.send(v2.clone()).unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), attempt_rx.recv())
                .await
                .unwrap(),
            Some(1)
        );
        expect_no_policy_report(&mut reports).await;
        assert_eq!(engine.current_generation(), 0);

        polls.send(v2.clone()).unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), attempt_rx.recv())
                .await
                .unwrap(),
            Some(2)
        );
        expect_policy_report(&mut reports, 2).await;
        assert_eq!(engine.current_generation(), 1);

        polls.send(v2).unwrap();
        expect_no_policy_report(&mut reports).await;
        assert_eq!(connector_attempts.load(Ordering::SeqCst), 2);
        handle.abort();
    }

    #[tokio::test]
    async fn no_signer_capability_uses_legacy_middleware_connector_without_credentials() {
        let mut v1 = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        v1.policy_hash = "same-policy".to_string();
        let mut v2 = v1.clone();
        v2.version = 2;
        v2.config_revision = 200;
        v2.supervisor_middleware_services =
            vec![openshell_core::proto::SupervisorMiddlewareService {
                name: "legacy-guard".to_string(),
                grpc_endpoint: "http://legacy.invalid".to_string(),
                ..Default::default()
            }];
        assert!(!v2.extension_authentication_enabled);

        let (inner, polls, mut reports) = scripted_policy_gateway();
        let credential_requests = Arc::new(AtomicUsize::new(0));
        let client = CredentialRejectingPolicyGateway {
            inner,
            credential_requests: credential_requests.clone(),
        };
        let (connector_tx, mut connector_rx) = tokio::sync::mpsc::unbounded_channel();
        let connector: MiddlewareConnector = Arc::new(move |_services, authentication| {
            connector_tx
                .send((authentication.credentials.len(), authentication.enabled))
                .unwrap();
            Box::pin(async move {
                connect_middleware_registry(&[], &MiddlewareAuthentication::default()).await
            })
        });
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let loaded_revision = LoadedPolicyRevision::from_snapshot(&v1);
        let ctx = policy_poll_test_context(
            engine,
            LoadedPolicyOrigin::Gateway {
                revision: Some(loaded_revision),
                has_last_valid_policy: true,
            },
            connector,
        );

        polls.send(v1).unwrap();
        let handle = tokio::spawn(run_policy_poll_loop_with_client(ctx, client));
        expect_policy_report(&mut reports, 1).await;
        polls.send(v2).unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), connector_rx.recv())
                .await
                .unwrap(),
            Some((0, false))
        );
        expect_policy_report(&mut reports, 2).await;
        assert_eq!(credential_requests.load(Ordering::SeqCst), 0);
        handle.abort();
    }

    #[tokio::test]
    async fn enabled_extension_authentication_keeps_credential_failure_fail_closed() {
        let mut v1 = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        v1.policy_hash = "same-policy".to_string();
        let mut v2 = v1.clone();
        v2.version = 2;
        v2.config_revision = 200;
        v2.extension_authentication_enabled = true;
        v2.supervisor_middleware_services =
            vec![openshell_core::proto::SupervisorMiddlewareService {
                name: "authenticated-guard".to_string(),
                grpc_endpoint: "https://guard.invalid".to_string(),
                ..Default::default()
            }];

        let (inner, polls, mut reports) = scripted_policy_gateway();
        let credential_requests = Arc::new(AtomicUsize::new(0));
        let client = CredentialRejectingPolicyGateway {
            inner,
            credential_requests: credential_requests.clone(),
        };
        let (connector_tx, mut connector_rx) = tokio::sync::mpsc::unbounded_channel();
        let connector: MiddlewareConnector = Arc::new(move |_services, authentication| {
            connector_tx
                .send((authentication.credentials.len(), authentication.enabled))
                .unwrap();
            Box::pin(async move {
                if authentication.enabled && authentication.credentials.is_empty() {
                    Err(miette::miette!(
                        "missing authenticated middleware credential"
                    ))
                } else {
                    connect_middleware_registry(&[], &authentication).await
                }
            })
        });
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let loaded_revision = LoadedPolicyRevision::from_snapshot(&v1);
        let ctx = policy_poll_test_context(
            engine,
            LoadedPolicyOrigin::Gateway {
                revision: Some(loaded_revision),
                has_last_valid_policy: true,
            },
            connector,
        );

        polls.send(v1).unwrap();
        let handle = tokio::spawn(run_policy_poll_loop_with_client(ctx, client));
        expect_policy_report(&mut reports, 1).await;
        polls.send(v2).unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), connector_rx.recv())
                .await
                .unwrap(),
            Some((0, true))
        );
        expect_no_policy_report(&mut reports).await;
        assert_eq!(credential_requests.load(Ordering::SeqCst), 1);
        handle.abort();
    }

    async fn assert_poll_does_not_use_same_hash_acknowledgement(
        initial: openshell_core::grpc_client::SettingsPollResult,
        next: openshell_core::grpc_client::SettingsPollResult,
        origin: LoadedPolicyOrigin,
        initial_report: Option<u32>,
    ) {
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let ctx = policy_poll_test_context(engine.clone(), origin, default_middleware_connector());
        let (client, polls, mut reports) = scripted_policy_gateway();
        polls.send(initial).unwrap();
        let handle = tokio::spawn(run_policy_poll_loop_with_client(ctx, client));

        if let Some(version) = initial_report {
            expect_policy_report(&mut reports, version).await;
        } else {
            expect_no_policy_report(&mut reports).await;
        }

        polls.send(next).unwrap();
        expect_no_policy_report(&mut reports).await;
        assert_eq!(
            engine.current_generation(),
            0,
            "negative same-hash scope must not reload OPA"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn same_hash_ack_poll_loop_rejects_local_global_empty_equal_and_older_scopes() {
        let mut sandbox_v1 = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        sandbox_v1.policy_hash = "same-policy".to_string();
        let loaded_v1 = LoadedPolicyRevision::from_snapshot(&sandbox_v1);
        let mut sandbox_v2 = sandbox_v1.clone();
        sandbox_v2.version = 2;
        sandbox_v2.config_revision = 200;

        assert_poll_does_not_use_same_hash_acknowledgement(
            sandbox_v1.clone(),
            sandbox_v2.clone(),
            LoadedPolicyOrigin::LocalOverride,
            None,
        )
        .await;

        let mut global_v2 = sandbox_v2.clone();
        global_v2.policy_source = openshell_core::proto::PolicySource::Global;
        assert_poll_does_not_use_same_hash_acknowledgement(
            sandbox_v1.clone(),
            global_v2,
            LoadedPolicyOrigin::Gateway {
                revision: Some(loaded_v1.clone()),
                has_last_valid_policy: true,
            },
            Some(1),
        )
        .await;

        let mut empty_v1 = sandbox_v1.clone();
        empty_v1.policy_hash.clear();
        let empty_loaded = LoadedPolicyRevision::from_snapshot(&empty_v1);
        let mut empty_v2 = sandbox_v2.clone();
        empty_v2.policy_hash.clear();
        assert_poll_does_not_use_same_hash_acknowledgement(
            empty_v1,
            empty_v2,
            LoadedPolicyOrigin::Gateway {
                revision: Some(empty_loaded),
                has_last_valid_policy: true,
            },
            Some(1),
        )
        .await;

        assert_poll_does_not_use_same_hash_acknowledgement(
            sandbox_v1.clone(),
            sandbox_v1.clone(),
            LoadedPolicyOrigin::Gateway {
                revision: Some(loaded_v1.clone()),
                has_last_valid_policy: true,
            },
            Some(1),
        )
        .await;

        let loaded_v2 = LoadedPolicyRevision::from_snapshot(&sandbox_v2);
        assert_poll_does_not_use_same_hash_acknowledgement(
            sandbox_v2,
            sandbox_v1,
            LoadedPolicyOrigin::Gateway {
                revision: Some(loaded_v2),
                has_last_valid_policy: true,
            },
            Some(2),
        )
        .await;
    }

    #[tokio::test]
    async fn changed_hash_poll_uses_normal_opa_reload_and_status_path() {
        let v1 = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let v2 = settings_poll_result(
            Some(proto_policy_fixture()),
            2,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let loaded_revision = LoadedPolicyRevision::from_snapshot(&v1);
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let ctx = policy_poll_test_context(
            engine.clone(),
            LoadedPolicyOrigin::Gateway {
                revision: Some(loaded_revision),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        let (client, polls, mut reports) = scripted_policy_gateway();
        polls.send(v1).unwrap();
        let handle = tokio::spawn(run_policy_poll_loop_with_client(ctx, client));

        expect_policy_report(&mut reports, 1).await;
        polls.send(v2).unwrap();
        expect_policy_report(&mut reports, 2).await;
        assert_eq!(
            engine.current_generation(),
            1,
            "changed policy content must still reload OPA"
        );
        handle.abort();
    }

    fn outcome(
        result: &openshell_core::proto::ConfigComponentApplyResult,
    ) -> openshell_core::proto::ConfigApplyOutcome {
        openshell_core::proto::ConfigApplyOutcome::try_from(result.outcome).unwrap()
    }

    #[tokio::test]
    async fn duplicate_stream_snapshot_preserves_local_policy_override() {
        use openshell_core::proto::{ConfigApplyOutcome, PolicySource};

        let engine = Arc::new(
            OpaEngine::from_proto(&proto_policy_fixture()).expect("build local OPA engine"),
        );
        let ctx = policy_poll_test_context(
            Arc::clone(&engine),
            LoadedPolicyOrigin::LocalOverride,
            default_middleware_connector(),
        );
        let (client, _polls, _reports) = scripted_policy_gateway();
        let initial_generation = engine.current_generation();
        let candidate =
            settings_poll_result(Some(proto_tcp_policy_fixture()), 2, PolicySource::Sandbox);
        let mut runtime = ConfigRuntime::new(&ctx, Some(&candidate));
        // The first delivery is new to the runtime; the second is a duplicate.
        runtime.config_revision = 0;

        for _ in 0..2 {
            let (result, _) = runtime
                .apply_delivered_sandbox(&ctx, &client, candidate.clone())
                .await;

            assert_eq!(engine.current_generation(), initial_generation);
            assert_eq!(outcome(&result), ConfigApplyOutcome::RetainedLocalOverride);
            assert!(result.applied_revision.is_none());
            assert!(runtime.applied_revision.is_none());
        }
    }

    #[tokio::test]
    async fn failed_stream_snapshot_remains_retryable() {
        let initial = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let mut desired = settings_poll_result(
            Some(proto_policy_fixture()),
            2,
            openshell_core::proto::PolicySource::Sandbox,
        );
        desired.policy_validation_failure_mode = PolicyValidationFailureMode::RetainLastValid;
        desired.supervisor_middleware_services =
            vec![openshell_core::proto::SupervisorMiddlewareService {
                name: "unavailable-guard".into(),
                grpc_endpoint: "http://127.0.0.1:1".into(),
                max_payload_bytes: 1024,
                ..Default::default()
            }];
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        install_builtin_middleware_registry(&engine)
            .await
            .expect("install built-in middleware registry");
        let ctx = policy_poll_test_context(
            engine,
            LoadedPolicyOrigin::Gateway {
                revision: Some(LoadedPolicyRevision::from_snapshot(&initial)),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        let (client, _polls, _reports) = scripted_policy_gateway();
        let initial_revision = sandbox_config_revision(&initial);
        let mut runtime = ConfigRuntime::new(&ctx, Some(&initial));
        let _ = runtime
            .stage_delivered_provider(&ctx, provider_snapshot_for(&desired, "REGION", "west"))
            .await;

        let (result, admission) = runtime
            .apply_delivered_sandbox(&ctx, &client, desired)
            .await;

        assert_eq!(runtime.config_revision, initial.config_revision);
        assert_eq!(runtime.policy_version, initial.version);
        assert_eq!(runtime.policy_hash, initial.policy_hash);
        assert_eq!(result.applied_revision, Some(initial_revision));
        assert_eq!(
            outcome(&result),
            openshell_core::proto::ConfigApplyOutcome::FailedRetainedLastKnownGood
        );
        assert_eq!(
            admission.state,
            i32::from(openshell_core::proto::ConfigurationAdmissionState::Rejected)
        );
        // A redelivered provider snapshot retries the held configuration.
        assert!(runtime.stream.pending_sandbox.is_some());
        assert!(runtime.stream.pending_provider.is_some());
    }

    fn provider_snapshot_for(
        settings: &openshell_core::grpc_client::SettingsPollResult,
        name: &str,
        value: &str,
    ) -> openshell_core::proto::ProviderEnvironmentSnapshot {
        openshell_core::proto::ProviderEnvironmentSnapshot {
            provider_env_revision: settings.provider_env_revision,
            provider_attachment_epoch: settings.provider_attachment_epoch.clone(),
            policy_hash: settings.policy_hash.clone(),
            values: vec![openshell_core::proto::ProviderEnvironmentValue {
                name: name.to_string(),
                value: value.to_string(),
                classification:
                    openshell_core::proto::ProviderEnvironmentValueClassification::NonSecret.into(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn rejected_stream_snapshot_preserves_admitted_settings() {
        use openshell_core::proto::{ConfigApplyOutcome, PolicySource};

        let mut initial =
            settings_poll_result(Some(proto_policy_fixture()), 1, PolicySource::Sandbox);
        initial
            .settings
            .insert("ocsf_json_enabled".to_string(), effective_bool(true));
        initial.settings.insert(
            openshell_core::settings::AGENT_POLICY_PROPOSALS_ENABLED_KEY.to_string(),
            effective_bool(true),
        );
        let mut rejected = initial.clone();
        rejected.version = 2;
        rejected.config_revision = 200;
        rejected.settings_revision = 2;
        rejected.configuration_admitted = false;
        rejected.configuration_error = "invalid policy".to_string();
        rejected.policy_validation_failure_mode = PolicyValidationFailureMode::RetainLastValid;
        rejected
            .settings
            .insert("ocsf_json_enabled".to_string(), effective_bool(false));
        rejected.settings.insert(
            openshell_core::settings::AGENT_POLICY_PROPOSALS_ENABLED_KEY.to_string(),
            effective_bool(false),
        );

        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let ctx = policy_poll_test_context(
            engine,
            LoadedPolicyOrigin::Gateway {
                revision: Some(LoadedPolicyRevision::from_snapshot(&initial)),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        ctx.ocsf_enabled.store(true, Ordering::Relaxed);
        ctx.agent_proposals.set_enabled(true);
        let (client, _polls, _reports) = scripted_policy_gateway();
        let mut runtime = ConfigRuntime::new(&ctx, Some(&initial));
        let initial_revision = sandbox_config_revision(&initial);
        let (result, _) = runtime
            .apply_delivered_sandbox(&ctx, &client, rejected)
            .await;

        assert_eq!(
            outcome(&result),
            ConfigApplyOutcome::FailedRetainedLastKnownGood
        );
        assert_eq!(result.applied_revision, Some(initial_revision));
        assert!(ctx.ocsf_enabled.load(Ordering::Relaxed));
        assert!(ctx.agent_proposals.enabled());
        assert_eq!(runtime.settings, initial.settings);
    }

    #[tokio::test]
    async fn stream_configuration_never_polls_gateway_settings() {
        let initial = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let mut ctx = policy_poll_test_context(
            engine,
            LoadedPolicyOrigin::Gateway {
                revision: Some(LoadedPolicyRevision::from_snapshot(&initial)),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        ctx.initial_stream_snapshot = Some(initial);
        let (config_apply_tx, config_apply_rx) = tokio::sync::mpsc::channel(1);
        ctx.config_apply_rx = Some(config_apply_rx);
        let (client, _polls, _reports) = scripted_policy_gateway();
        let poll_calls = Arc::clone(&client.poll_calls);

        let handle = tokio::spawn(run_policy_poll_loop_with_client(ctx, client));
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        config_apply_tx
            .send(ConfigApplyRequest::Update {
                update: openshell_core::proto::ConfigUpdate {
                    update_id: "provider-2".to_string(),
                    component_sequence: 1,
                    component: Some(
                        openshell_core::proto::config_update::Component::ProviderEnvironment(
                            openshell_core::proto::ProviderEnvironmentSnapshot {
                                provider_env_revision: 2,
                                ..Default::default()
                            },
                        ),
                    ),
                },
                response: response_tx,
            })
            .await
            .unwrap();
        timeout(Duration::from_secs(1), response_rx)
            .await
            .expect("stream update timed out")
            .expect("stream update responder stopped");

        assert_eq!(poll_calls.load(Ordering::SeqCst), 0);
        handle.abort();
    }

    async fn deliver_update(
        config_apply_tx: &tokio::sync::mpsc::Sender<ConfigApplyRequest>,
        update_id: &str,
        component: openshell_core::proto::config_update::Component,
    ) -> openshell_core::proto::ConfigUpdateResult {
        let (response, receiver) = tokio::sync::oneshot::channel();
        config_apply_tx
            .send(ConfigApplyRequest::Update {
                update: openshell_core::proto::ConfigUpdate {
                    update_id: update_id.to_string(),
                    component_sequence: 1,
                    component: Some(component),
                },
                response,
            })
            .await
            .unwrap();
        timeout(Duration::from_secs(5), receiver)
            .await
            .expect("stream update timed out")
            .expect("stream update responder stopped")
    }

    #[tokio::test]
    async fn stream_policy_status_is_reported_only_in_acknowledgements() {
        use openshell_core::proto::{ConfigApplyOutcome, PolicySource, config_update::Component};

        let initial = settings_poll_result(Some(proto_policy_fixture()), 1, PolicySource::Sandbox);
        let desired = settings_poll_result(Some(proto_policy_fixture()), 2, PolicySource::Sandbox);
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let mut ctx = policy_poll_test_context(
            engine,
            LoadedPolicyOrigin::Gateway {
                revision: Some(LoadedPolicyRevision::from_snapshot(&initial)),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        ctx.initial_stream_snapshot = Some(initial);
        let (config_apply_tx, config_apply_rx) = tokio::sync::mpsc::channel(1);
        ctx.config_apply_rx = Some(config_apply_rx);
        let (client, _polls, mut reports) = scripted_policy_gateway();
        let handle = tokio::spawn(run_policy_poll_loop_with_client(ctx, client));

        let provider = deliver_update(
            &config_apply_tx,
            "provider-2",
            Component::ProviderEnvironment(provider_snapshot_for(&desired, "REGION", "west")),
        )
        .await;
        assert_eq!(
            outcome(provider.result.as_ref().unwrap()),
            ConfigApplyOutcome::AwaitingComponent
        );
        let sandbox = deliver_update(
            &config_apply_tx,
            "sandbox-2",
            Component::SandboxConfig(openshell_core::proto::SandboxConfigSnapshot {
                version: desired.version,
                policy_hash: desired.policy_hash.clone(),
                config_revision: desired.config_revision,
                policy_source: PolicySource::Sandbox.into(),
                policy: desired.policy.clone(),
                configuration_admitted: true,
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(
            outcome(sandbox.result.as_ref().unwrap()),
            ConfigApplyOutcome::Applied
        );

        // The acknowledgement carries the loaded policy version; the polling
        // status RPC must not report it a second time.
        assert!(
            timeout(Duration::from_millis(200), reports.recv())
                .await
                .is_err()
        );
        handle.abort();
    }

    #[tokio::test]
    async fn stream_started_runtime_polls_when_session_stops_applying() {
        let initial = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let mut ctx = policy_poll_test_context(
            engine,
            LoadedPolicyOrigin::Gateway {
                revision: Some(LoadedPolicyRevision::from_snapshot(&initial)),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        ctx.initial_stream_snapshot = Some(initial);
        let (_config_apply_tx, config_apply_rx) = tokio::sync::mpsc::channel(1);
        ctx.config_apply_rx = Some(config_apply_rx);
        let (apply_enabled_tx, apply_enabled_rx) = tokio::sync::watch::channel(true);
        ctx.config_push_enabled = Some(apply_enabled_rx);
        let (client, _polls, _reports) = scripted_policy_gateway();
        let poll_calls = Arc::clone(&client.poll_calls);

        let handle = tokio::spawn(run_policy_poll_loop_with_client(ctx, client));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(poll_calls.load(Ordering::SeqCst), 0);

        // A reconnect lands on a gateway that keeps polling authoritative.
        apply_enabled_tx.send_replace(false);
        timeout(Duration::from_secs(5), async {
            while poll_calls.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("a session without apply must resume polling");
        handle.abort();
    }

    #[tokio::test]
    async fn streamed_tcp_expansion_reports_retained_active_policy() {
        use openshell_core::proto::{ConfigApplyOutcome, PolicySource};

        let engine = Arc::new(
            OpaEngine::from_proto(&proto_policy_fixture()).expect("build initial OPA engine"),
        );
        let mut ctx = policy_poll_test_context(
            Arc::clone(&engine),
            LoadedPolicyOrigin::Gateway {
                revision: None,
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        ctx.transparent_tcp = TransparentTcpReloadState {
            capable: true,
            substrate_ready: false,
        };
        let initial = settings_poll_result(Some(proto_policy_fixture()), 1, PolicySource::Sandbox);
        let mut candidate =
            settings_poll_result(Some(proto_tcp_policy_fixture()), 2, PolicySource::Sandbox);
        candidate.policy_validation_failure_mode = PolicyValidationFailureMode::FailClosed;
        let (client, _polls, _reports) = scripted_policy_gateway();
        let initial_revision = sandbox_config_revision(&initial);
        let initial_generation = engine.current_generation();
        let mut runtime = ConfigRuntime::new(&ctx, Some(&initial));
        let _ = runtime
            .stage_delivered_provider(&ctx, provider_snapshot_for(&candidate, "REGION", "west"))
            .await;
        let (result, _) = runtime
            .apply_delivered_sandbox(&ctx, &client, candidate)
            .await;

        assert_eq!(engine.current_generation(), initial_generation);
        assert!(engine.fail_closed_reason().is_none());
        assert_eq!(
            outcome(&result),
            ConfigApplyOutcome::FailedRetainedLastKnownGood
        );
        assert_eq!(result.applied_revision, Some(initial_revision));
        assert!(
            result
                .failure
                .as_ref()
                .unwrap()
                .message
                .contains("without the transparent TCP substrate")
        );
        // Readiness reports the rejected generation rather than claiming the
        // retained policy as evidence for it.
        assert_eq!(
            ctx.provider_readiness
                .observation(&ctx.provider_credentials)
                .reason,
            i32::from(ProviderReadinessReason::PolicyActivationFailed)
        );
    }

    #[tokio::test]
    async fn stream_provider_rotation_rebinds_policy_generation() {
        use openshell_core::proto::PolicySource;

        let initial = settings_poll_result(Some(proto_policy_fixture()), 1, PolicySource::Sandbox);
        let mut desired = initial.clone();
        desired.config_revision = 200;
        desired.provider_env_revision = 19;
        desired.provider_attachment_epoch = "epoch-19".to_string();
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let initial_generation = engine.current_generation();
        let ctx = policy_poll_test_context(
            engine,
            LoadedPolicyOrigin::Gateway {
                revision: Some(LoadedPolicyRevision::from_snapshot(&initial)),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        let (client, _polls, _reports) = scripted_policy_gateway();
        let mut runtime = ConfigRuntime::new(&ctx, Some(&initial));
        let _ = runtime
            .stage_delivered_provider(&ctx, provider_snapshot_for(&desired, "REGION", "west"))
            .await;

        let (applied, _) = runtime
            .apply_delivered_sandbox(&ctx, &client, desired.clone())
            .await;

        assert!(config_apply_result_activates(&applied));
        // As with polling, the credentials install with a fresh generation of
        // the unchanged policy, and readiness binds to that generation.
        assert!(ctx.opa_engine.current_generation() > initial_generation);
        let observed = ctx
            .provider_readiness
            .observation(&ctx.provider_credentials);
        assert!(observed.credentials_installed);
        assert!(observed.policy_active);
        assert_eq!(observed.provider_env_revision, 19);
        assert_eq!(observed.config_revision, 200);
        assert_eq!(observed.attachment_epoch, "epoch-19");
        assert_eq!(observed.policy_hash, desired.policy_hash);
    }

    #[tokio::test]
    async fn stream_provider_snapshot_waits_for_matching_sandbox_generation() {
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let ctx = policy_poll_test_context(
            engine,
            LoadedPolicyOrigin::Gateway {
                revision: None,
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        let initial = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let mut desired = settings_poll_result(
            Some(proto_policy_fixture()),
            2,
            openshell_core::proto::PolicySource::Sandbox,
        );
        desired.provider_env_revision = 17;
        desired.provider_attachment_epoch = "epoch-b".to_string();
        let mut runtime = ConfigRuntime::new(&ctx, Some(&initial));
        let result = runtime
            .stage_delivered_provider(&ctx, provider_snapshot_for(&desired, "REGION", "west"))
            .await;

        assert_eq!(
            outcome(&result),
            openshell_core::proto::ConfigApplyOutcome::AwaitingComponent
        );
        assert!(result.failure.is_none());
        assert_eq!(ctx.provider_credentials.snapshot().revision, 0);
        assert!(
            !ctx.provider_credentials
                .snapshot()
                .child_env
                .contains_key("REGION")
        );

        let (client, _polls, _reports) = scripted_policy_gateway();
        let (applied, _) = runtime
            .apply_delivered_sandbox(&ctx, &client, desired.clone())
            .await;
        assert!(config_apply_result_activates(&applied));
        let sandbox_revision_token = sandbox_config_revision(&desired);
        assert_eq!(
            applied.requested_revision,
            Some(sandbox_revision_token.clone())
        );
        assert_eq!(applied.applied_revision, Some(sandbox_revision_token));
        assert_eq!(runtime.provider_env_revision, 17);
        assert_eq!(ctx.provider_credentials.snapshot().revision, 17);
        assert!(
            ctx.provider_credentials
                .snapshot()
                .child_env
                .contains_key("REGION")
        );
        let provider_retry = runtime
            .stage_delivered_provider(&ctx, provider_snapshot_for(&desired, "REGION", "west"))
            .await;
        assert_eq!(
            outcome(&provider_retry),
            openshell_core::proto::ConfigApplyOutcome::IgnoredDuplicate
        );
        let provider_revision_token = provider_config_revision(17);
        assert_eq!(
            provider_retry.requested_revision,
            Some(provider_revision_token.clone())
        );
        assert_eq!(
            provider_retry.applied_revision,
            Some(provider_revision_token)
        );
    }

    #[tokio::test]
    async fn stream_sandbox_snapshot_applies_without_fetching() {
        let initial = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let desired = settings_poll_result(
            Some(proto_policy_fixture()),
            2,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let ctx = policy_poll_test_context(
            engine,
            LoadedPolicyOrigin::Gateway {
                revision: Some(LoadedPolicyRevision::from_snapshot(&initial)),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        let (client, _polls, _reports) = scripted_policy_gateway();
        let mut runtime = ConfigRuntime::new(&ctx, Some(&initial));
        let _ = runtime
            .stage_delivered_provider(&ctx, provider_snapshot_for(&desired, "REGION", "west"))
            .await;

        let (result, _) = runtime
            .apply_delivered_sandbox(&ctx, &client, desired.clone())
            .await;

        assert_eq!(runtime.config_revision, desired.config_revision);
        assert_eq!(runtime.policy_version, desired.version);
        assert_eq!(runtime.policy_hash, desired.policy_hash);
        assert_eq!(
            outcome(&result),
            openshell_core::proto::ConfigApplyOutcome::Applied
        );
        assert_eq!(client.poll_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn stream_sandbox_snapshot_waits_for_provider_delivered_second() {
        use openshell_core::proto::{ConfigApplyOutcome, PolicySource};

        let initial = settings_poll_result(Some(proto_policy_fixture()), 1, PolicySource::Sandbox);
        let mut desired =
            settings_poll_result(Some(proto_policy_fixture()), 2, PolicySource::Sandbox);
        desired.provider_env_revision = 23;
        desired.provider_attachment_epoch = "epoch-23".to_string();
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let ctx = policy_poll_test_context(
            engine,
            LoadedPolicyOrigin::Gateway {
                revision: Some(LoadedPolicyRevision::from_snapshot(&initial)),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        let (client, _polls, _reports) = scripted_policy_gateway();
        let mut runtime = ConfigRuntime::new(&ctx, Some(&initial));

        let (waiting, _) = runtime
            .apply_delivered_sandbox(&ctx, &client, desired.clone())
            .await;
        assert_eq!(outcome(&waiting), ConfigApplyOutcome::AwaitingComponent);
        assert!(waiting.failure.is_none());
        assert!(runtime.stream.pending_sandbox.is_some());
        assert_eq!(ctx.provider_credentials.snapshot().revision, 0);

        let provider_revision_token = provider_config_revision(desired.provider_env_revision);
        let (response, receiver) = tokio::sync::oneshot::channel();
        runtime
            .apply_delivered(
                &ctx,
                &client,
                ConfigApplyRequest::Update {
                    update: openshell_core::proto::ConfigUpdate {
                        update_id: "provider-second".to_string(),
                        component_sequence: 1,
                        component: Some(
                            openshell_core::proto::config_update::Component::ProviderEnvironment(
                                provider_snapshot_for(&desired, "REGION", "west"),
                            ),
                        ),
                    },
                    response,
                },
            )
            .await;
        let provider_result = receiver
            .await
            .expect("provider result")
            .result
            .expect("provider component result");
        assert_eq!(outcome(&provider_result), ConfigApplyOutcome::Applied);
        assert_eq!(
            provider_result.requested_revision,
            Some(provider_revision_token.clone())
        );
        assert_eq!(
            provider_result.applied_revision,
            Some(provider_revision_token)
        );
        assert!(runtime.stream.pending_sandbox.is_none());

        let (applied, admission) = runtime
            .apply_delivered_sandbox(&ctx, &client, desired.clone())
            .await;
        assert_eq!(outcome(&applied), ConfigApplyOutcome::IgnoredDuplicate);
        let desired_revision = sandbox_config_revision(&desired);
        assert_eq!(applied.requested_revision, Some(desired_revision.clone()));
        assert_eq!(applied.applied_revision, Some(desired_revision));
        assert_eq!(
            admission.state,
            i32::from(openshell_core::proto::ConfigurationAdmissionState::Accepted)
        );
        assert_eq!(runtime.provider_env_revision, 23);
        assert_eq!(ctx.provider_credentials.snapshot().revision, 23);
        assert!(
            ctx.provider_credentials
                .snapshot()
                .child_env
                .contains_key("REGION")
        );
    }

    #[tokio::test]
    async fn duplicate_rejected_stream_snapshot_does_not_advance_fail_closed_generation() {
        use openshell_core::proto::{ConfigApplyOutcome, PolicySource};

        let mut rejected =
            settings_poll_result(Some(proto_policy_fixture()), 2, PolicySource::Sandbox);
        rejected.config_revision = 200;
        rejected.settings_revision = 2;
        rejected.configuration_admitted = false;
        rejected.configuration_error = "invalid policy".to_string();
        rejected.policy_validation_failure_mode = PolicyValidationFailureMode::FailClosed;

        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let initial_generation = engine.current_generation();
        let ctx = policy_poll_test_context(
            engine,
            LoadedPolicyOrigin::Gateway {
                revision: None,
                has_last_valid_policy: false,
            },
            default_middleware_connector(),
        );
        let (client, _polls, _reports) = scripted_policy_gateway();
        let mut runtime = ConfigRuntime::new(&ctx, None);

        let (result, _) = runtime
            .apply_delivered_sandbox(&ctx, &client, rejected.clone())
            .await;

        assert_eq!(outcome(&result), ConfigApplyOutcome::FailedClosed);
        let rejected_generation = ctx.opa_engine.current_generation();
        assert!(rejected_generation > initial_generation);

        let (duplicate, _) = runtime
            .apply_delivered_sandbox(&ctx, &client, rejected)
            .await;

        assert_eq!(duplicate, result);
        assert_eq!(ctx.opa_engine.current_generation(), rejected_generation);
    }

    #[tokio::test]
    async fn stream_snapshot_restoring_rejected_policy_clears_quarantine() {
        use openshell_core::proto::{ConfigApplyOutcome, PolicySource};

        let initial = settings_poll_result(Some(proto_policy_fixture()), 1, PolicySource::Sandbox);
        let mut rejected = initial.clone();
        rejected.version = 2;
        rejected.policy_hash = "hash-v2".to_string();
        rejected.config_revision = 200;
        rejected.configuration_admitted = false;
        rejected.configuration_error = "invalid policy".to_string();
        rejected.policy_validation_failure_mode = PolicyValidationFailureMode::FailClosed;
        // A later generation restores byte-identical policy content.
        let mut restored = initial.clone();
        restored.version = 3;
        restored.config_revision = 300;

        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let ctx = policy_poll_test_context(
            Arc::clone(&engine),
            LoadedPolicyOrigin::Gateway {
                revision: Some(LoadedPolicyRevision::from_snapshot(&initial)),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        let (client, _polls, _reports) = scripted_policy_gateway();
        let mut runtime = ConfigRuntime::new(&ctx, Some(&initial));

        let (result, _) = runtime
            .apply_delivered_sandbox(&ctx, &client, rejected)
            .await;
        assert_eq!(outcome(&result), ConfigApplyOutcome::FailedClosed);
        assert!(engine.fail_closed_reason().is_some());
        let quarantined_generation = engine.current_generation();

        let (result, admission) = runtime
            .apply_delivered_sandbox(&ctx, &client, restored.clone())
            .await;
        assert_eq!(outcome(&result), ConfigApplyOutcome::Applied);
        assert_eq!(
            result.applied_revision,
            Some(sandbox_config_revision(&restored))
        );
        assert_eq!(
            admission.state,
            i32::from(openshell_core::proto::ConfigurationAdmissionState::Accepted)
        );
        // Matching policy bytes must not leave the runtime deny-all.
        assert!(engine.fail_closed_reason().is_none());
        assert!(engine.current_generation() > quarantined_generation);
        assert_eq!(runtime.policy_version, restored.version);
    }

    #[tokio::test]
    async fn failed_stream_provider_snapshot_revokes_static_credentials() {
        use openshell_core::proto::{ConfigApplyOutcome, PolicySource};

        let initial = settings_poll_result(Some(proto_policy_fixture()), 1, PolicySource::Sandbox);
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let mut ctx = policy_poll_test_context(
            engine,
            LoadedPolicyOrigin::Gateway {
                revision: Some(LoadedPolicyRevision::from_snapshot(&initial)),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        let mut runtime = ConfigRuntime::new(&ctx, Some(&initial));
        for (revision, readiness_reason, classification, expected_code) in [
            (
                2,
                ProviderReadinessReason::UnsupportedSupervisor,
                openshell_core::proto::ProviderEnvironmentValueClassification::NonSecret,
                "provider_environment_unavailable",
            ),
            (
                3,
                ProviderReadinessReason::Unspecified,
                openshell_core::proto::ProviderEnvironmentValueClassification::Unspecified,
                "invalid_provider_environment",
            ),
        ] {
            ctx.provider_credentials = initial_provider_credentials(
                static_provider_environment(1, Some("initial")),
                &ctx.provider_readiness,
            );
            assert!(
                ctx.provider_credentials
                    .resolver_for_endpoint("tools.example.com", 443, "/v1/chat")
                    .is_some()
            );
            let mut snapshot = provider_snapshot_for(&initial, "REGION", "west");
            snapshot.provider_env_revision = revision;
            snapshot.readiness_reason = readiness_reason.into();
            snapshot.values[0].classification = classification.into();

            let result = runtime.stage_delivered_provider(&ctx, snapshot).await;

            assert_eq!(outcome(&result), ConfigApplyOutcome::FailedClosed);
            assert_eq!(result.failure.as_ref().unwrap().code, expected_code);
            assert!(runtime.stream.pending_provider.is_none());
            assert!(ctx.provider_credentials.resolver().is_none());
            assert!(
                !ctx.provider_credentials
                    .snapshot()
                    .child_env
                    .contains_key("EXTERNAL_TOKEN")
            );
            assert!(
                !ctx.provider_readiness
                    .observation(&ctx.provider_credentials)
                    .credentials_installed
            );
        }
    }

    #[tokio::test]
    async fn stream_snapshot_drops_credentials_of_removed_middleware() {
        use openshell_core::proto::{ConfigApplyOutcome, PolicySource};

        let mut initial =
            settings_poll_result(Some(proto_policy_fixture()), 1, PolicySource::Sandbox);
        initial.extension_authentication_enabled = true;
        initial.supervisor_middleware_services =
            vec![openshell_core::proto::SupervisorMiddlewareService {
                name: "removed-guard".to_string(),
                grpc_endpoint: "http://removed.invalid".to_string(),
                ..Default::default()
            }];
        let mut desired =
            settings_poll_result(Some(proto_policy_fixture()), 2, PolicySource::Sandbox);
        desired.extension_authentication_enabled = true;
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let ctx = policy_poll_test_context(
            engine,
            LoadedPolicyOrigin::Gateway {
                revision: Some(LoadedPolicyRevision::from_snapshot(&initial)),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        let now_ms = openshell_core::time::now_ms();
        ctx.extension_credentials
            .install("removed-guard", "token", now_ms + 3_600_000, now_ms)
            .expect("install extension credential");
        let (client, _polls, _reports) = scripted_policy_gateway();
        let mut runtime = ConfigRuntime::new(&ctx, Some(&initial));
        let _ = runtime
            .stage_delivered_provider(&ctx, provider_snapshot_for(&desired, "REGION", "west"))
            .await;

        let (result, _) = runtime
            .apply_delivered_sandbox(&ctx, &client, desired)
            .await;

        assert_eq!(outcome(&result), ConfigApplyOutcome::Applied);
        assert!(runtime.middleware_services.is_empty());
        assert!(ctx.extension_credentials.get("removed-guard").is_none());
    }

    /// Mirrors the gateway's `validate_component_apply_result`; a result that
    /// violates it makes the gateway end the supervisor session.
    fn gateway_accepts_result(result: &openshell_core::proto::ConfigComponentApplyResult) -> bool {
        use openshell_core::proto::ConfigApplyOutcome;

        let Some(requested) = result.requested_revision.as_ref() else {
            return false;
        };
        let applied_matches_request = result.applied_revision.as_ref() == Some(requested);
        match ConfigApplyOutcome::try_from(result.outcome).unwrap_or_default() {
            ConfigApplyOutcome::Applied
            | ConfigApplyOutcome::IgnoredDuplicate
            | ConfigApplyOutcome::Degraded => applied_matches_request,
            ConfigApplyOutcome::RetainedLocalOverride
            | ConfigApplyOutcome::FailedClosed
            | ConfigApplyOutcome::AwaitingComponent => result.applied_revision.is_none(),
            ConfigApplyOutcome::FailedRetainedLastKnownGood => {
                result.applied_revision.is_some() && !applied_matches_request
            }
            ConfigApplyOutcome::IgnoredStale | ConfigApplyOutcome::Unsupported => true,
            ConfigApplyOutcome::Unspecified => false,
        }
    }

    /// A stream-started runtime whose startup middleware was unreachable.
    struct DegradedStreamStartup {
        ctx: PolicyPollLoopContext,
        engine: Arc<OpaEngine>,
        runtime: ConfigRuntime,
        startup: openshell_core::grpc_client::SettingsPollResult,
        middleware_available: Arc<AtomicBool>,
        client: ScriptedPolicyGateway,
    }

    fn degraded_stream_startup() -> DegradedStreamStartup {
        use openshell_core::proto::PolicySource;

        let mut startup =
            settings_poll_result(Some(proto_policy_fixture()), 1, PolicySource::Sandbox);
        startup.supervisor_middleware_services =
            vec![openshell_core::proto::SupervisorMiddlewareService {
                name: "late-guard".to_string(),
                grpc_endpoint: "http://late.invalid".to_string(),
                ..Default::default()
            }];
        let middleware_available = Arc::new(AtomicBool::new(false));
        let connector_available = Arc::clone(&middleware_available);
        let connector: MiddlewareConnector = Arc::new(move |_services, _authentication| {
            let available = connector_available.load(Ordering::SeqCst);
            Box::pin(async move {
                if available {
                    connect_middleware_registry(&[], &MiddlewareAuthentication::default()).await
                } else {
                    Err(miette::miette!("middleware is still unavailable"))
                }
            })
        });
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let mut ctx = policy_poll_test_context(
            Arc::clone(&engine),
            LoadedPolicyOrigin::Gateway {
                revision: Some(LoadedPolicyRevision::from_snapshot(&startup)),
                has_last_valid_policy: true,
            },
            connector,
        );
        ctx.middleware_registry_status = MiddlewareRegistryStatus::NeedsReconciliation;
        let mut runtime = ConfigRuntime::new(&ctx, Some(&startup));
        // Bind startup evidence as the stream-started loop does.
        let generation = engine
            .generation_guard(engine.current_generation())
            .expect("startup generation");
        ctx.provider_readiness.policy_activated(
            &EnvironmentIdentity::from_settings(&startup),
            startup.config_revision,
            generation.clone(),
        );
        runtime.policy_generation = Some(generation);
        let (client, _polls, _reports) = scripted_policy_gateway();
        DegradedStreamStartup {
            ctx,
            engine,
            runtime,
            startup,
            middleware_available,
            client,
        }
    }

    #[tokio::test]
    async fn degraded_stream_startup_retries_middleware_registry() {
        let DegradedStreamStartup {
            ctx,
            engine,
            mut runtime,
            middleware_available,
            client,
            ..
        } = degraded_stream_startup();
        let initial_generation = engine.current_generation();

        runtime.retry_degraded_startup(&ctx, &client).await;
        assert_eq!(
            runtime.middleware_registry_status,
            MiddlewareRegistryStatus::NeedsReconciliation
        );
        assert!(runtime.stream.degraded_startup.is_some());
        assert_eq!(engine.current_generation(), initial_generation);
        // The startup configuration is still enforced, so a failed retry does
        // not report a failed policy activation.
        assert!(
            ctx.provider_readiness
                .observation(&ctx.provider_credentials)
                .policy_active
        );

        middleware_available.store(true, Ordering::SeqCst);
        runtime.retry_degraded_startup(&ctx, &client).await;
        assert_eq!(
            runtime.middleware_registry_status,
            MiddlewareRegistryStatus::Synchronized
        );
        assert!(runtime.stream.degraded_startup.is_none());
        assert!(engine.current_generation() > initial_generation);
    }

    #[tokio::test]
    async fn degraded_stream_startup_retry_keeps_later_quarantine() {
        use openshell_core::proto::ConfigApplyOutcome;

        let DegradedStreamStartup {
            ctx,
            engine,
            mut runtime,
            startup,
            middleware_available,
            client,
        } = degraded_stream_startup();
        let mut rejected = startup.clone();
        rejected.version = 2;
        rejected.policy_hash = "hash-v2".to_string();
        rejected.config_revision = 200;
        rejected.configuration_admitted = false;
        rejected.configuration_error = "invalid policy".to_string();
        rejected.policy_validation_failure_mode = PolicyValidationFailureMode::FailClosed;

        let (result, _) = runtime
            .apply_delivered_sandbox(&ctx, &client, rejected.clone())
            .await;
        assert_eq!(outcome(&result), ConfigApplyOutcome::FailedClosed);
        assert!(gateway_accepts_result(&result));
        let quarantined_generation = engine.current_generation();

        middleware_available.store(true, Ordering::SeqCst);
        runtime.retry_degraded_startup(&ctx, &client).await;

        // The sandbox stays deny-all and the startup policy is not reinstalled.
        assert!(engine.fail_closed_reason().is_some());
        assert_eq!(engine.current_generation(), quarantined_generation);
        assert_eq!(runtime.config_revision, startup.config_revision);
        let (redelivered, _) = runtime
            .apply_delivered_sandbox(&ctx, &client, rejected)
            .await;
        assert_eq!(outcome(&redelivered), ConfigApplyOutcome::FailedClosed);
        assert!(engine.fail_closed_reason().is_some());
    }

    #[tokio::test]
    async fn degraded_stream_startup_retry_does_not_replace_later_failure() {
        use openshell_core::proto::{ConfigApplyOutcome, PolicySource};

        let DegradedStreamStartup {
            ctx,
            engine,
            mut runtime,
            startup,
            middleware_available,
            client,
        } = degraded_stream_startup();
        let mut later =
            settings_poll_result(Some(proto_policy_fixture()), 3, PolicySource::Sandbox);
        later
            .supervisor_middleware_services
            .clone_from(&startup.supervisor_middleware_services);
        let _ = runtime
            .stage_delivered_provider(&ctx, provider_snapshot_for(&later, "REGION", "west"))
            .await;

        let (result, _) = runtime.apply_delivered_sandbox(&ctx, &client, later).await;
        assert_eq!(
            outcome(&result),
            ConfigApplyOutcome::FailedRetainedLastKnownGood
        );
        assert_eq!(
            result.applied_revision,
            Some(sandbox_config_revision(&startup))
        );
        assert!(gateway_accepts_result(&result));
        let failed_generation = engine.current_generation();

        middleware_available.store(true, Ordering::SeqCst);
        runtime.retry_degraded_startup(&ctx, &client).await;

        assert_eq!(engine.current_generation(), failed_generation);
        assert!(runtime.stream.degraded_startup.is_none());
        assert_eq!(runtime.config_revision, startup.config_revision);
        assert_eq!(
            runtime.middleware_registry_status,
            MiddlewareRegistryStatus::NeedsReconciliation
        );
    }

    #[tokio::test]
    async fn redelivered_degraded_startup_bootstrap_reports_degraded() {
        use openshell_core::proto::{ConfigApplyOutcome, ConfigurationAdmissionState};

        let DegradedStreamStartup {
            ctx,
            engine,
            mut runtime,
            startup,
            client,
            ..
        } = degraded_stream_startup();
        let bootstrap = openshell_core::proto::ConfigBootstrap {
            sandbox_config: Some(openshell_core::proto::SandboxConfigSnapshot {
                version: startup.version,
                policy_hash: startup.policy_hash.clone(),
                config_revision: startup.config_revision,
                policy_source: startup.policy_source.into(),
                policy: startup.policy.clone(),
                supervisor_middleware_services: startup.supervisor_middleware_services.clone(),
                configuration_admitted: true,
                ..Default::default()
            }),
            provider_environment: Some(provider_snapshot_for(&startup, "REGION", "west")),
        };
        let (response, receiver) = tokio::sync::oneshot::channel();

        runtime
            .apply_delivered(
                &ctx,
                &client,
                ConfigApplyRequest::Bootstrap {
                    bootstrap,
                    response,
                },
            )
            .await;

        let result = receiver.await.expect("bootstrap result");
        let outcomes = result.results.iter().map(outcome).collect::<Vec<_>>();
        assert_eq!(
            outcomes,
            [
                ConfigApplyOutcome::IgnoredDuplicate,
                ConfigApplyOutcome::Degraded
            ]
        );
        assert!(result.results.iter().all(gateway_accepts_result));
        assert!(result.results.iter().all(config_apply_result_activates));
        assert_eq!(
            result.admission.expect("bootstrap admission").state,
            i32::from(ConfigurationAdmissionState::Accepted)
        );
        assert!(engine.fail_closed_reason().is_none());
        assert!(runtime.stream.degraded_startup.is_some());
        assert!(
            ctx.provider_readiness
                .observation(&ctx.provider_credentials)
                .policy_active
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stream_bootstrap_starts_degraded_when_middleware_is_unavailable() {
        use openshell_core::proto::PolicySource;

        let mut snapshot =
            settings_poll_result(Some(proto_policy_fixture()), 1, PolicySource::Sandbox);
        enrich_proto_baseline_paths(snapshot.policy.as_mut().unwrap());
        snapshot.supervisor_middleware_services =
            vec![openshell_core::proto::SupervisorMiddlewareService {
                name: "unavailable-guard".to_string(),
                grpc_endpoint: "http://127.0.0.1:1".to_string(),
                ..Default::default()
            }];

        let (_, engine, _, status, origin, _, _, _) = load_stream_bootstrap_policy(
            "sandbox-test",
            "http://127.0.0.1:1",
            snapshot,
            &openshell_extension_core::ExtensionCredentialStore::new(),
            None,
        )
        .await
        .expect("an unreachable middleware service must not fail startup");

        assert_eq!(status, MiddlewareRegistryStatus::NeedsReconciliation);
        assert!(engine.is_some());
        assert!(origin.allows_gateway_policy_reload());
    }
}
