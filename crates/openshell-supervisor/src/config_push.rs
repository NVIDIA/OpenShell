// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration loop for a supervisor that can receive pushed configuration.
//!
//! When the gateway session pushes configuration, the supervisor stops
//! polling. Snapshots and answers flow over the session, and each snapshot
//! goes through the same [`ConfigApplier`] that polling uses. While no
//! session pushes (the gateway runs in poll mode, or the session is down),
//! the loop polls as before.
//!
//! The two pushed parts arrive and are answered independently. A policy part
//! that needs a provider environment the supervisor has not received is held
//! and answered `AWAITING_COMPONENT`; the gateway then sends the matching
//! provider environment. A provider environment is installed only with a
//! policy part that names its exact identity.

use std::time::Duration;

use miette::Result;
use openshell_core::grpc_client::{
    ProviderEnvironmentResult, SettingsPollResult, provider_environment_result,
    settings_poll_result,
};
use openshell_core::proto::{
    ConfigApplyOutcome, ConfigPartIdentity, ConfigPartResult, ConfigUpdate, ConfigUpdateResult,
    GetSandboxConfigResponse, GetSandboxProviderEnvironmentResponse,
};
use openshell_supervisor_process::supervisor_session::{
    ConfigDeliveryState, ConfigPushReceiver, ConfigReply, PushedConfig,
};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use super::{
    AdmissionReporter, ApplyOutcome, ApplyReport, ConfigApplier, FetchedProviderEnvironment,
    MiddlewareRegistryStatus, PolicyGatewayClient, PolicyPollLoopContext,
    ProviderEnvironmentSource, ProviderFetch, RpcAdmissionReporter, next_poll_delay,
};
use crate::provider_readiness::EnvironmentIdentity;

/// Pushed policy results answer admission through the session; the gateway
/// records it from the answer.
struct PushedAdmission;

#[tonic::async_trait]
impl AdmissionReporter for PushedAdmission {
    async fn report(
        &self,
        _ctx: &PolicyPollLoopContext,
        _snapshot: &SettingsPollResult,
        _accepted: bool,
        _error: &str,
    ) -> bool {
        true
    }
}

/// The latest pushed provider environment, when it matches the policy part
/// being applied.
struct PushedProviderEnvironment<'a> {
    latest: Option<&'a ProviderEnvironmentResult>,
}

#[tonic::async_trait]
impl ProviderEnvironmentSource for PushedProviderEnvironment<'_> {
    async fn provider_environment(&self, desired: &EnvironmentIdentity) -> ProviderFetch {
        match self.latest {
            Some(environment) if EnvironmentIdentity::from_environment(environment) == *desired => {
                ProviderFetch::Fetched(Box::new(Ok(environment.clone())))
            }
            _ => ProviderFetch::Awaiting,
        }
    }
}

fn sandbox_config_identity(message: &GetSandboxConfigResponse) -> ConfigPartIdentity {
    ConfigPartIdentity {
        config_revision: message.config_revision,
        policy_version: message.version,
        policy_hash: message.policy_hash.clone(),
        provider_env_revision: message.provider_env_revision,
        provider_attachment_epoch: message.provider_attachment_epoch.clone(),
    }
}

fn provider_environment_identity(
    message: &GetSandboxProviderEnvironmentResponse,
) -> ConfigPartIdentity {
    ConfigPartIdentity {
        config_revision: 0,
        policy_version: 0,
        policy_hash: message.policy_hash.clone(),
        provider_env_revision: message.provider_env_revision,
        provider_attachment_epoch: message.provider_attachment_epoch.clone(),
    }
}

/// Outcome reported for a policy part.
fn sandbox_config_outcome(
    outcome: ApplyOutcome,
    reloads_gateway_policy: bool,
) -> ConfigApplyOutcome {
    match outcome {
        ApplyOutcome::Unchanged if !reloads_gateway_policy => {
            ConfigApplyOutcome::RetainedLocalOverride
        }
        ApplyOutcome::Unchanged => ConfigApplyOutcome::IgnoredDuplicate,
        ApplyOutcome::Applied => ConfigApplyOutcome::Applied,
        ApplyOutcome::LocalOverride => ConfigApplyOutcome::RetainedLocalOverride,
        ApplyOutcome::FailedClosed => ConfigApplyOutcome::FailedClosed,
        ApplyOutcome::Degraded => ConfigApplyOutcome::Degraded,
        ApplyOutcome::AwaitingProvider => ConfigApplyOutcome::AwaitingComponent,
        // The policy was not installed; the last working one stays active.
        ApplyOutcome::FailedRetained
        | ApplyOutcome::ProviderFailed
        | ApplyOutcome::ReportFailed => ConfigApplyOutcome::FailedRetainedLastKnownGood,
    }
}

/// Outcome reported for a provider environment that matched the policy part
/// it was applied with.
fn provider_environment_outcome(report: ApplyReport) -> ConfigApplyOutcome {
    match report.outcome {
        ApplyOutcome::Unchanged => ConfigApplyOutcome::IgnoredDuplicate,
        ApplyOutcome::Applied => ConfigApplyOutcome::Applied,
        ApplyOutcome::LocalOverride if report.provider_installed => ConfigApplyOutcome::Applied,
        ApplyOutcome::LocalOverride => ConfigApplyOutcome::RetainedLocalOverride,
        // Static credentials were revoked; dynamic grants that stay bound
        // remain active.
        ApplyOutcome::ProviderFailed | ApplyOutcome::FailedClosed => {
            ConfigApplyOutcome::FailedClosed
        }
        ApplyOutcome::AwaitingProvider => ConfigApplyOutcome::AwaitingComponent,
        // Credentials commit only with the policy runtime they bind to.
        ApplyOutcome::FailedRetained | ApplyOutcome::Degraded | ApplyOutcome::ReportFailed => {
            ConfigApplyOutcome::FailedRetainedLastKnownGood
        }
    }
}

fn part_result(outcome: ConfigApplyOutcome, identity: &ConfigPartIdentity) -> ConfigPartResult {
    ConfigPartResult {
        outcome: outcome.into(),
        identity: Some(identity.clone()),
        error: String::new(),
    }
}

/// Answer state of the latest provider environment part.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProviderAnswer {
    /// Not answered yet.
    Owed,
    /// Answered `AWAITING_COMPONENT`; a final answer follows once it is
    /// applied with a matching policy part.
    Awaiting,
    Done,
}

struct HeldProvider {
    environment: ProviderEnvironmentResult,
    identity: ConfigPartIdentity,
    answer: ProviderAnswer,
}

struct HeldConfig {
    snapshot: SettingsPollResult,
    identity: ConfigPartIdentity,
    /// Already answered `AWAITING_COMPONENT`.
    awaiting: bool,
}

/// Parts received over the current push session.
#[derive(Default)]
struct PushedParts {
    /// Policy part not yet applied because its provider environment has not
    /// arrived.
    held: Option<HeldConfig>,
    /// Latest provider environment part.
    provider: Option<HeldProvider>,
    /// Latest policy part the supervisor processed, polled or pushed.
    current: Option<SettingsPollResult>,
}

/// The configuration loop. `push` connects it to the gateway session.
pub struct ConfigLoop<C> {
    applier: ConfigApplier,
    client: C,
    push: ConfigPushReceiver,
    interval: Duration,
    initialized: bool,
    parts: PushedParts,
    /// Re-apply the current policy part at this time, after a degraded or
    /// incomplete apply.
    retry_at: Option<Instant>,
    /// The session task can still change the delivery state.
    session_open: bool,
}

impl<C: PolicyGatewayClient> ConfigLoop<C> {
    pub fn new(
        applier: ConfigApplier,
        client: C,
        push: ConfigPushReceiver,
        interval: Duration,
    ) -> Self {
        Self {
            applier,
            client,
            push,
            interval,
            initialized: false,
            parts: PushedParts::default(),
            retry_at: None,
            session_open: true,
        }
    }

    fn pushing(&self) -> bool {
        self.session_open
            && matches!(
                *self.push.state.borrow(),
                ConfigDeliveryState::Pushing { .. }
            )
    }

    pub async fn run(mut self) -> Result<()> {
        // The session normally connects together with the workload. Wait for
        // it to say whether it pushes, so the first snapshot is not fetched
        // twice; poll if it does not answer within one interval.
        let decided = tokio::time::timeout(
            self.interval,
            self.push
                .state
                .wait_for(|state| *state != ConfigDeliveryState::Disconnected),
        )
        .await
        .is_ok_and(|state| state.is_ok());
        if !decided {
            debug!("configuration loop: no supervisor session yet; polling");
        }
        let mut next_poll = Some(Instant::now());

        loop {
            let pushing = self.pushing();
            if pushing {
                next_poll = None;
            } else if next_poll.is_none() {
                // Push ended. Poll right away when the gateway said it does
                // not push, and after one interval when the session dropped.
                let delay = if *self.push.state.borrow() == ConfigDeliveryState::Polling {
                    Duration::ZERO
                } else {
                    self.interval
                };
                self.parts.held = None;
                self.parts.provider = None;
                next_poll = Some(Instant::now() + delay);
            }
            let rotate_at = (pushing && self.applier.current_extension_authentication_enabled)
                .then(|| {
                    Instant::now()
                        + next_poll_delay(&self.applier.ctx.extension_credentials, self.interval)
                });

            tokio::select! {
                biased;
                pushed = self.push.updates.recv() => match pushed {
                    Some(pushed) => self.on_pushed(pushed).await?,
                    None => return Ok(()),
                },
                changed = self.push.state.changed(), if self.session_open => {
                    if changed.is_err() {
                        // The session task ended for good; keep polling.
                        self.session_open = false;
                    }
                },
                () = super::sleep_until_or_never(next_poll), if !pushing => {
                    self.poll().await?;
                    next_poll = Some(Instant::now()
                        + next_poll_delay(&self.applier.ctx.extension_credentials, self.interval));
                }
                () = super::sleep_until_or_never(self.retry_at), if pushing => {
                    self.retry().await?;
                }
                () = super::sleep_until_or_never(rotate_at) => {
                    self.rotate_extension_credentials().await;
                }
            }
        }
    }

    async fn middleware_credentials(
        &self,
        snapshot: &SettingsPollResult,
    ) -> std::collections::HashMap<String, openshell_extension_core::BearerTokenSlot> {
        if !snapshot.extension_authentication_enabled {
            return std::collections::HashMap::new();
        }
        match self
            .client
            .extension_credentials_for(&snapshot.supervisor_middleware_services)
            .await
        {
            Ok(credentials) => credentials,
            Err(error) => {
                warn!(error = %error, "configuration: extension credential refresh failed");
                std::collections::HashMap::new()
            }
        }
    }

    /// Rotate installed extension credentials that are due. Polling does
    /// this on every poll; a pushing supervisor has no polls.
    async fn rotate_extension_credentials(&self) {
        let services = self.applier.current_middleware_services.clone();
        if let Err(error) = self.client.extension_credentials_for(&services).await {
            warn!(error = %error, "configuration: extension credential rotation failed");
        }
    }

    /// Apply a snapshot, routing the first one through the startup
    /// acknowledgement.
    async fn apply(
        &mut self,
        snapshot: SettingsPollResult,
        provider_source: &impl ProviderEnvironmentSource,
        admission: &impl AdmissionReporter,
    ) -> Result<ApplyReport> {
        let snapshot = if self.initialized {
            snapshot
        } else {
            self.initialized = true;
            match self.applier.initial(snapshot).await {
                Some(snapshot) => snapshot,
                None => return Ok(ApplyReport::new(ApplyOutcome::Unchanged)),
            }
        };
        let credentials = self.middleware_credentials(&snapshot).await;
        let report = self
            .applier
            .apply(snapshot, credentials, provider_source, admission)
            .await?;
        self.retry_at = (matches!(
            report.outcome,
            ApplyOutcome::Degraded | ApplyOutcome::ReportFailed
        ) || self.applier.middleware_registry_status
            == MiddlewareRegistryStatus::NeedsReconciliation)
            .then(|| Instant::now() + self.interval);
        Ok(report)
    }

    async fn poll(&mut self) -> Result<()> {
        let snapshot = match self.client.poll_settings(&self.applier.ctx.sandbox).await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                debug!(error = %error, "Settings poll: server unreachable, will retry");
                if self.applier.current_extension_authentication_enabled
                    && let Err(refresh_error) =
                        self.client.refresh_installed_extension_credentials().await
                {
                    warn!(
                        error = %refresh_error,
                        "Settings poll: extension credential refresh failed while configuration was unavailable"
                    );
                }
                return Ok(());
            }
        };
        let _ = self.applier.ctx.workspace_tx.send(self.client.workspace());
        self.parts.current = Some(snapshot.clone());
        let endpoint = self.applier.ctx.endpoint.clone();
        let sandbox_id = self.applier.ctx.sandbox_id.clone();
        let client = self.client.clone();
        let source = FetchedProviderEnvironment {
            client: &client,
            endpoint: &endpoint,
            sandbox_id: &sandbox_id,
        };
        self.apply(snapshot, &source, &RpcAdmissionReporter).await?;
        Ok(())
    }

    /// Re-apply the current policy part after a degraded apply. Recovery is
    /// reported with `ReportSandboxConfiguration`, because no pushed update
    /// is waiting for an answer.
    async fn retry(&mut self) -> Result<()> {
        self.retry_at = None;
        let Some(snapshot) = self.parts.current.clone() else {
            return Ok(());
        };
        let latest = self
            .parts
            .provider
            .as_ref()
            .map(|held| held.environment.clone());
        let source = PushedProviderEnvironment {
            latest: latest.as_ref(),
        };
        let report = self.apply(snapshot, &source, &RpcAdmissionReporter).await?;
        debug!(outcome = ?report.outcome, "configuration: retried degraded apply");
        Ok(())
    }

    async fn on_pushed(&mut self, pushed: PushedConfig) -> Result<()> {
        let PushedConfig { update, reply } = pushed;
        let ConfigUpdate {
            delivery_id,
            initial,
            sandbox_config,
            provider_environment,
        } = update;
        if initial {
            // A new session starts from a complete snapshot; nothing held
            // for the old session can still be answered.
            self.parts.held = None;
            self.parts.provider = None;
        }
        let mut result = ConfigUpdateResult {
            delivery_id,
            configuration_instance_id: self.applier.admission_instance_id().unwrap_or_default(),
            ..Default::default()
        };

        if let Some(environment) = provider_environment {
            let identity = provider_environment_identity(&environment);
            match provider_environment_result(environment) {
                Ok(environment) => {
                    self.parts.provider = Some(HeldProvider {
                        environment,
                        identity,
                        answer: ProviderAnswer::Owed,
                    });
                }
                Err(error) => {
                    warn!(error = %error, "configuration: pushed provider environment is malformed");
                    result.provider_environment = Some(ConfigPartResult {
                        error: "provider environment is malformed".to_string(),
                        ..part_result(ConfigApplyOutcome::FailedClosed, &identity)
                    });
                }
            }
        }
        if let Some(config) = sandbox_config {
            let identity = sandbox_config_identity(&config);
            self.parts.held = Some(HeldConfig {
                snapshot: settings_poll_result(config),
                identity,
                awaiting: false,
            });
        }

        let target = self
            .parts
            .held
            .as_ref()
            .map(|held| held.snapshot.clone())
            .or_else(|| self.parts.current.clone());
        let Some(target) = target else {
            // Nothing to bind a provider environment to yet.
            if let Some(provider) = self.parts.provider.as_mut()
                && provider.answer == ProviderAnswer::Owed
            {
                provider.answer = ProviderAnswer::Awaiting;
                result.provider_environment = Some(part_result(
                    ConfigApplyOutcome::AwaitingComponent,
                    &provider.identity,
                ));
            }
            send(&reply, result);
            return Ok(());
        };
        if !target.workspace.is_empty() {
            let _ = self.applier.ctx.workspace_tx.send(target.workspace.clone());
        }

        let latest = self
            .parts
            .provider
            .as_ref()
            .map(|held| held.environment.clone());
        let report = self
            .apply(
                target.clone(),
                &PushedProviderEnvironment {
                    latest: latest.as_ref(),
                },
                &PushedAdmission,
            )
            .await?;

        if let Some(held) = self.parts.held.take() {
            if report.outcome == ApplyOutcome::AwaitingProvider {
                if !held.awaiting {
                    result.sandbox_config = Some(part_result(
                        ConfigApplyOutcome::AwaitingComponent,
                        &held.identity,
                    ));
                }
                self.parts.held = Some(HeldConfig {
                    awaiting: true,
                    ..held
                });
            } else {
                result.sandbox_config = Some(part_result(
                    sandbox_config_outcome(report.outcome, self.applier.reloads_gateway_policy),
                    &held.identity,
                ));
                self.parts.current = Some(held.snapshot);
            }
        }
        if let Some(provider) = self.parts.provider.as_mut()
            && provider.answer != ProviderAnswer::Done
        {
            let matches = EnvironmentIdentity::from_environment(&provider.environment)
                == EnvironmentIdentity::from_settings(&target);
            if matches && report.outcome != ApplyOutcome::AwaitingProvider {
                provider.answer = ProviderAnswer::Done;
                result.provider_environment = Some(part_result(
                    provider_environment_outcome(report),
                    &provider.identity,
                ));
            } else if !matches && provider.answer == ProviderAnswer::Owed {
                provider.answer = ProviderAnswer::Awaiting;
                result.provider_environment = Some(part_result(
                    ConfigApplyOutcome::AwaitingComponent,
                    &provider.identity,
                ));
            }
        }
        info!(
            delivery_id,
            initial,
            outcome = ?report.outcome,
            "configuration: applied pushed update"
        );
        send(&reply, result);
        Ok(())
    }
}

fn send(reply: &ConfigReply, result: ConfigUpdateResult) {
    if result.sandbox_config.is_none() && result.provider_environment.is_none() {
        return;
    }
    if !reply.send(result) {
        debug!("configuration: session ended before the answer was sent");
    }
}
