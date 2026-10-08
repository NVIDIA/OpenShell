// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The delivery task of one push session.

use std::future::Future;
use std::ops::ControlFlow;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use openshell_core::proto::{
    ConfigApplyOutcome, ConfigUpdateResult, ConfigurationAdmissionState, GatewayMessage,
    GetSandboxConfigResponse, SandboxConfigurationAdmission, gateway_message,
};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

use super::build::{BuildError, build_parts};
use super::scheduler::BuildPermit;
use super::session::{AnsweredPart, PartEffect, SessionDelivery};
use super::{BuildRequest, ConfigDelivery, SessionEntry};
use crate::ServerState;
use crate::gateway_metrics::{
    BuildLane, ConfigPart, record_config_ack_timeout, record_config_build_wait,
    record_config_result, record_config_result_rejected, record_config_unchanged,
    record_config_update_sent,
};
use crate::grpc::policy::{AdmissionEvidence, record_configuration_admission};

/// How long a pushed part may go unanswered before it is sent again.
pub const ACK_TIMEOUT: Duration = Duration::from_mins(1);
/// First and largest delay before retrying a failed build.
const RETRY_INITIAL: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_mins(1);
/// Builds of the initial snapshot whose parts may disagree before the
/// session is closed.
const INITIAL_MATCH_ATTEMPTS: u32 = 3;

/// When the first consistency check runs: a random point within one
/// interval, so sessions that connect together do not check together.
fn first_check(interval: Duration) -> Instant {
    Instant::now() + interval.mul_f64(rand::random::<f64>())
}

/// Next consistency check, `interval` ± 10%.
fn next_check(interval: Duration) -> Instant {
    Instant::now() + interval.mul_f64(rand::random::<f64>().mul_add(0.2, 0.9))
}

/// Snake-case outcome name for metrics.
pub const fn outcome_label(outcome: ConfigApplyOutcome) -> &'static str {
    match outcome {
        ConfigApplyOutcome::Unspecified => "unspecified",
        ConfigApplyOutcome::Applied => "applied",
        ConfigApplyOutcome::IgnoredDuplicate => "ignored_duplicate",
        ConfigApplyOutcome::IgnoredStale => "ignored_stale",
        ConfigApplyOutcome::RetainedLocalOverride => "retained_local_override",
        ConfigApplyOutcome::Degraded => "degraded",
        ConfigApplyOutcome::FailedRetainedLastKnownGood => "failed_retained_last_known_good",
        ConfigApplyOutcome::FailedClosed => "failed_closed",
        ConfigApplyOutcome::Unsupported => "unsupported",
        ConfigApplyOutcome::AwaitingComponent => "awaiting_component",
    }
}

/// Admission state a policy part outcome reports, if any.
const fn admission_state(outcome: ConfigApplyOutcome) -> Option<ConfigurationAdmissionState> {
    match outcome {
        ConfigApplyOutcome::Applied | ConfigApplyOutcome::IgnoredDuplicate => {
            Some(ConfigurationAdmissionState::Accepted)
        }
        ConfigApplyOutcome::FailedClosed
        | ConfigApplyOutcome::FailedRetainedLastKnownGood
        | ConfigApplyOutcome::Degraded => Some(ConfigurationAdmissionState::Rejected),
        ConfigApplyOutcome::Unspecified
        | ConfigApplyOutcome::IgnoredStale
        | ConfigApplyOutcome::RetainedLocalOverride
        | ConfigApplyOutcome::Unsupported
        | ConfigApplyOutcome::AwaitingComponent => None,
    }
}

/// A wait for build capacity that keeps its place across loop iterations.
type PendingPermit = Pin<Box<dyn Future<Output = BuildPermit> + Send + Sync>>;

pub(super) struct DeliveryTask {
    state: Arc<ServerState>,
    delivery: Arc<ConfigDelivery>,
    entry: Arc<SessionEntry>,
    outbound: mpsc::Sender<GatewayMessage>,
    results: mpsc::Receiver<ConfigUpdateResult>,
    protocol: SessionDelivery,
    retry_delay: Duration,
    retry_at: Option<Instant>,
    initial_mismatches: u32,
    /// Waiting for build capacity, in the lane it was requested for.
    acquiring: Option<(BuildLane, PendingPermit)>,
    /// Next rebuild that repairs a missed change. It rebuilds the policy part
    /// and builds the provider environment only if the policy part says its
    /// identity moved, so an unchanged check calls no credential backend.
    check_at: Instant,
}

impl DeliveryTask {
    pub(super) fn new(
        state: Arc<ServerState>,
        delivery: Arc<ConfigDelivery>,
        entry: Arc<SessionEntry>,
        outbound: mpsc::Sender<GatewayMessage>,
        results: mpsc::Receiver<ConfigUpdateResult>,
    ) -> Self {
        let check_at = first_check(delivery.consistency_check_interval());
        Self {
            state,
            delivery,
            entry,
            outbound,
            results,
            protocol: SessionDelivery::default(),
            retry_delay: RETRY_INITIAL,
            retry_at: None,
            initial_mismatches: 0,
            acquiring: None,
            check_at,
        }
    }

    pub(super) async fn run(mut self) {
        loop {
            let now = Instant::now();
            for part in self.protocol.expire(now, ACK_TIMEOUT) {
                record_config_ack_timeout(part);
                warn!(
                    sandbox_id = %self.entry.sandbox_id,
                    part = part.label(),
                    "pushed configuration was not answered in time; sending it again"
                );
                self.entry
                    .mark(BuildLane::Sandbox, part == ConfigPart::ProviderEnvironment);
            }
            if self.flush().is_break() {
                return;
            }
            if now >= self.check_at {
                self.check_at = next_check(self.delivery.consistency_check_interval());
                self.entry.mark(BuildLane::Fanout, false);
            }

            let lane = self.entry.lane();
            let dirty = lane.is_some();
            let retry_wait = self.retry_at.filter(|at| *at > now);
            match lane.filter(|_| retry_wait.is_none()) {
                // Keep the place in the queue unless the change became more
                // urgent than the lane it is waiting in.
                Some(lane)
                    if self
                        .acquiring
                        .as_ref()
                        .is_none_or(|(waiting, _)| lane < *waiting) =>
                {
                    let scheduler = self.delivery.scheduler.clone();
                    let workspace = self.entry.workspace();
                    self.acquiring = Some((
                        lane,
                        Box::pin(async move { scheduler.acquire(lane, &workspace).await }),
                    ));
                }
                Some(_) => {}
                None => self.acquiring = None,
            }
            let wake_at = [
                retry_wait.filter(|_| dirty),
                self.protocol.next_expiry(ACK_TIMEOUT),
                Some(self.check_at),
            ]
            .into_iter()
            .flatten()
            .min();

            let mut acquiring = self.acquiring.take();
            let waiting_lane = acquiring.as_ref().map(|(lane, _)| *lane);
            tokio::select! {
                biased;
                result = self.results.recv() => match result {
                    Some(result) => self.on_result(result).await,
                    None => return,
                },
                permit = async { acquiring.as_mut().expect("guarded").1.as_mut().await },
                    if acquiring.is_some() =>
                {
                    acquiring = None;
                    if let Some(request) = self.entry.take()
                        && self.build(request).await.is_break()
                    {
                        return;
                    }
                    drop(permit);
                }
                () = self.entry.wake.notified() => {}
                () = sleep_until_or_never(wake_at) => {}
            }
            if let (Some(lane), Some(future)) = (waiting_lane, acquiring) {
                self.acquiring = Some((lane, future.1));
            }
        }
    }

    /// Queue every update that can be sent now.
    fn flush(&mut self) -> ControlFlow<()> {
        while let Some(update) = self.protocol.next_update(Instant::now()) {
            if update.sandbox_config.is_some() {
                record_config_update_sent(ConfigPart::SandboxConfig, update.initial);
            }
            if update.provider_environment.is_some() {
                record_config_update_sent(ConfigPart::ProviderEnvironment, update.initial);
            }
            debug!(
                sandbox_id = %self.entry.sandbox_id,
                delivery_id = update.delivery_id,
                initial = update.initial,
                sandbox_config = update.sandbox_config.is_some(),
                provider_environment = update.provider_environment.is_some(),
                "pushing configuration"
            );
            // Unanswered updates are bounded per part, so the channel only
            // fills if the stream stopped draining for longer than the answer
            // timeout. Restart the session then; the supervisor reconnects
            // and gets a fresh initial snapshot.
            let message = GatewayMessage {
                payload: Some(gateway_message::Payload::ConfigUpdate(update)),
            };
            match self.outbound.try_send(message) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!(
                        sandbox_id = %self.entry.sandbox_id,
                        session_id = %self.entry.session_id,
                        "supervisor session is not draining pushed configuration; closing it"
                    );
                    self.state
                        .supervisor_sessions
                        .disconnect_session(&self.entry.sandbox_id, &self.entry.session_id);
                    return ControlFlow::Break(());
                }
                Err(mpsc::error::TrySendError::Closed(_)) => return ControlFlow::Break(()),
            }
        }
        ControlFlow::Continue(())
    }

    async fn build(&mut self, request: BuildRequest) -> ControlFlow<()> {
        record_config_build_wait(request.lane, request.since.elapsed());
        let protocol = &self.protocol;
        #[cfg(test)]
        let injected = self
            .delivery
            .injected_build_failures
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |remaining| remaining.checked_sub(1),
            )
            .is_ok();
        #[cfg(not(test))]
        let injected = false;
        let built = if injected {
            Err(BuildError::Failed(tonic::Status::unavailable(
                "injected build failure",
            )))
        } else {
            build_parts(&self.state, &self.entry.sandbox_id, |config| {
                request.force_provider || protocol.needs_provider_environment(config)
            })
            .await
        };
        let parts = match built {
            Ok(parts) => parts,
            Err(BuildError::SandboxGone) => return ControlFlow::Break(()),
            Err(BuildError::Failed(status)) => {
                warn!(
                    sandbox_id = %self.entry.sandbox_id,
                    code = %status.code(),
                    error = %status.message(),
                    retry_in = ?self.retry_delay,
                    "pushed configuration build failed; retrying"
                );
                self.retry_later(request);
                return ControlFlow::Continue(());
            }
        };
        self.entry
            .record_coverage(parts.workspace, parts.provider_ids);

        if !self.protocol.initial_sent()
            && let Some(environment) = parts.provider_environment.as_ref()
            && environment.environment_identity() != parts.sandbox_config.environment_identity()
        {
            self.initial_mismatches += 1;
            if self.initial_mismatches >= INITIAL_MATCH_ATTEMPTS {
                error!(
                    sandbox_id = %self.entry.sandbox_id,
                    session_id = %self.entry.session_id,
                    attempts = self.initial_mismatches,
                    "initial configuration parts did not match; closing the supervisor session"
                );
                self.state
                    .supervisor_sessions
                    .disconnect_session(&self.entry.sandbox_id, &self.entry.session_id);
                return ControlFlow::Break(());
            }
            self.retry_later(request);
            return ControlFlow::Continue(());
        }

        self.retry_delay = RETRY_INITIAL;
        self.retry_at = None;
        if !self.protocol.sandbox_config.offer(parts.sandbox_config) {
            record_config_unchanged(ConfigPart::SandboxConfig);
        }
        if let Some(environment) = parts.provider_environment {
            let offered = if request.force_provider {
                self.protocol.provider_environment.offer_forced(environment)
            } else {
                self.protocol.provider_environment.offer(environment)
            };
            if !offered {
                record_config_unchanged(ConfigPart::ProviderEnvironment);
            }
        }
        ControlFlow::Continue(())
    }

    fn retry_later(&mut self, request: BuildRequest) {
        self.entry.restore(request);
        self.retry_at = Some(Instant::now() + self.retry_delay);
        self.retry_delay = (self.retry_delay * 2).min(RETRY_MAX);
    }

    async fn on_result(&mut self, result: ConfigUpdateResult) {
        let answered = self.protocol.answer(&result);
        if let Some(answer) = answered.sandbox_config {
            match answer {
                Ok(answer) => {
                    record_config_result(ConfigPart::SandboxConfig, outcome_label(answer.outcome));
                    match answer.effect {
                        PartEffect::AwaitingOther => self.entry.mark(BuildLane::Sandbox, true),
                        PartEffect::Resend => self.entry.mark(BuildLane::Sandbox, false),
                        PartEffect::Acknowledged => {}
                    }
                    self.record_admission(&result.configuration_instance_id, &answer)
                        .await;
                }
                Err(rejection) => {
                    record_config_result_rejected(ConfigPart::SandboxConfig, rejection.label());
                    warn!(
                        sandbox_id = %self.entry.sandbox_id,
                        delivery_id = result.delivery_id,
                        reason = rejection.label(),
                        "rejected supervisor answer for pushed policy and settings"
                    );
                }
            }
        }
        if let Some(answer) = answered.provider_environment {
            match answer {
                Ok(answer) => {
                    record_config_result(
                        ConfigPart::ProviderEnvironment,
                        outcome_label(answer.outcome),
                    );
                    match answer.effect {
                        PartEffect::AwaitingOther => self.entry.mark(BuildLane::Sandbox, false),
                        PartEffect::Resend => self.entry.mark(BuildLane::Sandbox, true),
                        PartEffect::Acknowledged => {}
                    }
                }
                Err(rejection) => {
                    record_config_result_rejected(
                        ConfigPart::ProviderEnvironment,
                        rejection.label(),
                    );
                    warn!(
                        sandbox_id = %self.entry.sandbox_id,
                        delivery_id = result.delivery_id,
                        reason = rejection.label(),
                        "rejected supervisor answer for pushed provider environment"
                    );
                }
            }
        }
    }

    /// Record what the supervisor reported about the policy part as the
    /// sandbox's configuration admission, as a polling supervisor does with
    /// `ReportSandboxConfiguration`.
    async fn record_admission(
        &self,
        instance_id: &str,
        answer: &AnsweredPart<GetSandboxConfigResponse>,
    ) {
        let Some(admission_state) = admission_state(answer.outcome) else {
            return;
        };
        if uuid::Uuid::parse_str(instance_id).is_err() {
            return;
        }
        let sent = &answer.part.message;
        let admission = SandboxConfigurationAdmission {
            instance_id: instance_id.to_string(),
            state: admission_state.into(),
            policy_version: sent.version,
            policy_hash: sent.policy_hash.clone(),
            config_revision: sent.config_revision,
            provider_env_revision: sent.provider_env_revision,
            error: String::new(),
        };
        if let Err(status) = record_configuration_admission(
            &self.state,
            &self.entry.sandbox_id,
            admission,
            "",
            AdmissionEvidence::Pushed(sent),
        )
        .await
        {
            // A newer supervisor instance or a stopped sandbox makes the
            // report moot; nothing to retry.
            info!(
                sandbox_id = %self.entry.sandbox_id,
                code = %status.code(),
                error = %status.message(),
                "configuration admission from pushed result was not recorded"
            );
        }
    }
}

async fn sleep_until_or_never(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}
