// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Installation evidence reported under the accepted supervisor session.
//!
//! Desired-state cursors never establish success. Credentials, policy, and
//! the authenticated workload boundary must acknowledge the same authority.

use std::sync::Arc;
use std::time::Duration;

use openshell_core::proto::{
    ProviderReadinessObservation, ProviderReadinessReason as Reason,
    ReportProviderReadinessResponse,
};
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_isolation_interface::contract::{BoundaryExec, ProviderEnvironmentInstallation};
use openshell_supervisor_network::opa::PolicyGenerationGuard;
use tokio::sync::watch;

/// Authority captured before consuming a provider response's credential fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnvironmentIdentity {
    pub(crate) attachment_epoch: String,
    pub(crate) revision: u64,
    pub(crate) policy_hash: String,
}

impl EnvironmentIdentity {
    /// Preserve the authority delivered with a credential snapshot before consuming it.
    pub(crate) fn from_environment(
        result: &openshell_core::grpc_client::ProviderEnvironmentResult,
    ) -> Self {
        Self {
            attachment_epoch: result.provider_attachment_epoch.clone(),
            revision: result.provider_env_revision,
            policy_hash: result.policy_hash.clone(),
        }
    }

    /// Capture the requested authority without claiming that it is installed.
    pub(crate) fn from_settings(result: &openshell_core::grpc_client::SettingsPollResult) -> Self {
        Self {
            attachment_epoch: result.provider_attachment_epoch.clone(),
            revision: result.provider_env_revision,
            policy_hash: result.policy_hash.clone(),
        }
    }
}

#[derive(Clone, Debug)]
struct InstalledPolicy {
    epoch: String,
    hash: String,
    config_revision: u64,
    generation: PolicyGenerationGuard,
}

#[derive(Clone, Debug)]
struct FailedPolicy {
    identity: EnvironmentIdentity,
    config_revision: u64,
}

#[derive(Clone, Debug)]
struct State {
    identity: EnvironmentIdentity,
    installation_id: String,
    credential_reason: Reason,
    expires_at_ms: Option<i64>,
    policy: Option<InstalledPolicy>,
    policy_failure: Option<FailedPolicy>,
    process: Option<ProviderEnvironmentInstallation>,
    process_reason: Reason,
}

/// Shared installation tracker; each transition wakes the independent reporter.
#[derive(Clone, Debug)]
pub struct Tracker {
    state: watch::Sender<State>,
}

impl Tracker {
    /// Start without credential, policy, or process installation evidence.
    pub(crate) fn new() -> Self {
        let (state, _) = watch::channel(State {
            identity: EnvironmentIdentity::default(),
            installation_id: String::new(),
            credential_reason: Reason::WaitingForCredentials,
            expires_at_ms: None,
            policy: None,
            policy_failure: None,
            process: None,
            process_reason: Reason::WaitingForProcess,
        });
        Self { state }
    }

    /// Invalidate old success before a replacement or fail-closed clear begins.
    pub(crate) fn credentials_failed(&self, identity: EnvironmentIdentity, reason: Reason) {
        self.state.send_modify(|state| {
            state.identity = identity;
            state.installation_id.clear();
            state.credential_reason = reason;
            state.expires_at_ms = None;
            state.process = None;
            state.process_reason = Reason::WaitingForProcess;
        });
    }

    /// Record a completed credential installation and require a fresh process acknowledgment.
    pub(crate) fn credentials_installed(
        &self,
        identity: EnvironmentIdentity,
        credentials: &ProviderCredentialState,
        expires_at_ms: Option<i64>,
    ) {
        let snapshot = credentials.snapshot();
        self.state.send_modify(|state| {
            state.credential_reason =
                if !identity.policy_hash.is_empty() && snapshot.revision == identity.revision {
                    Reason::Unspecified
                } else {
                    Reason::SnapshotMismatch
                };
            state.identity = identity;
            state.installation_id.clone_from(&snapshot.installation_id);
            state.expires_at_ms = expires_at_ms;
            state.process = None;
            state.process_reason = Reason::WaitingForProcess;
        });
    }

    /// Retry failed installations even when the requested fingerprint is unchanged.
    pub(crate) fn needs_environment(&self, identity: &EnvironmentIdentity) -> bool {
        let state = self.state.borrow();
        state.credential_reason != Reason::Unspecified || state.identity != *identity
    }

    /// Bind policy evidence to the exact generation returned by runtime installation.
    pub(crate) fn policy_activated(
        &self,
        identity: &EnvironmentIdentity,
        config_revision: u64,
        generation: PolicyGenerationGuard,
    ) {
        self.state.send_modify(|state| {
            state.policy = Some(InstalledPolicy {
                epoch: identity.attachment_epoch.clone(),
                hash: identity.policy_hash.clone(),
                config_revision,
                generation,
            });
            state.policy_failure = None;
        });
    }

    /// Report the rejected desired configuration without acknowledging its policy.
    pub(crate) fn policy_install_failed(
        &self,
        identity: EnvironmentIdentity,
        config_revision: u64,
    ) {
        self.state.send_modify(|state| {
            // Failed desired identity must not masquerade as evidence for the
            // last installed policy, even when the failure retains that policy.
            state.policy_failure = Some(FailedPolicy {
                identity,
                config_revision,
            });
        });
    }

    fn process_installed(
        &self,
        installed: ProviderEnvironmentInstallation,
        credentials: &ProviderCredentialState,
    ) {
        let current = credentials.snapshot();
        self.state.send_if_modified(|state| {
            if installed.installation_id != current.installation_id
                || installed.installation_id != state.installation_id
                || installed.revision != state.identity.revision
            {
                return false;
            }
            let changed = state.process.as_ref() != Some(&installed)
                || state.process_reason != Reason::Unspecified;
            state.process = Some(installed);
            state.process_reason = Reason::Unspecified;
            changed
        });
    }

    fn process_failed(&self) {
        self.state.send_if_modified(|state| {
            let changed =
                state.process.is_some() || state.process_reason != Reason::ProcessInstallFailed;
            state.process = None;
            state.process_reason = Reason::ProcessInstallFailed;
            changed
        });
    }

    /// Read current evidence, rechecking credential expiry and policy generation.
    pub(crate) fn observation(
        &self,
        credentials: &ProviderCredentialState,
    ) -> ProviderReadinessObservation {
        let state = self.state.borrow();
        let current = credentials.snapshot();
        let identity = state
            .policy_failure
            .as_ref()
            .map_or(&state.identity, |failure| &failure.identity);
        let expired = state
            .expires_at_ms
            .is_some_and(|expiry| expiry <= openshell_core::time::now_ms());
        let credentials_installed = state.credential_reason == Reason::Unspecified
            && !expired
            && state.identity == *identity
            && current.installation_id == state.installation_id;
        let policy_active = state.policy_failure.is_none()
            && state.policy.as_ref().is_some_and(|policy| {
                !policy.hash.is_empty()
                    && policy.hash == identity.policy_hash
                    && policy.epoch == identity.attachment_epoch
                    && !policy.generation.is_stale()
            });
        let launch_environment_installed = credentials_installed
            && state.process.as_ref().is_some_and(|process| {
                process.installation_id == state.installation_id
                    && process.revision == identity.revision
            });
        let reason = if state.policy_failure.is_some() {
            Reason::PolicyActivationFailed
        } else if expired {
            Reason::CredentialExpired
        } else if state.credential_reason != Reason::Unspecified {
            state.credential_reason
        } else if !credentials_installed {
            Reason::WaitingForCredentials
        } else if !policy_active {
            Reason::WaitingForPolicy
        } else if !launch_environment_installed {
            if state.process_reason == Reason::Unspecified {
                Reason::WaitingForProcess
            } else {
                state.process_reason
            }
        } else {
            Reason::Unspecified
        };
        ProviderReadinessObservation {
            attachment_epoch: identity.attachment_epoch.clone(),
            provider_env_revision: identity.revision,
            config_revision: state.policy_failure.as_ref().map_or_else(
                || {
                    state
                        .policy
                        .as_ref()
                        .map_or(0, |policy| policy.config_revision)
                },
                |failure| failure.config_revision,
            ),
            policy_hash: identity.policy_hash.clone(),
            credentials_installed,
            policy_active,
            launch_environment_installed,
            process_instance_id: state
                .process
                .as_ref()
                .map_or_else(String::new, |process| process.session_id.to_string()),
            reason: reason.into(),
            ..Default::default()
        }
    }

    /// Report while the owner holds this handle; reconnects use the accepted session.
    pub(crate) fn start_reporter(
        &self,
        endpoint: String,
        sandbox_id: String,
        credentials: ProviderCredentialState,
        sessions: watch::Receiver<Option<String>>,
        boundary: Arc<dyn BoundaryExec>,
    ) -> Reporter {
        let tracker = self.clone();
        Reporter(tokio::spawn(async move {
            tracker
                .run_reporter(
                    credentials,
                    sessions,
                    boundary,
                    GatewayReporter {
                        endpoint,
                        sandbox_id,
                    },
                )
                .await;
        }))
    }

    async fn run_reporter<C: ReportClient>(
        &self,
        credentials: ProviderCredentialState,
        mut sessions: watch::Receiver<Option<String>>,
        boundary: Arc<dyn BoundaryExec>,
        client: C,
    ) {
        let tracker = self;
        let mut updates = tracker.state.subscribe();
        let mut active_session = None;
        let mut sequence = 0_u64;
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let guard = tracker
                .state
                .borrow()
                .policy
                .as_ref()
                .map(|policy| policy.generation.clone())
                .filter(|guard| !guard.is_stale());
            tokio::select! {
                changed = sessions.changed() => { if changed.is_err() { return; } }
                changed = updates.changed() => { if changed.is_err() { return; } }
                _ = interval.tick() => {}
                () = async {
                    if let Some(guard) = guard { guard.wait_until_stale().await; }
                    else { std::future::pending::<()>().await; }
                } => {}
            }
            let session = sessions.borrow_and_update().clone();
            if session != active_session {
                sequence = 0;
                active_session = session.clone();
            }
            let Some(session) = session else {
                continue;
            };
            // Synchronization is also a boundary liveness check. A stopped
            // boundary cannot keep renewing successful launch evidence.
            let synchronization = tokio::time::timeout(
                Duration::from_secs(10),
                boundary.synchronize_provider_environment(),
            );
            let installed = tokio::select! {
                changed = sessions.changed() => { if changed.is_err() { return; } interval.reset_immediately(); continue; }
                installed = synchronization => installed,
            };
            match installed {
                Ok(Ok(installed)) => tracker.process_installed(installed, &credentials),
                _ => tracker.process_failed(),
            }
            let Some(next_sequence) = sequence.checked_add(1) else {
                return;
            };
            sequence = next_sequence;
            let mut observation = tracker.observation(&credentials);
            observation.session_id.clone_from(&session);
            observation.sequence = sequence;
            let report = tokio::time::timeout(Duration::from_secs(5), client.report(observation));
            let response = tokio::select! {
                changed = sessions.changed() => { if changed.is_err() { return; } interval.reset_immediately(); continue; }
                response = report => response,
            };
            if let Ok(Ok(response)) = response
                && !report_acknowledged(&response, sequence)
            {
                // A gateway rejection does not invalidate the boundary's
                // installation. Retry on the normal cadence or a real state
                // change without creating a self-triggered failure/retry loop.
                tracing::warn!("Provider readiness report was not acknowledged");
            }
        }
    }
}

/// An acknowledgment must bind this report and a valid positive evidence lease.
fn report_acknowledged(response: &ReportProviderReadinessResponse, sequence: u64) -> bool {
    response.accepted_sequence == sequence
        && response
            .observation_ttl
            .as_ref()
            .and_then(|ttl| openshell_core::time::duration_to_std(ttl).ok())
            .is_some_and(|ttl| !ttl.is_zero())
}

#[tonic::async_trait]
trait ReportClient: Send + Sync {
    async fn report(
        &self,
        observation: ProviderReadinessObservation,
    ) -> miette::Result<ReportProviderReadinessResponse>;
}

struct GatewayReporter {
    endpoint: String,
    sandbox_id: String,
}

#[tonic::async_trait]
impl ReportClient for GatewayReporter {
    async fn report(
        &self,
        observation: ProviderReadinessObservation,
    ) -> miette::Result<ReportProviderReadinessResponse> {
        openshell_core::grpc_client::report_provider_readiness(
            &self.endpoint,
            &self.sandbox_id,
            observation,
        )
        .await
    }
}

/// Cancels reporting before supervisor teardown can renew stale evidence.
pub struct Reporter(tokio::task::JoinHandle<()>);

impl Drop for Reporter {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn acknowledgment_requires_matching_sequence_and_valid_positive_ttl() {
        let mut response = ReportProviderReadinessResponse {
            accepted_sequence: 7,
            ..Default::default()
        };
        assert!(!report_acknowledged(&response, 7));
        for (seconds, nanos, valid) in [
            (15, 0, true),
            (0, 1, true),
            (0, 0, false),
            (-1, 0, false),
            (0, -1, false),
            (1, -1, false),
            (0, 1_000_000_000, false),
            (315_576_000_001, 0, false),
        ] {
            response.observation_ttl = Some(prost_types::Duration { seconds, nanos });
            assert_eq!(
                report_acknowledged(&response, 7),
                valid,
                "seconds={seconds}, nanos={nanos}"
            );
        }
        response.observation_ttl = Some(prost_types::Duration {
            seconds: 15,
            nanos: 0,
        });
        assert!(!report_acknowledged(&response, 8));
    }

    struct CapturingReporter(tokio::sync::mpsc::UnboundedSender<ProviderReadinessObservation>);

    #[tonic::async_trait]
    impl ReportClient for CapturingReporter {
        async fn report(
            &self,
            observation: ProviderReadinessObservation,
        ) -> miette::Result<ReportProviderReadinessResponse> {
            let sequence = observation.sequence;
            self.0.send(observation).unwrap();
            Ok(ReportProviderReadinessResponse {
                accepted_sequence: sequence,
                report_interval: Some(
                    openshell_core::time::duration_from_std(Duration::from_secs(5)).unwrap(),
                ),
                observation_ttl: Some(
                    openshell_core::time::duration_from_std(Duration::from_secs(15)).unwrap(),
                ),
            })
        }
    }

    struct DelayedReporter(
        tokio::sync::mpsc::UnboundedSender<(
            ProviderReadinessObservation,
            tokio::sync::oneshot::Sender<ReportProviderReadinessResponse>,
        )>,
    );

    #[tonic::async_trait]
    impl ReportClient for DelayedReporter {
        async fn report(
            &self,
            observation: ProviderReadinessObservation,
        ) -> miette::Result<ReportProviderReadinessResponse> {
            let (response, received) = tokio::sync::oneshot::channel();
            self.0.send((observation, response)).unwrap();
            received
                .await
                .map_err(|_| miette::miette!("report response channel closed"))
        }
    }

    struct DelayedBoundary(
        tokio::sync::mpsc::UnboundedSender<
            tokio::sync::oneshot::Sender<ProviderEnvironmentInstallation>,
        >,
    );

    #[tonic::async_trait]
    impl BoundaryExec for DelayedBoundary {
        async fn exec(
            &self,
            _spec: openshell_isolation_interface::contract::ExecSpec,
        ) -> Result<
            openshell_isolation_interface::contract::ExecSession,
            openshell_isolation_interface::contract::BackendError,
        > {
            unreachable!("reporting must never launch a workload process")
        }

        async fn synchronize_provider_environment(
            &self,
        ) -> Result<
            ProviderEnvironmentInstallation,
            openshell_isolation_interface::contract::BackendError,
        > {
            let (sender, receiver) = tokio::sync::oneshot::channel();
            self.0.send(sender).unwrap();
            receiver.await.map_err(|_| {
                openshell_isolation_interface::contract::BackendError::Unavailable(
                    "boundary disconnected".into(),
                )
            })
        }
    }

    async fn next_installation_report(
        installations: &mut tokio::sync::mpsc::UnboundedReceiver<
            tokio::sync::oneshot::Sender<ProviderEnvironmentInstallation>,
        >,
        reports: &mut tokio::sync::mpsc::UnboundedReceiver<(
            ProviderReadinessObservation,
            tokio::sync::oneshot::Sender<ReportProviderReadinessResponse>,
        )>,
        installed: &ProviderEnvironmentInstallation,
        wait: Duration,
    ) -> (
        ProviderReadinessObservation,
        tokio::sync::oneshot::Sender<ReportProviderReadinessResponse>,
    ) {
        tokio::time::timeout(wait, async {
            installations
                .recv()
                .await
                .unwrap()
                .send(installed.clone())
                .unwrap();
            reports.recv().await.unwrap()
        })
        .await
        .expect("reporter did not synchronize and report before the deadline")
    }

    #[tokio::test]
    async fn invalid_report_acknowledgments_retry_without_installation_feedback() {
        let tracker = Tracker::new();
        let credentials = ProviderCredentialState::from_child_env_snapshot(6, HashMap::new());
        tracker.credentials_installed(identity(), &credentials, None);
        let policy = openshell_policy::restrictive_default_policy();
        let engine = openshell_supervisor_network::opa::OpaEngine::from_proto(&policy).unwrap();
        tracker.policy_activated(&identity(), 12, engine.generation_guard(0).unwrap());
        let mut installed = installation(&credentials);
        let (sessions, receiver) = watch::channel(Some("current-session".to_string()));
        let (boundary_tx, mut boundary_rx) = tokio::sync::mpsc::unbounded_channel();
        let (report_tx, mut report_rx) = tokio::sync::mpsc::unbounded_channel();
        let reporting_tracker = tracker.clone();
        let reporting_credentials = credentials.clone();
        let task = tokio::spawn(async move {
            reporting_tracker
                .run_reporter(
                    reporting_credentials,
                    receiver,
                    Arc::new(DelayedBoundary(boundary_tx)),
                    DelayedReporter(report_tx),
                )
                .await;
        });
        // The first installation changes local evidence once. Its watch update
        // may cause one additional report, but an invalid gateway reply must
        // not keep toggling that evidence and scheduling more installations.
        for sequence in 1..=2 {
            let (report, response) = next_installation_report(
                &mut boundary_rx,
                &mut report_rx,
                &installed,
                Duration::from_secs(1),
            )
            .await;
            assert_eq!(report.sequence, sequence);
            assert!(report.launch_environment_installed);
            response
                .send(ReportProviderReadinessResponse::default())
                .unwrap();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), boundary_rx.recv())
                .await
                .is_err(),
            "invalid report replies must not repeatedly reinstall an unchanged environment"
        );

        // A real credential installation still wakes the reporter immediately.
        credentials.install_child_env_snapshot(6, HashMap::new());
        tracker.credentials_installed(identity(), &credentials, None);
        installed.installation_id = credentials.snapshot().installation_id.clone();
        let (report, response) = next_installation_report(
            &mut boundary_rx,
            &mut report_rx,
            &installed,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(report.sequence, 3);
        assert!(report.launch_environment_installed);
        // A policy update received while the report is pending must survive
        // processing its reply and cause a report of the new configuration.
        tracker.policy_activated(&identity(), 13, engine.generation_guard(0).unwrap());
        response
            .send(ReportProviderReadinessResponse::default())
            .unwrap();
        let (report, response) = next_installation_report(
            &mut boundary_rx,
            &mut report_rx,
            &installed,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(report.sequence, 4);
        assert_eq!(report.config_revision, 13);
        response
            .send(ReportProviderReadinessResponse::default())
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), boundary_rx.recv())
                .await
                .is_err()
        );

        sessions.send_replace(Some("replacement-session".to_string()));
        let (report, response) = next_installation_report(
            &mut boundary_rx,
            &mut report_rx,
            &installed,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(report.session_id, "replacement-session");
        assert_eq!(report.sequence, 1);
        response
            .send(ReportProviderReadinessResponse::default())
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), boundary_rx.recv())
                .await
                .is_err()
        );

        // Without further state changes, the periodic liveness check retries.
        let (report, response) = next_installation_report(
            &mut boundary_rx,
            &mut report_rx,
            &installed,
            Duration::from_secs(6),
        )
        .await;
        assert_eq!(report.session_id, "replacement-session");
        assert_eq!(report.sequence, 2);
        assert!(report.launch_environment_installed);
        response
            .send(ReportProviderReadinessResponse::default())
            .unwrap();
        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn reconnect_cancels_delayed_boundary_ack_and_starts_a_new_report_sequence() {
        let tracker = Tracker::new();
        let credentials = ProviderCredentialState::from_child_env_snapshot(6, HashMap::new());
        tracker.credentials_installed(identity(), &credentials, None);
        let installed = installation(&credentials);
        let (sessions, receiver) = watch::channel(Some("old-session".to_string()));
        let (boundary_tx, mut boundary_rx) = tokio::sync::mpsc::unbounded_channel();
        let (report_tx, mut report_rx) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            tracker
                .run_reporter(
                    credentials,
                    receiver,
                    Arc::new(DelayedBoundary(boundary_tx)),
                    CapturingReporter(report_tx),
                )
                .await;
        });
        let old_ack = tokio::time::timeout(Duration::from_secs(1), boundary_rx.recv())
            .await
            .unwrap()
            .unwrap();
        sessions.send_replace(Some("current-session".to_string()));
        let current_ack = tokio::time::timeout(Duration::from_secs(1), boundary_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            old_ack.send(installed.clone()).is_err(),
            "replaced session must cancel its pending installation"
        );
        current_ack.send(installed.clone()).unwrap();
        let report = tokio::time::timeout(Duration::from_secs(1), report_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(report.session_id, "current-session");
        assert_eq!(report.sequence, 1);
        assert!(report.launch_environment_installed);
        // The installation transition wakes a second report, whose sequence
        // must advance even though its desired authority is unchanged.
        let next_ack = tokio::time::timeout(Duration::from_secs(1), boundary_rx.recv())
            .await
            .unwrap()
            .unwrap();
        next_ack.send(installed).unwrap();
        let report = tokio::time::timeout(Duration::from_secs(1), report_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(report.sequence, 2);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), boundary_rx.recv())
                .await
                .is_err(),
            "an unchanged installation acknowledgment must not trigger another report"
        );
        sessions.send_replace(None);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), report_rx.recv())
                .await
                .is_err()
        );
        task.abort();
        let _ = task.await;
    }

    fn identity() -> EnvironmentIdentity {
        EnvironmentIdentity {
            attachment_epoch: "epoch".into(),
            revision: 6,
            policy_hash: "policy".into(),
        }
    }

    fn installation(credentials: &ProviderCredentialState) -> ProviderEnvironmentInstallation {
        ProviderEnvironmentInstallation {
            installation_id: credentials.snapshot().installation_id.clone(),
            revision: 6,
            session_id: uuid::Uuid::new_v4().to_string().parse().unwrap(),
        }
    }

    #[test]
    fn same_revision_repair_rejects_the_previous_boundary_acknowledgment() {
        let tracker = Tracker::new();
        let credentials = ProviderCredentialState::from_child_env_snapshot(6, HashMap::new());
        tracker.credentials_installed(identity(), &credentials, None);
        let old = installation(&credentials);
        credentials
            .install_child_env_snapshot(6, HashMap::from([("TOKEN".into(), "restored".into())]));
        tracker.credentials_installed(identity(), &credentials, None);
        tracker.process_installed(old, &credentials);
        assert!(
            !tracker
                .observation(&credentials)
                .launch_environment_installed
        );
        tracker.process_installed(installation(&credentials), &credentials);
        assert!(
            tracker
                .observation(&credentials)
                .launch_environment_installed
        );
    }

    #[test]
    fn policy_failure_and_generation_change_invalidate_installed_evidence() {
        let tracker = Tracker::new();
        let credentials = ProviderCredentialState::from_child_env_snapshot(6, HashMap::new());
        let policy = openshell_policy::restrictive_default_policy();
        let engine = openshell_supervisor_network::opa::OpaEngine::from_proto(&policy).unwrap();
        tracker.credentials_installed(identity(), &credentials, None);
        tracker.policy_activated(&identity(), 12, engine.generation_guard(0).unwrap());
        tracker.process_installed(installation(&credentials), &credentials);
        assert!(tracker.observation(&credentials).policy_active);
        engine.enter_fail_closed("test quarantine").unwrap();
        assert!(!tracker.observation(&credentials).policy_active);
        let mut rejected = identity();
        rejected.policy_hash = "rejected".into();
        tracker.policy_install_failed(rejected, 13);
        let observed = tracker.observation(&credentials);
        assert_eq!(observed.config_revision, 13);
        assert_eq!(observed.policy_hash, "rejected");
        assert!(!observed.credentials_installed);
        assert!(!observed.launch_environment_installed);
    }

    #[test]
    fn expired_credentials_and_disconnected_boundary_never_complete() {
        let tracker = Tracker::new();
        let credentials = ProviderCredentialState::from_child_env_snapshot(6, HashMap::new());
        tracker.credentials_installed(identity(), &credentials, Some(1));
        tracker.process_installed(installation(&credentials), &credentials);
        assert_eq!(
            tracker.observation(&credentials).reason,
            i32::from(Reason::CredentialExpired)
        );
        tracker.credentials_installed(identity(), &credentials, None);
        tracker.process_installed(installation(&credentials), &credentials);
        tracker.process_failed();
        assert!(
            !tracker
                .observation(&credentials)
                .launch_environment_installed
        );
    }
}
