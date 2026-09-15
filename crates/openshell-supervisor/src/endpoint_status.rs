// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Report the last observed network result for configured external tool endpoints.
//!
//! Only MCP-over-HTTP traffic currently supplies observations. Reporting is
//! passive, bounded, and independent of policy enforcement and sandbox readiness.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use openshell_core::endpoint_status::{
    EndpointConfigVersion, EndpointInventoryEntry, EndpointObservationSender,
    EndpointStatusCommand, EndpointStatusReceiver, EndpointStatusTracker, endpoint_id,
};
use openshell_core::mcp::is_mcp_protocol;
use openshell_core::proto::SandboxPolicy;
use tokio::time::timeout;
use tracing::warn;

use crate::{PolicyGatewayClient, is_retryable_error};

/// Deliver complete tool server endpoint snapshots independently from network traffic.
///
/// The tracker consumes one FIFO and rejects observations from an earlier
/// inventory or supervisor session. Retries retain an immutable snapshot until
/// an inventory reset supersedes it; each frozen snapshot reserves a distinct
/// session sequence so cancellation cannot reuse an ambiguously accepted body.
pub async fn run_reporter<C: PolicyGatewayClient>(
    client: C,
    sandbox_id: String,
    mut commands: EndpointStatusReceiver,
    mut supervisor_session_id: tokio::sync::watch::Receiver<Option<String>>,
) {
    const REPORT_TIMEOUT: Duration = Duration::from_secs(10);
    const OBSERVATION_COALESCE_WINDOW: Duration = Duration::from_millis(250);

    let mut tracker = commands.tracker();
    // Adopting the current value also acknowledges its watch notification.
    // A value queued before startup must not later cancel the initial report.
    let mut active_session = supervisor_session_id.borrow_and_update().clone();
    // Startup adopts the latest session, so handles captured before the
    // reporter started cannot establish that session's observation freshness.
    tracker.clear_observations();
    let mut next_sequence = 1_u64;
    let mut dirty = false;
    let mut observed_endpoint_ids = BTreeSet::new();
    let mut coalesce_until = None;
    let mut commands_open = true;
    let mut session_watch_open = true;

    'outbox: loop {
        // Endpoint state can accumulate while disconnected, but it cannot leave
        // the sandbox until an authenticated supervisor session is active.
        while !dirty || active_session.is_none() {
            if !commands_open && !session_watch_open {
                return;
            }
            tokio::select! {
                command = commands.recv(), if commands_open => match command {
                    Some(command) => {
                        let inventory_reset = matches!(
                            &command,
                            EndpointStatusCommand::Reset { .. }
                        );
                        let changed = apply_command(
                            &mut tracker,
                            &mut observed_endpoint_ids,
                            command,
                        );
                        dirty |= changed;
                        if changed {
                            coalesce_until = if inventory_reset {
                                None
                            } else {
                                Some(tokio::time::Instant::now() + OBSERVATION_COALESCE_WINDOW)
                            };
                        }
                    }
                    None => commands_open = false,
                },
                changed = supervisor_session_id.changed(), if session_watch_open => {
                    if changed.is_err() {
                        session_watch_open = false;
                    } else if apply_session_change(
                        &mut tracker,
                        &mut observed_endpoint_ids,
                        &mut active_session,
                        &mut next_sequence,
                        supervisor_session_id.borrow_and_update().clone(),
                        &mut dirty,
                    ) {
                        coalesce_until = None;
                    }
                }
            }
        }

        if let Some(flush_at) = coalesce_until.take() {
            loop {
                tokio::select! {
                    () = tokio::time::sleep_until(flush_at) => break,
                    command = commands.recv(), if commands_open => match command {
                        Some(command) => {
                            dirty |= apply_command(
                                &mut tracker,
                                &mut observed_endpoint_ids,
                                command,
                            );
                        }
                        None => commands_open = false,
                    },
                    changed = supervisor_session_id.changed(), if session_watch_open => {
                        if changed.is_err() {
                            session_watch_open = false;
                        } else if apply_session_change(
                            &mut tracker,
                            &mut observed_endpoint_ids,
                            &mut active_session,
                            &mut next_sequence,
                            supervisor_session_id.borrow_and_update().clone(),
                            &mut dirty,
                        ) {
                            continue 'outbox;
                        }
                    }
                }
            }
        }

        // Freeze one immutable report after draining commands already queued.
        // Observations update the next report, never an in-flight retry. An
        // inventory reset retires that report and reserves a higher sequence.
        while let Ok(command) = commands.try_recv() {
            dirty |= apply_command(&mut tracker, &mut observed_endpoint_ids, command);
        }
        let Some(session_id) = active_session.clone() else {
            continue;
        };
        let Some(mut snapshot) = tracker.snapshot() else {
            dirty = false;
            continue;
        };
        snapshot.observed_endpoint_ids = observed_endpoint_ids.iter().cloned().collect();
        snapshot.supervisor_session_id = session_id;
        snapshot.report_sequence = next_sequence;
        // A cancelled RPC may already have committed. Reserve the sequence
        // before sending so a reset cannot reuse it with a different body,
        // even when configuration values return to an earlier configuration.
        let Some(following_sequence) = next_sequence.checked_add(1) else {
            warn!("Endpoint status sequence exhausted for the active session");
            return;
        };
        next_sequence = following_sequence;
        observed_endpoint_ids.clear();
        dirty = false;

        let mut attempt = 1_u32;
        'retry: loop {
            let mut report = Box::pin(timeout(
                REPORT_TIMEOUT,
                client.report_endpoint_status(&sandbox_id, &snapshot),
            ));
            let result = loop {
                tokio::select! {
                    result = &mut report => break result,
                    command = commands.recv(), if commands_open => match command {
                        Some(command) => {
                            let inventory_reset = matches!(
                                &command,
                                EndpointStatusCommand::Reset { .. }
                            );
                            if inventory_reset {
                                // A cancelled batch may not have reached the
                                // gateway. Retain its real observations only
                                // where the reset preserves their results.
                                observed_endpoint_ids.extend(snapshot.observed_endpoint_ids.iter().cloned());
                            }
                            let changed = apply_command(
                                &mut tracker,
                                &mut observed_endpoint_ids,
                                command,
                            );
                            dirty |= changed;
                            // An accepted reset supersedes this installation,
                            // including same-value reinstalls. Retrying its old
                            // snapshot could block current observations forever.
                            if changed && inventory_reset {
                                continue 'outbox;
                            }
                        }
                        None => commands_open = false,
                    },
                    changed = supervisor_session_id.changed(), if session_watch_open => {
                        if changed.is_err() {
                            session_watch_open = false;
                        } else if apply_session_change(
                            &mut tracker,
                            &mut observed_endpoint_ids,
                            &mut active_session,
                            &mut next_sequence,
                            supervisor_session_id.borrow_and_update().clone(),
                            &mut dirty,
                        ) {
                            continue 'outbox;
                        }
                    }
                }
            };

            match result {
                Ok(Ok(())) => continue 'outbox,
                Ok(Err(error)) if !is_retryable_error(&error) => {
                    warn!(%error, "Discarding terminal endpoint status snapshot");
                    continue 'outbox;
                }
                Ok(Err(error)) => {
                    warn!(%error, attempt, "Endpoint status report failed transiently; retaining immutable snapshot");
                }
                Err(error) => {
                    warn!(%error, attempt, "Endpoint status report timed out; retaining immutable snapshot");
                }
            }

            let retry_at = tokio::time::Instant::now()
                + Duration::from_secs(1_u64 << attempt.saturating_sub(1).min(5));
            loop {
                tokio::select! {
                    () = tokio::time::sleep_until(retry_at) => {
                        attempt = attempt.saturating_add(1);
                        continue 'retry;
                    }
                    command = commands.recv(), if commands_open => match command {
                        Some(command) => {
                            let inventory_reset = matches!(
                                &command,
                                EndpointStatusCommand::Reset { .. }
                            );
                            if inventory_reset {
                                // A cancelled batch may not have reached the
                                // gateway. Retain its real observations only
                                // where the reset preserves their results.
                                observed_endpoint_ids.extend(snapshot.observed_endpoint_ids.iter().cloned());
                            }
                            let changed = apply_command(
                                &mut tracker,
                                &mut observed_endpoint_ids,
                                command,
                            );
                            dirty |= changed;
                            // An accepted reset supersedes this installation,
                            // including same-value reinstalls. Retrying its old
                            // snapshot could block current observations forever.
                            if changed && inventory_reset {
                                continue 'outbox;
                            }
                        }
                        None => commands_open = false,
                    },
                    changed = supervisor_session_id.changed(), if session_watch_open => {
                        if changed.is_err() {
                            session_watch_open = false;
                        } else if apply_session_change(
                            &mut tracker,
                            &mut observed_endpoint_ids,
                            &mut active_session,
                            &mut next_sequence,
                            supervisor_session_id.borrow_and_update().clone(),
                            &mut dirty,
                        ) {
                            continue 'outbox;
                        }
                    }
                }
            }
        }
    }
}

fn apply_session_change(
    tracker: &mut EndpointStatusTracker,
    observed_endpoint_ids: &mut BTreeSet<String>,
    active_session: &mut Option<String>,
    next_sequence: &mut u64,
    replacement: Option<String>,
    dirty: &mut bool,
) -> bool {
    if *active_session == replacement {
        // Watch notifications can repeat the same session. Only a different
        // authority may cancel delivery or reset the report sequence.
        return false;
    }
    *active_session = replacement;
    *next_sequence = 1;
    observed_endpoint_ids.clear();
    // Results belong to the session that observed them. Clearing on both
    // disconnect and replacement prevents a new stream from replaying them.
    *dirty |= tracker.clear_observations();
    true
}

fn apply_command(
    tracker: &mut EndpointStatusTracker,
    observed_endpoint_ids: &mut BTreeSet<String>,
    command: EndpointStatusCommand,
) -> bool {
    let retained_endpoint_ids = match &command {
        EndpointStatusCommand::Reset {
            config_version,
            endpoints,
            ..
        } => {
            let previous = tracker.snapshot();
            // Match the tracker's reset rule: provider changes retain evidence
            // only for endpoints without provider credentials. Policy changes
            // and endpoint removal retire the corresponding observations.
            Some(
                endpoints
                    .iter()
                    .filter(|endpoint| {
                        previous.as_ref().is_some_and(|snapshot| {
                            snapshot.config_version.policy_hash == config_version.policy_hash
                                && (snapshot.config_version.provider_env_revision
                                    == config_version.provider_env_revision
                                    || !endpoint.uses_provider_credentials)
                        })
                    })
                    .map(|endpoint| endpoint.endpoint_id.clone())
                    .collect::<BTreeSet<_>>(),
            )
        }
        EndpointStatusCommand::Observe { .. } => None,
    };
    let observed_endpoint_id = match &command {
        EndpointStatusCommand::Observe { endpoint_id, .. } => Some(endpoint_id.clone()),
        EndpointStatusCommand::Reset { .. } => None,
    };
    if !tracker.apply(command) {
        return false;
    }
    if let Some(retained_endpoint_ids) = retained_endpoint_ids {
        // Surviving results still need their pending observation markers if
        // an earlier report was superseded before its acknowledgement arrived.
        observed_endpoint_ids.retain(|endpoint_id| retained_endpoint_ids.contains(endpoint_id));
    } else if let Some(endpoint_id) = observed_endpoint_id {
        observed_endpoint_ids.insert(endpoint_id);
    }
    true
}

/// Collect the MCP endpoints whose HTTP exchanges provide status observations.
pub fn mcp_endpoint_inventory(policy: &SandboxPolicy) -> Vec<EndpointInventoryEntry> {
    let mut endpoints = BTreeMap::new();
    for endpoint in policy
        .network_policies
        .values()
        .flat_map(|rule| &rule.endpoints)
        .filter(|endpoint| is_mcp_protocol(&endpoint.protocol))
    {
        endpoints
            .entry(endpoint_id(endpoint))
            .and_modify(|credentialed| *credentialed |= endpoint.provider_credentialed)
            .or_insert(endpoint.provider_credentialed);
    }
    endpoints
        .into_iter()
        .map(
            |(endpoint_id, uses_provider_credentials)| EndpointInventoryEntry {
                endpoint_id,
                uses_provider_credentials,
            },
        )
        .collect()
}

/// Reset observations after the policy and provider environment are installed.
pub async fn reset(
    sender: Option<&EndpointObservationSender>,
    policy: Option<&SandboxPolicy>,
    policy_hash: &str,
    provider_env_revision: u64,
) {
    let (Some(sender), Some(policy)) = (sender, policy) else {
        // Local policy overrides and disabled networking have no gateway
        // endpoint inventory to report against.
        return;
    };
    if policy_hash.is_empty() {
        // Until a gateway policy is installed, observations cannot be bound
        // to an authoritative configuration version.
        return;
    }
    let config_version = EndpointConfigVersion {
        policy_hash: policy_hash.to_string(),
        provider_env_revision,
    };
    if let Err(error) = sender
        .reset(config_version, mcp_endpoint_inventory(policy))
        .await
    {
        warn!(%error, "Endpoint status tracker unavailable during policy installation");
    }
}

#[cfg(test)]
#[allow(
    clippy::similar_names,
    reason = "Test fixtures compare successive report identities."
)]
mod tests {
    use super::*;
    use miette::Result;
    use openshell_core::endpoint_status::{
        EndpointResult, EndpointStatusSnapshot, endpoint_status_channel,
    };
    use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::mpsc::UnboundedSender;

    #[derive(Clone)]
    struct EndpointStatusGateway {
        reports: UnboundedSender<EndpointStatusSnapshot>,
    }

    #[tonic::async_trait]
    impl PolicyGatewayClient for EndpointStatusGateway {
        async fn poll_settings(
            &self,
            _sandbox_id: &str,
        ) -> Result<openshell_core::grpc_client::SettingsPollResult> {
            Err(miette::miette!(
                "endpoint-status test does not poll settings"
            ))
        }

        async fn report_policy_status(
            &self,
            _sandbox_id: &str,
            _version: u32,
            _loaded: bool,
            _error: &str,
        ) -> Result<()> {
            Ok(())
        }

        async fn report_endpoint_status(
            &self,
            _sandbox_id: &str,
            snapshot: &EndpointStatusSnapshot,
        ) -> Result<()> {
            self.reports
                .send(snapshot.clone())
                .map_err(|_| miette::miette!("endpoint-status report receiver closed"))
        }

        fn workspace(&self) -> String {
            String::new()
        }
    }

    #[derive(Clone)]
    struct RetryEndpointStatusGateway {
        attempts: Arc<AtomicUsize>,
        reports: UnboundedSender<EndpointStatusSnapshot>,
    }

    #[tonic::async_trait]
    impl PolicyGatewayClient for RetryEndpointStatusGateway {
        async fn poll_settings(
            &self,
            _sandbox_id: &str,
        ) -> Result<openshell_core::grpc_client::SettingsPollResult> {
            Err(miette::miette!(
                "endpoint-status test does not poll settings"
            ))
        }

        async fn report_policy_status(
            &self,
            _sandbox_id: &str,
            _version: u32,
            _loaded: bool,
            _error: &str,
        ) -> Result<()> {
            Ok(())
        }

        async fn report_endpoint_status(
            &self,
            _sandbox_id: &str,
            snapshot: &EndpointStatusSnapshot,
        ) -> Result<()> {
            self.reports
                .send(snapshot.clone())
                .map_err(|_| miette::miette!("endpoint-status report receiver closed"))?;
            if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(miette::miette!("simulated connection loss after commit"))
            } else {
                Ok(())
            }
        }

        fn workspace(&self) -> String {
            String::new()
        }
    }

    #[tokio::test]
    async fn reporter_coalesces_observation_bursts() {
        let (sender, receiver) = endpoint_status_channel();
        let (reports_tx, mut reports_rx) = tokio::sync::mpsc::unbounded_channel();
        let (session_tx, session_rx) =
            tokio::sync::watch::channel(Some("session-test".to_string()));
        let reporter = tokio::spawn(run_reporter(
            EndpointStatusGateway {
                reports: reports_tx,
            },
            "sandbox-test".to_string(),
            receiver,
            session_rx,
        ));
        sender
            .reset(
                EndpointConfigVersion {
                    policy_hash: "policy-a".to_string(),
                    provider_env_revision: 1,
                },
                vec![
                    EndpointInventoryEntry {
                        endpoint_id: "endpoint:public".to_string(),
                        uses_provider_credentials: false,
                    },
                    EndpointInventoryEntry {
                        endpoint_id: "endpoint:unused".to_string(),
                        uses_provider_credentials: false,
                    },
                ],
            )
            .await
            .expect("reporter remains active");
        let initial = timeout(Duration::from_secs(1), reports_rx.recv())
            .await
            .expect("initial inventory report timed out")
            .expect("reporter remains active");
        assert_eq!(
            initial.endpoints[0].result,
            EndpointResult::NoObservedExchange
        );
        assert!(initial.observed_endpoint_ids.is_empty());
        assert_eq!(initial.supervisor_session_id, "session-test");
        assert_eq!(initial.report_sequence, 1);

        for result in [
            EndpointResult::HttpResponseReceived,
            EndpointResult::PolicyDenied,
            EndpointResult::HttpResponseReceived,
        ] {
            let observation = sender
                .begin("endpoint:public".to_string())
                .expect("reset published a configuration version");
            assert!(sender.try_observe(observation, result));
        }

        let coalesced = timeout(Duration::from_secs(1), reports_rx.recv())
            .await
            .expect("coalesced observation report timed out")
            .expect("reporter remains active");
        assert_eq!(
            coalesced
                .endpoints
                .iter()
                .find(|endpoint| endpoint.endpoint_id == "endpoint:public")
                .expect("public endpoint remains in the full snapshot")
                .result,
            EndpointResult::HttpResponseReceived
        );
        assert_eq!(
            coalesced.observed_endpoint_ids,
            vec!["endpoint:public".to_string()]
        );
        assert_eq!(coalesced.report_sequence, 2);
        assert!(
            timeout(Duration::from_millis(100), reports_rx.recv())
                .await
                .is_err(),
            "one observation burst must produce one control-plane write"
        );

        let stale_observation = sender
            .begin("endpoint:unused".to_string())
            .expect("reset published a configuration version");
        session_tx.send_replace(Some("session-replacement".to_string()));
        let replacement = timeout(Duration::from_secs(1), reports_rx.recv())
            .await
            .expect("replacement-session report timed out")
            .expect("reporter remains active");
        assert_eq!(replacement.supervisor_session_id, "session-replacement");
        assert_eq!(replacement.report_sequence, 1);
        assert!(replacement.observed_endpoint_ids.is_empty());
        assert!(
            replacement
                .endpoints
                .iter()
                .all(|endpoint| endpoint.result == EndpointResult::NoObservedExchange)
        );

        assert!(sender.try_observe(stale_observation, EndpointResult::HttpResponseReceived));
        // Wait beyond the coalescing window: a stale exchange must not produce
        // a report that advances the replacement session's observation times.
        assert!(
            timeout(Duration::from_millis(500), reports_rx.recv())
                .await
                .is_err(),
            "an exchange started in the previous session must not be reported"
        );

        let fresh_observation = sender
            .begin("endpoint:public".to_string())
            .expect("the replacement session retains the inventory");
        assert!(sender.try_observe(fresh_observation, EndpointResult::PolicyDenied));
        let fresh = timeout(Duration::from_secs(1), reports_rx.recv())
            .await
            .expect("fresh replacement-session observation timed out")
            .expect("reporter remains active");
        assert_eq!(fresh.supervisor_session_id, "session-replacement");
        assert_eq!(fresh.report_sequence, 2);
        assert_eq!(
            fresh.observed_endpoint_ids,
            vec!["endpoint:public".to_string()]
        );
        assert_eq!(fresh.endpoints[0].endpoint_id, "endpoint:public");
        assert_eq!(fresh.endpoints[0].result, EndpointResult::PolicyDenied);
        assert_eq!(fresh.endpoints[1].endpoint_id, "endpoint:unused");
        assert_eq!(
            fresh.endpoints[1].result,
            EndpointResult::NoObservedExchange
        );
        reporter.abort();
    }

    #[tokio::test]
    async fn reporter_invalidates_handles_queued_before_startup() {
        let (sender, receiver) = endpoint_status_channel();
        let (reports_tx, mut reports_rx) = tokio::sync::mpsc::unbounded_channel();
        let (session_tx, session_rx) = tokio::sync::watch::channel(Some("session-a".to_string()));
        sender
            .reset(
                EndpointConfigVersion {
                    policy_hash: "policy-a".to_string(),
                    provider_env_revision: 1,
                },
                vec![EndpointInventoryEntry {
                    endpoint_id: "endpoint:public".to_string(),
                    uses_provider_credentials: false,
                }],
            )
            .await
            .expect("the receiver remains active");
        let stale_observation = sender
            .begin("endpoint:public".to_string())
            .expect("the queued reset published a configuration version");
        session_tx.send_replace(Some("session-b".to_string()));
        assert!(sender.try_observe(stale_observation, EndpointResult::HttpResponseReceived));

        // Both commands precede reporter startup. Adopting the latest watch
        // value must invalidate the earlier handle before draining the FIFO.
        let reporter = tokio::spawn(run_reporter(
            EndpointStatusGateway {
                reports: reports_tx,
            },
            "sandbox-test".to_string(),
            receiver,
            session_rx,
        ));
        let initial = timeout(Duration::from_secs(1), reports_rx.recv())
            .await
            .expect("initial inventory report timed out")
            .expect("reporter remains active");
        assert_eq!(initial.supervisor_session_id, "session-b");
        assert_eq!(initial.report_sequence, 1);
        assert_eq!(
            initial.endpoints[0].result,
            EndpointResult::NoObservedExchange
        );
        assert!(initial.observed_endpoint_ids.is_empty());

        let fresh_observation = sender
            .begin("endpoint:public".to_string())
            .expect("the reporter published its observation authority");
        assert!(sender.try_observe(fresh_observation, EndpointResult::PolicyDenied));
        let fresh = timeout(Duration::from_secs(1), reports_rx.recv())
            .await
            .expect("fresh observation report timed out")
            .expect("reporter remains active");
        assert_eq!(fresh.supervisor_session_id, "session-b");
        assert_eq!(fresh.report_sequence, 2);
        assert_eq!(fresh.endpoints[0].result, EndpointResult::PolicyDenied);
        assert_eq!(
            fresh.observed_endpoint_ids,
            vec!["endpoint:public".to_string()]
        );
        reporter.abort();
    }

    #[tokio::test]
    async fn session_change_invalidates_handles_before_pending_reset() {
        let (sender, mut commands) = endpoint_status_channel();
        let mut tracker = commands.tracker();
        let config_version = EndpointConfigVersion {
            policy_hash: "policy-a".to_string(),
            provider_env_revision: 1,
        };
        sender
            .reset(
                config_version.clone(),
                vec![EndpointInventoryEntry {
                    endpoint_id: "endpoint:public".to_string(),
                    uses_provider_credentials: false,
                }],
            )
            .await
            .expect("tracker remains active");
        let stale_observation = sender
            .begin("endpoint:public".to_string())
            .expect("the queued reset published a configuration version");

        let mut observed_endpoint_ids = BTreeSet::new();
        let mut active_session = Some("session-test".to_string());
        let mut next_sequence = 9;
        let mut dirty = false;
        // A session can change before the first inventory is consumed. Its
        // pending reset must not restore the previous observation authority.
        apply_session_change(
            &mut tracker,
            &mut observed_endpoint_ids,
            &mut active_session,
            &mut next_sequence,
            Some("session-replacement".to_string()),
            &mut dirty,
        );
        assert_eq!(active_session.as_deref(), Some("session-replacement"));
        assert_eq!(next_sequence, 1);
        assert!(!dirty);
        assert!(tracker.snapshot().is_none());

        let fresh_observation = sender
            .begin("endpoint:public".to_string())
            .expect("new requests capture the replacement authority");
        assert!(apply_command(
            &mut tracker,
            &mut observed_endpoint_ids,
            commands.try_recv().expect("the first reset is pending"),
        ));

        assert!(sender.try_observe(stale_observation, EndpointResult::HttpResponseReceived));
        assert!(!apply_command(
            &mut tracker,
            &mut observed_endpoint_ids,
            commands
                .try_recv()
                .expect("the stale observation is queued"),
        ));
        assert!(observed_endpoint_ids.is_empty());
        assert_eq!(
            tracker
                .snapshot()
                .expect("the inventory is installed")
                .endpoints[0]
                .result,
            EndpointResult::NoObservedExchange
        );

        assert!(sender.try_observe(fresh_observation, EndpointResult::PolicyDenied));
        assert!(apply_command(
            &mut tracker,
            &mut observed_endpoint_ids,
            commands
                .try_recv()
                .expect("the fresh observation is queued"),
        ));
        assert_eq!(
            observed_endpoint_ids,
            BTreeSet::from(["endpoint:public".to_string()])
        );
        assert_eq!(
            tracker
                .snapshot()
                .expect("the inventory is installed")
                .endpoints[0]
                .result,
            EndpointResult::PolicyDenied
        );
    }

    #[tokio::test]
    async fn reporter_retries_an_immutable_sequence() {
        let (sender, receiver) = endpoint_status_channel();
        let (reports_tx, mut reports_rx) = tokio::sync::mpsc::unbounded_channel();
        let (_session_tx, session_rx) =
            tokio::sync::watch::channel(Some("session-test".to_string()));
        let reporter = tokio::spawn(run_reporter(
            RetryEndpointStatusGateway {
                attempts: Arc::new(AtomicUsize::new(0)),
                reports: reports_tx,
            },
            "sandbox-test".to_string(),
            receiver,
            session_rx,
        ));
        sender
            .reset(
                EndpointConfigVersion {
                    policy_hash: "policy-a".to_string(),
                    provider_env_revision: 1,
                },
                vec![EndpointInventoryEntry {
                    endpoint_id: "endpoint:public".to_string(),
                    uses_provider_credentials: false,
                }],
            )
            .await
            .expect("reporter remains active");
        let first_attempt = timeout(Duration::from_secs(1), reports_rx.recv())
            .await
            .expect("first report timed out")
            .expect("reporter remains active");
        let observation = sender
            .begin("endpoint:public".to_string())
            .expect("reset published a configuration version");
        assert!(sender.try_observe(observation, EndpointResult::HttpResponseReceived));

        let retry = timeout(Duration::from_secs(2), reports_rx.recv())
            .await
            .expect("retry timed out")
            .expect("reporter remains active");
        assert_eq!(retry, first_attempt, "retry must preserve batch identity");

        let next = timeout(Duration::from_secs(1), reports_rx.recv())
            .await
            .expect("deferred observation report timed out")
            .expect("reporter remains active");
        assert_eq!(next.report_sequence, 2);
        assert_eq!(
            next.observed_endpoint_ids,
            vec!["endpoint:public".to_string()]
        );
        assert_eq!(
            next.endpoints[0].result,
            EndpointResult::HttpResponseReceived
        );
        reporter.abort();
    }

    struct ControlledEndpointStatusAttempt {
        snapshot: EndpointStatusSnapshot,
        complete: tokio::sync::oneshot::Sender<Result<()>>,
    }

    #[derive(Clone)]
    struct ControlledEndpointStatusGateway {
        reports: UnboundedSender<ControlledEndpointStatusAttempt>,
    }

    #[tonic::async_trait]
    impl PolicyGatewayClient for ControlledEndpointStatusGateway {
        async fn poll_settings(
            &self,
            _sandbox_id: &str,
        ) -> Result<openshell_core::grpc_client::SettingsPollResult> {
            Err(miette::miette!(
                "endpoint-status test does not poll settings"
            ))
        }

        async fn report_policy_status(
            &self,
            _sandbox_id: &str,
            _version: u32,
            _loaded: bool,
            _error: &str,
        ) -> Result<()> {
            Ok(())
        }

        async fn report_endpoint_status(
            &self,
            _sandbox_id: &str,
            snapshot: &EndpointStatusSnapshot,
        ) -> Result<()> {
            let (complete, result) = tokio::sync::oneshot::channel();
            self.reports
                .send(ControlledEndpointStatusAttempt {
                    snapshot: snapshot.clone(),
                    complete,
                })
                .map_err(|_| miette::miette!("endpoint-status report receiver closed"))?;
            result
                .await
                .map_err(|_| miette::miette!("endpoint-status response cancelled"))?
        }

        fn workspace(&self) -> String {
            String::new()
        }
    }

    async fn assert_reset_supersedes_pending_snapshot(during_backoff: bool) {
        let (sender, receiver) = endpoint_status_channel();
        let (reports_tx, mut reports_rx) = tokio::sync::mpsc::unbounded_channel();
        let (_session_tx, session_rx) =
            tokio::sync::watch::channel(Some("session-test".to_string()));
        let reporter = tokio::spawn(run_reporter(
            ControlledEndpointStatusGateway {
                reports: reports_tx,
            },
            "sandbox-test".to_string(),
            receiver,
            session_rx,
        ));
        let initial_config_version = EndpointConfigVersion {
            policy_hash: "policy-a".to_string(),
            provider_env_revision: 1,
        };
        let inventory = vec![
            EndpointInventoryEntry {
                endpoint_id: "endpoint:public".to_string(),
                uses_provider_credentials: false,
            },
            EndpointInventoryEntry {
                endpoint_id: "endpoint:secure".to_string(),
                uses_provider_credentials: true,
            },
        ];
        sender
            .reset(initial_config_version.clone(), inventory.clone())
            .await
            .expect("reporter remains active");
        let first = timeout(Duration::from_secs(1), reports_rx.recv())
            .await
            .expect("initial report timed out")
            .expect("reporter remains active");
        assert_eq!(first.snapshot.report_sequence, 1);
        first
            .complete
            .send(Ok(()))
            .expect("initial call remains active");
        for endpoint_id in ["endpoint:public", "endpoint:secure"] {
            let observation = sender
                .begin(endpoint_id.to_string())
                .expect("inventory installed");
            assert!(sender.try_observe(observation, EndpointResult::HttpResponseReceived));
        }
        let pending = timeout(Duration::from_secs(1), reports_rx.recv())
            .await
            .expect("observation report timed out")
            .expect("reporter remains active");
        assert_eq!(pending.snapshot.report_sequence, 2);
        assert_eq!(
            pending.snapshot.observed_endpoint_ids,
            vec!["endpoint:public", "endpoint:secure"]
        );
        let mut response = Some(pending.complete);

        // Exercise provider replacement, return to the original values,
        // same-value reinstallation, and a policy change while unresolved
        // public observations must either survive or be invalidated together
        // with the results they justify.
        for (offset, config_version) in [
            EndpointConfigVersion {
                provider_env_revision: 2,
                ..initial_config_version.clone()
            },
            initial_config_version.clone(),
            initial_config_version,
            EndpointConfigVersion {
                policy_hash: "policy-b".to_string(),
                provider_env_revision: 1,
            },
        ]
        .into_iter()
        .enumerate()
        {
            let stale = sender
                .begin("endpoint:secure".to_string())
                .expect("inventory remains installed");
            if during_backoff {
                response
                    .take()
                    .expect("pending response")
                    .send(Err(miette::miette!(
                        "simulated transient configuration mismatch"
                    )))
                    .expect("pending call remains active");
                // On the current-thread test runtime this lets the reporter
                // consume the response and enter its one-second retry backoff.
                tokio::task::yield_now().await;
            }
            sender
                .reset(config_version.clone(), inventory.clone())
                .await
                .expect("reporter remains active");
            let fresh = sender
                .begin("endpoint:secure".to_string())
                .expect("replacement inventory installed");
            assert!(sender.try_observe(fresh, EndpointResult::CredentialUnavailable));
            assert!(sender.try_observe(stale, EndpointResult::HttpResponseReceived));

            let next = timeout(Duration::from_millis(500), reports_rx.recv())
                .await
                .expect("reset must bypass the obsolete call or backoff")
                .expect("reporter remains active");
            assert_eq!(next.snapshot.config_version, config_version);
            assert_eq!(
                next.snapshot.report_sequence,
                u64::try_from(offset).expect("small test offset") + 3
            );
            assert_eq!(next.snapshot.endpoints.len(), 2);
            assert_eq!(next.snapshot.endpoints[0].endpoint_id, "endpoint:public");
            assert_eq!(next.snapshot.endpoints[1].endpoint_id, "endpoint:secure");
            assert_eq!(
                next.snapshot.endpoints[1].result,
                EndpointResult::CredentialUnavailable
            );
            if config_version.policy_hash == "policy-a" {
                assert_eq!(
                    next.snapshot.observed_endpoint_ids,
                    vec!["endpoint:public", "endpoint:secure"]
                );
                assert_eq!(
                    next.snapshot.endpoints[0].result,
                    EndpointResult::HttpResponseReceived
                );
            } else {
                assert_eq!(next.snapshot.observed_endpoint_ids, vec!["endpoint:secure"]);
                assert_eq!(
                    next.snapshot.endpoints[0].result,
                    EndpointResult::NoObservedExchange
                );
            }
            if let Some(previous_response) = response.take() {
                assert!(
                    previous_response.send(Ok(())).is_err(),
                    "reset must cancel the obsolete RPC future"
                );
            }
            response = Some(next.complete);
        }
        response
            .expect("final pending response")
            .send(Ok(()))
            .expect("current report remains active");
        reporter.abort();
    }

    #[tokio::test]
    async fn reporter_supersedes_in_flight_snapshot_on_inventory_reset() {
        assert_reset_supersedes_pending_snapshot(false).await;
    }

    #[tokio::test]
    async fn reporter_supersedes_backoff_snapshot_on_inventory_reset() {
        assert_reset_supersedes_pending_snapshot(true).await;
    }

    #[tokio::test]
    async fn reporter_retains_delivery_on_same_session_notifications() {
        let (sender, receiver) = endpoint_status_channel();
        let (reports_tx, mut reports_rx) = tokio::sync::mpsc::unbounded_channel();
        let (session_tx, session_rx) =
            tokio::sync::watch::channel(Some("session-test".to_string()));
        let reporter = tokio::spawn(run_reporter(
            ControlledEndpointStatusGateway {
                reports: reports_tx,
            },
            "sandbox-test".to_string(),
            receiver,
            session_rx,
        ));
        sender
            .reset(
                EndpointConfigVersion {
                    policy_hash: "policy-a".to_string(),
                    provider_env_revision: 1,
                },
                vec![EndpointInventoryEntry {
                    endpoint_id: "endpoint:public".to_string(),
                    uses_provider_credentials: false,
                }],
            )
            .await
            .expect("reporter remains active");
        let first = timeout(Duration::from_secs(1), reports_rx.recv())
            .await
            .expect("initial report timed out")
            .expect("reporter remains active");

        // Repeat the current value while the RPC is pending. The watch emits
        // a notification, but there is no new authority to cancel this batch.
        session_tx.send_replace(Some("session-test".to_string()));
        tokio::task::yield_now().await;
        assert!(
            !first.complete.is_closed(),
            "same-session notification must not cancel the pending call"
        );
        first
            .complete
            .send(Err(miette::miette!(
                "simulated connection loss after commit"
            )))
            .expect("pending report remains active");
        tokio::task::yield_now().await;

        // Repeat during backoff with newer evidence already queued. Delivery
        // must still retry the identical body before publishing that evidence.
        let observation = sender
            .begin("endpoint:public".to_string())
            .expect("inventory remains installed");
        assert!(sender.try_observe(observation, EndpointResult::HttpResponseReceived));
        session_tx.send_replace(Some("session-test".to_string()));
        let retry = timeout(Duration::from_secs(2), reports_rx.recv())
            .await
            .expect("unchanged-session retry timed out")
            .expect("reporter remains active");
        assert_eq!(
            retry.snapshot, first.snapshot,
            "a repeated session value must preserve retry identity"
        );
        retry.complete.send(Ok(())).expect("retry remains active");

        let observed = timeout(Duration::from_secs(1), reports_rx.recv())
            .await
            .expect("queued observation timed out")
            .expect("reporter remains active");
        assert_eq!(
            observed.snapshot.report_sequence,
            first.snapshot.report_sequence + 1
        );
        assert_eq!(
            observed.snapshot.observed_endpoint_ids,
            vec!["endpoint:public"]
        );
        assert_eq!(
            observed.snapshot.endpoints[0].result,
            EndpointResult::HttpResponseReceived
        );
        observed
            .complete
            .send(Ok(()))
            .expect("observation remains active");
        reporter.abort();
    }

    #[test]
    fn mcp_endpoint_inventory_is_deduplicated_and_protocol_scoped() {
        let endpoint = NetworkEndpoint {
            host: "api.example.com".to_string(),
            port: 443,
            protocol: "MCP".to_string(),
            ..Default::default()
        };
        let policy = SandboxPolicy {
            network_policies: std::collections::HashMap::from([(
                "tool-servers".to_string(),
                NetworkPolicyRule {
                    endpoints: vec![
                        endpoint.clone(),
                        NetworkEndpoint {
                            host: "API.EXAMPLE.COM".to_string(),
                            protocol: "mcp".to_string(),
                            provider_credentialed: true,
                            ..endpoint.clone()
                        },
                        NetworkEndpoint {
                            host: "ordinary-http.example.com".to_string(),
                            protocol: "rest".to_string(),
                            ..endpoint.clone()
                        },
                    ],
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        assert_eq!(
            mcp_endpoint_inventory(&policy),
            vec![EndpointInventoryEntry {
                endpoint_id: endpoint_id(&endpoint),
                uses_provider_credentials: true,
            }]
        );
    }
}
