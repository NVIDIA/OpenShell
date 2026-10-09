// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration protocol of one streamed-apply supervisor session.
//!
//! The first connection prepares the startup policy against the workload
//! image. Every session then starts from a bootstrap that carries both
//! components, and afterwards holds at most one unacknowledged update per
//! component. Session lifecycle and relays stay in `supervisor_session`.

use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;
use std::time::{Duration, Instant};

use metrics::counter;
use openshell_core::proto::{
    ConfigApplyOutcome, ConfigBootstrap, ConfigBootstrapResult, ConfigComponent,
    ConfigComponentApplyResult, ConfigSnapshotRevision, ConfigUpdate, ConfigUpdateResult,
    GatewayMessage, PolicySource, ProviderEnvironmentSnapshot, Sandbox, SandboxConfigRevision,
    SandboxConfigSnapshot, SandboxConfigurationAdmission, SandboxPolicy, StartupConfigCandidate,
    SupervisorHello, SupervisorMessage, config_snapshot_revision, config_update, gateway_message,
    startup_config_prepared, supervisor_message,
};
use prost::Message;
use tokio::sync::mpsc;
use tonic::Status;
use tracing::{debug, warn};
use uuid::Uuid;

use super::{
    ConfigComponentKind, ConfigComponents, ConfigSlots, DeliveryDisposition,
    MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES, SupervisorConfigMessage,
};
use crate::ServerState;
use crate::auth::principal::Principal;
use crate::grpc::policy::{
    build_provider_environment_snapshot_from_inputs, build_sandbox_config_snapshot_from_inputs,
    load_sandbox_config_inputs,
};
use crate::supervisor_session::{AcceptedSession, SupervisorSessionRegistry};

/// Streamed-apply supervisors start from the bootstrap, so allow several
/// concurrent component builds, including revision-mismatch retries, before
/// rejecting the session. Session setup does not hold a delivery build slot.
const CONFIG_BOOTSTRAP_BUILD_TIMEOUT: Duration = Duration::from_secs(45);
/// How long an invalid image policy waits for an operator to store a gateway
/// policy before the startup session is rejected.
const STARTUP_POLICY_REPAIR_TIMEOUT: Duration = Duration::from_mins(5);
/// How long a session holds newer updates for a component while waiting for
/// the supervisor to acknowledge the one it already has.
const CONFIG_ACK_TIMEOUT: Duration = Duration::from_mins(1);

#[cfg(test)]
static FAIL_NEXT_ADMISSION_PERSISTENCE_FOR_SANDBOX: std::sync::LazyLock<Mutex<Option<String>>> =
    std::sync::LazyLock::new(|| Mutex::new(None));

// ---------------------------------------------------------------------------
// Snapshot identity
// ---------------------------------------------------------------------------

/// One configuration component snapshot, borrowed from an update or a
/// bootstrap.
#[derive(Clone, Copy)]
enum ComponentSnapshot<'a> {
    SandboxConfig(&'a SandboxConfigSnapshot),
    ProviderEnvironment(&'a ProviderEnvironmentSnapshot),
}

impl<'a> From<&'a SupervisorConfigMessage> for ComponentSnapshot<'a> {
    fn from(message: &'a SupervisorConfigMessage) -> Self {
        match message {
            SupervisorConfigMessage::SandboxConfig(snapshot) => Self::SandboxConfig(snapshot),
            SupervisorConfigMessage::ProviderEnvironment(snapshot) => {
                Self::ProviderEnvironment(snapshot)
            }
        }
    }
}

impl ComponentSnapshot<'_> {
    fn component(self) -> ConfigComponentKind {
        match self {
            Self::SandboxConfig(_) => ConfigComponentKind::SandboxConfig,
            Self::ProviderEnvironment(_) => ConfigComponentKind::ProviderEnvironment,
        }
    }

    /// The revision a supervisor reports its result against.
    fn revision(self) -> ConfigSnapshotRevision {
        let component = match self {
            Self::SandboxConfig(snapshot) => {
                config_snapshot_revision::Component::SandboxConfig(SandboxConfigRevision {
                    config_revision: snapshot.config_revision,
                    policy_version: snapshot.version,
                    policy_source: snapshot.policy_source,
                    global_policy_version: snapshot.global_policy_version,
                    settings_revision: snapshot.settings_revision,
                })
            }
            Self::ProviderEnvironment(snapshot) => {
                config_snapshot_revision::Component::ProviderEnvironment(
                    snapshot.provider_env_revision,
                )
            }
        };
        ConfigSnapshotRevision {
            component: Some(component),
        }
    }

    /// Identifies a snapshot the supervisor already has, including the
    /// generation inputs its revision does not cover.
    fn fingerprint(self) -> ConfigSnapshotFingerprint {
        match self {
            Self::SandboxConfig(snapshot) => ConfigSnapshotFingerprint::Sandbox {
                revision: self.revision(),
                provider_env_revision: snapshot.provider_env_revision,
                provider_attachment_epoch: snapshot.provider_attachment_epoch.clone(),
                policy_hash: snapshot.policy_hash.clone(),
            },
            Self::ProviderEnvironment(snapshot) => ConfigSnapshotFingerprint::ProviderEnvironment {
                provider_env_revision: snapshot.provider_env_revision,
                provider_attachment_epoch: snapshot.provider_attachment_epoch.clone(),
                policy_hash: snapshot.policy_hash.clone(),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ConfigSnapshotFingerprint {
    Sandbox {
        revision: ConfigSnapshotRevision,
        provider_env_revision: u64,
        provider_attachment_epoch: String,
        policy_hash: String,
    },
    ProviderEnvironment {
        provider_env_revision: u64,
        provider_attachment_epoch: String,
        policy_hash: String,
    },
}

// ---------------------------------------------------------------------------
// Per-session delivery state
// ---------------------------------------------------------------------------

/// Delivery state of a session that applies and acknowledges streamed
/// configuration. Each component is held until its previous update is
/// acknowledged.
#[derive(Debug)]
pub struct ConfigSessionState {
    slots: Arc<ConfigSlots>,
    sandbox_config: ComponentDeliveryState,
    provider_environment: ComponentDeliveryState,
}

#[derive(Debug, Default)]
struct ComponentDeliveryState {
    sequence: u64,
    in_flight: Option<InFlightConfigUpdate>,
    pending: Option<SupervisorConfigMessage>,
    last_acknowledged_fingerprint: Option<ConfigSnapshotFingerprint>,
    /// The supervisor staged the last delivered update until its matching
    /// counterpart arrives, and still owes a result for it.
    staged: bool,
    /// When the session's bootstrap was sent, until its result arrives. A
    /// rebuild that races the bootstrap waits as `pending`, so it is dropped
    /// if the bootstrap result acknowledges the same snapshot.
    awaiting_bootstrap_since: Option<Instant>,
    /// The supervisor failed to apply the last update it finished.
    /// Reconciliation rebuilds the component until an update succeeds.
    rejected: bool,
}

#[derive(Debug)]
struct InFlightConfigUpdate {
    update_id: String,
    component_sequence: u64,
    revision: ConfigSnapshotRevision,
    fingerprint: ConfigSnapshotFingerprint,
    admission: Option<SandboxConfigurationAdmission>,
    sent_at: Instant,
}

struct CompletedConfigUpdate {
    component: ConfigComponentKind,
    update_id: String,
    component_sequence: u64,
    revision: ConfigSnapshotRevision,
    fingerprint: ConfigSnapshotFingerprint,
    outcome: ConfigApplyOutcome,
    admission: Option<SandboxConfigurationAdmission>,
}

/// Outcome of finishing an in-flight configuration update.
#[derive(Debug, PartialEq, Eq)]
enum Finalized {
    /// The session or update was replaced before the result was finished.
    Obsolete,
    Done {
        rebuild: Option<ConfigComponentKind>,
    },
}

impl Finalized {
    fn rebuild(&self) -> Option<ConfigComponentKind> {
        match self {
            Self::Obsolete => None,
            Self::Done { rebuild } => *rebuild,
        }
    }
}

/// An update to queue on the session stream once the registry lock is
/// released.
struct Outgoing {
    slots: Arc<ConfigSlots>,
    component: ConfigComponentKind,
    message: GatewayMessage,
}

impl Outgoing {
    /// Returns true when an unsent update was replaced.
    fn send(self) -> bool {
        self.slots.replace(self.component, self.message)
    }
}

impl ConfigSessionState {
    pub fn new(slots: Arc<ConfigSlots>) -> Self {
        Self {
            slots,
            sandbox_config: ComponentDeliveryState::default(),
            provider_environment: ComponentDeliveryState::default(),
        }
    }

    fn component_mut(&mut self, component: ConfigComponentKind) -> &mut ComponentDeliveryState {
        match component {
            ConfigComponentKind::SandboxConfig => &mut self.sandbox_config,
            ConfigComponentKind::ProviderEnvironment => &mut self.provider_environment,
        }
    }

    fn deliver(
        &mut self,
        message: SupervisorConfigMessage,
    ) -> Result<Outgoing, DeliveryDisposition> {
        let component = message.component();
        let slots = Arc::clone(&self.slots);
        let delivery_state = self.component_mut(component);
        if delivery_state.in_flight.is_none()
            && delivery_state.last_acknowledged_fingerprint.as_ref()
                == Some(&ComponentSnapshot::from(&message).fingerprint())
        {
            return Err(DeliveryDisposition::SuppressedUnchanged);
        }
        // Hold the component until the supervisor acknowledges the update or
        // bootstrap it already has, bounded so a lost result cannot stall it.
        let held_since = delivery_state
            .in_flight
            .as_ref()
            .map(|update| update.sent_at)
            .or(delivery_state.awaiting_bootstrap_since);
        if held_since.is_some_and(|sent_at| sent_at.elapsed() < CONFIG_ACK_TIMEOUT) {
            delivery_state.pending = Some(message);
            return Err(DeliveryDisposition::Coalesced);
        }
        delivery_state.pending = None;
        delivery_state.in_flight = None;
        delivery_state.awaiting_bootstrap_since = None;

        // Replacing an unsent snapshot leaves a gap in the sequence.
        let (message, in_flight) = build_config_update(delivery_state, message);
        if message.encoded_len() > MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES {
            return Err(DeliveryDisposition::PayloadTooLarge);
        }
        delivery_state.in_flight = Some(in_flight);
        Ok(Outgoing {
            slots,
            component,
            message,
        })
    }

    fn complete(&mut self, result: &ConfigUpdateResult) -> Result<CompletedConfigUpdate, Status> {
        let component_result = result
            .result
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("configuration result is required"))?;
        let component =
            ConfigComponentKind::from_proto(component_result.component).ok_or_else(|| {
                Status::invalid_argument("configuration result component is required")
            })?;
        let in_flight = self
            .component_mut(component)
            .in_flight
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("no matching update is in flight"))?;
        if in_flight.update_id != result.update_id
            || in_flight.component_sequence != result.component_sequence
        {
            return Err(Status::invalid_argument(
                "configuration result does not match the in-flight delivery",
            ));
        }
        let outcome = validate_component_apply_result(component_result, &in_flight.revision)?;
        Ok(CompletedConfigUpdate {
            component,
            update_id: in_flight.update_id.clone(),
            component_sequence: in_flight.component_sequence,
            revision: in_flight.revision.clone(),
            fingerprint: in_flight.fingerprint.clone(),
            outcome,
            admission: in_flight.admission.clone(),
        })
    }

    fn finalize(
        &mut self,
        completed: &CompletedConfigUpdate,
        acknowledge: bool,
    ) -> (Finalized, Option<Outgoing>) {
        let component = completed.component;
        let counterpart = component.counterpart();
        let delivery_state = self.component_mut(component);
        let Some(in_flight) = delivery_state.in_flight.as_ref() else {
            return (Finalized::Obsolete, None);
        };
        if in_flight.update_id != completed.update_id
            || in_flight.component_sequence != completed.component_sequence
            || in_flight.revision != completed.revision
        {
            return (Finalized::Obsolete, None);
        }
        let acknowledged = acknowledge && outcome_acknowledges_revision(completed.outcome);
        if acknowledged {
            delivery_state.last_acknowledged_fingerprint = Some(completed.fingerprint.clone());
        }
        let staged = completed.outcome == ConfigApplyOutcome::AwaitingComponent;
        delivery_state.staged = staged;
        delivery_state.rejected = outcome_rejects_revision(completed.outcome);
        delivery_state.in_flight = None;
        let pending = delivery_state.pending.take();

        let other = self.component_mut(counterpart);
        let rebuild = if staged {
            (!other.staged).then_some(counterpart)
        } else if acknowledged {
            std::mem::take(&mut other.staged).then_some(counterpart)
        } else {
            None
        };
        let finalized = Finalized::Done { rebuild };
        (finalized, self.release_pending(component, pending))
    }

    /// Send a held snapshot, unless the supervisor already acknowledged it.
    fn release_pending(
        &mut self,
        component: ConfigComponentKind,
        pending: Option<SupervisorConfigMessage>,
    ) -> Option<Outgoing> {
        let pending = pending?;
        let slots = Arc::clone(&self.slots);
        let delivery_state = self.component_mut(component);
        if delivery_state.last_acknowledged_fingerprint.as_ref()
            == Some(&ComponentSnapshot::from(&pending).fingerprint())
        {
            return None;
        }
        let (message, next) = build_config_update(delivery_state, pending);
        if message.encoded_len() > MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES {
            return None;
        }
        delivery_state.in_flight = Some(next);
        Some(Outgoing {
            slots,
            component,
            message,
        })
    }

    /// Hold rebuilds until the bootstrap result arrives.
    fn await_bootstrap(&mut self) {
        let now = Instant::now();
        self.sandbox_config.awaiting_bootstrap_since = Some(now);
        self.provider_environment.awaiting_bootstrap_since = Some(now);
    }

    /// The bootstrap result for `component` arrived: release a snapshot held
    /// behind it.
    fn end_bootstrap_hold(&mut self, component: ConfigComponentKind) -> Option<Outgoing> {
        let delivery_state = self.component_mut(component);
        delivery_state.awaiting_bootstrap_since = None;
        if delivery_state.in_flight.is_some() {
            // A snapshot sent after the hold expired owns the pending slot.
            return None;
        }
        let pending = delivery_state.pending.take();
        self.release_pending(component, pending)
    }

    fn rejected_components(&self) -> ConfigComponents {
        ConfigComponents {
            sandbox_config: self.sandbox_config.rejected,
            provider_environment: self.provider_environment.rejected,
        }
    }

    fn acknowledge_bootstrap(
        &mut self,
        result: &ConfigComponentApplyResult,
        fingerprint: &ConfigSnapshotFingerprint,
    ) -> bool {
        let Some(component) = ConfigComponentKind::from_proto(result.component) else {
            return false;
        };
        let outcome = ConfigApplyOutcome::try_from(result.outcome).unwrap_or_default();
        if !outcome_acknowledges_revision(outcome) || result.requested_revision.is_none() {
            return false;
        }
        let delivery_state = self.component_mut(component);
        if delivery_state.in_flight.is_some()
            || delivery_state.last_acknowledged_fingerprint.is_some()
        {
            return false;
        }
        delivery_state.last_acknowledged_fingerprint = Some(fingerprint.clone());
        true
    }
}

impl SupervisorSessionRegistry {
    /// Hand a snapshot to the session it was built for. A replacement session
    /// received its own bootstrap and must not receive an older build.
    pub(crate) fn deliver_config(
        &self,
        sandbox_id: &str,
        session_id: &str,
        message: SupervisorConfigMessage,
    ) -> DeliveryDisposition {
        let delivery = self.with_config_session(sandbox_id, session_id, |config| {
            config.map_or(Err(DeliveryDisposition::UnsupportedSession), |config| {
                config.deliver(message)
            })
        });
        match delivery {
            None => DeliveryDisposition::NoActiveSession,
            Some(Err(disposition)) => disposition,
            Some(Ok(outgoing)) => {
                if outgoing.send() {
                    DeliveryDisposition::Replaced
                } else {
                    DeliveryDisposition::Queued
                }
            }
        }
    }

    fn complete_config_update(
        &self,
        sandbox_id: &str,
        session_id: &str,
        result: &ConfigUpdateResult,
    ) -> Result<CompletedConfigUpdate, Status> {
        self.with_config_session(sandbox_id, session_id, |config| {
            config.map(|config| config.complete(result))
        })
        .flatten()
        .unwrap_or_else(|| {
            Err(Status::failed_precondition(
                "obsolete supervisor session result",
            ))
        })
    }

    /// Finish a validated update after all durable side effects have either
    /// succeeded or failed. Keeping the update in flight until this point
    /// prevents reconciliation from treating a locally reported result as an
    /// acknowledgement before its admission is durable.
    ///
    /// Returns the component to rebuild now, if any. A staged component waits
    /// for its counterpart, so the counterpart is rebuilt rather than the
    /// staged one, which the supervisor would only stage again. Once the
    /// counterpart is acknowledged, the staged component is rebuilt so the
    /// supervisor reports the result it still owes. A counterpart that is
    /// itself staged is not rebuilt, so mismatched halves cannot keep
    /// requesting each other; the next publication or reconciliation pass
    /// repairs them.
    fn finalize_config_update(
        &self,
        sandbox_id: &str,
        session_id: &str,
        completed: &CompletedConfigUpdate,
        acknowledge: bool,
    ) -> Finalized {
        let Some((finalized, outgoing)) = self
            .with_config_session(sandbox_id, session_id, |config| {
                config.map(|config| config.finalize(completed, acknowledge))
            })
            .flatten()
        else {
            return Finalized::Obsolete;
        };
        if let Some(outgoing) = outgoing {
            outgoing.send();
        }
        finalized
    }

    /// Record a successfully persisted bootstrap result in the live session's
    /// delivery state so reconciliation does not immediately redeliver it.
    ///
    /// A streamed update may be delivered while the bootstrap result is being
    /// persisted. In that case, or if this session has already acknowledged a
    /// revision, leave the newer delivery state untouched.
    fn acknowledge_bootstrap_component(
        &self,
        sandbox_id: &str,
        session_id: &str,
        result: &ConfigComponentApplyResult,
        fingerprint: Option<&ConfigSnapshotFingerprint>,
    ) -> bool {
        let Some(component) = ConfigComponentKind::from_proto(result.component) else {
            return false;
        };
        let Some((acknowledged, outgoing)) = self
            .with_config_session(sandbox_id, session_id, |config| {
                config.map(|config| {
                    let acknowledged = fingerprint.is_some_and(|fingerprint| {
                        config.acknowledge_bootstrap(result, fingerprint)
                    });
                    (acknowledged, config.end_bootstrap_hold(component))
                })
            })
            .flatten()
        else {
            return false;
        };
        if let Some(outgoing) = outgoing {
            outgoing.send();
        }
        acknowledged
    }

    /// Components whose last update the session's supervisor failed to
    /// apply.
    pub(crate) fn rejected_config_components(
        &self,
        sandbox_id: &str,
        session_id: &str,
    ) -> ConfigComponents {
        self.with_config_session(sandbox_id, session_id, |config| {
            config.map(|config| config.rejected_components())
        })
        .flatten()
        .unwrap_or_default()
    }

    /// Hold configuration updates for a session until its bootstrap result
    /// arrives.
    pub(crate) fn await_config_bootstrap(&self, sandbox_id: &str, session_id: &str) {
        self.with_config_session(sandbox_id, session_id, |config| {
            if let Some(config) = config {
                config.await_bootstrap();
            }
        });
    }
}

fn build_config_update(
    state: &mut ComponentDeliveryState,
    message: SupervisorConfigMessage,
) -> (GatewayMessage, InFlightConfigUpdate) {
    state.sequence = state.sequence.saturating_add(1);
    state.staged = false;
    let component_sequence = state.sequence;
    let snapshot = ComponentSnapshot::from(&message);
    let revision = snapshot.revision();
    let fingerprint = snapshot.fingerprint();
    let (component, admission) = match message {
        SupervisorConfigMessage::SandboxConfig(snapshot) => {
            let admission = expected_configuration_admission(&snapshot);
            (
                config_update::Component::SandboxConfig(*snapshot),
                Some(admission),
            )
        }
        SupervisorConfigMessage::ProviderEnvironment(snapshot) => (
            config_update::Component::ProviderEnvironment(snapshot),
            None,
        ),
    };
    let update_id = Uuid::new_v4().to_string();
    (
        GatewayMessage {
            payload: Some(gateway_message::Payload::ConfigUpdate(ConfigUpdate {
                update_id: update_id.clone(),
                component_sequence,
                component: Some(component),
            })),
        },
        InFlightConfigUpdate {
            update_id,
            component_sequence,
            revision,
            fingerprint,
            admission,
            sent_at: Instant::now(),
        },
    )
}

// ---------------------------------------------------------------------------
// Results and admission
// ---------------------------------------------------------------------------

fn validate_component_apply_result(
    result: &ConfigComponentApplyResult,
    requested_revision: &ConfigSnapshotRevision,
) -> Result<ConfigApplyOutcome, Status> {
    if result.requested_revision.as_ref() != Some(requested_revision) {
        return Err(Status::invalid_argument(
            "configuration result revision does not match the delivered snapshot",
        ));
    }
    let outcome = ConfigApplyOutcome::try_from(result.outcome).unwrap_or_default();
    let applied_matches_request = result.applied_revision.as_ref() == Some(requested_revision);
    let applied_is_absent = result.applied_revision.is_none();
    let valid = match outcome {
        ConfigApplyOutcome::Applied
        | ConfigApplyOutcome::IgnoredDuplicate
        | ConfigApplyOutcome::Degraded => applied_matches_request,
        ConfigApplyOutcome::RetainedLocalOverride
        | ConfigApplyOutcome::FailedClosed
        | ConfigApplyOutcome::AwaitingComponent => applied_is_absent,
        ConfigApplyOutcome::FailedRetainedLastKnownGood => {
            result.applied_revision.is_some() && !applied_matches_request
        }
        ConfigApplyOutcome::IgnoredStale | ConfigApplyOutcome::Unsupported => true,
        ConfigApplyOutcome::Unspecified => false,
    };
    if !valid {
        return Err(Status::invalid_argument(
            "configuration result outcome does not match its applied revision",
        ));
    }
    Ok(outcome)
}

fn outcome_rejects_revision(outcome: ConfigApplyOutcome) -> bool {
    matches!(
        outcome,
        ConfigApplyOutcome::FailedRetainedLastKnownGood | ConfigApplyOutcome::FailedClosed
    )
}

fn outcome_acknowledges_revision(outcome: ConfigApplyOutcome) -> bool {
    matches!(
        outcome,
        ConfigApplyOutcome::Applied
            | ConfigApplyOutcome::IgnoredDuplicate
            | ConfigApplyOutcome::RetainedLocalOverride
            | ConfigApplyOutcome::Degraded
    )
}

fn expected_configuration_admission(
    snapshot: &SandboxConfigSnapshot,
) -> SandboxConfigurationAdmission {
    use openshell_core::proto::ConfigurationAdmissionState;

    SandboxConfigurationAdmission {
        instance_id: snapshot.configuration_instance_id.clone(),
        state: if snapshot.configuration_admitted {
            ConfigurationAdmissionState::Accepted.into()
        } else {
            ConfigurationAdmissionState::Rejected.into()
        },
        policy_version: snapshot.version,
        policy_hash: snapshot.policy_hash.clone(),
        config_revision: snapshot.config_revision,
        provider_env_revision: snapshot.provider_env_revision,
        error: snapshot.configuration_error.clone(),
    }
}

fn validate_configuration_admission(
    reported: Option<&SandboxConfigurationAdmission>,
    expected: &SandboxConfigurationAdmission,
    outcome: ConfigApplyOutcome,
) -> Result<SandboxConfigurationAdmission, Status> {
    use openshell_core::proto::ConfigurationAdmissionState;

    let reported = reported.ok_or_else(|| {
        Status::invalid_argument("sandbox configuration admission result is required")
    })?;
    if reported.instance_id != expected.instance_id
        || reported.policy_version != expected.policy_version
        || reported.policy_hash != expected.policy_hash
        || reported.config_revision != expected.config_revision
        || reported.provider_env_revision != expected.provider_env_revision
    {
        return Err(Status::invalid_argument(
            "configuration admission does not match the delivered generation",
        ));
    }
    let expected_state = ConfigurationAdmissionState::try_from(expected.state).unwrap_or_default();
    let reported_state = ConfigurationAdmissionState::try_from(reported.state).unwrap_or_default();
    if expected_state == ConfigurationAdmissionState::Rejected {
        if reported_state != ConfigurationAdmissionState::Rejected {
            return Err(Status::invalid_argument(
                "rejected gateway configuration was reported as accepted",
            ));
        }
        return Ok(expected.clone());
    }
    if outcome_acknowledges_revision(outcome)
        && reported_state == ConfigurationAdmissionState::Accepted
    {
        let mut admission = expected.clone();
        admission.error.clear();
        return Ok(admission);
    }
    if reported_state == ConfigurationAdmissionState::Rejected {
        let mut admission = expected.clone();
        admission.state = ConfigurationAdmissionState::Rejected.into();
        admission.error = "effective configuration could not be activated".to_string();
        return Ok(admission);
    }
    Err(Status::invalid_argument(
        "configuration admission is inconsistent with the apply result",
    ))
}

/// What a streamed-apply supervisor must report for the bootstrap it was
/// accepted with.
#[derive(Debug)]
pub struct ExpectedBootstrap {
    components: Vec<ExpectedComponent>,
    admission: Option<SandboxConfigurationAdmission>,
}

#[derive(Debug)]
struct ExpectedComponent {
    component: ConfigComponentKind,
    revision: ConfigSnapshotRevision,
    fingerprint: ConfigSnapshotFingerprint,
}

impl ExpectedBootstrap {
    pub fn new(bootstrap: &ConfigBootstrap) -> Self {
        let snapshots = bootstrap
            .sandbox_config
            .iter()
            .map(ComponentSnapshot::SandboxConfig)
            .chain(
                bootstrap
                    .provider_environment
                    .iter()
                    .map(ComponentSnapshot::ProviderEnvironment),
            );
        Self {
            components: snapshots
                .map(|snapshot| ExpectedComponent {
                    component: snapshot.component(),
                    revision: snapshot.revision(),
                    fingerprint: snapshot.fingerprint(),
                })
                .collect(),
            admission: bootstrap
                .sandbox_config
                .as_ref()
                .map(expected_configuration_admission),
        }
    }

    fn expected(&self, component: i32) -> Option<&ExpectedComponent> {
        let component = ConfigComponentKind::from_proto(component)?;
        self.components
            .iter()
            .find(|expected| expected.component == component)
    }

    /// Check that every delivered component is reported exactly once against
    /// its delivered revision. Returns whether all of them took effect.
    fn validate_results(&self, results: &[ConfigComponentApplyResult]) -> Result<bool, Status> {
        if self.components.len() != 2 || results.len() != self.components.len() {
            return Err(Status::invalid_argument(
                "bootstrap result must contain every delivered component exactly once",
            ));
        }
        let mut seen = Vec::with_capacity(results.len());
        let mut all_succeeded = true;
        for result in results {
            let component = ConfigComponentKind::from_proto(result.component)
                .filter(|component| !seen.contains(component))
                .ok_or_else(|| {
                    Status::invalid_argument(
                        "bootstrap result contains an invalid or duplicate component",
                    )
                })?;
            let expected = self.expected(result.component).ok_or_else(|| {
                Status::invalid_argument("bootstrap result contains an unexpected component")
            })?;
            let outcome = validate_component_apply_result(result, &expected.revision)?;
            seen.push(component);
            all_succeeded &= outcome_acknowledges_revision(outcome);
        }
        Ok(all_succeeded)
    }

    /// Validate a complete bootstrap result and return the admission to
    /// persist for it.
    fn validate(
        &self,
        result: &ConfigBootstrapResult,
    ) -> Result<SandboxConfigurationAdmission, Status> {
        let succeeded = self.validate_results(&result.results)?;
        let expected = self.admission.as_ref().ok_or_else(|| {
            Status::invalid_argument("supervisor bootstrap omitted its expected admission")
        })?;
        let outcome = if succeeded {
            ConfigApplyOutcome::Applied
        } else {
            ConfigApplyOutcome::Unsupported
        };
        validate_configuration_admission(result.admission.as_ref(), expected, outcome)
    }
}

/// Validate a bootstrap result against the bootstrap the session was
/// accepted with, then record it. Nothing is persisted for an invalid
/// result. Returns false when the session must close.
pub async fn handle_bootstrap_result(
    session: &AcceptedSession,
    expected: &ExpectedBootstrap,
    result: &ConfigBootstrapResult,
) -> bool {
    let AcceptedSession {
        state,
        sandbox_id,
        session_id,
        ..
    } = session;
    let admission = match expected.validate(result) {
        Ok(admission) => admission,
        Err(error) => {
            warn!(
                sandbox_id,
                session_id,
                error = %error,
                "supervisor configuration bootstrap result did not match the delivered bootstrap"
            );
            return false;
        }
    };
    if !state
        .supervisor_sessions
        .is_current_session(sandbox_id, session_id)
    {
        return false;
    }
    for component in &result.results {
        let recorded = match record_component_apply_result(state, sandbox_id, component).await {
            Ok(()) => true,
            Err(error) => {
                warn!(
                    sandbox_id,
                    session_id,
                    component = component.component,
                    error = %error,
                    "failed to persist supervisor bootstrap result"
                );
                false
            }
        };
        let fingerprint = expected
            .expected(component.component)
            .filter(|_| recorded)
            .map(|expected| &expected.fingerprint);
        state.supervisor_sessions.acknowledge_bootstrap_component(
            sandbox_id,
            session_id,
            component,
            fingerprint,
        );
    }
    persist_and_ack_admission(session, &admission).await
}

pub async fn handle_config_update_result(session: &AcceptedSession, result: &ConfigUpdateResult) {
    let AcceptedSession {
        state,
        sandbox_id,
        session_id,
        ..
    } = session;
    let registry = &state.supervisor_sessions;
    let completed = match registry.complete_config_update(sandbox_id, session_id, result) {
        Ok(completed) => completed,
        Err(error) => {
            debug!(
                sandbox_id,
                session_id,
                error = %error,
                "ignored unmatched supervisor configuration result"
            );
            return;
        }
    };
    let finalized = if completed.outcome == ConfigApplyOutcome::AwaitingComponent {
        // A transient ordering result is never recorded. The supervisor keeps
        // this half staged until its counterpart arrives.
        debug!(
            sandbox_id,
            session_id, "supervisor configuration is waiting for its matching component"
        );
        registry.finalize_config_update(sandbox_id, session_id, &completed, false)
    } else if let Some(component_result) = result.result.as_ref()
        && let Err(error) = record_component_apply_result(state, sandbox_id, component_result).await
    {
        warn!(
            sandbox_id,
            session_id,
            component = component_result.component,
            error = %error,
            "failed to persist supervisor configuration result"
        );
        registry.finalize_config_update(sandbox_id, session_id, &completed, false)
    } else if let Some(expected_admission) = completed.admission.as_ref() {
        match validate_configuration_admission(
            result.admission.as_ref(),
            expected_admission,
            completed.outcome,
        ) {
            Ok(admission) => {
                let acknowledged = persist_and_ack_admission(session, &admission).await;
                registry.finalize_config_update(sandbox_id, session_id, &completed, acknowledged)
            }
            Err(error) => {
                warn!(sandbox_id, session_id, error = %error, "invalid supervisor configuration admission");
                registry.finalize_config_update(sandbox_id, session_id, &completed, false)
            }
        }
    } else {
        registry.finalize_config_update(sandbox_id, session_id, &completed, true)
    };
    if let Some(component) = finalized.rebuild() {
        super::publish_sandbox_components(state, sandbox_id, ConfigComponents::only(component));
    }
}

async fn persist_and_ack_admission(
    session: &AcceptedSession,
    admission: &SandboxConfigurationAdmission,
) -> bool {
    let AcceptedSession {
        state,
        sandbox_id,
        session_id,
        instance_id,
        tx,
        ..
    } = session;
    if !state
        .supervisor_sessions
        .is_current_session(sandbox_id, session_id)
    {
        return false;
    }
    #[cfg(test)]
    {
        let mut failure_target = FAIL_NEXT_ADMISSION_PERSISTENCE_FOR_SANDBOX.lock().unwrap();
        if failure_target.as_deref() == Some(sandbox_id.as_str()) {
            failure_target.take();
            return false;
        }
    }
    if let Err(error) = state
        .compute
        .supervisor_session_admission(sandbox_id, instance_id, admission)
        .await
    {
        warn!(sandbox_id, session_id, error = %error, "failed to persist supervisor configuration admission");
        return false;
    }
    if tx
        .send(GatewayMessage {
            payload: Some(gateway_message::Payload::ConfigurationAdmission(
                admission.clone(),
            )),
        })
        .await
        .is_err()
    {
        return false;
    }
    state.telemetry.sandbox_session_connected(sandbox_id);
    true
}

async fn record_component_apply_result(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    result: &ConfigComponentApplyResult,
) -> Result<(), Status> {
    let component = ConfigComponent::try_from(result.component).unwrap_or_default();
    let outcome = ConfigApplyOutcome::try_from(result.outcome).unwrap_or_default();
    counter!(
        "openshell_supervisor_config_apply_results_total",
        "component" => component.as_str_name(),
        "outcome" => outcome.as_str_name(),
    )
    .increment(1);
    if component != ConfigComponent::SandboxConfig {
        return Ok(());
    }
    let Some(config_snapshot_revision::Component::SandboxConfig(revision)) = result
        .requested_revision
        .as_ref()
        .and_then(|revision| revision.component.as_ref())
    else {
        return Err(Status::invalid_argument(
            "sandbox configuration result is missing its requested revision",
        ));
    };
    if PolicySource::try_from(revision.policy_source).unwrap_or_default() != PolicySource::Sandbox
        || revision.policy_version == 0
    {
        return Ok(());
    }
    // Degraded enforces the policy with only built-in middleware.
    let loaded = matches!(
        outcome,
        ConfigApplyOutcome::Applied
            | ConfigApplyOutcome::IgnoredDuplicate
            | ConfigApplyOutcome::Degraded
    );
    let failed = matches!(
        outcome,
        ConfigApplyOutcome::FailedRetainedLastKnownGood | ConfigApplyOutcome::FailedClosed
    );
    if !loaded && !failed {
        return Ok(());
    }
    crate::grpc::policy::record_policy_apply_result(
        state,
        sandbox_id,
        revision.policy_version,
        loaded,
        result
            .failure
            .as_ref()
            .map(|failure| failure.message.as_str()),
        "stream",
    )
    .await
}

// ---------------------------------------------------------------------------
// Bootstrap and startup preparation
// ---------------------------------------------------------------------------

async fn build_config_bootstrap(
    state: &Arc<ServerState>,
    sandbox: &Sandbox,
) -> Result<ConfigBootstrap, Status> {
    tokio::time::timeout(
        CONFIG_BOOTSTRAP_BUILD_TIMEOUT,
        build_consistent_config_bootstrap(state, sandbox),
    )
    .await
    .map_err(|_| Status::deadline_exceeded("supervisor configuration bootstrap timed out"))?
}

async fn build_consistent_config_bootstrap(
    state: &Arc<ServerState>,
    sandbox: &Sandbox,
) -> Result<ConfigBootstrap, Status> {
    const MAX_BUILD_ATTEMPTS: usize = 3;
    for _ in 0..MAX_BUILD_ATTEMPTS {
        // Both components build from one captured input load, so a source
        // written mid-attempt cannot reach only one of them. The identity
        // check below still rejects any pair that disagrees.
        let inputs = load_sandbox_config_inputs(state, sandbox.clone()).await?;
        let (sandbox_config, provider_environment) = tokio::join!(
            build_sandbox_config_snapshot_from_inputs(state, &inputs),
            build_provider_environment_snapshot_from_inputs(state, &inputs, true),
        );
        let bootstrap = ConfigBootstrap {
            sandbox_config: Some(sandbox_config?),
            provider_environment: Some(provider_environment?),
        };
        if bootstrap_identities_match(&bootstrap) {
            return Ok(bootstrap);
        }
        counter!("openshell_supervisor_config_bootstrap_revision_mismatches_total").increment(1);
    }
    Err(Status::aborted(
        "configuration changed while building supervisor bootstrap",
    ))
}

/// Both components must describe the same attachments, provider revision,
/// and effective policy. Without a gateway policy the sandbox configuration
/// carries no hash, and the provider environment binds no policy endpoints.
fn bootstrap_identities_match(bootstrap: &ConfigBootstrap) -> bool {
    bootstrap
        .sandbox_config
        .as_ref()
        .zip(bootstrap.provider_environment.as_ref())
        .is_some_and(|(sandbox, provider)| {
            sandbox.provider_env_revision == provider.provider_env_revision
                && sandbox.provider_attachment_epoch == provider.provider_attachment_epoch
                && (sandbox.policy.is_none() || sandbox.policy_hash == provider.policy_hash)
        })
}

/// Image policy discovery reported by a supervisor's first connection.
pub enum ImagePolicyAdmission {
    Missing,
    Invalid,
    Policy(Box<SandboxPolicy>),
}

pub fn image_policy_admission(hello: &SupervisorHello) -> Result<ImagePolicyAdmission, Status> {
    use openshell_core::proto::image_policy_discovery::Result as DiscoveryResult;

    let Some(discovery) = hello.image_policy_discovery.as_ref() else {
        return Ok(ImagePolicyAdmission::Missing);
    };
    match discovery.result.as_ref() {
        Some(DiscoveryResult::Missing(())) => Ok(ImagePolicyAdmission::Missing),
        Some(DiscoveryResult::Invalid(())) => Ok(ImagePolicyAdmission::Invalid),
        Some(DiscoveryResult::Policy(policy)) => {
            Ok(ImagePolicyAdmission::Policy(Box::new(policy.clone())))
        }
        None => Err(Status::invalid_argument(
            "image policy discovery result is required",
        )),
    }
}

/// Build the authoritative bootstrap for a streamed-apply session.
///
/// An invalid image policy cannot become the startup baseline, so the build
/// waits for an operator to store a gateway policy, bounded by
/// `STARTUP_POLICY_REPAIR_TIMEOUT`.
pub async fn build_session_bootstrap(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    image_policy_admission: &ImagePolicyAdmission,
) -> Result<ConfigBootstrap, Status> {
    let waits_for_repair = matches!(image_policy_admission, ImagePolicyAdmission::Invalid);
    let mut repair_updates =
        waits_for_repair.then(|| state.sandbox_watch_bus.subscribe(sandbox_id));
    let repair_deadline = tokio::time::Instant::now() + STARTUP_POLICY_REPAIR_TIMEOUT;
    loop {
        let current_sandbox =
            crate::supervisor_session::require_persisted_sandbox(&state.store, sandbox_id).await?;
        match build_config_bootstrap(state, &current_sandbox).await {
            Ok(bootstrap) => {
                let has_gateway_policy = bootstrap
                    .sandbox_config
                    .as_ref()
                    .and_then(|snapshot| snapshot.policy.as_ref())
                    .is_some();
                if !waits_for_repair || has_gateway_policy {
                    counter!(
                        "openshell_supervisor_config_bootstrap_total",
                        "outcome" => "built"
                    )
                    .increment(1);
                    return Ok(bootstrap);
                }
                warn!(
                    sandbox_id = %sandbox_id,
                    "invalid image policy rejected; waiting for a gateway policy repair"
                );
            }
            Err(error) if waits_for_repair => {
                warn!(
                    sandbox_id = %sandbox_id,
                    error_code = ?error.code(),
                    "invalid image policy rejected; waiting for configuration repair"
                );
            }
            Err(error) => {
                counter!(
                    "openshell_supervisor_config_bootstrap_total",
                    "outcome" => "build_failed"
                )
                .increment(1);
                warn!(
                    sandbox_id = %sandbox_id,
                    error_code = ?error.code(),
                    "failed to build supervisor configuration bootstrap"
                );
                return Err(error);
            }
        }

        let updates = repair_updates
            .as_mut()
            .expect("only an invalid image policy waits for repair");
        match tokio::time::timeout_at(repair_deadline, updates.recv()).await {
            Ok(Ok(()) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                return Err(Status::aborted(
                    "sandbox configuration watch closed during startup repair",
                ));
            }
            Err(_) => {
                return Err(Status::deadline_exceeded(
                    "image policy repair window expired",
                ));
            }
        }
    }
}

/// A startup policy offered to a supervisor's first connection for
/// preparation against its workload image.
pub struct StartupCandidate {
    candidate_id: String,
    policy: SandboxPolicy,
    gateway_has_policy: bool,
}

/// Offer the gateway-selected policy, or the image policy when the gateway
/// has none, before the bootstrap is final.
pub async fn send_startup_candidate(
    tx: &mpsc::Sender<GatewayMessage>,
    gateway_snapshot: Option<&SandboxConfigSnapshot>,
    image_policy_admission: ImagePolicyAdmission,
) -> Result<StartupCandidate, Status> {
    let gateway_policy = gateway_snapshot.and_then(|snapshot| snapshot.policy.clone());
    let gateway_has_policy = gateway_policy.is_some();
    let policy = gateway_policy
        .or_else(|| match image_policy_admission {
            ImagePolicyAdmission::Policy(policy) => Some(*policy),
            ImagePolicyAdmission::Missing => Some(openshell_policy::restrictive_default_policy()),
            ImagePolicyAdmission::Invalid => None,
        })
        .ok_or_else(|| Status::failed_precondition("startup policy candidate is missing"))?;
    let (policy_hash, policy_source, policy_version) =
        gateway_snapshot.filter(|_| gateway_has_policy).map_or_else(
            || {
                (
                    openshell_core::policy_identity::deterministic_policy_hash(&policy),
                    PolicySource::Sandbox.into(),
                    0,
                )
            },
            |snapshot| {
                (
                    snapshot.policy_hash.clone(),
                    snapshot.policy_source,
                    snapshot.version,
                )
            },
        );
    let candidate_id = Uuid::new_v4().to_string();
    let candidate = GatewayMessage {
        payload: Some(gateway_message::Payload::StartupConfigCandidate(
            StartupConfigCandidate {
                candidate_id: candidate_id.clone(),
                policy_hash,
                policy_source,
                policy_version,
                policy: Some(policy.clone()),
            },
        )),
    };
    if candidate.encoded_len() > MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES {
        return Err(Status::resource_exhausted(
            "startup configuration candidate exceeds the stream message limit",
        ));
    }
    tx.send(candidate)
        .await
        .map_err(|_| Status::internal("failed to send startup configuration candidate"))?;
    Ok(StartupCandidate {
        candidate_id,
        policy,
        gateway_has_policy,
    })
}

impl StartupCandidate {
    /// Wait for the supervisor's prepared policy, persist it unless it is the
    /// unchanged gateway policy, and build the bootstrap from the result.
    pub async fn finish(
        self,
        state: &Arc<ServerState>,
        principal: Option<Principal>,
        sandbox: &Sandbox,
        inbound: &mut tonic::Streaming<SupervisorMessage>,
    ) -> Result<ConfigBootstrap, Status> {
        use crate::persistence::ObjectId;

        let prepared = tokio::time::timeout(CONFIG_BOOTSTRAP_BUILD_TIMEOUT, inbound.message())
            .await
            .map_err(|_| Status::deadline_exceeded("startup configuration preparation timed out"))??
            .ok_or_else(|| Status::aborted("supervisor disconnected during startup preparation"))?;
        let Some(supervisor_message::Payload::StartupConfigPrepared(prepared)) = prepared.payload
        else {
            return Err(Status::invalid_argument("expected StartupConfigPrepared"));
        };
        if prepared.candidate_id != self.candidate_id {
            return Err(Status::failed_precondition(
                "startup configuration candidate ID does not match",
            ));
        }

        let policy_to_persist = match prepared.result {
            Some(startup_config_prepared::Result::Unchanged(())) => {
                (!self.gateway_has_policy).then_some(self.policy)
            }
            Some(startup_config_prepared::Result::PreparedPolicy(policy)) => Some(policy),
            Some(startup_config_prepared::Result::Failure(failure)) => {
                return Err(Status::failed_precondition(format!(
                    "supervisor could not prepare startup policy: {}: {}",
                    failure.code, failure.message
                )));
            }
            None => {
                return Err(Status::invalid_argument(
                    "startup configuration result is required",
                ));
            }
        };

        if let Some(policy) = policy_to_persist {
            let principal = principal.ok_or_else(|| {
                Status::unauthenticated(
                    "startup policy preparation requires an authenticated supervisor",
                )
            })?;
            crate::grpc::policy::persist_supervisor_startup_policy(
                state, principal, sandbox, policy,
            )
            .await?;
        }

        let sandbox =
            crate::supervisor_session::require_persisted_sandbox(&state.store, sandbox.object_id())
                .await?;
        build_config_bootstrap(state, &sandbox).await
    }
}

/// The result a supervisor reports after applying `bootstrap` in full.
#[cfg(test)]
pub fn applied_bootstrap_result(bootstrap: &ConfigBootstrap) -> ConfigBootstrapResult {
    let sandbox = bootstrap
        .sandbox_config
        .as_ref()
        .expect("sandbox bootstrap component");
    let provider = bootstrap
        .provider_environment
        .as_ref()
        .expect("provider bootstrap component");
    let applied =
        |component: ConfigComponent, revision: ConfigSnapshotRevision| ConfigComponentApplyResult {
            component: component.into(),
            requested_revision: Some(revision.clone()),
            applied_revision: Some(revision),
            outcome: ConfigApplyOutcome::Applied.into(),
            ..Default::default()
        };
    ConfigBootstrapResult {
        results: vec![
            applied(
                ConfigComponent::SandboxConfig,
                ComponentSnapshot::SandboxConfig(sandbox).revision(),
            ),
            applied(
                ConfigComponent::ProviderEnvironment,
                ComponentSnapshot::ProviderEnvironment(provider).revision(),
            ),
        ],
        admission: Some(expected_configuration_admission(sandbox)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_delivery::SessionOutbound;
    use crate::grpc::test_support::StreamFeatures;
    use crate::supervisor_owner::{OWNER_TTL, SupervisorOwnerIndex};
    use crate::supervisor_session::SessionMode;
    use openshell_core::proto::{
        ProviderEnvironmentValue, SandboxSpec, SessionAccepted, StartupConfigPrepared,
    };
    use std::collections::HashMap;
    use tokio::sync::oneshot;

    fn config_message_revision(message: &SupervisorConfigMessage) -> ConfigSnapshotRevision {
        ComponentSnapshot::from(message).revision()
    }

    fn config_message_fingerprint(message: &SupervisorConfigMessage) -> ConfigSnapshotFingerprint {
        ComponentSnapshot::from(message).fingerprint()
    }

    fn make_shutdown() -> oneshot::Sender<()> {
        oneshot::channel::<()>().0
    }

    fn sandbox_record(id: &str, name: &str) -> Sandbox {
        Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: id.to_string(),
                name: name.to_string(),
                workspace: "default".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    async fn state_with_sandbox(sandbox_id: &str) -> Arc<ServerState> {
        let state = crate::grpc::test_support::test_server_state().await;
        state
            .store
            .put_message(&sandbox_record(sandbox_id, sandbox_id))
            .await
            .unwrap();
        state
    }

    async fn first_gateway_message(
        harness: &mut crate::grpc::test_support::SupervisorStreamHarness,
    ) -> GatewayMessage {
        tokio::time::timeout(Duration::from_secs(5), harness.inbound.message())
            .await
            .expect("gateway response before timeout")
            .expect("stream open")
            .expect("gateway message")
    }

    fn accepted_session(
        state: &Arc<ServerState>,
        sandbox_id: &str,
        tx: mpsc::Sender<GatewayMessage>,
    ) -> AcceptedSession {
        AcceptedSession {
            state: Arc::clone(state),
            sandbox_id: sandbox_id.into(),
            session_id: "session-1".into(),
            instance_id: "instance-1".into(),
            tx,
            supports_session_redirect: false,
            expected_bootstrap: None,
        }
    }

    #[test]
    fn bootstrap_requires_matching_component_identities() {
        let matching = || ConfigBootstrap {
            sandbox_config: Some(SandboxConfigSnapshot {
                policy: Some(SandboxPolicy::default()),
                policy_hash: "policy-1".into(),
                provider_env_revision: 7,
                provider_attachment_epoch: "epoch-1".into(),
                ..Default::default()
            }),
            provider_environment: Some(ProviderEnvironmentSnapshot {
                policy_hash: "policy-1".into(),
                provider_env_revision: 7,
                provider_attachment_epoch: "epoch-1".into(),
                ..Default::default()
            }),
        };
        // A legitimately empty provider environment is a valid component.
        assert!(bootstrap_identities_match(&matching()));

        let mut revision = matching();
        revision
            .provider_environment
            .as_mut()
            .unwrap()
            .provider_env_revision = 8;
        assert!(!bootstrap_identities_match(&revision));

        // Equal provider revisions do not cover the complete policy.
        let mut policy = matching();
        policy.provider_environment.as_mut().unwrap().policy_hash = "policy-2".into();
        assert!(!bootstrap_identities_match(&policy));

        let mut epoch = matching();
        epoch
            .provider_environment
            .as_mut()
            .unwrap()
            .provider_attachment_epoch = "epoch-2".into();
        assert!(!bootstrap_identities_match(&epoch));

        // Without a gateway policy the configuration carries no hash to match.
        let mut no_policy = matching();
        let config = no_policy.sandbox_config.as_mut().unwrap();
        config.policy = None;
        config.policy_hash.clear();
        assert!(bootstrap_identities_match(&no_policy));
    }

    #[test]
    fn configuration_stream_messages_round_trip() {
        let bootstrap = GatewayMessage {
            payload: Some(gateway_message::Payload::SessionAccepted(SessionAccepted {
                session_id: "session-1".into(),
                heartbeat_interval: openshell_core::time::duration_from_std(Duration::from_secs(
                    15,
                ))
                .ok(),
                bootstrap: Some(ConfigBootstrap {
                    sandbox_config: Some(SandboxConfigSnapshot::default()),
                    provider_environment: Some(ProviderEnvironmentSnapshot::default()),
                }),
                config_apply_enabled: true,
            })),
        };
        let updates = [
            config_update::Component::SandboxConfig(SandboxConfigSnapshot::default()),
            config_update::Component::ProviderEnvironment(ProviderEnvironmentSnapshot::default()),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, component)| GatewayMessage {
            payload: Some(gateway_message::Payload::ConfigUpdate(ConfigUpdate {
                update_id: format!("update-{index}"),
                component_sequence: u64::try_from(index + 1).unwrap(),
                component: Some(component),
            })),
        });

        for original in std::iter::once(bootstrap).chain(updates) {
            let decoded = GatewayMessage::decode(original.encode_to_vec().as_slice()).unwrap();
            assert_eq!(decoded, original);
        }

        let result = SupervisorMessage {
            payload: Some(supervisor_message::Payload::ConfigUpdateResult(
                ConfigUpdateResult {
                    update_id: "update-1".into(),
                    component_sequence: 4,
                    admission: None,
                    result: Some(ConfigComponentApplyResult {
                        component: ConfigComponent::SandboxConfig.into(),
                        requested_revision: Some(ConfigSnapshotRevision {
                            component: Some(config_snapshot_revision::Component::SandboxConfig(
                                SandboxConfigRevision {
                                    config_revision: 7,
                                    policy_version: 3,
                                    ..Default::default()
                                },
                            )),
                        }),
                        applied_revision: Some(ConfigSnapshotRevision {
                            component: Some(config_snapshot_revision::Component::SandboxConfig(
                                SandboxConfigRevision {
                                    config_revision: 7,
                                    policy_version: 3,
                                    ..Default::default()
                                },
                            )),
                        }),
                        outcome: ConfigApplyOutcome::Applied.into(),
                        failure: None,
                    }),
                },
            )),
        };
        let decoded = SupervisorMessage::decode(result.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded, result);
    }

    fn register_apply_session_with_outbound(
        registry: &SupervisorSessionRegistry,
        sandbox_id: &str,
        session_id: &str,
    ) -> (mpsc::Sender<GatewayMessage>, SessionOutbound) {
        let (tx, rx) = mpsc::channel(4);
        let slots = Arc::new(ConfigSlots::default());
        registry.register_with_mode(
            sandbox_id.into(),
            session_id.into(),
            tx.clone(),
            make_shutdown(),
            SessionMode::Push(Arc::clone(&slots)),
        );
        (tx, SessionOutbound::new(rx, slots))
    }

    fn sent_update(message: GatewayMessage) -> ConfigUpdate {
        match message.payload {
            Some(gateway_message::Payload::ConfigUpdate(update)) => update,
            other => panic!("expected config update, got {other:?}"),
        }
    }

    fn sandbox_config(config_revision: u64) -> SupervisorConfigMessage {
        SupervisorConfigMessage::SandboxConfig(Box::new(SandboxConfigSnapshot {
            config_revision,
            ..Default::default()
        }))
    }

    #[test]
    fn config_delivery_reports_missing_session() {
        assert_eq!(
            SupervisorSessionRegistry::new().deliver_config(
                "missing",
                "session",
                SupervisorConfigMessage::SandboxConfig(Box::default())
            ),
            DeliveryDisposition::NoActiveSession
        );
    }

    #[tokio::test]
    async fn config_delivery_holds_newer_snapshots_until_acknowledged() {
        use tokio_stream::StreamExt as _;

        let registry = SupervisorSessionRegistry::new();
        let (_tx, mut outbound) =
            register_apply_session_with_outbound(&registry, "sb-1", "session-1");

        assert_eq!(
            registry.deliver_config("sb-1", "session-1", sandbox_config(1)),
            DeliveryDisposition::Queued
        );
        for config_revision in [2, 3] {
            assert_eq!(
                registry.deliver_config("sb-1", "session-1", sandbox_config(config_revision)),
                DeliveryDisposition::Coalesced
            );
        }
        assert_eq!(
            registry.deliver_config(
                "sb-1",
                "session-1",
                SupervisorConfigMessage::ProviderEnvironment(ProviderEnvironmentSnapshot::default())
            ),
            DeliveryDisposition::Queued,
            "components are acknowledged independently"
        );

        let first = sent_update(outbound.next().await.unwrap().unwrap());
        assert!(matches!(
            first.component,
            Some(config_update::Component::SandboxConfig(ref snapshot)) if snapshot.config_revision == 1
        ));
        assert!(matches!(
            sent_update(outbound.next().await.unwrap().unwrap()).component,
            Some(config_update::Component::ProviderEnvironment(_))
        ));

        let revision = config_message_revision(&sandbox_config(1));
        let completed = registry
            .complete_config_update(
                "sb-1",
                "session-1",
                &ConfigUpdateResult {
                    update_id: first.update_id,
                    component_sequence: first.component_sequence,
                    result: Some(ConfigComponentApplyResult {
                        component: ConfigComponent::SandboxConfig.into(),
                        requested_revision: Some(revision.clone()),
                        applied_revision: Some(revision),
                        outcome: ConfigApplyOutcome::Applied.into(),
                        ..Default::default()
                    }),
                    admission: None,
                },
            )
            .unwrap();
        assert_eq!(
            registry.finalize_config_update("sb-1", "session-1", &completed, true),
            Finalized::Done { rebuild: None }
        );

        // The acknowledgement releases only the newest held snapshot.
        let next = sent_update(outbound.next().await.unwrap().unwrap());
        assert_eq!(next.component_sequence, 2);
        assert!(matches!(
            next.component,
            Some(config_update::Component::SandboxConfig(snapshot)) if snapshot.config_revision == 3
        ));
    }

    #[tokio::test]
    async fn config_delivery_never_crosses_into_a_replacement_session() {
        use tokio_stream::StreamExt as _;

        let registry = SupervisorSessionRegistry::new();
        let (_old_tx, _old_outbound) =
            register_apply_session_with_outbound(&registry, "sb-1", "old-session");
        let (_new_tx, mut new_outbound) =
            register_apply_session_with_outbound(&registry, "sb-1", "new-session");

        assert_eq!(
            registry.deliver_config(
                "sb-1",
                "old-session",
                SupervisorConfigMessage::SandboxConfig(Box::default())
            ),
            DeliveryDisposition::NoActiveSession
        );
        assert_eq!(
            registry.deliver_config(
                "sb-1",
                "new-session",
                SupervisorConfigMessage::SandboxConfig(Box::default())
            ),
            DeliveryDisposition::Queued
        );
        let update = sent_update(new_outbound.next().await.unwrap().unwrap());
        assert_eq!(update.component_sequence, 1);
    }

    #[test]
    fn config_delivery_skips_polling_sessions() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, _rx) = mpsc::channel(1);
        registry.register("sb-1".into(), "session-1".into(), tx, make_shutdown());
        assert_eq!(
            registry.deliver_config(
                "sb-1",
                "session-1",
                SupervisorConfigMessage::SandboxConfig(Box::default())
            ),
            DeliveryDisposition::UnsupportedSession
        );
    }

    #[tokio::test]
    async fn config_delivery_rejects_oversized_messages() {
        use tokio_stream::StreamExt as _;

        let registry = SupervisorSessionRegistry::new();
        let (tx, mut outbound) =
            register_apply_session_with_outbound(&registry, "sb-1", "session-1");

        let snapshot = ProviderEnvironmentSnapshot {
            values: vec![ProviderEnvironmentValue {
                name: "TOKEN".into(),
                value: "x".repeat(MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            registry.deliver_config(
                "sb-1",
                "session-1",
                SupervisorConfigMessage::ProviderEnvironment(snapshot)
            ),
            DeliveryDisposition::PayloadTooLarge
        );
        drop(tx);
        registry.remove_if_current("sb-1", "session-1");
        assert!(outbound.next().await.is_none());
    }
    /// Register a streamed-apply session and return its configuration slots.
    fn register_apply_session(
        registry: &SupervisorSessionRegistry,
        sandbox_id: &str,
        session_id: &str,
    ) -> Arc<ConfigSlots> {
        let (tx, _rx) = mpsc::channel(1);
        let slots = Arc::new(ConfigSlots::default());
        registry.register_with_mode(
            sandbox_id.into(),
            session_id.into(),
            tx,
            make_shutdown(),
            SessionMode::Push(Arc::clone(&slots)),
        );
        slots
    }

    async fn push_state() -> Arc<ServerState> {
        let mut state = crate::grpc::test_support::test_server_state().await;
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .config_delivery_mode = openshell_core::config::ConfigDeliveryMode::Push;
        state
    }

    async fn push_state_with_sandbox(sandbox_id: &str) -> Arc<ServerState> {
        let state = push_state().await;
        state
            .store
            .put_message(&sandbox_record(sandbox_id, sandbox_id))
            .await
            .unwrap();
        state
    }

    fn applied_bootstrap_result(bootstrap: &ConfigBootstrap) -> ConfigBootstrapResult {
        let sandbox = bootstrap
            .sandbox_config
            .as_ref()
            .expect("sandbox bootstrap component");
        let provider = bootstrap
            .provider_environment
            .as_ref()
            .expect("provider bootstrap component");
        let sandbox_revision = config_message_revision(&SupervisorConfigMessage::SandboxConfig(
            Box::new(sandbox.clone()),
        ));
        let provider_revision = config_message_revision(
            &SupervisorConfigMessage::ProviderEnvironment(provider.clone()),
        );
        ConfigBootstrapResult {
            results: vec![
                ConfigComponentApplyResult {
                    component: ConfigComponent::SandboxConfig.into(),
                    requested_revision: Some(sandbox_revision.clone()),
                    applied_revision: Some(sandbox_revision),
                    outcome: ConfigApplyOutcome::Applied.into(),
                    ..Default::default()
                },
                ConfigComponentApplyResult {
                    component: ConfigComponent::ProviderEnvironment.into(),
                    requested_revision: Some(provider_revision.clone()),
                    applied_revision: Some(provider_revision),
                    outcome: ConfigApplyOutcome::Applied.into(),
                    ..Default::default()
                },
            ],
            admission: Some(expected_configuration_admission(sandbox)),
        }
    }

    #[test]
    fn rebuild_racing_the_bootstrap_waits_and_is_dropped_when_unchanged() {
        let registry = SupervisorSessionRegistry::new();
        let slots = register_apply_session(&registry, "sb-1", "session-1");
        registry.await_config_bootstrap("sb-1", "session-1");
        let snapshot = |revision| {
            SupervisorConfigMessage::ProviderEnvironment(ProviderEnvironmentSnapshot {
                provider_env_revision: revision,
                ..Default::default()
            })
        };
        let bootstrap_result = |revision| {
            let revision = ConfigSnapshotRevision {
                component: Some(config_snapshot_revision::Component::ProviderEnvironment(
                    revision,
                )),
            };
            ConfigComponentApplyResult {
                component: ConfigComponent::ProviderEnvironment.into(),
                requested_revision: Some(revision.clone()),
                applied_revision: Some(revision),
                outcome: ConfigApplyOutcome::Applied.into(),
                ..Default::default()
            }
        };
        let fingerprint = |revision| ConfigSnapshotFingerprint::ProviderEnvironment {
            provider_env_revision: revision,
            provider_attachment_epoch: String::new(),
            policy_hash: String::new(),
        };

        // The same snapshot the bootstrap carried is held, then dropped.
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", snapshot(7)),
            DeliveryDisposition::Coalesced
        );
        assert!(registry.acknowledge_bootstrap_component(
            "sb-1",
            "session-1",
            &bootstrap_result(7),
            Some(&fingerprint(7)),
        ));
        assert!(slots.take_for_test().is_none());
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", snapshot(7)),
            DeliveryDisposition::SuppressedUnchanged
        );

        // A newer snapshot held behind the bootstrap is sent once it lands.
        let slots = register_apply_session(&registry, "sb-1", "session-2");
        registry.await_config_bootstrap("sb-1", "session-2");
        assert_eq!(
            registry.deliver_config("sb-1", "session-2", snapshot(8)),
            DeliveryDisposition::Coalesced
        );
        registry.acknowledge_bootstrap_component(
            "sb-1",
            "session-2",
            &bootstrap_result(7),
            Some(&fingerprint(7)),
        );
        assert!(slots.take_for_test().is_some(), "newer snapshot is sent");
    }

    #[test]
    fn bootstrap_acknowledgement_does_not_replace_newer_delivery_state() {
        let registry = SupervisorSessionRegistry::new();
        let slots = register_apply_session(&registry, "sb-1", "session-1");
        let bootstrap_revision = ConfigSnapshotRevision {
            component: Some(config_snapshot_revision::Component::ProviderEnvironment(7)),
        };
        let bootstrap_fingerprint = ConfigSnapshotFingerprint::ProviderEnvironment {
            provider_env_revision: 7,
            provider_attachment_epoch: String::new(),
            policy_hash: String::new(),
        };

        assert_eq!(
            registry.deliver_config(
                "sb-1",
                "session-1",
                SupervisorConfigMessage::ProviderEnvironment(ProviderEnvironmentSnapshot {
                    provider_env_revision: 8,
                    ..Default::default()
                })
            ),
            DeliveryDisposition::Queued
        );
        assert!(!registry.acknowledge_bootstrap_component(
            "sb-1",
            "session-1",
            &ConfigComponentApplyResult {
                component: ConfigComponent::ProviderEnvironment.into(),
                requested_revision: Some(bootstrap_revision.clone()),
                applied_revision: Some(bootstrap_revision.clone()),
                outcome: ConfigApplyOutcome::Applied.into(),
                ..Default::default()
            },
            Some(&bootstrap_fingerprint),
        ));

        let message = slots.take_for_test().ok_or(()).expect("newer update");
        let Some(gateway_message::Payload::ConfigUpdate(update)) = message.payload else {
            panic!("expected config update");
        };
        assert_eq!(update.component_sequence, 1);
        let in_flight_revision = registry
            .with_config_session("sb-1", "session-1", |config| {
                config
                    .unwrap()
                    .provider_environment
                    .in_flight
                    .as_ref()
                    .unwrap()
                    .revision
                    .clone()
            })
            .unwrap();
        assert_eq!(
            in_flight_revision.component,
            Some(config_snapshot_revision::Component::ProviderEnvironment(8))
        );

        let (replacement_tx, _replacement_rx) = mpsc::channel(1);
        let (replacement_shutdown_tx, _replacement_shutdown_rx) = oneshot::channel();
        registry.register(
            "sb-1".into(),
            "session-2".into(),
            replacement_tx,
            replacement_shutdown_tx,
        );
        assert!(!registry.acknowledge_bootstrap_component(
            "sb-1",
            "session-1",
            &ConfigComponentApplyResult {
                component: ConfigComponent::ProviderEnvironment.into(),
                requested_revision: Some(bootstrap_revision.clone()),
                applied_revision: Some(bootstrap_revision),
                outcome: ConfigApplyOutcome::Applied.into(),
                ..Default::default()
            },
            Some(&bootstrap_fingerprint),
        ));
    }

    #[test]
    fn bootstrap_acknowledgement_suppresses_unchanged_reconciliation() {
        let registry = SupervisorSessionRegistry::new();
        let slots = register_apply_session(&registry, "sb-1", "session-1");
        let snapshot = SandboxConfigSnapshot {
            config_revision: 7,
            version: 11,
            ..Default::default()
        };
        let revision = config_message_revision(&SupervisorConfigMessage::SandboxConfig(Box::new(
            snapshot.clone(),
        )));
        let fingerprint = config_message_fingerprint(&SupervisorConfigMessage::SandboxConfig(
            Box::new(snapshot.clone()),
        ));

        assert!(!registry.acknowledge_bootstrap_component(
            "sb-1",
            "session-1",
            &ConfigComponentApplyResult {
                component: ConfigComponent::SandboxConfig.into(),
                requested_revision: Some(revision.clone()),
                applied_revision: None,
                outcome: ConfigApplyOutcome::FailedClosed.into(),
                ..Default::default()
            },
            Some(&fingerprint),
        ));
        assert!(registry.acknowledge_bootstrap_component(
            "sb-1",
            "session-1",
            &ConfigComponentApplyResult {
                component: ConfigComponent::SandboxConfig.into(),
                requested_revision: Some(revision.clone()),
                applied_revision: Some(revision),
                outcome: ConfigApplyOutcome::Applied.into(),
                ..Default::default()
            },
            Some(&fingerprint),
        ));
        assert_eq!(
            registry.deliver_config(
                "sb-1",
                "session-1",
                SupervisorConfigMessage::SandboxConfig(Box::new(snapshot))
            ),
            DeliveryDisposition::SuppressedUnchanged
        );
        assert!(slots.take_for_test().ok_or(()).is_err());
    }

    #[test]
    fn bootstrap_requires_every_delivered_component_to_succeed() {
        let sandbox_revision = ConfigSnapshotRevision {
            component: Some(config_snapshot_revision::Component::SandboxConfig(
                SandboxConfigRevision {
                    config_revision: 7,
                    ..Default::default()
                },
            )),
        };
        let provider_revision = ConfigSnapshotRevision {
            component: Some(config_snapshot_revision::Component::ProviderEnvironment(9)),
        };
        let expected = ExpectedBootstrap::new(&ConfigBootstrap {
            sandbox_config: Some(SandboxConfigSnapshot {
                config_revision: 7,
                ..Default::default()
            }),
            provider_environment: Some(ProviderEnvironmentSnapshot {
                provider_env_revision: 9,
                ..Default::default()
            }),
        });
        let result =
            |component: ConfigComponent,
             revision: ConfigSnapshotRevision,
             outcome: ConfigApplyOutcome| ConfigComponentApplyResult {
                component: component.into(),
                requested_revision: Some(revision.clone()),
                applied_revision: Some(revision),
                outcome: outcome.into(),
                ..Default::default()
            };
        let mut results = vec![
            result(
                ConfigComponent::SandboxConfig,
                sandbox_revision,
                ConfigApplyOutcome::Applied,
            ),
            result(
                ConfigComponent::ProviderEnvironment,
                provider_revision,
                ConfigApplyOutcome::Degraded,
            ),
        ];
        assert!(expected.validate_results(&results).unwrap());

        results[1].outcome = ConfigApplyOutcome::FailedClosed.into();
        results[1].applied_revision = None;
        assert!(!expected.validate_results(&results).unwrap());
        assert!(expected.validate_results(&results[..1]).is_err());
        results[1].requested_revision = Some(ConfigSnapshotRevision::default());
        assert!(expected.validate_results(&results).is_err());
    }

    #[tokio::test]
    async fn sandbox_config_result_records_the_policy_load_failure() {
        use crate::policy_store::PolicyStoreExt as _;

        let state = push_state_with_sandbox("sb-policy-result").await;
        state
            .store
            .put_policy_revision(
                "policy-3",
                "sb-policy-result",
                "default",
                3,
                &SandboxPolicy::default().encode_to_vec(),
                "hash-3",
            )
            .await
            .unwrap();
        let revision = |config_revision| ConfigSnapshotRevision {
            component: Some(config_snapshot_revision::Component::SandboxConfig(
                SandboxConfigRevision {
                    config_revision,
                    policy_version: 3,
                    policy_source: PolicySource::Sandbox.into(),
                    ..Default::default()
                },
            )),
        };
        record_component_apply_result(
            &state,
            "sb-policy-result",
            &ConfigComponentApplyResult {
                component: ConfigComponent::SandboxConfig.into(),
                requested_revision: Some(revision(7)),
                applied_revision: Some(revision(6)),
                outcome: ConfigApplyOutcome::FailedRetainedLastKnownGood.into(),
                failure: Some(openshell_core::proto::ConfigApplyFailure {
                    message: "x".repeat(2_000),
                    ..Default::default()
                }),
            },
        )
        .await
        .unwrap();

        let policy = state
            .store
            .get_policy_by_version("sb-policy-result", 3)
            .await
            .unwrap()
            .expect("policy revision");
        assert_eq!(policy.status, "failed");
        assert_eq!(policy.load_error.map(|error| error.len()), Some(1_024));
    }

    #[test]
    fn configuration_admission_preserves_gateway_rejection_and_accepts_repair() {
        use openshell_core::proto::ConfigurationAdmissionState;

        let mut expected = SandboxConfigurationAdmission {
            instance_id: "configuration-1".into(),
            state: ConfigurationAdmissionState::Rejected.into(),
            policy_version: 3,
            policy_hash: "policy-hash".into(),
            config_revision: 7,
            provider_env_revision: 5,
            error: "invalid image policy".into(),
        };
        let rejected = validate_configuration_admission(
            Some(&expected),
            &expected,
            ConfigApplyOutcome::Applied,
        )
        .unwrap();
        assert_eq!(rejected, expected);

        expected.state = ConfigurationAdmissionState::Accepted.into();
        expected.error.clear();
        let accepted = validate_configuration_admission(
            Some(&expected),
            &expected,
            ConfigApplyOutcome::Applied,
        )
        .unwrap();
        assert_eq!(accepted, expected);
    }

    #[tokio::test]
    async fn failed_admission_persistence_does_not_suppress_unchanged_repair() {
        let sandbox_id = "sb-admission-persistence-retry";
        let state = push_state_with_sandbox(sandbox_id).await;
        let (tx, _rx) = mpsc::channel(4);
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        let slots = Arc::new(ConfigSlots::default());
        state.supervisor_sessions.register_with_mode(
            sandbox_id.into(),
            "session-1".into(),
            tx.clone(),
            shutdown_tx,
            SessionMode::Push(Arc::clone(&slots)),
        );
        let snapshot = SandboxConfigSnapshot {
            configuration_instance_id: "configuration-1".into(),
            configuration_admitted: true,
            config_revision: 7,
            version: 3,
            policy_hash: "policy-hash".into(),
            provider_env_revision: 5,
            ..Default::default()
        };
        let message = SupervisorConfigMessage::SandboxConfig(Box::new(snapshot.clone()));
        assert_eq!(
            state
                .supervisor_sessions
                .deliver_config(sandbox_id, "session-1", message.clone()),
            DeliveryDisposition::Queued
        );
        let Some(gateway_message::Payload::ConfigUpdate(update)) =
            slots.take_for_test().expect("initial update").payload
        else {
            panic!("expected initial config update");
        };
        let revision = config_message_revision(&message);
        *FAIL_NEXT_ADMISSION_PERSISTENCE_FOR_SANDBOX.lock().unwrap() = Some(sandbox_id.into());

        handle_config_update_result(
            &accepted_session(&state, sandbox_id, tx.clone()),
            &ConfigUpdateResult {
                update_id: update.update_id,
                component_sequence: update.component_sequence,
                result: Some(ConfigComponentApplyResult {
                    component: ConfigComponent::SandboxConfig.into(),
                    requested_revision: Some(revision.clone()),
                    applied_revision: Some(revision),
                    outcome: ConfigApplyOutcome::Applied.into(),
                    ..Default::default()
                }),
                admission: Some(expected_configuration_admission(&snapshot)),
            },
        )
        .await;

        assert_eq!(
            state
                .supervisor_sessions
                .deliver_config(sandbox_id, "session-1", message),
            DeliveryDisposition::Queued,
            "a non-durable admission must leave the revision eligible for repair"
        );
        assert!(matches!(
            slots.take_for_test().expect("repair update").payload,
            Some(gateway_message::Payload::ConfigUpdate(_))
        ));
    }

    #[tokio::test]
    async fn awaiting_result_rebuilds_only_the_counterpart_without_persistence() {
        use openshell_core::proto::ConfigurationAdmissionState;

        let sandbox_id = "sb-generation-pending-retry";
        let state = push_state_with_sandbox(sandbox_id).await;
        let mut stored_sandbox = state
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .unwrap()
            .expect("sandbox is persisted");
        stored_sandbox.spec = Some(SandboxSpec::default());
        state.store.put_message(&stored_sandbox).await.unwrap();
        let mut session = crate::config_delivery::register_test_apply_session(
            &state,
            &stored_sandbox,
            "session-1",
        );
        let tx = session.control.clone();
        SupervisorOwnerIndex::new(Arc::clone(&state.store), OWNER_TTL)
            .publish(
                sandbox_id,
                "session-1",
                "instance-1",
                1,
                &state.replica_id,
                "local://test",
            )
            .await
            .unwrap();
        let snapshot = SandboxConfigSnapshot {
            configuration_instance_id: "configuration-1".into(),
            configuration_admitted: true,
            config_revision: 7,
            version: 3,
            policy_hash: "policy-hash".into(),
            provider_env_revision: 5,
            ..Default::default()
        };
        let message = SupervisorConfigMessage::SandboxConfig(Box::new(snapshot.clone()));
        assert_eq!(
            state
                .supervisor_sessions
                .deliver_config(sandbox_id, "session-1", message.clone()),
            DeliveryDisposition::Queued
        );
        let Some(gateway_message::Payload::ConfigUpdate(update)) =
            tokio_stream::StreamExt::next(&mut session.outbound)
                .await
                .expect("initial update")
                .expect("outbound frame")
                .payload
        else {
            panic!("expected initial config update");
        };
        let revision = config_message_revision(&message);
        let mut rejected_admission = expected_configuration_admission(&snapshot);
        rejected_admission.state = ConfigurationAdmissionState::Rejected.into();
        rejected_admission.error = "effective configuration could not be activated".into();

        handle_config_update_result(
            &accepted_session(&state, sandbox_id, tx.clone()),
            &ConfigUpdateResult {
                update_id: update.update_id,
                component_sequence: update.component_sequence,
                result: Some(ConfigComponentApplyResult {
                    component: ConfigComponent::SandboxConfig.into(),
                    requested_revision: Some(revision),
                    applied_revision: None,
                    outcome: ConfigApplyOutcome::AwaitingComponent.into(),
                    failure: None,
                }),
                admission: Some(rejected_admission),
            },
        )
        .await;

        let sandbox = state
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .unwrap()
            .expect("sandbox remains persisted");
        assert!(
            sandbox
                .status
                .as_ref()
                .and_then(|status| status.configuration_admission.as_ref())
                .is_none(),
            "a transient generation mismatch must not persist rejected admission"
        );
        let redriven = tokio::time::timeout(
            Duration::from_secs(2),
            tokio_stream::StreamExt::next(&mut session.outbound),
        )
        .await
        .expect("the awaited counterpart is rebuilt promptly")
        .expect("outbound frame")
        .unwrap();
        assert!(matches!(
            sent_update(redriven).component,
            Some(config_update::Component::ProviderEnvironment(_))
        ));
        assert!(
            tokio::time::timeout(
                Duration::from_millis(300),
                tokio_stream::StreamExt::next(&mut session.outbound),
            )
            .await
            .is_err(),
            "the staged sandbox configuration is not resent"
        );
    }

    /// Model a supervisor that stages a component until its counterpart
    /// arrives, then reports the result it owes once the pair activates.
    fn finalize_result(
        registry: &SupervisorSessionRegistry,
        update: &ConfigUpdate,
        message: &SupervisorConfigMessage,
        outcome: ConfigApplyOutcome,
    ) -> Finalized {
        let revision = config_message_revision(message);
        let completed = registry
            .complete_config_update(
                "sb-1",
                "session-1",
                &ConfigUpdateResult {
                    update_id: update.update_id.clone(),
                    component_sequence: update.component_sequence,
                    result: Some(ConfigComponentApplyResult {
                        component: ConfigComponent::from(message.component()).into(),
                        requested_revision: Some(revision.clone()),
                        applied_revision: (!matches!(
                            outcome,
                            ConfigApplyOutcome::AwaitingComponent
                                | ConfigApplyOutcome::FailedClosed
                        ))
                        .then_some(revision),
                        outcome: outcome.into(),
                        ..Default::default()
                    }),
                    admission: None,
                },
            )
            .unwrap();
        registry.finalize_config_update("sb-1", "session-1", &completed, true)
    }

    #[test]
    fn rejected_components_stay_eligible_for_reconciliation_until_applied() {
        let registry = SupervisorSessionRegistry::new();
        let slots = register_apply_session(&registry, "sb-1", "session-1");
        let provider = SupervisorConfigMessage::ProviderEnvironment(ProviderEnvironmentSnapshot {
            provider_env_revision: 5,
            ..Default::default()
        });
        let rejected = || registry.rejected_config_components("sb-1", "session-1");
        let send = || {
            assert_eq!(
                registry.deliver_config("sb-1", "session-1", provider.clone()),
                DeliveryDisposition::Queued
            );
            sent_update(slots.take_for_test().expect("delivered update"))
        };

        let update = send();
        finalize_result(
            &registry,
            &update,
            &provider,
            ConfigApplyOutcome::FailedClosed,
        );
        assert_eq!(
            rejected(),
            ConfigComponents::only(ConfigComponentKind::ProviderEnvironment)
        );

        // The failed snapshot was never acknowledged, so a rebuild resends it.
        let update = send();
        finalize_result(&registry, &update, &provider, ConfigApplyOutcome::Applied);
        assert_eq!(rejected(), ConfigComponents::default());
        assert_eq!(
            registry.rejected_config_components("sb-1", "other-session"),
            ConfigComponents::default()
        );
    }

    #[test]
    fn staged_component_is_rebuilt_only_after_its_counterpart_is_acknowledged() {
        let registry = SupervisorSessionRegistry::new();
        let slots = register_apply_session(&registry, "sb-1", "session-1");
        let sandbox = sandbox_config(7);
        let provider = SupervisorConfigMessage::ProviderEnvironment(ProviderEnvironmentSnapshot {
            provider_env_revision: 5,
            ..Default::default()
        });
        let send = |message: &SupervisorConfigMessage| {
            assert_eq!(
                registry.deliver_config("sb-1", "session-1", message.clone()),
                DeliveryDisposition::Queued
            );
            sent_update(slots.take_for_test().expect("delivered update"))
        };

        let sandbox_update = send(&sandbox);
        assert_eq!(
            finalize_result(
                &registry,
                &sandbox_update,
                &sandbox,
                ConfigApplyOutcome::AwaitingComponent
            ),
            Finalized::Done {
                rebuild: Some(ConfigComponentKind::ProviderEnvironment)
            },
            "a staged half requests only its counterpart"
        );
        let provider_update = send(&provider);
        assert_eq!(
            finalize_result(
                &registry,
                &provider_update,
                &provider,
                ConfigApplyOutcome::Applied
            ),
            Finalized::Done {
                rebuild: Some(ConfigComponentKind::SandboxConfig)
            },
            "the acknowledged counterpart releases the staged half once"
        );
        let sandbox_update = send(&sandbox);
        assert_eq!(
            finalize_result(
                &registry,
                &sandbox_update,
                &sandbox,
                ConfigApplyOutcome::IgnoredDuplicate
            ),
            Finalized::Done { rebuild: None }
        );

        // Halves that each wait for the other do not keep requesting rebuilds.
        let sandbox = sandbox_config(8);
        let provider = SupervisorConfigMessage::ProviderEnvironment(ProviderEnvironmentSnapshot {
            provider_env_revision: 6,
            ..Default::default()
        });
        let sandbox_update = send(&sandbox);
        let provider_update = send(&provider);
        assert_eq!(
            finalize_result(
                &registry,
                &sandbox_update,
                &sandbox,
                ConfigApplyOutcome::AwaitingComponent
            ),
            Finalized::Done {
                rebuild: Some(ConfigComponentKind::ProviderEnvironment)
            }
        );
        assert_eq!(
            finalize_result(
                &registry,
                &provider_update,
                &provider,
                ConfigApplyOutcome::AwaitingComponent
            ),
            Finalized::Done { rebuild: None }
        );
    }

    #[tokio::test]
    async fn slow_or_failing_provider_build_cannot_loop_sandbox_config_deliveries() {
        use openshell_core::proto::{CredentialHandle, Provider};

        let sandbox_id = "sb-staged-sandbox-config";
        let state = push_state().await;
        // Resolving this handle fails, so every provider environment build
        // fails after the gate releases it.
        state
            .store
            .put_message(&Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: "provider".into(),
                    name: "provider".into(),
                    workspace: "default".into(),
                    ..Default::default()
                }),
                r#type: "github".into(),
                credential_handles: HashMap::from([(
                    "GITHUB_TOKEN".into(),
                    CredentialHandle {
                        driver: "test-static".into(),
                        handle: "missing".into(),
                        ..Default::default()
                    },
                )]),
                ..Default::default()
            })
            .await
            .unwrap();
        let mut sandbox = sandbox_record(sandbox_id, sandbox_id);
        sandbox.spec = Some(SandboxSpec {
            providers: vec!["provider".into()],
            ..Default::default()
        });
        state.store.put_message(&sandbox).await.unwrap();
        let mut session =
            crate::config_delivery::register_test_apply_session(&state, &sandbox, "session-1");
        SupervisorOwnerIndex::new(Arc::clone(&state.store), OWNER_TTL)
            .publish(
                sandbox_id,
                "session-1",
                "instance-1",
                1,
                &state.replica_id,
                "local://test",
            )
            .await
            .unwrap();

        let message = sandbox_config(7);
        assert_eq!(
            state
                .supervisor_sessions
                .deliver_config(sandbox_id, "session-1", message.clone()),
            DeliveryDisposition::Queued
        );
        let update = sent_update(
            tokio_stream::StreamExt::next(&mut session.outbound)
                .await
                .expect("initial update")
                .unwrap(),
        );
        let (resolve_hit, release_resolve) = state.credentials.gate_next_resolve();
        let revision = config_message_revision(&message);
        handle_config_update_result(
            &accepted_session(&state, sandbox_id, session.control.clone()),
            &ConfigUpdateResult {
                update_id: update.update_id,
                component_sequence: update.component_sequence,
                result: Some(ConfigComponentApplyResult {
                    component: ConfigComponent::SandboxConfig.into(),
                    requested_revision: Some(revision),
                    applied_revision: None,
                    outcome: ConfigApplyOutcome::AwaitingComponent.into(),
                    failure: None,
                }),
                admission: None,
            },
        )
        .await;

        tokio::time::timeout(Duration::from_secs(5), resolve_hit)
            .await
            .expect("the awaited provider environment is rebuilt")
            .unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(300),
                tokio_stream::StreamExt::next(&mut session.outbound),
            )
            .await
            .is_err(),
            "a stalled provider build must not resend the staged sandbox configuration"
        );
        release_resolve.send(()).unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(500),
                tokio_stream::StreamExt::next(&mut session.outbound),
            )
            .await
            .is_err(),
            "a failed provider build must not resend the staged sandbox configuration"
        );
    }

    #[tokio::test]
    async fn invalid_image_policy_waits_for_gateway_repair_on_same_stream() {
        use openshell_core::proto::image_policy_discovery::Result as DiscoveryResult;

        let sandbox_id = "sb-invalid-image-repair";
        let state = state_with_startup_policy(sandbox_id, None).await;
        let connecting_state = Arc::clone(&state);
        let connection = tokio::spawn(async move {
            crate::grpc::test_support::connect_supervisor_stream_with_image_policy_discovery(
                &connecting_state,
                sandbox_id,
                StreamFeatures::Apply,
                openshell_core::proto::ImagePolicyDiscovery {
                    result: Some(DiscoveryResult::Invalid(())),
                },
            )
            .await
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !connection.is_finished(),
            "invalid image policy must keep the startup stream pending"
        );

        let repaired_policy = openshell_policy::restrictive_default_policy();
        let mut sandbox = state
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .unwrap()
            .expect("sandbox exists");
        sandbox.spec.get_or_insert_default().policy = Some(repaired_policy.clone());
        state.store.put_message(&sandbox).await.unwrap();
        state.sandbox_watch_bus.notify(sandbox_id);

        let mut harness = tokio::time::timeout(Duration::from_secs(5), connection)
            .await
            .expect("repair resumes the pending stream")
            .expect("connection task")
            .expect("supervisor connects after repair");
        let Some(gateway_message::Payload::StartupConfigCandidate(candidate)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected StartupConfigCandidate after repair");
        };
        assert_eq!(candidate.policy.as_ref(), Some(&repaired_policy));
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::StartupConfigPrepared(
                    StartupConfigPrepared {
                        candidate_id: candidate.candidate_id,
                        result: Some(startup_config_prepared::Result::Unchanged(())),
                    },
                )),
            })
            .await
            .unwrap();
        assert!(matches!(
            first_gateway_message(&mut harness).await.payload,
            Some(gateway_message::Payload::SessionAccepted(_))
        ));
    }

    #[tokio::test]
    async fn invalid_prepared_policy_rejects_session_without_acceptance() {
        let image_policy = openshell_policy::restrictive_default_policy();
        let mut invalid_policy = image_policy.clone();
        invalid_policy
            .filesystem
            .get_or_insert_default()
            .read_only
            .push("relative/path".into());
        let state = state_with_startup_policy("sb-startup-invalid", None).await;
        let mut harness = crate::grpc::test_support::connect_supervisor_stream_with_image_policy(
            &state,
            "sb-startup-invalid",
            StreamFeatures::Apply,
            Some(image_policy),
        )
        .await
        .expect("supervisor must connect");

        let Some(gateway_message::Payload::StartupConfigCandidate(candidate)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected StartupConfigCandidate");
        };
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::StartupConfigPrepared(
                    StartupConfigPrepared {
                        candidate_id: candidate.candidate_id,
                        result: Some(startup_config_prepared::Result::PreparedPolicy(
                            invalid_policy,
                        )),
                    },
                )),
            })
            .await
            .unwrap();

        let Some(gateway_message::Payload::SessionRejected(rejected)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("invalid preparation must reject without accepting the session");
        };
        assert!(rejected.reason.contains("policy"));
    }

    /// Register a streamed-apply session whose control channel stays open
    /// for as long as the returned receiver lives.
    fn register_apply_session_in_state(
        state: &ServerState,
        sandbox_id: &str,
    ) -> (
        mpsc::Sender<GatewayMessage>,
        mpsc::Receiver<GatewayMessage>,
        Arc<ConfigSlots>,
    ) {
        let (tx, rx) = mpsc::channel(1);
        let slots = Arc::new(ConfigSlots::default());
        state.supervisor_sessions.register_with_mode(
            sandbox_id.into(),
            "session-1".into(),
            tx.clone(),
            make_shutdown(),
            SessionMode::Push(Arc::clone(&slots)),
        );
        (tx, rx, slots)
    }

    fn admitted_bootstrap() -> ConfigBootstrap {
        ConfigBootstrap {
            sandbox_config: Some(SandboxConfigSnapshot {
                configuration_instance_id: "configuration-1".into(),
                configuration_admitted: true,
                config_revision: 7,
                provider_env_revision: 11,
                ..Default::default()
            }),
            provider_environment: Some(ProviderEnvironmentSnapshot {
                provider_env_revision: 11,
                ..Default::default()
            }),
        }
    }

    #[tokio::test]
    async fn persisted_bootstrap_result_suppresses_unchanged_reconciliation() {
        let state = push_state_with_sandbox("sb-bootstrap-ack").await;
        let (tx, mut rx, slots) = register_apply_session_in_state(&state, "sb-bootstrap-ack");
        let bootstrap = admitted_bootstrap();

        assert!(
            handle_bootstrap_result(
                &accepted_session(&state, "sb-bootstrap-ack", tx),
                &ExpectedBootstrap::new(&bootstrap),
                &applied_bootstrap_result(&bootstrap),
            )
            .await
        );
        assert!(matches!(
            rx.recv().await.expect("admission").payload,
            Some(gateway_message::Payload::ConfigurationAdmission(_))
        ));
        assert_eq!(
            state.supervisor_sessions.deliver_config(
                "sb-bootstrap-ack",
                "session-1",
                SupervisorConfigMessage::ProviderEnvironment(
                    bootstrap.provider_environment.unwrap()
                )
            ),
            DeliveryDisposition::SuppressedUnchanged
        );
        assert!(slots.take_for_test().ok_or(()).is_err());
    }

    #[tokio::test]
    async fn invalid_bootstrap_admission_records_no_component_result() {
        let state = push_state_with_sandbox("sb-bootstrap-invalid").await;
        let (tx, _rx, slots) = register_apply_session_in_state(&state, "sb-bootstrap-invalid");
        let bootstrap = admitted_bootstrap();
        let mut result = applied_bootstrap_result(&bootstrap);
        result.admission.as_mut().unwrap().config_revision = 8;

        assert!(
            !handle_bootstrap_result(
                &accepted_session(&state, "sb-bootstrap-invalid", tx),
                &ExpectedBootstrap::new(&bootstrap),
                &result,
            )
            .await,
            "a mismatched admission closes the session"
        );
        // Neither component was acknowledged, so both remain eligible.
        assert_eq!(
            state.supervisor_sessions.deliver_config(
                "sb-bootstrap-invalid",
                "session-1",
                SupervisorConfigMessage::ProviderEnvironment(
                    bootstrap.provider_environment.unwrap()
                )
            ),
            DeliveryDisposition::Queued
        );
        assert!(slots.take_for_test().is_some());
    }

    #[tokio::test]
    async fn prepared_policy_is_validated_and_returned_in_fresh_bootstrap() {
        let image_policy = openshell_policy::restrictive_default_policy();
        let mut prepared_policy = image_policy.clone();
        prepared_policy
            .filesystem
            .get_or_insert_default()
            .read_only
            .push("/prepared-path".into());
        let state = state_with_startup_policy("sb-startup-prepared", None).await;
        let mut harness = crate::grpc::test_support::connect_supervisor_stream_with_image_policy(
            &state,
            "sb-startup-prepared",
            StreamFeatures::Apply,
            Some(image_policy),
        )
        .await
        .expect("supervisor must connect");

        let Some(gateway_message::Payload::StartupConfigCandidate(candidate)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected StartupConfigCandidate");
        };
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::StartupConfigPrepared(
                    StartupConfigPrepared {
                        candidate_id: candidate.candidate_id,
                        result: Some(startup_config_prepared::Result::PreparedPolicy(
                            prepared_policy.clone(),
                        )),
                    },
                )),
            })
            .await
            .unwrap();

        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected SessionAccepted");
        };
        assert_eq!(
            accepted
                .bootstrap
                .and_then(|bootstrap| bootstrap.sandbox_config)
                .and_then(|snapshot| snapshot.policy),
            Some(prepared_policy)
        );
    }

    #[test]
    fn provider_delivery_fingerprint_includes_policy_hash_and_attachment_epoch() {
        let registry = SupervisorSessionRegistry::new();
        let slots = register_apply_session(&registry, "sb-1", "session-1");
        let snapshot = ProviderEnvironmentSnapshot {
            provider_env_revision: 7,
            provider_attachment_epoch: "epoch-1".into(),
            policy_hash: "policy-1".into(),
            ..Default::default()
        };
        let message = SupervisorConfigMessage::ProviderEnvironment(snapshot.clone());
        let revision = config_message_revision(&message);
        let fingerprint = config_message_fingerprint(&message);
        assert!(registry.acknowledge_bootstrap_component(
            "sb-1",
            "session-1",
            &ConfigComponentApplyResult {
                component: ConfigComponent::ProviderEnvironment.into(),
                requested_revision: Some(revision.clone()),
                applied_revision: Some(revision),
                outcome: ConfigApplyOutcome::Applied.into(),
                ..Default::default()
            },
            Some(&fingerprint),
        ));
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", message),
            DeliveryDisposition::SuppressedUnchanged
        );

        let policy_changed =
            SupervisorConfigMessage::ProviderEnvironment(ProviderEnvironmentSnapshot {
                policy_hash: "policy-2".into(),
                ..snapshot.clone()
            });
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", policy_changed),
            DeliveryDisposition::Queued
        );
        assert!(slots.take_for_test().ok_or(()).is_ok());

        let replacement_slots = register_apply_session(&registry, "sb-1", "session-2");
        let fingerprint = config_message_fingerprint(
            &SupervisorConfigMessage::ProviderEnvironment(snapshot.clone()),
        );
        assert!(registry.acknowledge_bootstrap_component(
            "sb-1",
            "session-2",
            &ConfigComponentApplyResult {
                component: ConfigComponent::ProviderEnvironment.into(),
                requested_revision: Some(config_message_revision(
                    &SupervisorConfigMessage::ProviderEnvironment(snapshot.clone()),
                )),
                applied_revision: Some(config_message_revision(
                    &SupervisorConfigMessage::ProviderEnvironment(snapshot.clone()),
                )),
                outcome: ConfigApplyOutcome::Applied.into(),
                ..Default::default()
            },
            Some(&fingerprint),
        ));
        assert_eq!(
            registry.deliver_config(
                "sb-1",
                "session-2",
                SupervisorConfigMessage::ProviderEnvironment(ProviderEnvironmentSnapshot {
                    provider_attachment_epoch: "epoch-2".into(),
                    ..snapshot
                })
            ),
            DeliveryDisposition::Queued
        );
        assert!(replacement_slots.take_for_test().ok_or(()).is_ok());
    }

    async fn report_bootstrap_and_runtime_ready(
        state: &Arc<ServerState>,
        sandbox_id: &str,
        harness: &mut crate::grpc::test_support::SupervisorStreamHarness,
        bootstrap: &ConfigBootstrap,
    ) {
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::ConfigBootstrapResult(
                    applied_bootstrap_result(bootstrap),
                )),
            })
            .await
            .unwrap();
        assert!(matches!(
            first_gateway_message(harness).await.payload,
            Some(gateway_message::Payload::ConfigurationAdmission(_))
        ));
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::RuntimeReady(
                    openshell_core::proto::SupervisorRuntimeReady {},
                )),
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !state.supervisor_sessions.is_runtime_ready(sandbox_id) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("runtime readiness before timeout");
    }

    #[tokio::test]
    async fn apply_reconnect_skips_startup_preparation_and_restores_readiness() {
        let sandbox_id = "sb-reconnect-no-preparation";
        let policy = openshell_policy::restrictive_default_policy();
        let state = state_with_startup_policy(sandbox_id, Some(policy)).await;
        let mut initial = crate::grpc::test_support::connect_supervisor_stream(
            &state,
            sandbox_id,
            StreamFeatures::Apply,
        )
        .await
        .expect("initial supervisor connection");
        let Some(gateway_message::Payload::StartupConfigCandidate(candidate)) =
            first_gateway_message(&mut initial).await.payload
        else {
            panic!("initial session must prepare the startup policy");
        };
        initial
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::StartupConfigPrepared(
                    StartupConfigPrepared {
                        candidate_id: candidate.candidate_id,
                        result: Some(startup_config_prepared::Result::Unchanged(())),
                    },
                )),
            })
            .await
            .unwrap();
        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(&mut initial).await.payload
        else {
            panic!("expected initial SessionAccepted");
        };
        let bootstrap = accepted.bootstrap.expect("initial authoritative bootstrap");
        report_bootstrap_and_runtime_ready(&state, sandbox_id, &mut initial, &bootstrap).await;
        drop(initial);

        let mut reconnect = crate::grpc::test_support::reconnect_supervisor_stream(
            &state,
            sandbox_id,
            StreamFeatures::Apply,
        )
        .await
        .expect("stock supervisor reconnect");
        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(&mut reconnect).await.payload
        else {
            panic!("reconnect must proceed directly to SessionAccepted");
        };
        let bootstrap = accepted
            .bootstrap
            .expect("reconnect authoritative bootstrap");
        report_bootstrap_and_runtime_ready(&state, sandbox_id, &mut reconnect, &bootstrap).await;
    }

    #[test]
    fn sandbox_delivery_fingerprint_includes_provider_generation() {
        let registry = SupervisorSessionRegistry::new();
        let slots = register_apply_session(&registry, "sb-1", "session-1");
        let snapshot = SandboxConfigSnapshot {
            configuration_admitted: true,
            config_revision: 7,
            provider_env_revision: 11,
            provider_attachment_epoch: "epoch-1".into(),
            policy_hash: "policy-1".into(),
            ..Default::default()
        };
        let message = SupervisorConfigMessage::SandboxConfig(Box::new(snapshot.clone()));
        let revision = config_message_revision(&message);
        assert!(registry.acknowledge_bootstrap_component(
            "sb-1",
            "session-1",
            &ConfigComponentApplyResult {
                component: ConfigComponent::SandboxConfig.into(),
                requested_revision: Some(revision.clone()),
                applied_revision: Some(revision),
                outcome: ConfigApplyOutcome::Applied.into(),
                ..Default::default()
            },
            Some(&config_message_fingerprint(&message)),
        ));
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", message),
            DeliveryDisposition::SuppressedUnchanged
        );
        assert_eq!(
            registry.deliver_config(
                "sb-1",
                "session-1",
                SupervisorConfigMessage::SandboxConfig(Box::new(SandboxConfigSnapshot {
                    provider_env_revision: 12,
                    ..snapshot
                }))
            ),
            DeliveryDisposition::Queued
        );
        assert!(slots.take_for_test().ok_or(()).is_ok());
    }

    #[tokio::test]
    async fn poll_mode_gateway_does_not_enable_apply() {
        let state = state_with_sandbox("sb-poll-apply").await;
        let mut harness = crate::grpc::test_support::connect_supervisor_stream(
            &state,
            "sb-poll-apply",
            StreamFeatures::Apply,
        )
        .await
        .expect("apply-capable supervisor connects in poll mode");

        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected SessionAccepted without a startup candidate");
        };
        assert!(!accepted.config_apply_enabled);
        assert!(accepted.bootstrap.is_none());

        // This supervisor connects before its workload starts, so acceptance
        // alone must not report it ready.
        assert!(!state.supervisor_sessions.is_runtime_ready("sb-poll-apply"));
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::RuntimeReady(
                    openshell_core::proto::SupervisorRuntimeReady {},
                )),
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !state.supervisor_sessions.is_runtime_ready("sb-poll-apply") {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("runtime readiness marks the polling session ready");
    }

    #[tokio::test]
    async fn polling_reconnect_after_workload_start_is_ready_on_accept() {
        let state = state_with_sandbox("sb-poll-running").await;
        let mut harness = crate::grpc::test_support::connect_supervisor_stream(
            &state,
            "sb-poll-running",
            StreamFeatures::ApplyAfterStart,
        )
        .await
        .expect("apply-capable supervisor reconnects in poll mode");

        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected SessionAccepted");
        };
        assert!(!accepted.config_apply_enabled);
        // Its workload already runs, so it is ready like a supervisor that
        // predates streamed apply.
        assert!(
            state
                .supervisor_sessions
                .is_runtime_ready("sb-poll-running")
        );
    }

    #[tokio::test]
    async fn startup_candidate_prefers_gateway_policy_and_accepts_unchanged_result() {
        let gateway_policy = openshell_policy::restrictive_default_policy();
        let mut image_policy = gateway_policy.clone();
        image_policy
            .filesystem
            .get_or_insert_default()
            .read_only
            .push("/image-only".into());
        let state =
            state_with_startup_policy("sb-startup-gateway", Some(gateway_policy.clone())).await;
        let mut harness = crate::grpc::test_support::connect_supervisor_stream_with_image_policy(
            &state,
            "sb-startup-gateway",
            StreamFeatures::Apply,
            Some(image_policy),
        )
        .await
        .expect("supervisor must connect");

        let Some(gateway_message::Payload::StartupConfigCandidate(candidate)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected StartupConfigCandidate");
        };
        assert_eq!(candidate.policy.as_ref(), Some(&gateway_policy));
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::StartupConfigPrepared(
                    StartupConfigPrepared {
                        candidate_id: candidate.candidate_id,
                        result: Some(startup_config_prepared::Result::Unchanged(())),
                    },
                )),
            })
            .await
            .unwrap();

        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected SessionAccepted");
        };
        assert_eq!(
            accepted
                .bootstrap
                .and_then(|bootstrap| bootstrap.sandbox_config)
                .and_then(|snapshot| snapshot.policy),
            Some(gateway_policy)
        );
    }

    async fn state_with_startup_policy(
        sandbox_id: &str,
        policy: Option<SandboxPolicy>,
    ) -> Arc<ServerState> {
        let state = push_state().await;
        let mut sandbox = sandbox_record(sandbox_id, sandbox_id);
        sandbox.spec = Some(SandboxSpec {
            policy,
            ..SandboxSpec::default()
        });
        state.store.put_message(&sandbox).await.unwrap();
        state
    }

    #[tokio::test]
    async fn unchanged_image_policy_is_persisted_before_session_acceptance() {
        let image_policy = openshell_policy::restrictive_default_policy();
        let state = state_with_startup_policy("sb-startup-image", None).await;
        let mut harness = crate::grpc::test_support::connect_supervisor_stream_with_image_policy(
            &state,
            "sb-startup-image",
            StreamFeatures::Apply,
            Some(image_policy.clone()),
        )
        .await
        .expect("supervisor must connect");

        let Some(gateway_message::Payload::StartupConfigCandidate(candidate)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected StartupConfigCandidate");
        };
        assert_eq!(candidate.policy.as_ref(), Some(&image_policy));
        assert_eq!(candidate.policy_version, 0);
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::StartupConfigPrepared(
                    StartupConfigPrepared {
                        candidate_id: candidate.candidate_id,
                        result: Some(startup_config_prepared::Result::Unchanged(())),
                    },
                )),
            })
            .await
            .unwrap();

        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected SessionAccepted");
        };
        let snapshot = accepted
            .bootstrap
            .and_then(|bootstrap| bootstrap.sandbox_config)
            .expect("authoritative sandbox snapshot");
        assert_eq!(snapshot.policy, Some(image_policy));
        assert_eq!(snapshot.version, 1);
    }
}
