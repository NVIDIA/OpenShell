// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration protocol of one streamed-apply supervisor session.
//!
//! Every session starts from a bootstrap update, and afterwards holds at most
//! one unanswered update. Updates share the session's ordered outbound channel
//! with its other messages. Session lifecycle and relays stay in
//! `supervisor_session`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use metrics::{counter, histogram};
use openshell_core::proto::{
    ConfigApplyOutcome, ConfigUpdate, ConfigUpdateResult, GatewayMessage, PolicyLoadResult,
    PolicySource, ProviderEnvironmentSnapshot, Sandbox, SandboxConfigRevision,
    SandboxConfigSnapshot, SandboxConfigurationAdmission, SessionAccepted, gateway_message,
};
use prost::Message;
use tokio::sync::mpsc;
use tonic::Status;
use tracing::{debug, warn};
use uuid::Uuid;

use super::{DeliveryDisposition, MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES, SupervisorConfig};
use crate::ServerState;
use crate::grpc::policy::{
    build_provider_environment_snapshot_from_inputs, build_sandbox_config_snapshot_from_inputs,
    is_configuration_rejection, load_sandbox_config_inputs, unadmitted_sandbox_config,
};
use crate::persistence::ObjectId;
use crate::supervisor_session::{AcceptedSession, SupervisorSessionRegistry};

/// Bounds the whole bootstrap build. The provider environment has its own
/// shorter timeout and is delivered unresolved when it expires, so only a
/// store that cannot answer refuses the session.
const CONFIG_BOOTSTRAP_BUILD_TIMEOUT: Duration = Duration::from_secs(45);

// ---------------------------------------------------------------------------
// Configuration identity
// ---------------------------------------------------------------------------

/// Identifies a configuration the supervisor already has. The sandbox
/// configuration names its provider environment by revision, attachment
/// epoch, and policy hash, so it identifies the whole update.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ConfigFingerprint {
    revision: SandboxConfigRevision,
    provider_env_revision: u64,
    provider_attachment_epoch: String,
    policy_hash: String,
}

impl ConfigFingerprint {
    fn of(snapshot: &SandboxConfigSnapshot) -> Self {
        Self {
            revision: SandboxConfigRevision {
                config_revision: snapshot.config_revision,
                policy_version: snapshot.version,
                policy_source: snapshot.policy_source,
                global_policy_version: snapshot.global_policy_version,
                settings_revision: snapshot.settings_revision,
            },
            provider_env_revision: snapshot.provider_env_revision,
            provider_attachment_epoch: snapshot.provider_attachment_epoch.clone(),
            policy_hash: snapshot.policy_hash.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Per-session delivery state
// ---------------------------------------------------------------------------

/// Delivery state of a session that applies and acknowledges streamed
/// configuration. One update is in flight at a time, starting with the
/// bootstrap, until the supervisor answers it or the session closes.
#[derive(Debug)]
pub struct ConfigSessionState {
    /// The session's ordered outbound channel.
    tx: mpsc::Sender<GatewayMessage>,
    in_flight: Option<InFlightConfigUpdate>,
    /// Newest configuration built while an update was in flight.
    pending: Option<SupervisorConfig>,
    /// The configuration the supervisor last applied.
    acknowledged: Option<ConfigFingerprint>,
    /// The admission this session last persisted. The admission is written
    /// again only when it changes, so a redelivered configuration writes
    /// nothing.
    persisted_admission: Option<SandboxConfigurationAdmission>,
    /// Preserve the last successful load across later rejected updates until
    /// it is recorded or a newer successful load supersedes it.
    unrecorded_policy_loads: UnrecordedPolicyLoads,
}

#[derive(Debug, Default)]
struct UnrecordedPolicyLoads {
    loaded: Option<PolicyLoadResult>,
    failed: Option<PolicyLoadResult>,
}

impl UnrecordedPolicyLoads {
    fn keep(&mut self, mut result: PolicyLoadResult) {
        let slot = if result.loaded {
            result.error.clear();
            if self
                .failed
                .as_ref()
                .is_some_and(|failed| failed.version == result.version)
            {
                self.failed = None;
            }
            &mut self.loaded
        } else {
            result.error = result.error.chars().take(1024).collect();
            &mut self.failed
        };
        if slot
            .as_ref()
            .is_none_or(|kept| kept.version <= result.version)
        {
            *slot = Some(result);
        }
    }

    fn take(&mut self) -> Vec<PolicyLoadResult> {
        let mut results = [self.loaded.take(), self.failed.take()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        results.sort_by_key(|result| result.version);
        results
    }
}

#[derive(Debug)]
struct InFlightConfigUpdate {
    update_id: String,
    fingerprint: ConfigFingerprint,
    admission: SandboxConfigurationAdmission,
    /// The session's bootstrap, whose result completes session setup.
    bootstrap: bool,
    sent_at: Instant,
}

/// The bootstrap a session is accepted with, in flight from the start.
#[derive(Debug)]
pub struct BootstrapInFlight(InFlightConfigUpdate);

struct CompletedConfigUpdate {
    update_id: String,
    fingerprint: ConfigFingerprint,
    outcome: ConfigApplyOutcome,
    admission: SandboxConfigurationAdmission,
    bootstrap: bool,
    sent_at: Instant,
}

/// An update to queue on the session stream once the registry lock is
/// released.
struct Outgoing {
    tx: mpsc::Sender<GatewayMessage>,
    message: GatewayMessage,
}

impl ConfigSessionState {
    pub fn new(tx: mpsc::Sender<GatewayMessage>) -> Self {
        Self {
            tx,
            in_flight: None,
            pending: None,
            acknowledged: None,
            persisted_admission: None,
            unrecorded_policy_loads: UnrecordedPolicyLoads::default(),
        }
    }

    fn deliver(&mut self, config: SupervisorConfig) -> Result<Outgoing, DeliveryDisposition> {
        if self.in_flight.is_none()
            && self.acknowledged.as_ref() == Some(&ConfigFingerprint::of(&config.sandbox_config))
        {
            return Err(DeliveryDisposition::SuppressedUnchanged);
        }
        // Hold the configuration until the supervisor answers the update it
        // already has. The supervisor answers every update in order, so an
        // answer that never comes means the session is gone.
        if self.in_flight.is_some() {
            self.pending = Some(config);
            return Err(DeliveryDisposition::Coalesced);
        }
        self.send(config)
    }

    fn send(&mut self, config: SupervisorConfig) -> Result<Outgoing, DeliveryDisposition> {
        let (update, in_flight) = build_config_update(config, false, live_message_len);
        let message = GatewayMessage {
            payload: Some(gateway_message::Payload::ConfigUpdate(update)),
        };
        if message.encoded_len() > MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES {
            return Err(DeliveryDisposition::PayloadTooLarge);
        }
        self.in_flight = Some(in_flight);
        Ok(Outgoing {
            tx: self.tx.clone(),
            message,
        })
    }

    fn complete(&self, result: &ConfigUpdateResult) -> Result<CompletedConfigUpdate, Status> {
        let in_flight = self
            .in_flight
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("no update is in flight"))?;
        if in_flight.update_id != result.update_id {
            return Err(Status::invalid_argument(
                "configuration result does not match the in-flight update",
            ));
        }
        // An outcome this gateway does not know did not take effect here.
        let outcome = ConfigApplyOutcome::try_from(result.outcome)
            .ok()
            .filter(|outcome| *outcome != ConfigApplyOutcome::Unspecified)
            .unwrap_or(ConfigApplyOutcome::Unsupported);
        Ok(CompletedConfigUpdate {
            update_id: in_flight.update_id.clone(),
            fingerprint: in_flight.fingerprint.clone(),
            outcome,
            admission: in_flight.admission.clone(),
            bootstrap: in_flight.bootstrap,
            sent_at: in_flight.sent_at,
        })
    }

    /// Finish the update in flight and release configuration held behind
    /// it, unless the supervisor already has that configuration.
    fn finalize(
        &mut self,
        completed: &CompletedConfigUpdate,
        acknowledge: bool,
    ) -> Option<Outgoing> {
        if self
            .in_flight
            .as_ref()
            .is_none_or(|update| update.update_id != completed.update_id)
        {
            return None;
        }
        self.in_flight = None;
        if acknowledge && outcome_acknowledges_revision(completed.outcome) {
            // A degraded supervisor enforces this configuration but failed to
            // reload part of its runtime, so reconciliation delivers it again
            // to retry the reload, as the next poll would.
            self.acknowledged = (completed.outcome != ConfigApplyOutcome::Degraded)
                .then(|| completed.fingerprint.clone());
        }
        let pending = self.pending.take()?;
        if self.acknowledged.as_ref() == Some(&ConfigFingerprint::of(&pending.sandbox_config)) {
            return None;
        }
        self.send(pending).ok()
    }

    fn admission_changed(&self, admission: &SandboxConfigurationAdmission) -> bool {
        self.persisted_admission.as_ref() != Some(admission)
    }
}

impl SupervisorSessionRegistry {
    /// Hand a configuration to the session it was built for. A replacement
    /// session received its own bootstrap and must not receive an older
    /// build.
    pub(crate) fn deliver_config(
        &self,
        sandbox_id: &str,
        session_id: &str,
        config: SupervisorConfig,
    ) -> DeliveryDisposition {
        let delivery = self.with_config_session(sandbox_id, session_id, |session| {
            session.map_or(Err(DeliveryDisposition::UnsupportedSession), |session| {
                session.deliver(config)
            })
        });
        match delivery {
            None => DeliveryDisposition::NoActiveSession,
            Some(Err(disposition)) => disposition,
            Some(Ok(outgoing)) => {
                if self.send_or_close(sandbox_id, session_id, outgoing) {
                    DeliveryDisposition::Queued
                } else {
                    DeliveryDisposition::StreamClosed
                }
            }
        }
    }

    /// Queue `outgoing` on the session's stream. A stream too full to take
    /// it has stopped draining, so the session closes and its supervisor
    /// reconnects with a fresh bootstrap. A closed stream is already ending.
    fn send_or_close(&self, sandbox_id: &str, session_id: &str, outgoing: Outgoing) -> bool {
        match outgoing.tx.try_send(outgoing.message) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(
                    sandbox_id,
                    session_id, "supervisor session stopped draining configuration; closing it"
                );
                self.close_if_current(sandbox_id, session_id);
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    /// Hold configuration updates for a session until the bootstrap it was
    /// accepted with is answered.
    /// Start the session with its bootstrap in flight. `persisted_admission`
    /// is the admission the sandbox record already holds, which a result
    /// reporting the same admission does not write again.
    pub(crate) fn begin_config_bootstrap(
        &self,
        sandbox_id: &str,
        session_id: &str,
        bootstrap: BootstrapInFlight,
        persisted_admission: Option<SandboxConfigurationAdmission>,
    ) {
        self.with_config_session(sandbox_id, session_id, |session| {
            if let Some(session) = session {
                session.in_flight = Some(bootstrap.0);
                session.persisted_admission = persisted_admission;
            }
        });
    }

    fn complete_config_update(
        &self,
        sandbox_id: &str,
        session_id: &str,
        result: &ConfigUpdateResult,
    ) -> Result<CompletedConfigUpdate, Status> {
        self.with_config_session(sandbox_id, session_id, |session| {
            session.map(|session| session.complete(result))
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
    fn finalize_config_update(
        &self,
        sandbox_id: &str,
        session_id: &str,
        completed: &CompletedConfigUpdate,
        acknowledge: bool,
    ) {
        if let Some(outgoing) = self
            .with_config_session(sandbox_id, session_id, |session| {
                session.and_then(|session| session.finalize(completed, acknowledge))
            })
            .flatten()
        {
            self.send_or_close(sandbox_id, session_id, outgoing);
        }
    }

    /// Whether persisting `admission` would change what this session last
    /// persisted, or `None` once the session was replaced.
    fn admission_changed(
        &self,
        sandbox_id: &str,
        session_id: &str,
        admission: &SandboxConfigurationAdmission,
    ) -> Option<bool> {
        self.with_config_session(sandbox_id, session_id, |session| {
            session.is_none_or(|session| session.admission_changed(admission))
        })
    }

    fn record_persisted_admission(
        &self,
        sandbox_id: &str,
        session_id: &str,
        admission: &SandboxConfigurationAdmission,
    ) {
        self.with_config_session(sandbox_id, session_id, |session| {
            if let Some(session) = session {
                session.persisted_admission = Some(admission.clone());
            }
        });
    }

    fn take_unrecorded_policy_loads(
        &self,
        sandbox_id: &str,
        session_id: &str,
    ) -> Vec<PolicyLoadResult> {
        self.with_config_session(sandbox_id, session_id, |session| {
            session.map_or_else(Vec::new, |session| session.unrecorded_policy_loads.take())
        })
        .unwrap_or_default()
    }

    fn keep_unrecorded_policy_load(
        &self,
        sandbox_id: &str,
        session_id: &str,
        policy_load: PolicyLoadResult,
    ) {
        self.with_config_session(sandbox_id, session_id, |session| {
            if let Some(session) = session {
                session.unrecorded_policy_loads.keep(policy_load);
            }
        });
    }
}

/// The encoded length of a message whose one empty message field is replaced
/// by a message of `field_len` bytes. An empty message field encodes as its
/// key and a one-byte zero length. Measuring this way avoids copying a large
/// configuration into its envelope.
fn with_message_field(len_with_empty_field: usize, field_len: usize) -> usize {
    len_with_empty_field - 1 + prost::encoding::encoded_len_varint(field_len as u64) + field_len
}

/// The encoded length of the message that carries a live update of
/// `update_len` bytes.
fn live_message_len(update_len: usize) -> usize {
    let envelope = GatewayMessage {
        payload: Some(gateway_message::Payload::ConfigUpdate(
            ConfigUpdate::default(),
        )),
    };
    with_message_field(envelope.encoded_len(), update_len)
}

/// The encoded length of the `accepted` message once it carries a bootstrap
/// of `update_len` bytes.
fn bootstrap_message_len(accepted: &SessionAccepted, update_len: usize) -> usize {
    let accepted = SessionAccepted {
        bootstrap: Some(ConfigUpdate::default()),
        ..accepted.clone()
    };
    let envelope = GatewayMessage {
        payload: Some(gateway_message::Payload::SessionAccepted(
            SessionAccepted::default(),
        )),
    };
    with_message_field(
        envelope.encoded_len(),
        with_message_field(accepted.encoded_len(), update_len),
    )
}

/// `message_size` maps the encoded length of the update to the length of
/// the message that carries it.
fn build_config_update(
    config: SupervisorConfig,
    bootstrap: bool,
    message_size: impl Fn(usize) -> usize,
) -> (ConfigUpdate, InFlightConfigUpdate) {
    let update_id = Uuid::new_v4().to_string();
    let mut update = ConfigUpdate {
        update_id: update_id.clone(),
        sandbox_config: Some(config.sandbox_config),
        provider_environment: Some(config.provider_environment),
    };
    let size = message_size(update.encoded_len());
    if size > MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES {
        let snapshot = update
            .sandbox_config
            .as_mut()
            .expect("sandbox configuration");
        snapshot.policy = None;
        snapshot.settings.clear();
        snapshot.supervisor_middleware_services.clear();
        snapshot.configuration_admitted = false;
        snapshot.configuration_error = format!(
            "configuration_too_large: encoded configuration is {size} bytes; maximum is {MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES} bytes"
        );
        update.provider_environment = Some(super::unresolved_provider_environment(snapshot));
    }
    let snapshot = update
        .sandbox_config
        .as_ref()
        .expect("sandbox configuration");
    let in_flight = InFlightConfigUpdate {
        update_id,
        fingerprint: ConfigFingerprint::of(snapshot),
        admission: expected_configuration_admission(snapshot),
        bootstrap,
        sent_at: Instant::now(),
    };
    (update, in_flight)
}

/// The update a session is accepted with, and its in-flight state for
/// [`SupervisorSessionRegistry::begin_config_bootstrap`].
pub fn bootstrap_update(
    config: SupervisorConfig,
    accepted: &SessionAccepted,
) -> (ConfigUpdate, BootstrapInFlight) {
    let (update, in_flight) = build_config_update(config, true, |update_len| {
        bootstrap_message_len(accepted, update_len)
    });
    (update, BootstrapInFlight(in_flight))
}

// ---------------------------------------------------------------------------
// Results and admission
// ---------------------------------------------------------------------------

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

/// Record the result of the update in flight, including the bootstrap.
/// Nothing is persisted for an invalid result. Returns false when the
/// session must close: a result that answers no update in flight, or a
/// bootstrap whose result is invalid or whose admission could not be
/// persisted.
pub async fn handle_config_update_result(
    session: &AcceptedSession,
    result: &ConfigUpdateResult,
) -> bool {
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
            // The supervisor answers each update once, in order, so this
            // session and its supervisor disagree; a reconnect resets both.
            warn!(
                sandbox_id,
                session_id,
                error = %error,
                "supervisor configuration result answers no update in flight; closing the session"
            );
            return false;
        }
    };
    histogram!(
        crate::gateway_metrics::SUPERVISOR_CONFIG_APPLY_DURATION_SECONDS,
        "outcome" => completed.outcome.as_str_name(),
    )
    .record(completed.sent_at.elapsed().as_secs_f64());
    record_apply_result(sandbox_id, completed.outcome, result);
    let admission = match validate_configuration_admission(
        result.admission.as_ref(),
        &completed.admission,
        completed.outcome,
    ) {
        Ok(admission) => admission,
        Err(error) => {
            warn!(
                sandbox_id,
                session_id,
                error = %error,
                "supervisor configuration result did not match the delivered update"
            );
            registry.finalize_config_update(sandbox_id, session_id, &completed, false);
            return !completed.bootstrap;
        }
    };
    let bootstrap_load = if completed.bootstrap && result.policy_load.is_none() {
        bootstrap_policy_load(state, sandbox_id, &completed, &admission).await
    } else {
        None
    };
    // Retry the successful load before a later rejection so the policy still
    // enforced cannot lose its load acknowledgement.
    let mut recorded = true;
    let policy_loads = registry
        .take_unrecorded_policy_loads(sandbox_id, session_id)
        .into_iter()
        .chain(result.policy_load.clone())
        .chain(bootstrap_load);
    for policy_load in policy_loads {
        match record_policy_load(state, sandbox_id, &policy_load).await {
            Ok(()) => {}
            // The revision is gone, so there is nothing left to record.
            Err(error) if error.code() == tonic::Code::NotFound => {
                debug!(
                    sandbox_id,
                    session_id,
                    version = policy_load.version,
                    "dropped policy result for a missing revision"
                );
            }
            Err(error) => {
                warn!(
                    sandbox_id,
                    session_id,
                    error = %error,
                    "failed to persist supervisor policy result"
                );
                registry.keep_unrecorded_policy_load(sandbox_id, session_id, policy_load);
                recorded = false;
            }
        }
    }
    let admitted = persist_admission(session, &admission).await;
    // An unpersisted result leaves the configuration unacknowledged, so
    // reconciliation delivers it again and the supervisor reports it again.
    registry.finalize_config_update(sandbox_id, session_id, &completed, recorded && admitted);
    admitted || !completed.bootstrap
}

/// Count and log an update result.
fn record_apply_result(sandbox_id: &str, outcome: ConfigApplyOutcome, result: &ConfigUpdateResult) {
    counter!(
        "openshell_supervisor_config_apply_results_total",
        "outcome" => outcome.as_str_name(),
    )
    .increment(1);
    if !outcome_acknowledges_revision(outcome) {
        let failure = result.failure.as_ref();
        warn!(
            sandbox_id,
            outcome = outcome.as_str_name(),
            failure_code = failure.map_or("", |failure| failure.code.as_str()),
            failure = failure
                .map(|failure| failure.message.chars().take(1024).collect::<String>())
                .unwrap_or_default(),
            "supervisor failed to apply pushed configuration"
        );
    }
}

/// Record a sandbox policy load result. The supervisor reports one only
/// when an update changed the sandbox policy, as polling does.
async fn record_policy_load(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    policy_load: &PolicyLoadResult,
) -> Result<(), Status> {
    crate::grpc::policy::record_policy_apply_result(
        state,
        sandbox_id,
        policy_load.version,
        policy_load.loaded,
        (!policy_load.loaded).then_some(policy_load.error.as_str()),
        "stream",
    )
    .await
}

/// The load that a bootstrap result implies for the sandbox policy revision
/// the supervisor enforces, unless that revision is already settled.
///
/// The supervisor reports a load only when an update changes its policy, so
/// the bootstrap of a reconnect reports none. A load result lost with an
/// earlier session, because its write failed or the session ended before the
/// result arrived, would otherwise leave the revision pending. The bootstrap
/// settles it, as a polling supervisor's startup acknowledgement does.
async fn bootstrap_policy_load(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    completed: &CompletedConfigUpdate,
    admission: &SandboxConfigurationAdmission,
) -> Option<PolicyLoadResult> {
    use crate::policy_store::PolicyStoreExt as _;
    use openshell_core::proto::ConfigurationAdmissionState;

    let revision = &completed.fingerprint.revision;
    // Degraded enforces the policy with only built-in middleware. A local
    // override enforces no gateway policy.
    let enforced = matches!(
        completed.outcome,
        ConfigApplyOutcome::Applied
            | ConfigApplyOutcome::IgnoredDuplicate
            | ConfigApplyOutcome::Degraded
    ) && admission.state == i32::from(ConfigurationAdmissionState::Accepted);
    if !enforced
        || revision.policy_source != i32::from(PolicySource::Sandbox)
        || revision.policy_version == 0
    {
        return None;
    }
    let version = revision.policy_version;
    match state
        .store
        .get_policy_by_version(sandbox_id, i64::from(version))
        .await
    {
        Ok(Some(policy)) if matches!(policy.status.as_str(), "loaded" | "superseded") => {
            return None;
        }
        Ok(None) => return None,
        Ok(Some(_)) => {}
        // Record it anyway. A failed write is kept and retried with the
        // session's next result.
        Err(error) => {
            debug!(sandbox_id, version, error = %error, "failed to read the bootstrap policy revision");
        }
    }
    Some(PolicyLoadResult {
        version,
        loaded: true,
        error: String::new(),
    })
}

/// Persist the session's admission when it differs from the one this session
/// last persisted, so a redelivered configuration writes nothing.
async fn persist_admission(
    session: &AcceptedSession,
    admission: &SandboxConfigurationAdmission,
) -> bool {
    let AcceptedSession {
        state,
        sandbox_id,
        session_id,
        instance_id,
        ..
    } = session;
    let registry = &state.supervisor_sessions;
    match registry.admission_changed(sandbox_id, session_id, admission) {
        None => return false,
        Some(false) => return true,
        Some(true) => {}
    }
    if let Err(error) = state
        .compute
        .supervisor_session_admission(sandbox_id, session_id, instance_id, admission)
        .await
    {
        warn!(sandbox_id, session_id, error = %error, "failed to persist supervisor configuration admission");
        return false;
    }
    registry.record_persisted_admission(sandbox_id, session_id, admission);
    true
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

/// How a session's bootstrap was built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapOutcome {
    Built,
    /// The stored configuration is invalid, so the bootstrap carries the
    /// not-admitted configuration and the supervisor applies its failure
    /// mode.
    Rejected,
    /// The provider environment could not be built, so the bootstrap carries
    /// it unresolved, as live delivery does. The supervisor revokes static
    /// credentials and rejects the update until a rebuild resolves it.
    ProviderEnvironmentFailed,
}

impl BootstrapOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::Rejected => "rejected",
            Self::ProviderEnvironmentFailed => "provider_environment_failed",
        }
    }
}

/// The configuration a streamed-apply session is accepted with.
#[derive(Debug, Clone)]
pub struct SessionBootstrap {
    pub config: SupervisorConfig,
    pub outcome: BootstrapOutcome,
}

impl SessionBootstrap {
    /// The resolved provider environment the session can reuse, if any.
    pub fn resolved_provider_environment(&self) -> Option<ProviderEnvironmentSnapshot> {
        (self.outcome == BootstrapOutcome::Built).then(|| self.config.provider_environment.clone())
    }

    /// Whether the session must rebuild its configuration at once, because
    /// the bootstrap could not resolve part of it.
    pub fn needs_rebuild(&self) -> bool {
        self.outcome == BootstrapOutcome::ProviderEnvironmentFailed
    }
}

/// Build the bootstrap a streamed-apply session is accepted with.
pub async fn build_session_bootstrap(
    state: &Arc<ServerState>,
    sandbox: &Sandbox,
) -> Result<SessionBootstrap, Status> {
    // Bootstraps share the build permits with session reconciliation, so a
    // burst of reconnects, such as a replica's sessions redirected at
    // shutdown, cannot exhaust the database pool user requests need.
    let _permit = state
        .config_delivery
        .builds
        .acquire()
        .await
        .expect("the build semaphore is never closed");
    let bootstrap = build_config_bootstrap(state, sandbox).await;
    let outcome = bootstrap
        .as_ref()
        .map_or("build_failed", |bootstrap| bootstrap.outcome.label());
    counter!("openshell_supervisor_config_bootstrap_total", "outcome" => outcome).increment(1);
    if let Err(error) = &bootstrap {
        warn!(
            sandbox_id = %sandbox.object_id(),
            error_code = ?error.code(),
            "failed to build supervisor configuration bootstrap"
        );
    }
    bootstrap
}

/// Build both parts of a session's configuration from one load of their
/// inputs. Only a failure to read the stored configuration refuses the
/// session; anything the supervisor can act on is delivered.
async fn build_config_bootstrap(
    state: &Arc<ServerState>,
    sandbox: &Sandbox,
) -> Result<SessionBootstrap, Status> {
    tokio::time::timeout(CONFIG_BOOTSTRAP_BUILD_TIMEOUT, async {
        let built = async {
            let inputs = load_sandbox_config_inputs(state, sandbox.clone()).await?;
            let sandbox_config = build_sandbox_config_snapshot_from_inputs(state, &inputs).await?;
            Ok::<_, Status>((inputs, sandbox_config))
        }
        .await;
        let (inputs, sandbox_config) = match built {
            Ok(built) => built,
            Err(error) if is_configuration_rejection(&error) => {
                let sandbox_config = unadmitted_sandbox_config(state, sandbox, &error);
                return Ok(SessionBootstrap {
                    config: SupervisorConfig {
                        provider_environment: super::unresolved_provider_environment(
                            &sandbox_config,
                        ),
                        sandbox_config,
                    },
                    outcome: BootstrapOutcome::Rejected,
                });
            }
            Err(error) => return Err(error),
        };
        let provider_environment = tokio::time::timeout(
            super::PROVIDER_ENVIRONMENT_BUILD_TIMEOUT,
            build_provider_environment_snapshot_from_inputs(state, &inputs, true, true),
        )
        .await;
        let (provider_environment, outcome) = match provider_environment {
            Ok(Ok(provider_environment)) => (provider_environment, BootstrapOutcome::Built),
            failed => {
                let error_code = match &failed {
                    Ok(Err(error)) => error.code(),
                    _ => tonic::Code::DeadlineExceeded,
                };
                warn!(
                    sandbox_id = %sandbox.object_id(),
                    ?error_code,
                    "failed to build the bootstrap provider environment; delivering it unresolved"
                );
                (
                    super::unresolved_provider_environment(&sandbox_config),
                    BootstrapOutcome::ProviderEnvironmentFailed,
                )
            }
        };
        Ok(SessionBootstrap {
            config: SupervisorConfig {
                sandbox_config,
                provider_environment,
            },
            outcome,
        })
    })
    .await
    .map_err(|_| Status::deadline_exceeded("supervisor configuration bootstrap timed out"))?
}

/// The result a supervisor reports after applying `update` in full.
#[cfg(test)]
pub fn applied_result(update: &ConfigUpdate) -> ConfigUpdateResult {
    let sandbox = update
        .sandbox_config
        .as_ref()
        .expect("sandbox configuration");
    let policy_load = (sandbox.policy_source == i32::from(PolicySource::Sandbox)
        && sandbox.version > 0)
        .then(|| PolicyLoadResult {
            version: sandbox.version,
            loaded: true,
            error: String::new(),
        });
    ConfigUpdateResult {
        update_id: update.update_id.clone(),
        outcome: ConfigApplyOutcome::Applied.into(),
        failure: None,
        admission: Some(expected_configuration_admission(sandbox)),
        policy_load,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::test_support::StreamFeatures;
    use crate::supervisor_session::SessionMode;
    use openshell_core::proto::{
        ProviderEnvironmentSnapshot, ProviderEnvironmentValue, SandboxPolicy, SandboxSpec,
        SessionAccepted, SupervisorMessage, supervisor_message,
    };
    use tokio::sync::oneshot;

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
            pushes_config: true,
        }
    }

    #[test]
    fn configuration_stream_messages_round_trip() {
        let update = || ConfigUpdate {
            update_id: "update-1".into(),
            sandbox_config: Some(SandboxConfigSnapshot::default()),
            provider_environment: Some(ProviderEnvironmentSnapshot::default()),
        };
        let messages = [
            GatewayMessage {
                payload: Some(gateway_message::Payload::SessionAccepted(SessionAccepted {
                    session_id: "session-1".into(),
                    heartbeat_interval: openshell_core::time::duration_from_std(
                        Duration::from_secs(15),
                    )
                    .ok(),
                    bootstrap: Some(update()),
                    config_push_enabled: true,
                })),
            },
            GatewayMessage {
                payload: Some(gateway_message::Payload::ConfigUpdate(update())),
            },
        ];
        for original in messages {
            let decoded = GatewayMessage::decode(original.encode_to_vec().as_slice()).unwrap();
            assert_eq!(decoded, original);
        }

        let result = SupervisorMessage {
            payload: Some(supervisor_message::Payload::ConfigUpdateResult(
                ConfigUpdateResult {
                    update_id: "update-1".into(),
                    outcome: ConfigApplyOutcome::Applied.into(),
                    failure: None,
                    admission: Some(SandboxConfigurationAdmission::default()),
                    policy_load: Some(PolicyLoadResult {
                        version: 3,
                        loaded: true,
                        error: String::new(),
                    }),
                },
            )),
        };
        let decoded = SupervisorMessage::decode(result.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded, result);
    }

    /// Register a streamed-apply session and return its outbound channel.
    fn register_apply_session_with_outbound(
        registry: &SupervisorSessionRegistry,
        sandbox_id: &str,
        session_id: &str,
    ) -> (mpsc::Sender<GatewayMessage>, mpsc::Receiver<GatewayMessage>) {
        let (tx, rx) = mpsc::channel(16);
        registry.register_with_mode(
            sandbox_id.into(),
            session_id.into(),
            tx.clone(),
            make_shutdown(),
            SessionMode::Push,
        );
        (tx, rx)
    }

    /// The next configuration update queued on a session's channel, skipping
    /// any admission sent ahead of it.
    fn take_update(outbound: &mut mpsc::Receiver<GatewayMessage>) -> Option<ConfigUpdate> {
        while let Ok(message) = outbound.try_recv() {
            if let Some(gateway_message::Payload::ConfigUpdate(update)) = message.payload {
                return Some(update);
            }
        }
        None
    }

    fn sent_update(message: GatewayMessage) -> ConfigUpdate {
        match message.payload {
            Some(gateway_message::Payload::ConfigUpdate(update)) => update,
            other => panic!("expected config update, got {other:?}"),
        }
    }

    fn config(config_revision: u64) -> SupervisorConfig {
        SupervisorConfig {
            sandbox_config: SandboxConfigSnapshot {
                config_revision,
                ..Default::default()
            },
            provider_environment: ProviderEnvironmentSnapshot::default(),
        }
    }

    fn config_revision(update: &ConfigUpdate) -> u64 {
        update.sandbox_config.as_ref().unwrap().config_revision
    }

    /// A supervisor result for `update` with `outcome`.
    fn update_result(update: &ConfigUpdate, outcome: ConfigApplyOutcome) -> ConfigUpdateResult {
        ConfigUpdateResult {
            update_id: update.update_id.clone(),
            outcome: outcome.into(),
            ..Default::default()
        }
    }

    #[test]
    fn config_delivery_reports_missing_session() {
        assert_eq!(
            SupervisorSessionRegistry::new().deliver_config("missing", "session", config(1)),
            DeliveryDisposition::NoActiveSession
        );
    }

    #[tokio::test]
    async fn config_delivery_holds_newer_configuration_until_acknowledged() {
        let registry = SupervisorSessionRegistry::new();
        let (_tx, mut outbound) =
            register_apply_session_with_outbound(&registry, "sb-1", "session-1");

        assert_eq!(
            registry.deliver_config("sb-1", "session-1", config(1)),
            DeliveryDisposition::Queued
        );
        for config_revision in [2, 3] {
            assert_eq!(
                registry.deliver_config("sb-1", "session-1", config(config_revision)),
                DeliveryDisposition::Coalesced
            );
        }
        let first = sent_update(outbound.recv().await.unwrap());
        assert_eq!(config_revision(&first), 1);
        assert!(first.provider_environment.is_some());

        let completed = registry
            .complete_config_update(
                "sb-1",
                "session-1",
                &update_result(&first, ConfigApplyOutcome::Applied),
            )
            .unwrap();
        registry.finalize_config_update("sb-1", "session-1", &completed, true);

        // The acknowledgement releases only the newest held configuration.
        let next = sent_update(outbound.recv().await.unwrap());
        assert_eq!(config_revision(&next), 3);
        assert_ne!(next.update_id, first.update_id);
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", config(3)),
            DeliveryDisposition::Coalesced,
            "the release is in flight"
        );
    }

    #[tokio::test]
    async fn config_delivery_never_crosses_into_a_replacement_session() {
        let registry = SupervisorSessionRegistry::new();
        let (_old_tx, _old_outbound) =
            register_apply_session_with_outbound(&registry, "sb-1", "old-session");
        let (_new_tx, mut new_outbound) =
            register_apply_session_with_outbound(&registry, "sb-1", "new-session");

        assert_eq!(
            registry.deliver_config("sb-1", "old-session", config(1)),
            DeliveryDisposition::NoActiveSession
        );
        assert_eq!(
            registry.deliver_config("sb-1", "new-session", config(2)),
            DeliveryDisposition::Queued
        );
        let update = sent_update(new_outbound.recv().await.unwrap());
        assert_eq!(config_revision(&update), 2);
    }

    #[test]
    fn config_delivery_skips_polling_sessions() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, _rx) = mpsc::channel(1);
        registry.register("sb-1".into(), "session-1".into(), tx, make_shutdown());
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", config(1)),
            DeliveryDisposition::UnsupportedSession
        );
    }

    fn oversized_config() -> SupervisorConfig {
        let mut config = admitted_config();
        config.sandbox_config.policy = Some(SandboxPolicy::default());
        config.sandbox_config.version = 3;
        config.sandbox_config.policy_hash = "policy-hash".into();
        config.sandbox_config.provider_attachment_epoch = "attachment-1".into();
        config.sandbox_config.policy_validation_failure_mode = "retain_last_valid".into();
        config.provider_environment.values = vec![ProviderEnvironmentValue {
            name: "TOKEN".into(),
            value: "secret".repeat(MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES / 6 + 1),
            ..Default::default()
        }];
        config
    }

    fn assert_oversized_rejection(update: &ConfigUpdate, original: &SandboxConfigSnapshot) {
        let rejected = update.sandbox_config.as_ref().unwrap();
        assert_eq!(
            ConfigFingerprint::of(rejected),
            ConfigFingerprint::of(original)
        );
        assert_eq!(
            rejected.configuration_instance_id,
            original.configuration_instance_id
        );
        assert_eq!(
            rejected.policy_validation_failure_mode,
            original.policy_validation_failure_mode
        );
        assert!(!rejected.configuration_admitted);
        assert!(
            rejected
                .configuration_error
                .starts_with("configuration_too_large:")
        );
        assert!(rejected.configuration_error.len() < 200);
        assert!(rejected.policy.is_none());
        assert!(rejected.settings.is_empty());
        assert!(rejected.supervisor_middleware_services.is_empty());
        assert_eq!(
            update.provider_environment.as_ref().unwrap(),
            &super::super::unresolved_provider_environment(rejected)
        );
        assert!(update.encoded_len() < 1024);
        assert!(!String::from_utf8_lossy(&update.encode_to_vec()).contains("secret"));
    }

    #[tokio::test]
    async fn oversized_live_and_pending_updates_deliver_rejections_and_recover() {
        for pending in [false, true] {
            let registry = SupervisorSessionRegistry::new();
            let (_tx, mut outbound) =
                register_apply_session_with_outbound(&registry, "sb-1", "session-1");
            let first = pending.then(|| {
                assert_eq!(
                    registry.deliver_config("sb-1", "session-1", config(1)),
                    DeliveryDisposition::Queued
                );
                sent_update(outbound.try_recv().unwrap())
            });
            let oversized = oversized_config();
            let original = oversized.sandbox_config.clone();
            assert_eq!(
                registry.deliver_config("sb-1", "session-1", oversized),
                if pending {
                    DeliveryDisposition::Coalesced
                } else {
                    DeliveryDisposition::Queued
                }
            );
            if let Some(first) = first {
                answer_bootstrap(
                    &registry,
                    "sb-1",
                    "session-1",
                    &first,
                    ConfigApplyOutcome::Applied,
                );
            }
            let rejection = sent_update(outbound.recv().await.unwrap());
            assert_oversized_rejection(&rejection, &original);
            let completed = registry
                .complete_config_update(
                    "sb-1",
                    "session-1",
                    &update_result(&rejection, ConfigApplyOutcome::FailedRetainedLastKnownGood),
                )
                .unwrap();
            assert_eq!(
                completed.admission.state,
                i32::from(openshell_core::proto::ConfigurationAdmissionState::Rejected)
            );
            assert!(
                validate_configuration_admission(
                    Some(&completed.admission),
                    &completed.admission,
                    completed.outcome
                )
                .is_ok()
            );
            registry.finalize_config_update("sb-1", "session-1", &completed, true);
            let recovery = SupervisorConfig {
                sandbox_config: SandboxConfigSnapshot {
                    configuration_admitted: true,
                    ..original
                },
                provider_environment: ProviderEnvironmentSnapshot::default(),
            };
            assert_eq!(
                registry.deliver_config("sb-1", "session-1", recovery),
                DeliveryDisposition::Queued
            );
            let recovered = sent_update(outbound.recv().await.unwrap());
            assert!(recovered.sandbox_config.unwrap().configuration_admitted);
        }
    }

    #[test]
    fn oversized_bootstrap_delivers_rejection_with_original_identity() {
        let config = oversized_config();
        let original = config.sandbox_config.clone();
        let acceptance = SessionAccepted {
            session_id: "session-1".into(),
            config_push_enabled: true,
            ..Default::default()
        };
        let (update, in_flight) = bootstrap_update(config, &acceptance);
        assert_oversized_rejection(&update, &original);
        assert_eq!(
            in_flight.0.admission.state,
            i32::from(openshell_core::proto::ConfigurationAdmissionState::Rejected)
        );
        let message = GatewayMessage {
            payload: Some(gateway_message::Payload::SessionAccepted(SessionAccepted {
                bootstrap: Some(update),
                ..acceptance
            })),
        };
        assert!(message.encoded_len() <= MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES);
    }

    #[test]
    fn bootstrap_size_limit_includes_the_session_envelope() {
        let mut config = admitted_config();
        config.provider_environment.values = vec![ProviderEnvironmentValue {
            name: "TOKEN".into(),
            value: "x".repeat(MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES),
            ..Default::default()
        }];
        let raw = ConfigUpdate {
            update_id: Uuid::new_v4().to_string(),
            sandbox_config: Some(config.sandbox_config.clone()),
            provider_environment: Some(config.provider_environment.clone()),
        };
        let overhead = GatewayMessage {
            payload: Some(gateway_message::Payload::ConfigUpdate(raw)),
        }
        .encoded_len()
            - MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES;
        config.provider_environment.values[0]
            .value
            .truncate(MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES - overhead);
        let (live, _) = build_config_update(config.clone(), false, live_message_len);
        assert!(live.sandbox_config.unwrap().configuration_admitted);
        let acceptance = SessionAccepted {
            session_id: Uuid::new_v4().to_string(),
            config_push_enabled: true,
            ..Default::default()
        };
        let (bootstrap, _) = bootstrap_update(config, &acceptance);
        assert!(!bootstrap.sandbox_config.unwrap().configuration_admitted);
    }

    #[test]
    fn message_lengths_match_their_encodings() {
        let accepted = SessionAccepted {
            session_id: Uuid::new_v4().to_string(),
            config_push_enabled: true,
            heartbeat_interval: Some(prost_types::Duration {
                seconds: 15,
                nanos: 0,
            }),
            ..Default::default()
        };
        // Cover the lengths where a length prefix gains a byte.
        for value_len in [0, 100, 127, 128, 16_383, 16_384, 2_097_151, 2_097_152] {
            let mut config = admitted_config();
            config.provider_environment.values = vec![ProviderEnvironmentValue {
                name: "TOKEN".into(),
                value: "x".repeat(value_len),
                ..Default::default()
            }];
            let update = ConfigUpdate {
                update_id: Uuid::new_v4().to_string(),
                sandbox_config: Some(config.sandbox_config),
                provider_environment: Some(config.provider_environment),
            };
            let live = GatewayMessage {
                payload: Some(gateway_message::Payload::ConfigUpdate(update.clone())),
            };
            assert_eq!(live_message_len(update.encoded_len()), live.encoded_len());
            let bootstrap = GatewayMessage {
                payload: Some(gateway_message::Payload::SessionAccepted(SessionAccepted {
                    bootstrap: Some(update.clone()),
                    ..accepted.clone()
                })),
            };
            assert_eq!(
                bootstrap_message_len(&accepted, update.encoded_len()),
                bootstrap.encoded_len()
            );
        }
    }

    /// Register a streamed-apply session and return its outbound channel.
    fn register_apply_session(
        registry: &SupervisorSessionRegistry,
        sandbox_id: &str,
        session_id: &str,
    ) -> mpsc::Receiver<GatewayMessage> {
        register_apply_session_with_outbound(registry, sandbox_id, session_id).1
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

    /// Answer the bootstrap in flight on `session_id` with `outcome`.
    fn answer_bootstrap(
        registry: &SupervisorSessionRegistry,
        sandbox_id: &str,
        session_id: &str,
        bootstrap: &ConfigUpdate,
        outcome: ConfigApplyOutcome,
    ) {
        let completed = registry
            .complete_config_update(sandbox_id, session_id, &update_result(bootstrap, outcome))
            .unwrap();
        registry.finalize_config_update(sandbox_id, session_id, &completed, true);
    }

    /// Register a push session accepted with `bootstrap` in flight.
    fn register_bootstrapped_session(
        registry: &SupervisorSessionRegistry,
        sandbox_id: &str,
        session_id: &str,
        bootstrap: SupervisorConfig,
    ) -> (mpsc::Receiver<GatewayMessage>, ConfigUpdate) {
        let slots = register_apply_session(registry, sandbox_id, session_id);
        let (update, in_flight) = bootstrap_update(bootstrap, &SessionAccepted::default());
        registry.begin_config_bootstrap(sandbox_id, session_id, in_flight, None);
        (slots, update)
    }

    #[test]
    fn rebuild_racing_the_bootstrap_waits_and_is_dropped_when_unchanged() {
        let registry = SupervisorSessionRegistry::new();
        let (mut slots, bootstrap) =
            register_bootstrapped_session(&registry, "sb-1", "session-1", config(7));

        // The configuration the bootstrap carried is held, then dropped.
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", config(7)),
            DeliveryDisposition::Coalesced
        );
        answer_bootstrap(
            &registry,
            "sb-1",
            "session-1",
            &bootstrap,
            ConfigApplyOutcome::Applied,
        );
        assert!(take_update(&mut slots).is_none());
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", config(7)),
            DeliveryDisposition::SuppressedUnchanged
        );

        // Newer configuration held behind the bootstrap is sent once it lands.
        let (mut slots, bootstrap) =
            register_bootstrapped_session(&registry, "sb-1", "session-2", config(7));
        assert_eq!(
            registry.deliver_config("sb-1", "session-2", config(8)),
            DeliveryDisposition::Coalesced
        );
        answer_bootstrap(
            &registry,
            "sb-1",
            "session-2",
            &bootstrap,
            ConfigApplyOutcome::Applied,
        );
        let released = take_update(&mut slots).expect("newer configuration is sent");
        assert_eq!(config_revision(&released), 8);
    }

    #[test]
    fn session_that_stops_draining_its_stream_is_closed() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, _rx) = mpsc::channel(1);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        registry.register_with_mode(
            "sb-1".into(),
            "session-1".into(),
            tx.clone(),
            shutdown_tx,
            SessionMode::Push,
        );
        tx.try_send(GatewayMessage::default()).unwrap();

        assert_eq!(
            registry.deliver_config("sb-1", "session-1", config(7)),
            DeliveryDisposition::StreamClosed
        );
        assert!(
            shutdown_rx.try_recv().is_ok(),
            "the session's task is told to end"
        );
        assert!(
            registry.is_current_session("sb-1", "session-1"),
            "the task's cleanup removes the session and records the disconnect"
        );
    }

    #[test]
    fn bootstrap_result_acknowledges_only_an_applied_configuration() {
        let registry = SupervisorSessionRegistry::new();
        let (mut slots, bootstrap) =
            register_bootstrapped_session(&registry, "sb-1", "session-1", config(7));
        answer_bootstrap(
            &registry,
            "sb-1",
            "session-1",
            &bootstrap,
            ConfigApplyOutcome::FailedClosed,
        );
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", config(7)),
            DeliveryDisposition::Queued,
            "a failed bootstrap leaves its configuration eligible for repair"
        );
        assert!(take_update(&mut slots).is_some());

        let (mut slots, bootstrap) =
            register_bootstrapped_session(&registry, "sb-1", "session-2", config(7));
        answer_bootstrap(
            &registry,
            "sb-1",
            "session-2",
            &bootstrap,
            ConfigApplyOutcome::Applied,
        );
        assert_eq!(
            registry.deliver_config("sb-1", "session-2", config(7)),
            DeliveryDisposition::SuppressedUnchanged
        );
        assert!(take_update(&mut slots).is_none());
    }

    #[test]
    fn rejected_configuration_stays_eligible_for_reconciliation_until_applied() {
        let registry = SupervisorSessionRegistry::new();
        let mut slots = register_apply_session(&registry, "sb-1", "session-1");
        let mut report = |outcome| {
            assert_eq!(
                registry.deliver_config("sb-1", "session-1", config(7)),
                DeliveryDisposition::Queued
            );
            let update = take_update(&mut slots).expect("update");
            let completed = registry
                .complete_config_update("sb-1", "session-1", &update_result(&update, outcome))
                .unwrap();
            registry.finalize_config_update("sb-1", "session-1", &completed, true);
        };

        report(ConfigApplyOutcome::FailedRetainedLastKnownGood);
        report(ConfigApplyOutcome::Applied);
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", config(7)),
            DeliveryDisposition::SuppressedUnchanged
        );
    }

    #[test]
    fn degraded_configuration_is_delivered_again_until_applied() {
        let registry = SupervisorSessionRegistry::new();
        let (mut slots, bootstrap) =
            register_bootstrapped_session(&registry, "sb-1", "session-1", config(7));
        answer_bootstrap(
            &registry,
            "sb-1",
            "session-1",
            &bootstrap,
            ConfigApplyOutcome::Degraded,
        );
        let mut report = |outcome| {
            assert_eq!(
                registry.deliver_config("sb-1", "session-1", config(7)),
                DeliveryDisposition::Queued,
                "a degraded runtime reload stays eligible for reconciliation"
            );
            let update = take_update(&mut slots).expect("update");
            let completed = registry
                .complete_config_update("sb-1", "session-1", &update_result(&update, outcome))
                .unwrap();
            registry.finalize_config_update("sb-1", "session-1", &completed, true);
        };

        report(ConfigApplyOutcome::Degraded);
        report(ConfigApplyOutcome::IgnoredDuplicate);
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", config(7)),
            DeliveryDisposition::SuppressedUnchanged
        );
    }

    #[test]
    fn unmatched_result_leaves_the_update_in_flight() {
        let registry = SupervisorSessionRegistry::new();
        let mut slots = register_apply_session(&registry, "sb-1", "session-1");
        registry.deliver_config("sb-1", "session-1", config(7));
        let update = take_update(&mut slots).expect("update");
        let mut stale = update_result(&update, ConfigApplyOutcome::Applied);
        stale.update_id = "other".into();
        assert!(
            registry
                .complete_config_update("sb-1", "session-1", &stale)
                .is_err()
        );
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", config(8)),
            DeliveryDisposition::Coalesced
        );
    }

    #[test]
    fn unknown_outcome_does_not_acknowledge_the_update() {
        let registry = SupervisorSessionRegistry::new();
        let mut slots = register_apply_session(&registry, "sb-1", "session-1");
        for outcome in [ConfigApplyOutcome::Unspecified.into(), 1_000] {
            registry.deliver_config("sb-1", "session-1", config(7));
            let update = take_update(&mut slots).expect("update");
            let mut result = update_result(&update, ConfigApplyOutcome::Applied);
            result.outcome = outcome;
            let completed = registry
                .complete_config_update("sb-1", "session-1", &result)
                .unwrap();
            assert_eq!(completed.outcome, ConfigApplyOutcome::Unsupported);
            registry.finalize_config_update("sb-1", "session-1", &completed, true);
        }
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", config(7)),
            DeliveryDisposition::Queued,
            "the configuration stays eligible for repair"
        );
    }

    /// A sandbox configuration that settles sandbox policy version 3.
    fn sandbox_policy_snapshot() -> SandboxConfigSnapshot {
        SandboxConfigSnapshot {
            configuration_instance_id: "configuration-1".into(),
            configuration_admitted: true,
            config_revision: 7,
            version: 3,
            policy_hash: "policy-hash".into(),
            provider_env_revision: 5,
            policy_source: PolicySource::Sandbox.into(),
            ..Default::default()
        }
    }

    async fn put_sandbox_policy_revision(state: &Arc<ServerState>, sandbox_id: &str) {
        use crate::policy_store::PolicyStoreExt as _;

        state
            .store
            .put_policy_revision(
                "policy-3",
                sandbox_id,
                "default",
                3,
                &SandboxPolicy::default().encode_to_vec(),
                "policy-hash",
            )
            .await
            .unwrap();
    }

    /// Register `session-1`, streaming to `tx`, as the push session of a
    /// running workload.
    fn register_running_push_session(
        state: &Arc<ServerState>,
        sandbox_id: &str,
        tx: &mpsc::Sender<GatewayMessage>,
    ) {
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        state.supervisor_sessions.register_with_mode(
            sandbox_id.into(),
            "session-1".into(),
            tx.clone(),
            shutdown_tx,
            SessionMode::Push,
        );
    }

    /// What a supervisor reports for `update`: the admission its outcome
    /// implies, and a policy load result for a sandbox policy revision.
    fn reported_result(update: &ConfigUpdate, outcome: ConfigApplyOutcome) -> ConfigUpdateResult {
        use openshell_core::proto::{ConfigApplyFailure, ConfigurationAdmissionState};

        let snapshot = update.sandbox_config.as_ref().unwrap();
        let applied = outcome_acknowledges_revision(outcome);
        let mut admission = expected_configuration_admission(snapshot);
        if !applied {
            admission.state = ConfigurationAdmissionState::Rejected.into();
        }
        ConfigUpdateResult {
            update_id: update.update_id.clone(),
            outcome: outcome.into(),
            failure: (!applied).then(|| ConfigApplyFailure {
                code: "policy_rejected".into(),
                message: "policy rejected".into(),
                retryable: true,
            }),
            admission: Some(admission),
            // A duplicate changes no policy, so it reports no load.
            policy_load: (snapshot.policy_source == i32::from(PolicySource::Sandbox)
                && snapshot.version > 0
                && outcome != ConfigApplyOutcome::IgnoredDuplicate)
                .then(|| PolicyLoadResult {
                    version: snapshot.version,
                    loaded: applied,
                    error: if applied {
                        String::new()
                    } else {
                        "policy rejected".into()
                    },
                }),
        }
    }

    /// Deliver `snapshot` to `session-1` and return the supervisor's result
    /// for the update it receives.
    fn deliver_and_report(
        state: &Arc<ServerState>,
        sandbox_id: &str,
        outbound: &mut mpsc::Receiver<GatewayMessage>,
        snapshot: &SandboxConfigSnapshot,
        outcome: ConfigApplyOutcome,
    ) -> ConfigUpdateResult {
        let config = SupervisorConfig {
            sandbox_config: snapshot.clone(),
            provider_environment: ProviderEnvironmentSnapshot::default(),
        };
        assert_eq!(
            state
                .supervisor_sessions
                .deliver_config(sandbox_id, "session-1", config),
            DeliveryDisposition::Queued
        );
        reported_result(&take_update(outbound).expect("update"), outcome)
    }

    /// Push a sandbox policy update to a running workload and return the
    /// supervisor's result for it.
    async fn running_push_session_result(
        state: &Arc<ServerState>,
        sandbox_id: &str,
        tx: &mpsc::Sender<GatewayMessage>,
        outbound: &mut mpsc::Receiver<GatewayMessage>,
    ) -> (ConfigUpdateResult, SandboxConfigurationAdmission) {
        put_sandbox_policy_revision(state, sandbox_id).await;
        register_running_push_session(state, sandbox_id, tx);
        let snapshot = sandbox_policy_snapshot();
        let result = deliver_and_report(
            state,
            sandbox_id,
            outbound,
            &snapshot,
            ConfigApplyOutcome::Applied,
        );
        (result, expected_configuration_admission(&snapshot))
    }

    fn sandbox_admission(sandbox: &Sandbox) -> Option<&SandboxConfigurationAdmission> {
        sandbox
            .status
            .as_ref()
            .and_then(|status| status.configuration_admission.as_ref())
    }

    async fn stored_sandbox(state: &Arc<ServerState>, sandbox_id: &str) -> Sandbox {
        state
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .unwrap()
            .expect("sandbox")
    }

    #[tokio::test]
    async fn running_workload_results_are_written_inline_without_an_acknowledgement() {
        use crate::policy_store::PolicyStoreExt as _;

        let sandbox_id = "sb-running-result";
        let state = push_state_with_sandbox(sandbox_id).await;
        let (tx, mut rx) = mpsc::channel(4);
        let (result, admission) =
            running_push_session_result(&state, sandbox_id, &tx, &mut rx).await;

        assert!(
            handle_config_update_result(&accepted_session(&state, sandbox_id, tx.clone()), &result)
                .await
        );

        assert!(
            rx.try_recv().is_err(),
            "a running workload's supervisor needs no admission"
        );
        assert_eq!(
            sandbox_admission(&stored_sandbox(&state, sandbox_id).await),
            Some(&admission)
        );
        let policy = state
            .store
            .get_policy_by_version(sandbox_id, 3)
            .await
            .unwrap()
            .expect("policy revision");
        assert_eq!(policy.status, "loaded");
    }

    #[tokio::test]
    async fn running_workload_admission_is_written_when_it_changes() {
        let sandbox_id = "sb-running-admission";
        let state = push_state_with_sandbox(sandbox_id).await;
        let (tx, mut rx) = mpsc::channel(4);
        register_running_push_session(&state, sandbox_id, &tx);
        let session = accepted_session(&state, sandbox_id, tx);
        // No sandbox policy, so the admission is the only result to persist.
        let snapshot = |config_revision| SandboxConfigSnapshot {
            config_revision,
            policy_source: PolicySource::Unspecified.into(),
            ..sandbox_policy_snapshot()
        };
        let mut report = |config_revision, outcome| {
            deliver_and_report(
                &state,
                sandbox_id,
                &mut rx,
                &snapshot(config_revision),
                outcome,
            )
        };
        let resource_version = |sandbox: &Sandbox| {
            sandbox
                .metadata
                .as_ref()
                .map(|metadata| metadata.resource_version)
        };

        let rejected = report(7, ConfigApplyOutcome::FailedRetainedLastKnownGood);
        assert!(handle_config_update_result(&session, &rejected).await);
        let stored = stored_sandbox(&state, sandbox_id).await;
        assert_eq!(
            sandbox_admission(&stored).map(|admission| admission.state),
            Some(i32::from(
                openshell_core::proto::ConfigurationAdmissionState::Rejected
            ))
        );

        // The unacknowledged configuration is delivered again and rejected
        // again, which leaves the stored admission alone.
        let redelivered = report(7, ConfigApplyOutcome::FailedRetainedLastKnownGood);
        assert!(handle_config_update_result(&session, &redelivered).await);
        assert_eq!(
            resource_version(&stored_sandbox(&state, sandbox_id).await),
            resource_version(&stored)
        );

        let accepted = report(8, ConfigApplyOutcome::Applied);
        assert!(handle_config_update_result(&session, &accepted).await);
        let stored = stored_sandbox(&state, sandbox_id).await;
        let admission = sandbox_admission(&stored).expect("admission");
        assert_eq!(
            admission.state,
            i32::from(openshell_core::proto::ConfigurationAdmissionState::Accepted)
        );
        assert_eq!(admission.config_revision, 8);
    }

    #[tokio::test]
    async fn replaced_session_result_persists_nothing() {
        let sandbox_id = "sb-replaced-result";
        let state = push_state_with_sandbox(sandbox_id).await;
        let (tx, mut rx) = mpsc::channel(4);
        let (result, _) = running_push_session_result(&state, sandbox_id, &tx, &mut rx).await;
        let (replacement_tx, _replacement_rx) = mpsc::channel(4);
        state.supervisor_sessions.register_with_mode(
            sandbox_id.into(),
            "session-2".into(),
            replacement_tx,
            make_shutdown(),
            SessionMode::Push,
        );

        assert!(
            !handle_config_update_result(&accepted_session(&state, sandbox_id, tx), &result).await
        );
        assert!(
            sandbox_admission(&stored_sandbox(&state, sandbox_id).await).is_none(),
            "an admission from a replaced session must not be persisted"
        );
    }

    /// Fail every update of the named record type, as a database outage
    /// would.
    const FAIL_POLICY_RECORD_WRITES: &str = r#"
CREATE TRIGGER fail_result_writes BEFORE UPDATE ON "objects"
WHEN OLD."object_type" = 'sandbox_policy'
BEGIN SELECT RAISE(ABORT, 'database unavailable'); END;
"#;
    const FAIL_SANDBOX_RECORD_WRITES: &str = r#"
CREATE TRIGGER fail_result_writes BEFORE UPDATE ON "objects"
WHEN OLD."object_type" = 'sandbox'
BEGIN SELECT RAISE(ABORT, 'database unavailable'); END;
"#;
    const RESTORE_RESULT_WRITES: &str = "DROP TRIGGER fail_result_writes;";

    /// A running workload applies `snapshot` while `failing_writes` makes
    /// every attempt to persist its result fail. Once writes recover,
    /// reconciliation must redeliver the unchanged configuration so the
    /// supervisor reports the result again.
    async fn reconcile_after_result_writes_fail(
        state: &Arc<ServerState>,
        sandbox_id: &str,
        snapshot: &SandboxConfigSnapshot,
        failing_writes: &'static str,
    ) {
        let (tx, mut rx) = mpsc::channel(4);
        register_running_push_session(state, sandbox_id, &tx);
        let session = accepted_session(state, sandbox_id, tx);

        state.store.execute_for_test(failing_writes).await;
        let applied = deliver_and_report(
            state,
            sandbox_id,
            &mut rx,
            snapshot,
            ConfigApplyOutcome::Applied,
        );
        handle_config_update_result(&session, &applied).await;
        state.store.execute_for_test(RESTORE_RESULT_WRITES).await;

        // The supervisor already applied the configuration and reports a
        // duplicate.
        let duplicate = deliver_and_report(
            state,
            sandbox_id,
            &mut rx,
            snapshot,
            ConfigApplyOutcome::IgnoredDuplicate,
        );
        handle_config_update_result(&session, &duplicate).await;
    }

    #[tokio::test]
    async fn reconciliation_recovers_a_dropped_policy_result() {
        use crate::policy_store::PolicyStoreExt as _;

        let sandbox_id = "sb-dropped-policy-result";
        let state = push_state_with_sandbox(sandbox_id).await;
        put_sandbox_policy_revision(&state, sandbox_id).await;

        reconcile_after_result_writes_fail(
            &state,
            sandbox_id,
            &sandbox_policy_snapshot(),
            FAIL_POLICY_RECORD_WRITES,
        )
        .await;

        let policy = state
            .store
            .get_policy_by_version(sandbox_id, 3)
            .await
            .unwrap()
            .expect("policy revision");
        assert_eq!(policy.status, "loaded");
        let sandbox = state
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .unwrap()
            .expect("sandbox");
        assert_eq!(sandbox.current_policy_version(), 3);
    }

    fn sandbox_policy_config() -> SupervisorConfig {
        SupervisorConfig {
            sandbox_config: sandbox_policy_snapshot(),
            provider_environment: ProviderEnvironmentSnapshot::default(),
        }
    }

    #[tokio::test]
    async fn reconnect_bootstrap_settles_a_policy_load_lost_with_the_previous_session() {
        use crate::policy_store::PolicyStoreExt as _;

        let sandbox_id = "sb-lost-policy-load";
        let state = push_state_with_sandbox(sandbox_id).await;
        put_sandbox_policy_revision(&state, sandbox_id).await;

        // The supervisor loads policy version 3, but writing its load result
        // fails, and the session ends before reconciliation delivers the
        // configuration again.
        let (tx, mut rx) = mpsc::channel(4);
        register_running_push_session(&state, sandbox_id, &tx);
        state
            .store
            .execute_for_test(FAIL_POLICY_RECORD_WRITES)
            .await;
        let applied = deliver_and_report(
            &state,
            sandbox_id,
            &mut rx,
            &sandbox_policy_snapshot(),
            ConfigApplyOutcome::Applied,
        );
        handle_config_update_result(&accepted_session(&state, sandbox_id, tx), &applied).await;
        state.store.execute_for_test(RESTORE_RESULT_WRITES).await;
        state
            .supervisor_sessions
            .remove_if_current(sandbox_id, "session-1");
        let lost = state
            .store
            .get_policy_by_version(sandbox_id, 3)
            .await
            .unwrap()
            .expect("policy revision");
        assert_eq!(lost.status, "pending");

        // The reconnect's bootstrap carries the same configuration, which
        // the supervisor already enforces, so it reports no load.
        let (tx, _rx) = mpsc::channel(4);
        register_running_push_session(&state, sandbox_id, &tx);
        let bootstrap = begin_bootstrap(&state, sandbox_id, sandbox_policy_config());
        let duplicate = reported_result(&bootstrap, ConfigApplyOutcome::IgnoredDuplicate);
        assert_eq!(duplicate.policy_load, None);
        assert!(
            handle_config_update_result(&accepted_session(&state, sandbox_id, tx), &duplicate)
                .await
        );

        let policy = state
            .store
            .get_policy_by_version(sandbox_id, 3)
            .await
            .unwrap()
            .expect("policy revision");
        assert_eq!(policy.status, "loaded");
        assert_eq!(
            stored_sandbox(&state, sandbox_id)
                .await
                .current_policy_version(),
            3
        );
    }

    #[tokio::test]
    async fn reconnect_bootstrap_leaves_a_settled_policy_load_alone() {
        let sandbox_id = "sb-settled-policy-load";
        let state = push_state_with_sandbox(sandbox_id).await;
        put_sandbox_policy_revision(&state, sandbox_id).await;
        record_policy_load(
            &state,
            sandbox_id,
            &PolicyLoadResult {
                version: 3,
                loaded: true,
                error: String::new(),
            },
        )
        .await
        .unwrap();

        // The reconnect starts from the stored admission, so only a policy
        // write could change the sandbox record.
        let (tx, _rx) = mpsc::channel(4);
        register_running_push_session(&state, sandbox_id, &tx);
        let (bootstrap, in_flight) =
            bootstrap_update(sandbox_policy_config(), &SessionAccepted::default());
        state.supervisor_sessions.begin_config_bootstrap(
            sandbox_id,
            "session-1",
            in_flight,
            Some(expected_configuration_admission(&sandbox_policy_snapshot())),
        );
        let before = stored_sandbox(&state, sandbox_id).await;
        assert!(
            handle_config_update_result(
                &accepted_session(&state, sandbox_id, tx),
                &reported_result(&bootstrap, ConfigApplyOutcome::IgnoredDuplicate),
            )
            .await
        );

        let after = stored_sandbox(&state, sandbox_id).await;
        assert_eq!(
            after.metadata.as_ref().unwrap().resource_version,
            before.metadata.as_ref().unwrap().resource_version,
            "a settled policy revision takes no sandbox write"
        );
    }

    #[tokio::test]
    async fn reconciliation_recovers_a_dropped_admission() {
        let sandbox_id = "sb-dropped-admission";
        let state = push_state_with_sandbox(sandbox_id).await;
        // No sandbox policy, so the admission is the only result to persist.
        let snapshot = SandboxConfigSnapshot {
            policy_source: PolicySource::Unspecified.into(),
            ..sandbox_policy_snapshot()
        };

        reconcile_after_result_writes_fail(
            &state,
            sandbox_id,
            &snapshot,
            FAIL_SANDBOX_RECORD_WRITES,
        )
        .await;

        let sandbox = state
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .unwrap()
            .expect("sandbox");
        assert_eq!(
            sandbox
                .status
                .as_ref()
                .and_then(|status| status.configuration_admission.as_ref()),
            Some(&expected_configuration_admission(&snapshot))
        );
    }

    #[tokio::test]
    async fn reported_policy_load_failure_is_recorded() {
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
        record_policy_load(
            &state,
            "sb-policy-result",
            &PolicyLoadResult {
                version: 3,
                loaded: false,
                error: "x".repeat(2_000),
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

    /// Register a streamed-apply session whose outbound channel stays open
    /// for as long as the returned receiver lives.
    fn register_apply_session_in_state(
        state: &ServerState,
        sandbox_id: &str,
    ) -> (mpsc::Sender<GatewayMessage>, mpsc::Receiver<GatewayMessage>) {
        register_apply_session_with_outbound(&state.supervisor_sessions, sandbox_id, "session-1")
    }

    fn admitted_config() -> SupervisorConfig {
        SupervisorConfig {
            sandbox_config: SandboxConfigSnapshot {
                configuration_instance_id: "configuration-1".into(),
                configuration_admitted: true,
                config_revision: 7,
                provider_env_revision: 11,
                ..Default::default()
            },
            provider_environment: ProviderEnvironmentSnapshot {
                provider_env_revision: 11,
                ..Default::default()
            },
        }
    }

    async fn current_config(state: &Arc<ServerState>, sandbox_id: &str) -> SupervisorConfig {
        let sandbox = state
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .unwrap()
            .expect("sandbox exists");
        let bootstrap = build_config_bootstrap(state, &sandbox).await.unwrap();
        assert_eq!(bootstrap.outcome, BootstrapOutcome::Built);
        bootstrap.config
    }

    /// Put `config` in flight on `session-1` as its bootstrap.
    fn begin_bootstrap(
        state: &ServerState,
        sandbox_id: &str,
        config: SupervisorConfig,
    ) -> ConfigUpdate {
        let (update, in_flight) = bootstrap_update(config, &SessionAccepted::default());
        state
            .supervisor_sessions
            .begin_config_bootstrap(sandbox_id, "session-1", in_flight, None);
        update
    }

    async fn push_state_with_sandbox_spec(sandbox_id: &str) -> Arc<ServerState> {
        let state = push_state().await;
        let mut sandbox = sandbox_record(sandbox_id, sandbox_id);
        sandbox.spec = Some(SandboxSpec::default());
        state.store.put_message(&sandbox).await.unwrap();
        state
    }

    #[tokio::test]
    async fn persisted_bootstrap_result_suppresses_unchanged_reconciliation() {
        let state = push_state_with_sandbox_spec("sb-bootstrap-ack").await;
        let (tx, mut rx) = register_apply_session_in_state(&state, "sb-bootstrap-ack");
        let config = current_config(&state, "sb-bootstrap-ack").await;
        let bootstrap = begin_bootstrap(&state, "sb-bootstrap-ack", config.clone());

        assert!(
            handle_config_update_result(
                &accepted_session(&state, "sb-bootstrap-ack", tx),
                &applied_result(&bootstrap),
            )
            .await
        );
        assert_eq!(
            state
                .supervisor_sessions
                .deliver_config("sb-bootstrap-ack", "session-1", config),
            DeliveryDisposition::SuppressedUnchanged
        );
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn reconnect_reporting_the_stored_admission_writes_nothing() {
        let sandbox_id = "sb-reconnect";
        let state = push_state_with_sandbox_spec(sandbox_id).await;
        let config = current_config(&state, sandbox_id).await;

        // The first session persists its admission.
        let (tx, _rx) = register_apply_session_in_state(&state, sandbox_id);
        let bootstrap = begin_bootstrap(&state, sandbox_id, config.clone());
        assert!(
            handle_config_update_result(
                &accepted_session(&state, sandbox_id, tx),
                &applied_result(&bootstrap),
            )
            .await
        );
        let stored = stored_sandbox(&state, sandbox_id).await;
        let admission = sandbox_admission(&stored).cloned().expect("admission");

        // The reconnect starts from the stored admission and reports it again.
        let (tx, _rx) = register_apply_session_in_state(&state, sandbox_id);
        let (update, in_flight) = bootstrap_update(config, &SessionAccepted::default());
        state.supervisor_sessions.begin_config_bootstrap(
            sandbox_id,
            "session-1",
            in_flight,
            Some(admission),
        );
        assert!(
            handle_config_update_result(
                &accepted_session(&state, sandbox_id, tx),
                &applied_result(&update),
            )
            .await
        );
        let unchanged = stored_sandbox(&state, sandbox_id).await;
        assert_eq!(
            unchanged.metadata.as_ref().unwrap().resource_version,
            stored.metadata.as_ref().unwrap().resource_version,
            "an unchanged admission takes no sandbox write"
        );
    }

    #[tokio::test]
    async fn result_answering_no_update_in_flight_closes_the_session() {
        let state = push_state_with_sandbox("sb-unmatched").await;
        let (tx, _rx) = register_apply_session_in_state(&state, "sb-unmatched");
        let result = ConfigUpdateResult {
            update_id: "unknown".into(),
            outcome: ConfigApplyOutcome::Applied.into(),
            ..Default::default()
        };

        assert!(
            !handle_config_update_result(&accepted_session(&state, "sb-unmatched", tx), &result)
                .await
        );
    }

    #[tokio::test]
    async fn invalid_bootstrap_admission_closes_the_session_without_acknowledging() {
        let state = push_state_with_sandbox("sb-bootstrap-invalid").await;
        let (tx, mut rx) = register_apply_session_in_state(&state, "sb-bootstrap-invalid");
        let config = admitted_config();
        let bootstrap = begin_bootstrap(&state, "sb-bootstrap-invalid", config.clone());
        let mut result = applied_result(&bootstrap);
        result.admission.as_mut().unwrap().config_revision = 8;

        assert!(
            !handle_config_update_result(
                &accepted_session(&state, "sb-bootstrap-invalid", tx),
                &result,
            )
            .await,
            "a mismatched admission closes the session"
        );
        // The bootstrap was not acknowledged, so it remains eligible.
        assert_eq!(
            state
                .supervisor_sessions
                .deliver_config("sb-bootstrap-invalid", "session-1", config),
            DeliveryDisposition::Queued
        );
        assert!(take_update(&mut rx).is_some());
    }

    #[test]
    fn fingerprint_covers_the_provider_environment_the_configuration_names() {
        let registry = SupervisorSessionRegistry::new();
        let snapshot = SandboxConfigSnapshot {
            configuration_admitted: true,
            config_revision: 7,
            provider_env_revision: 11,
            provider_attachment_epoch: "epoch-1".into(),
            policy_hash: "policy-1".into(),
            ..Default::default()
        };
        let with = |snapshot: SandboxConfigSnapshot| SupervisorConfig {
            sandbox_config: snapshot,
            provider_environment: ProviderEnvironmentSnapshot::default(),
        };
        let changes = [
            SandboxConfigSnapshot {
                provider_env_revision: 12,
                ..snapshot.clone()
            },
            SandboxConfigSnapshot {
                provider_attachment_epoch: "epoch-2".into(),
                ..snapshot.clone()
            },
            SandboxConfigSnapshot {
                policy_hash: "policy-2".into(),
                ..snapshot.clone()
            },
        ];
        for (index, changed) in changes.into_iter().enumerate() {
            let session_id = format!("session-{index}");
            let (mut slots, bootstrap) = register_bootstrapped_session(
                &registry,
                "sb-1",
                &session_id,
                with(snapshot.clone()),
            );
            answer_bootstrap(
                &registry,
                "sb-1",
                &session_id,
                &bootstrap,
                ConfigApplyOutcome::Applied,
            );
            assert_eq!(
                registry.deliver_config("sb-1", &session_id, with(snapshot.clone())),
                DeliveryDisposition::SuppressedUnchanged
            );
            assert_eq!(
                registry.deliver_config("sb-1", &session_id, with(changed)),
                DeliveryDisposition::Queued
            );
            assert!(take_update(&mut slots).is_some());
        }
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
            panic!("expected SessionAccepted");
        };
        assert!(!accepted.config_push_enabled);
        assert!(accepted.bootstrap.is_none());
    }

    #[tokio::test]
    async fn push_session_is_ready_on_accept() {
        use openshell_core::proto::SandboxPhase;

        let sandbox_id = "sb-push-ready";
        let state = push_state_with_sandbox_spec(sandbox_id).await;
        let mut harness = crate::grpc::test_support::connect_supervisor_stream(
            &state,
            sandbox_id,
            StreamFeatures::Apply,
        )
        .await
        .expect("push supervisor connects");

        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected SessionAccepted");
        };
        assert!(accepted.config_push_enabled);
        assert!(accepted.bootstrap.is_some());
        // The supervisor connects once its workload runs, so the sandbox is
        // ready before the bootstrap is answered.
        assert_eq!(
            stored_sandbox(&state, sandbox_id).await.phase(),
            SandboxPhase::Ready as i32
        );
    }

    #[test]
    fn unrecorded_policy_loads_keep_success_and_coalesce_newer_results() {
        let mut pending = UnrecordedPolicyLoads::default();
        for version in 1..=100 {
            pending.keep(PolicyLoadResult {
                version,
                loaded: true,
                error: String::new(),
            });
        }
        for version in 101..=200 {
            pending.keep(PolicyLoadResult {
                version,
                loaded: false,
                error: "rejected".repeat(1024),
            });
        }
        let results = pending.take();
        assert_eq!(results.len(), 2);
        assert_eq!((results[0].version, results[0].loaded), (100, true));
        assert_eq!((results[1].version, results[1].loaded), (200, false));
        assert_eq!(results[1].error.len(), 1024);
        assert!(pending.take().is_empty());

        for (version, loaded) in [(201, true), (202, false), (203, true)] {
            pending.keep(PolicyLoadResult {
                version,
                loaded,
                error: String::new(),
            });
        }
        assert_eq!(
            pending.take(),
            vec![
                PolicyLoadResult {
                    version: 202,
                    loaded: false,
                    error: String::new()
                },
                PolicyLoadResult {
                    version: 203,
                    loaded: true,
                    error: String::new()
                }
            ]
        );
    }

    async fn assert_policy_load_recovery(
        results: &[(u32, bool)],
        expected_statuses: &[(u32, &str)],
        active_version: u32,
    ) {
        use crate::policy_store::PolicyStoreExt as _;

        let sandbox_id = "sb-unrecorded-success";
        let state = push_state_with_sandbox_spec(sandbox_id).await;
        put_sandbox_policy_revision(&state, sandbox_id).await;
        let latest = results.iter().map(|(version, _)| *version).max().unwrap();
        for version in 4..=latest {
            state
                .store
                .put_policy_revision(
                    &format!("policy-{version}"),
                    sandbox_id,
                    "default",
                    i64::from(version),
                    &SandboxPolicy::default().encode_to_vec(),
                    &format!("policy-{version}-hash"),
                )
                .await
                .unwrap();
        }
        let snapshot = |version| SandboxConfigSnapshot {
            version,
            config_revision: 7 + u64::from(version - 3),
            policy_hash: format!("policy-{version}-hash"),
            ..sandbox_policy_snapshot()
        };
        let outcome = |loaded| {
            if loaded {
                ConfigApplyOutcome::Applied
            } else {
                ConfigApplyOutcome::FailedRetainedLastKnownGood
            }
        };
        let (tx, mut rx) = register_apply_session_in_state(&state, sandbox_id);
        let session = accepted_session(&state, sandbox_id, tx);
        state
            .store
            .execute_for_test(FAIL_POLICY_RECORD_WRITES)
            .await;
        for &(version, loaded) in results {
            let result = deliver_and_report(
                &state,
                sandbox_id,
                &mut rx,
                &snapshot(version),
                outcome(loaded),
            );
            assert!(handle_config_update_result(&session, &result).await);
        }
        state.store.execute_for_test(RESTORE_RESULT_WRITES).await;
        let &(version, loaded) = results.last().unwrap();
        let mut repeated = deliver_and_report(
            &state,
            sandbox_id,
            &mut rx,
            &snapshot(version),
            outcome(loaded),
        );
        repeated.policy_load = None;
        assert!(handle_config_update_result(&session, &repeated).await);
        for &(version, expected) in expected_statuses {
            let record = state
                .store
                .get_policy_by_version(sandbox_id, i64::from(version))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(record.status, expected, "policy {version}");
        }
        assert_eq!(
            stored_sandbox(&state, sandbox_id)
                .await
                .current_policy_version(),
            active_version
        );
    }

    #[tokio::test]
    async fn newer_rejection_preserves_unrecorded_success() {
        assert_policy_load_recovery(&[(3, true), (4, false)], &[(3, "loaded"), (4, "failed")], 3)
            .await;
    }

    #[tokio::test]
    async fn newer_success_preserves_unrecorded_rejection() {
        assert_policy_load_recovery(
            &[(3, true), (4, false), (5, true)],
            &[(3, "superseded"), (4, "failed"), (5, "loaded")],
            5,
        )
        .await;
    }

    #[tokio::test]
    async fn successful_retry_replaces_unrecorded_rejection_of_same_revision() {
        assert_policy_load_recovery(
            &[(3, true), (4, false), (4, true)],
            &[(3, "superseded"), (4, "loaded")],
            4,
        )
        .await;
    }

    #[tokio::test]
    async fn rejection_of_loaded_revision_preserves_its_unrecorded_success() {
        assert_policy_load_recovery(
            &[(3, true), (4, true), (4, false)],
            &[(3, "superseded"), (4, "failed")],
            4,
        )
        .await;
    }
}
