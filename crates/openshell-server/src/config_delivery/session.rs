// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Delivery protocol state for one supervisor session.
//!
//! Each configuration part has a slot. At most one update per part is
//! unanswered at a time; a newer build waits in the slot, replacing any older
//! one that has not been sent. A build the supervisor already has (or will
//! have once the unanswered update lands) is dropped, which makes rebuilding
//! cheap when nothing changed. This module is pure state: the delivery task
//! drives it and does the I/O.

use std::collections::BTreeMap;
use std::time::Duration;

use openshell_core::proto::{
    ConfigApplyOutcome, ConfigPartIdentity, ConfigPartResult, ConfigUpdate, ConfigUpdateResult,
    GetSandboxConfigResponse, GetSandboxProviderEnvironmentResponse,
};
use prost::Message as _;
use sha2::{Digest, Sha256};
use tokio::time::Instant;

use crate::gateway_metrics::ConfigPart;

/// Content fingerprint of one built part. It covers credential values, so it
/// is kept in memory only and never logged.
pub type Fingerprint = [u8; 32];

/// One built configuration part, ready to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltPart<T> {
    pub message: T,
    pub fingerprint: Fingerprint,
    pub identity: ConfigPartIdentity,
}

impl BuiltPart<GetSandboxConfigResponse> {
    pub fn sandbox_config(message: GetSandboxConfigResponse) -> Self {
        let identity = ConfigPartIdentity {
            config_revision: message.config_revision,
            policy_version: message.version,
            policy_hash: message.policy_hash.clone(),
            provider_env_revision: message.provider_env_revision,
            provider_attachment_epoch: message.provider_attachment_epoch.clone(),
        };
        let fingerprint = sandbox_config_fingerprint(&message);
        Self {
            message,
            fingerprint,
            identity,
        }
    }

    /// The provider environment identity this part needs installed with it.
    pub fn environment_identity(&self) -> EnvironmentIdentity {
        EnvironmentIdentity::of(&self.identity)
    }
}

impl BuiltPart<GetSandboxProviderEnvironmentResponse> {
    pub fn provider_environment(message: GetSandboxProviderEnvironmentResponse) -> Self {
        let identity = ConfigPartIdentity {
            config_revision: 0,
            policy_version: 0,
            policy_hash: message.policy_hash.clone(),
            provider_env_revision: message.provider_env_revision,
            provider_attachment_epoch: message.provider_attachment_epoch.clone(),
        };
        let fingerprint = provider_environment_fingerprint(&message);
        Self {
            message,
            fingerprint,
            identity,
        }
    }

    pub fn environment_identity(&self) -> EnvironmentIdentity {
        EnvironmentIdentity::of(&self.identity)
    }
}

/// What ties the two parts together: a provider environment may be installed
/// only with a policy part that names the same attachment epoch, provider
/// environment revision, and policy hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentIdentity {
    pub provider_attachment_epoch: String,
    pub provider_env_revision: u64,
    pub policy_hash: String,
}

impl EnvironmentIdentity {
    fn of(identity: &ConfigPartIdentity) -> Self {
        Self {
            provider_attachment_epoch: identity.provider_attachment_epoch.clone(),
            provider_env_revision: identity.provider_env_revision,
            policy_hash: identity.policy_hash.clone(),
        }
    }
}

fn hash_sorted_entries<'a, V: 'a>(
    hasher: &mut Sha256,
    tag: &[u8],
    entries: impl Iterator<Item = (&'a String, V)>,
    encode: impl Fn(V) -> Vec<u8>,
) {
    let sorted: BTreeMap<&String, Vec<u8>> =
        entries.map(|(key, value)| (key, encode(value))).collect();
    hasher.update(tag);
    hasher.update((sorted.len() as u64).to_le_bytes());
    for (key, value) in sorted {
        hasher.update((key.len() as u64).to_le_bytes());
        hasher.update(key.as_bytes());
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value);
    }
}

/// Protobuf map encoding follows hash-map iteration order, so maps are hashed
/// as sorted entries. The policy is covered by `policy_hash`, its canonical
/// identity.
fn sandbox_config_fingerprint(message: &GetSandboxConfigResponse) -> Fingerprint {
    let mut rest = message.clone();
    rest.policy = None;
    rest.settings.clear();
    let mut hasher = Sha256::new();
    hasher.update(b"openshell-pushed-sandbox-config-v1");
    let rest = rest.encode_to_vec();
    hasher.update((rest.len() as u64).to_le_bytes());
    hasher.update(rest);
    hash_sorted_entries(&mut hasher, b"settings", message.settings.iter(), |value| {
        value.encode_to_vec()
    });
    hasher.finalize().into()
}

fn provider_environment_fingerprint(
    message: &GetSandboxProviderEnvironmentResponse,
) -> Fingerprint {
    let mut rest = message.clone();
    rest.environment.clear();
    rest.credential_expiration_times.clear();
    rest.dynamic_credentials.clear();
    rest.static_credential_bindings.clear();
    rest.files.clear();
    rest.non_secret_environment_keys.sort();
    let mut hasher = Sha256::new();
    hasher.update(b"openshell-pushed-provider-environment-v1");
    let rest = rest.encode_to_vec();
    hasher.update((rest.len() as u64).to_le_bytes());
    hasher.update(rest);
    hash_sorted_entries(
        &mut hasher,
        b"environment",
        message.environment.iter(),
        |value| value.as_bytes().to_vec(),
    );
    hash_sorted_entries(
        &mut hasher,
        b"credential_expiration_times",
        message.credential_expiration_times.iter(),
        prost::Message::encode_to_vec,
    );
    hash_sorted_entries(
        &mut hasher,
        b"dynamic_credentials",
        message.dynamic_credentials.iter(),
        prost::Message::encode_to_vec,
    );
    hash_sorted_entries(
        &mut hasher,
        b"static_credential_bindings",
        message.static_credential_bindings.iter(),
        prost::Message::encode_to_vec,
    );
    hash_sorted_entries(&mut hasher, b"files", message.files.iter(), |value| {
        value.as_bytes().to_vec()
    });
    hasher.finalize().into()
}

#[derive(Clone, Debug)]
struct Sent<T> {
    delivery_id: u64,
    part: BuiltPart<T>,
}

/// Delivery state of one configuration part.
#[derive(Debug)]
pub struct PartSlot<T> {
    /// Sent and not yet answered.
    in_flight: Option<(Sent<T>, Instant)>,
    /// Answered `AWAITING_COMPONENT`: the supervisor holds it unapplied until
    /// the matching other part arrives.
    held: Option<Sent<T>>,
    /// Built while another update was in flight; replaced by newer builds.
    pending: Option<BuiltPart<T>>,
    /// The last part the supervisor acknowledged.
    acked: Option<(Fingerprint, ConfigPartIdentity)>,
}

impl<T> Default for PartSlot<T> {
    fn default() -> Self {
        Self {
            in_flight: None,
            held: None,
            pending: None,
            acked: None,
        }
    }
}

/// What a valid part result means for delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartEffect {
    /// The supervisor acknowledged the part.
    Acknowledged,
    /// The supervisor holds the part and needs the matching other part.
    AwaitingOther,
    /// Not acknowledged; the part must be rebuilt and sent again.
    Resend,
}

/// Why a part result was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultRejection {
    /// The result answers no update this slot is waiting on.
    UnknownDelivery,
    /// The identity differs from the part that was sent.
    IdentityMismatch,
    /// The supervisor claims to have applied a part the gateway did not admit.
    NotAdmitted,
    /// The outcome is not a valid answer.
    InvalidOutcome,
}

impl ResultRejection {
    pub const fn label(self) -> &'static str {
        match self {
            Self::UnknownDelivery => "unknown_delivery",
            Self::IdentityMismatch => "identity_mismatch",
            Self::NotAdmitted => "not_admitted",
            Self::InvalidOutcome => "invalid_outcome",
        }
    }
}

impl<T: Clone> PartSlot<T> {
    /// The fingerprint of the newest version the supervisor has or will have.
    fn latest_fingerprint(&self) -> Option<&Fingerprint> {
        self.pending
            .as_ref()
            .map(|part| &part.fingerprint)
            .or_else(|| {
                self.in_flight
                    .as_ref()
                    .map(|(sent, _)| &sent.part.fingerprint)
            })
            .or_else(|| self.held.as_ref().map(|sent| &sent.part.fingerprint))
            .or_else(|| self.acked.as_ref().map(|(fingerprint, _)| fingerprint))
    }

    /// The identity of the newest version the supervisor has or will have.
    pub fn latest_identity(&self) -> Option<&ConfigPartIdentity> {
        self.pending
            .as_ref()
            .map(|part| &part.identity)
            .or_else(|| self.in_flight.as_ref().map(|(sent, _)| &sent.part.identity))
            .or_else(|| self.held.as_ref().map(|sent| &sent.part.identity))
            .or_else(|| self.acked.as_ref().map(|(_, identity)| identity))
    }

    /// Offer a freshly built part. Returns `false` when the supervisor
    /// already has or will have exactly this content.
    pub fn offer(&mut self, part: BuiltPart<T>) -> bool {
        if self.latest_fingerprint() == Some(&part.fingerprint) {
            return false;
        }
        self.pending = Some(part);
        true
    }

    /// Offer a part the supervisor asked for again. It is dropped only when
    /// the same content is already about to be sent or awaiting an answer.
    pub fn offer_forced(&mut self, part: BuiltPart<T>) -> bool {
        let queued = self
            .pending
            .as_ref()
            .map(|pending| &pending.fingerprint)
            .or_else(|| {
                self.in_flight
                    .as_ref()
                    .map(|(sent, _)| &sent.part.fingerprint)
            });
        if queued == Some(&part.fingerprint) {
            return false;
        }
        self.pending = Some(part);
        true
    }

    /// Take the pending part if nothing is in flight.
    fn take_sendable(&mut self) -> Option<BuiltPart<T>> {
        if self.in_flight.is_some() {
            return None;
        }
        self.pending.take()
    }

    fn mark_sent(&mut self, delivery_id: u64, part: BuiltPart<T>, now: Instant) {
        // The supervisor replaces any part it holds with this one.
        self.held = None;
        self.in_flight = Some((Sent { delivery_id, part }, now));
    }

    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// When the unanswered update times out, if one is in flight.
    pub fn in_flight_deadline(&self, timeout: Duration) -> Option<Instant> {
        self.in_flight
            .as_ref()
            .map(|(_, sent_at)| *sent_at + timeout)
    }

    /// Give up on an update whose answer did not arrive in time. Returns true
    /// when one was dropped; the part must then be rebuilt or resent.
    pub fn expire(&mut self, now: Instant, timeout: Duration) -> bool {
        if self
            .in_flight
            .as_ref()
            .is_some_and(|(_, sent_at)| now >= *sent_at + timeout)
        {
            self.in_flight = None;
            return true;
        }
        false
    }

    /// Match a result to the update it answers.
    fn answer(
        &mut self,
        delivery_id: u64,
        result: &ConfigPartResult,
        admitted: impl Fn(&T) -> bool,
    ) -> Result<(PartEffect, BuiltPart<T>), ResultRejection> {
        let identity = result.identity.clone().unwrap_or_default();
        let from_in_flight = self
            .in_flight
            .as_ref()
            .is_some_and(|(sent, _)| sent.delivery_id == delivery_id);
        // A held part is completed by a later update carrying the other part.
        let from_held = !from_in_flight
            && self.held.as_ref().is_some_and(|sent| {
                sent.delivery_id < delivery_id && sent.part.identity == identity
            });
        let sent = if from_in_flight {
            &self.in_flight.as_ref().expect("checked").0
        } else if from_held {
            self.held.as_ref().expect("checked")
        } else {
            return Err(ResultRejection::UnknownDelivery);
        };
        if sent.part.identity != identity {
            return Err(ResultRejection::IdentityMismatch);
        }
        let outcome = ConfigApplyOutcome::try_from(result.outcome)
            .map_err(|_| ResultRejection::InvalidOutcome)?;
        let effect = match outcome {
            ConfigApplyOutcome::Applied
            | ConfigApplyOutcome::IgnoredDuplicate
            | ConfigApplyOutcome::Degraded => {
                if !admitted(&sent.part.message) {
                    return Err(ResultRejection::NotAdmitted);
                }
                PartEffect::Acknowledged
            }
            ConfigApplyOutcome::RetainedLocalOverride
            | ConfigApplyOutcome::FailedRetainedLastKnownGood
            | ConfigApplyOutcome::FailedClosed
            | ConfigApplyOutcome::Unsupported => PartEffect::Acknowledged,
            ConfigApplyOutcome::AwaitingComponent if from_in_flight => PartEffect::AwaitingOther,
            ConfigApplyOutcome::IgnoredStale => PartEffect::Resend,
            ConfigApplyOutcome::Unspecified | ConfigApplyOutcome::AwaitingComponent => {
                return Err(ResultRejection::InvalidOutcome);
            }
        };
        let sent = if from_in_flight {
            self.in_flight.take().expect("checked").0
        } else {
            self.held.take().expect("checked")
        };
        let part = sent.part.clone();
        match effect {
            PartEffect::Acknowledged => {
                self.acked = Some((sent.part.fingerprint, sent.part.identity));
            }
            PartEffect::AwaitingOther => self.held = Some(sent),
            PartEffect::Resend => {}
        }
        Ok((effect, part))
    }
}

/// Answer for one part of a result, after validation.
#[derive(Debug)]
pub struct AnsweredPart<T> {
    pub outcome: ConfigApplyOutcome,
    pub effect: PartEffect,
    pub part: BuiltPart<T>,
}

/// A validated result.
#[derive(Debug, Default)]
pub struct AnsweredResult {
    pub sandbox_config: Option<Result<AnsweredPart<GetSandboxConfigResponse>, ResultRejection>>,
    pub provider_environment:
        Option<Result<AnsweredPart<GetSandboxProviderEnvironmentResponse>, ResultRejection>>,
}

/// Delivery protocol state for one session.
#[derive(Debug, Default)]
pub struct SessionDelivery {
    next_delivery_id: u64,
    initial_sent: bool,
    pub sandbox_config: PartSlot<GetSandboxConfigResponse>,
    pub provider_environment: PartSlot<GetSandboxProviderEnvironmentResponse>,
}

impl SessionDelivery {
    pub const fn initial_sent(&self) -> bool {
        self.initial_sent
    }

    /// Whether the provider environment must be built along with `config`:
    /// the supervisor has, or will have, no provider environment matching it.
    pub fn needs_provider_environment(&self, config: &BuiltPart<GetSandboxConfigResponse>) -> bool {
        config.message.configuration_admitted
            && self
                .provider_environment
                .latest_identity()
                .is_none_or(|identity| {
                    EnvironmentIdentity::of(identity) != config.environment_identity()
                })
    }

    /// Build the next update from parts that can be sent now, if any.
    ///
    /// The first update of a session is the initial snapshot. It waits until
    /// the policy part is available and carries every pending part.
    pub fn next_update(&mut self, now: Instant) -> Option<ConfigUpdate> {
        if !self.initial_sent && !self.sandbox_config.has_pending() {
            return None;
        }
        let sandbox_config = self.sandbox_config.take_sendable();
        let provider_environment = self.provider_environment.take_sendable();
        if sandbox_config.is_none() && provider_environment.is_none() {
            return None;
        }
        self.next_delivery_id += 1;
        let delivery_id = self.next_delivery_id;
        let update = ConfigUpdate {
            delivery_id,
            initial: !self.initial_sent,
            sandbox_config: sandbox_config.as_ref().map(|part| part.message.clone()),
            provider_environment: provider_environment
                .as_ref()
                .map(|part| part.message.clone()),
        };
        self.initial_sent = true;
        if let Some(part) = sandbox_config {
            self.sandbox_config.mark_sent(delivery_id, part, now);
        }
        if let Some(part) = provider_environment {
            self.provider_environment.mark_sent(delivery_id, part, now);
        }
        Some(update)
    }

    /// Validate a result against the updates it answers and record it.
    pub fn answer(&mut self, result: &ConfigUpdateResult) -> AnsweredResult {
        if result.delivery_id == 0 || result.delivery_id > self.next_delivery_id {
            return AnsweredResult {
                sandbox_config: result
                    .sandbox_config
                    .as_ref()
                    .map(|_| Err(ResultRejection::UnknownDelivery)),
                provider_environment: result
                    .provider_environment
                    .as_ref()
                    .map(|_| Err(ResultRejection::UnknownDelivery)),
            };
        }
        let sandbox_config = result.sandbox_config.as_ref().map(|part| {
            self.sandbox_config
                .answer(
                    result.delivery_id,
                    part,
                    |message: &GetSandboxConfigResponse| message.configuration_admitted,
                )
                .map(|(effect, sent)| AnsweredPart {
                    outcome: ConfigApplyOutcome::try_from(part.outcome)
                        .unwrap_or(ConfigApplyOutcome::Unspecified),
                    effect,
                    part: sent,
                })
        });
        let provider_environment = result.provider_environment.as_ref().map(|part| {
            self.provider_environment
                .answer(result.delivery_id, part, |_| true)
                .map(|(effect, sent)| AnsweredPart {
                    outcome: ConfigApplyOutcome::try_from(part.outcome)
                        .unwrap_or(ConfigApplyOutcome::Unspecified),
                    effect,
                    part: sent,
                })
        });
        AnsweredResult {
            sandbox_config,
            provider_environment,
        }
    }

    /// Drop updates whose answers are overdue. Returns the parts that must
    /// be rebuilt.
    pub fn expire(&mut self, now: Instant, timeout: Duration) -> Vec<ConfigPart> {
        let mut expired = Vec::new();
        if self.sandbox_config.expire(now, timeout) {
            expired.push(ConfigPart::SandboxConfig);
        }
        if self.provider_environment.expire(now, timeout) {
            expired.push(ConfigPart::ProviderEnvironment);
        }
        expired
    }

    /// The earliest moment an unanswered update times out.
    pub fn next_expiry(&self, timeout: Duration) -> Option<Instant> {
        [
            self.sandbox_config.in_flight_deadline(timeout),
            self.provider_environment.in_flight_deadline(timeout),
        ]
        .into_iter()
        .flatten()
        .min()
    }
}
