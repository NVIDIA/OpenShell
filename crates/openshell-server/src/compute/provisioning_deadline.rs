// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-owned provisioning repair-window transitions.
//!
//! Callers must persist each transition under the sandbox lifecycle fence. Times
//! are gateway-assigned Unix milliseconds, never supervisor-supplied values.
//! The timer remains armed after admission acceptance until compute becomes Ready.

use openshell_core::proto::SandboxProvisioning;
use openshell_core::time::{timestamp_from_millis, timestamp_to_millis};
use serde::{Deserialize, Serialize};

const REPAIR_WINDOW_MS: i64 = 300_000;

/// Opaque identity of a committed effective configuration change. A -> B -> A
/// must use three different IDs even if the first and last content hashes match.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigurationChange {
    pub id: String,
    pub committed_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ProvisioningDeadline {
    attempt_id: String,
    change: ConfigurationChange,
    first_rejection_at_ms: Option<i64>,
    state: DeadlineState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum DeadlineState {
    Armed { deadline_at_ms: i64 },
    Expired { expired_at_ms: i64 },
    Ready,
}

impl ProvisioningDeadline {
    /// Decode persisted timing strictly. Invalid timing must not silently grant
    /// another repair window on every gateway restart.
    pub fn from_record(record: &SandboxProvisioning) -> Result<Self, String> {
        fn millis(value: Option<&prost_types::Timestamp>, field: &str) -> Result<i64, String> {
            let value = value.ok_or_else(|| format!("missing provisioning {field}"))?;
            timestamp_to_millis(value).map_err(|_| format!("invalid provisioning {field}"))
        }
        if record.attempt_id.is_empty() || record.configuration_change_id.is_empty() {
            return Err("missing provisioning identity".into());
        }
        if record.deadline.is_some() && record.timeout_time.is_some() {
            return Err("provisioning cannot be armed and expired".into());
        }
        let state = if record.timeout_time.is_some() {
            DeadlineState::Expired {
                expired_at_ms: millis(record.timeout_time.as_ref(), "timeout time")?,
            }
        } else if record.deadline.is_some() {
            DeadlineState::Armed {
                deadline_at_ms: millis(record.deadline.as_ref(), "deadline")?,
            }
        } else {
            DeadlineState::Ready
        };
        Ok(Self {
            attempt_id: record.attempt_id.clone(),
            change: ConfigurationChange {
                id: record.configuration_change_id.clone(),
                committed_at_ms: millis(record.configuration_change_time.as_ref(), "change time")?,
            },
            first_rejection_at_ms: record
                .first_rejection_time
                .as_ref()
                .map(|value| millis(Some(value), "rejection time"))
                .transpose()?,
            state,
        })
    }

    /// Replace timing only, preserving cleanup progress written by the worker.
    pub fn write_record(&self, record: &mut SandboxProvisioning) {
        record.attempt_id.clone_from(&self.attempt_id);
        record.configuration_change_id.clone_from(&self.change.id);
        record.configuration_change_time = timestamp_from_millis(self.change.committed_at_ms).ok();
        record.first_rejection_time = self
            .first_rejection_at_ms
            .and_then(|value| timestamp_from_millis(value).ok());
        record.deadline = self
            .deadline_at_ms()
            .and_then(|value| timestamp_from_millis(value).ok());
        record.timeout_time = match self.state {
            DeadlineState::Expired { expired_at_ms } => timestamp_from_millis(expired_at_ms).ok(),
            _ => None,
        };
    }

    pub fn new(attempt_id: String, change: ConfigurationChange, now_ms: i64) -> Self {
        Self {
            attempt_id,
            change,
            first_rejection_at_ms: None,
            state: DeadlineState::Armed {
                deadline_at_ms: now_ms.saturating_add(REPAIR_WINDOW_MS),
            },
        }
    }

    pub fn deadline_at_ms(&self) -> Option<i64> {
        match self.state {
            DeadlineState::Armed { deadline_at_ms } => Some(deadline_at_ms),
            DeadlineState::Expired { .. } | DeadlineState::Ready => None,
        }
    }

    /// Apply a newer, committed change to an active attempt. Delayed observation
    /// uses commit time, not poll time. A change after expiry cannot revive it.
    pub fn configuration_changed(&mut self, attempt_id: &str, change: ConfigurationChange) -> bool {
        let Some(deadline_at_ms) = self.deadline_at_ms() else {
            return false;
        };
        if attempt_id != self.attempt_id
            || change.id == self.change.id
            || change.committed_at_ms < self.change.committed_at_ms
            || change.committed_at_ms >= deadline_at_ms
        {
            return false;
        }
        self.state = DeadlineState::Armed {
            deadline_at_ms: deadline_at_ms
                .max(change.committed_at_ms.saturating_add(REPAIR_WINDOW_MS)),
        };
        self.change = change;
        self.first_rejection_at_ms = None;
        true
    }

    /// Only the first accepted rejection for the current change grants a repair
    /// window. Retrying, reconnecting, or changing diagnostic text does not.
    pub fn rejected(&mut self, attempt_id: &str, change_id: &str, now_ms: i64) -> bool {
        let Some(deadline_at_ms) = self.deadline_at_ms() else {
            return false;
        };
        if !self.matches(attempt_id, change_id)
            || self.first_rejection_at_ms.is_some()
            || now_ms < self.change.committed_at_ms
            || now_ms >= deadline_at_ms
        {
            return false;
        }
        self.first_rejection_at_ms = Some(now_ms);
        self.state = DeadlineState::Armed {
            deadline_at_ms: deadline_at_ms.max(now_ms.saturating_add(REPAIR_WINDOW_MS)),
        };
        true
    }

    /// Claim expiry after rechecking authoritative configuration under the same
    /// lifecycle transaction. The caller must persist cleanup intent atomically.
    pub fn expire(&mut self, attempt_id: &str, change_id: &str, now_ms: i64) -> bool {
        if !self.matches(attempt_id, change_id)
            || self
                .deadline_at_ms()
                .is_none_or(|deadline| now_ms < deadline)
        {
            return false;
        }
        self.state = DeadlineState::Expired {
            expired_at_ms: now_ms,
        };
        true
    }

    /// Ready is the successful end of provisioning; admission acceptance alone
    /// must not call this method. Late readiness requires an explicit retry.
    pub fn ready(&mut self, attempt_id: &str, change_id: &str, now_ms: i64) -> bool {
        if !self.matches(attempt_id, change_id)
            || self
                .deadline_at_ms()
                .is_none_or(|deadline| now_ms >= deadline)
        {
            return false;
        }
        self.state = DeadlineState::Ready;
        true
    }

    fn matches(&self, attempt_id: &str, change_id: &str) -> bool {
        self.attempt_id == attempt_id && self.change.id == change_id
    }
}

/// Whether compute reclamation belongs to a timed-out provisioning attempt.
pub fn timed_out(sandbox: &openshell_core::proto::Sandbox) -> bool {
    sandbox
        .status
        .as_ref()
        .and_then(|status| status.provisioning.as_ref())
        .is_some_and(|record| record.timeout_time.is_some())
}

/// Create an independent attempt. Supervisor reconnects must never call this.
pub fn new_record(now_ms: i64) -> SandboxProvisioning {
    let mut record = SandboxProvisioning::default();
    ProvisioningDeadline::new(
        uuid::Uuid::new_v4().to_string(),
        ConfigurationChange {
            id: format!("initial:{}", uuid::Uuid::new_v4()),
            committed_at_ms: now_ms,
        },
        now_ms,
    )
    .write_record(&mut record);
    record
}

/// Apply the first accepted rejection under the same CAS as admission evidence.
/// The report's generation and supervisor instance must already be validated.
pub fn record_rejection(record: &mut SandboxProvisioning, now_ms: i64) -> Result<(), String> {
    let mut deadline = ProvisioningDeadline::from_record(record)?;
    deadline.rejected(&record.attempt_id, &record.configuration_change_id, now_ms);
    deadline.write_record(record);
    Ok(())
}

pub fn allows_admission(record: &SandboxProvisioning, now_ms: i64) -> bool {
    ProvisioningDeadline::from_record(record).is_ok_and(|deadline| {
        !matches!(deadline.state, DeadlineState::Expired { .. })
            && deadline.deadline_at_ms().is_none_or(|value| now_ms < value)
    })
}

/// Readiness, not admission acceptance, ends the repair window. A late Ready
/// observation cannot win merely because the deadline scanner has not run yet.
pub(super) fn reconcile_readiness(sandbox: &mut openshell_core::proto::Sandbox, now_ms: i64) {
    use openshell_core::proto::{SandboxCondition, SandboxPhase};
    let Some(status) = sandbox.status.as_mut() else {
        return;
    };
    if status.phase != i32::from(SandboxPhase::Ready) {
        return;
    }
    let Some(record) = status.provisioning.as_mut() else {
        return;
    };
    let Ok(mut deadline) = ProvisioningDeadline::from_record(record) else {
        return;
    };
    if deadline.deadline_at_ms().is_none() {
        return;
    }
    if deadline.ready(&record.attempt_id, &record.configuration_change_id, now_ms) {
        deadline.write_record(record);
    } else {
        status.phase = SandboxPhase::Provisioning.into();
        status
            .conditions
            .retain(|condition| condition.r#type != "Ready");
        status.conditions.push(SandboxCondition {
            r#type: "Ready".into(),
            status: "False".into(),
            reason: "ProvisioningDeadlineElapsed".into(),
            message: "Provisioning deadline elapsed; awaiting compute reclamation".into(),
            ..Default::default()
        });
    }
}

/// Attachment edits are stamped in the same sandbox CAS as the spec change.
pub fn attachments_changed(sandbox: &mut openshell_core::proto::Sandbox, now_ms: i64) {
    if let Some(record) = sandbox
        .status
        .as_mut()
        .and_then(|status| status.provisioning.as_mut())
        && record.deadline.is_some()
    {
        record.attachment_change_id = uuid::Uuid::new_v4().to_string();
        record.attachment_change_time = timestamp_from_millis(now_ms).ok();
    }
}

/// Adopt legacy attempts once and reconcile committed source clocks before any
/// rejection/expiry decision. Persist the returned record with the owning CAS.
pub async fn refresh_configuration(
    store: &crate::persistence::Store,
    sandbox: &mut openshell_core::proto::Sandbox,
    now_ms: i64,
) -> Result<(), String> {
    use openshell_core::proto::SandboxPhase;
    if !matches!(
        SandboxPhase::try_from(sandbox.phase()),
        Ok(SandboxPhase::Provisioning | SandboxPhase::Starting)
    ) {
        return Ok(());
    }
    let status = sandbox.status.get_or_insert_with(Default::default);
    let record = status
        .provisioning
        .get_or_insert_with(|| new_record(now_ms));
    if record.deadline.is_none() {
        return Ok(());
    }
    let change = crate::grpc::policy::configuration_change(store, sandbox).await?;
    let record = sandbox
        .status
        .as_mut()
        .and_then(|status| status.provisioning.as_mut())
        .expect("record initialized");
    let mut deadline = ProvisioningDeadline::from_record(record)?;
    if record.configuration_change_id.starts_with("initial:") {
        // Taking the first source snapshot does not grant a second initial window.
        deadline.change.id = change.id;
    } else {
        deadline.configuration_changed(&record.attempt_id, change);
    }
    deadline.write_record(record);
    Ok(())
}

impl super::ComputeRuntime {
    pub(super) async fn provisioning_loop(
        self: std::sync::Arc<Self>,
        mut cancel: tokio::sync::watch::Receiver<bool>,
    ) {
        loop {
            tokio::select! {
                _ = cancel.changed() => return,
                result = self.reconcile_provisioning_deadlines(openshell_core::time::now_ms()) => {
                    if let Err(error) = result {
                        tracing::warn!(%error, "Provisioning deadline reconciliation failed");
                    }
                }
            }
            tokio::select! {
                _ = cancel.changed() => return,
                () = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
            }
        }
    }

    pub(super) async fn reconcile_provisioning_deadlines(&self, now_ms: i64) -> Result<(), String> {
        use crate::persistence::{ObjectListQuery, ObjectType};
        use openshell_core::{
            ObjectId,
            proto::{Sandbox, SandboxPhase},
        };
        use prost::Message;
        let records = self
            .store
            .collect_records(Sandbox::object_type(), ObjectListQuery::AllWorkspaces)
            .await
            .map_err(|error| error.to_string())?;
        for record in records {
            let candidate =
                Sandbox::decode(record.payload.as_slice()).map_err(|error| error.to_string())?;
            if !matches!(
                SandboxPhase::try_from(candidate.phase()),
                Ok(SandboxPhase::Provisioning | SandboxPhase::Starting)
            ) && !timed_out(&candidate)
            {
                continue;
            }
            // Expiration can fence Starting while its driver RPC owns the
            // lifecycle gate. Cleanup waits for that gate; Error never waits
            // for compute I/O, matching the existing driver-observation fence.
            let global = self.sync_lock.clone().lock_owned().await;
            let Some(mut current) = self
                .store
                .get_message::<Sandbox>(&record.id)
                .await
                .map_err(|e| e.to_string())?
            else {
                continue;
            };
            let previous = current.clone();
            refresh_configuration(&self.store, &mut current, now_ms).await?;
            if current != previous {
                current = self
                    .store
                    .update_message_cas::<Sandbox, _>(
                        &record.id,
                        super::sandbox_resource_version(&previous),
                        |sandbox| sandbox.status.clone_from(&current.status),
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                self.sandbox_watch_bus.notify(&record.id);
            }
            if let Some(expired) = self.claim_provisioning_timeout(&current, now_ms).await? {
                current = expired;
            }
            drop(global);
            if timed_out(&current)
                && current
                    .status
                    .as_ref()
                    .and_then(|status| status.provisioning.as_ref())
                    .is_some_and(|record| {
                        record.cleanup_completed_time.is_none()
                            && record
                                .cleanup_retry_time
                                .as_ref()
                                .and_then(|t| timestamp_to_millis(t).ok())
                                .is_none_or(|t| t <= now_ms)
                    })
            {
                let Ok(guard) = self.lifecycle_gates.gate_for(&record.id).try_lock_owned() else {
                    continue;
                };
                let gate = super::SandboxLifecycleGuard { _guard: guard };
                let runtime = self.clone();
                tokio::spawn(async move {
                    if let Err(error) = runtime.reclaim_provisioning_timeout(&current, &gate).await
                    {
                        tracing::warn!(sandbox_id = current.object_id(), %error, "Provisioning cleanup will retry");
                    }
                });
            }
        }
        Ok(())
    }

    /// Claim expiration durably before touching the backend. The caller owns the
    /// global configuration guard; CAS fences concurrent lifecycle operations.
    /// The separate cleanup step also requires the per-sandbox lifecycle gate.
    pub(crate) async fn claim_provisioning_timeout(
        &self,
        current: &openshell_core::proto::Sandbox,
        now_ms: i64,
    ) -> Result<Option<openshell_core::proto::Sandbox>, String> {
        use openshell_core::ObjectId;
        use openshell_core::proto::{Sandbox, SandboxCondition, SandboxPhase};
        if !matches!(
            SandboxPhase::try_from(current.phase()),
            Ok(SandboxPhase::Provisioning | SandboxPhase::Starting)
        ) {
            return Ok(None);
        }
        let Some(record) = current
            .status
            .as_ref()
            .and_then(|status| status.provisioning.as_ref())
        else {
            return Ok(None);
        };
        let mut deadline = ProvisioningDeadline::from_record(record)?;
        if !deadline.expire(&record.attempt_id, &record.configuration_change_id, now_ms) {
            return Ok(None);
        }
        let updated = self
            .store
            .update_message_cas::<Sandbox, _>(
                current.object_id(),
                super::sandbox_resource_version(current),
                |sandbox| {
                    let status = sandbox.status.as_mut().expect("provisioning status exists");
                    deadline.write_record(
                        status
                            .provisioning
                            .as_mut()
                            .expect("provisioning record exists"),
                    );
                    status.phase = SandboxPhase::Error.into();
                    let diagnostic = status
                        .configuration_admission
                        .as_ref()
                        .map_or("", |admission| admission.error.as_str());
                    let message = if diagnostic.is_empty() {
                        "Provisioning repair window expired after 300 seconds".to_string()
                    } else {
                        format!(
                            "Provisioning repair window expired after 300 seconds: {diagnostic}"
                        )
                    };
                    status
                        .conditions
                        .retain(|condition| condition.r#type != "Ready");
                    status.conditions.push(SandboxCondition {
                        r#type: "Ready".into(),
                        status: "False".into(),
                        reason: "ProvisioningTimedOut".into(),
                        message,
                        transition_time: timestamp_from_millis(now_ms).ok(),
                    });
                },
            )
            .await
            .map_err(|error| error.to_string())?;
        self.sandbox_index.update_from_sandbox(&updated);
        self.sandbox_watch_bus.notify(current.object_id());
        tracing::warn!(
            sandbox_id = current.object_id(),
            "Sandbox provisioning repair window expired"
        );
        Ok(Some(updated))
    }

    /// The lifecycle gate remains owned across the bounded driver call, so an
    /// explicit start cannot race an old cleanup worker. Retry intent survives
    /// cancellation, gateway restart, and a lost leader lease.
    pub(super) async fn reclaim_provisioning_timeout(
        &self,
        expired: &openshell_core::proto::Sandbox,
        lifecycle_guard: &super::SandboxLifecycleGuard,
    ) -> Result<(), String> {
        use openshell_core::proto::Sandbox;
        use openshell_core::proto::compute::v1::StopSandboxRequest;
        use openshell_core::{ObjectId, ObjectName};
        let current = {
            let _global_guard = self.lock_global_for_lifecycle(lifecycle_guard).await;
            self.store
                .get_message::<Sandbox>(expired.object_id())
                .await
                .map_err(|error| error.to_string())?
        };
        let Some(current) = current else {
            return Ok(());
        };
        let expected_attempt = expired
            .status
            .as_ref()
            .and_then(|status| status.provisioning.as_ref())
            .map(|record| record.attempt_id.as_str());
        if current.phase() != i32::from(openshell_core::proto::SandboxPhase::Error)
            || current
                .status
                .as_ref()
                .and_then(|status| status.provisioning.as_ref())
                .map(|record| record.attempt_id.as_str())
                != expected_attempt
        {
            return Ok(());
        }
        let expired = &current;
        let Some(record) = expired
            .status
            .as_ref()
            .and_then(|status| status.provisioning.as_ref())
        else {
            return Ok(());
        };
        if record.timeout_time.is_none() || record.cleanup_completed_time.is_some() {
            return Ok(());
        }
        let now_ms = openshell_core::time::now_ms();
        if record
            .cleanup_retry_time
            .as_ref()
            .map(timestamp_to_millis)
            .transpose()
            .map_err(|error| error.to_string())?
            .is_some_and(|retry| retry > now_ms)
        {
            return Ok(());
        }
        // Cross-replica cleanup claim. A replacement leader waits longer than
        // the bounded driver call before retrying an interrupted reclamation.
        {
            let _global_guard = self.lock_global_for_lifecycle(lifecycle_guard).await;
            self.store
                .update_message_cas::<Sandbox, _>(
                    expired.object_id(),
                    super::sandbox_resource_version(expired),
                    |sandbox| {
                        sandbox
                            .status
                            .as_mut()
                            .and_then(|status| status.provisioning.as_mut())
                            .expect("timeout record exists")
                            .cleanup_retry_time =
                            timestamp_from_millis(now_ms.saturating_add(35_000)).ok();
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
        }
        let sandbox_id = expired.object_id().to_string();
        let sandbox_name = expired.object_name().to_string();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.driver.call(
                openshell_otel::rpc::STOP_SANDBOX,
                Some(&sandbox_id),
                |driver| {
                    let sandbox_id = sandbox_id.clone();
                    async move {
                        driver
                            .stop_sandbox(tonic::Request::new(StopSandboxRequest {
                                sandbox_id,
                                name: sandbox_name,
                            }))
                            .await
                    }
                },
            ),
        )
        .await;
        let reclaimed = matches!(&result, Ok(Ok(_)))
            || matches!(&result, Ok(Err(error)) if error.code() == tonic::Code::NotFound);
        let _global_guard = self.lock_global_for_lifecycle(lifecycle_guard).await;
        let Some(current) = self
            .store
            .get_message::<Sandbox>(&sandbox_id)
            .await
            .map_err(|error| error.to_string())?
        else {
            return Ok(());
        };
        if !current
            .status
            .as_ref()
            .and_then(|status| status.provisioning.as_ref())
            .is_some_and(|latest| {
                latest.attempt_id == record.attempt_id && latest.timeout_time.is_some()
            })
        {
            return Ok(());
        }
        let completed_at_ms = openshell_core::time::now_ms();
        let updated = self
            .store
            .update_message_cas::<Sandbox, _>(
                &sandbox_id,
                super::sandbox_resource_version(&current),
                |sandbox| {
                    let record = sandbox
                        .status
                        .as_mut()
                        .and_then(|status| status.provisioning.as_mut())
                        .expect("timeout attempt was checked under the lifecycle gate");
                    if reclaimed {
                        record.cleanup_completed_time = timestamp_from_millis(completed_at_ms).ok();
                        record.cleanup_error.clear();
                        record.cleanup_retry_time = None;
                    } else {
                        record.cleanup_error =
                            "Compute reclamation is pending; the gateway will retry".into();
                        record.cleanup_retry_time =
                            timestamp_from_millis(completed_at_ms.saturating_add(5_000)).ok();
                    }
                },
            )
            .await
            .map_err(|error| error.to_string())?;
        if reclaimed {
            self.cleanup_stopped_sandbox_sessions(&updated).await?;
            tracing::info!(sandbox_id, "Reclaimed timed-out provisioning compute");
        }
        self.sandbox_index.update_from_sandbox(&updated);
        self.sandbox_watch_bus.notify(&sandbox_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protobuf_roundtrip_retains_deadline_and_cleanup_progress() {
        use prost::Message;
        let mut deadline = ProvisioningDeadline::new("attempt".into(), change("change", 0), 0);
        assert!(deadline.rejected("attempt", "change", 1_000));
        let mut record = SandboxProvisioning::default();
        deadline.write_record(&mut record);
        let bytes = record.encode_to_vec();
        let mut restored = SandboxProvisioning::decode(bytes.as_slice()).unwrap();
        assert_eq!(
            ProvisioningDeadline::from_record(&restored).unwrap(),
            deadline
        );
        assert!(deadline.expire("attempt", "change", 301_000));
        deadline.write_record(&mut restored);
        restored.cleanup_error = "retry pending".into();
        restored.cleanup_retry_time = timestamp_from_millis(306_000).ok();
        let restored_deadline = ProvisioningDeadline::from_record(&restored).unwrap();
        restored_deadline.write_record(&mut restored);
        assert_eq!(restored.cleanup_error, "retry pending");
        assert!(restored.cleanup_retry_time.is_some());
        assert!(restored.deadline.is_none());
        assert_eq!(restored_deadline, deadline);
    }

    #[test]
    fn malformed_persisted_timing_cannot_grant_another_window() {
        assert!(ProvisioningDeadline::from_record(&SandboxProvisioning::default()).is_err());
        let mut record = new_record(0);
        record.timeout_time = timestamp_from_millis(300_000).ok();
        assert!(ProvisioningDeadline::from_record(&record).is_err());
        record.timeout_time = None;
        record.configuration_change_time = None;
        assert!(ProvisioningDeadline::from_record(&record).is_err());
    }

    fn change(id: &str, committed_at_ms: i64) -> ConfigurationChange {
        ConfigurationChange {
            id: id.into(),
            committed_at_ms,
        }
    }

    fn initial() -> ProvisioningDeadline {
        ProvisioningDeadline::new("attempt-1".into(), change("change-1", 0), 0)
    }

    #[test]
    fn expires_at_exactly_300_seconds_without_a_report() {
        let mut timer = initial();
        assert!(!timer.expire("attempt-1", "change-1", 299_999));
        assert!(timer.expire("attempt-1", "change-1", 300_000));
        assert!(!timer.expire("attempt-1", "change-1", 300_001));
    }

    #[test]
    fn repeated_failures_do_not_extend_the_repair_window() {
        let mut timer = initial();
        assert!(timer.rejected("attempt-1", "change-1", 5_000));
        for now in (7_000..305_000).step_by(2_000) {
            assert!(!timer.rejected("attempt-1", "change-1", now));
        }
        assert_eq!(timer.deadline_at_ms(), Some(305_000));
        assert!(timer.expire("attempt-1", "change-1", 305_000));
    }

    #[test]
    fn change_and_first_failed_load_each_reset_once() {
        let mut timer = initial();
        assert!(timer.configuration_changed("attempt-1", change("change-2", 100_000)));
        assert_eq!(timer.deadline_at_ms(), Some(400_000));
        assert!(timer.rejected("attempt-1", "change-2", 105_000));
        assert_eq!(timer.deadline_at_ms(), Some(405_000));
        assert!(!timer.configuration_changed("attempt-1", change("change-2", 110_000)));
        assert!(!timer.rejected("attempt-1", "change-2", 110_000));
        assert_eq!(timer.deadline_at_ms(), Some(405_000));
    }

    #[test]
    fn delayed_observation_uses_commit_time() {
        let mut timer = initial();
        // Caller can observe this later, but it committed before the deadline.
        assert!(timer.configuration_changed("attempt-1", change("change-2", 100_000)));
        assert_eq!(timer.deadline_at_ms(), Some(400_000));
        assert!(!timer.configuration_changed("attempt-1", change("older", 50_000)));
    }

    #[test]
    fn stale_attempts_and_changes_cannot_extend_or_expire() {
        let mut timer = initial();
        assert!(!timer.rejected("old-attempt", "change-1", 1_000));
        assert!(!timer.rejected("attempt-1", "old-change", 1_000));
        assert!(!timer.configuration_changed("old-attempt", change("change-2", 1_000)));
        assert!(!timer.expire("old-attempt", "change-1", 400_000));
        assert!(!timer.expire("attempt-1", "old-change", 400_000));
        assert_eq!(timer.deadline_at_ms(), Some(300_000));
    }

    #[test]
    fn late_change_failure_or_ready_cannot_escape_expiry() {
        let mut timer = initial();
        assert!(!timer.configuration_changed("attempt-1", change("change-2", 300_000)));
        assert!(!timer.rejected("attempt-1", "change-1", 300_000));
        assert!(!timer.ready("attempt-1", "change-1", 300_000));
        assert!(timer.expire("attempt-1", "change-1", 300_000));
        assert!(!timer.ready("attempt-1", "change-1", 300_001));
        assert!(!timer.configuration_changed("attempt-1", change("change-2", 100_000)));
    }

    #[test]
    fn ready_disarms_and_cannot_rearm_for_a_failed_live_update() {
        let mut timer = initial();
        assert!(timer.ready("attempt-1", "change-1", 50_000));
        assert!(!timer.rejected("attempt-1", "change-1", 60_000));
        assert!(!timer.configuration_changed("attempt-1", change("change-2", 60_000)));
        assert!(!timer.expire("attempt-1", "change-1", 400_000));
    }

    #[test]
    fn restart_roundtrip_preserves_first_failure_and_deadline() {
        let mut timer = initial();
        assert!(timer.rejected("attempt-1", "change-1", 5_000));
        let encoded = serde_json::to_vec(&timer).unwrap();
        let mut restored: ProvisioningDeadline = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(restored, timer);
        assert!(!restored.rejected("attempt-1", "change-1", 100_000));
        assert_eq!(restored.deadline_at_ms(), Some(305_000));
    }

    #[test]
    fn explicit_retry_is_a_new_attempt_and_old_cleanup_cannot_expire_it() {
        let mut timer =
            ProvisioningDeadline::new("attempt-2".into(), change("change-2", 350_000), 400_000);
        assert_eq!(timer.deadline_at_ms(), Some(700_000));
        assert!(!timer.expire("attempt-1", "change-2", 800_000));
    }

    #[test]
    fn legacy_initialization_grants_one_window_from_adoption() {
        let timer = ProvisioningDeadline::new("adopted".into(), change("legacy", 0), 1_000_000);
        assert_eq!(timer.deadline_at_ms(), Some(1_300_000));
    }
}
