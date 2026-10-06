// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Retain ownership of submitted driver work until its outcome is known.
//!
//! Local cancellation and backend absence cannot prove that an external create
//! stopped. A durable claim prevents another replica from declaring cleanup
//! complete, retrying, or deleting the only record of an unresolved request.

use std::future::Future;
use std::time::Duration;

use ryno_core::{ObjectId, proto::Sandbox};
use tonic::Status;
use tracing::Instrument as _;

use super::{
    ComputeRuntime, provisioning_deadline, sandbox_provisioning_attempt_id,
    sandbox_resource_version, sandbox_runtime_generation,
};
use crate::persistence::PersistenceError;

/// An attempt may contain several recovery operations on the same generation.
/// Keep the last operation ID after settlement so a delayed callback cannot
/// adopt a newer operation merely because it has already finished.
pub(super) fn same_operation(left: &Sandbox, right: &Sandbox) -> bool {
    sandbox_provisioning_attempt_id(left) == sandbox_provisioning_attempt_id(right)
        && operation_id(left) == operation_id(right)
}

fn operation_id(sandbox: &Sandbox) -> Option<&str> {
    sandbox
        .status
        .as_ref()?
        .provisioning
        .as_ref()
        .map(|record| record.driver_operation_id.as_str())
}

/// Called only inside a CAS that has checked the prior operation is settled.
/// Legacy rows without an attempt retain their existing lifecycle contract.
pub(super) fn claim_record(sandbox: &mut Sandbox) {
    if let Some(record) = sandbox
        .status
        .as_mut()
        .and_then(|status| status.provisioning.as_mut())
    {
        record.driver_operation_pending = true;
        record.driver_operation_id = uuid::Uuid::new_v4().to_string();
    }
}

pub(super) fn ensure_current_result(current: &Sandbox, owned: &Sandbox) -> Result<(), Status> {
    if !same_operation(current, owned)
        || sandbox_runtime_generation(current) != sandbox_runtime_generation(owned)
    {
        return Err(Status::aborted(
            "sandbox driver operation changed before result handling",
        ));
    }
    if provisioning_deadline::timed_out(current) {
        return Err(Status::deadline_exceeded("provisioning deadline expired"));
    }
    ensure_operation_settled(current)
}

pub(super) fn ensure_operation_settled(sandbox: &Sandbox) -> Result<(), Status> {
    if provisioning_deadline::driver_operation_pending(sandbox) {
        return Err(Status::failed_precondition(
            "previous driver operation is still pending; retry and deletion are blocked",
        ));
    }
    Ok(())
}

/// Keep monitor interruption separate from an actual driver response. Only
/// the latter may enter the caller's existing failure recovery path.
#[derive(Debug, thiserror::Error)]
pub(super) enum ProvisioningOperationError {
    #[error("{status}")]
    Driver {
        status: Status,
        settled: Box<Sandbox>,
    },
    #[error("{0}")]
    Monitor(Status),
    #[error("{0}")]
    Unsettled(Status),
}

impl From<ProvisioningOperationError> for Status {
    fn from(error: ProvisioningOperationError) -> Self {
        match error {
            ProvisioningOperationError::Driver { status, .. }
            | ProvisioningOperationError::Monitor(status)
            | ProvisioningOperationError::Unsettled(status) => status,
        }
    }
}

impl ComputeRuntime {
    /// Claim before polling the operation, then retain its task even when the
    /// caller or deadline monitor leaves. Pending describes the owned future,
    /// not backend cancellation: transport-error ambiguity remains governed by
    /// the compute driver's existing error contract.
    pub(super) async fn await_provisioning_operation<T: Send + 'static>(
        &self,
        starting: &Sandbox,
        operation: impl Future<Output = Result<T, Status>> + Send + 'static,
    ) -> Result<(T, Box<Sandbox>), ProvisioningOperationError> {
        let claimed = self
            .claim_provisioning_operation(starting)
            .await
            .map_err(ProvisioningOperationError::Monitor)?;
        self.await_claimed_provisioning_operation(&claimed, operation)
            .await
    }

    /// The caller has atomically claimed both its lifecycle transition and the
    /// operation. The detached worker owns I/O, not the caller's local gate.
    pub(super) async fn await_claimed_provisioning_operation<T: Send + 'static>(
        &self,
        starting: &Sandbox,
        operation: impl Future<Output = Result<T, Status>> + Send + 'static,
    ) -> Result<(T, Box<Sandbox>), ProvisioningOperationError> {
        let tracked = sandbox_provisioning_attempt_id(starting).is_some();
        let runtime = self.clone();
        let owned_attempt = starting.clone();
        // Dropping a JoinHandle detaches its task. Do not abort it on a monitor
        // error or deadline: the remote side may still commit the request.
        let worker = async move {
            let result = operation.await;
            let settled = if tracked {
                let settled = runtime
                    .settle_provisioning_operation(&owned_attempt)
                    .await
                    .map_err(ProvisioningOperationError::Monitor)?;
                // Settlement records a known response even if another writer
                // rotated identity. That response cannot bind or compensate
                // against the replacement generation in its returned snapshot.
                if sandbox_runtime_generation(&settled)
                    != sandbox_runtime_generation(&owned_attempt)
                {
                    return Err(ProvisioningOperationError::Monitor(Status::aborted(
                        "sandbox runtime generation changed during driver operation",
                    )));
                }
                settled
            } else {
                owned_attempt
            };
            match result {
                Ok(response) => Ok((response, Box::new(settled))),
                Err(status) => Err(ProvisioningOperationError::Driver {
                    status,
                    settled: Box::new(settled),
                }),
            }
        };
        // Retain the request span so detaching ownership preserves the driver
        // call's parent trace, including when the caller stops waiting.
        let mut worker = tokio::spawn(worker.in_current_span());
        loop {
            tokio::select! {
                result = &mut worker => return result.map_err(|error| {
                    ProvisioningOperationError::Unsettled(Status::internal(format!(
                        "driver operation owner terminated; outcome remains unknown: {error}"
                    )))
                })?,
                () = tokio::time::sleep(Duration::from_secs(1)) => {
                    let current = self.store.get_message::<Sandbox>(starting.object_id())
                        .await.map_err(|error| ProvisioningOperationError::Monitor(
                            Status::internal(format!("monitor provisioning: {error}"))
                        ))?
                        .ok_or_else(|| ProvisioningOperationError::Monitor(
                            Status::not_found("sandbox removed during startup")
                        ))?;
                    if !same_operation(&current, starting)
                        || sandbox_runtime_generation(&current) != sandbox_runtime_generation(starting) {
                        return Err(ProvisioningOperationError::Monitor(Status::aborted(
                            "sandbox provisioning attempt changed while waiting for compute"
                        )));
                    }
                    if provisioning_deadline::timed_out(&current) {
                        return Err(ProvisioningOperationError::Monitor(Status::deadline_exceeded(
                            "provisioning deadline expired; driver settlement may still be pending"
                        )));
                    }
                }
            }
        }
    }

    async fn claim_provisioning_operation(&self, starting: &Sandbox) -> Result<Sandbox, Status> {
        let Some(attempt_id) = sandbox_provisioning_attempt_id(starting) else {
            // Legacy rows without an attempt do not gain a synthetic deadline.
            return Ok(starting.clone());
        };
        if attempt_id.is_empty() {
            return Err(Status::failed_precondition("provisioning attempt is empty"));
        }
        for _ in 0..super::START_PHASE_CAS_RETRY_LIMIT {
            let current = self
                .store
                .get_message::<Sandbox>(starting.object_id())
                .await
                .map_err(|error| Status::internal(error.to_string()))?
                .ok_or_else(|| Status::not_found("sandbox removed before driver dispatch"))?;
            if provisioning_deadline::timed_out(&current) {
                return Err(Status::deadline_exceeded(
                    "provisioning deadline already expired",
                ));
            }
            if provisioning_deadline::driver_operation_pending(&current) {
                return Err(Status::failed_precondition(
                    "previous driver operation may still complete; retry and deletion are blocked",
                ));
            }
            if !same_operation(&current, starting)
                || sandbox_runtime_generation(&current) != sandbox_runtime_generation(starting)
            {
                return Err(Status::aborted(
                    "provisioning operation changed before driver dispatch",
                ));
            }
            if current.phase() != starting.phase() {
                return Err(Status::aborted(
                    "sandbox phase changed before driver dispatch",
                ));
            }
            match self
                .store
                .update_message_cas::<Sandbox, _>(
                    starting.object_id(),
                    sandbox_resource_version(&current),
                    claim_record,
                )
                .await
            {
                Ok(updated) => {
                    self.sandbox_index.update_from_sandbox(&updated);
                    self.sandbox_watch_bus.notify(starting.object_id());
                    return Ok(updated);
                }
                Err(PersistenceError::Conflict { .. }) => {}
                Err(error) => return Err(Status::internal(error.to_string())),
            }
        }
        Err(Status::aborted(
            "sandbox kept changing before driver dispatch",
        ))
    }

    async fn settle_provisioning_operation(&self, starting: &Sandbox) -> Result<Sandbox, Status> {
        // Keep the observed response in this task across transient persistence
        // failures. A process crash still leaves the durable claim intact;
        // neither lease expiry nor backend absence can safely clear it.
        loop {
            let result = self.try_settle_provisioning_operation(starting).await;
            match result {
                Ok(settled) => return Ok(settled),
                Err(error) if error.code() == tonic::Code::Aborted => return Err(error),
                Err(error) => {
                    tracing::warn!(sandbox_id = starting.object_id(), %error,
                        "Retaining driver response until operation ownership can be persisted");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    async fn try_settle_provisioning_operation(
        &self,
        starting: &Sandbox,
    ) -> Result<Sandbox, Status> {
        let current = self
            .store
            .get_message::<Sandbox>(starting.object_id())
            .await
            .map_err(|error| Status::internal(error.to_string()))?
            .ok_or_else(|| Status::aborted("sandbox removed before driver settlement"))?;
        if !same_operation(&current, starting) {
            return Err(Status::aborted(
                "provisioning attempt changed before driver settlement",
            ));
        }
        let updated = self
            .store
            .update_message_cas::<Sandbox, _>(
                starting.object_id(),
                sandbox_resource_version(&current),
                |sandbox| {
                    if let Some(record) = sandbox
                        .status
                        .as_mut()
                        .and_then(|status| status.provisioning.as_mut())
                    {
                        record.driver_operation_pending = false;
                        // Any stop before this response may have seen absence before
                        // the late create committed. Require another cleanup pass.
                        record.cleanup_completed_time = None;
                        // The retry timestamp may be another replica's active
                        // STOP lease. Preserve it through driver settlement.
                    }
                },
            )
            .await
            .map_err(|error| Status::internal(error.to_string()))?;
        self.sandbox_index.update_from_sandbox(&updated);
        self.sandbox_watch_bus.notify(starting.object_id());
        Ok(updated)
    }
}
