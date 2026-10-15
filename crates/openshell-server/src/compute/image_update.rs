// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Stopped-only image changes. Persist intent before touching the driver so a
//! lost response cannot allow Start to run a different image than the gateway.

use super::{
    ComputeRuntime, START_PHASE_CAS_RETRY_LIMIT, provisioning_operation,
    sandbox_compute_runtime_identity,
};
use openshell_core::extension_protocol::COMPUTE_UPDATE_SANDBOX_IMAGE;
use openshell_core::proto::compute::v1::UpdateSandboxImageRequest;
use openshell_core::proto::{Sandbox, SandboxImageUpdate, SandboxPhase};
use openshell_core::{GetResourceVersion, ObjectId, ObjectName};
use tonic::{Request, Status};
use tracing::info;

impl ComputeRuntime {
    pub(crate) async fn update_sandbox_image(
        &self,
        sandbox_id: &str,
        image: String,
        expected_resource_version: u64,
    ) -> Result<Sandbox, Status> {
        if !self
            .driver_info
            .negotiated_extension
            .supported_capabilities
            .iter()
            .any(|capability| capability == COMPUTE_UPDATE_SANDBOX_IMAGE)
        {
            return Err(Status::unimplemented(
                "compute driver does not support storage-preserving sandbox image updates",
            ));
        }
        let lifecycle_guard = self.lifecycle_gates.lock_for(sandbox_id).await;
        let sandbox_guard = self.lock_sandbox_for_lifecycle(&lifecycle_guard).await;
        let current = self
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .map_err(|error| Status::internal(format!("fetch sandbox failed: {error}")))?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        ensure_image_update_stopped(&current)?;
        if current.get_resource_version() != expected_resource_version {
            return Err(crate::grpc::persistence_error_to_status(
                crate::persistence::PersistenceError::Conflict {
                    current_resource_version: Some(current.get_resource_version()),
                },
                "update sandbox image",
            ));
        }
        let old_image = current
            .spec
            .as_ref()
            .and_then(|spec| spec.template.as_ref())
            .map(|template| template.image.clone())
            .filter(|image| !image.is_empty())
            .ok_or_else(|| Status::failed_precondition("sandbox has no workload image"))?;
        let pending = current
            .status
            .as_ref()
            .and_then(|status| status.image_update.clone());
        if pending
            .as_ref()
            .is_some_and(|pending| pending.image != image)
        {
            return Err(Status::failed_precondition(
                "another image update is pending; retry that image before selecting a different image",
            ));
        }
        if pending.is_none() && old_image == image {
            return Ok(current);
        }
        let intent = if let Some(intent) = pending {
            intent
        } else {
            let revision = current
                .status
                .as_ref()
                .map_or(0, |status| status.image_revision)
                .checked_add(1)
                .ok_or_else(|| Status::resource_exhausted("sandbox image revision exhausted"))?;
            SandboxImageUpdate {
                operation_id: uuid::Uuid::new_v4().to_string(),
                previous_image: old_image,
                image: image.clone(),
                revision,
            }
        };
        if current
            .status
            .as_ref()
            .is_none_or(|status| status.image_update.is_none())
        {
            let request = image_update_driver_request(&current, &intent, true);
            self.driver
                .call_owned(
                    openshell_otel::rpc::UPDATE_SANDBOX_IMAGE,
                    Some(sandbox_id),
                    move |driver| async move {
                        driver.update_sandbox_image(Request::new(request)).await
                    },
                )
                .await?;
        }
        let pending = if current
            .status
            .as_ref()
            .is_some_and(|status| status.image_update.is_some())
        {
            current
        } else {
            let intent_for_write = intent.clone();
            self.store
                .update_message_cas::<Sandbox, _>(
                    sandbox_id,
                    expected_resource_version,
                    move |sandbox| {
                        sandbox
                            .spec
                            .as_mut()
                            .expect("validated spec")
                            .template
                            .as_mut()
                            .expect("validated template")
                            .image
                            .clone_from(&image);
                        let status = sandbox.status.get_or_insert_with(Default::default);
                        status.image_revision = intent_for_write.revision;
                        status.image_update = Some(intent_for_write.clone());
                    },
                )
                .await
                .map_err(|error| {
                    crate::grpc::persistence_error_to_status(error, "record sandbox image update")
                })?
        };
        self.sandbox_index.update_from_sandbox(&pending);
        self.sandbox_watch_bus.notify(sandbox_id);
        drop(sandbox_guard);

        // The durable intent commits ownership. Cancellation of the public RPC
        // must not release the lifecycle gate while the driver can still apply.
        let runtime = self.clone();
        tokio::spawn(async move {
            let _lifecycle_guard = lifecycle_guard;
            runtime.complete_image_update(pending, intent).await
        })
        .await
        .map_err(|error| Status::internal(format!("sandbox image update worker failed: {error}")))?
    }

    async fn complete_image_update(
        &self,
        pending: Sandbox,
        intent: SandboxImageUpdate,
    ) -> Result<Sandbox, Status> {
        let request = image_update_driver_request(&pending, &intent, false);
        self.driver
            .call_owned(openshell_otel::rpc::UPDATE_SANDBOX_IMAGE, Some(pending.object_id()), move |driver| async move {
                driver.update_sandbox_image(Request::new(request)).await
            })
            .await?;

        // Watchers may have advanced the resource version. Never restore an old
        // record or overwrite a concurrent deletion to acknowledge the driver.
        let _guard = self.lock_sandbox_local(pending.object_id()).await;
        for _ in 0..START_PHASE_CAS_RETRY_LIMIT {
            let current = self
                .store
                .get_message::<Sandbox>(pending.object_id())
                .await
                .map_err(|error| Status::internal(format!("reload image update failed: {error}")))?
                .ok_or_else(|| Status::not_found("sandbox was deleted"))?;
            ensure_image_update_stopped(&current)?;
            if current
                .status
                .as_ref()
                .and_then(|status| status.image_update.as_ref())
                != Some(&intent)
            {
                return Err(Status::aborted("sandbox image update intent changed"));
            }
            match self
                .store
                .update_message_cas::<Sandbox, _>(
                    pending.object_id(),
                    current.get_resource_version(),
                    |sandbox| {
                        sandbox
                            .status
                            .as_mut()
                            .expect("pending status")
                            .image_update = None;
                    },
                )
                .await
            {
                Ok(updated) => {
                    self.sandbox_index.update_from_sandbox(&updated);
                    self.sandbox_watch_bus.notify(updated.object_id());
                    info!(sandbox_id = %updated.object_id(), operation_id = %intent.operation_id, "Sandbox workload image updated; sandbox remains stopped");
                    return Ok(updated);
                }
                Err(crate::persistence::PersistenceError::Conflict { .. }) => {}
                Err(error) => {
                    return Err(crate::grpc::persistence_error_to_status(
                        error,
                        "complete sandbox image update",
                    ));
                }
            }
        }
        Err(Status::aborted(
            "sandbox changed while acknowledging image update; read and retry the pending image",
        ))
    }
}

fn image_update_driver_request(
    sandbox: &Sandbox,
    intent: &SandboxImageUpdate,
    validate_only: bool,
) -> UpdateSandboxImageRequest {
    UpdateSandboxImageRequest {
        sandbox_id: sandbox.object_id().to_string(),
        name: sandbox.object_name().to_string(),
        image: intent.image.clone(),
        expected_image: intent.previous_image.clone(),
        expected_runtime_identity: sandbox_compute_runtime_identity(sandbox),
        operation_id: intent.operation_id.clone(),
        validate_only,
        revision: intent.revision,
    }
}

fn ensure_image_update_stopped(sandbox: &Sandbox) -> Result<(), Status> {
    provisioning_operation::ensure_operation_settled(sandbox)?;
    if sandbox.phase() != SandboxPhase::Stopped as i32
        || sandbox
            .metadata
            .as_ref()
            .is_some_and(|metadata| metadata.deletion_time.is_some())
    {
        return Err(Status::failed_precondition(
            "sandbox must be Stopped before updating its image",
        ));
    }
    Ok(())
}

/// Checked both before and after lifecycle locking by Start. A failed driver
/// response does not prove it had no effects, so only a successful retry clears
/// the durable intent. Ordinary stop and deletion never clear it.
pub(super) fn ensure_no_pending_image_update(sandbox: &Sandbox) -> Result<(), Status> {
    if sandbox
        .status
        .as_ref()
        .is_some_and(|status| status.image_update.is_some())
    {
        return Err(Status::failed_precondition(
            "sandbox image update is pending; read the current resource version and retry UpdateSandbox with the same image before starting",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute::{
        COMPUTE_RUNTIME_IDENTITY_ANNOTATION, apply_driver_snapshot, provisioning_deadline,
    };
    use crate::sandbox_index::SandboxIndex;
    use crate::sandbox_watch::SandboxWatchBus;
    use crate::supervisor_session::SupervisorSessionRegistry;
    use crate::test_support::{FakeComputeDriver, FakeComputeDriverCall};
    use crate::tracing_bus::TracingLogBus;
    use openshell_core::proto::compute::v1::{DriverSandbox, DriverSandboxStatus};
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::{SandboxSpec, SandboxTemplate};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tonic::Code;

    async fn fixture(supported: bool) -> (ComputeRuntime, Arc<FakeComputeDriver>, Sandbox) {
        let store = Arc::new(crate::persistence::test_store().await);
        crate::ensure_default_workspace(&store).await.unwrap();
        let driver = Arc::new(FakeComputeDriver::new());
        let mut runtime = ComputeRuntime::from_driver(
            "test".into(),
            driver.clone(),
            None,
            store.clone(),
            SandboxIndex::new(),
            SandboxWatchBus::new(),
            TracingLogBus::new(),
            Arc::new(SupervisorSessionRegistry::new()),
        )
        .await
        .unwrap();
        if supported {
            runtime
                .driver_info
                .negotiated_extension
                .supported_capabilities
                .push(COMPUTE_UPDATE_SANDBOX_IMAGE.into());
        }
        let mut sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: "image-sandbox-id".into(),
                name: "image-sandbox".into(),
                workspace: "default".into(),
                labels: HashMap::from([("app".into(), "retained".into())]),
                annotations: HashMap::from([(
                    COMPUTE_RUNTIME_IDENTITY_ANNOTATION.into(),
                    "stable-runtime".into(),
                )]),
                ..Default::default()
            }),
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    image: "example/workload:old".into(),
                    ..Default::default()
                }),
                environment: HashMap::from([("KEEP".into(), "value".into())]),
                command: vec!["/bin/sh".into()],
                ..Default::default()
            }),
            host_key_fingerprint: "SHA256:stable-key".into(),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Stopped as i32);
        store.put_message(&sandbox).await.unwrap();
        let sandbox = store
            .get_message::<Sandbox>(sandbox.object_id())
            .await
            .unwrap()
            .unwrap();
        (runtime, driver, sandbox)
    }

    fn image_calls(driver: &FakeComputeDriver) -> Vec<UpdateSandboxImageRequest> {
        driver
            .calls()
            .into_iter()
            .filter_map(|call| match call {
                FakeComputeDriverCall::UpdateSandboxImage { request } if !request.validate_only => {
                    Some(request)
                }
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn image_update_preserves_identity_and_every_other_spec_field() {
        let (runtime, driver, original) = fixture(true).await;
        let updated = runtime
            .update_sandbox_image(
                original.object_id(),
                "example/workload:new".into(),
                original.get_resource_version(),
            )
            .await
            .unwrap();
        let mut expected = original.spec.clone().unwrap();
        expected.template.as_mut().unwrap().image = "example/workload:new".into();
        assert_eq!(updated.spec, Some(expected));
        assert_eq!(updated.object_id(), original.object_id());
        assert_eq!(updated.object_name(), original.object_name());
        assert_eq!(updated.host_key_fingerprint, original.host_key_fingerprint);
        assert_eq!(
            updated.metadata.as_ref().unwrap().annotations,
            original.metadata.as_ref().unwrap().annotations
        );
        assert_eq!(
            updated.metadata.as_ref().unwrap().labels,
            original.metadata.as_ref().unwrap().labels
        );
        assert_eq!(updated.phase(), SandboxPhase::Stopped as i32);
        assert!(updated.status.as_ref().unwrap().image_update.is_none());
        assert_eq!(updated.status.as_ref().unwrap().image_revision, 1);
        let calls = image_calls(&driver);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].expected_image, "example/workload:old");
        assert_eq!(calls[0].image, "example/workload:new");
        assert_eq!(calls[0].revision, 1);
        assert_eq!(calls[0].expected_runtime_identity, "stable-runtime");
        assert!(uuid::Uuid::parse_str(&calls[0].operation_id).is_ok());
        assert!(!driver.calls().iter().any(|call| matches!(
            call,
            FakeComputeDriverCall::CreateSandbox { .. }
                | FakeComputeDriverCall::DeleteSandbox { .. }
                | FakeComputeDriverCall::StartSandbox { .. }
        )));
        let unchanged = runtime
            .update_sandbox_image(
                updated.object_id(),
                "example/workload:new".into(),
                updated.get_resource_version(),
            )
            .await
            .unwrap();
        assert_eq!(
            unchanged.get_resource_version(),
            updated.get_resource_version()
        );
        assert_eq!(image_calls(&driver).len(), 1);
        let back = runtime
            .update_sandbox_image(
                updated.object_id(),
                "example/workload:old".into(),
                updated.get_resource_version(),
            )
            .await
            .unwrap();
        assert_eq!(back.status.as_ref().unwrap().image_revision, 2);
        assert_eq!(image_calls(&driver)[1].revision, 2);
    }

    #[tokio::test]
    async fn image_update_rejects_unsupported_driver_and_stale_version_without_writes() {
        let (runtime, driver, original) = fixture(false).await;
        assert_eq!(
            runtime
                .update_sandbox_image(
                    original.object_id(),
                    "example/workload:new".into(),
                    original.get_resource_version()
                )
                .await
                .unwrap_err()
                .code(),
            Code::Unimplemented
        );
        assert!(image_calls(&driver).is_empty());
        let (runtime, driver, original) = fixture(true).await;
        assert_eq!(
            runtime
                .update_sandbox_image(
                    original.object_id(),
                    "example/workload:new".into(),
                    original.get_resource_version() + 1
                )
                .await
                .unwrap_err()
                .code(),
            Code::Aborted
        );
        assert!(image_calls(&driver).is_empty());
        assert_eq!(
            runtime
                .store
                .get_message::<Sandbox>(original.object_id())
                .await
                .unwrap()
                .unwrap(),
            original
        );
    }

    #[tokio::test]
    async fn failed_image_preflight_has_no_durable_effects() {
        let (runtime, driver, original) = fixture(true).await;
        driver.set_image_validation_error(Some(Code::InvalidArgument));
        assert_eq!(
            runtime
                .update_sandbox_image(
                    original.object_id(),
                    "invalid:image".into(),
                    original.get_resource_version()
                )
                .await
                .unwrap_err()
                .code(),
            Code::InvalidArgument
        );
        assert!(image_calls(&driver).is_empty());
        assert_eq!(
            runtime
                .store
                .get_message::<Sandbox>(original.object_id())
                .await
                .unwrap()
                .unwrap(),
            original
        );
    }

    #[tokio::test]
    async fn concurrent_image_updates_cannot_overwrite_each_other() {
        let (runtime, driver, original) = fixture(true).await;
        // Real RPCs are separate tasks. Polling both futures with join! in one
        // task would share the debug task-local lock-order tracker.
        let spawn_update = |image: &str| {
            let runtime = runtime.clone();
            let sandbox_id = original.object_id().to_string();
            let version = original.get_resource_version();
            let image = image.to_string();
            tokio::spawn(async move {
                runtime
                    .update_sandbox_image(&sandbox_id, image, version)
                    .await
            })
        };
        let first = spawn_update("example/workload:first");
        let second = spawn_update("example/workload:second");
        let (first, second) = tokio::join!(first, second);
        let (first, second) = (first.unwrap(), second.unwrap());
        assert_ne!(first.is_ok(), second.is_ok());
        assert_eq!(
            first.err().or_else(|| second.err()).unwrap().code(),
            Code::Aborted
        );
        assert_eq!(image_calls(&driver).len(), 1);
    }

    #[tokio::test]
    async fn image_update_rejects_non_stopped_states() {
        for phase in [
            SandboxPhase::Ready,
            SandboxPhase::Provisioning,
            SandboxPhase::Starting,
            SandboxPhase::Stopping,
            SandboxPhase::Completed,
            SandboxPhase::Error,
            SandboxPhase::Deleting,
        ] {
            let (runtime, driver, mut sandbox) = fixture(true).await;
            sandbox.set_phase(phase as i32);
            runtime.store.put_message(&sandbox).await.unwrap();
            let sandbox = runtime
                .store
                .get_message::<Sandbox>(sandbox.object_id())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                runtime
                    .update_sandbox_image(
                        sandbox.object_id(),
                        "example/workload:new".into(),
                        sandbox.get_resource_version()
                    )
                    .await
                    .unwrap_err()
                    .code(),
                Code::FailedPrecondition,
                "{phase:?}"
            );
            assert!(image_calls(&driver).is_empty());
        }
    }

    #[tokio::test]
    async fn image_update_can_roll_back_after_start_timeout_cleanup() {
        let (runtime, driver, mut original) = fixture(true).await;
        crate::auth::sandbox_session::PersistedSandboxIdentity::new()
            .unwrap()
            .write(&mut original.metadata.as_mut().unwrap().annotations);
        runtime.store.put_message(&original).await.unwrap();
        let original = runtime
            .store
            .get_message::<Sandbox>(original.object_id())
            .await
            .unwrap()
            .unwrap();
        let upgraded = runtime
            .update_sandbox_image(
                original.object_id(),
                "example/workload:missing".into(),
                original.get_resource_version(),
            )
            .await
            .unwrap();
        let starting = runtime
            .start_sandbox("default", original.object_name())
            .await
            .unwrap();
        assert_eq!(starting.phase(), SandboxPhase::Starting as i32);
        // Backdate the owned preparation clock rather than waiting for the
        // production budget. Keep its attempt and settled operation identities.
        let overdue = runtime
            .store
            .update_message_cas::<Sandbox, _>(
                starting.object_id(),
                starting.get_resource_version(),
                |sandbox| {
                    let record = sandbox
                        .status
                        .as_mut()
                        .unwrap()
                        .provisioning
                        .as_mut()
                        .unwrap();
                    record.preparation_deadline =
                        openshell_core::time::timestamp_from_millis(1).ok();
                    record.deadline = record.preparation_deadline;
                },
            )
            .await
            .unwrap();
        let expired = {
            let _guard = runtime.lock_sandbox_local(overdue.object_id()).await;
            runtime
                .claim_provisioning_timeout(&overdue, openshell_core::time::now_ms())
                .await
                .unwrap()
                .unwrap()
        };
        assert_eq!(expired.phase(), SandboxPhase::Error as i32);
        assert!(
            runtime
                .stop_sandbox("default", original.object_name())
                .await
                .is_err()
        );
        assert!(
            runtime
                .update_sandbox_image(
                    original.object_id(),
                    "example/workload:old".into(),
                    expired.get_resource_version()
                )
                .await
                .is_err()
        );
        {
            let gate = runtime.lifecycle_gates.lock_for(expired.object_id()).await;
            runtime
                .reclaim_provisioning_timeout(&expired, &gate)
                .await
                .unwrap();
        }
        let reclaimed = runtime
            .store
            .get_message::<Sandbox>(original.object_id())
            .await
            .unwrap()
            .unwrap();
        assert!(
            reclaimed
                .status
                .as_ref()
                .unwrap()
                .provisioning
                .as_ref()
                .unwrap()
                .cleanup_completed_time
                .is_some()
        );
        let stopped = runtime
            .stop_sandbox("default", original.object_name())
            .await
            .unwrap();
        assert_eq!(stopped.phase(), SandboxPhase::Stopped as i32);
        assert_eq!(
            stopped.status.as_ref().unwrap().provisioning,
            reclaimed.status.as_ref().unwrap().provisioning
        );
        let corrected = runtime
            .update_sandbox_image(
                original.object_id(),
                "example/workload:old".into(),
                stopped.get_resource_version(),
            )
            .await
            .unwrap();
        assert_eq!(
            corrected.status.as_ref().unwrap().image_revision,
            upgraded.status.as_ref().unwrap().image_revision + 1
        );
        assert_eq!(corrected.object_id(), original.object_id());
        assert_eq!(
            corrected.host_key_fingerprint,
            original.host_key_fingerprint
        );
        assert_eq!(corrected.spec, original.spec);
        let retried = runtime
            .start_sandbox("default", original.object_name())
            .await
            .unwrap();
        assert_eq!(retried.phase(), SandboxPhase::Starting as i32);
        assert!(!provisioning_deadline::timed_out(&retried));
        let calls = driver.calls();
        assert_eq!(
            calls
                .iter()
                .filter(|call| matches!(call, FakeComputeDriverCall::StopSandbox { .. }))
                .count(),
            1,
            "only timeout reclamation stops the driver"
        );
        assert_eq!(
            calls
                .iter()
                .filter(|call| matches!(call, FakeComputeDriverCall::StartSandbox { .. }))
                .count(),
            2
        );
        assert!(!calls.iter().any(|call| matches!(
            call,
            FakeComputeDriverCall::CreateSandbox { .. }
                | FakeComputeDriverCall::DeleteSandbox { .. }
        )));
    }

    #[tokio::test]
    async fn interrupted_image_update_blocks_start_and_retries_the_same_operation() {
        let (runtime, driver, original) = fixture(true).await;
        driver.set_image_update_error(Some(Code::Unavailable));
        assert_eq!(
            runtime
                .update_sandbox_image(
                    original.object_id(),
                    "example/workload:new".into(),
                    original.get_resource_version()
                )
                .await
                .unwrap_err()
                .code(),
            Code::Unavailable
        );
        let pending = runtime
            .store
            .get_message::<Sandbox>(original.object_id())
            .await
            .unwrap()
            .unwrap();
        assert!(pending.status.as_ref().unwrap().image_update.is_some());
        assert_eq!(
            runtime
                .start_sandbox("default", original.object_name())
                .await
                .unwrap_err()
                .code(),
            Code::FailedPrecondition
        );
        assert_eq!(
            runtime
                .update_sandbox_image(
                    original.object_id(),
                    "example/workload:other".into(),
                    pending.get_resource_version()
                )
                .await
                .unwrap_err()
                .code(),
            Code::FailedPrecondition
        );
        driver.set_image_update_error(None);
        let complete = runtime
            .update_sandbox_image(
                original.object_id(),
                "example/workload:new".into(),
                pending.get_resource_version(),
            )
            .await
            .unwrap();
        assert!(complete.status.as_ref().unwrap().image_update.is_none());
        let calls = image_calls(&driver);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], calls[1]);
    }

    #[test]
    fn image_update_intent_survives_driver_status_replacement() {
        let intent = SandboxImageUpdate {
            operation_id: "operation".into(),
            previous_image: "old".into(),
            image: "new".into(),
            revision: 1,
        };
        let grant_failure = Box::new(openshell_core::proto::TokenGrantFailureObservation {
            destination_host: "api.example.com".into(),
            ..Default::default()
        });
        let mut sandbox = Sandbox::default();
        sandbox.set_phase(SandboxPhase::Stopped as i32);
        let status = sandbox.status.as_mut().unwrap();
        status.image_update = Some(intent.clone());
        status.image_revision = 1;
        status.last_token_grant_failure = Some(grant_failure.clone());
        let incoming = DriverSandbox {
            name: "test".into(),
            status: Some(DriverSandboxStatus::default()),
            ..Default::default()
        };
        apply_driver_snapshot(&mut sandbox, &incoming, false, false);
        assert_eq!(
            sandbox.status.as_ref().unwrap().image_update.as_ref(),
            Some(&intent)
        );
        assert_eq!(sandbox.status.as_ref().unwrap().image_revision, 1);
        assert_eq!(
            sandbox.status.as_ref().unwrap().last_token_grant_failure,
            Some(grant_failure)
        );
    }
}
