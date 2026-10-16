// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Stopped-only image changes with private durable intent and an operation
//! interlock understood by supported older gateways.

use super::{ComputeRuntime, provisioning_operation, sandbox_compute_runtime_identity};
use crate::storage_proto::StoredSandboxImageUpdate as SandboxImageUpdate;
use openshell_core::extension_protocol::COMPUTE_UPDATE_SANDBOX_IMAGE;
use openshell_core::proto::compute::v1::UpdateSandboxImageRequest;
use openshell_core::proto::{Sandbox, SandboxPhase};
use openshell_core::{GetResourceVersion, ObjectId, ObjectName};
use tonic::{Request, Status};
use tracing::info;

impl ComputeRuntime {
    pub(crate) fn with_sandbox_image_updates(mut self, enabled: bool) -> Self {
        self.image_updates_enabled = enabled;
        self
    }

    pub(crate) async fn update_sandbox_image(
        &self,
        sandbox_id: &str,
        image: String,
        expected_resource_version: u64,
    ) -> Result<Sandbox, Status> {
        // Explicit operator activation follows retirement of incompatible
        // gateways and their outstanding driver work. Refuse before preflight
        // or durable effects; a cached placement ring is not a version proof.
        if !self.image_updates_enabled {
            return Err(Status::failed_precondition(
                "sandbox image updates are disabled; complete the compatible deployment rollout before activating them",
            ));
        }
        self.store
            .ensure_image_update_deployment_compatible()
            .await
            .map_err(|error| match error {
                crate::persistence::PersistenceError::Config(message) => {
                    Status::failed_precondition(message)
                }
                _ => Status::unavailable("cannot verify image-update deployment compatibility"),
            })?;
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
            .map_err(|_| Status::internal("fetch sandbox failed"))?
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
        let state = self
            .store
            .get_sandbox_image_state(sandbox_id)
            .await
            .map_err(|_| Status::internal("fetch private sandbox image state failed"))?;
        let pending = state.as_ref().and_then(|state| state.pending.clone());
        if let Some(intent) = &pending {
            ensure_image_update_interlock(&current, intent)?;
            if intent.image != image {
                return Err(Status::failed_precondition(
                    "another image update is pending; retry that image before selecting a different image",
                ));
            }
        } else {
            provisioning_operation::ensure_operation_settled(&current)?;
        }
        let old_image = current
            .spec
            .as_ref()
            .and_then(|spec| spec.template.as_ref())
            .map(|template| template.image.clone())
            .filter(|image| !image.is_empty())
            .ok_or_else(|| Status::failed_precondition("sandbox has no workload image"))?;
        if pending.is_none() && old_image == image {
            return Ok(current);
        }
        let revision = state.as_ref().map_or(0, |state| state.revision);
        let intent = pending.clone().unwrap_or_else(|| SandboxImageUpdate {
            operation_id: uuid::Uuid::new_v4().to_string(),
            previous_image: old_image,
            image,
            revision: revision.saturating_add(1),
        });
        if pending.is_none() && revision == u64::MAX {
            return Err(Status::resource_exhausted(
                "sandbox image revision exhausted",
            ));
        }
        let accepted = if pending.is_some() {
            current
        } else {
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
            // The private intent, desired image, and OLD-understood pending
            // operation flag commit in one version-fenced transaction.
            self.store
                .begin_sandbox_image_update(
                    sandbox_id,
                    expected_resource_version,
                    revision,
                    &intent,
                )
                .await
                .map_err(|error| {
                    crate::grpc::persistence_error_to_status(error, "record sandbox image update")
                })?
        };
        self.sandbox_index.update_from_sandbox(&accepted);
        self.sandbox_watch_bus.notify(sandbox_id);
        drop(sandbox_guard);
        let runtime = self.clone();
        tokio::spawn(async move {
            let _lifecycle_guard = lifecycle_guard;
            runtime.complete_image_update(accepted, intent).await
        })
        .await
        .map_err(|_| {
            Status::internal("sandbox image update worker failed; intent remains pending")
        })?
    }

    async fn complete_image_update(
        &self,
        pending: Sandbox,
        intent: SandboxImageUpdate,
    ) -> Result<Sandbox, Status> {
        ensure_image_update_interlock(&pending, &intent)?;
        let request = image_update_driver_request(&pending, &intent, false);
        self.driver.call_owned(openshell_otel::rpc::UPDATE_SANDBOX_IMAGE, Some(pending.object_id()),
            move |driver| async move { driver.update_sandbox_image(Request::new(request)).await }).await?;
        let _guard = self.lock_sandbox_local(pending.object_id()).await;
        // An ambiguous error NEVER clears either the private intent or the
        // public operation interlock. Only exact successful reconciliation can.
        let updated = self
            .store
            .complete_sandbox_image_update(pending.object_id(), &intent)
            .await
            .map_err(|error| {
                crate::grpc::persistence_error_to_status(error, "complete sandbox image update")
            })?;
        self.sandbox_index.update_from_sandbox(&updated);
        self.sandbox_watch_bus.notify(updated.object_id());
        info!(sandbox_id = %updated.object_id(), operation_id = %intent.operation_id,
            "Sandbox workload image updated; sandbox remains stopped");
        Ok(updated)
    }

    pub(super) async fn ensure_no_pending_image_update(
        &self,
        sandbox: &Sandbox,
    ) -> Result<(), Status> {
        let state = self
            .store
            .get_sandbox_image_state(sandbox.object_id())
            .await
            .map_err(|_| Status::unavailable("cannot read private sandbox image state"))?;
        if state.as_ref().is_some_and(|state| state.pending.is_some()) {
            return Err(Status::failed_precondition(
                "sandbox image update is pending; read the current resource version and retry UpdateSandbox with the same image before starting",
            ));
        }
        Ok(())
    }
}

fn ensure_image_update_interlock(
    sandbox: &Sandbox,
    intent: &SandboxImageUpdate,
) -> Result<(), Status> {
    if sandbox
        .status
        .as_ref()
        .and_then(|status| status.provisioning.as_ref())
        .is_none_or(|record| {
            !record.driver_operation_pending || record.driver_operation_id != intent.operation_id
        })
    {
        return Err(Status::aborted(
            "sandbox image-update operation interlock changed",
        ));
    }
    Ok(())
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
        runtime.image_updates_enabled = true;
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
        let state = runtime
            .store
            .get_sandbox_image_state(updated.object_id())
            .await
            .unwrap()
            .unwrap();
        assert!(state.pending.is_none());
        assert_eq!(state.revision, 1);
        assert_eq!(updated.status, original.status);
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
        assert_eq!(
            runtime
                .store
                .get_sandbox_image_state(back.object_id())
                .await
                .unwrap()
                .unwrap()
                .revision,
            2
        );
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
        let upgraded_revision = runtime
            .store
            .get_sandbox_image_state(upgraded.object_id())
            .await
            .unwrap()
            .unwrap()
            .revision;
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
            runtime
                .store
                .get_sandbox_image_state(corrected.object_id())
                .await
                .unwrap()
                .unwrap()
                .revision,
            upgraded_revision + 1
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
        assert!(
            runtime
                .store
                .get_sandbox_image_state(pending.object_id())
                .await
                .unwrap()
                .unwrap()
                .pending
                .is_some()
        );
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
        assert!(
            runtime
                .store
                .get_sandbox_image_state(complete.object_id())
                .await
                .unwrap()
                .unwrap()
                .pending
                .is_none()
        );
        let calls = image_calls(&driver);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], calls[1]);
    }

    #[tokio::test]
    async fn image_update_intent_survives_driver_status_replacement() {
        let (runtime, driver, original) = fixture(true).await;
        driver.set_image_update_error(Some(Code::Unavailable));
        runtime
            .update_sandbox_image(
                original.object_id(),
                "example/workload:new".into(),
                original.get_resource_version(),
            )
            .await
            .unwrap_err();
        let expected = runtime
            .store
            .get_sandbox_image_state(original.object_id())
            .await
            .unwrap()
            .unwrap();
        let mut sandbox = runtime
            .store
            .get_message::<Sandbox>(original.object_id())
            .await
            .unwrap()
            .unwrap();
        let grant_failure = Box::new(openshell_core::proto::TokenGrantFailureObservation {
            destination_host: "api.example.com".into(),
            ..Default::default()
        });
        sandbox.status.as_mut().unwrap().last_token_grant_failure = Some(grant_failure.clone());
        let incoming = DriverSandbox {
            id: original.object_id().into(),
            name: original.object_name().into(),
            status: Some(DriverSandboxStatus::default()),
            ..Default::default()
        };
        apply_driver_snapshot(&mut sandbox, &incoming, false, false);
        runtime.store.put_message(&sandbox).await.unwrap();
        assert_eq!(
            runtime
                .store
                .get_sandbox_image_state(original.object_id())
                .await
                .unwrap()
                .unwrap(),
            expected
        );
        assert!(
            sandbox
                .status
                .as_ref()
                .unwrap()
                .provisioning
                .as_ref()
                .unwrap()
                .driver_operation_pending
        );
        assert_eq!(
            sandbox.status.as_ref().unwrap().last_token_grant_failure,
            Some(grant_failure)
        );
        assert_eq!(
            runtime
                .start_sandbox("default", original.object_name())
                .await
                .unwrap_err()
                .code(),
            Code::FailedPrecondition
        );
    }

    #[tokio::test]
    async fn image_update_activation_is_disabled_by_default_without_effects() {
        let (mut runtime, driver, original) = fixture(true).await;
        runtime.image_updates_enabled = false;
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
            Code::FailedPrecondition
        );
        assert!(
            !driver
                .calls()
                .iter()
                .any(|call| matches!(call, FakeComputeDriverCall::UpdateSandboxImage { .. }))
        );
        assert_eq!(
            runtime
                .store
                .get_message::<Sandbox>(original.object_id())
                .await
                .unwrap()
                .unwrap(),
            original
        );
        assert!(
            runtime
                .store
                .get_sandbox_image_state(original.object_id())
                .await
                .unwrap()
                .is_none()
        );
    }
    // These are the relevant pre-feature wire fields: no image-update fields
    // exist in public status. Older readers already understand provisioning.
    #[derive(Clone, PartialEq, prost::Message)]
    struct LegacyStatus014 {
        #[prost(int32, tag = "6")]
        phase: i32,
        #[prost(message, optional, tag = "13")]
        provisioning: Option<openshell_core::proto::SandboxProvisioning>,
    }

    #[tokio::test]
    async fn legacy_status_roundtrip_cannot_erase_intent_or_bypass_lifecycle_interlock() {
        use prost::Message;
        let (runtime, driver, original) = fixture(true).await;
        driver.set_image_update_error(Some(Code::Unavailable));
        runtime
            .update_sandbox_image(
                original.object_id(),
                "example/workload:new".into(),
                original.get_resource_version(),
            )
            .await
            .unwrap_err();
        let private_before = runtime
            .store
            .get_sandbox_image_state(original.object_id())
            .await
            .unwrap()
            .unwrap();
        let mut pending = runtime
            .store
            .get_message::<Sandbox>(original.object_id())
            .await
            .unwrap()
            .unwrap();
        let legacy =
            LegacyStatus014::decode(pending.status.as_ref().unwrap().encode_to_vec().as_slice())
                .unwrap();
        assert!(
            legacy
                .provisioning
                .as_ref()
                .unwrap()
                .driver_operation_pending
        );
        pending.status = Some(
            openshell_core::proto::SandboxStatus::decode(legacy.encode_to_vec().as_slice())
                .unwrap(),
        );
        runtime.store.put_message(&pending).await.unwrap();
        let rewritten = runtime
            .store
            .get_message::<Sandbox>(original.object_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            runtime
                .store
                .get_sandbox_image_state(original.object_id())
                .await
                .unwrap()
                .unwrap(),
            private_before
        );
        // This existing guard is also present in v0.1.4, unlike our private check.
        assert_eq!(
            provisioning_operation::ensure_operation_settled(&rewritten)
                .unwrap_err()
                .code(),
            Code::FailedPrecondition
        );
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
                .stop_sandbox("default", original.object_name())
                .await
                .unwrap_err()
                .code(),
            Code::FailedPrecondition
        );
        assert_eq!(
            runtime
                .delete_sandbox("default", original.object_name())
                .await
                .unwrap_err()
                .code(),
            Code::FailedPrecondition
        );
        runtime
            .recover_persisted_lifecycle_transitions()
            .await
            .unwrap();
        assert!(!driver.calls().iter().any(|call| matches!(
            call,
            FakeComputeDriverCall::StartSandbox { .. }
                | FakeComputeDriverCall::StopSandbox { .. }
                | FakeComputeDriverCall::DeleteSandbox { .. }
        )));
        driver.set_image_update_error(None);
        let complete = runtime
            .update_sandbox_image(
                original.object_id(),
                "example/workload:new".into(),
                rewritten.get_resource_version(),
            )
            .await
            .unwrap();
        assert!(provisioning_operation::ensure_operation_settled(&complete).is_ok());
        assert!(
            runtime
                .store
                .get_sandbox_image_state(original.object_id())
                .await
                .unwrap()
                .unwrap()
                .pending
                .is_none()
        );
    }

    #[tokio::test]
    async fn stale_legacy_start_cas_loses_to_atomic_image_acceptance() {
        let (runtime, driver, original) = fixture(true).await;
        // Model an old Start paused after reading Stopped but before its CAS.
        driver.set_image_update_error(Some(Code::Unavailable));
        runtime
            .update_sandbox_image(
                original.object_id(),
                "example/workload:new".into(),
                original.get_resource_version(),
            )
            .await
            .unwrap_err();
        let stale_start = runtime
            .store
            .update_message_cas::<Sandbox, _>(
                original.object_id(),
                original.get_resource_version(),
                |sandbox| sandbox.set_phase(SandboxPhase::Starting as i32),
            )
            .await;
        assert!(matches!(
            stale_start,
            Err(crate::persistence::PersistenceError::Conflict { .. })
        ));
        let current = runtime
            .store
            .get_message::<Sandbox>(original.object_id())
            .await
            .unwrap()
            .unwrap();
        assert!(provisioning_operation::ensure_operation_settled(&current).is_err());
        assert!(
            !driver
                .calls()
                .iter()
                .any(|call| matches!(call, FakeComputeDriverCall::StartSandbox { .. }))
        );
    }

    #[tokio::test]
    async fn image_acceptance_loses_if_legacy_start_already_claimed_starting() {
        let (runtime, driver, original) = fixture(true).await;
        let starting = runtime
            .store
            .update_message_cas::<Sandbox, _>(
                original.object_id(),
                original.get_resource_version(),
                |sandbox| sandbox.set_phase(SandboxPhase::Starting as i32),
            )
            .await
            .unwrap();
        assert_eq!(
            runtime
                .update_sandbox_image(
                    original.object_id(),
                    "example/workload:new".into(),
                    starting.get_resource_version()
                )
                .await
                .unwrap_err()
                .code(),
            Code::FailedPrecondition
        );
        assert!(
            runtime
                .store
                .get_sandbox_image_state(original.object_id())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !driver
                .calls()
                .iter()
                .any(|call| matches!(call, FakeComputeDriverCall::UpdateSandboxImage { .. }))
        );
    }
}
