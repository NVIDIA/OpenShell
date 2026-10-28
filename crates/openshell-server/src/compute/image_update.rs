// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Stopped-only configuration changes with private durable intent and an operation
//! interlock understood by supported older gateways.

use super::{ComputeRuntime, provisioning_operation, sandbox_compute_runtime_identity};
use crate::storage_proto::StoredSandboxImageUpdate as SandboxImageUpdate;
use openshell_core::extension_protocol::COMPUTE_UPDATE_SANDBOX_CONFIGURATION;
use openshell_core::proto::compute::v1::SandboxUpdatePreconditions;
use openshell_core::proto::{Sandbox, SandboxPhase};
use openshell_core::{GetResourceVersion, ObjectId, ObjectName};
use tonic::{Request, Status};
use tracing::info;

const UPDATE_RECOVERY_PAGE_SIZE: u32 = 128;

impl ComputeRuntime {
    pub(crate) fn with_sandbox_updates(mut self, enabled: bool) -> Self {
        self.sandbox_updates_enabled = enabled;
        self
    }

    #[cfg(test)]
    pub(crate) async fn update_sandbox_image(
        &self,
        sandbox_id: &str,
        image: String,
        expected_resource_version: u64,
    ) -> Result<Sandbox, Status> {
        self.update_sandbox_configuration(
            sandbox_id,
            &openshell_core::proto::UpdateSandboxRequest {
                image: Some(image),
                expected_resource_version,
                ..Default::default()
            },
        )
        .await
    }

    pub(crate) async fn update_sandbox_configuration(
        &self,
        sandbox_id: &str,
        update: &openshell_core::proto::UpdateSandboxRequest,
    ) -> Result<Sandbox, Status> {
        let expected_resource_version = update.expected_resource_version;
        let lifecycle_guard = self.lifecycle_gates.lock_for(sandbox_id).await;
        let mut sandbox_guard = self.lock_sandbox_for_lifecycle(&lifecycle_guard).await;
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
        let resume = update.image.is_none()
            && update.command.is_none()
            && update.environment.is_none()
            && update.labels.is_none()
            && update.annotations.is_none();
        if pending.is_none() {
            if resume {
                return Err(Status::failed_precondition(
                    "sandbox has no pending update to resume",
                ));
            }
            if !self.sandbox_updates_enabled {
                return Err(Status::failed_precondition(
                    "sandbox updates are disabled; complete the compatible deployment rollout before activating them",
                ));
            }
            provisioning_operation::ensure_operation_settled(&current)?;
            // Metadata lives only in the gateway. CAS fences lifecycle changes
            // and writes the label index in the same transaction as the object.
            if update.image.is_none() && update.command.is_none() && update.environment.is_none() {
                let mut candidate = current.clone();
                openshell_core::sandbox_update::apply_configuration(
                    &mut candidate,
                    None,
                    None,
                    update.labels.as_ref(),
                    update.annotations.as_ref(),
                );
                if candidate == current {
                    return Ok(current);
                }
                let updated = self
                    .store
                    .update_message_cas::<Sandbox, _>(
                        sandbox_id,
                        expected_resource_version,
                        |sandbox| {
                            openshell_core::sandbox_update::apply_configuration(
                                sandbox,
                                None,
                                None,
                                update.labels.as_ref(),
                                update.annotations.as_ref(),
                            );
                        },
                    )
                    .await
                    .map_err(|error| {
                        crate::grpc::persistence_error_to_status(error, "update sandbox metadata")
                    })?;
                self.sandbox_index.update_from_sandbox(&updated);
                self.sandbox_watch_bus.notify(sandbox_id);
                return Ok(updated);
            }
            self.store
                .ensure_image_update_deployment_compatible()
                .await
                .map_err(|error| match error {
                    crate::persistence::PersistenceError::Config(message) => {
                        Status::failed_precondition(message)
                    }
                    _ => {
                        Status::unavailable("cannot verify sandbox-update deployment compatibility")
                    }
                })?;
        }
        self.ensure_configuration_update_supported()?;
        let image = update
            .image
            .clone()
            .or_else(|| {
                current
                    .spec
                    .as_ref()
                    .and_then(|spec| spec.template.as_ref())
                    .map(|template| template.image.clone())
            })
            .ok_or_else(|| Status::failed_precondition("sandbox has no workload image"))?;
        if let Some(intent) = &pending {
            ensure_image_update_interlock(&current, intent)?;
            if !resume
                && (intent.image != image
                    || intent.command != update.command
                    || intent.environment != update.environment
                    || intent.labels != update.labels
                    || intent.annotations != update.annotations)
            {
                return Err(Status::failed_precondition(
                    "another sandbox update is pending; resume with the current resource version and no selected fields",
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
        let mut candidate = current.clone();
        openshell_core::sandbox_update::apply_configuration(
            &mut candidate,
            update.command.as_ref(),
            update.environment.as_ref(),
            update.labels.as_ref(),
            update.annotations.as_ref(),
        );
        if pending.is_none() && old_image == image && candidate == current {
            return Ok(current);
        }
        let revision = state.as_ref().map_or(0, |state| state.revision);
        let intent = pending.clone().unwrap_or_else(|| SandboxImageUpdate {
            operation_id: uuid::Uuid::new_v4().to_string(),
            previous_image: old_image,
            image,
            revision: revision.saturating_add(1),
            command: update.command.clone(),
            environment: update.environment.clone(),
            labels: update.labels.clone(),
            annotations: update.annotations.clone(),
        });
        if pending.is_none() && revision == u64::MAX {
            return Err(Status::resource_exhausted(
                "sandbox image revision exhausted",
            ));
        }
        let accepted = if pending.is_some() {
            current
        } else {
            // Keep lifecycle operations serialized, but let driver watch events
            // and reconciliation progress while preflight waits on the driver.
            // The acceptance CAS below rejects any intervening record changes.
            drop(sandbox_guard);
            self.reconcile_sandbox_update(&current, &intent, true)
                .await?;
            sandbox_guard = self.lock_sandbox_for_lifecycle(&lifecycle_guard).await;
            // The private intent, selected configuration, and OLD-understood pending
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
        self.reconcile_sandbox_update(&pending, &intent, false)
            .await?;
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
            "Sandbox configuration updated; sandbox remains stopped");
        Ok(updated)
    }

    async fn reconcile_sandbox_update(
        &self,
        sandbox: &Sandbox,
        intent: &SandboxImageUpdate,
        validate_only: bool,
    ) -> Result<(), Status> {
        let image_update = image_update_driver_request(sandbox, intent, validate_only);
        let mut candidate = sandbox.clone();
        openshell_core::sandbox_update::apply_configuration(
            &mut candidate,
            intent.command.as_ref(),
            intent.environment.as_ref(),
            intent.labels.as_ref(),
            intent.annotations.as_ref(),
        );
        let spec = candidate
            .spec
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("sandbox has no spec"))?;
        let main_process = intent.command.as_ref().map(|_| {
            openshell_core::proto::compute::v1::SandboxMainProcessUpdate {
                command: spec.command.clone(),
                tty: spec.tty,
            }
        });
        let environment = intent.environment.as_ref().map(|_| {
            let mut values = spec
                .template
                .as_ref()
                .map_or_else(Default::default, |template| template.environment.clone());
            values.extend(spec.environment.clone());
            openshell_core::proto::compute::v1::SandboxEnvironmentUpdate { values }
        });
        let request = openshell_core::proto::compute::v1::UpdateSandboxConfigurationRequest {
            preconditions: Some(image_update),
            main_process,
            environment,
        };
        let driver = self.image_update_driver.clone().ok_or_else(|| {
            Status::unimplemented("compute driver has no registered configuration updater")
        })?;
        self.driver
            .call_owned(
                openshell_otel::rpc::UPDATE_SANDBOX_CONFIGURATION,
                Some(sandbox.object_id()),
                move |_| async move {
                    driver
                        .update_sandbox_configuration(Request::new(request))
                        .await
                },
            )
            .await?;
        Ok(())
    }

    fn ensure_configuration_update_supported(&self) -> Result<(), Status> {
        let capability = COMPUTE_UPDATE_SANDBOX_CONFIGURATION;
        if self.image_update_driver.is_none()
            || !self
                .driver_info
                .negotiated_extension
                .supported_capabilities
                .iter()
                .any(|value| value == capability)
        {
            return Err(Status::unimplemented(format!(
                "compute driver does not support {capability}; restore a compatible driver to resume pending updates"
            )));
        }
        Ok(())
    }

    /// Recover from private durable intent, independent of new-update activation.
    pub(super) async fn recover_sandbox_update(&self, sandbox: &Sandbox) -> Result<bool, Status> {
        let state = self
            .store
            .get_sandbox_image_state(sandbox.object_id())
            .await
            .map_err(|_| Status::unavailable("cannot read pending sandbox update"))?;
        let Some(intent) = state.and_then(|state| state.pending) else {
            return Ok(false);
        };
        if sandbox.phase() == SandboxPhase::Deleting as i32 {
            return Ok(false);
        }
        ensure_image_update_stopped(sandbox)?;
        self.ensure_configuration_update_supported()?;
        self.complete_image_update(sandbox.clone(), intent).await?;
        Ok(true)
    }

    pub(super) async fn recover_pending_sandbox_updates(&self) -> Result<(), String> {
        let Ok(permit) = self.update_recovery_sweep.clone().try_acquire_owned() else {
            return Ok(());
        };
        let ids = self
            .store
            .list_pending_sandbox_update_ids(None, UPDATE_RECOVERY_PAGE_SIZE)
            .await
            .map_err(|error| format!("list pending sandbox updates: {error}"))?;
        if ids.is_empty() {
            return Ok(());
        }
        let runtime = self.clone();
        // Recovery must not hold readiness or unrelated reconciliation hostage
        // to a slow remote driver. One bounded sweep per runtime, at most eight
        // operations in flight, with the normal per-sandbox lifecycle gate.
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = runtime.recover_pending_sandbox_update_pages(ids).await {
                tracing::warn!(%error, "Sandbox update recovery sweep failed");
            }
        });
        Ok(())
    }

    async fn recover_pending_sandbox_update_pages(
        &self,
        mut ids: Vec<String>,
    ) -> Result<(), String> {
        use futures::StreamExt as _;
        while let Some(after) = ids.last().cloned() {
            futures::stream::iter(ids)
                .for_each_concurrent(8, |id| {
                    // Each sandbox owns independent locks even though these
                    // futures are polled concurrently in the same Tokio task.
                    crate::persistence::lock_order::branch(async move {
                        if let Err(error) = self.recover_one_sandbox_update(&id).await {
                            tracing::warn!(sandbox_id = %id, %error,
                                "Sandbox update remains pending; recovery will retry");
                        }
                    })
                })
                .await;
            ids = self
                .store
                .list_pending_sandbox_update_ids(Some(&after), UPDATE_RECOVERY_PAGE_SIZE)
                .await
                .map_err(|error| format!("list pending sandbox updates: {error}"))?;
        }
        Ok(())
    }

    async fn recover_one_sandbox_update(&self, id: &str) -> Result<(), Status> {
        let Some(_gate) = self.lifecycle_gates.try_lock_for(id) else {
            return Ok(());
        };
        let recover = async {
            let sandbox = self
                .store
                .get_message::<Sandbox>(id)
                .await
                .map_err(|_| Status::unavailable("cannot read sandbox for update recovery"))?;
            if let Some(sandbox) = sandbox {
                self.recover_sandbox_update(&sandbox).await?;
            }
            Ok(())
        };
        tokio::time::timeout(std::time::Duration::from_mins(1), recover)
            .await
            .map_err(|_| Status::deadline_exceeded("sandbox update recovery timed out"))?
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
                "sandbox update is pending; recovery will retry automatically, or resume UpdateSandbox with the current resource version and no selected fields",
            ));
        }
        Ok(())
    }
}

pub(super) fn ensure_image_update_interlock(
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
) -> SandboxUpdatePreconditions {
    SandboxUpdatePreconditions {
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
            "sandbox must be Stopped before updating its configuration",
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
        runtime.sandbox_updates_enabled = true;
        if supported {
            runtime.image_update_driver = Some(driver.clone());
            runtime
                .driver_info
                .negotiated_extension
                .supported_capabilities
                .extend([COMPUTE_UPDATE_SANDBOX_CONFIGURATION.into()]);
        }
        let mut sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: "image-sandbox-id".into(),
                name: "image-sandbox".into(),
                workspace: "default".into(),
                labels: HashMap::from([("app".into(), "retained".into())]),
                annotations: HashMap::from([
                    (
                        COMPUTE_RUNTIME_IDENTITY_ANNOTATION.into(),
                        "stable-runtime".into(),
                    ),
                    (
                        crate::compute::ISOLATION_BACKEND_ANNOTATION.into(),
                        openshell_core::isolation_registration::BUILTIN_BACKEND_NAME.into(),
                    ),
                ]),
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

    fn image_calls(driver: &FakeComputeDriver) -> Vec<SandboxUpdatePreconditions> {
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
    async fn recovery_drains_multiple_pending_pages_with_updates_disabled() {
        let (mut runtime, driver, original) = fixture(true).await;
        runtime.sandbox_updates_enabled = false;
        let mut expected_ids = Vec::new();
        for index in 0..129 {
            let id = format!("pending-{index:03}");
            let mut sandbox = original.clone();
            let metadata = sandbox.metadata.as_mut().unwrap();
            metadata.id.clone_from(&id);
            metadata.name.clone_from(&id);
            runtime.store.put_message(&sandbox).await.unwrap();
            let sandbox = runtime
                .store
                .get_message::<Sandbox>(&id)
                .await
                .unwrap()
                .unwrap();
            runtime
                .store
                .begin_sandbox_image_update(
                    &id,
                    sandbox.get_resource_version(),
                    0,
                    &SandboxImageUpdate {
                        operation_id: format!("operation-{index}"),
                        previous_image: "example/workload:old".into(),
                        image: "example/workload:new".into(),
                        revision: 1,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            expected_ids.push(id);
        }
        runtime.recover_pending_sandbox_updates().await.unwrap();
        drop(runtime.update_recovery_sweep.acquire().await.unwrap());
        let mut recovered_ids: Vec<_> = image_calls(&driver)
            .into_iter()
            .map(|call| call.sandbox_id)
            .collect();
        recovered_ids.sort();
        assert_eq!(recovered_ids, expected_ids);
        assert!(
            runtime
                .store
                .list_pending_sandbox_update_ids(None, 128)
                .await
                .unwrap()
                .is_empty()
        );
        // A subsequent empty sweep must not revisit completed updates.
        runtime.recover_pending_sandbox_updates().await.unwrap();
        drop(runtime.update_recovery_sweep.acquire().await.unwrap());
        assert_eq!(image_calls(&driver).len(), expected_ids.len());
    }

    #[tokio::test]
    async fn startup_does_not_wait_for_a_blocked_update_driver() {
        use std::time::Duration;
        for manages_lifecycle in [false, true] {
            let (mut runtime, driver, original) = fixture(true).await;
            runtime.driver_info.gateway_manages_lifecycle = manages_lifecycle;
            driver.set_image_update_error(Some(Code::Unavailable));
            runtime
                .update_sandbox_image(
                    original.object_id(),
                    "new-image".into(),
                    original.get_resource_version(),
                )
                .await
                .unwrap_err();
            driver.set_image_update_error(None);
            let (entered, release) = driver.pause_image_updates();
            tokio::time::timeout(Duration::from_secs(2), runtime.start_persisted_sandboxes())
                .await
                .expect("startup must not wait on update recovery")
                .unwrap();
            tokio::time::timeout(Duration::from_secs(2), entered.notified())
                .await
                .expect("startup must schedule update recovery");
            assert!(
                runtime
                    .store
                    .get_sandbox_image_state(original.object_id())
                    .await
                    .unwrap()
                    .unwrap()
                    .pending
                    .is_some()
            );
            release.add_permits(1);
            drop(runtime.update_recovery_sweep.acquire().await.unwrap());
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
    }

    #[tokio::test]
    async fn recovery_uses_stored_selection_even_when_admission_is_disabled() {
        use openshell_core::proto::{SandboxCommandUpdate, SandboxMapUpdate, UpdateSandboxRequest};
        for automatic in [false, true] {
            let (mut runtime, driver, original) = fixture(true).await;
            driver.set_image_update_error(Some(Code::Unavailable));
            let update = UpdateSandboxRequest {
                command: Some(SandboxCommandUpdate {
                    argv: vec!["sleep".into(), "infinity".into()],
                }),
                environment: Some(SandboxMapUpdate::default()),
                expected_resource_version: original.get_resource_version(),
                ..Default::default()
            };
            runtime
                .update_sandbox_configuration(original.object_id(), &update)
                .await
                .unwrap_err();
            runtime.sandbox_updates_enabled = false;
            // Missing driver support keeps the intent; restoring it is enough
            // for recovery, without re-enabling admission or reconstructing fields.
            let updater = runtime.image_update_driver.take();
            runtime.recover_pending_sandbox_updates().await.unwrap();
            drop(runtime.update_recovery_sweep.acquire().await.unwrap());
            assert!(
                runtime
                    .store
                    .get_sandbox_image_state(original.object_id())
                    .await
                    .unwrap()
                    .unwrap()
                    .pending
                    .is_some()
            );
            runtime.image_update_driver = updater;
            driver.set_image_update_error(None);
            let pending = runtime
                .store
                .get_message::<Sandbox>(original.object_id())
                .await
                .unwrap()
                .unwrap();
            if automatic {
                runtime.recover_pending_sandbox_updates().await.unwrap();
                drop(runtime.update_recovery_sweep.acquire().await.unwrap());
            } else {
                runtime
                    .update_sandbox_configuration(
                        original.object_id(),
                        &UpdateSandboxRequest {
                            expected_resource_version: pending.get_resource_version(),
                            ..Default::default()
                        },
                    )
                    .await
                    .unwrap();
            }
            let complete = runtime
                .store
                .get_message::<Sandbox>(original.object_id())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(complete.spec, pending.spec);
            assert!(provisioning_operation::ensure_operation_settled(&complete).is_ok());
            let calls = image_calls(&driver);
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0], calls[1]);
        }
    }

    #[tokio::test]
    async fn metadata_only_update_preserves_retention_and_needs_no_driver_capability() {
        use openshell_core::proto::{SandboxMapUpdate, UpdateSandboxRequest};
        let (runtime, driver, mut original) = fixture(false).await;
        original.metadata.as_mut().unwrap().annotations.extend([
            ("openshell.nvidia.com/retention".into(), "ephemeral".into()),
            ("openshell.ai/user-note".into(), "old".into()),
        ]);
        runtime.store.put_message(&original).await.unwrap();
        let original = runtime
            .store
            .get_message::<Sandbox>(original.object_id())
            .await
            .unwrap()
            .unwrap();
        let updated = runtime
            .update_sandbox_configuration(
                original.object_id(),
                &UpdateSandboxRequest {
                    labels: Some(SandboxMapUpdate {
                        values: HashMap::from([("team".into(), "new".into())]),
                    }),
                    annotations: Some(SandboxMapUpdate {
                        values: HashMap::from([("openshell.ai/user-note".into(), "new".into())]),
                    }),
                    expected_resource_version: original.get_resource_version(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            updated.metadata.as_ref().unwrap().annotations["openshell.nvidia.com/retention"],
            "ephemeral"
        );
        assert_eq!(
            updated.metadata.as_ref().unwrap().annotations["openshell.ai/user-note"],
            "new"
        );
        let noop = runtime
            .update_sandbox_configuration(
                original.object_id(),
                &UpdateSandboxRequest {
                    labels: Some(SandboxMapUpdate {
                        values: updated.metadata.as_ref().unwrap().labels.clone(),
                    }),
                    expected_resource_version: updated.get_resource_version(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(noop, updated);
        assert_eq!(updated.spec, original.spec);
        assert_eq!(updated.status, original.status);
        assert!(image_calls(&driver).is_empty());
        assert!(
            runtime
                .store
                .get_sandbox_image_state(original.object_id())
                .await
                .unwrap()
                .is_none()
        );
        let record = runtime
            .store
            .get("sandbox", original.object_id())
            .await
            .unwrap()
            .unwrap();
        let labels: serde_json::Value =
            serde_json::from_str(record.labels.as_ref().unwrap()).unwrap();
        assert_eq!(labels["team"], "new");
        assert_eq!(
            runtime
                .update_sandbox_configuration(
                    original.object_id(),
                    &UpdateSandboxRequest {
                        labels: Some(SandboxMapUpdate::default()),
                        expected_resource_version: original.get_resource_version(),
                        ..Default::default()
                    }
                )
                .await
                .unwrap_err()
                .code(),
            Code::Aborted
        );
    }

    #[tokio::test]
    async fn explicit_delete_supersedes_pending_update_without_restoring_the_driver() {
        let (mut runtime, driver, original) = fixture(true).await;
        driver.set_image_update_error(Some(Code::Unavailable));
        runtime
            .update_sandbox_image(
                original.object_id(),
                "new-image".into(),
                original.get_resource_version(),
            )
            .await
            .unwrap_err();
        let intent = runtime
            .store
            .get_sandbox_image_state(original.object_id())
            .await
            .unwrap()
            .unwrap()
            .pending
            .unwrap();
        runtime.image_update_driver = None;
        runtime.sandbox_updates_enabled = false;
        runtime
            .delete_sandbox("default", original.object_name())
            .await
            .unwrap();
        assert!(
            runtime
                .store
                .get_message::<Sandbox>(original.object_id())
                .await
                .unwrap()
                .is_none()
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
            runtime
                .store
                .complete_sandbox_image_update(original.object_id(), &intent)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn configuration_update_reconciles_all_fields_and_recovers_exact_pending_target() {
        use openshell_core::proto::{SandboxCommandUpdate, SandboxMapUpdate, UpdateSandboxRequest};
        let (runtime, driver, original) = fixture(true).await;
        let request = UpdateSandboxRequest {
            image: Some("example/workload:new".into()),
            command: Some(SandboxCommandUpdate {
                argv: vec!["/usr/local/bin/start-agent".into(), "--new".into()],
            }),
            environment: Some(SandboxMapUpdate {
                values: HashMap::from([("MODE".into(), "new".into())]),
            }),
            labels: Some(SandboxMapUpdate {
                values: HashMap::from([("team".into(), "agents".into())]),
            }),
            annotations: Some(SandboxMapUpdate {
                values: HashMap::from([("example.com/revision".into(), "2".into())]),
            }),
            expected_resource_version: original.get_resource_version(),
            ..Default::default()
        };
        driver.set_image_update_error(Some(Code::Unavailable));
        assert_eq!(
            runtime
                .update_sandbox_configuration(original.object_id(), &request)
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
            pending
                .status
                .as_ref()
                .unwrap()
                .provisioning
                .as_ref()
                .unwrap()
                .driver_operation_pending
        );
        let mut retry = request.clone();
        retry.expected_resource_version = pending.get_resource_version();
        retry
            .command
            .as_mut()
            .unwrap()
            .argv
            .push("--different".into());
        assert_eq!(
            runtime
                .update_sandbox_configuration(original.object_id(), &retry)
                .await
                .unwrap_err()
                .code(),
            Code::FailedPrecondition
        );
        retry.command = request.command.clone();
        driver.set_image_update_error(None);
        let updated = runtime
            .update_sandbox_configuration(original.object_id(), &retry)
            .await
            .unwrap();
        assert_eq!(updated.phase(), SandboxPhase::Stopped as i32);
        assert_eq!(
            updated.spec.as_ref().unwrap().command,
            request.command.unwrap().argv
        );
        assert_eq!(
            updated.spec.as_ref().unwrap().environment,
            request.environment.unwrap().values
        );
        for (key, value) in &original.metadata.as_ref().unwrap().annotations {
            if openshell_core::sandbox_update::is_system_metadata_key(key) {
                assert_eq!(
                    updated.metadata.as_ref().unwrap().annotations.get(key),
                    Some(value)
                );
            }
        }
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
        let clear = UpdateSandboxRequest {
            command: Some(SandboxCommandUpdate::default()),
            environment: Some(SandboxMapUpdate::default()),
            labels: Some(SandboxMapUpdate::default()),
            annotations: Some(SandboxMapUpdate::default()),
            expected_resource_version: updated.get_resource_version(),
            ..Default::default()
        };
        let cleared = runtime
            .update_sandbox_configuration(original.object_id(), &clear)
            .await
            .unwrap();
        assert!(cleared.spec.as_ref().unwrap().command.is_empty());
        assert!(cleared.spec.as_ref().unwrap().environment.is_empty());
        assert!(cleared.metadata.as_ref().unwrap().labels.is_empty());
        assert_eq!(
            cleared
                .spec
                .as_ref()
                .unwrap()
                .template
                .as_ref()
                .unwrap()
                .image,
            "example/workload:new"
        );
    }

    #[tokio::test]
    async fn configuration_update_requires_capability_before_mutating() {
        use openshell_core::proto::SandboxCommandUpdate;
        let (mut runtime, _, original) = fixture(true).await;
        runtime
            .driver_info
            .negotiated_extension
            .supported_capabilities
            .retain(|capability| capability != COMPUTE_UPDATE_SANDBOX_CONFIGURATION);
        let update = openshell_core::proto::UpdateSandboxRequest {
            command: Some(SandboxCommandUpdate::default()),
            expected_resource_version: original.get_resource_version(),
            ..Default::default()
        };
        assert_eq!(
            runtime
                .update_sandbox_configuration(original.object_id(), &update)
                .await
                .unwrap_err()
                .code(),
            Code::Unimplemented
        );
        assert!(
            runtime
                .store
                .get_sandbox_image_state(original.object_id())
                .await
                .unwrap()
                .is_none()
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
    }

    #[tokio::test]
    async fn image_update_preserves_identity_and_every_other_spec_field() {
        let (runtime, driver, mut original) = fixture(true).await;
        // Image edits must preserve the upstream backend pin and launch identity,
        // including generation/session and authorization epoch annotations.
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
    async fn image_update_state_is_removed_on_sandbox_deletion() {
        for out_of_band in [false, true] {
            let (runtime, _, original) = fixture(true).await;
            let mut unrelated = original.clone();
            let metadata = unrelated.metadata.as_mut().unwrap();
            metadata.id = "unrelated-sandbox-id".into();
            metadata.name = "unrelated-sandbox".into();
            runtime.store.put_message(&unrelated).await.unwrap();
            let unrelated = runtime
                .store
                .get_message::<Sandbox>(unrelated.object_id())
                .await
                .unwrap()
                .unwrap();
            for sandbox in [&original, &unrelated] {
                runtime
                    .update_sandbox_image(
                        sandbox.object_id(),
                        "example/workload:new".into(),
                        sandbox.get_resource_version(),
                    )
                    .await
                    .unwrap();
            }
            let unrelated_state = runtime
                .store
                .get_sandbox_image_state(unrelated.object_id())
                .await
                .unwrap()
                .unwrap();
            assert!(
                runtime
                    .store
                    .get_sandbox_image_state(original.object_id())
                    .await
                    .unwrap()
                    .is_some()
            );

            // Exercise explicit deletion and watch-driven removal, including
            // a delayed or repeated watch deletion event.
            if out_of_band {
                runtime.apply_deleted(original.object_id()).await.unwrap();
            } else {
                runtime
                    .delete_sandbox("default", original.object_name())
                    .await
                    .unwrap();
            }
            runtime.apply_deleted(original.object_id()).await.unwrap();
            assert!(
                runtime
                    .store
                    .get_message::<Sandbox>(original.object_id())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                runtime
                    .store
                    .get_sandbox_image_state(original.object_id())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                runtime
                    .store
                    .get_sandbox_image_state(unrelated.object_id())
                    .await
                    .unwrap(),
                Some(unrelated_state)
            );
        }
    }

    #[tokio::test]
    async fn image_update_rejects_unregistered_updater_without_writes() {
        let (mut runtime, driver, original) = fixture(true).await;
        runtime.image_update_driver = None;
        driver.clear_calls();
        let error = runtime
            .update_sandbox_image(
                original.object_id(),
                "example/workload:new".into(),
                original.get_resource_version(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::Unimplemented);
        assert!(driver.calls().is_empty());
        assert_eq!(
            runtime
                .store
                .get_message::<Sandbox>(original.object_id())
                .await
                .unwrap(),
            Some(original.clone())
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
    async fn image_preflight_allows_watch_progress_and_rejects_intervening_changes() {
        use openshell_core::proto::compute::v1::{
            WatchSandboxesEvent, WatchSandboxesSandboxEvent, watch_sandboxes_event,
        };
        use std::time::Duration;

        let (runtime, driver, original) = fixture(true).await;
        let mut unrelated = original.clone();
        let metadata = unrelated.metadata.as_mut().unwrap();
        metadata.id = "unrelated-sandbox-id".into();
        metadata.name = "unrelated-sandbox".into();
        runtime.store.put_message(&unrelated).await.unwrap();
        let unrelated = runtime
            .store
            .get_message::<Sandbox>(unrelated.object_id())
            .await
            .unwrap()
            .unwrap();
        let (entered, release) = driver.pause_image_updates();
        let update = {
            let runtime = runtime.clone();
            let original = original.clone();
            tokio::spawn(async move {
                runtime
                    .update_sandbox_image(
                        original.object_id(),
                        "example/workload:new".into(),
                        original.get_resource_version(),
                    )
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("update must reach preflight");

        // Process snapshots in watch-loop order. The event for the sandbox
        // being validated must not hold up the following unrelated event.
        tokio::time::timeout(Duration::from_secs(2), async {
            for sandbox in [&original, &unrelated] {
                runtime
                    .apply_watch_event(WatchSandboxesEvent {
                        payload: Some(watch_sandboxes_event::Payload::Sandbox(
                            WatchSandboxesSandboxEvent {
                                sandbox: Some(DriverSandbox {
                                    id: sandbox.object_id().into(),
                                    name: sandbox.object_name().into(),
                                    ..Default::default()
                                }),
                            },
                        )),
                    })
                    .await
                    .unwrap();
            }
        })
        .await
        .expect("watch events must progress while preflight is paused");
        for sandbox in [&original, &unrelated] {
            let observed = runtime
                .store
                .get_message::<Sandbox>(sandbox.object_id())
                .await
                .unwrap()
                .unwrap();
            assert!(observed.get_resource_version() > sandbox.get_resource_version());
            assert_eq!(observed.spec, sandbox.spec);
        }

        // The original conditional request is now stale. Preflight success
        // must not commit intent or issue a mutating driver call.
        release.add_permits(1);
        let result = tokio::time::timeout(Duration::from_secs(2), update)
            .await
            .expect("stale update must finish without applying")
            .unwrap();
        assert_eq!(result.unwrap_err().code(), Code::Aborted);
        assert!(image_calls(&driver).is_empty());
        assert!(
            runtime
                .store
                .get_sandbox_image_state(original.object_id())
                .await
                .unwrap()
                .is_none()
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
    async fn terminal_workload_can_stop_update_command_and_start() {
        use openshell_core::proto::{SandboxCommandUpdate, UpdateSandboxRequest};

        for exit_code in [0, 1, 137] {
            let (runtime, driver, mut original) = fixture(true).await;
            crate::auth::sandbox_session::PersistedSandboxIdentity::new()
                .unwrap()
                .write(&mut original.metadata.as_mut().unwrap().annotations);
            original.spec.as_mut().unwrap().command =
                vec!["/bin/sh".into(), "-c".into(), format!("exit {exit_code}")];
            super::super::apply_main_process_exit(&mut original, "exited-instance", exit_code);
            runtime.store.put_message(&original).await.unwrap();

            let stopped = runtime
                .stop_sandbox("default", original.object_name())
                .await
                .unwrap();
            assert_eq!(stopped.phase(), SandboxPhase::Stopped as i32);
            assert_eq!(stopped.status.as_ref().unwrap().exit_code, Some(exit_code));
            assert_eq!(
                stopped.status.as_ref().unwrap().main_process_instance_id,
                "exited-instance"
            );
            assert_eq!(stopped.spec, original.spec);
            assert_eq!(stopped.object_id(), original.object_id());
            assert_eq!(stopped.host_key_fingerprint, original.host_key_fingerprint);
            let repeated = runtime
                .stop_sandbox("default", original.object_name())
                .await
                .unwrap();
            assert_eq!(repeated, stopped);

            let command = vec!["sleep".into(), "infinity".into()];
            let updated = runtime
                .update_sandbox_configuration(
                    original.object_id(),
                    &UpdateSandboxRequest {
                        command: Some(SandboxCommandUpdate {
                            argv: command.clone(),
                        }),
                        expected_resource_version: stopped.get_resource_version(),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(updated.phase(), SandboxPhase::Stopped as i32);
            assert_eq!(updated.spec.as_ref().unwrap().command, command);
            assert_eq!(updated.status.as_ref().unwrap().exit_code, Some(exit_code));
            let starting = runtime
                .start_sandbox("default", original.object_name())
                .await
                .unwrap();
            assert_eq!(starting.phase(), SandboxPhase::Starting as i32);
            assert_eq!(starting.spec, updated.spec);
            assert_eq!(starting.status.as_ref().unwrap().exit_code, None);
            let calls = driver.calls();
            assert_eq!(
                calls
                    .iter()
                    .filter(|call| matches!(call, FakeComputeDriverCall::StopSandbox { .. }))
                    .count(),
                1,
                "terminal compute must be stopped once before updating"
            );
            assert!(!calls.iter().any(|call| matches!(
                call,
                FakeComputeDriverCall::DeleteSandbox { .. }
                    | FakeComputeDriverCall::CreateSandbox { .. }
            )));
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
    async fn sandbox_update_activation_is_disabled_by_default_without_effects() {
        let (mut runtime, driver, original) = fixture(true).await;
        runtime.sandbox_updates_enabled = false;
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
