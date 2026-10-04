// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Explicit recovery must stop retained compute before issuing a fresh launch.

use super::*;
use crate::auth::sandbox_session::PersistedSandboxIdentity;
use openshell_core::proto::ConfigurationAdmissionState;

async fn stored(runtime: &ComputeRuntime, id: &str) -> Sandbox {
    runtime
        .store
        .get_message::<Sandbox>(id)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn failed_gateway_start_can_be_stopped_and_retried() {
    let driver = ControlledDriver::new();
    driver.set_start_outcome(ControlledLifecycleOutcome::Error(
        "supervisor endpoint unavailable",
    ));
    driver.set_runtime_identity("retained-runtime");
    let mut runtime =
        test_runtime_with_gateway_managed_lifecycle(driver.clone(), "test-driver").await;
    enable_runtime_identity_binding(&mut runtime);
    let mut sandbox = sandbox_record("retained-id", "retained", SandboxPhase::Ready);
    sandbox.spec = Some(SandboxSpec {
        template: Some(SandboxTemplate {
            image: "example.test/workload:retained".into(),
            ..Default::default()
        }),
        command: vec!["sleep".into(), "3600".into()],
        ..Default::default()
    });
    sandbox.status.as_mut().unwrap().configuration_activated = Some(true);
    set_compute_runtime_binding(&mut sandbox, "retained-runtime");
    runtime.store.put_message(&sandbox).await.unwrap();

    // Exercise the production startup sweep rather than inventing its failure record.
    runtime.start_persisted_sandboxes().await.unwrap();
    let failed = stored(&runtime, sandbox.object_id()).await;
    assert_eq!(failed.phase(), SandboxPhase::Error as i32);
    assert_eq!(ready_condition(&failed).unwrap().reason, "StartFailed");
    driver.set_start_outcome(ControlledLifecycleOutcome::Ok);
    runtime.start_persisted_sandboxes().await.unwrap();
    assert_eq!(
        driver.start_calls(),
        1,
        "gateway restart does not retry this Error"
    );
    let error = runtime
        .start_sandbox("default", "retained")
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);

    let session = ssh_session_record("old-session", sandbox.object_id());
    runtime.store.put_message(&session).await.unwrap();
    register_test_supervisor_session(&runtime, sandbox.object_id());
    let stopped = runtime.stop_sandbox("default", "retained").await.unwrap();
    assert_eq!(stopped.phase(), SandboxPhase::Stopped as i32);
    assert_eq!(stopped.object_id(), sandbox.object_id());
    assert_eq!(stopped.object_workspace(), sandbox.object_workspace());
    assert_eq!(stopped.spec, sandbox.spec);
    assert_eq!(
        sandbox_compute_runtime_identity(&stopped),
        "retained-runtime"
    );
    assert_eq!(
        driver.stop_requests(),
        vec![("retained-id".into(), "retained".into())]
    );
    assert_eq!(driver.delete_calls(), 0);
    assert!(!runtime.supervisor_sessions.has_session(sandbox.object_id()));
    assert!(
        runtime
            .store
            .get_message::<SshSession>(session.object_id())
            .await
            .unwrap()
            .is_none()
    );

    let authority = test_session_authority();
    let starting = runtime
        .start_sandbox_authenticated("default", "retained", Some(&authority))
        .await
        .unwrap();
    assert_eq!(starting.phase(), SandboxPhase::Starting as i32);
    assert_eq!(starting.object_id(), sandbox.object_id());
    assert_eq!(starting.spec, sandbox.spec);
    let before =
        PersistedSandboxIdentity::read(&failed.metadata.as_ref().unwrap().annotations).unwrap();
    let after =
        PersistedSandboxIdentity::read(&starting.metadata.as_ref().unwrap().annotations).unwrap();
    assert_eq!(after.runtime_generation, before.runtime_generation);
    assert_eq!(after.auth_epoch.get(), before.auth_epoch.get() + 1);
    assert_ne!(after.gateway_token_id, before.gateway_token_id);
    assert_eq!(
        driver.start_expected_runtime_identities(),
        vec!["retained-runtime", "retained-runtime"]
    );
    let status = starting.status.as_ref().unwrap();
    assert_eq!(status.configuration_activated, Some(true));
    assert_eq!(
        status.configuration_admission.as_ref().unwrap().state,
        ConfigurationAdmissionState::Pending as i32
    );

    // A live driver and connected supervisor cannot skip fresh configuration admission.
    register_test_supervisor_session(&runtime, sandbox.object_id());
    let snapshot = ready_driver_sandbox(sandbox.object_id(), sandbox.object_name());
    driver.set_get_outcome(ControlledGetOutcome::Sandbox(Box::new(snapshot.clone())));
    runtime.apply_sandbox_update(snapshot).await.unwrap();
    assert_eq!(
        stored(&runtime, sandbox.object_id()).await.phase(),
        SandboxPhase::Starting as i32
    );
    assert_eq!(driver.delete_calls(), 0);
}

#[tokio::test]
async fn explicit_stop_accepts_driver_error_reasons_without_an_allowlist() {
    for reason in [
        "StartFailed",
        "ProcessExited",
        "ContainerExited",
        "DriverSpecificFailure",
    ] {
        let driver = ControlledDriver::new();
        let runtime = test_runtime(driver.clone()).await;
        let sandbox = error_sandbox_record("error-id", "errored", reason);
        runtime.store.put_message(&sandbox).await.unwrap();

        let stopped = runtime.stop_sandbox("default", "errored").await.unwrap();
        assert_eq!(stopped.phase(), SandboxPhase::Stopped as i32, "{reason}");
        assert_eq!(
            driver.stop_calls(),
            1,
            "Error is not proof that compute stopped"
        );
        assert_eq!(driver.delete_calls(), 0);
        runtime.stop_sandbox("default", "errored").await.unwrap();
        assert_eq!(
            driver.stop_calls(),
            1,
            "a completed stop remains idempotent"
        );
    }
}

#[tokio::test]
async fn pending_driver_operation_blocks_error_recovery_without_mutation() {
    let driver = ControlledDriver::new();
    let runtime = test_runtime(driver.clone()).await;
    let mut sandbox = error_sandbox_record("pending-id", "pending", "StartFailed");
    let mut operation = provisioning_deadline::new_record(openshell_core::time::now_ms());
    operation.driver_operation_pending = true;
    operation.driver_operation_id = "owned-operation".into();
    sandbox.status.as_mut().unwrap().provisioning = Some(operation);
    runtime.store.put_message(&sandbox).await.unwrap();
    let before = stored(&runtime, sandbox.object_id()).await;

    let error = runtime
        .stop_sandbox("default", "pending")
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert!(error.message().contains("operation is still pending"));
    assert_eq!(stored(&runtime, sandbox.object_id()).await, before);
    assert_eq!(driver.stop_calls(), 0);
    assert_eq!(driver.delete_calls(), 0);
}

#[tokio::test]
async fn timeout_stop_preserves_cleanup_and_direct_start_recovery() {
    for cleanup_complete in [false, true] {
        let driver = ControlledDriver::new();
        driver.set_start_outcome(ControlledLifecycleOutcome::NotFound);
        driver.track_compute.store(true, Ordering::SeqCst);
        let runtime = test_runtime(driver.clone()).await;
        let mut sandbox = error_sandbox_record("timeout-id", "timeout", "ProvisioningTimedOut");
        let mut operation = provisioning_deadline::new_record(0);
        operation.timeout_time = openshell_core::time::timestamp_from_millis(300_000).ok();
        operation.cleanup_retry_time = openshell_core::time::timestamp_from_millis(310_000).ok();
        if cleanup_complete {
            operation.cleanup_completed_time =
                openshell_core::time::timestamp_from_millis(320_000).ok();
        }
        sandbox.status.as_mut().unwrap().provisioning = Some(operation);
        runtime.store.put_message(&sandbox).await.unwrap();
        let before = stored(&runtime, sandbox.object_id()).await;

        let error = runtime
            .stop_sandbox("default", "timeout")
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::FailedPrecondition);
        assert!(error.message().contains("start"));
        assert_eq!(stored(&runtime, sandbox.object_id()).await, before);
        assert_eq!(driver.stop_calls(), 0, "timeout cleanup owns reclamation");

        let result = runtime.start_sandbox("default", "timeout").await;
        if cleanup_complete {
            assert_eq!(result.unwrap().phase(), SandboxPhase::Starting as i32);
            assert!(
                driver.compute_exists.load(Ordering::SeqCst),
                "start recreates the missing backend after cleanup"
            );
            assert_eq!(driver.start_calls(), 1);
        } else {
            assert_eq!(result.unwrap_err().code(), Code::FailedPrecondition);
            assert_eq!(stored(&runtime, sandbox.object_id()).await, before);
            assert_eq!(driver.start_calls(), 0);
        }
        assert_eq!(driver.delete_calls(), 0);
    }
}

#[tokio::test]
async fn failed_error_stop_retains_retryable_state_without_claiming_success() {
    for observed_error in [false, true] {
        let driver = ControlledDriver::new();
        driver.set_stop_outcome(ControlledLifecycleOutcome::Error(
            "stop response unavailable",
        ));
        let runtime = test_runtime(driver.clone()).await;
        let sandbox = error_sandbox_record("retry-id", "retry", "ProcessExited");
        if observed_error {
            let mut snapshot = ready_driver_sandbox("retry-id", "retry");
            snapshot.status.as_mut().unwrap().conditions = vec![DriverCondition {
                r#type: "Ready".into(),
                status: "False".into(),
                reason: "ProcessExited".into(),
                message: "runtime exited".into(),
                ..Default::default()
            }];
            driver.set_get_outcome(ControlledGetOutcome::Sandbox(Box::new(snapshot)));
        } else {
            // A response for a different sandbox cannot settle this one's stop.
            driver.set_get_outcome(ControlledGetOutcome::Sandbox(Box::new(
                ready_driver_sandbox("foreign-id", "retry"),
            )));
        }
        runtime.store.put_message(&sandbox).await.unwrap();

        let error = runtime.stop_sandbox("default", "retry").await.unwrap_err();
        assert_eq!(error.code(), Code::Internal);
        let retained = stored(&runtime, sandbox.object_id()).await;
        assert_eq!(
            retained.phase(),
            if observed_error {
                SandboxPhase::Error
            } else {
                SandboxPhase::Stopping
            } as i32
        );
        assert_eq!(retained.object_id(), sandbox.object_id());
        driver.set_stop_outcome(ControlledLifecycleOutcome::Ok);
        assert_eq!(
            runtime
                .stop_sandbox("default", "retry")
                .await
                .unwrap()
                .phase(),
            SandboxPhase::Stopped as i32
        );
        assert_eq!(
            driver.stop_requests(),
            vec![("retry-id".into(), "retry".into()); 2]
        );
        assert_eq!(driver.start_calls(), 0);
        assert_eq!(driver.delete_calls(), 0);
    }
}

#[tokio::test]
async fn canceled_error_stop_still_settles_before_start() {
    let driver = ControlledDriver::new();
    driver.block_stop();
    let runtime = test_runtime(driver.clone()).await;
    let sandbox = error_sandbox_record("cancel-id", "cancel", "StartFailed");
    runtime.store.put_message(&sandbox).await.unwrap();
    let request_runtime = runtime.clone();
    let request =
        tokio::spawn(async move { request_runtime.stop_sandbox("default", "cancel").await });
    tokio::time::timeout(Duration::from_secs(3), driver.stop_started.notified())
        .await
        .expect("stop must reach the driver");
    assert_eq!(
        stored(&runtime, sandbox.object_id()).await.phase(),
        SandboxPhase::Stopping as i32
    );
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    driver.release_stop();
    let gate = tokio::time::timeout(
        Duration::from_secs(3),
        runtime.lifecycle_gates.lock_for(sandbox.object_id()),
    )
    .await
    .expect("owned stop worker must finish after cancellation");
    assert_eq!(
        stored(&runtime, sandbox.object_id()).await.phase(),
        SandboxPhase::Stopped as i32
    );
    drop(gate);
    assert_eq!(
        runtime
            .start_sandbox("default", "cancel")
            .await
            .unwrap()
            .phase(),
        SandboxPhase::Starting as i32
    );
    assert_eq!(driver.stop_calls(), 1);
    assert_eq!(driver.start_calls(), 1);
    assert_eq!(driver.delete_calls(), 0);
}
