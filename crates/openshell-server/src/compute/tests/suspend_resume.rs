// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Suspend retains memory state behind gateway-owned phases; resume restores
//! it in a new runtime generation.

use super::*;

async fn stored(runtime: &ComputeRuntime, id: &str) -> Sandbox {
    runtime
        .store
        .get_message::<Sandbox>(id)
        .await
        .unwrap()
        .unwrap()
}

fn enable_suspend_resume(runtime: &mut ComputeRuntime) {
    runtime
        .driver_info
        .negotiated_extension
        .supported_capabilities
        .push(openshell_core::extension_protocol::COMPUTE_SUSPEND_RESUME.to_string());
}

async fn suspend_capable_runtime(driver: Arc<ControlledDriver>) -> ComputeRuntime {
    let mut runtime = test_runtime(driver).await;
    enable_suspend_resume(&mut runtime);
    runtime
}

fn has_resume_intent(sandbox: &Sandbox) -> bool {
    sandbox
        .metadata
        .as_ref()
        .is_some_and(|metadata| metadata.annotations.contains_key(RESUME_INTENT_ANNOTATION))
}

fn exited_driver_sandbox(sandbox: &Sandbox) -> DriverSandbox {
    let mut exited = ready_driver_sandbox(sandbox.object_id(), sandbox.object_name());
    exited.status = Some(make_driver_status(make_driver_condition(
        "ContainerExited",
        "Container exited with status 0",
    )));
    exited
}

#[tokio::test]
async fn suspend_commits_suspended_and_revokes_sessions() {
    let driver = ControlledDriver::new();
    let runtime = suspend_capable_runtime(driver.clone()).await;
    let sandbox = sandbox_record("sb-suspend", "suspend", SandboxPhase::Ready);
    runtime.store.put_message(&sandbox).await.unwrap();
    let session = ssh_session_record("suspend-session", sandbox.object_id());
    runtime.store.put_message(&session).await.unwrap();
    register_test_supervisor_session(&runtime, sandbox.object_id());

    let suspended = runtime.suspend_sandbox("default", "suspend").await.unwrap();

    assert_eq!(suspended.phase(), SandboxPhase::Suspended as i32);
    assert_eq!(ready_condition(&suspended).unwrap().reason, "Suspended");
    assert_eq!(driver.suspend_calls(), 1);
    assert_eq!(driver.stop_calls(), 0, "suspend never stops compute");
    assert!(!runtime.supervisor_sessions.has_session(sandbox.object_id()));
    assert!(
        runtime
            .store
            .get_message::<SshSession>(session.object_id())
            .await
            .unwrap()
            .is_none(),
        "suspend revokes ephemeral SSH sessions"
    );

    let again = runtime.suspend_sandbox("default", "suspend").await.unwrap();
    assert_eq!(again.phase(), SandboxPhase::Suspended as i32);
    assert_eq!(driver.suspend_calls(), 1, "stable suspend is idempotent");
}

#[tokio::test]
async fn suspend_requires_driver_capability() {
    let driver = ControlledDriver::new();
    let runtime = test_runtime(driver.clone()).await;
    let sandbox = sandbox_record("sb-unsupported", "unsupported", SandboxPhase::Ready);
    runtime.store.put_message(&sandbox).await.unwrap();

    let error = runtime
        .suspend_sandbox("default", "unsupported")
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert!(error.message().contains("does not support sandbox suspend"));

    let suspended = sandbox_record("sb-unsupported-2", "unsupported-2", SandboxPhase::Suspended);
    runtime.store.put_message(&suspended).await.unwrap();
    let error = runtime
        .resume_sandbox("default", "unsupported-2", false)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert!(error.message().contains("does not support sandbox resume"));

    assert_eq!(driver.suspend_calls(), 0);
    assert_eq!(driver.start_calls(), 0);
    assert_eq!(
        stored(&runtime, sandbox.object_id()).await.phase(),
        SandboxPhase::Ready as i32
    );
}

#[tokio::test]
async fn suspend_rejects_sandboxes_that_are_not_ready() {
    let driver = ControlledDriver::new();
    let runtime = suspend_capable_runtime(driver.clone()).await;
    for (id, phase) in [
        ("sb-provisioning", SandboxPhase::Provisioning),
        ("sb-starting", SandboxPhase::Starting),
        ("sb-stopping", SandboxPhase::Stopping),
        ("sb-stopped", SandboxPhase::Stopped),
        ("sb-error", SandboxPhase::Error),
        ("sb-completed", SandboxPhase::Completed),
    ] {
        runtime
            .store
            .put_message(&sandbox_record(id, id, phase))
            .await
            .unwrap();
        let error = runtime.suspend_sandbox("default", id).await.unwrap_err();
        assert_eq!(error.code(), Code::FailedPrecondition, "{phase:?}");
        assert!(
            error.message().contains("must be Ready to suspend"),
            "{phase:?}"
        );
        assert_eq!(stored(&runtime, id).await.phase(), phase as i32);
    }
    assert_eq!(driver.suspend_calls(), 0);
}

#[tokio::test]
async fn suspend_retries_an_unresolved_suspending_transition() {
    let driver = ControlledDriver::new();
    let runtime = suspend_capable_runtime(driver.clone()).await;
    let sandbox = sandbox_record("sb-suspending", "suspending", SandboxPhase::Suspending);
    runtime.store.put_message(&sandbox).await.unwrap();

    let suspended = runtime
        .suspend_sandbox("default", "suspending")
        .await
        .unwrap();

    assert_eq!(suspended.phase(), SandboxPhase::Suspended as i32);
    assert_eq!(driver.suspend_calls(), 1);
}

#[tokio::test]
async fn failed_suspend_restores_a_still_running_sandbox() {
    let driver = ControlledDriver::new();
    driver.set_suspend_outcome(ControlledLifecycleOutcome::Error("boundary busy"));
    let runtime = suspend_capable_runtime(driver.clone()).await;
    let sandbox = sandbox_record("sb-suspend-fail", "suspend-fail", SandboxPhase::Ready);
    runtime.store.put_message(&sandbox).await.unwrap();
    driver.set_get_outcome(ControlledGetOutcome::Sandbox(Box::new(
        ready_driver_sandbox(sandbox.object_id(), sandbox.object_name()),
    )));

    let error = runtime
        .suspend_sandbox("default", "suspend-fail")
        .await
        .unwrap_err();

    assert!(error.message().starts_with("suspend sandbox failed"));
    assert_eq!(
        stored(&runtime, sandbox.object_id()).await.phase(),
        SandboxPhase::Ready as i32
    );
}

#[tokio::test]
async fn resume_starts_a_new_generation_that_restores_retained_state() {
    let driver = ControlledDriver::new();
    let runtime = suspend_capable_runtime(driver.clone()).await;
    let sandbox = sandbox_record("sb-resume", "resume", SandboxPhase::Suspended);
    let suspended_generation = sandbox_runtime_generation(&sandbox).unwrap();
    runtime.store.put_message(&sandbox).await.unwrap();

    let resumed = runtime
        .resume_sandbox("default", "resume", true)
        .await
        .unwrap();

    assert_eq!(resumed.phase(), SandboxPhase::Starting as i32);
    assert_eq!(ready_condition(&resumed).unwrap().reason, "Resuming");
    assert_eq!(driver.start_resume_requests(), vec![(true, true)]);
    let generation = sandbox_runtime_generation(&resumed).unwrap();
    assert_ne!(generation, suspended_generation);
    assert_eq!(driver.start_generations(), vec![generation.into_string()]);
    assert!(
        !has_resume_intent(&resumed),
        "an accepted resume consumes the retained state"
    );

    // An explicit retry of the accepted start must not restore again.
    runtime.start_sandbox("default", "resume").await.unwrap();
    assert_eq!(
        driver.start_resume_requests(),
        vec![(true, true), (false, false)]
    );
    let error = runtime
        .resume_sandbox("default", "resume", true)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert!(error.message().contains("must be Suspended to resume"));
}

#[tokio::test]
async fn unresolved_resume_retries_with_the_same_request() {
    let driver = ControlledDriver::new();
    driver.set_start_outcome(ControlledLifecycleOutcome::Error("transport reset"));
    driver.set_get_outcome(ControlledGetOutcome::Error("driver unavailable"));
    let runtime = suspend_capable_runtime(driver.clone()).await;
    let sandbox = sandbox_record("sb-resume-retry", "resume-retry", SandboxPhase::Suspended);
    runtime.store.put_message(&sandbox).await.unwrap();

    runtime
        .resume_sandbox("default", "resume-retry", false)
        .await
        .unwrap_err();
    let pending = stored(&runtime, sandbox.object_id()).await;
    assert_eq!(pending.phase(), SandboxPhase::Starting as i32);
    assert!(has_resume_intent(&pending));

    driver.set_start_outcome(ControlledLifecycleOutcome::Ok);
    // Both an explicit resume and a plain start retry the committed resume.
    runtime
        .resume_sandbox("default", "resume-retry", true)
        .await
        .unwrap();
    assert_eq!(
        driver.start_resume_requests(),
        vec![(true, false), (true, false)],
        "a retry repeats the committed fallback choice"
    );
    let generations = driver.start_generations();
    assert_eq!(generations[0], generations[1]);
    assert!(!has_resume_intent(
        &stored(&runtime, sandbox.object_id()).await
    ));
}

#[tokio::test]
async fn failed_resume_of_a_frozen_runtime_restores_suspended() {
    let driver = ControlledDriver::new();
    driver.set_start_outcome(ControlledLifecycleOutcome::Error("restore failed"));
    let runtime = suspend_capable_runtime(driver.clone()).await;
    let sandbox = sandbox_record("sb-resume-fail", "resume-fail", SandboxPhase::Suspended);
    runtime.store.put_message(&sandbox).await.unwrap();
    driver.set_get_outcome(ControlledGetOutcome::Sandbox(Box::new(
        exited_driver_sandbox(&sandbox),
    )));

    runtime
        .resume_sandbox("default", "resume-fail", false)
        .await
        .unwrap_err();

    let restored = stored(&runtime, sandbox.object_id()).await;
    assert_eq!(restored.phase(), SandboxPhase::Suspended as i32);
    assert!(!has_resume_intent(&restored));
}

#[tokio::test]
async fn start_from_suspended_discards_retained_state() {
    let driver = ControlledDriver::new();
    let runtime = suspend_capable_runtime(driver.clone()).await;
    let sandbox = sandbox_record("sb-cold", "cold", SandboxPhase::Suspended);
    runtime.store.put_message(&sandbox).await.unwrap();

    let starting = runtime.start_sandbox("default", "cold").await.unwrap();

    assert_eq!(starting.phase(), SandboxPhase::Starting as i32);
    assert_eq!(driver.start_resume_requests(), vec![(false, false)]);
    assert_ne!(
        sandbox_runtime_generation(&starting).unwrap(),
        sandbox_runtime_generation(&sandbox).unwrap()
    );
}

#[tokio::test]
async fn stop_from_suspended_commits_stopped() {
    let driver = ControlledDriver::new();
    let runtime = suspend_capable_runtime(driver.clone()).await;
    let sandbox = sandbox_record(
        "sb-stop-suspended",
        "stop-suspended",
        SandboxPhase::Suspended,
    );
    runtime.store.put_message(&sandbox).await.unwrap();

    let stopped = runtime
        .stop_sandbox("default", "stop-suspended")
        .await
        .unwrap();

    assert_eq!(stopped.phase(), SandboxPhase::Stopped as i32);
    assert_eq!(driver.stop_calls(), 1);
}

#[tokio::test]
async fn driver_snapshots_and_sessions_cannot_move_suspension() {
    let driver = ControlledDriver::new();
    let runtime = suspend_capable_runtime(driver.clone()).await;
    for (id, phase) in [
        ("sb-snapshot-suspending", SandboxPhase::Suspending),
        ("sb-snapshot-suspended", SandboxPhase::Suspended),
    ] {
        let sandbox = sandbox_record(id, id, phase);
        runtime.store.put_message(&sandbox).await.unwrap();
        register_test_supervisor_session(&runtime, sandbox.object_id());

        for snapshot in [
            exited_driver_sandbox(&sandbox),
            ready_driver_sandbox(sandbox.object_id(), sandbox.object_name()),
        ] {
            runtime.apply_sandbox_update(snapshot).await.unwrap();
            assert_eq!(stored(&runtime, id).await.phase(), phase as i32);
        }
        runtime
            .supervisor_session_connected(id, "stale-instance")
            .await
            .expect_err("a stale supervisor cannot reconnect a suspension");
        assert_eq!(stored(&runtime, id).await.phase(), phase as i32);
    }
}

#[tokio::test]
async fn gateway_restart_retries_suspending_and_leaves_suspended_alone() {
    let driver = ControlledDriver::new();
    let mut runtime =
        test_runtime_with_gateway_managed_lifecycle(driver.clone(), "test-driver").await;
    enable_suspend_resume(&mut runtime);
    let suspended = sandbox_record(
        "sb-restart-suspended",
        "restart-suspended",
        SandboxPhase::Suspended,
    );
    let suspending = sandbox_record(
        "sb-restart-suspending",
        "restart-suspending",
        SandboxPhase::Suspending,
    );
    for sandbox in [&suspended, &suspending] {
        runtime.store.put_message(sandbox).await.unwrap();
    }

    runtime.start_persisted_sandboxes().await.unwrap();

    assert_eq!(driver.suspend_calls(), 1);
    assert_eq!(driver.start_calls(), 0, "suspension is never auto-started");
    for sandbox in [&suspended, &suspending] {
        assert_eq!(
            stored(&runtime, sandbox.object_id()).await.phase(),
            SandboxPhase::Suspended as i32
        );
    }

    runtime.cleanup_on_shutdown().await.unwrap();
    assert_eq!(
        driver.stop_calls(),
        0,
        "shutdown leaves suspended compute alone"
    );
}

#[tokio::test]
async fn gateway_restart_repeats_an_unresolved_resume() {
    let driver = ControlledDriver::new();
    driver.set_start_outcome(ControlledLifecycleOutcome::Error("transport reset"));
    driver.set_get_outcome(ControlledGetOutcome::Error("driver unavailable"));
    let mut runtime =
        test_runtime_with_gateway_managed_lifecycle(driver.clone(), "test-driver").await;
    enable_suspend_resume(&mut runtime);
    let sandbox = sandbox_record(
        "sb-restart-resume",
        "restart-resume",
        SandboxPhase::Suspended,
    );
    runtime.store.put_message(&sandbox).await.unwrap();
    runtime
        .resume_sandbox("default", "restart-resume", true)
        .await
        .unwrap_err();
    assert!(has_resume_intent(
        &stored(&runtime, sandbox.object_id()).await
    ));
    runtime.cleanup_on_shutdown().await.unwrap();
    assert_eq!(
        driver.stop_calls(),
        0,
        "shutdown keeps the state an unresolved resume still needs"
    );

    driver.set_start_outcome(ControlledLifecycleOutcome::Ok);
    runtime.start_persisted_sandboxes().await.unwrap();

    let requests = driver.start_resume_requests();
    assert_eq!(requests[0], (true, true));
    assert_eq!(
        requests[1],
        (true, true),
        "recovery repeats the committed resume"
    );
    assert!(
        requests[2..]
            .iter()
            .all(|request| *request == (false, false)),
        "after the driver accepts the resume, later starts boot fresh: {requests:?}"
    );
    let generations = driver.start_generations();
    assert!(
        generations
            .iter()
            .all(|generation| *generation == generations[0])
    );
    assert!(!has_resume_intent(
        &stored(&runtime, sandbox.object_id()).await
    ));
}

#[tokio::test]
async fn main_process_exit_wins_over_pending_suspend() {
    for outcome in [
        ControlledLifecycleOutcome::Ok,
        ControlledLifecycleOutcome::Error("process already exited"),
    ] {
        for exit_code in [0, 9] {
            let driver = ControlledDriver::new();
            driver.suspend_blocked.store(true, Ordering::SeqCst);
            driver.set_suspend_outcome(outcome.clone());
            let runtime = suspend_capable_runtime(driver.clone()).await;
            let mut sandbox = sandbox_record("sb-exit-race", "exit-race", SandboxPhase::Ready);
            sandbox.status.as_mut().unwrap().main_process_instance_id = "instance-1".into();
            runtime.store.put_message(&sandbox).await.unwrap();
            driver.set_get_outcome(ControlledGetOutcome::Sandbox(Box::new(
                ready_driver_sandbox(sandbox.object_id(), sandbox.object_name()),
            )));
            let pending = {
                let runtime = runtime.clone();
                tokio::spawn(async move { runtime.suspend_sandbox("default", "exit-race").await })
            };
            driver.suspend_started.notified().await;
            assert_eq!(
                stored(&runtime, sandbox.object_id()).await.phase(),
                SandboxPhase::Suspending as i32
            );
            runtime
                .report_main_process_exit(sandbox.object_id(), "instance-1", exit_code)
                .await
                .unwrap();
            runtime
                .finalize_main_process_exit(sandbox.object_id(), "instance-1")
                .await
                .unwrap();
            driver.suspend_release.add_permits(1);
            pending.await.unwrap().unwrap_err();
            let completed = stored(&runtime, sandbox.object_id()).await;
            assert_eq!(
                completed.phase(),
                if exit_code == 0 {
                    SandboxPhase::Completed
                } else {
                    SandboxPhase::Error
                } as i32
            );
            assert_eq!(completed.status.unwrap().exit_code, Some(exit_code));
        }
    }
}

#[tokio::test]
async fn failed_recovered_resume_preserves_retryable_state() {
    for recover_on_startup in [false, true] {
        for confirmed_stopped in [false, true] {
            let driver = ControlledDriver::new();
            driver.set_start_outcome(ControlledLifecycleOutcome::Error("restore failed"));
            driver.set_get_outcome(ControlledGetOutcome::Error("driver unavailable"));
            let mut runtime =
                test_runtime_with_gateway_managed_lifecycle(driver.clone(), "test-driver").await;
            enable_suspend_resume(&mut runtime);
            let sandbox = sandbox_record(
                "sb-recover-resume",
                "recover-resume",
                SandboxPhase::Suspended,
            );
            runtime.store.put_message(&sandbox).await.unwrap();
            runtime
                .resume_sandbox("default", "recover-resume", false)
                .await
                .unwrap_err();
            let pending = stored(&runtime, sandbox.object_id()).await;
            if confirmed_stopped {
                driver.set_get_outcome(ControlledGetOutcome::Sandbox(Box::new(
                    exited_driver_sandbox(&sandbox),
                )));
            }
            if recover_on_startup {
                runtime.start_persisted_sandboxes().await.unwrap();
            } else {
                runtime
                    .resume_sandbox("default", "recover-resume", false)
                    .await
                    .unwrap_err();
            }
            let recovered = stored(&runtime, sandbox.object_id()).await;
            assert_eq!(
                driver.start_calls(),
                2,
                "startup must not retry an unresolved resume twice"
            );
            assert_eq!(
                sandbox_runtime_generation(&recovered),
                sandbox_runtime_generation(&pending)
            );
            assert_eq!(
                recovered.phase(),
                if confirmed_stopped {
                    SandboxPhase::Suspended
                } else {
                    SandboxPhase::Starting
                } as i32
            );
            assert_eq!(has_resume_intent(&recovered), !confirmed_stopped);
            driver.set_start_outcome(ControlledLifecycleOutcome::Ok);
            runtime
                .resume_sandbox("default", "recover-resume", false)
                .await
                .unwrap();
        }
    }
}
