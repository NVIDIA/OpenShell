// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use tokio::process::{Child, Command};
use tonic::Code;

use super::launcher_cleanup::{RUN_STATE_DIR_ENV, Run};
use super::tests::{insert_test_record, test_driver_with_extensions};
use super::{
    LifecycleExtensionRegistry, PROCESS_TERMINATION_GRACE, SANDBOX_DELETE_PENDING_FILE,
    SANDBOX_STOPPED_FILE, Sandbox, SandboxRecord, VmDriver, sandbox_runtime_disk_paths,
    sandbox_state_dir, watch_sandboxes_event, write_sandbox_request,
};

fn write_launcher(parent: &Path) -> PathBuf {
    let path = parent.join("launcher");
    fs::write(
        &path,
        r#"#!/bin/sh
set -eu
state=$OPENSHELL_VM_LAUNCH_STATE_DIR
run=$OPENSHELL_VM_LAUNCH_RUN_ID
root=$(dirname "$0")
resource="$root/resource-$run"
busy="$root/busy-$run"

publish_status() {
    printf '%s\n' "$1" > "$state/status.tmp"
    mv "$state/status.tmp" "$state/status"
}

case "$1" in
    --internal-run-vm)
        : > "$resource"
        if [ -f "$root/delay-$run" ] || [ -f "$root/handoff-$run" ]; then
            sleep 60 &
            compute=$!
            stop_compute() {
                trap '' TERM
                kill -TERM "$compute"
                wait "$compute" || :
                publish_status compute-stopped
                : > "$root/compute-stopped-$run"
                while [ ! -f "$root/release-$run" ]; do sleep 0.02; done
                rm "$resource"
                if [ -d "$busy" ]; then rmdir "$busy"; fi
                publish_status complete
                exit 0
            }
            if [ -f "$root/handoff-$run" ]; then
                mkdir "$busy"
                : > "$root/ready-$run"
                while [ ! -f "$state/stop-requested" ]; do sleep 0.02; done
                stop_compute
            fi
            trap stop_compute TERM
            : > "$root/ready-$run"
            wait "$compute"
            exit 3
        fi
        sh -c 'exit 0'
        status=compute-stopped
        ;;
    --internal-cleanup-vm)
        printf '%s\n' "$run" >> "$root/recovery-requests"
        if [ -d "$busy" ]; then
            exit 0
        elif [ -f "$root/release-$run" ]; then
            rm -f "$resource"
            status=complete
        elif [ -f "$root/fail-$run" ]; then
            status=cleanup-failed
        else
            exit 0
        fi
        ;;
    *) exit 2 ;;
esac

publish_status "$status"
"#,
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn managed_driver(root: &Path, launcher: &Path) -> VmDriver {
    let mut driver = test_driver_with_extensions(LifecycleExtensionRegistry::new());
    driver.config.state_dir = root.join("driver-state");
    driver.config.launcher_bin = Some(launcher.to_path_buf());
    driver.config.launcher_managed_cleanup = true;
    driver.launcher_bin = launcher.to_path_buf();
    driver
}

#[tokio::test]
async fn launcher_cleanup_delete_after_failed_provisioning() {
    let temp = tempfile::tempdir().unwrap();
    let launcher = write_launcher(temp.path());
    let driver = managed_driver(temp.path(), &launcher);
    let id = "sandbox-failed-provisioning";
    let state_dir = sandbox_state_dir(&driver.config.state_dir, id).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    driver.registry.lock().await.insert(
        id.to_string(),
        SandboxRecord {
            snapshot: Sandbox {
                id: id.to_string(),
                ..Default::default()
            },
            state_dir: state_dir.clone(),
            process: None,
            provisioning_task: None,
            preparation: None,
            gpu_bdf: None,
            deleting: false,
        },
    );

    driver
        .fail_provisioning(id, &state_dir, "ProvisioningFailed", "image failed", true)
        .await;

    assert!(!state_dir.exists());
    assert!(driver.delete_sandbox(id, "").await.unwrap().deleted);
    assert!(!state_dir.exists());
    assert!(driver.get_sandbox(id, "").await.unwrap().is_none());
}

async fn launch_and_exit_compute(run: &Run, launcher: &Path) -> Child {
    let mut command = Command::new(launcher);
    run.configure(&mut command);
    let mut launcher_process = command.arg("--internal-run-vm").spawn().unwrap();
    assert!(launcher_process.wait().await.unwrap().success());
    launcher_process
}

struct LauncherProcessGroup(Option<Pid>);

impl Drop for LauncherProcessGroup {
    fn drop(&mut self) {
        if let Some(group) = self.0 {
            let _ = killpg(group, Signal::SIGKILL);
        }
    }
}

fn launch_live_compute(run: &Run, launcher: &Path) -> (Child, LauncherProcessGroup) {
    let mut command = Command::new(launcher);
    run.configure(&mut command);
    let launcher_process = command
        .arg("--internal-run-vm")
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let pid = i32::try_from(launcher_process.id().unwrap()).unwrap();
    (
        launcher_process,
        LauncherProcessGroup(Some(Pid::from_raw(pid))),
    )
}

async fn wait_for_fixture_signal(path: &Path) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("launcher never wrote {}", path.display()));
}

#[tokio::test]
async fn launcher_cleanup_stop_leaves_slow_resource_release_running() {
    let temp = tempfile::tempdir().unwrap();
    let launcher = write_launcher(temp.path());
    let driver = managed_driver(temp.path(), &launcher);
    let id = "sandbox-123";
    let state_dir = sandbox_state_dir(&driver.config.state_dir, id).unwrap();
    fs::create_dir_all(&state_dir).unwrap();

    let run = Run::begin(&state_dir, &launcher).await.unwrap();
    let run_id = run.id();
    fs::write(temp.path().join(format!("delay-{run_id}")), b"").unwrap();
    let ready = temp.path().join(format!("ready-{run_id}"));
    let resource = temp.path().join(format!("resource-{run_id}"));

    let (launcher_process, mut cleanup) = launch_live_compute(&run, &launcher);
    insert_test_record(&driver, id, state_dir.clone(), launcher_process).await;
    let process = driver.registry.lock().await[id].process.clone().unwrap();
    wait_for_fixture_signal(&ready).await;

    let started = tokio::time::Instant::now();
    let pending = tokio::time::timeout(
        PROCESS_TERMINATION_GRACE + Duration::from_secs(3),
        driver.stop_sandbox(id, ""),
    )
    .await
    .expect("Stop should return during the cleanup delay")
    .unwrap_err();
    assert!(started.elapsed() >= PROCESS_TERMINATION_GRACE);
    assert!(pending.message().contains("compute stopped"));
    assert!(pending.message().contains("cleanup pending"));
    assert!(resource.exists());
    assert!(process.lock().await.child.try_wait().unwrap().is_none());

    fs::write(temp.path().join(format!("release-{run_id}")), b"").unwrap();
    driver.stop_sandbox(id, "").await.unwrap();
    let exit = process.lock().await.child.try_wait().unwrap().unwrap();
    cleanup.0 = None;
    assert!(
        exit.success(),
        "the launcher should have finished by itself"
    );
    assert!(!resource.exists());
    assert!(Run::load(&state_dir).await.unwrap().is_none());
    assert!(!temp.path().join("recovery-requests").exists());
}

#[tokio::test]
async fn launcher_cleanup_stop_requests_exit_without_a_process_handle() {
    let temp = tempfile::tempdir().unwrap();
    let launcher = write_launcher(temp.path());
    let driver = managed_driver(temp.path(), &launcher);
    let id = "sandbox-123";
    let state_dir = sandbox_state_dir(&driver.config.state_dir, id).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    driver.registry.lock().await.insert(
        id.to_owned(),
        SandboxRecord {
            snapshot: Sandbox {
                id: id.to_owned(),
                name: id.to_owned(),
                ..Default::default()
            },
            state_dir: state_dir.clone(),
            process: None,
            provisioning_task: None,
            preparation: None,
            gpu_bdf: None,
            deleting: false,
        },
    );

    let run = Run::begin(&state_dir, &launcher).await.unwrap();
    let run_id = run.id();
    fs::write(temp.path().join(format!("handoff-{run_id}")), b"").unwrap();
    let (mut launcher_process, mut cleanup) = launch_live_compute(&run, &launcher);
    wait_for_fixture_signal(&temp.path().join(format!("ready-{run_id}"))).await;
    let resource = temp.path().join(format!("resource-{run_id}"));
    assert!(resource.exists());

    let pending = tokio::time::timeout(
        PROCESS_TERMINATION_GRACE + Duration::from_secs(3),
        driver.stop_sandbox(id, ""),
    )
    .await
    .expect("Stop should return while the original owner holds the lock")
    .unwrap_err();
    assert!(pending.message().contains(run_id));
    wait_for_fixture_signal(&temp.path().join(format!("compute-stopped-{run_id}"))).await;
    assert!(launcher_process.try_wait().unwrap().is_none());
    assert!(resource.exists());
    assert_eq!(Run::load(&state_dir).await.unwrap().unwrap().id(), run_id);
    let requests = fs::read_to_string(temp.path().join("recovery-requests")).unwrap();
    assert_eq!(requests.trim_end(), run_id);

    fs::write(temp.path().join(format!("release-{run_id}")), b"").unwrap();
    let status = tokio::time::timeout(Duration::from_secs(5), launcher_process.wait())
        .await
        .expect("the original launcher should finish after the release")
        .unwrap();
    cleanup.0 = None;
    assert!(status.success());
    driver.stop_sandbox(id, "").await.unwrap();
    assert!(!resource.exists());
    assert!(Run::load(&state_dir).await.unwrap().is_none());
}

#[tokio::test]
async fn launcher_cleanup_fences_start_and_allows_delete_retry() {
    let temp = tempfile::tempdir().unwrap();
    let launcher = write_launcher(temp.path());
    let driver = managed_driver(temp.path(), &launcher);
    let id = "sandbox-123";
    let state_dir = sandbox_state_dir(&driver.config.state_dir, id).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    let overlay = sandbox_runtime_disk_paths(&state_dir).overlay_disk;
    fs::write(&overlay, b"retained disk").unwrap();

    let run = Run::begin(&state_dir, &launcher).await.unwrap();
    let run_id = run.id();
    let resource = temp.path().join(format!("resource-{run_id}"));
    let launcher_process = launch_and_exit_compute(&run, &launcher).await;
    insert_test_record(&driver, id, state_dir.clone(), launcher_process).await;
    assert!(
        resource.exists(),
        "compute exit leaves host cleanup pending"
    );

    let pending = driver.stop_sandbox(id, "").await.unwrap_err();
    assert_eq!(pending.code(), Code::Unavailable);
    assert!(pending.message().contains("compute stopped"));
    assert!(pending.message().contains("cleanup pending"));
    assert!(pending.message().contains(run_id));

    let start = driver
        .start_sandbox(id, "", "g0000000000000002", Vec::new())
        .await
        .unwrap_err();
    assert_eq!(start.code(), Code::FailedPrecondition);
    assert!(start.message().contains("retry Stop or Delete"));
    assert_eq!(fs::read(&overlay).unwrap(), b"retained disk");
    assert_eq!(
        Run::load(&state_dir).await.unwrap().unwrap().id(),
        run_id,
        "Start must leave the pending run authoritative"
    );

    fs::write(temp.path().join(format!("fail-{run_id}")), b"").unwrap();
    let failed = driver.delete_sandbox(id, "").await.unwrap_err();
    assert_eq!(failed.code(), Code::FailedPrecondition);
    assert!(failed.message().contains("compute stopped"));
    assert!(failed.message().contains("cleanup failed"));
    assert!(failed.message().contains(run_id));
    assert!(driver.get_sandbox(id, "").await.unwrap().is_some());
    assert!(resource.exists());
    assert!(overlay.exists());

    fs::write(temp.path().join(format!("release-{run_id}")), b"").unwrap();
    assert!(driver.delete_sandbox(id, "").await.unwrap().deleted);
    assert!(!resource.exists());
    assert!(!state_dir.exists());
    let requests = fs::read_to_string(temp.path().join("recovery-requests")).unwrap();
    assert_eq!(requests.lines().collect::<Vec<_>>(), [run_id; 3]);
}

#[tokio::test]
async fn launcher_cleanup_recovery_ignores_an_old_run_completion() {
    let temp = tempfile::tempdir().unwrap();
    let launcher = write_launcher(temp.path());
    let driver = managed_driver(temp.path(), &launcher);
    let sandbox = Sandbox {
        id: "sandbox-123".to_owned(),
        name: "cleanup-recovery".to_owned(),
        ..Default::default()
    };
    let state_dir = sandbox_state_dir(&driver.config.state_dir, &sandbox.id).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    write_sandbox_request(&state_dir, &sandbox).await.unwrap();

    let previous = Run::begin(&state_dir, &launcher).await.unwrap();
    let mut command = Command::new(&launcher);
    previous.configure(&mut command);
    let previous_dir = command
        .as_std()
        .get_envs()
        .find_map(|(key, value)| {
            (key == OsStr::new(RUN_STATE_DIR_ENV))
                .then_some(value)
                .flatten()
                .map(PathBuf::from)
        })
        .unwrap();
    fs::write(previous_dir.join("status"), b"complete\n").unwrap();
    previous.retire().await.unwrap();

    let run = Run::begin(&state_dir, &launcher).await.unwrap();
    let run_id = run.id();
    let resource = temp.path().join(format!("resource-{run_id}"));
    launch_and_exit_compute(&run, &launcher).await;
    fs::create_dir_all(&previous_dir).unwrap();
    fs::write(previous_dir.join("status"), b"complete\n").unwrap();
    drop(driver);

    let restarted = managed_driver(temp.path(), &launcher);
    let mut events = restarted.events.subscribe();
    restarted.restore_persisted_sandboxes().await;
    let recovered = restarted
        .get_sandbox(&sandbox.id, "")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        recovered.status.unwrap().conditions[0].reason,
        "LauncherCleanupIncomplete"
    );
    assert!(resource.exists());
    assert_eq!(Run::load(&state_dir).await.unwrap().unwrap().id(), run_id);

    let request_log = temp.path().join("recovery-requests");
    tokio::time::timeout(Duration::from_secs(5), async {
        while !fs::read_to_string(&request_log).is_ok_and(|contents| !contents.is_empty()) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("background recovery should attempt cleanup for the active run");
    assert!(state_dir.join(SANDBOX_STOPPED_FILE).exists());
    fs::write(temp.path().join(format!("release-{run_id}")), b"").unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let event = events.recv().await.unwrap();
            if let Some(watch_sandboxes_event::Payload::Sandbox(update)) = event.payload
                && let Some(snapshot) = update.sandbox
                && snapshot.id == sandbox.id
                && snapshot
                    .status
                    .is_some_and(|status| status.conditions[0].reason == "ComputeStopped")
            {
                break;
            }
        }
    })
    .await
    .expect("background recovery should stop only after cleanup completes");
    assert!(!resource.exists());
    assert!(Run::load(&state_dir).await.unwrap().is_none());
    let requests = fs::read_to_string(request_log).unwrap();
    assert!(requests.lines().all(|request| request == run_id));
}

#[tokio::test]
async fn launcher_cleanup_recovery_finishes_pending_delete() {
    let temp = tempfile::tempdir().unwrap();
    let launcher = write_launcher(temp.path());
    let driver = managed_driver(temp.path(), &launcher);
    let id = "sandbox-123";
    let sandbox = Sandbox {
        id: id.to_owned(),
        name: id.to_owned(),
        ..Default::default()
    };
    let state_dir = sandbox_state_dir(&driver.config.state_dir, id).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    write_sandbox_request(&state_dir, &sandbox).await.unwrap();

    let run = Run::begin(&state_dir, &launcher).await.unwrap();
    let run_id = run.id();
    let resource = temp.path().join(format!("resource-{run_id}"));
    let launcher_process = launch_and_exit_compute(&run, &launcher).await;
    insert_test_record(&driver, id, state_dir.clone(), launcher_process).await;

    let pending = driver.delete_sandbox(id, "").await.unwrap_err();
    assert!(pending.message().contains("cleanup pending"));
    assert!(state_dir.join(SANDBOX_DELETE_PENDING_FILE).exists());
    assert!(resource.exists());
    drop(driver);

    fs::write(temp.path().join(format!("release-{run_id}")), b"").unwrap();
    let restarted = managed_driver(temp.path(), &launcher);
    let mut events = restarted.events.subscribe();
    restarted.restore_persisted_sandboxes().await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let event = events.recv().await.unwrap();
            if matches!(event.payload, Some(watch_sandboxes_event::Payload::Deleted(deleted))
                if deleted.sandbox_id == id)
            {
                break;
            }
        }
    })
    .await
    .expect("restore should publish Delete only after cleanup");

    assert!(restarted.get_sandbox(id, "").await.unwrap().is_none());
    assert!(!state_dir.exists());
    assert!(!resource.exists());
}
