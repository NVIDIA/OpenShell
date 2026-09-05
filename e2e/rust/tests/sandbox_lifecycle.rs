// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::binary::{openshell_cmd, openshell_tty_cmd};
use openshell_e2e::harness::cli::{run_cli, wait_for_sandbox_phase};
use openshell_e2e::harness::output::{extract_field, strip_ansi};
use openshell_e2e::harness::sandbox::SandboxGuard;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::{Instant, sleep};

const SANDBOX_PRESENCE_TIMEOUT: Duration = Duration::from_secs(30);
const SANDBOX_LIST_POLL_INTERVAL: Duration = Duration::from_millis(500);

fn normalize_output(output: &str) -> String {
    let stripped = strip_ansi(output).replace('\r', "");
    let mut cleaned = String::with_capacity(stripped.len());

    for ch in stripped.chars() {
        match ch {
            '\u{8}' => {
                cleaned.pop();
            }
            '\u{4}' => {}
            _ => cleaned.push(ch),
        }
    }

    cleaned
}

fn extract_sandbox_name(output: &str) -> Option<String> {
    if let Some((_, rest)) = output.split_once("Created sandbox:") {
        return rest.split_whitespace().next().map(ToOwned::to_owned);
    }

    extract_field(output, "Created sandbox").or_else(|| extract_field(output, "Name"))
}

async fn sandbox_list_names(deadline: Instant) -> Option<Vec<String>> {
    if Instant::now() >= deadline {
        return None;
    }

    let mut cmd = openshell_cmd();
    cmd.args(["sandbox", "list", "--names"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = match tokio::time::timeout_at(deadline, cmd.output()).await {
        Ok(output) => output.expect("spawn openshell sandbox list"),
        Err(_) => return None,
    };
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = normalize_output(&format!("{stdout}{stderr}"));
    assert!(
        output.status.success(),
        "sandbox list should succeed (exit {:?}):\n{combined}",
        output.status.code()
    );

    Some(
        combined
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
    )
}

async fn assert_sandbox_presence_eventually(
    sandbox_name: &str,
    should_exist: bool,
) -> Result<(), Vec<String>> {
    let deadline = Instant::now() + SANDBOX_PRESENCE_TIMEOUT;
    let mut last_sandbox_names = Vec::new();

    loop {
        let Some(sandbox_names) = sandbox_list_names(deadline).await else {
            return Err(last_sandbox_names);
        };
        let exists = sandbox_names.iter().any(|name| name == sandbox_name);
        if exists == should_exist {
            return Ok(());
        }

        let now = Instant::now();
        if now >= deadline {
            return Err(sandbox_names);
        }

        last_sandbox_names = sandbox_names;
        sleep(SANDBOX_LIST_POLL_INTERVAL.min(deadline - now)).await;
    }
}

async fn delete_sandbox(name: &str) {
    let mut cmd = openshell_cmd();
    cmd.args(["sandbox", "delete", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _ = cmd.status().await;
}

async fn run_sandbox_lifecycle_command(operation: &str, name: &str) -> String {
    let mut cmd = openshell_cmd();
    cmd.args(["sandbox", operation, name])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd
        .output()
        .await
        .unwrap_or_else(|error| panic!("spawn openshell sandbox {operation}: {error}"));
    let combined = normalize_output(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ));
    assert!(
        output.status.success(),
        "sandbox {operation} should succeed (exit {:?}):\n{combined}",
        output.status.code(),
    );
    combined
}

async fn sandbox_details(name: &str) -> String {
    let (details, exit_code) = run_cli(&["sandbox", "get", name]).await;
    let details = normalize_output(&details);
    assert_eq!(
        exit_code, 0,
        "sandbox get should succeed for {name}:\n{details}"
    );
    details
}

async fn reconnect_with_input_ownership(
    sandbox_name: &str,
) -> (tokio::process::Child, Vec<String>) {
    let reconnect_deadline = Instant::now() + Duration::from_secs(30);
    let mut attempt = 0;

    loop {
        attempt += 1;
        let token = format!("reconnect-{attempt}");
        let mut reconnect_cmd = openshell_cmd();
        reconnect_cmd
            .args(["sandbox", "connect", sandbox_name])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut candidate = reconnect_cmd.spawn().expect("spawn reconnect attachment");
        let mut candidate_stdin = candidate.stdin.take().expect("reconnect stdin");
        candidate_stdin
            .write_all(format!("{token}\n").as_bytes())
            .await
            .expect("write reconnect ownership probe");
        candidate_stdin
            .flush()
            .await
            .expect("flush reconnect ownership probe");

        let reconnect_stdout = candidate.stdout.take().expect("reconnect stdout");
        let mut reconnect_lines = BufReader::new(reconnect_stdout).lines();
        let mut candidate_replay = Vec::new();
        let remaining = reconnect_deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "reconnect did not acquire input ownership"
        );
        let attempt_timeout = Duration::from_secs(2).min(remaining);
        let acquired = tokio::time::timeout(attempt_timeout, async {
            loop {
                let Some(line) = reconnect_lines
                    .next_line()
                    .await
                    .expect("read reconnect output")
                else {
                    return false;
                };
                if line.contains("main_pid=") {
                    candidate_replay.push(line.clone());
                }
                if line.contains(&format!("input={token}")) {
                    return true;
                }
            }
        })
        .await
        .unwrap_or(false);

        if acquired {
            return (candidate, candidate_replay);
        }

        let _ = candidate.kill().await;
        let _ = candidate.wait().await;
        assert!(
            Instant::now() < reconnect_deadline,
            "reconnect did not acquire input ownership"
        );
        sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn sandbox_stop_start_preserves_workspace() {
    const SENTINEL: &str = "openshell-stop-start-sentinel";
    const SENTINEL_PATH: &str = "/sandbox/.openshell-stop-start-e2e";
    const RUN_COUNT_PATH: &str = "/sandbox/.openshell-main-run-count";
    let write_sentinel = format!("printf '%s\\n' '{SENTINEL}' > '{SENTINEL_PATH}'");
    let main = format!(
        "count=0; test ! -f '{RUN_COUNT_PATH}' || count=$(cat '{RUN_COUNT_PATH}'); \
         count=$((count + 1)); printf '%s\\n' \"$count\" > '{RUN_COUNT_PATH}'; \
         echo lifecycle-ready-$count; exec sleep infinity"
    );

    let mut sandbox = SandboxGuard::create_keep(&["sh", "-c", &main], "lifecycle-ready")
        .await
        .expect("sandbox create should start a durable main process");
    sandbox
        .exec(&["sh", "-lc", &write_sentinel])
        .await
        .expect("sandbox exec should write the workspace sentinel");

    let stop_output = run_sandbox_lifecycle_command("stop", &sandbox.name).await;
    assert!(
        stop_output.contains("Stopped sandbox"),
        "expected stop confirmation in:\n{stop_output}",
    );

    let mut exec_cmd = openshell_cmd();
    exec_cmd
        .args([
            "sandbox",
            "exec",
            "--name",
            &sandbox.name,
            "--no-tty",
            "--",
            "cat",
            SENTINEL_PATH,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let stopped_exec = exec_cmd
        .output()
        .await
        .expect("spawn openshell sandbox exec while stopped");
    assert!(
        !stopped_exec.status.success(),
        "sandbox exec should fail while stopped"
    );

    let start_output = run_sandbox_lifecycle_command("start", &sandbox.name).await;
    assert!(
        start_output.contains("Started sandbox"),
        "expected start confirmation in:\n{start_output}",
    );

    let sentinel = sandbox
        .exec(&["cat", SENTINEL_PATH])
        .await
        .expect("sandbox exec should succeed after start");
    assert!(
        sentinel.lines().any(|line| line.trim() == SENTINEL),
        "workspace sentinel should survive stop and start:\n{sentinel}",
    );
    let run_count = sandbox
        .exec(&["cat", RUN_COUNT_PATH])
        .await
        .expect("sandbox exec should read the canonical main run count");
    assert_eq!(
        run_count.trim(),
        "2",
        "start should launch a fresh canonical main instance:\n{run_count}",
    );

    sandbox.cleanup().await;
}

#[tokio::test]
async fn sandbox_can_be_deleted_while_stopped() {
    let mut sandbox = SandboxGuard::create_keep(
        &["sh", "-c", "echo stop-ready; exec sleep infinity"],
        "stop-ready",
    )
    .await
    .expect("sandbox create should start a durable main process");

    let stop_output = run_sandbox_lifecycle_command("stop", &sandbox.name).await;
    assert!(
        stop_output.contains("Stopped sandbox"),
        "expected stop confirmation in:\n{stop_output}",
    );

    let delete_output = run_sandbox_lifecycle_command("delete", &sandbox.name).await;
    assert!(
        delete_output.contains("Deleted sandbox"),
        "expected delete confirmation in:\n{delete_output}",
    );

    if let Err(last_sandbox_list) = assert_sandbox_presence_eventually(&sandbox.name, false).await {
        sandbox.cleanup().await;
        panic!(
            "stopped sandbox {} should be deleted without starting after \
             {SANDBOX_PRESENCE_TIMEOUT:?}; last observed sandbox list: {last_sandbox_list:?}",
            sandbox.name,
        );
    }

    // Mark the guard cleaned up. Its idempotent delete is harmless now that
    // the lifecycle operation above has removed the sandbox.
    sandbox.cleanup().await;
}

#[tokio::test]
async fn canonical_main_exit_zero_completes_persistent_sandbox() {
    let mut cmd = openshell_tty_cmd(&["sandbox", "create", "--", "echo", "OK"]);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell sandbox create");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = normalize_output(&format!("{stdout}{stderr}"));

    assert!(output.status.success(), "create failed:\n{combined}");
    assert!(
        combined.contains("OK"),
        "main output was not streamed:\n{combined}"
    );
    let sandbox_name =
        extract_sandbox_name(&combined).expect("sandbox name should be present in output");

    if let Err(last_sandbox_list) = assert_sandbox_presence_eventually(&sandbox_name, true).await {
        delete_sandbox(&sandbox_name).await;
        panic!(
            "sandbox {sandbox_name} should still exist by default after {SANDBOX_PRESENCE_TIMEOUT:?}; \
             last observed sandbox list: {last_sandbox_list:?}"
        );
    }

    let mut get_cmd = openshell_cmd();
    get_cmd
        .args(["sandbox", "get", &sandbox_name])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let get_output = get_cmd.output().await.expect("spawn openshell sandbox get");
    let details = normalize_output(&format!(
        "{}{}",
        String::from_utf8_lossy(&get_output.stdout),
        String::from_utf8_lossy(&get_output.stderr),
    ));
    assert!(
        get_output.status.success(),
        "sandbox get failed:\n{details}"
    );
    assert!(
        details.contains("Phase: Completed"),
        "expected terminal sandbox phase:\n{details}"
    );

    delete_sandbox(&sandbox_name).await;
}

#[tokio::test]
async fn canonical_main_nonzero_exit_preserves_status() {
    let mut cmd = openshell_tty_cmd(&[
        "sandbox",
        "create",
        "--",
        "sh",
        "-c",
        "echo failed-main; exit 7",
    ]);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell sandbox create");
    let combined = normalize_output(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ));
    assert_eq!(
        output.status.code(),
        Some(7),
        "unexpected result:\n{combined}"
    );
    assert!(
        combined.contains("failed-main"),
        "main output was not streamed:\n{combined}"
    );
    let sandbox_name =
        extract_sandbox_name(&combined).expect("sandbox name should be present in output");

    let mut get_cmd = openshell_cmd();
    get_cmd
        .args(["sandbox", "get", &sandbox_name])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let get_output = get_cmd.output().await.expect("spawn openshell sandbox get");
    let details = normalize_output(&format!(
        "{}{}",
        String::from_utf8_lossy(&get_output.stdout),
        String::from_utf8_lossy(&get_output.stderr),
    ));
    assert!(
        details.contains("Phase: Error"),
        "unexpected phase:\n{details}"
    );
    assert!(
        details.contains("Exit Code: 7"),
        "missing exit code:\n{details}"
    );
    delete_sandbox(&sandbox_name).await;
}

#[tokio::test]
async fn detached_canonical_main_exit_zero_reaches_completed() {
    const RELEASE_PATH: &str = "/sandbox/.openshell-detached-success-release";
    let script = format!("while [ ! -e '{RELEASE_PATH}' ]; do sleep 0.05; done; exit 0");
    let mut sandbox = SandboxGuard::create_detached_main(&["sh", "-c", &script])
        .await
        .expect("create detached successful canonical main");
    sandbox
        .exec(&["touch", RELEASE_PATH])
        .await
        .expect("release detached successful canonical main");

    wait_for_sandbox_phase(&sandbox.name, "Completed", SANDBOX_PRESENCE_TIMEOUT)
        .await
        .unwrap_or_else(|err| panic!("detached successful main did not complete:\n{err}"));
    let details = sandbox_details(&sandbox.name).await;
    assert!(
        details.contains("Phase: Completed"),
        "detached successful main should retain Completed status:\n{details}"
    );

    sandbox.cleanup().await;
}

#[tokio::test]
async fn detached_canonical_main_nonzero_exit_reaches_error() {
    const RELEASE_PATH: &str = "/sandbox/.openshell-detached-failure-release";
    let script = format!("while [ ! -e '{RELEASE_PATH}' ]; do sleep 0.05; done; exit 11");
    let mut sandbox = SandboxGuard::create_detached_main(&["sh", "-c", &script])
        .await
        .expect("create detached failing canonical main");
    sandbox
        .exec(&["touch", RELEASE_PATH])
        .await
        .expect("release detached failing canonical main");

    wait_for_sandbox_phase(&sandbox.name, "Error", SANDBOX_PRESENCE_TIMEOUT)
        .await
        .unwrap_or_else(|err| panic!("detached failing main did not reach Error:\n{err}"));
    let details = sandbox_details(&sandbox.name).await;
    assert!(
        details.contains("Phase: Error") && details.contains("Exit Code: 11"),
        "detached failing main should retain its terminal result:\n{details}"
    );

    sandbox.cleanup().await;
}

#[tokio::test]
async fn canonical_tty_main_uses_sandbox_environment() {
    let script = r#"printf 'canonical_env home=%s user=%s term=%s\n' "$HOME" "$USER" "$TERM"; while true; do sleep 1; done"#;
    let mut sandbox =
        SandboxGuard::create_keep_with_args(&["--tty"], &["sh", "-lc", script], "canonical_env")
            .await
            .expect("create canonical TTY process");

    let output = normalize_output(&sandbox.create_output);
    let environment = output
        .lines()
        .find(|line| line.contains("canonical_env"))
        .expect("canonical environment output");
    let field = |name: &str| {
        environment
            .split_whitespace()
            .find_map(|value| value.strip_prefix(&format!("{name}=")))
            .unwrap_or_default()
    };

    assert!(
        !field("home").is_empty() && field("home") != "/root",
        "canonical process must not inherit the supervisor HOME: {environment}"
    );
    assert!(
        !field("user").is_empty(),
        "canonical process USER must identify the sandbox user: {environment}"
    );
    assert!(
        !field("term").is_empty() && field("term") != "dumb",
        "canonical TTY process must receive a usable TERM: {environment}"
    );

    sandbox.cleanup().await;
}

#[tokio::test]
async fn canonical_main_disconnect_reconnect_replays_history_for_same_process() {
    const FIRST_MARKER: &str = "sequence=0001";
    let script = r#"trap 'kill "$writer" 2>/dev/null || true' EXIT; (n=1; while true; do printf 'main_pid=%s sequence=%04d\n' "$$" "$n"; n=$((n + 1)); sleep 0.2; done) & writer=$!; while IFS= read -r line; do printf 'main_pid=%s input=%s\n' "$$" "$line"; done"#;
    let mut sandbox = SandboxGuard::create_detached_main(&["sh", "-lc", script])
        .await
        .expect("create retained canonical main process");

    let mut owner_cmd = openshell_cmd();
    owner_cmd
        .args(["sandbox", "connect", &sandbox.name])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut owner = owner_cmd.spawn().expect("spawn input-owning attachment");
    let owner_stdout = owner.stdout.take().expect("owner stdout");
    let mut owner_lines = BufReader::new(owner_stdout).lines();
    let owner_line = tokio::time::timeout(Duration::from_secs(30), owner_lines.next_line())
        .await
        .expect("owner output timeout")
        .expect("read owner output")
        .expect("owner output should remain open");
    assert!(
        owner_line.contains("main_pid="),
        "unexpected owner output: {owner_line}"
    );

    let mut observer_cmd = openshell_cmd();
    observer_cmd
        .args(["sandbox", "connect", &sandbox.name])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut observer = observer_cmd.spawn().expect("spawn competing attachment");
    let observer_stderr = observer.stderr.take().expect("observer stderr");
    let mut observer_errors = BufReader::new(observer_stderr).lines();
    let warning = tokio::time::timeout(Duration::from_secs(30), observer_errors.next_line())
        .await
        .expect("observer warning timeout")
        .expect("read observer warning")
        .expect("observer warning should remain open");
    assert!(
        warning.contains("already has an input owner") && warning.contains("read-only"),
        "competing attachment should become read-only: {warning}"
    );
    let observer_stdout = observer.stdout.take().expect("observer stdout");
    let mut observer_lines = BufReader::new(observer_stdout).lines();
    let observer_output_line =
        tokio::time::timeout(Duration::from_secs(30), observer_lines.next_line())
            .await
            .expect("observer output timeout")
            .expect("read observer output")
            .expect("observer output should remain open");
    assert!(
        observer_output_line.contains("main_pid="),
        "read-only attachment should observe output: {observer_output_line}"
    );

    owner.kill().await.expect("disconnect input owner");
    owner.wait().await.expect("wait for input owner disconnect");
    observer.kill().await.expect("disconnect observer");
    observer.wait().await.expect("wait for observer disconnect");

    let (mut reconnect, replay) = reconnect_with_input_ownership(&sandbox.name).await;

    let first_pid = owner_line
        .split_whitespace()
        .find_map(|field| field.strip_prefix("main_pid="))
        .expect("owner output pid");
    assert!(
        replay.iter().any(|line| line.contains(FIRST_MARKER)),
        "reconnect should replay the beginning of retained history: {replay:?}"
    );
    assert!(
        replay
            .iter()
            .all(|line| line.contains(&format!("main_pid={first_pid}"))),
        "reconnect should target the same canonical process: {replay:?}"
    );
    assert!(
        replay.iter().any(|line| !line.contains(FIRST_MARKER)),
        "reconnect should observe output beyond the first record: {replay:?}"
    );

    reconnect
        .kill()
        .await
        .expect("disconnect reconnect attachment");
    reconnect
        .wait()
        .await
        .expect("wait for reconnect disconnect");
    sandbox.cleanup().await;
}

#[tokio::test]
async fn sandbox_create_with_no_keep_cleans_up_after_tty_command() {
    let mut cmd = openshell_tty_cmd(&["sandbox", "create", "--no-keep", "--", "echo", "OK"]);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell sandbox create");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = normalize_output(&format!("{stdout}{stderr}"));

    assert!(output.status.success(), "create failed:\n{combined}");
    assert!(
        combined.contains("OK"),
        "main output was not streamed:\n{combined}"
    );
    let sandbox_name =
        extract_sandbox_name(&combined).expect("sandbox name should be present in output");

    if let Err(last_sandbox_list) = assert_sandbox_presence_eventually(&sandbox_name, false).await {
        delete_sandbox(&sandbox_name).await;
        panic!(
            "sandbox {sandbox_name} should have been deleted automatically after \
             {SANDBOX_PRESENCE_TIMEOUT:?}; last observed sandbox list: {last_sandbox_list:?}"
        );
    }
}

#[tokio::test]
async fn sandbox_create_with_no_keep_preserves_failure_then_cleans_up() {
    let mut cmd = openshell_tty_cmd(&[
        "sandbox",
        "create",
        "--no-keep",
        "--",
        "sh",
        "-c",
        "echo ephemeral-failure; exit 17",
    ]);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell sandbox create");
    let combined = normalize_output(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ));

    assert_eq!(
        output.status.code(),
        Some(17),
        "ephemeral main should preserve its failure code:\n{combined}"
    );
    assert!(
        combined.contains("ephemeral-failure"),
        "ephemeral main output was not streamed:\n{combined}"
    );
    let sandbox_name =
        extract_sandbox_name(&combined).expect("sandbox name should be present in output");

    if let Err(last_sandbox_list) = assert_sandbox_presence_eventually(&sandbox_name, false).await {
        delete_sandbox(&sandbox_name).await;
        panic!(
            "failed ephemeral sandbox {sandbox_name} should have been deleted automatically after \
             {SANDBOX_PRESENCE_TIMEOUT:?}; last observed sandbox list: {last_sandbox_list:?}"
        );
    }
}
