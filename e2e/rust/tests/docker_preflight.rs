// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Docker preflight e2e tests.
//!
//! These tests verify that the CLI fails fast with actionable guidance when
//! Docker is not available, instead of starting a multi-minute deploy that
//! eventually times out with a cryptic error.
//!
//! The tests do NOT require a running gateway or Docker — they intentionally
//! point `DOCKER_HOST` at a non-existent socket to simulate Docker being
//! unavailable.

use std::process::Stdio;
use std::time::Instant;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::strip_ansi;

/// Run `openshell <args>` in an isolated environment where Docker is
/// guaranteed to be unreachable.
///
/// Sets `DOCKER_HOST` to a non-existent socket so the preflight check
/// fails immediately regardless of the host's Docker configuration.
async fn run_without_docker(args: &[&str]) -> (String, i32, std::time::Duration) {
    let tmpdir = tempfile::tempdir().expect("create isolated config dir");
    let start = Instant::now();

    let mut cmd = openshell_cmd();
    cmd.args(args)
        .env("XDG_CONFIG_HOME", tmpdir.path())
        .env("HOME", tmpdir.path())
        .env("DOCKER_HOST", "unix:///tmp/openshell-e2e-nonexistent.sock")
        .env_remove("OPENSHELL_GATEWAY")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell");
    let elapsed = start.elapsed();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");
    let code = output.status.code().unwrap_or(-1);
    (combined, code, elapsed)
}

// -------------------------------------------------------------------
// gateway start: fails fast when Docker is unavailable
// -------------------------------------------------------------------

/// `openshell gateway start` with no Docker should fail within seconds
/// (not minutes) and produce a non-zero exit code.
#[tokio::test]
async fn gateway_start_fails_fast_without_docker() {
    let (output, code, elapsed) = run_without_docker(&["gateway", "start"]).await;

    assert_ne!(
        code, 0,
        "gateway start should fail when Docker is unavailable, output:\n{output}"
    );

    // The preflight check should cause failure in under 30 seconds.
    // Before the preflight was added, this would time out after several minutes
    // waiting for k3s namespace readiness.
    assert!(
        elapsed.as_secs() < 30,
        "gateway start should fail fast (took {}s), output:\n{output}",
        elapsed.as_secs()
    );
}

/// When Docker is unavailable, the error output should mention Docker
/// so the user knows what to fix.
#[tokio::test]
async fn gateway_start_error_mentions_docker() {
    let (output, code, _) = run_without_docker(&["gateway", "start"]).await;

    assert_ne!(code, 0);
    let clean = strip_ansi(&output);
    let lower = clean.to_lowercase();

    assert!(
        lower.contains("docker"),
        "error output should mention 'Docker' so the user knows what to fix:\n{clean}"
    );
}

/// When Docker is unavailable, the error output should include guidance
/// about DOCKER_HOST since that's the likely fix for non-default runtimes.
#[tokio::test]
async fn gateway_start_error_mentions_docker_host() {
    let (output, code, _) = run_without_docker(&["gateway", "start"]).await;

    assert_ne!(code, 0);
    let clean = strip_ansi(&output);

    assert!(
        clean.contains("DOCKER_HOST"),
        "error output should mention DOCKER_HOST for users with non-default socket paths:\n{clean}"
    );
}

/// When Docker is unavailable, the error output should suggest a
/// verification command like `docker info`.
#[tokio::test]
async fn gateway_start_error_suggests_verification() {
    let (output, code, _) = run_without_docker(&["gateway", "start"]).await;

    assert_ne!(code, 0);
    let clean = strip_ansi(&output);

    assert!(
        clean.contains("docker info"),
        "error output should suggest 'docker info' as a verification step:\n{clean}"
    );
}

// -------------------------------------------------------------------
// gateway start --recreate: same preflight behavior
// -------------------------------------------------------------------

/// `openshell gateway start --recreate` should also fail fast when
/// Docker is unavailable (the recreate flag should not bypass the check).
#[tokio::test]
async fn gateway_start_recreate_fails_fast_without_docker() {
    let (output, code, elapsed) = run_without_docker(&["gateway", "start", "--recreate"]).await;

    assert_ne!(
        code, 0,
        "gateway start --recreate should fail when Docker is unavailable, output:\n{output}"
    );

    assert!(
        elapsed.as_secs() < 30,
        "gateway start --recreate should fail fast (took {}s)",
        elapsed.as_secs()
    );
}

// -------------------------------------------------------------------
// sandbox create with auto-bootstrap: same preflight behavior
// -------------------------------------------------------------------

/// `openshell sandbox create` triggers auto-bootstrap when no gateway
/// exists. With Docker unavailable, it should fail fast with Docker
/// guidance rather than timing out.
#[tokio::test]
async fn sandbox_create_auto_bootstrap_fails_fast_without_docker() {
    let (output, code, elapsed) =
        run_without_docker(&["sandbox", "create", "--from", "openclaw"]).await;

    assert_ne!(
        code, 0,
        "sandbox create should fail when Docker is unavailable, output:\n{output}"
    );

    // Auto-bootstrap path should also hit the preflight check quickly.
    assert!(
        elapsed.as_secs() < 30,
        "sandbox create should fail fast via auto-bootstrap preflight (took {}s), output:\n{output}",
        elapsed.as_secs()
    );

    let clean = strip_ansi(&output);
    let lower = clean.to_lowercase();
    assert!(
        lower.contains("docker"),
        "sandbox create error should mention Docker:\n{clean}"
    );
}

// -------------------------------------------------------------------
// doctor check: validates system prerequisites
// -------------------------------------------------------------------

/// `openshell doctor check` with Docker unavailable should fail fast
/// and report the Docker check as FAILED.
#[tokio::test]
async fn doctor_check_fails_without_docker() {
    let (output, code, elapsed) = run_without_docker(&["doctor", "check"]).await;

    assert_ne!(
        code, 0,
        "doctor check should fail when Docker is unavailable, output:\n{output}"
    );

    assert!(
        elapsed.as_secs() < 10,
        "doctor check should complete quickly (took {}s)",
        elapsed.as_secs()
    );

    let clean = strip_ansi(&output);
    assert!(
        clean.contains("FAILED"),
        "doctor check should report Docker as FAILED:\n{clean}"
    );
}

/// `openshell doctor check` output should include the check label
/// so the user knows what was tested.
#[tokio::test]
async fn doctor_check_output_shows_docker_label() {
    let (output, _, _) = run_without_docker(&["doctor", "check"]).await;
    let clean = strip_ansi(&output);

    assert!(
        clean.contains("Docker"),
        "doctor check output should include 'Docker' label:\n{clean}"
    );
}

/// `openshell doctor check` with Docker unavailable should include
/// actionable guidance in the error output.
#[tokio::test]
async fn doctor_check_error_includes_guidance() {
    let (output, code, _) = run_without_docker(&["doctor", "check"]).await;

    assert_ne!(code, 0);
    let clean = strip_ansi(&output);

    assert!(
        clean.contains("DOCKER_HOST"),
        "doctor check error should mention DOCKER_HOST:\n{clean}"
    );
    assert!(
        clean.contains("docker info"),
        "doctor check error should suggest 'docker info':\n{clean}"
    );
}

/// When Docker IS available, `openshell doctor check` should pass and
/// report the version.
///
/// This test only runs when Docker is actually reachable on the host
/// (i.e., it will pass in CI with Docker but be skipped locally if
/// Docker is not running). We detect this by checking if the default
/// socket exists.
#[tokio::test]
async fn doctor_check_passes_with_docker() {
    if !std::path::Path::new("/var/run/docker.sock").exists() {
        eprintln!("skipping: /var/run/docker.sock not found");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create isolated config dir");
    let mut cmd = openshell_cmd();
    cmd.args(["doctor", "check"])
        .env("XDG_CONFIG_HOME", tmpdir.path())
        .env("HOME", tmpdir.path())
        .env_remove("OPENSHELL_GATEWAY")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");
    let code = output.status.code().unwrap_or(-1);
    let clean = strip_ansi(&combined);

    assert_eq!(
        code, 0,
        "doctor check should pass when Docker is available, output:\n{clean}"
    );
    assert!(
        clean.contains("All checks passed"),
        "doctor check should report success:\n{clean}"
    );
    assert!(
        clean.contains("ok"),
        "doctor check should show 'ok' for Docker:\n{clean}"
    );
}
