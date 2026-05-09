// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Doctor Docker preflight e2e tests.
//!
//! These tests verify that `openshell doctor check` reports actionable guidance
//! when Docker is not available.
//!
//! The tests do NOT require a running gateway or Docker — they intentionally
//! point `DOCKER_HOST` at a non-existent socket to simulate Docker being
//! unavailable.

use std::process::Stdio;
use std::time::Instant;
use std::{env, fs};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::strip_ansi;

/// Run `openshell <args>` in an isolated environment where Docker is
/// guaranteed to be unreachable.
///
/// Sets `DOCKER_HOST` to a non-existent socket so the preflight check
/// fails immediately regardless of the host's Docker configuration.
async fn run_without_docker(args: &[&str]) -> (String, i32, std::time::Duration) {
    let tmpdir = tempfile::tempdir().expect("create isolated config dir");
    let bin_dir = tmpdir.path().join("bin");
    fs::create_dir(&bin_dir).expect("create fake bin dir");
    let fake_docker = bin_dir.join("docker");
    fs::write(
        &fake_docker,
        "#!/bin/sh\n\
         echo 'Cannot connect to Docker daemon. Check DOCKER_HOST and run docker info.' >&2\n\
         exit 1\n",
    )
    .expect("write fake docker");
    #[cfg(unix)]
    fs::set_permissions(&fake_docker, fs::Permissions::from_mode(0o755))
        .expect("chmod fake docker");

    let old_path = env::var("PATH").unwrap_or_default();
    let path = format!("{}:{old_path}", bin_dir.display());
    let start = Instant::now();

    let mut cmd = openshell_cmd();
    cmd.args(args)
        .env("XDG_CONFIG_HOME", tmpdir.path())
        .env("HOME", tmpdir.path())
        .env("PATH", path)
        .env("DOCKER_HOST", "unix:///tmp/openshell-e2e-nonexistent.sock")
        .env_remove("OPENSHELL_GATEWAY")
        .env_remove("OPENSHELL_GATEWAY_ENDPOINT")
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
        .env_remove("OPENSHELL_GATEWAY_ENDPOINT")
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
