// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `openshell doctor check` against a fake `docker` on `PATH`, so the result
//! doesn't depend on the host's Docker.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct Doctor {
    combined: String,
    code: i32,
    elapsed: Duration,
}

/// Run `openshell doctor check` with only `bin` on `PATH`.
fn doctor_check(bin: &Path) -> Doctor {
    let home = tempfile::tempdir().expect("create isolated config dir");
    let start = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_openshell"))
        .args(["doctor", "check"])
        .env("XDG_CONFIG_HOME", home.path())
        .env("HOME", home.path())
        .env("PATH", bin)
        .env("NO_COLOR", "1")
        .env_remove("DOCKER_HOST")
        .env_remove("OPENSHELL_GATEWAY")
        .env_remove("OPENSHELL_GATEWAY_ENDPOINT")
        .stdin(Stdio::null())
        .output()
        .expect("run openshell doctor check");
    Doctor {
        combined: format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        code: output.status.code().unwrap_or(-1),
        elapsed: start.elapsed(),
    }
}

/// Write an executable `docker` script to `bin` that records its arguments
/// in `bin/docker-args` and then runs `body`.
fn fake_docker(bin: &Path, body: &str) {
    let docker = bin.join("docker");
    let args = bin.join("docker-args");
    fs::write(
        &docker,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" > '{}'\n{body}\n",
            args.display()
        ),
    )
    .expect("write fake docker");
    fs::set_permissions(&docker, fs::Permissions::from_mode(0o755)).expect("chmod fake docker");
}

fn docker_args(bin: &Path) -> String {
    fs::read_to_string(bin.join("docker-args")).unwrap_or_default()
}

#[test]
fn doctor_check_passes_when_docker_info_succeeds() {
    let bin = tempfile::tempdir().expect("create fake bin dir");
    fake_docker(bin.path(), "echo 27.3.1");

    let doctor = doctor_check(bin.path());
    assert_eq!(doctor.code, 0, "doctor check failed:\n{}", doctor.combined);
    assert_eq!(
        docker_args(bin.path()).trim(),
        "info --format {{.ServerVersion}}",
        "doctor check ran docker with unexpected arguments"
    );
    for expected in ["Docker", "ok (version 27.3.1)", "All checks passed"] {
        assert!(
            doctor.combined.contains(expected),
            "expected {expected:?} in doctor check output:\n{}",
            doctor.combined
        );
    }
}

#[test]
fn doctor_check_fails_fast_when_docker_info_fails() {
    let bin = tempfile::tempdir().expect("create fake bin dir");
    fake_docker(
        bin.path(),
        "echo 'Cannot connect to the Docker daemon' >&2\nexit 1",
    );

    let doctor = doctor_check(bin.path());
    assert_ne!(
        doctor.code, 0,
        "doctor check passed although docker info failed:\n{}",
        doctor.combined
    );
    assert!(
        doctor.elapsed < Duration::from_secs(10),
        "doctor check took {:?}",
        doctor.elapsed
    );
    for expected in [
        "Docker",
        "FAILED",
        "docker info failed",
        "Cannot connect to the Docker daemon",
    ] {
        assert!(
            doctor.combined.contains(expected),
            "expected {expected:?} in doctor check output:\n{}",
            doctor.combined
        );
    }
    assert!(
        !doctor.combined.contains("All checks passed"),
        "doctor check reported success:\n{}",
        doctor.combined
    );
}

#[test]
fn doctor_check_fails_without_docker_on_path() {
    let bin = tempfile::tempdir().expect("create empty bin dir");

    let doctor = doctor_check(bin.path());
    assert_ne!(
        doctor.code, 0,
        "doctor check passed without docker:\n{}",
        doctor.combined
    );
    assert!(
        doctor.combined.contains("failed to execute docker info"),
        "doctor check did not report that docker could not run:\n{}",
        doctor.combined
    );
}
