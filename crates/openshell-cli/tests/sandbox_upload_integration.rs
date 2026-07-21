// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::{Command, Output};

fn run_upload(
    local_path: &Path,
    config_dir: &Path,
    path: Option<&OsStr>,
    git_marker: Option<&Path>,
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_openshell"));
    command
        .args([
            "--gateway",
            "test-gateway",
            "--gateway-endpoint",
            "http://127.0.0.1:0",
            "sandbox",
            "upload",
            "test-sandbox",
        ])
        .arg(local_path)
        .arg("/sandbox/uploaded")
        .env("XDG_CONFIG_HOME", config_dir)
        .env("NO_COLOR", "1");

    if let Some(path) = path {
        command.env("PATH", path);
    }
    if let Some(marker) = git_marker {
        command.env("OPENSHELL_TEST_GIT_MARKER", marker);
    }

    command.output().expect("run openshell sandbox upload")
}

#[test]
fn sandbox_upload_command_accepts_dangling_symlink_preflight() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let link = tmpdir.path().join("dangling-link");
    symlink("missing-target", &link).expect("create dangling symlink");

    let output = run_upload(&link, tmpdir.path(), None, None);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "the test gateway is unreachable");
    assert!(
        stderr.contains("Uploading "),
        "dangling symlink should pass local preflight before the gateway error: {stderr}"
    );
    assert!(
        !stderr.contains("local path does not exist"),
        "dangling symlink was rejected as missing: {stderr}"
    );
}

#[test]
fn sandbox_upload_command_skips_git_filtering_for_symlink_source() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let repo = tmpdir.path().join("repo");
    fs::create_dir(&repo).expect("create repo");
    let git_status = Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repo)
        .status()
        .expect("run git init");
    assert!(git_status.success(), "git init failed");

    let target = repo.join("real-dir");
    fs::create_dir(&target).expect("create symlink target");
    fs::write(target.join("file.txt"), "hello").expect("write target file");
    let link = repo.join("link-dir");
    symlink("real-dir", &link).expect("create symlink");

    let fake_bin = tmpdir.path().join("bin");
    fs::create_dir(&fake_bin).expect("create fake bin directory");
    let fake_git = fake_bin.join("git");
    fs::write(
        &fake_git,
        "#!/bin/sh\n: > \"$OPENSHELL_TEST_GIT_MARKER\"\nexit 1\n",
    )
    .expect("write fake git");
    let mut permissions = fs::metadata(&fake_git)
        .expect("stat fake git")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_git, permissions).expect("make fake git executable");

    let marker = tmpdir.path().join("git-invoked");
    let mut path_entries = vec![fake_bin];
    if let Some(current_path) = std::env::var_os("PATH") {
        path_entries.extend(std::env::split_paths(&current_path));
    }
    let path = std::env::join_paths(path_entries).expect("build test PATH");

    let output = run_upload(&link, tmpdir.path(), Some(&path), Some(&marker));
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "the test gateway is unreachable");
    assert!(
        stderr.contains("Uploading "),
        "symlink should reach the upload transport: {stderr}"
    );
    assert!(
        !marker.exists(),
        "standalone sandbox upload invoked Git-aware filtering for a symlink source"
    );
}
