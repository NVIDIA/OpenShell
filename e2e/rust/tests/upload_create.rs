// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E test: `sandbox create --upload` pre-loads files before running a command.
//!
//! Validates that the `--upload <local>:<dest>` flag on `sandbox create`
//! transfers files into the sandbox before the user command executes,
//! so the command can read the uploaded content.
//!
//! Prerequisites:
//! - A running openshell gateway (`mise run gateway:docker`)
//! - The `openshell` binary (built automatically from the workspace)

use std::fs;

use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;

/// Create a sandbox with `--upload dir:/sandbox/data` and verify directory
/// uploads preserve the source basename at `/sandbox/data/<dirname>/...`.
#[tokio::test]
async fn create_with_upload_directory_preserves_source_basename() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");

    // Create a directory with files to upload.
    let upload_dir = tmpdir.path().join("project");
    fs::create_dir_all(upload_dir.join("src")).expect("create project/src");
    fs::write(upload_dir.join("marker.txt"), "upload-create-marker").expect("write marker.txt");
    fs::write(upload_dir.join("src/main.py"), "print('hello')").expect("write main.py");

    let upload_str = upload_dir.to_str().expect("upload path is UTF-8");
    let remote_marker = "/sandbox/data/project/marker.txt";

    // The command reads the marker file — if upload worked, its content
    // appears in the output.
    let mut guard = SandboxGuard::create_with_upload(
        upload_str,
        "/sandbox/data",
        &["cat", remote_marker],
    )
    .await
    .expect("sandbox create --upload");

    let clean = strip_ansi(&guard.create_output);
    assert!(
        clean.contains("upload-create-marker"),
        "expected uploaded marker content in sandbox output:\n{clean}"
    );

    guard.cleanup().await;
}

/// Two `--upload` specs in a single `sandbox create` call should both land in
/// the sandbox before the command runs.
#[tokio::test]
async fn create_with_multiple_uploads() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");

    let dir_a = tmpdir.path().join("alpha");
    let dir_b = tmpdir.path().join("beta");
    fs::create_dir_all(&dir_a).expect("create alpha");
    fs::create_dir_all(&dir_b).expect("create beta");
    fs::write(dir_a.join("a.txt"), "content-alpha").expect("write a.txt");
    fs::write(dir_b.join("b.txt"), "content-beta").expect("write b.txt");

    let spec_a = dir_a.to_str().expect("alpha path is UTF-8");
    let spec_b = dir_b.to_str().expect("beta path is UTF-8");

    let mut guard = SandboxGuard::create_with_uploads(
        &[(spec_a, "/sandbox/alpha"), (spec_b, "/sandbox/beta")],
        &["sh", "-c", "cat /sandbox/alpha/alpha/a.txt /sandbox/beta/beta/b.txt"],
    )
    .await
    .expect("sandbox create with multiple --upload flags");

    let clean = strip_ansi(&guard.create_output);
    assert!(
        clean.contains("content-alpha"),
        "expected alpha content in output:\n{clean}"
    );
    assert!(
        clean.contains("content-beta"),
        "expected beta content in output:\n{clean}"
    );

    guard.cleanup().await;
}

/// `--upload` with a single file (not a directory) should work.
#[tokio::test]
async fn create_with_upload_single_file() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let file_path = tmpdir.path().join("config.txt");
    fs::write(&file_path, "single-file-upload-test").expect("write config.txt");

    let file_str = file_path.to_str().expect("file path is UTF-8");

    let mut guard = SandboxGuard::create_with_upload(
        file_str,
        "/sandbox",
        &["cat", "/sandbox/config.txt"],
    )
    .await
    .expect("sandbox create --upload single file");

    let clean = strip_ansi(&guard.create_output);
    assert!(
        clean.contains("single-file-upload-test"),
        "expected single-file content in sandbox output:\n{clean}"
    );

    guard.cleanup().await;
}
