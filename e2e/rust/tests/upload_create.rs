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
//! - A running nemoclaw gateway (`nemoclaw gateway start`)
//! - The `nemoclaw` binary (built automatically from the workspace)

use std::fs;

use nemoclaw_e2e::harness::output::strip_ansi;
use nemoclaw_e2e::harness::sandbox::SandboxGuard;

/// Create a sandbox with `--upload dir:/sandbox/data` and run a command that
/// reads the uploaded files, verifying the content appears in stdout.
#[tokio::test]
async fn create_with_upload_provides_files_to_command() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");

    // Create a directory with files to upload.
    let upload_dir = tmpdir.path().join("project");
    fs::create_dir_all(upload_dir.join("src")).expect("create project/src");
    fs::write(upload_dir.join("marker.txt"), "upload-create-marker").expect("write marker.txt");
    fs::write(upload_dir.join("src/main.py"), "print('hello')").expect("write main.py");

    let upload_str = upload_dir.to_str().expect("upload path is UTF-8");

    // The command reads the marker file — if upload worked, its content
    // appears in the output.
    let mut guard = SandboxGuard::create_with_upload(
        upload_str,
        "/sandbox/data",
        &["cat", "/sandbox/data/marker.txt"],
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
