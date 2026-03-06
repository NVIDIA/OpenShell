// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E test: bidirectional file upload/download with a sandbox.
//!
//! Prerequisites:
//! - A running nemoclaw gateway (`nemoclaw gateway start`)
//! - The `nemoclaw` binary (built automatically from the workspace)

use std::fs;
use std::io::Write;
use std::process::Stdio;

use sha2::{Digest, Sha256};

use nemoclaw_e2e::harness::sandbox::SandboxGuard;

/// Create a long-running sandbox, upload and download files, and verify
/// contents.
///
/// Covers:
/// 1. Directory round-trip (nested files)
/// 2. Large file round-trip (~512 KiB) with SHA-256 checksum verification
/// 3. Single-file round-trip
#[tokio::test]
async fn sandbox_file_upload_download_round_trip() {
    // ---------------------------------------------------------------
    // Step 1 — Create a sandbox with `--keep` running `sleep infinity`.
    // ---------------------------------------------------------------
    let mut guard = SandboxGuard::create_keep(&["sleep", "infinity"], "Ready")
        .await
        .expect("sandbox create --keep");

    let tmpdir = tempfile::tempdir().expect("create tmpdir");

    // ---------------------------------------------------------------
    // Step 2 — Upload: push a local directory into the sandbox.
    // ---------------------------------------------------------------
    let upload_dir = tmpdir.path().join("upload");
    fs::create_dir_all(upload_dir.join("subdir")).expect("create upload dirs");
    fs::write(upload_dir.join("greeting.txt"), "hello-from-local").expect("write greeting.txt");
    fs::write(upload_dir.join("subdir/nested.txt"), "nested-content").expect("write nested.txt");

    let upload_str = upload_dir.to_str().expect("upload path is UTF-8");
    guard
        .upload(upload_str, "/sandbox/uploaded")
        .await
        .expect("upload directory");

    // ---------------------------------------------------------------
    // Step 3 — Download: pull the uploaded files back and verify.
    // ---------------------------------------------------------------
    let download_dir = tmpdir.path().join("download");
    fs::create_dir_all(&download_dir).expect("create download dir");

    let download_str = download_dir.to_str().expect("download path is UTF-8");
    guard
        .download("/sandbox/uploaded", download_str)
        .await
        .expect("download directory");

    // Verify top-level file.
    let greeting = fs::read_to_string(download_dir.join("greeting.txt"))
        .expect("read greeting.txt after download");
    assert_eq!(
        greeting, "hello-from-local",
        "greeting.txt content mismatch"
    );

    // Verify nested file.
    let nested = fs::read_to_string(download_dir.join("subdir/nested.txt"))
        .expect("read subdir/nested.txt after download");
    assert_eq!(nested, "nested-content", "subdir/nested.txt content mismatch");

    // ---------------------------------------------------------------
    // Step 4 — Large-file round-trip (~512 KiB) to exercise multi-chunk
    //          SSH transport.
    // ---------------------------------------------------------------
    let large_dir = tmpdir.path().join("large_upload");
    fs::create_dir_all(&large_dir).expect("create large_upload dir");

    let large_file = large_dir.join("large.bin");
    {
        let mut f = fs::File::create(&large_file).expect("create large.bin");
        let mut rng_data = vec![0u8; 512 * 1024]; // 512 KiB
        rand::fill(&mut rng_data[..]);
        f.write_all(&rng_data).expect("write large.bin");
    }

    let expected_hash = {
        let data = fs::read(&large_file).expect("read large.bin for hash");
        let mut hasher = Sha256::new();
        hasher.update(&data);
        hex::encode(hasher.finalize())
    };

    let large_dir_str = large_dir.to_str().expect("large_dir path is UTF-8");
    guard
        .upload(large_dir_str, "/sandbox/large_test")
        .await
        .expect("upload large file");

    let large_down = tmpdir.path().join("large_download");
    fs::create_dir_all(&large_down).expect("create large_download dir");

    let large_down_str = large_down.to_str().expect("large_down path is UTF-8");
    guard
        .download("/sandbox/large_test", large_down_str)
        .await
        .expect("download large file");

    let actual_data = fs::read(large_down.join("large.bin")).expect("read large.bin after download");
    let actual_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&actual_data);
        hex::encode(hasher.finalize())
    };

    assert_eq!(
        expected_hash, actual_hash,
        "large.bin SHA-256 mismatch after round-trip"
    );
    assert_eq!(
        actual_data.len(),
        512 * 1024,
        "large.bin size mismatch: expected {} bytes, got {}",
        512 * 1024,
        actual_data.len()
    );

    // ---------------------------------------------------------------
    // Step 5 — Single-file round-trip.
    // ---------------------------------------------------------------
    let single_file = tmpdir.path().join("single.txt");
    fs::write(&single_file, "single-file-payload").expect("write single.txt");

    let single_str = single_file.to_str().expect("single path is UTF-8");
    guard
        .upload(single_str, "/sandbox")
        .await
        .expect("upload single file");

    let single_down = tmpdir.path().join("single_down");
    fs::create_dir_all(&single_down).expect("create single_down dir");

    let single_down_str = single_down.to_str().expect("single_down path is UTF-8");
    guard
        .download("/sandbox/single.txt", single_down_str)
        .await
        .expect("download single file");

    let single_content = fs::read_to_string(single_down.join("single.txt"))
        .expect("read single.txt after download");
    assert_eq!(
        single_content, "single-file-payload",
        "single.txt content mismatch"
    );

    // ---------------------------------------------------------------
    // Cleanup (guard also cleans up on drop).
    // ---------------------------------------------------------------
    guard.cleanup().await;
}

/// Verify that `sandbox upload` respects `.gitignore` by default.
///
/// Creates a temporary git repository with a `.gitignore` that excludes
/// `*.log` files, uploads the directory (without `--no-git-ignore`), and
/// confirms that tracked files arrive but ignored files do not.
#[tokio::test]
async fn upload_respects_gitignore_by_default() {
    // ---------------------------------------------------------------
    // Step 1 — Create a sandbox with `--keep`.
    // ---------------------------------------------------------------
    let mut guard = SandboxGuard::create_keep(&["sleep", "infinity"], "Ready")
        .await
        .expect("sandbox create --keep");

    // ---------------------------------------------------------------
    // Step 2 — Set up a temp git repo with tracked + ignored files.
    // ---------------------------------------------------------------
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let repo = tmpdir.path().join("repo");
    fs::create_dir_all(&repo).expect("create repo dir");

    // Initialize git repo and add files.
    let git_init = tokio::process::Command::new("git")
        .args(["init"])
        .current_dir(&repo)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .expect("git init");
    assert!(git_init.success(), "git init should succeed");

    // Configure git user for the commit.
    let _ = tokio::process::Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .current_dir(&repo)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
    let _ = tokio::process::Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(&repo)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;

    // Create .gitignore, a tracked file, and an ignored file.
    fs::write(repo.join(".gitignore"), "*.log\nbuild/\n").expect("write .gitignore");
    fs::write(repo.join("tracked.txt"), "i-am-tracked").expect("write tracked.txt");
    fs::write(repo.join("ignored.log"), "i-should-be-filtered").expect("write ignored.log");
    fs::create_dir_all(repo.join("build")).expect("create build dir");
    fs::write(repo.join("build/output.bin"), "build-artifact").expect("write build/output.bin");

    // git add + commit so git ls-files works.
    let _ = tokio::process::Command::new("git")
        .args(["add", "."])
        .current_dir(&repo)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .expect("git add");
    let _ = tokio::process::Command::new("git")
        .args(["commit", "-m", "init"])
        .current_dir(&repo)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .expect("git commit");

    // ---------------------------------------------------------------
    // Step 3 — Upload WITH gitignore filtering (default).
    // ---------------------------------------------------------------
    let repo_str = repo.to_str().expect("repo path is UTF-8");
    guard
        .upload_with_gitignore(repo_str, "/sandbox/filtered", &repo)
        .await
        .expect("upload with gitignore filtering");

    // ---------------------------------------------------------------
    // Step 4 — Verify: tracked file exists, ignored files do not.
    // ---------------------------------------------------------------
    // Download the uploaded directory and verify contents.
    let download_dir = tmpdir.path().join("verify");
    fs::create_dir_all(&download_dir).expect("create verify dir");
    let download_str = download_dir.to_str().expect("verify path is UTF-8");

    guard
        .download("/sandbox/filtered", download_str)
        .await
        .expect("download filtered upload");

    // tracked.txt should be present.
    let tracked = fs::read_to_string(download_dir.join("tracked.txt"))
        .expect("tracked.txt should exist after filtered upload");
    assert_eq!(tracked, "i-am-tracked", "tracked.txt content mismatch");

    // .gitignore itself should be present (it's tracked).
    assert!(
        download_dir.join(".gitignore").exists(),
        ".gitignore should be uploaded (it's a tracked file)"
    );

    // ignored.log should NOT be present.
    assert!(
        !download_dir.join("ignored.log").exists(),
        "ignored.log should be filtered out by .gitignore"
    );

    // build/ directory should NOT be present.
    assert!(
        !download_dir.join("build").exists(),
        "build/ directory should be filtered out by .gitignore"
    );

    // ---------------------------------------------------------------
    // Cleanup.
    // ---------------------------------------------------------------
    guard.cleanup().await;
}
