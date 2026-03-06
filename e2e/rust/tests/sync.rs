// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E test: bidirectional file sync with a sandbox.
//!
//! Replaces `e2e/bash/test_sandbox_sync.sh`.
//!
//! Prerequisites:
//! - A running nemoclaw cluster (`nemoclaw cluster admin deploy`)
//! - The `nemoclaw` binary (built automatically from the workspace)

use std::fs;
use std::io::Write;

use sha2::{Digest, Sha256};

use nemoclaw_e2e::harness::sandbox::SandboxGuard;

/// Create a long-running sandbox, sync files up and down, and verify contents.
///
/// Covers:
/// 1. Directory round-trip (nested files)
/// 2. Large file round-trip (~512 KiB) with SHA-256 checksum verification
/// 3. Single-file round-trip
#[tokio::test]
async fn sandbox_file_sync_round_trip() {
    // ---------------------------------------------------------------
    // Step 1 — Create a sandbox with `--keep` running `sleep infinity`.
    // ---------------------------------------------------------------
    let mut guard = SandboxGuard::create_keep(&["sleep", "infinity"], "Ready")
        .await
        .expect("sandbox create --keep");

    let tmpdir = tempfile::tempdir().expect("create tmpdir");

    // ---------------------------------------------------------------
    // Step 2 — Sync up: push a local directory into the sandbox.
    // ---------------------------------------------------------------
    let upload_dir = tmpdir.path().join("upload");
    fs::create_dir_all(upload_dir.join("subdir")).expect("create upload dirs");
    fs::write(upload_dir.join("greeting.txt"), "hello-from-local").expect("write greeting.txt");
    fs::write(upload_dir.join("subdir/nested.txt"), "nested-content").expect("write nested.txt");

    let upload_str = upload_dir.to_str().expect("upload path is UTF-8");
    guard
        .sync(&["--up", upload_str, "/sandbox/uploaded"])
        .await
        .expect("sync --up directory");

    // ---------------------------------------------------------------
    // Step 3 — Sync down: pull the uploaded files back and verify.
    // ---------------------------------------------------------------
    let download_dir = tmpdir.path().join("download");
    fs::create_dir_all(&download_dir).expect("create download dir");

    let download_str = download_dir.to_str().expect("download path is UTF-8");
    guard
        .sync(&["--down", "/sandbox/uploaded", download_str])
        .await
        .expect("sync --down directory");

    // Verify top-level file.
    let greeting = fs::read_to_string(download_dir.join("greeting.txt"))
        .expect("read greeting.txt after sync down");
    assert_eq!(
        greeting, "hello-from-local",
        "greeting.txt content mismatch"
    );

    // Verify nested file.
    let nested = fs::read_to_string(download_dir.join("subdir/nested.txt"))
        .expect("read subdir/nested.txt after sync down");
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
        .sync(&["--up", large_dir_str, "/sandbox/large_test"])
        .await
        .expect("sync --up large file");

    let large_down = tmpdir.path().join("large_download");
    fs::create_dir_all(&large_down).expect("create large_download dir");

    let large_down_str = large_down.to_str().expect("large_down path is UTF-8");
    guard
        .sync(&["--down", "/sandbox/large_test", large_down_str])
        .await
        .expect("sync --down large file");

    let actual_data = fs::read(large_down.join("large.bin")).expect("read large.bin after sync");
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
        .sync(&["--up", single_str, "/sandbox"])
        .await
        .expect("sync --up single file");

    let single_down = tmpdir.path().join("single_down");
    fs::create_dir_all(&single_down).expect("create single_down dir");

    let single_down_str = single_down.to_str().expect("single_down path is UTF-8");
    guard
        .sync(&["--down", "/sandbox/single.txt", single_down_str])
        .await
        .expect("sync --down single file");

    let single_content = fs::read_to_string(single_down.join("single.txt"))
        .expect("read single.txt after sync");
    assert_eq!(
        single_content, "single-file-payload",
        "single.txt content mismatch"
    );

    // ---------------------------------------------------------------
    // Cleanup (guard also cleans up on drop).
    // ---------------------------------------------------------------
    guard.cleanup().await;
}
