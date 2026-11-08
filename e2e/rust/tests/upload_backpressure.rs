// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "e2e", unix))]

//! Regression for large built-in uploads through the CLI, gateway, supervisor,
//! and sandbox. A fast sender previously overflowed the supervisor's 4 MiB
//! pending-stdin budget while tar was creating many files (issue #4430).

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::time::Duration;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;
use rand::{RngCore, SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};
use tokio::time::timeout;

const FILE_COUNT: usize = 12_000;
const FILE_BYTES: usize = 8_192;
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(300);

/// An archive substantially larger than the stdin budget must finish without
/// pacing at the caller, preserving every file's content and tar semantics.
#[tokio::test]
async fn large_upload_preserves_content_and_metadata_outside_workdir() {
    let tmpdir = tempfile::tempdir().expect("create upload fixture tempdir");
    let source = tmpdir.path().join("large-project");
    fs::create_dir_all(source.join("payload")).expect("create payload directory");

    // Distinct deterministic pseudorandom bytes keep the fixture reproducible
    // without letting compression or identical-file checks hide dropped data.
    let mut rng = StdRng::seed_from_u64(4430);
    let mut payload = [0_u8; FILE_BYTES];
    let mut checksums = String::new();
    for index in 0..FILE_COUNT {
        rng.fill_bytes(&mut payload);
        let relative = format!("payload/{index:05}.bin");
        fs::write(source.join(&relative), payload).expect("write payload file");
        writeln!(checksums, "{:x}  {relative}", Sha256::digest(payload))
            .expect("append file checksum");
    }
    let manifest_digest = format!("{:x}", Sha256::digest(checksums.as_bytes()));
    fs::write(source.join("SHA256SUMS"), checksums).expect("write checksum manifest");
    fs::write(
        source.join("run.sh"),
        "#!/bin/sh\nprintf '%s\\n' upload-executable-ok\n",
    )
    .expect("write executable fixture");
    fs::set_permissions(source.join("run.sh"), fs::Permissions::from_mode(0o751))
        .expect("set executable mode");
    symlink("payload/00000.bin", source.join("payload-link")).expect("create relative symlink");
    symlink("missing-target", source.join("dangling-link")).expect("create dangling symlink");
    fs::write(source.join("conflict.txt"), "local-conflict").expect("write merge fixture");

    let mut sandbox = SandboxGuard::create(&[])
        .await
        .expect("create persistent upload sandbox");
    sandbox
        .exec(&[
            "sh",
            "-c",
            "set -eu; test \"$(pwd -P)\" != /tmp/openshell-upload-backpressure; \
             mkdir -p /tmp/openshell-upload-backpressure/large-project; \
             printf remote-conflict > /tmp/openshell-upload-backpressure/large-project/conflict.txt; \
             printf remote-preserved > /tmp/openshell-upload-backpressure/large-project/unrelated.txt",
        ])
        .await
        .expect("prepare destination outside the canonical workdir");

    // No sleep, bandwidth limit, or retry: the protocol must backpressure the
    // normal CLI tar stream, even when the local sender outruns extraction.
    let mut upload = openshell_cmd();
    upload
        .env("RUST_LOG", "warn")
        .args(["sandbox", "upload", &sandbox.name])
        .arg(&source)
        .args(["/tmp/openshell-upload-backpressure", "--no-git-ignore"]);
    let result = timeout(TRANSFER_TIMEOUT, upload.output())
        .await
        .expect("large upload must not hang waiting for credit")
        .expect("start large upload");
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.status.success(), "large upload failed: {output}");
    assert!(
        !output.contains("sandbox sync operation failed; retrying"),
        "large upload required a retry: {output}"
    );

    let verify = format!(
        "set -eu; cd /tmp/openshell-upload-backpressure/large-project; \
         test \"$(find payload -type f | wc -l)\" -eq {FILE_COUNT}; \
         test \"$(sha256sum SHA256SUMS | cut -d ' ' -f 1)\" = {manifest_digest}; \
         sha256sum --check --quiet SHA256SUMS; \
         test \"$(stat -c %a run.sh)\" = 751; \
         test \"$(./run.sh)\" = upload-executable-ok; \
         test -L payload-link; test \"$(readlink payload-link)\" = payload/00000.bin; \
         test -L dangling-link; test ! -e dangling-link; \
         test \"$(readlink dangling-link)\" = missing-target; \
         test \"$(cat conflict.txt)\" = local-conflict; \
         test \"$(cat unrelated.txt)\" = remote-preserved; \
         printf large-upload-content-and-metadata-ok"
    );
    let output = timeout(TRANSFER_TIMEOUT, sandbox.exec(&["sh", "-c", &verify]))
        .await
        .expect("large upload verification must not hang")
        .expect("every uploaded file and metadata item must match");
    assert!(
        strip_ansi(&output).contains("large-upload-content-and-metadata-ok"),
        "expected complete upload verification marker:\n{output}"
    );

    sandbox.cleanup().await;
}
