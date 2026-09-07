// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-local-container-driver")]

//! E2E test: build custom container images and run sandboxes with them.
//!
//! Prerequisites:
//! - A running Docker- or Podman-backed openshell gateway
//! - The matching container runtime running (for image builds)
//! - The `openshell` binary (built automatically from the workspace)

use std::{fs, io::Write};

use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serial_test::serial;

const DOCKERFILE_CONTENT: &str = r#"FROM public.ecr.aws/docker/library/python:3.13-slim

# iproute2 is required for sandbox network namespace isolation.
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 1235 appstaff && \
    useradd -m -u 1234 -g appstaff app

# The final image identity already owns the OCI working directory. Existing
# root-owned content remains root-owned.
WORKDIR /workspace/project
RUN printf root-owned > root-owned.txt && chown app:appstaff .

# Write a marker file so we can verify this is our custom image.
# Place under /etc (Landlock baseline read-only path) so the sandbox
# can read it when filesystem restrictions are properly enforced.
RUN echo "custom-image-e2e-marker" > /etc/marker.txt

USER app
CMD ["sleep", "infinity"]
"#;

const NUMERIC_DOCKERFILE_CONTENT: &str = r#"FROM public.ecr.aws/docker/library/python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

USER 2345:2346
CMD ["sleep", "infinity"]
"#;

const UNWRITABLE_WORKDIR_DOCKERFILE_CONTENT: &str = r#"FROM public.ecr.aws/docker/library/python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 3235 appstaff \
    && useradd -m -u 3234 -g appstaff app

WORKDIR /workspace/project
USER app
CMD ["sleep", "infinity"]
"#;

const MARKER: &str = "custom-image-e2e-marker";

/// A named OCI user can write through direct and SSH children when the image
/// already grants that authority; existing content retains its ownership.
#[tokio::test]
#[serial(custom_image)]
async fn sandbox_from_custom_dockerfile() {
    // Step 1: Write a temporary Dockerfile.
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let dockerfile_path = tmpdir.path().join("Dockerfile");
    {
        let mut f = std::fs::File::create(&dockerfile_path).expect("create Dockerfile");
        f.write_all(DOCKERFILE_CONTENT.as_bytes())
            .expect("write Dockerfile");
    }

    // Step 2: Create a sandbox from the Dockerfile.
    let dockerfile_str = dockerfile_path.to_str().expect("Dockerfile path is UTF-8");
    let mut guard = SandboxGuard::create_keep_with_args(
        &["--from", dockerfile_str, "--no-tty"],
        &[
            "sh",
            "-c",
            "set -eu; id -u; id -g; test \"$(pwd -P)\" = /workspace/project; \
             test \"$HOME\" = /workspace/project; test \"$(cat root-owned.txt)\" = root-owned; \
             test \"$(stat -c %u:%g .)\" = 1234:1235; \
             test \"$(stat -c %u:%g root-owned.txt)\" = 0:0; \
             touch direct-oci-user-write; cat /etc/marker.txt; echo Ready; sleep infinity",
        ],
        "Ready",
    )
    .await
    .expect("sandbox create from Dockerfile");

    // Step 3: Verify the marker file content appears in the output.
    let clean_output = strip_ansi(&guard.create_output);
    assert!(
        clean_output.contains(MARKER),
        "expected marker '{MARKER}' in sandbox output:\n{clean_output}"
    );
    assert!(
        clean_output.contains("1234") && clean_output.contains("1235"),
        "expected named OCI identity 1234:1235 in sandbox output:\n{clean_output}"
    );

    let ssh_output = guard
        .exec(&[
            "sh",
            "-c",
            "set -eu; test \"$(id -u):$(id -g)\" = 1234:1235; \
             test \"$(pwd -P)\" = /workspace/project; test \"$HOME\" = /workspace/project; \
             touch ssh-oci-user-write; echo ssh-write-ok",
        ])
        .await
        .expect("SSH child should write to prepared workspace");
    assert!(
        ssh_output.contains("ssh-write-ok"),
        "expected SSH write marker:\n{ssh_output}"
    );

    let transfer_source = tmpdir.path().join("workspace-transfer.txt");
    fs::write(&transfer_source, "workspace-transfer-ok").expect("write transfer fixture");
    guard
        .upload_to_workdir(
            transfer_source
                .to_str()
                .expect("transfer fixture path is UTF-8"),
        )
        .await
        .expect("upload should default to the OCI workspace");
    let transfer_download = tmpdir.path().join("workspace-transfer-downloaded.txt");
    guard
        .download(
            "workspace-transfer.txt",
            transfer_download
                .to_str()
                .expect("download destination path is UTF-8"),
        )
        .await
        .expect("download should resolve relative to the OCI workspace");
    assert_eq!(
        fs::read_to_string(transfer_download).expect("read downloaded transfer fixture"),
        "workspace-transfer-ok"
    );

    guard
        .exec(&[
            "sh",
            "-c",
            "set -eu; mkdir -p merge-upload; \
             printf remote-conflict > merge-upload/conflict.txt; \
             printf remote-preserved > merge-upload/unrelated.txt",
        ])
        .await
        .expect("seed existing remote upload directory");
    let merge_source = tmpdir.path().join("merge-upload");
    fs::create_dir(&merge_source).expect("create local upload directory");
    fs::write(merge_source.join("conflict.txt"), "local-conflict")
        .expect("write conflicting local upload file");
    fs::write(merge_source.join("added.txt"), "local-added")
        .expect("write added local upload file");
    guard
        .upload_to_workdir(merge_source.to_str().expect("merge upload path is UTF-8"))
        .await
        .expect("upload should merge into the existing remote directory");
    guard
        .exec(&[
            "sh",
            "-c",
            "set -eu; \
             test \"$(cat merge-upload/conflict.txt)\" = local-conflict; \
             test \"$(cat merge-upload/added.txt)\" = local-added; \
             test \"$(cat merge-upload/unrelated.txt)\" = remote-preserved",
        ])
        .await
        .expect("upload should overwrite conflicts and preserve unrelated remote files");

    // Explicit cleanup (also happens in Drop, but explicit is clearer in tests).
    guard.cleanup().await;
}

/// A numeric OCI user/group pair works without passwd or group entries.
/// The image intentionally has no pre-existing `/sandbox`.
#[tokio::test]
#[serial(custom_image)]
async fn sandbox_from_passwd_less_numeric_oci_user() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let dockerfile_path = tmpdir.path().join("Dockerfile");
    {
        let mut f = std::fs::File::create(&dockerfile_path).expect("create Dockerfile");
        f.write_all(NUMERIC_DOCKERFILE_CONTENT.as_bytes())
            .expect("write Dockerfile");
    }

    let dockerfile_str = dockerfile_path.to_str().expect("Dockerfile path is UTF-8");
    let mut guard = SandboxGuard::create(&[
        "--from",
        dockerfile_str,
        "--",
        "sh",
        "-c",
        "set -eu; id -u; id -g; test \"$(pwd -P)\" = /sandbox; \
         test \"$HOME\" = /sandbox; touch numeric-oci-user-write",
    ])
    .await
    .expect("sandbox create from numeric OCI Dockerfile");

    let clean_output = strip_ansi(&guard.create_output);
    assert!(
        clean_output.contains("2345") && clean_output.contains("2346"),
        "expected numeric OCI identity 2345:2346 in sandbox output:\n{clean_output}"
    );

    guard.cleanup().await;
}

#[tokio::test]
#[serial(custom_image)]
async fn sandbox_rejects_image_workdir_that_would_require_new_authority() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let dockerfile_path = tmpdir.path().join("Dockerfile");
    fs::write(&dockerfile_path, UNWRITABLE_WORKDIR_DOCKERFILE_CONTENT).expect("write Dockerfile");
    let dockerfile_str = dockerfile_path.to_str().expect("Dockerfile path is UTF-8");

    let result = SandboxGuard::create_keep_with_args(
        &["--from", dockerfile_str, "--no-tty"],
        &["sh", "-c", "echo should-not-run"],
        "should-not-run",
    )
    .await;
    let error = match result {
        Ok(mut guard) => {
            guard.cleanup().await;
            panic!("root-owned workdir must not be made writable for the image user");
        }
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        message.contains("WorkingDir")
            || message.contains("workspace")
            || message.contains("readiness"),
        "expected workspace authority failure, got: {message}"
    );
}
