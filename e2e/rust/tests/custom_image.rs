// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-local-container-driver")]

//! E2E test: build custom container images and run sandboxes with them.
//!
//! Prerequisites:
//! - A running Docker- or Podman-backed openshell gateway
//! - The matching container runtime running (for image builds)
//! - The `openshell` binary (built automatically from the workspace)

use std::io::Write;

use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;

const DOCKERFILE_CONTENT: &str = r#"FROM public.ecr.aws/docker/library/python:3.13-slim

# iproute2 is required for sandbox network namespace isolation.
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 1235 appstaff && \
    useradd -m -u 1234 -g appstaff app

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

const MARKER: &str = "custom-image-e2e-marker";

/// Direct and SSH children use the same named OCI identity.
#[tokio::test]
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
            "set -eu; id -u; id -g; cat /etc/marker.txt; echo Ready; sleep infinity",
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
            "set -eu; test \"$(id -u):$(id -g)\" = 1234:1235; echo ssh-identity-ok",
        ])
        .await
        .expect("SSH child should use OCI identity");
    assert!(
        ssh_output.contains("ssh-identity-ok"),
        "expected SSH identity marker:\n{ssh_output}"
    );

    // Explicit cleanup (also happens in Drop, but explicit is clearer in tests).
    guard.cleanup().await;
}

/// A numeric OCI user/group pair works without passwd or group entries.
#[tokio::test]
async fn sandbox_from_passwd_less_numeric_oci_user() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let dockerfile_path = tmpdir.path().join("Dockerfile");
    {
        let mut f = std::fs::File::create(&dockerfile_path).expect("create Dockerfile");
        f.write_all(NUMERIC_DOCKERFILE_CONTENT.as_bytes())
            .expect("write Dockerfile");
    }

    let dockerfile_str = dockerfile_path.to_str().expect("Dockerfile path is UTF-8");
    let mut guard =
        SandboxGuard::create(&["--from", dockerfile_str, "--", "sh", "-c", "id -u; id -g"])
            .await
            .expect("sandbox create from numeric OCI Dockerfile");

    let clean_output = strip_ansi(&guard.create_output);
    assert!(
        clean_output.contains("2345") && clean_output.contains("2346"),
        "expected numeric OCI identity 2345:2346 in sandbox output:\n{clean_output}"
    );

    guard.cleanup().await;
}
