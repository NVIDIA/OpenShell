// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E test: build a custom container image and run a sandbox with it.
//!
//! Prerequisites:
//! - A running nemoclaw gateway (`nemoclaw gateway start`)
//! - Docker daemon running (for image build)
//! - The `nemoclaw` binary (built automatically from the workspace)

use std::io::Write;

use nemoclaw_e2e::harness::output::strip_ansi;
use nemoclaw_e2e::harness::sandbox::SandboxGuard;

const DOCKERFILE_CONTENT: &str = r#"FROM python:3.12-slim

# iproute2 is required for sandbox network namespace isolation.
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Create the sandbox user/group so the supervisor can switch to it.
RUN groupadd -g 1000 sandbox && \
    useradd -m -u 1000 -g sandbox sandbox

# Write a marker file so we can verify this is our custom image.
RUN echo "custom-image-e2e-marker" > /opt/marker.txt

CMD ["sleep", "infinity"]
"#;

const MARKER: &str = "custom-image-e2e-marker";

/// Build a custom Docker image from a Dockerfile and verify that a sandbox
/// created from it contains the expected marker file.
#[tokio::test]
async fn sandbox_from_custom_dockerfile() {
    // Step 1 — Write a temporary Dockerfile.
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let dockerfile_path = tmpdir.path().join("Dockerfile");
    {
        let mut f = std::fs::File::create(&dockerfile_path).expect("create Dockerfile");
        f.write_all(DOCKERFILE_CONTENT.as_bytes())
            .expect("write Dockerfile");
    }

    // Step 2 — Create a sandbox from the Dockerfile.
    let dockerfile_str = dockerfile_path.to_str().expect("Dockerfile path is UTF-8");
    let mut guard = SandboxGuard::create(&[
        "--from",
        dockerfile_str,
        "--",
        "cat",
        "/opt/marker.txt",
    ])
    .await
    .expect("sandbox create from Dockerfile");

    // Step 3 — Verify the marker file content appears in the output.
    let clean_output = strip_ansi(&guard.create_output);
    assert!(
        clean_output.contains(MARKER),
        "expected marker '{MARKER}' in sandbox output:\n{clean_output}"
    );

    // Explicit cleanup (also happens in Drop, but explicit is clearer in tests).
    guard.cleanup().await;
}
