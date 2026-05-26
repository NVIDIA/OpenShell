// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-vm")]

//! E2E test: build a custom container image locally, then launch it through the
//! standalone VM gateway.
//!
//! Prerequisites:
//! - A running VM-backed openshell gateway (`mise run e2e:vm` or
//!   `e2e/rust/e2e-vm.sh`)
//! - Docker daemon running locally (the CLI builds Dockerfiles into the local
//!   Docker daemon before handing the resulting image to the gateway)
//! - The `openshell` binary (built automatically from the workspace)

use std::io::Write;

use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;

const DOCKERFILE_CONTENT: &str = r#"FROM public.ecr.aws/docker/library/python:3.13-slim

# iproute2 is required for sandbox network namespace isolation.
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Create the sandbox user/group so the supervisor can switch to it.
# Use a high UID range to avoid conflicts with host users when running without
# user namespace remapping (UID in container = UID on host).
RUN groupadd -g 1000660000 sandbox && \
    useradd -m -u 1000660000 -g sandbox sandbox

# Write a marker file so we can verify this is our custom image.
# Place under /etc (Landlock baseline read-only path) so the sandbox
# can read it when filesystem restrictions are properly enforced.
RUN echo "vm-custom-image-e2e-marker" > /etc/marker.txt

CMD ["sleep", "infinity"]
"#;

const MARKER: &str = "vm-custom-image-e2e-marker";

#[tokio::test]
async fn sandbox_from_custom_dockerfile_on_vm_gateway() {
    if std::env::var("OPENSHELL_E2E_DRIVER").as_deref() != Ok("vm") {
        eprintln!("Skipping VM custom image test: e2e driver is not vm");
        return;
    }
    if std::env::var_os("DOCKER_HOST").is_none()
        && !std::path::Path::new("/var/run/docker.sock").exists()
    {
        eprintln!("Skipping VM custom image test: /var/run/docker.sock not found");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let dockerfile_path = tmpdir.path().join("Dockerfile");
    {
        let mut dockerfile = std::fs::File::create(&dockerfile_path).expect("create Dockerfile");
        dockerfile
            .write_all(DOCKERFILE_CONTENT.as_bytes())
            .expect("write Dockerfile");
    }

    let dockerfile_str = dockerfile_path.to_str().expect("Dockerfile path is UTF-8");
    let mut sandbox = SandboxGuard::create(&[
        "--from",
        dockerfile_str,
        "--",
        "cat",
        "/etc/marker.txt",
    ])
    .await
    .expect("sandbox create from Dockerfile on VM gateway");

    let clean_output = strip_ansi(&sandbox.create_output);
    assert!(
        clean_output.contains(MARKER),
        "expected marker '{MARKER}' in VM sandbox output:\n{clean_output}"
    );

    sandbox.cleanup().await;
}
