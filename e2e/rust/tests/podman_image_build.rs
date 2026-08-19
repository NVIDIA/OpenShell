// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-podman")]

//! Builds a minimal sandbox image through the gateway-selected Podman runtime.

use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serial_test::serial;

const IMAGE_MARKER: &str = "podman-gateway-build-image";
const READY_MARKER: &str = "podman-gateway-build-ready";
const EXEC_MARKER: &str = "podman-gateway-build-exec";

#[tokio::test]
#[serial(podman_image_build)]
async fn podman_gateway_builds_and_runs_minimal_sandbox_image() {
    if std::env::var("OPENSHELL_E2E_DRIVER").as_deref() != Ok("podman") {
        eprintln!("Skipping Podman image-build test: e2e driver is not podman");
        return;
    }

    let context = tempfile::tempdir().expect("create image build context");
    std::fs::write(
        context.path().join("Dockerfile"),
        format!(
            r#"FROM public.ecr.aws/docker/library/alpine:3.21
RUN apk add --no-cache iproute2 \
    && printf '{IMAGE_MARKER}\n' > /etc/openshell-image-build-marker
USER 10001:10001
CMD ["sleep", "infinity"]
"#
        ),
    )
    .expect("write minimal sandbox Dockerfile");
    let context_path = context.path().to_str().expect("context path is UTF-8");

    let sandbox = SandboxGuard::create_keep_with_args(
        &["--from", context_path, "--no-tty"],
        &[
            "sh",
            "-c",
            &format!(
                "set -eu; test \"$(cat /etc/openshell-image-build-marker)\" = {IMAGE_MARKER}; echo {READY_MARKER}; sleep infinity"
            ),
        ],
        READY_MARKER,
    )
    .await
    .expect("create sandbox from gateway-built Podman image");

    let create_output = strip_ansi(&sandbox.create_output);
    assert!(
        create_output.contains("is available to the gateway's selected compute runtime"),
        "expected the gateway image build to complete:\n{create_output}"
    );
    assert!(
        create_output.contains(READY_MARKER),
        "expected a command to run in the newly built image:\n{create_output}"
    );

    let exec_output = sandbox
        .exec(&[
            "sh",
            "-c",
            &format!(
                "test \"$(cat /etc/openshell-image-build-marker)\" = {IMAGE_MARKER} && echo {EXEC_MARKER}"
            ),
        ])
        .await
        .expect("execute a second command in the gateway-built image");
    assert!(
        exec_output.contains(EXEC_MARKER),
        "expected exec marker from gateway-built image:\n{exec_output}"
    );
}
