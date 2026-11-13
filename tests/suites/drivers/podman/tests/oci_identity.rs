// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Podman driver supervisor identity.
//!
//! Podman runs a sandbox's supervisor container as the workload's resolved
//! OCI identity with no effective capabilities; Docker runs it as a fixed
//! unprivileged user. The workload side of the same image is covered by the
//! `oci-image` feature suite in `tests/suites/features`.

use container_engine_support::Engine;
use testkit::{Context, ResultExt as _};

const OCI_IDENTITY: &str = "2345:2346";
/// A complete policy without a `process` section, so the sandbox identity
/// falls back to the image `USER`.
const IMAGE_IDENTITY_POLICY: &str = "version: 1

filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /lib64, /proc, /dev/urandom, /etc]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort

network_policies: {}
";

/// The supervisor container runs as the image's numeric `USER`, not root or a
/// fixed user, and has no effective capabilities.
#[testkit::test]
async fn supervisor_runs_as_oci_identity_without_capabilities(cx: &mut Context) -> testkit::Result {
    cx.expect_compute_driver("podman").await?;
    let engine = Engine::from_env()?;

    let image = engine
        .build_test_image(
            cx,
            "oci-identity",
            &format!(
                "FROM {}
USER 0:0
RUN mkdir -p /home/app/project && \\
    chown {OCI_IDENTITY} /home/app /home/app/project && \\
    chmod 0700 /home/app /home/app/project
WORKDIR /home/app/project
USER {OCI_IDENTITY}
",
                testkit::base_image()
            ),
        )
        .await?;
    let image_user = engine
        .output([
            "image",
            "inspect",
            "--format",
            "{{.Config.User}}",
            &image.tag,
        ])
        .await?;
    testkit::ensure!(
        image_user == OCI_IDENTITY,
        "the test image has USER {image_user:?}; expected {OCI_IDENTITY}"
    );

    let sandbox = cx
        .cli_sandbox("oi")
        .image(&image.tag)
        .policy_yaml(IMAGE_IDENTITY_POLICY)
        .command(["sleep", "infinity"])
        .create_ready()
        .await
        .context("sandbox starts from the OCI identity image")?;

    let supervisor = engine
        .container_for_role(sandbox.name(), "supervisor")
        .await?;
    let user = engine
        .inspect_container(&supervisor, "{{.Config.User}}")
        .await?;
    testkit::ensure!(
        user == OCI_IDENTITY,
        "the supervisor container runs as {user:?}; expected the image identity {OCI_IDENTITY}"
    );
    let caps = engine
        .inspect_container(&supervisor, "{{.EffectiveCaps}}")
        .await?;
    testkit::ensure!(
        caps == "[]",
        "the supervisor container has effective capabilities {caps}; expected none"
    );
    Ok(())
}
