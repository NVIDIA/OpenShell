// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Podman container settings for a sandbox created from an image with a custom
//! `USER` and `WORKDIR` that the sandbox cannot observe from inside.
//!
//! The shared `oci-image` feature suite checks what the workload sees. This
//! test inspects the Podman containers directly: the workload runs the image
//! ID inspected before creation rather than the mutable tag, and is fenced by
//! `network=none`; the supervisor runs as the image user with no effective
//! capabilities.
//!
//! `OPENSHELL_TEST_CONTAINER_ENGINE` is the command that reaches the gateway's
//! Podman store, such as `podman` or `sudo -n podman`.

mod support;

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use openshell_conformance::OpenShellRunner;

use support::assert_podman_gateway;

const ENGINE_ENV: &str = "OPENSHELL_TEST_CONTAINER_ENGINE";
const CREATE_TIMEOUT: Duration = Duration::from_mins(10);
const IMAGE_USER: &str = "2345:2346";

#[tokio::test]
async fn podman_containers_use_pinned_image_and_image_user() {
    let mut runner = OpenShellRunner::from_env("podman-oci-identity")
        .expect("candidate openshell CLI is available");
    let tag = format!(
        "localhost/openshell-test-podman-oci-identity:{}",
        std::process::id()
    );
    let result = async {
        runner.check_gateway_status().await?;
        assert_podman_gateway(&runner).await?;

        let containerfile = format!(
            "FROM nvcr.io/nvidia/base/ubuntu:24.04
RUN mkdir -p /workspace/project && chown {IMAGE_USER} /workspace/project
WORKDIR /workspace/project
USER {IMAGE_USER}
"
        );
        podman(&["build", "--tag", &tag, "-"], Some(&containerfile))?;
        let image_id = podman(&["image", "inspect", "--format", "{{.Id}}", &tag], None)?;

        let name = format!("po-{}", runner.id());
        runner.track_sandbox(&name);
        runner
            .step("oci-identity/create")
            .description("sandbox starts from the test image")
            .with_timeout(CREATE_TIMEOUT)
            .run(&[
                "sandbox", "create", "--name", &name, "--from", &tag, "--detach", "--", "sleep",
                "infinity",
            ])
            .await
            .map_err(|error| error.to_string())?
            .require_success()?;

        let workload = container_for_role(&name, "sandbox")?;
        let supervisor = container_for_role(&name, "supervisor")?;
        for (what, container, format, expected) in [
            ("workload image", &workload, "{{.Image}}", image_id.as_str()),
            ("workload user", &workload, "{{.Config.User}}", IMAGE_USER),
            (
                "workload network",
                &workload,
                "{{.HostConfig.NetworkMode}}",
                "none",
            ),
            (
                "supervisor user",
                &supervisor,
                "{{.Config.User}}",
                IMAGE_USER,
            ),
            (
                "supervisor capabilities",
                &supervisor,
                "{{.EffectiveCaps}}",
                "[]",
            ),
        ] {
            let actual = podman(&["inspect", "--format", format, container], None)?;
            if actual.trim_start_matches("sha256:") != expected.trim_start_matches("sha256:") {
                return Err(format!("{what} is {actual:?}, expected {expected:?}"));
            }
        }
        Ok(())
    }
    .await;
    // Remove the tag only after the sandbox is gone. A test failure takes
    // precedence over a cleanup failure.
    let result = runner.finish(result).await;
    let cleanup = podman(&["image", "rm", &tag], None);
    if let Err(error) = result {
        panic!("Podman OCI identity failed:\n{error}");
    }
    cleanup.expect("remove test image");
}

/// The one container with `role` for `sandbox`.
fn container_for_role(sandbox: &str, role: &str) -> Result<String, String> {
    let ids = podman(
        &[
            "ps",
            "-aq",
            "--filter",
            &format!("label=openshell.ai/sandbox-name={sandbox}"),
            "--filter",
            &format!("label=openshell.ai/isolation-role={role}"),
        ],
        None,
    )?;
    match ids.lines().collect::<Vec<_>>().as_slice() {
        [id] => Ok((*id).to_string()),
        ids => Err(format!(
            "expected one {role} container for sandbox {sandbox}, found {ids:?}"
        )),
    }
}

/// Run a command against the gateway's Podman store and return its stdout.
fn podman(args: &[&str], stdin: Option<&str>) -> Result<String, String> {
    let engine = std::env::var(ENGINE_ENV)
        .map_err(|_| format!("{ENGINE_ENV} must name the gateway's Podman command"))?;
    let command = format!("{engine} {}", args.join(" "));
    let mut engine = engine.split_whitespace();
    let program = engine
        .next()
        .ok_or_else(|| format!("{ENGINE_ENV} is empty"))?;
    let mut child = Command::new(program)
        .args(engine)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to run {command}: {error}"))?;
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(input.as_bytes())
            .map_err(|error| format!("write stdin of {command}: {error}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("wait for {command}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{command} failed ({}):\n{}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
