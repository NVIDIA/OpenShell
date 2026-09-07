// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-podman")]

//! Podman-specific E2E coverage for OCI identity inspection and immutable-image
//! launch.
//!
//! The test builds an image through the selected Podman engine, creates a
//! sandbox from its mutable tag, and verifies both the child identity and the
//! image ID recorded on the real sandbox container. This exercises the Podman
//! API inspect → protected metadata → create path rather than only its unit
//! serialization boundaries.

use std::process::Stdio;

use openshell_e2e::harness::container::{ContainerEngine, is_e2e_driver};
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;

const BASE_IMAGE: &str = "ghcr.io/nvidia/openshell-community/sandboxes/base:latest";
const READY_MARKER: &str = "podman-oci-identity-ready";
const OCI_UID: &str = "2345";
const OCI_GID: &str = "2346";
const OCI_FALLBACK_POLICY: &str = r#"version: 1

filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /lib64, /proc, /dev/urandom, /etc]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort

network_policies: {}
"#;

struct ImageGuard {
    engine: ContainerEngine,
    tag: String,
    id: String,
}

impl ImageGuard {
    fn build() -> Result<Self, String> {
        let engine = ContainerEngine::from_env()?;
        if engine.name() != "podman" {
            return Err(format!(
                "Podman OCI identity E2E requires podman, got {}",
                engine.name()
            ));
        }

        let context = tempfile::tempdir().map_err(|err| format!("create build context: {err}"))?;
        let containerfile = context.path().join("Containerfile");
        std::fs::write(
            &containerfile,
            format!("FROM {BASE_IMAGE}\nUSER {OCI_UID}:{OCI_GID}\n"),
        )
        .map_err(|err| format!("write Containerfile: {err}"))?;

        let tag = format!(
            "localhost/openshell-e2e-podman-oci-identity:{}",
            std::process::id()
        );
        run_engine(
            &engine,
            &[
                "build",
                "--pull=never",
                "--file",
                containerfile
                    .to_str()
                    .ok_or_else(|| "Containerfile path is not UTF-8".to_string())?,
                "--tag",
                &tag,
                context
                    .path()
                    .to_str()
                    .ok_or_else(|| "build context path is not UTF-8".to_string())?,
            ],
        )?;
        let id = run_engine(&engine, &["image", "inspect", "--format", "{{.Id}}", &tag])?;
        let user = run_engine(
            &engine,
            &["image", "inspect", "--format", "{{.Config.User}}", &tag],
        )?;
        if user != format!("{OCI_UID}:{OCI_GID}") {
            return Err(format!(
                "Podman-built image has OCI user '{user}', expected {OCI_UID}:{OCI_GID}"
            ));
        }

        Ok(Self { engine, tag, id })
    }
}

impl Drop for ImageGuard {
    fn drop(&mut self) {
        let _ = self
            .engine
            .command()
            .args(["image", "rm", "--force", &self.tag])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn run_engine(engine: &ContainerEngine, args: &[&str]) -> Result<String, String> {
    let output = engine
        .command()
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|err| format!("failed to run {} {}: {err}", engine.name(), args.join(" ")))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Err(format!(
            "{} {} failed (exit {:?}):\n{stdout}{stderr}",
            engine.name(),
            args.join(" "),
            output.status.code()
        ));
    }
    Ok(stdout.trim().to_string())
}

fn sandbox_container_id(engine: &ContainerEngine, sandbox_name: &str) -> Result<String, String> {
    let name_filter = format!("label=openshell.ai/sandbox-name={sandbox_name}");
    let stdout = run_engine(
        engine,
        &[
            "ps",
            "-aq",
            "--filter",
            "label=openshell.managed=true",
            "--filter",
            &name_filter,
        ],
    )?;
    let ids = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    match ids.as_slice() {
        [id] => Ok((*id).to_string()),
        [] => Err(format!(
            "no Podman container found for sandbox '{sandbox_name}'"
        )),
        _ => Err(format!(
            "multiple Podman containers found for sandbox '{sandbox_name}': {ids:?}"
        )),
    }
}

fn normalized_image_id(image_id: &str) -> &str {
    image_id
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(image_id.trim())
}

#[tokio::test]
async fn podman_uses_oci_identity_and_inspected_image_id() {
    if !is_e2e_driver("podman") {
        eprintln!("Skipping Podman OCI identity test: e2e driver is not podman");
        return;
    }

    let image = ImageGuard::build().expect("build Podman OCI identity image");
    // The community base image contains a baked default policy with an
    // explicit `sandbox` process identity. Supply a complete policy that
    // intentionally omits `process` so this test exercises OCI fallback.
    let policy = tempfile::NamedTempFile::new().expect("create OCI fallback policy");
    std::fs::write(policy.path(), OCI_FALLBACK_POLICY).expect("write OCI fallback policy");
    let policy_path = policy.path().to_str().expect("policy path is UTF-8");
    let mut sandbox = SandboxGuard::create_keep_with_args(
        &[
            "--from",
            &image.tag,
            "--policy",
            policy_path,
            "--no-tty",
        ],
        &[
            "sh",
            "-c",
            "set -eu; printf 'direct-identity=%s:%s\n' \"$(id -u)\" \"$(id -g)\"; echo podman-oci-identity-ready; sleep infinity",
        ],
        READY_MARKER,
    )
    .await
    .expect("create sandbox from Podman-built OCI identity image");

    let direct_output = strip_ansi(&sandbox.create_output);
    assert!(
        direct_output.contains("direct-identity=2345:2346"),
        "expected direct child identity {OCI_UID}:{OCI_GID}:\n{direct_output}"
    );

    let ssh_output = sandbox
        .exec(&[
            "sh",
            "-c",
            "test \"$(id -u):$(id -g)\" = 2345:2346; echo podman-ssh-identity-ok",
        ])
        .await
        .expect("SSH child should use Podman OCI identity");
    assert!(
        ssh_output.contains("podman-ssh-identity-ok"),
        "expected SSH identity marker:\n{ssh_output}"
    );

    let container_id =
        sandbox_container_id(&image.engine, &sandbox.name).expect("find Podman sandbox container");
    let launched_image_id = run_engine(
        &image.engine,
        &[
            "container",
            "inspect",
            "--format",
            "{{.Image}}",
            &container_id,
        ],
    )
    .expect("inspect Podman sandbox container image");
    assert_eq!(
        normalized_image_id(&launched_image_id),
        normalized_image_id(&image.id),
        "Podman sandbox must launch the immutable image ID inspected before creation"
    );

    sandbox.cleanup().await;
}
