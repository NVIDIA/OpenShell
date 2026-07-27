// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-local-container-driver")]

//! OCI image identity E2E coverage for the Docker and Podman local drivers.
//!
//! Docker fixtures intentionally go through `openshell sandbox create --from
//! Dockerfile`. Podman fixtures are built into the local Podman store first and
//! passed to `--from` by tag because the CLI's Dockerfile builder targets the
//! Docker daemon.

use std::path::Path;
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::container::{ContainerEngine, e2e_driver};
use openshell_e2e::harness::output::{extract_field, strip_ansi};
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::{Map, Value};

const NUMERIC_DOCKERFILE: &str = r"FROM public.ecr.aws/docker/library/python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && ! getent passwd 1234 \
    && ! getent group 1235
RUN printf numeric-image-marker > /etc/openshell-image-marker
USER 1234:1235
";

const NAMED_DOCKERFILE: &str = r"FROM public.ecr.aws/docker/library/python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 2346 appgroup \
    && useradd --uid 2345 --gid 2346 --no-create-home --home-dir /sandbox app
RUN printf named-image-marker > /etc/openshell-image-marker
USER app
";

const MISSING_USER_DOCKERFILE: &str = r"FROM public.ecr.aws/docker/library/python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*
";

const ROOT_USER_DOCKERFILE: &str = r"FROM public.ecr.aws/docker/library/python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*
USER root
";

const PROBE_LABEL: &str = "OPENSHELL_IDENTITY_PROBE";
const PROBE_SCRIPT: &str = r#"set -eu
uid=$(id -u)
gid=$(id -g)
groups=$(id -G)
if grep -Eq "^[^:]*:[^:]*:${uid}:" /etc/passwd; then passwd=present; else passwd=absent; fi
if grep -Eq "^[^:]*:[^:]*:${gid}:" /etc/group; then group=present; else group=absent; fi
marker=$(cat /etc/openshell-image-marker)
printf sandbox-write-ok > /sandbox/identity-probe
write=$(cat /sandbox/identity-probe)
printf 'OPENSHELL_IDENTITY_PROBE uid=%s gid=%s groups=%s home=%s user=%s logname=%s passwd=%s group=%s marker=%s write=%s\n' \
  "$uid" "$gid" "$groups" "${HOME-<unset>}" "${USER-<unset>}" "${LOGNAME-<unset>}" \
  "$passwd" "$group" "$marker" "$write"
"#;

struct Fixture {
    _directory: tempfile::TempDir,
    engine: ContainerEngine,
    source: String,
    image_tag: Option<String>,
    cli_build: bool,
}

impl Fixture {
    fn create(name: &str, dockerfile: &str) -> Result<Self, String> {
        let driver = local_driver();
        let engine = ContainerEngine::from_env()?;
        let directory = tempfile::tempdir().map_err(|err| format!("create fixture dir: {err}"))?;
        let dockerfile_path = directory.path().join("Dockerfile");
        std::fs::write(&dockerfile_path, dockerfile)
            .map_err(|err| format!("write {}: {err}", dockerfile_path.display()))?;

        if driver == "docker" {
            return Ok(Self {
                _directory: directory,
                engine,
                source: path_string(&dockerfile_path)?,
                image_tag: None,
                cli_build: true,
            });
        }

        let image_tag = unique_image_tag(name);
        let output = engine
            .command()
            .arg("build")
            .arg("--tag")
            .arg(&image_tag)
            .arg("--file")
            .arg(&dockerfile_path)
            .arg(directory.path())
            .output()
            .map_err(|err| format!("run podman build for {name}: {err}"))?;
        if !output.status.success() {
            return Err(format!(
                "podman build for {name} failed (exit {:?}):\n{}{}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(Self {
            _directory: directory,
            engine,
            source: image_tag.clone(),
            image_tag: Some(image_tag),
            cli_build: false,
        })
    }

    fn capture_cli_built_image(&mut self, output: &str) -> Result<(), String> {
        if !self.cli_build || self.image_tag.is_some() {
            return Ok(());
        }
        self.image_tag = cli_built_image(output);
        self.image_tag.as_ref().map_or_else(
            || Err("could not identify CLI-built Docker fixture image for cleanup".to_string()),
            |_| Ok(()),
        )
    }

    fn cleanup(&mut self) -> Result<(), String> {
        let Some(image_tag) = self.image_tag.take() else {
            return Ok(());
        };
        let output = self
            .engine
            .command()
            .args(["image", "rm", "--force", &image_tag])
            .output()
            .map_err(|err| format!("remove fixture image {image_tag}: {err}"))?;
        if output.status.success() {
            return Ok(());
        }
        Err(format!(
            "remove fixture image {image_tag} failed (exit {:?}):\n{}{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[tokio::test]
#[serial_test::serial]
async fn passwdless_numeric_user_preserves_declared_identity() {
    if !image_identity_mode_enabled() {
        return;
    }
    let output = run_fixture(
        "numeric",
        NUMERIC_DOCKERFILE,
        &[],
        &["sh", "-lc", PROBE_SCRIPT],
    )
    .await
    .expect("run passwd-less numeric image");

    assert_probe(
        &output,
        "OPENSHELL_IDENTITY_PROBE uid=1234 gid=1235 groups=1235 home=/sandbox user=1234 logname=1234 passwd=absent group=absent marker=numeric-image-marker write=sandbox-write-ok",
    );
}

#[tokio::test]
#[serial_test::serial]
async fn named_user_uses_passwd_primary_group() {
    if !image_identity_mode_enabled() {
        return;
    }
    let output = run_fixture("named", NAMED_DOCKERFILE, &[], &["sh", "-lc", PROBE_SCRIPT])
        .await
        .expect("run named-user image");

    assert_probe(
        &output,
        "OPENSHELL_IDENTITY_PROBE uid=2345 gid=2346 groups=2346 home=/sandbox user=app logname=app passwd=present group=present marker=named-image-marker write=sandbox-write-ok",
    );
}

#[tokio::test]
#[serial_test::serial]
async fn fixed_identity_preserves_configured_identity() {
    let Some((uid, gid)) = fixed_identity_config() else {
        return;
    };
    let output = run_fixture(
        "fixed",
        NUMERIC_DOCKERFILE,
        &[],
        &["sh", "-lc", PROBE_SCRIPT],
    )
    .await
    .expect("run fixed-identity image");

    assert_probe(
        &output,
        &format!(
            "OPENSHELL_IDENTITY_PROBE uid={uid} gid={gid} groups={gid} home=/sandbox user={uid} logname={uid} passwd=absent group=absent marker=numeric-image-marker write=sandbox-write-ok"
        ),
    );
}

#[tokio::test]
#[serial_test::serial]
async fn missing_and_root_user_declarations_fail_provisioning() {
    if !image_identity_mode_enabled() {
        return;
    }
    for (name, dockerfile, expected) in [
        (
            "missing-user",
            MISSING_USER_DOCKERFILE,
            "must declare a non-empty OCI Config.User",
        ),
        (
            "root-user",
            ROOT_USER_DOCKERFILE,
            "OCI Config.User must not explicitly select root",
        ),
    ] {
        let error = run_fixture(name, dockerfile, &[], &["true"])
            .await
            .expect_err("invalid image identity should fail sandbox provisioning");
        let normalized_error = normalize_whitespace(&strip_ansi(&error));
        assert!(
            normalized_error.contains(expected),
            "expected {name} failure to contain '{expected}':\n{error}"
        );
    }
}

#[tokio::test]
#[serial_test::serial]
async fn image_identity_rejects_external_bind_and_named_volume_mounts() {
    if !image_identity_mode_enabled() {
        return;
    }
    let bind_directory = tempfile::tempdir().expect("create rejected bind source");
    let bind_source = path_string(bind_directory.path()).expect("bind source path is UTF-8");
    let driver = local_driver();
    let mounts = [
        (
            "bind",
            serde_json::json!({
                "type": "bind",
                "source": bind_source,
                "target": "/sandbox/external-bind",
                "read_only": false
            }),
            "bind mounts are not allowed when identity_source = 'image'",
        ),
        (
            "volume",
            serde_json::json!({
                "type": "volume",
                "source": "openshell-e2e-rejected-volume",
                "target": "/sandbox/external-volume",
                "read_only": false
            }),
            "named volume mounts are not allowed when identity_source = 'image'",
        ),
    ];

    for (name, mount, expected) in mounts {
        let driver_config = driver_config_mount_json(&driver, &mount);
        let extra_args = ["--driver-config-json".to_string(), driver_config];
        let error = run_fixture(
            &format!("rejected-{name}"),
            NUMERIC_DOCKERFILE,
            &extra_args,
            &["true"],
        )
        .await
        .expect_err("image identity must reject creator-selected external storage");
        let normalized_error = normalize_whitespace(&strip_ansi(&error));
        assert!(
            normalized_error.contains(expected),
            "expected {name} rejection to contain '{expected}':\n{error}"
        );
    }
}

fn normalize_whitespace(value: &str) -> String {
    value
        .split_whitespace()
        .filter(|token| *token != "│")
        .collect::<Vec<_>>()
        .join(" ")
}

async fn run_fixture(
    name: &str,
    dockerfile: &str,
    extra_args: &[String],
    command: &[&str],
) -> Result<String, String> {
    let mut fixture = Fixture::create(name, dockerfile)?;
    let mut args = vec![
        "--no-keep".to_string(),
        "--from".to_string(),
        fixture.source.clone(),
    ];
    args.extend_from_slice(extra_args);
    args.push("--".to_string());
    args.extend(command.iter().map(|arg| (*arg).to_string()));
    let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();

    let result = SandboxGuard::create(&arg_refs).await;
    match result {
        Ok(mut sandbox) => {
            let captured_image = fixture.capture_cli_built_image(&sandbox.create_output);
            let output = sandbox.create_output.clone();
            sandbox.cleanup().await;
            captured_image?;
            fixture.cleanup()?;
            Ok(output)
        }
        Err(error) => {
            let captured_image = fixture.capture_cli_built_image(&error);
            cleanup_failed_sandbox(&error).await?;
            captured_image?;
            fixture.cleanup()?;
            Err(error)
        }
    }
}

async fn cleanup_failed_sandbox(output: &str) -> Result<(), String> {
    let name = extract_field(output, "Created sandbox").or_else(|| extract_field(output, "Name"));
    let Some(name) = name else {
        return Ok(());
    };

    let delete = openshell_cmd()
        .arg("sandbox")
        .arg("delete")
        .arg(&name)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|err| format!("delete failed fixture sandbox {name}: {err}"))?;
    if delete.status.success() {
        return Ok(());
    }
    Err(format!(
        "delete failed fixture sandbox {name} (exit {:?}):\n{}{}",
        delete.status.code(),
        String::from_utf8_lossy(&delete.stdout),
        String::from_utf8_lossy(&delete.stderr)
    ))
}

fn assert_probe(output: &str, expected: &str) {
    let clean = strip_ansi(output);
    let record = clean
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with(PROBE_LABEL))
        .unwrap_or_else(|| panic!("identity probe record missing from output:\n{clean}"));
    assert_eq!(record, expected, "unexpected identity probe record");
}

fn image_identity_mode_enabled() -> bool {
    std::env::var("OPENSHELL_E2E_IDENTITY_SOURCE").as_deref() == Ok("image")
}

fn fixed_identity_config() -> Option<(u32, u32)> {
    if std::env::var("OPENSHELL_E2E_IDENTITY_SOURCE").as_deref() != Ok("fixed") {
        return None;
    }
    let uid = std::env::var("OPENSHELL_E2E_FIXED_UID")
        .expect("fixed mode must export OPENSHELL_E2E_FIXED_UID")
        .parse()
        .expect("fixed UID must be numeric");
    let gid = std::env::var("OPENSHELL_E2E_FIXED_GID")
        .expect("fixed mode must export OPENSHELL_E2E_FIXED_GID")
        .parse()
        .expect("fixed GID must be numeric");
    Some((uid, gid))
}

fn local_driver() -> String {
    let driver = e2e_driver().expect("OPENSHELL_E2E_DRIVER must be set by the e2e wrapper");
    assert!(
        matches!(driver.as_str(), "docker" | "podman"),
        "custom image e2e requires docker or podman, got {driver}"
    );
    driver
}

fn driver_config_mount_json(driver: &str, mount: &Value) -> String {
    let mut root = Map::new();
    root.insert(
        driver.to_string(),
        serde_json::json!({
            "mounts": [mount]
        }),
    );
    Value::Object(root).to_string()
}

fn unique_image_tag(name: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    format!(
        "openshell/e2e-image-identity-{name}:{}-{nanos}",
        std::process::id()
    )
}

fn cli_built_image(output: &str) -> Option<String> {
    const PREFIX: &str = "openshell/sandbox-from:";
    strip_ansi(output).split_whitespace().find_map(|token| {
        let start = token.find(PREFIX)?;
        let candidate = &token[start..];
        let end = candidate
            .find(|character: char| {
                !character.is_ascii_alphanumeric()
                    && !matches!(character, '/' | ':' | '.' | '_' | '-')
            })
            .unwrap_or(candidate.len());
        Some(candidate[..end].to_string())
    })
}

fn path_string(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(ToString::to_string)
        .ok_or_else(|| format!("path is not UTF-8: {}", path.display()))
}
