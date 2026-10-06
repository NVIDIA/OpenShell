// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCI image behavior shared by the Docker and Podman compute drivers.
//!
//! Each test builds a small image with the container engine that backs the
//! target gateway, creates a sandbox from it through the candidate CLI, and
//! checks the process identity, workspace, and image content seen by both the
//! sandbox main process and `sandbox exec`.
//!
//! `OPENSHELL_BIN` names the candidate CLI. `OPENSHELL_TEST_CONTAINER_ENGINE`
//! is the command that builds images into the gateway's image store, such as
//! `docker`, `podman`, or `sudo -n podman`.

use std::process::Command;
use std::time::Duration;

use openshell_conformance::OpenShellRunner;

const BASE_IMAGE: &str = "nvcr.io/nvidia/base/ubuntu:24.04";
const ENGINE_ENV: &str = "OPENSHELL_TEST_CONTAINER_ENGINE";
const CREATE_TIMEOUT: Duration = Duration::from_mins(10);
const COMMAND_TIMEOUT: Duration = Duration::from_mins(2);
/// A complete sandbox policy without a `process` section, so the sandbox
/// identity falls back to the image `USER`.
const IMAGE_IDENTITY_POLICY: &str = "version: 1

filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /lib64, /proc, /dev/urandom, /etc]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort

network_policies: {}
";

/// A named image user that owns its custom `WORKDIR`. Existing image content
/// keeps its ownership.
#[tokio::test]
async fn custom_workdir_with_named_user() {
    run("oci-image/custom-workdir-named-user", async |runner| {
        let image = TestImage::build(
            "named-workdir",
            &format!(
                "FROM {BASE_IMAGE}
RUN groupadd -g 1235 appstaff && useradd -m -u 1234 -g appstaff app
WORKDIR /workspace/project
RUN printf root-owned > root-owned.txt && chown app:appstaff .
USER app
"
            ),
        )?;
        let checks = format!(
            "{} test \"$(stat -c %u:%g .)\" = 1234:1235;",
            workspace_checks("1234:1235", "/workspace/project", true)
        );
        let sandbox = create_sandbox(runner, "named", "nu", &image, None, &checks).await?;
        file_transfer_uses_workspace(runner, &sandbox).await
    })
    .await;
}

/// A numeric image user without passwd entries can reach a custom `WORKDIR`
/// whose parent directories are private to that user. The sandbox policy omits
/// `process`, so the image `USER` is the only source of the sandbox identity.
#[tokio::test]
async fn custom_workdir_with_numeric_user_and_private_parents() {
    run("oci-image/custom-workdir-numeric-user", async |runner| {
        let image = TestImage::build(
            "numeric-workdir",
            &format!(
                "FROM {BASE_IMAGE}
RUN mkdir -p /home/app/project && \\
    chown 2345:2346 /home/app /home/app/project && \\
    chmod 0700 /home/app /home/app/project
WORKDIR /home/app/project
RUN printf root-owned > root-owned.txt
USER 2345:2346
"
            ),
        )?;
        let policy_file = tempfile::NamedTempFile::new()
            .map_err(|error| format!("create policy file: {error}"))?;
        std::fs::write(policy_file.path(), IMAGE_IDENTITY_POLICY)
            .map_err(|error| format!("write policy file: {error}"))?;
        let policy = policy_file
            .path()
            .to_str()
            .ok_or("policy path is not UTF-8")?;
        let checks = workspace_checks("2345:2346", "/home/app/project", true);
        create_sandbox(runner, "numeric", "pu", &image, Some(policy), &checks)
            .await
            .map(drop)
    })
    .await;
}

/// An image without a `WORKDIR` uses the managed `/sandbox` workspace, owned
/// by the image user, even when the image does not contain `/sandbox`.
#[tokio::test]
async fn default_workdir_uses_managed_workspace() {
    run("oci-image/default-workdir", async |runner| {
        let image = TestImage::build(
            "default-workdir",
            &format!("FROM {BASE_IMAGE}\nUSER 2345:2346\n"),
        )?;
        let checks = workspace_checks("2345:2346", "/sandbox", false);
        create_sandbox(runner, "default", "dw", &image, None, &checks)
            .await
            .map(drop)
    })
    .await;
}

/// OpenShell rejects a custom `WORKDIR` that the image user cannot write
/// instead of granting the user new access to it. Drivers may surface the
/// rejection through different startup diagnostics rather than one condition
/// reason.
#[tokio::test]
async fn unwritable_custom_workdir_is_rejected() {
    run("oci-image/unwritable-workdir", async |runner| {
        let image = TestImage::build(
            "unwritable-workdir",
            &format!(
                "FROM {BASE_IMAGE}
RUN groupadd -g 3235 appstaff && useradd -m -u 3234 -g appstaff app
WORKDIR /workspace/project
USER app
"
            ),
        )?;
        let name = format!("oi-{}-uw", runner.id());
        runner.track_sandbox(&name);
        let create = runner
            .step("unwritable/create")
            .description("sandbox creation fails before the command runs")
            .with_timeout(CREATE_TIMEOUT)
            .run(&[
                "sandbox",
                "create",
                "--name",
                &name,
                "--from",
                &image.tag,
                "--no-tty",
                "--",
                "sh",
                "-c",
                "echo should-not-run",
            ])
            .await
            .map_err(|error| error.to_string())?;
        if create.success() || create.stdout().contains("should-not-run") {
            return Err(create.failure_diagnostic("sandbox creation fails before the command runs"));
        }
        let diagnostic = format!("{}\n{}", create.stdout(), create.stderr());
        if !has_workspace_rejection_diagnostic(&diagnostic) {
            return Err(create.failure_diagnostic(
                "sandbox creation reports a workspace, permission, or workload startup rejection",
            ));
        }
        Ok(())
    })
    .await;
}

fn has_workspace_rejection_diagnostic(diagnostic: &str) -> bool {
    let diagnostic = diagnostic.to_ascii_lowercase();
    // The CLI may wrap the human message across lines with diagnostic gutters.
    // Match the existing startup reason and exit detail independently.
    if diagnostic.contains("containerexited") && diagnostic.contains("exited with code") {
        return true;
    }
    [
        "workspace",
        "workingdir",
        "permission denied",
        // Some drivers expose the rejected workload launch through SSH rather
        // than propagating the runtime's workspace validation text.
        "subsystem request failed",
    ]
    .iter()
    .any(|message| diagnostic.contains(message))
}

#[test]
fn workspace_rejection_diagnostics_do_not_require_one_condition_reason() {
    for diagnostic in [
        "image workspace validation failed",
        "WorkingDir /workspace/project is not writable",
        "Permission denied (os error 13)",
        "ContainerExited: Container exited with code 1",
        "Error: × sandbox entered error phase while provisioning: ContainerExited: Container\n  │ exited with code 1",
        "subsystem request failed",
    ] {
        assert!(has_workspace_rejection_diagnostic(diagnostic));
    }
    for diagnostic in [
        "",
        "gateway connection refused",
        "image pull failed",
        "ContainerExited",
    ] {
        assert!(!has_workspace_rejection_diagnostic(diagnostic));
    }
}

async fn run(scenario: &str, test: impl AsyncFnOnce(&mut OpenShellRunner) -> Result<(), String>) {
    let mut runner =
        OpenShellRunner::from_env(scenario).expect("candidate openshell CLI is available");
    let result = async {
        runner.check_gateway_status().await?;
        test(&mut runner).await
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("{scenario} failed:\n{error}");
    }
}

/// Shell checks for the identity, working directory, and `HOME` of a sandbox
/// child. With `image_file`, also check that root-owned image content is
/// present and unchanged in the workspace.
fn workspace_checks(identity: &str, workspace: &str, image_file: bool) -> String {
    let mut checks = format!(
        "test \"$(id -u):$(id -g)\" = {identity}; \
         test \"$(pwd -P)\" = {workspace}; \
         test \"$HOME\" = {workspace};"
    );
    if image_file {
        checks.push_str(
            " test \"$(cat root-owned.txt)\" = root-owned; \
             test \"$(stat -c %u:%g root-owned.txt)\" = 0:0;",
        );
    }
    checks
}

/// Create a detached sandbox whose main process runs `checks` and writes to
/// the workspace, then run the same checks and a write through `sandbox exec`.
async fn create_sandbox(
    runner: &mut OpenShellRunner,
    suffix: &str,
    short: &str,
    image: &TestImage,
    policy: Option<&str>,
    checks: &str,
) -> Result<String, String> {
    // Sandbox names are limited to 19 characters on some drivers.
    let name = format!("oi-{}-{short}", runner.id());
    runner.track_sandbox(&name);
    let main = format!(
        "(set -eu; {checks} touch main-write) >/tmp/oci-main.log 2>&1; \
         echo $? >/tmp/oci-main.status; exec sleep infinity"
    );
    let mut args = vec!["sandbox", "create", "--name", &name, "--from", &image.tag];
    if let Some(policy) = policy {
        args.extend(["--policy", policy]);
    }
    args.extend(["--detach", "--", "sh", "-c", &main]);
    runner
        .step(format!("{suffix}/create"))
        .description("sandbox starts from the test image")
        .with_timeout(CREATE_TIMEOUT)
        .run(&args)
        .await
        .map_err(|error| error.to_string())?
        .require_success()?;

    let exec = format!(
        "set -eu; i=0; \
         while [ ! -f /tmp/oci-main.status ]; do \
           i=$((i + 1)); [ \"$i\" -le 60 ] || {{ echo main process checks did not finish >&2; exit 1; }}; \
           sleep 1; \
         done; \
         if [ \"$(cat /tmp/oci-main.status)\" != 0 ]; then \
           echo main process checks failed: >&2; cat /tmp/oci-main.log >&2; exit 1; \
         fi; \
         test -f main-write; {checks} touch exec-write"
    );
    runner
        .step(format!("{suffix}/exec"))
        .description("main process and exec children see the image workspace")
        .with_timeout(COMMAND_TIMEOUT)
        .run(&[
            "sandbox", "exec", "--name", &name, "--no-tty", "--", "sh", "-c", &exec,
        ])
        .await
        .map_err(|error| error.to_string())?
        .require_success()?;
    Ok(name)
}

/// Upload and download default to paths relative to the image workspace.
async fn file_transfer_uses_workspace(
    runner: &OpenShellRunner,
    sandbox: &str,
) -> Result<(), String> {
    let local = tempfile::tempdir().map_err(|error| format!("create temp dir: {error}"))?;
    let upload = local.path().join("oci-transfer.txt");
    std::fs::write(&upload, "oci-transfer-ok").map_err(|error| format!("write upload: {error}"))?;
    let upload = upload.to_str().ok_or("upload path is not UTF-8")?;
    runner
        .step("named/upload")
        .description("upload without a destination writes to the workspace")
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["sandbox", "upload", sandbox, upload, "--no-git-ignore"])
        .await
        .map_err(|error| error.to_string())?
        .require_success()?;
    runner
        .step("named/uploaded")
        .description("uploaded file is in the workspace")
        .with_timeout(COMMAND_TIMEOUT)
        .run(&[
            "sandbox",
            "exec",
            "--name",
            sandbox,
            "--no-tty",
            "--",
            "sh",
            "-c",
            "test \"$(cat oci-transfer.txt)\" = oci-transfer-ok",
        ])
        .await
        .map_err(|error| error.to_string())?
        .require_success()?;

    let download = local.path().join("downloaded.txt");
    let download_path = download.to_str().ok_or("download path is not UTF-8")?;
    runner
        .step("named/download")
        .description("download resolves relative paths in the workspace")
        .with_timeout(COMMAND_TIMEOUT)
        .run(&[
            "sandbox",
            "download",
            sandbox,
            "oci-transfer.txt",
            download_path,
        ])
        .await
        .map_err(|error| error.to_string())?
        .require_success()?;
    let downloaded =
        std::fs::read_to_string(&download).map_err(|error| format!("read download: {error}"))?;
    if downloaded != "oci-transfer-ok" {
        return Err(format!(
            "downloaded file has unexpected content: {downloaded:?}"
        ));
    }

    // A directory upload merges into an existing workspace directory.
    let merge = local.path().join("merge-upload");
    std::fs::create_dir(&merge).map_err(|error| format!("create merge dir: {error}"))?;
    std::fs::write(merge.join("conflict.txt"), "local-conflict")
        .and_then(|()| std::fs::write(merge.join("added.txt"), "local-added"))
        .map_err(|error| format!("write merge files: {error}"))?;
    let merge = merge.to_str().ok_or("merge path is not UTF-8")?;
    let seed = "mkdir merge-upload && printf remote-conflict > merge-upload/conflict.txt \
                && printf remote-preserved > merge-upload/unrelated.txt";
    let verify = "test \"$(cat merge-upload/conflict.txt)\" = local-conflict \
                  && test \"$(cat merge-upload/added.txt)\" = local-added \
                  && test \"$(cat merge-upload/unrelated.txt)\" = remote-preserved";
    for (step, description, args) in [
        (
            "named/merge-seed",
            "seed an existing workspace directory",
            [
                "sandbox", "exec", "--name", sandbox, "--no-tty", "--", "sh", "-c", seed,
            ]
            .as_slice(),
        ),
        (
            "named/merge-upload",
            "directory upload merges into the existing directory",
            ["sandbox", "upload", sandbox, merge, "--no-git-ignore"].as_slice(),
        ),
        (
            "named/merged",
            "upload overwrites conflicts and keeps unrelated files",
            [
                "sandbox", "exec", "--name", sandbox, "--no-tty", "--", "sh", "-c", verify,
            ]
            .as_slice(),
        ),
    ] {
        runner
            .step(step)
            .description(description)
            .with_timeout(COMMAND_TIMEOUT)
            .run(args)
            .await
            .map_err(|error| error.to_string())?
            .require_success()?;
    }
    Ok(())
}

/// An image built into the gateway's image store and removed on drop.
struct TestImage {
    engine: Vec<String>,
    tag: String,
}

impl TestImage {
    fn build(name: &str, containerfile: &str) -> Result<Self, String> {
        let engine: Vec<String> = std::env::var(ENGINE_ENV)
            .map_err(|_| format!("{ENGINE_ENV} must name the gateway's container engine"))?
            .split_whitespace()
            .map(str::to_string)
            .collect();
        if engine.is_empty() {
            return Err(format!("{ENGINE_ENV} is empty"));
        }
        let context = tempfile::tempdir().map_err(|error| format!("create context: {error}"))?;
        let file = context.path().join("Containerfile");
        std::fs::write(&file, containerfile)
            .map_err(|error| format!("write Containerfile: {error}"))?;
        let image = Self {
            engine,
            tag: format!("localhost/openshell-test-oci-{name}:{}", std::process::id()),
        };
        image.engine_command(&[
            "build",
            "--file",
            file.to_str().ok_or("Containerfile path is not UTF-8")?,
            "--tag",
            &image.tag,
            context.path().to_str().ok_or("context path is not UTF-8")?,
        ])?;
        Ok(image)
    }

    fn engine_command(&self, args: &[&str]) -> Result<(), String> {
        let command = format!("{} {}", self.engine.join(" "), args.join(" "));
        let output = Command::new(&self.engine[0])
            .args(&self.engine[1..])
            .args(args)
            .output()
            .map_err(|error| format!("failed to run {command}: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "{command} failed ({}):\n{}{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(())
    }
}

impl Drop for TestImage {
    fn drop(&mut self) {
        let _ = self.engine_command(&["image", "rm", "--force", &self.tag]);
    }
}
