// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCI image behavior shared by the Docker and Podman compute drivers.
//!
//! Each test builds a small image with the container engine that backs the
//! target gateway, creates a sandbox from it through the candidate CLI, and
//! checks the process identity, privileges, workspace, and image content seen
//! by both the sandbox main process and `sandbox exec`. One scenario also
//! inspects the containers the driver created, through the same engine.
//!
//! `OPENSHELL_BIN` names the candidate CLI. `OPENSHELL_TEST_CONTAINER_ENGINE`
//! is the command for the gateway's container engine and image store, such as
//! `docker`, `podman`, or `sudo -n podman`.

use std::process::Command;
use std::time::Duration;

use openshell_conformance::OpenShellRunner;

const BASE_IMAGE: &str = "nvcr.io/nvidia/base/ubuntu:24.04";
const ENGINE_ENV: &str = "OPENSHELL_TEST_CONTAINER_ENGINE";
const CREATE_TIMEOUT: Duration = Duration::from_mins(10);
const COMMAND_TIMEOUT: Duration = Duration::from_mins(2);
/// Sandbox condition reason for an image `WORKDIR` the sandbox identity
/// cannot use.
const WORKSPACE_VALIDATION_FAILED: &str = "WorkspaceValidationFailed";
/// A complete sandbox policy without a `process` section, so the sandbox
/// identity falls back to the image `USER`.
const IMAGE_IDENTITY_POLICY: &str = "version: 1

filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /lib64, /proc, /dev/urandom, /etc]
  read_write: [/tmp, /dev/null]
landlock:
  compatibility: best_effort

network_policies: {}
";

/// A named image user that owns its custom `WORKDIR`. Existing image content
/// keeps its ownership.
#[tokio::test]
async fn custom_workdir_with_named_user() {
    run(
        "oci-image/custom-workdir-named-user",
        async |runner, engine| {
            let image = engine.build_image(
                "named-workdir",
                &format!(
                    "FROM {BASE_IMAGE}
RUN groupadd -g 1235 appstaff && useradd -m -u 1234 -g appstaff app
WORKDIR /workspace/project
RUN printf root-owned > root-owned.txt && chown app:appstaff . && \
    printf custom-image-e2e-marker > /etc/oci-image-marker
USER app
"
                ),
            )?;
            let checks = format!(
                "{} test \"$(stat -c %u:%g .)\" = 1234:1235; \
             test \"$(cat /etc/oci-image-marker)\" = custom-image-e2e-marker; \
             test \"$(stat -c %u:%g /etc/oci-image-marker)\" = 0:0;",
                workspace_checks("1234:1235", "/workspace/project", true)
            );
            let sandbox = create_sandbox(runner, "nu", &image, None, &checks).await?;
            file_transfer_uses_workspace(runner, &sandbox).await
        },
    )
    .await;
}

/// A numeric image user without passwd entries can reach a custom `WORKDIR`
/// whose parent directories are private to that user. The sandbox policy omits
/// `process`, so the image `USER` is the only source of the sandbox identity.
/// The driver's containers launch the inspected image and keep the
/// supervisor separate from the workload.
#[tokio::test]
async fn custom_workdir_with_numeric_user_and_private_parents() {
    run(
        "oci-image/custom-workdir-numeric-user",
        async |runner, engine| {
            let image = engine.build_image(
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
            let policy = PolicyFile::new(IMAGE_IDENTITY_POLICY)?;
            let checks = workspace_checks("2345:2346", "/home/app/project", true);
            let sandbox =
                create_sandbox(runner, "pu", &image, Some(policy.path()?), &checks).await?;
            container_checks(engine, &sandbox, &image, "2345:2346")
        },
    )
    .await;
}

/// An image without `USER`, with no policy identity, runs as the numeric
/// default `1000:1000`. The base image has an account with UID 1000 in other
/// groups, such as `sudo`, and the default identity does not get them.
#[tokio::test]
async fn userless_image_uses_default_identity() {
    run("oci-image/userless-default", async |runner, engine| {
        let image = engine.build_image("userless", &format!("FROM {BASE_IMAGE}\n"))?;
        let policy = PolicyFile::new(IMAGE_IDENTITY_POLICY)?;
        let checks = format!(
            "{} test \"$(id -G)\" = 1000;",
            workspace_checks("1000:1000", "/sandbox", false)
        );
        let sandbox = create_sandbox(runner, "ud", &image, Some(policy.path()?), &checks).await?;
        container_checks(engine, &sandbox, &image, "1000:1000")
    })
    .await;
}

/// A policy `run_as_user` and `run_as_group` replace an image's `USER root`.
/// The image has no `WORKDIR`, so the managed `/sandbox` workspace is
/// writable by the policy identity and only identity resolution is tested.
#[tokio::test]
async fn policy_identity_overrides_root_image_user() {
    run("oci-image/policy-over-root", async |runner, engine| {
        let image = engine.build_image(
            "root-user",
            &format!(
                "FROM {BASE_IMAGE}
RUN groupadd -g 4235 appstaff && useradd -m -u 4234 -g appstaff app
USER root
"
            ),
        )?;
        let policy = PolicyFile::new(&format!(
            "{IMAGE_IDENTITY_POLICY}
process:
  run_as_user: \"4234\"
  run_as_group: \"4235\"
"
        ))?;
        let checks = format!(
            "{} test \"$(id -G)\" = 4235;",
            workspace_checks("4234:4235", "/sandbox", false)
        );
        let sandbox = create_sandbox(runner, "pr", &image, Some(policy.path()?), &checks).await?;
        container_checks(engine, &sandbox, &image, "4234:4235")
    })
    .await;
}

/// An image without a `WORKDIR` uses the managed `/sandbox` workspace, owned
/// by the image user, even when the image does not contain `/sandbox`.
#[tokio::test]
async fn default_workdir_uses_managed_workspace() {
    run("oci-image/default-workdir", async |runner, engine| {
        let image = engine.build_image(
            "default-workdir",
            &format!("FROM {BASE_IMAGE}\nUSER 2345:2346\n"),
        )?;
        let checks = workspace_checks("2345:2346", "/sandbox", false);
        create_sandbox(runner, "dw", &image, None, &checks)
            .await
            .map(drop)
    })
    .await;
}

/// OpenShell rejects a custom `WORKDIR` that the image user cannot write
/// instead of granting the user new access to it, and reports that reason
/// rather than a generic startup failure.
#[tokio::test]
async fn unwritable_custom_workdir_is_rejected() {
    run("oci-image/unwritable-workdir", async |runner, engine| {
        // First prove that this user, workspace and command can run. Only the
        // directory owner differs between the control and rejected image.
        for (suffix, owner, writable) in [("wc", "3234:3235", true), ("uw", "0:0", false)] {
            let image = engine.build_image(
                suffix,
                &format!(
                    "FROM {BASE_IMAGE}
RUN groupadd -g 3235 appstaff && useradd -m -u 3234 -g appstaff app
WORKDIR /workspace/project
RUN chown {owner} .
USER app
"
                ),
            )?;
            let name = track_sandbox(runner, suffix);
            let create = runner
                .step(format!("{suffix}/create"))
                .description(if writable {
                    "writable control runs the same command successfully"
                } else {
                    "sandbox creation fails before the command runs"
                })
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
                    "echo workspace-access-marker",
                ])
                .await
                .map_err(|error| error.to_string())?;
            if writable {
                create.require_success()?;
                if !create.stdout().contains("workspace-access-marker") {
                    return Err(
                        create.failure_diagnostic("writable control executes the command marker")
                    );
                }
                continue;
            }
            let printed =
                |text: &str| create.stdout().contains(text) || create.stderr().contains(text);
            if create.success() || printed("workspace-access-marker") {
                return Err(
                    create.failure_diagnostic("sandbox creation fails before the command runs")
                );
            }
            // Require the condition reason, so another provisioning failure
            // cannot pass as a workspace rejection.
            let sandbox = runner
                .step("uw/get")
                .description("rejected sandbox reports the workspace validation reason")
                .with_timeout(COMMAND_TIMEOUT)
                .run(&["sandbox", "get", &name, "--output", "json"])
                .await
                .map_err(|error| error.to_string())?;
            sandbox.require_success()?;
            let reasons: Vec<String> = sandbox
                .json::<serde_json::Value>()
                .map_err(|error| error.to_string())?["conditions"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|condition| condition["reason"].as_str().map(str::to_string))
                .collect();
            if !reasons
                .iter()
                .any(|reason| reason == WORKSPACE_VALIDATION_FAILED)
            {
                return Err(sandbox.failure_diagnostic(&format!(
                    "sandbox condition reason is {WORKSPACE_VALIDATION_FAILED}, got {reasons:?}"
                )));
            }
        }
        Ok(())
    })
    .await;
}

async fn run(
    scenario: &str,
    test: impl AsyncFnOnce(&mut OpenShellRunner, &mut Engine) -> Result<(), String>,
) {
    let mut runner =
        OpenShellRunner::from_env(scenario).expect("candidate openshell CLI is available");
    let mut engine = Engine::from_env();
    let result = async {
        runner.check_gateway_status().await?;
        test(&mut runner, &mut engine).await
    }
    .await;
    // Delete sandboxes before their images. Non-forced image removal must
    // report remaining users rather than deleting workloads behind the
    // gateway's back. Keep functional and sandbox failures first.
    let mut errors: Vec<_> = runner.finish(result).await.err().into_iter().collect();
    errors.extend(engine.remove_images());
    if !errors.is_empty() {
        panic!("{scenario} failed:\n{}", errors.join("\n"));
    }
}

/// Name a sandbox for this scenario and register it for cleanup. Sandbox
/// names are limited to 19 characters on some drivers.
fn track_sandbox(runner: &mut OpenShellRunner, short: &str) -> String {
    let name = format!("oi-{}-{short}", runner.id());
    runner.track_sandbox(&name);
    name
}

/// Shell checks for the identity, working directory, and `HOME` of a sandbox
/// child. The image user gains no capabilities and cannot read the sandbox's
/// control credentials. A custom workspace is the image directory itself, not
/// a mount over it, and does not also get the managed `/sandbox`. With
/// `image_file`, also check that root-owned image content is present and
/// unchanged in the workspace.
fn workspace_checks(identity: &str, workspace: &str, image_file: bool) -> String {
    let mut checks = format!(
        "test \"$(id -u):$(id -g)\" = {identity}; \
         test \"$(pwd -P)\" = {workspace}; \
         test \"$HOME\" = {workspace}; \
         awk '/^(CapEff|CapBnd):/ && $2 != \"0000000000000000\" {{ exit 1 }} \
              /^NoNewPrivs:/ && $2 != 1 {{ exit 1 }}' /proc/self/status; \
         test ! -r /.openshell/channel/sandbox/server.key; \
         test ! -r /.openshell/supervisor/runtime-descriptor.json;"
    );
    if workspace != "/sandbox" {
        checks.push_str(&format!(
            " awk -v w={workspace} '$5 == w {{ exit 1 }}' /proc/self/mountinfo; \
             test ! -e /sandbox;"
        ));
    }
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
    short: &str,
    image: &TestImage,
    policy: Option<&str>,
    checks: &str,
) -> Result<String, String> {
    let name = track_sandbox(runner, short);
    let main = format!(
        "(set -eu; {checks} touch main-write) >/tmp/oci-main.log 2>&1; \
         echo $? >/tmp/oci-main.status; exec sleep infinity"
    );
    let mut args = vec!["sandbox", "create", "--name", &name, "--from", &image.tag];
    if let Some(policy) = policy {
        args.extend(["--policy", policy]);
    }
    args.extend(["--detach", "--", "sh", "-c", &main]);
    run_ok(
        runner,
        format!("{short}/create"),
        "sandbox starts from the test image",
        CREATE_TIMEOUT,
        &args,
    )
    .await?;

    let script = format!(
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
    exec(
        runner,
        &name,
        format!("{short}/exec"),
        "main process and exec children see the image workspace",
        &script,
    )
    .await?;
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
    run_ok(
        runner,
        "named/upload",
        "upload without a destination writes to the workspace",
        COMMAND_TIMEOUT,
        &["sandbox", "upload", sandbox, upload, "--no-git-ignore"],
    )
    .await?;
    exec(
        runner,
        sandbox,
        "named/uploaded",
        "uploaded file is in the workspace",
        "test \"$(cat oci-transfer.txt)\" = oci-transfer-ok",
    )
    .await?;

    let download = local.path().join("downloaded.txt");
    let download_path = download.to_str().ok_or("download path is not UTF-8")?;
    run_ok(
        runner,
        "named/download",
        "download resolves relative paths in the workspace",
        COMMAND_TIMEOUT,
        &[
            "sandbox",
            "download",
            sandbox,
            "oci-transfer.txt",
            download_path,
        ],
    )
    .await?;
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
    exec(
        runner,
        sandbox,
        "named/merge-seed",
        "seed an existing workspace directory",
        "mkdir merge-upload && printf remote-conflict > merge-upload/conflict.txt \
         && printf remote-preserved > merge-upload/unrelated.txt",
    )
    .await?;
    run_ok(
        runner,
        "named/merge-upload",
        "directory upload merges into the existing directory",
        COMMAND_TIMEOUT,
        &["sandbox", "upload", sandbox, merge, "--no-git-ignore"],
    )
    .await?;
    exec(
        runner,
        sandbox,
        "named/merged",
        "upload overwrites conflicts and keeps unrelated files",
        "test \"$(cat merge-upload/conflict.txt)\" = local-conflict \
         && test \"$(cat merge-upload/added.txt)\" = local-added \
         && test \"$(cat merge-upload/unrelated.txt)\" = remote-preserved",
    )
    .await
}

/// Check the containers the driver created for `sandbox`. The workload runs
/// the image ID captured after the fixture build, before sandbox creation, and
/// starts directly as the sandbox `identity` without a network or the
/// supervisor's credentials. The supervisor runs in a separate non-root
/// container.
fn container_checks(
    engine: &Engine,
    sandbox: &str,
    image: &TestImage,
    identity: &str,
) -> Result<(), String> {
    let workload = engine.container_for_role(sandbox, "sandbox")?;
    let supervisor = engine.container_for_role(sandbox, "supervisor")?;
    if workload == supervisor {
        return Err(format!("{sandbox} has no separate supervisor container"));
    }
    let launched = engine.inspect_container(&workload, "{{.Image}}")?;
    let digest = |id: &str| id.trim_start_matches("sha256:").to_string();
    if digest(&launched) != digest(&image.id) {
        return Err(format!(
            "workload launched image {launched}, expected the built image {}",
            image.id
        ));
    }
    let user = engine.inspect_container(&workload, "{{.Config.User}}")?;
    if user != identity {
        return Err(format!("workload starts as {user:?}, expected {identity}"));
    }
    let network = engine.inspect_container(&workload, "{{.HostConfig.NetworkMode}}")?;
    if network != "none" {
        return Err(format!(
            "workload network mode is {network:?}, expected none"
        ));
    }
    let mounts = engine.inspect_container(
        &workload,
        "{{range .Mounts}}{{println .Destination}}{{end}}",
    )?;
    if let Some(mount) = mounts.lines().find(|mount| {
        mount.starts_with("/etc/openshell/tls") || mount.starts_with("/.openshell/supervisor")
    }) {
        return Err(format!("workload mounts supervisor credentials at {mount}"));
    }
    let supervisor_user = engine.inspect_container(&supervisor, "{{.Config.User}}")?;
    if matches!(
        supervisor_user.split(':').next(),
        None | Some("" | "0" | "root")
    ) {
        return Err(format!("supervisor runs as root ({supervisor_user:?})"));
    }
    Ok(())
}

/// Run a CLI step that must succeed.
async fn run_ok(
    runner: &OpenShellRunner,
    step: impl Into<String>,
    description: &str,
    timeout: Duration,
    args: &[&str],
) -> Result<(), String> {
    runner
        .step(step)
        .description(description)
        .with_timeout(timeout)
        .run(args)
        .await
        .map_err(|error| error.to_string())?
        .require_success()
}

/// Run a shell script in `sandbox` through `sandbox exec`.
async fn exec(
    runner: &OpenShellRunner,
    sandbox: &str,
    step: impl Into<String>,
    description: &str,
    script: &str,
) -> Result<(), String> {
    run_ok(
        runner,
        step,
        description,
        COMMAND_TIMEOUT,
        &[
            "sandbox", "exec", "--name", sandbox, "--no-tty", "--", "sh", "-c", script,
        ],
    )
    .await
}

/// A sandbox policy written to a temporary file for `sandbox create --policy`.
struct PolicyFile(tempfile::NamedTempFile);

impl PolicyFile {
    fn new(contents: &str) -> Result<Self, String> {
        let file = tempfile::NamedTempFile::new()
            .map_err(|error| format!("create policy file: {error}"))?;
        std::fs::write(file.path(), contents)
            .map_err(|error| format!("write policy file: {error}"))?;
        Ok(Self(file))
    }

    fn path(&self) -> Result<&str, String> {
        self.0
            .path()
            .to_str()
            .ok_or_else(|| "policy path is not UTF-8".to_string())
    }
}

/// A built fixture's mutable tag and image ID captured before sandbox creation.
struct TestImage {
    tag: String,
    id: String,
}

/// The gateway's container engine. Images it builds for a scenario are
/// removed by `run` after sandbox cleanup.
struct Engine {
    command: Vec<String>,
    images: Vec<String>,
}

impl Engine {
    fn from_env() -> Self {
        let command: Vec<String> = std::env::var(ENGINE_ENV)
            .unwrap_or_else(|_| panic!("{ENGINE_ENV} must name the gateway's container engine"))
            .split_whitespace()
            .map(str::to_string)
            .collect();
        assert!(!command.is_empty(), "{ENGINE_ENV} is empty");
        Self {
            command,
            images: Vec::new(),
        }
    }

    /// Build `containerfile` and capture its image ID before sandbox creation.
    fn build_image(&mut self, name: &str, containerfile: &str) -> Result<TestImage, String> {
        let context = tempfile::tempdir().map_err(|error| format!("create context: {error}"))?;
        let file = context.path().join("Containerfile");
        std::fs::write(&file, containerfile)
            .map_err(|error| format!("write Containerfile: {error}"))?;
        let tag = format!("localhost/openshell-test-oci-{name}:{}", std::process::id());
        self.output(&[
            "build",
            "--file",
            file.to_str().ok_or("Containerfile path is not UTF-8")?,
            "--tag",
            &tag,
            context.path().to_str().ok_or("context path is not UTF-8")?,
        ])?;
        // A failed build leaves no tag to remove.
        self.images.push(tag.clone());
        let id = self.output(&["image", "inspect", "--format", "{{.Id}}", &tag])?;
        Ok(TestImage { tag, id })
    }

    /// Remove every built image, returning one error per failed removal.
    fn remove_images(&self) -> Vec<String> {
        self.images
            .iter()
            .filter_map(|tag| self.output(&["image", "rm", tag]).err())
            .map(|error| format!("image cleanup failed: {error}"))
            .collect()
    }

    /// The one container with isolation `role` for `sandbox`. Docker and
    /// Podman label sandbox containers the same way.
    fn container_for_role(&self, sandbox: &str, role: &str) -> Result<String, String> {
        let ids = self.output(&[
            "ps",
            "-aq",
            "--filter",
            &format!("label=openshell.ai/sandbox-name={sandbox}"),
            "--filter",
            &format!("label=openshell.ai/isolation-role={role}"),
        ])?;
        match ids.split_whitespace().collect::<Vec<_>>().as_slice() {
            [id] => Ok((*id).to_string()),
            ids => Err(format!(
                "expected one {role} container for {sandbox}, found {ids:?}"
            )),
        }
    }

    fn inspect_container(&self, id: &str, format: &str) -> Result<String, String> {
        self.output(&["container", "inspect", "--format", format, id])
    }

    /// Run the engine and return its trimmed standard output.
    fn output(&self, args: &[&str]) -> Result<String, String> {
        let command = format!("{} {}", self.command.join(" "), args.join(" "));
        let output = Command::new(&self.command[0])
            .args(&self.command[1..])
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
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
}
