// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCI image behavior shared by the Docker and Podman compute drivers.
//!
//! Each test builds a small image on `testkit::base_image()` with the
//! gateway's container engine (see the `container-engine-support` crate), creates a
//! sandbox from it through the CLI, and checks the process identity,
//! privileges, workspace, and image content seen by both the sandbox main
//! process and `sandbox exec`. Some tests also inspect the containers the
//! driver created, through the same engine.

use container_engine_support::{Engine, Image};
use serde_json::Value;
use testkit::{Context, Error, Result, ResultExt as _};

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

/// A named image user owns its custom `WORKDIR`, existing image content keeps
/// its ownership, and upload and download resolve paths in that workspace.
#[testkit::test]
async fn custom_workdir_with_named_user(cx: &mut Context) -> testkit::Result {
    run(cx, async |oci| {
        let image = oci
            .build_image(
                "named-workdir",
                &format!(
                    "FROM {}
RUN groupadd -g 1235 appstaff && useradd -m -u 1234 -g appstaff app
WORKDIR /workspace/project
RUN printf root-owned > root-owned.txt && chown app:appstaff . && \
    printf custom-image-e2e-marker > /etc/oci-image-marker
USER app
",
                    oci.base_image
                ),
            )
            .await?;
        let checks = format!(
            "{} test \"$(stat -c %u:%g .)\" = 1234:1235; \
             test \"$(cat /etc/oci-image-marker)\" = custom-image-e2e-marker; \
             test \"$(stat -c %u:%g /etc/oci-image-marker)\" = 0:0;",
            workspace_checks("1234:1235", "/workspace/project", true)
        );
        let sandbox = oci.create_sandbox("nu", &image, None, &checks).await?;
        oci.file_transfer_uses_workspace(&sandbox).await
    })
    .await
}

/// A numeric image user without passwd entries can reach a custom `WORKDIR`
/// whose parent directories are private to that user. The sandbox policy omits
/// `process`, so the image `USER` is the only source of the sandbox identity.
/// The driver's containers launch the inspected image and keep the
/// supervisor separate from the workload.
#[testkit::test]
async fn custom_workdir_with_numeric_user_and_private_parents(cx: &mut Context) -> testkit::Result {
    run(cx, async |oci| {
        let image = oci
            .build_image(
                "numeric-workdir",
                &format!(
                    "FROM {}
RUN mkdir -p /home/app/project && \\
    chown 2345:2346 /home/app /home/app/project && \\
    chmod 0700 /home/app /home/app/project
WORKDIR /home/app/project
RUN printf root-owned > root-owned.txt
USER 2345:2346
",
                    oci.base_image
                ),
            )
            .await?;
        let policy = PolicyFile::new(IMAGE_IDENTITY_POLICY)?;
        let checks = workspace_checks("2345:2346", "/home/app/project", true);
        let sandbox = oci
            .create_sandbox("pu", &image, Some(policy.path()?), &checks)
            .await?;
        oci.container_checks(&sandbox, &image, "2345:2346").await
    })
    .await
}

/// An image without `USER`, with no policy identity, runs as the numeric
/// default `1000:1000`. The base image has an account with UID 1000 in other
/// groups, such as `sudo`, and the default identity does not get them.
#[testkit::test]
async fn userless_image_uses_default_identity(cx: &mut Context) -> testkit::Result {
    run(cx, async |oci| {
        let image = oci
            .build_image("userless", &format!("FROM {}\n", oci.base_image))
            .await?;
        let policy = PolicyFile::new(IMAGE_IDENTITY_POLICY)?;
        let checks = format!(
            "{} test \"$(id -G)\" = 1000;",
            workspace_checks("1000:1000", "/sandbox", false)
        );
        let sandbox = oci
            .create_sandbox("ud", &image, Some(policy.path()?), &checks)
            .await?;
        oci.container_checks(&sandbox, &image, "1000:1000").await
    })
    .await
}

/// A policy `run_as_user` and `run_as_group` replace an image's `USER root`.
/// The image has no `WORKDIR`, so the managed `/sandbox` workspace is
/// writable by the policy identity and only identity resolution is tested.
#[testkit::test]
async fn policy_identity_overrides_root_image_user(cx: &mut Context) -> testkit::Result {
    run(cx, async |oci| {
        let image = oci
            .build_image(
                "root-user",
                &format!(
                    "FROM {}
RUN groupadd -g 4235 appstaff && useradd -m -u 4234 -g appstaff app
USER root
",
                    oci.base_image
                ),
            )
            .await?;
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
        let sandbox = oci
            .create_sandbox("pr", &image, Some(policy.path()?), &checks)
            .await?;
        oci.container_checks(&sandbox, &image, "4234:4235").await
    })
    .await
}

/// An image without a `WORKDIR` uses the managed `/sandbox` workspace, owned
/// by the image user, even when the image does not contain `/sandbox`.
#[testkit::test]
async fn default_workdir_uses_managed_workspace(cx: &mut Context) -> testkit::Result {
    run(cx, async |oci| {
        let image = oci
            .build_image(
                "default-workdir",
                &format!("FROM {}\nUSER 2345:2346\n", oci.base_image),
            )
            .await?;
        let checks = workspace_checks("2345:2346", "/sandbox", false);
        oci.create_sandbox("dw", &image, None, &checks)
            .await
            .map(drop)
    })
    .await
}

/// OpenShell rejects a custom `WORKDIR` that the image user cannot write
/// instead of granting the user new access to it, and reports that reason
/// rather than a generic startup failure.
#[testkit::test]
async fn unwritable_custom_workdir_is_rejected(cx: &mut Context) -> testkit::Result {
    run(cx, async |oci| {
        // First prove that this user, workspace and command can run. Only the
        // directory owner differs between the control and rejected image.
        for (suffix, owner, writable) in [("wc", "3234:3235", true), ("uw", "0:0", false)] {
            let image = oci
                .build_image(
                    suffix,
                    &format!(
                        "FROM {}
RUN groupadd -g 3235 appstaff && useradd -m -u 3234 -g appstaff app
WORKDIR /workspace/project
RUN chown {owner} .
USER app
",
                        oci.base_image
                    ),
                )
                .await?;
            let name = oci.track(suffix);
            let create = oci
                .cx
                .cli([
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
                .await?;
            if writable {
                let create = create
                    .success()
                    .context("writable control runs the same command successfully")?;
                testkit::ensure!(
                    create.stdout.contains("workspace-access-marker"),
                    "writable control did not print the command marker:\n{}",
                    create.stdout
                );
                continue;
            }
            let printed = create.stdout.contains("workspace-access-marker")
                || create.stderr.contains("workspace-access-marker");
            testkit::ensure!(
                create.exit_code != 0 && !printed,
                "sandbox creation did not fail before the command ran: `{}` exited with {}:\n{}{}",
                create.command,
                create.exit_code,
                create.stdout,
                create.stderr
            );
            // Require the condition reason, so another provisioning failure
            // cannot pass as a workspace rejection.
            let sandbox: Value = oci
                .cx
                .cli(["sandbox", "get", &name, "--output", "json"])
                .await?
                .success()?
                .json()?;
            let reasons: Vec<&str> = sandbox["conditions"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|condition| condition["reason"].as_str())
                .collect();
            testkit::ensure!(
                reasons.contains(&WORKSPACE_VALIDATION_FAILED),
                "rejected sandbox condition reasons are {reasons:?}; expected {WORKSPACE_VALIDATION_FAILED}"
            );
        }
        Ok(())
    })
    .await
}

/// What a test uses: the context and the gateway's container engine.
struct Oci<'a> {
    cx: &'a Context,
    engine: Engine,
    base_image: String,
}

/// Run `test` with the gateway's container engine.
async fn run(cx: &Context, test: impl AsyncFnOnce(&Oci<'_>) -> Result) -> Result {
    let oci = Oci {
        cx,
        engine: Engine::from_env()?,
        base_image: testkit::base_image(),
    };
    test(&oci).await
}

impl Oci<'_> {
    /// Build `containerfile` with a tag unique to this run, and remove the
    /// image when the test ends. Cleanup runs last registered first, so the
    /// sandboxes created from the image are deleted before it is removed.
    async fn build_image(&self, name: &str, containerfile: &str) -> Result<Image> {
        let tag = format!("localhost/openshell-test-oci-{name}:{}", self.cx.run_id());
        self.engine.build_image(&tag, containerfile).await?;
        let (engine, built) = (self.engine.clone(), tag.clone());
        self.cx
            .on_cleanup(format!("remove image {tag}"), async move || {
                engine.remove_image(&built).await
            });
        self.engine.image(&tag).await
    }

    /// Name a sandbox for this test and register it for cleanup. Sandbox
    /// names are limited to 19 characters on some drivers, so keep `short`
    /// to a few characters.
    fn track(&self, short: &str) -> String {
        let name = self.cx.name(short);
        self.cx.track(&name);
        name
    }

    /// Create a detached sandbox whose main process runs `checks` and writes
    /// to the workspace, then run the same checks and a write through
    /// `sandbox exec`.
    async fn create_sandbox(
        &self,
        short: &str,
        image: &Image,
        policy: Option<&str>,
        checks: &str,
    ) -> Result<String> {
        let name = self.track(short);
        let main = format!(
            "(set -eu; {checks} touch main-write) >/tmp/oci-main.log 2>&1; \
             echo $? >/tmp/oci-main.status; exec sleep infinity"
        );
        let mut args = vec!["sandbox", "create", "--name", &name, "--from", &image.tag];
        if let Some(policy) = policy {
            args.extend(["--policy", policy]);
        }
        args.extend(["--detach", "--", "sh", "-c", &main]);
        self.cx
            .cli(args)
            .await?
            .success()
            .context("sandbox starts from the test image")?;

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
        self.exec(&name, &script)
            .await
            .context("main process and exec children see the image workspace")?;
        Ok(name)
    }

    /// Upload and download default to paths relative to the image workspace.
    async fn file_transfer_uses_workspace(&self, sandbox: &str) -> Result {
        let local = tempfile::tempdir()
            .map_err(|error| Error::from_error(&error))
            .context("create temp dir")?;
        let upload = local.path().join("oci-transfer.txt");
        write(&upload, "oci-transfer-ok")?;
        self.cx
            .cli([
                "sandbox",
                "upload",
                sandbox,
                utf8(&upload)?,
                "--no-git-ignore",
            ])
            .await?
            .success()
            .context("upload without a destination writes to the workspace")?;
        self.exec(
            sandbox,
            "test \"$(cat oci-transfer.txt)\" = oci-transfer-ok",
        )
        .await
        .context("uploaded file is in the workspace")?;

        let download = local.path().join("downloaded.txt");
        self.cx
            .cli([
                "sandbox",
                "download",
                sandbox,
                "oci-transfer.txt",
                utf8(&download)?,
            ])
            .await?
            .success()
            .context("download resolves relative paths in the workspace")?;
        let downloaded = std::fs::read_to_string(&download)
            .map_err(|error| Error::from_error(&error))
            .context("read download")?;
        testkit::ensure!(
            downloaded == "oci-transfer-ok",
            "downloaded file has unexpected content: {downloaded:?}"
        );

        // A directory upload merges into an existing workspace directory.
        let merge = local.path().join("merge-upload");
        std::fs::create_dir(&merge)
            .map_err(|error| Error::from_error(&error))
            .context("create merge dir")?;
        write(&merge.join("conflict.txt"), "local-conflict")?;
        write(&merge.join("added.txt"), "local-added")?;
        self.exec(
            sandbox,
            "mkdir merge-upload && printf remote-conflict > merge-upload/conflict.txt \
             && printf remote-preserved > merge-upload/unrelated.txt",
        )
        .await
        .context("seed an existing workspace directory")?;
        self.cx
            .cli([
                "sandbox",
                "upload",
                sandbox,
                utf8(&merge)?,
                "--no-git-ignore",
            ])
            .await?
            .success()
            .context("directory upload merges into the existing directory")?;
        self.exec(
            sandbox,
            "test \"$(cat merge-upload/conflict.txt)\" = local-conflict \
             && test \"$(cat merge-upload/added.txt)\" = local-added \
             && test \"$(cat merge-upload/unrelated.txt)\" = remote-preserved",
        )
        .await
        .context("upload overwrites conflicts and keeps unrelated files")
    }

    /// Check the containers the driver created for `sandbox`. The workload
    /// runs the image ID captured after the fixture build, before sandbox
    /// creation, and starts directly as the sandbox `identity` without a
    /// network or the supervisor's credentials. The supervisor runs in a
    /// separate non-root container.
    async fn container_checks(&self, sandbox: &str, image: &Image, identity: &str) -> Result {
        let engine = &self.engine;
        let workload = engine.container_for_role(sandbox, "sandbox").await?;
        let supervisor = engine.container_for_role(sandbox, "supervisor").await?;
        testkit::ensure!(
            workload != supervisor,
            "{sandbox} has no separate supervisor container"
        );
        let launched = engine.inspect_container(&workload, "{{.Image}}").await?;
        let digest = |id: &str| id.trim_start_matches("sha256:").to_string();
        testkit::ensure!(
            digest(&launched) == digest(&image.id),
            "workload launched image {launched}, expected the built image {}",
            image.id
        );
        let user = engine
            .inspect_container(&workload, "{{.Config.User}}")
            .await?;
        testkit::ensure!(
            user == identity,
            "workload starts as {user:?}, expected {identity}"
        );
        let network = engine
            .inspect_container(&workload, "{{.HostConfig.NetworkMode}}")
            .await?;
        testkit::ensure!(
            network == "none",
            "workload network mode is {network:?}, expected none"
        );
        let mounts = engine
            .inspect_container(
                &workload,
                "{{range .Mounts}}{{println .Destination}}{{end}}",
            )
            .await?;
        if let Some(mount) = mounts.lines().find(|mount| {
            mount.starts_with("/etc/openshell/tls") || mount.starts_with("/.openshell/supervisor")
        }) {
            return Err(Error::msg(format!(
                "workload mounts supervisor credentials at {mount}"
            )));
        }
        let supervisor_user = engine
            .inspect_container(&supervisor, "{{.Config.User}}")
            .await?;
        testkit::ensure!(
            !matches!(
                supervisor_user.split(':').next(),
                None | Some("" | "0" | "root")
            ),
            "supervisor runs as root ({supervisor_user:?})"
        );
        Ok(())
    }

    /// Run a shell script in `sandbox` through `sandbox exec`.
    async fn exec(&self, sandbox: &str, script: &str) -> Result {
        self.cx
            .cli([
                "sandbox", "exec", "--name", sandbox, "--no-tty", "--", "sh", "-c", script,
            ])
            .await?
            .success()
            .map(drop)
    }
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

/// A sandbox policy written to a temporary file for `sandbox create --policy`.
struct PolicyFile(tempfile::NamedTempFile);

impl PolicyFile {
    fn new(contents: &str) -> Result<Self> {
        let file = tempfile::NamedTempFile::new()
            .map_err(|error| Error::from_error(&error))
            .context("create policy file")?;
        write(file.path(), contents)?;
        Ok(Self(file))
    }

    fn path(&self) -> Result<&str> {
        utf8(self.0.path())
    }
}

fn write(path: &std::path::Path, contents: &str) -> Result {
    std::fs::write(path, contents)
        .map_err(|error| Error::from_error(&error))
        .context(format!("write {}", path.display()))
}

fn utf8(path: &std::path::Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| Error::msg(format!("{} is not UTF-8", path.display())))
}
