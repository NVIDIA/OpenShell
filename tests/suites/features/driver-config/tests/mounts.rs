// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Docker and Podman sandboxes mount the engine volumes and host directories a
//! caller names in `--driver-config-json`.
//!
//! The gateway must allow caller driver config and bind mounts, and resource
//! admission must be off, because bind mounts can't carry approval labels. The
//! tmachine `<base>-driver-config` environments configure that. The tests
//! still label their volumes for the sandbox's workspace, so the volume tests
//! also pass with admission on.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use container_engine_support::Engine;
use testkit::{Context, Error, Result, ResultExt as _};

const VOLUME_TARGET: &str = "/sandbox/e2e-volume";
const OCI_VOLUME_TARGET: &str = "/workspace/project/e2e-volume";
const BIND_TARGET: &str = "/sandbox/e2e-bind";

/// An image whose `USER` has no passwd entry and owns its `WORKDIR`, so the
/// driver prepares a workspace with a volume nested inside it.
const OCI_USER_CONTAINERFILE: &str = "WORKDIR /workspace/project
RUN chown 2234:2235 .
USER 2234:2235
CMD [\"sleep\", \"infinity\"]
";

/// The bind test checks the driver's mount wiring, not Landlock over host
/// bind mounts, so the sandbox user may write the mount and `/tmp`. It runs
/// as the `sandbox` user, which the Python image has.
const BIND_POLICY: &str = "version: 1

filesystem_policy:
  include_workdir: false
  read_only: [/bin, /dev, /etc, /lib, /proc, /usr]
  read_write: [/sandbox/e2e-bind, /tmp]

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox
";

/// A sandbox's main command reads a file seeded in an existing volume and
/// writes one the host then reads.
#[testkit::test]
async fn sandbox_mounts_existing_driver_config_volume(cx: &mut Context) -> testkit::Result {
    let driver = container_driver(cx).await?;
    let engine = Engine::from_env()?;
    let volume = create_seeded_volume(cx, &engine, "dcv").await?;

    let builder = cx.cli_sandbox("dcv");
    let name = builder.name().to_string();
    let output = builder
        .args([
            "--driver-config-json",
            &mount_config(&driver, "volume", &volume, VOLUME_TARGET).to_string(),
        ])
        .command([
            "sh",
            "-lc",
            &format!(
                "set -eu; test \"$(cat {VOLUME_TARGET}/input.txt)\" = host-volume-ok; \
                 printf sandbox-volume-ok > {VOLUME_TARGET}/output.txt; \
                 cat {VOLUME_TARGET}/output.txt"
            ),
        ])
        .run()
        .await?
        .success()
        .context("sandbox reads and writes the mounted volume")?;
    testkit::ensure!(
        output.stdout.contains("sandbox-volume-ok"),
        "the sandbox did not print its write to the volume:\n{}",
        output.stdout
    );

    cx.adopt(&name).await?.delete().await?;
    run_on_volume(
        &engine,
        &volume,
        "test \"$(cat /vol/input.txt)\" = host-volume-ok; \
         test \"$(cat /vol/output.txt)\" = sandbox-volume-ok",
    )
    .await
    .context("the volume keeps the sandbox's write")
}

/// A volume mounted inside the workspace of an image with a numeric `USER`
/// keeps its ownership: the driver prepares the workspace for that user
/// without changing the ownership of the nested mount. The main process and
/// `sandbox exec` children both run as the image user in the workspace.
#[testkit::test]
async fn oci_workspace_preparation_skips_nested_volume_ownership(
    cx: &mut Context,
) -> testkit::Result {
    let driver = container_driver(cx).await?;
    let engine = Engine::from_env()?;
    let volume = create_seeded_volume(cx, &engine, "dco").await?;
    let image = engine
        .build_test_image(
            cx,
            "driver-config-oci-user",
            &format!("FROM {}\n{OCI_USER_CONTAINERFILE}", testkit::base_image()),
        )
        .await?;

    let checks = format!(
        "test \"$(id -u):$(id -g)\" = 2234:2235; \
         test \"$(pwd -P)\" = /workspace/project; test \"$HOME\" = /workspace/project; \
         test \"$(stat -c %u:%g {OCI_VOLUME_TARGET}/input.txt)\" = 0:0;"
    );
    let main = format!(
        "(set -eu; {checks} touch direct-write) >/tmp/dc-main.log 2>&1; \
         echo $? >/tmp/dc-main.status; exec sleep infinity"
    );
    let sandbox = cx
        .cli_sandbox("dco")
        .image(&image.tag)
        .args([
            "--driver-config-json",
            &mount_config(&driver, "volume", &volume, OCI_VOLUME_TARGET).to_string(),
        ])
        .command(["sh", "-c", &main])
        .create()
        .await
        .context("sandbox starts from the OCI-user image with a nested volume")?;

    let script = format!(
        "set -eu; i=0; \
         while [ ! -f /tmp/dc-main.status ]; do \
           i=$((i + 1)); [ \"$i\" -le 60 ] || {{ echo main process checks did not finish >&2; exit 1; }}; \
           sleep 1; \
         done; \
         if [ \"$(cat /tmp/dc-main.status)\" != 0 ]; then \
           echo main process checks failed: >&2; cat /tmp/dc-main.log >&2; exit 1; \
         fi; \
         test -f direct-write; {checks} touch exec-write"
    );
    sandbox.wait_ready().await?;
    sandbox
        .exec(["sh", "-c", &script])
        .await?
        .success()
        .context("main process and exec children keep the nested volume's ownership")?;

    sandbox.delete().await?;
    run_on_volume(
        &engine,
        &volume,
        "test \"$(stat -c %u:%g /vol/input.txt)\" = 0:0",
    )
    .await
    .context("the nested volume's ownership is unchanged")
}

/// With bind mounts enabled, a sandbox's main command reads a file in a host
/// directory and writes one the host then reads.
#[testkit::test]
async fn sandbox_mounts_enabled_driver_config_bind(cx: &mut Context) -> testkit::Result {
    let driver = container_driver(cx).await?;
    // Under the home directory, which the gateway's engine can reach: the
    // test user runs a rootless gateway, and a rootful engine reads any path.
    let home = std::env::var_os("HOME").ok_or_else(|| Error::msg("HOME is not set"))?;
    let host_dir = tempfile::Builder::new()
        .prefix("openshell-test-driver-config-bind-")
        .tempdir_in(home)
        .context("create the bind mount directory")?;
    set_mode(host_dir.path(), 0o777)?;
    let input = host_dir.path().join("input.txt");
    std::fs::write(&input, "host-bind-ok").context("seed the bind mount directory")?;
    set_mode(&input, 0o666)?;

    let source = host_dir
        .path()
        .to_str()
        .ok_or_else(|| Error::msg("the bind mount directory is not UTF-8"))?;
    let mut config = mount_config(&driver, "bind", source, BIND_TARGET);
    config[&driver]["mounts"][0]["selinux_label"] = "private".into();

    let builder = cx.cli_sandbox("dcb");
    let name = builder.name().to_string();
    let output = builder
        .image(testkit::python_image())
        .policy_yaml(BIND_POLICY)
        .args(["--driver-config-json", &config.to_string()])
        .command([
            "sh",
            "-lc",
            &format!(
                "set -eu; test \"$(cat {BIND_TARGET}/input.txt)\" = host-bind-ok; \
                 printf sandbox-bind-ok > {BIND_TARGET}/output.txt; \
                 cat {BIND_TARGET}/output.txt"
            ),
        ])
        .run()
        .await?
        .success()
        .context("sandbox reads and writes the bind mount")?;
    testkit::ensure!(
        output.stdout.contains("sandbox-bind-ok"),
        "the sandbox did not print its write to the bind mount:\n{}",
        output.stdout
    );

    cx.adopt(&name).await?.delete().await?;
    let written = std::fs::read_to_string(host_dir.path().join("output.txt"))
        .context("read the sandbox's write from the bind mount directory")?;
    testkit::ensure!(
        written == "sandbox-bind-ok",
        "the bind mount directory has output {written:?}; expected sandbox-bind-ok"
    );
    Ok(())
}

/// The gateway's compute driver, which must be Docker or Podman.
async fn container_driver(cx: &Context) -> Result<String> {
    let driver = cx.compute_driver().await?;
    testkit::ensure!(
        matches!(driver.as_str(), "docker" | "podman"),
        "this suite needs a Docker or Podman gateway; the gateway uses {driver}"
    );
    Ok(driver)
}

/// A driver config with one writable mount of `kind` from `source` at
/// `target`.
fn mount_config(driver: &str, kind: &str, source: &str, target: &str) -> serde_json::Value {
    serde_json::json!({
        driver: {
            "mounts": [{
                "type": kind,
                "source": source,
                "target": target,
                "read_only": false,
            }]
        }
    })
}

/// Create a volume the sandbox's workspace may attach, with a world-writable
/// root and `input.txt` owned by root.
async fn create_seeded_volume(cx: &Context, engine: &Engine, name: &str) -> Result<String> {
    let workspace = cx.cli_handle().gateway().workspace.clone();
    let volume = engine
        .create_test_volume(
            cx,
            name,
            &[
                ("openshell.ai/sandbox-attachable", "true"),
                ("openshell.ai/sandbox-attachable-workspace", &workspace),
            ],
        )
        .await?;
    run_on_volume(
        engine,
        &volume,
        "chmod 0777 /vol; printf host-volume-ok > /vol/input.txt",
    )
    .await
    .context(format!("seed volume {volume}"))?;
    Ok(volume)
}

/// Run `script` as root in a container from the base image, with `volume` at
/// `/vol`.
async fn run_on_volume(engine: &Engine, volume: &str, script: &str) -> Result {
    engine
        .output([
            "run",
            "--rm",
            "--user",
            "0:0",
            "--volume",
            &format!("{volume}:/vol"),
            "--entrypoint",
            "sh",
            &testkit::base_image(),
            "-c",
            &format!("set -eu; {script}"),
        ])
        .await
        .map(drop)
}

fn set_mode(path: &Path, mode: u32) -> Result {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .context(format!("set mode {mode:o} on {}", path.display()))
}
