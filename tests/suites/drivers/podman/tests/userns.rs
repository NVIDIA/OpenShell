// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Podman driver user namespaces.
//!
//! The environment configures the gateway with one user-namespace mode and
//! publishes it (see the `podman-support` crate). The test compares a
//! sandbox's UID map with the one Podman itself gives a container in the same
//! mode, so it doesn't bake a particular Podman mapping into the test.

use container_engine_support::Engine;
use podman_support::{Userns, normalize_uid_map, reference_uid_map};
use testkit::{Context, Error, ResultExt as _};

const WORKSPACE_OK: &str = "podman-userns-workspace-ok";
const WORKSPACE_AND_UID_MAP_PROBE: &str = r#"set -eu
workload_owner="$(id -u):$(id -g)"
workspace_owner="$(stat -c '%u:%g' /sandbox)"
printf 'workload-owner=%s\nworkspace-owner=%s\n' "$workload_owner" "$workspace_owner"
test "$(id -u)" -ne 0
test "$workspace_owner" = "$workload_owner"
probe=$(mktemp /sandbox/userns-probe.XXXXXX)
printf 'workspace probe\n' > "$probe"
rm "$probe"
echo podman-userns-workspace-ok
cat /proc/self/uid_map
"#;

/// A sandbox gets the UID map Podman gives a container in the gateway's
/// user-namespace mode, and its non-root workload owns and can write to the
/// managed `/sandbox` workspace.
#[testkit::test]
async fn configured_userns_matches_podman_reference(cx: &mut Context) -> testkit::Result {
    cx.expect_compute_driver("podman").await?;
    let userns = Userns::from_env()?;
    let engine = Engine::from_env()?;
    let image = testkit::base_image();
    let reference = reference_uid_map(&engine, userns, &image).await?;

    let name = cx.name("pu");
    cx.track(&name);
    let run = cx
        .cli([
            "sandbox",
            "create",
            "--name",
            &name,
            "--from",
            &image,
            "--no-tty",
            "--",
            "sh",
            "-c",
            WORKSPACE_AND_UID_MAP_PROBE,
        ])
        .await?
        .success()
        .context("sandbox can write to its owned workspace and prints its UID map")?;
    testkit::ensure!(
        run.stdout.contains(WORKSPACE_OK),
        "the non-root workload does not own or cannot write to /sandbox:\n{}",
        run.stdout
    );
    let sandbox = normalize_uid_map(&run.stdout).ok_or_else(|| {
        Error::msg(format!(
            "the sandbox printed no UID mappings:\n{}",
            run.stdout
        ))
    })?;
    testkit::ensure!(
        sandbox == reference,
        "the sandbox UID map differs from Podman's {userns:?} reference:\nexpected:\n{reference}\nactual:\n{sandbox}"
    );
    Ok(())
}
