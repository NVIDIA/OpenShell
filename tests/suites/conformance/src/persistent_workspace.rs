// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Lifecycle tests for a compute driver whose workspace is persistent.
//!
//! Adapted from the `sandbox-lifecycle` suite in NVIDIA/OpenShell#4629 by Evan
//! Lezar. Docker, Podman, Kubernetes, and MicroVM keep `/sandbox` across stop
//! and start, and so must every conformant driver. The Microsoft MXC driver
//! cannot start a stopped sandbox yet, so it is not conformant until it can.

use std::time::Duration;

use testkit::{Context, ResultExt as _};

/// Files in the workspace survive stop and start, and start runs the main
/// command again.
#[testkit::test]
async fn persistent_workspace_survives_stop_start(cx: &mut Context) -> testkit::Result {
    const SENTINEL: &str = "/sandbox/.openshell-stop-start-sentinel";
    const RUN_COUNT: &str = "/sandbox/.openshell-main-run-count";
    let main = format!(
        "count=0; test ! -f '{RUN_COUNT}' || count=$(cat '{RUN_COUNT}'); \
         count=$((count + 1)); printf '%s\\n' \"$count\" > '{RUN_COUNT}'; \
         exec sleep infinity"
    );
    let sandbox = cx
        .sandbox("kw")
        .command(["sh", "-c", main.as_str()])
        .create_ready()
        .await?;

    let sentinel = format!("openshell-stop-start-{}", cx.run_id());
    sandbox
        .exec([
            "sh",
            "-c",
            &format!("printf '%s\\n' '{sentinel}' > '{SENTINEL}' && sync"),
        ])
        .await?
        .success()
        .context("write the sentinel")?;

    sandbox.stop().await?;
    sandbox.start().await?;

    sandbox
        .exec(["cat", SENTINEL])
        .await?
        .expect_stdout(&format!("{sentinel}\n"))
        .context("read the sentinel after restart")?;
    // The sandbox is Ready before the restarted main command has necessarily
    // rewritten the count, so wait for it to say it ran again.
    sandbox
        .poll_exec(
            "the main command to run again",
            Duration::from_secs(30),
            ["cat", RUN_COUNT],
            |runs| runs.stdout == "2\n",
        )
        .await?;
    Ok(())
}
