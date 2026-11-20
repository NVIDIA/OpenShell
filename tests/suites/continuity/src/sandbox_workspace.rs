// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A sandbox and its workspace survive a disruption.

use std::time::Duration;

use testkit::{Context, ResultExt as _};

use crate::scenario::{id, name};

const MARKER: &str = "/sandbox/.continuity-marker";
const READY_TIMEOUT: Duration = Duration::from_secs(120);

/// Creates a sandbox, waits until it runs commands, and writes the run id to a
/// file in its workspace.
#[testkit::test]
async fn seed(cx: &mut Context) -> testkit::Result {
    let (sandbox, id) = (name("ws")?, id()?);
    // Created through the CLI, which testkit doesn't track, so it outlives
    // this test.
    cx.cli([
        "sandbox", "create", "--name", &sandbox, "--detach", "--", "sleep", "infinity",
    ])
    .await?
    .success()
    .context("create the sandbox")?;

    let write = format!("printf '%s\\n' '{id}' > '{MARKER}' && sync");
    let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
    loop {
        let out = cx
            .cli([
                "sandbox", "exec", "--name", &sandbox, "--no-tty", "--", "sh", "-c", &write,
            ])
            .await?;
        if out.success().is_ok() {
            return Ok(());
        }
        testkit::ensure!(
            tokio::time::Instant::now() < deadline,
            "sandbox {sandbox} did not run a command within {READY_TIMEOUT:?}"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// The sandbox is still listed and ready, its file is intact, and a sandbox
/// created after the disruption runs commands.
#[testkit::test]
async fn verify(cx: &mut Context) -> testkit::Result {
    let (sandbox, id) = (name("ws")?, id()?);
    // Adopting tracks the sandbox, so cleanup deletes it after this test.
    let existing = cx
        .adopt(&sandbox)
        .await
        .context("find the seeded sandbox")?;
    existing.wait_ready().await?;
    existing
        .exec(["cat", MARKER])
        .await?
        .expect_stdout(&format!("{id}\n"))
        .context("read the marker after the disruption")?;

    let fresh = cx.sandbox("after").create_ready().await?;
    fresh
        .exec(["true"])
        .await?
        .success()
        .context("run a command in a new sandbox")?;
    Ok(())
}
