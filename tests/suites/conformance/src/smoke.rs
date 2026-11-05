// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox smoke suite: create a sandbox, run a command in it, and delete it.

use testkit::Context;

/// A sandbox becomes ready, runs a command with exec, and is gone from get and
/// list after delete.
#[testkit::test]
async fn create_exec_delete(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .sandbox("smoke")
        .command(["sleep", "infinity"])
        .create()
        .await?;
    sandbox.wait_ready().await?;

    let marker = format!("openshell-e2e-{}", cx.run_id());
    let output = sandbox.exec(["echo", marker.as_str()]).await?;
    testkit::ensure!(
        output.exit_code == 0,
        "exec exited with {}; stderr: {}",
        output.exit_code,
        output.stderr
    );
    testkit::ensure!(
        output.stdout == format!("{marker}\n"),
        "exec stdout was {:?}; expected {:?}",
        output.stdout,
        format!("{marker}\n")
    );

    sandbox.delete().await?;
    cx.expect_absent(&sandbox).await
}
