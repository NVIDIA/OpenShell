// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox process suite: limits the sandbox applies to its processes.

use testkit::Context;

/// Sandbox processes can't write core dumps: both the soft and the hard core
/// file size limits are 0, so a process can't raise its own limit either.
#[testkit::test]
async fn core_dumps_are_disabled(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .sandbox("cd")
        .command(["sleep", "infinity"])
        .create()
        .await?;
    sandbox.wait_ready().await?;

    let output = sandbox
        .exec([
            "sh",
            "-c",
            "printf '%s %s' \"$(ulimit -c)\" \"$(ulimit -Hc)\"",
        ])
        .await?
        .success()?;
    testkit::ensure!(
        output.stdout == "0 0",
        "core file size limits (soft hard) are {:?}; expected \"0 0\"",
        output.stdout
    );
    Ok(())
}
