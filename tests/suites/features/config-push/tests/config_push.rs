// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The gateway pushes configuration over the supervisor session.
//!
//! Run it against a gateway with `config_delivery_mode = "push"`, such as the
//! one in the tmachine `ubuntu-docker-rootful-config-push` environment. Such
//! a gateway still lets a supervisor without push support poll, so nothing
//! else fails when push is silently off. This test fails then: the supervisor
//! of a new sandbox must report that its session receives pushed
//! configuration.

use std::time::Duration;

use testkit::{Context, Poll, Result};

/// What the supervisor logs, only when the gateway accepts its session with
/// config push enabled
/// (crates/openshell-supervisor-process/src/supervisor_session.rs).
const PUSHED_SESSION: &str = "gateway pushes configuration over the session";

/// How long the supervisor's log may take to reach the gateway after the
/// sandbox is Ready.
const LOG_TIMEOUT: Duration = Duration::from_secs(60);
const LOG_INTERVAL: Duration = Duration::from_secs(2);

/// A new sandbox's supervisor session receives configuration by push.
#[testkit::test]
async fn supervisor_session_receives_pushed_configuration(cx: &mut Context) -> Result {
    let sandbox = cx
        .sandbox("push")
        .command(["sleep", "infinity"])
        .create()
        .await?;
    sandbox.wait_ready().await?;

    let name = sandbox.name().to_string();
    testkit::poll_until(
        "the supervisor to report a pushed-configuration session",
        LOG_TIMEOUT,
        LOG_INTERVAL,
        async || {
            let logs = cx
                .cli(["logs", &name, "-n", "500", "--source", "sandbox"])
                .await?;
            // A failed read is retried; the timeout reports the last one.
            Ok(if logs.exit_code != 0 {
                Poll::Pending(format!(
                    "`openshell logs` exited with {}: {}",
                    logs.exit_code, logs.stderr
                ))
            } else if logs.stdout.contains(PUSHED_SESSION) {
                Poll::Ready(())
            } else {
                Poll::Pending(format!(
                    "no {PUSHED_SESSION:?} in the sandbox log; is the gateway configured with \
                     config_delivery_mode = \"push\"?\n{}",
                    logs.stdout
                ))
            })
        },
    )
    .await?;

    sandbox.delete().await?;
    cx.expect_absent(&sandbox).await
}
