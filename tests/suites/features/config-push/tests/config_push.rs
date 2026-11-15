// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The gateway pushes configuration over the supervisor session.
//!
//! An environment that configures the gateway with
//! `config_delivery_mode = "push"` publishes
//! `OPENSHELL_TEST_CONFIG_DELIVERY_MODE=push` (the tmachine
//! `ubuntu-docker-rootful-config-push` environment does). A gateway in push
//! mode still lets a supervisor without push support poll, so nothing else
//! fails when push is silently off. This test fails then: the supervisor of
//! a new sandbox must report that its session receives pushed configuration.

use std::time::Duration;

use testkit::{Context, Error, Poll, Result};

/// The variable the environment publishes with the gateway's delivery mode.
const MODE_ENV: &str = "OPENSHELL_TEST_CONFIG_DELIVERY_MODE";

/// What the supervisor logs once the gateway accepts its session with config
/// push enabled
/// (crates/openshell-supervisor-process/src/supervisor_session.rs).
const PUSHED_SESSION: &str = "gateway pushes configuration over the session";

/// How long the supervisor's log may take to reach the gateway after the
/// sandbox is Ready.
const LOG_TIMEOUT: Duration = Duration::from_secs(60);
const LOG_INTERVAL: Duration = Duration::from_secs(2);

/// A new sandbox's supervisor session receives configuration by push.
#[testkit::test]
async fn supervisor_session_receives_pushed_configuration(cx: &mut Context) -> Result {
    let mode = std::env::var(MODE_ENV).map_err(|_| {
        Error::msg(format!(
            "{MODE_ENV} is not set; run this suite in an environment whose gateway pushes \
             configuration, such as ubuntu-docker-rootful-config-push"
        ))
    })?;
    testkit::ensure!(
        mode == "push",
        "{MODE_ENV} is {mode:?}; this suite needs a gateway with config_delivery_mode = \"push\""
    );

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
                .await?
                .success()?;
            Ok(if logs.stdout.contains(PUSHED_SESSION) {
                Poll::Ready(())
            } else {
                Poll::Pending(format!(
                    "no {PUSHED_SESSION:?} in the sandbox log; is the gateway polling?\n{}",
                    logs.stdout
                ))
            })
        },
    )
    .await?;

    sandbox.delete().await?;
    cx.expect_absent(&sandbox).await
}
