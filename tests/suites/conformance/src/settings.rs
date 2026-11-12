// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Settings suite: sandbox-scoped settings.
//!
//! The gateway-global override test stays in `e2e/rust/tests/settings_management.rs`
//! until the runner can give it a test group of its own: it changes a setting
//! for the whole gateway, so nothing else may run beside it. Conformance tests
//! only read gateway-global settings.

use std::time::Duration;

use serde_json::Value;
use testkit::{Context, Poll, Sandbox, poll_until};

/// A registered boolean setting that does not change what these tests do.
const KEY: &str = "ocsf_json_enabled";
/// How the CLI shows a setting with no value.
const UNSET: &str = "<unset>";

/// With no global value, a sandbox setting starts unset, reads back after it
/// is set, and is unset again after it is deleted.
#[testkit::test]
async fn sandbox_setting_round_trip(cx: &mut Context) -> testkit::Result {
    // A global value would hide the sandbox's own.
    let global = read_global_setting(cx, KEY).await?;
    testkit::ensure!(
        global == UNSET,
        "the gateway sets {KEY} globally ({global}), which hides sandbox values; delete it with `openshell settings delete --global --key {KEY}`"
    );
    let sandbox = cx
        .sandbox("sr")
        .command(["sleep", "infinity"])
        .create_ready()
        .await?;
    expect_sandbox_setting(cx, &sandbox, UNSET, "unset").await?;

    set_sandbox_setting(cx, &sandbox, "true").await?.success()?;
    expect_sandbox_setting(cx, &sandbox, "true", "sandbox").await?;

    cx.cli(["settings", "delete", sandbox.name(), "--key", KEY])
        .await?
        .success()?;
    expect_sandbox_setting(cx, &sandbox, UNSET, "unset").await
}

async fn set_sandbox_setting(
    cx: &Context,
    sandbox: &Sandbox,
    value: &str,
) -> testkit::Result<testkit::CliOutput> {
    cx.cli([
        "settings",
        "set",
        sandbox.name(),
        "--key",
        KEY,
        "--value",
        value,
    ])
    .await
}

/// Wait until `settings get` for the sandbox shows [`KEY`] with `value` from
/// `scope`.
async fn expect_sandbox_setting(
    cx: &Context,
    sandbox: &Sandbox,
    value: &str,
    scope: &str,
) -> testkit::Result {
    poll_until(
        &format!(
            "{KEY} on sandbox {} to be {value} ({scope})",
            sandbox.name()
        ),
        Duration::from_secs(10),
        Duration::from_secs(1),
        async || {
            let settings: Value = cx
                .cli(["settings", "get", sandbox.name(), "--json"])
                .await?
                .success()?
                .json()?;
            let setting = &settings["settings"][KEY];
            Ok(if setting["value"] == value && setting["scope"] == scope {
                Poll::Ready(())
            } else {
                Poll::Pending(format!("{KEY} is {setting}"))
            })
        },
    )
    .await
}

/// The gateway-global value of `key` as the CLI shows it, [`UNSET`] if none.
async fn read_global_setting(cx: &Context, key: &str) -> testkit::Result<String> {
    let settings: Value = cx
        .cli(["settings", "get", "--global", "--json"])
        .await?
        .success()?
        .json()?;
    Ok(settings["settings"][key]
        .as_str()
        .unwrap_or(UNSET)
        .to_string())
}
