// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Settings suite: sandbox-scoped settings and the gateway-global settings
//! that override them.
//!
//! The global test changes a setting for the whole gateway. That is safe
//! because the runner runs one test at a time; a family that runs tests
//! concurrently needs to give it a test group of its own.

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
    // A global value would hide the sandbox's own, so clear it for the test.
    restore_global_setting_on_cleanup(cx, KEY).await?;
    delete_global_setting(&cx.cli_handle(), KEY).await?;
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

/// A global setting overrides the sandbox's value and blocks sandbox writes
/// and deletes for that key. Once the global setting is deleted, the sandbox
/// controls the key again.
#[testkit::test]
async fn global_setting_overrides_sandbox_scope(cx: &mut Context) -> testkit::Result {
    let cli = cx.cli_handle();
    restore_global_setting_on_cleanup(cx, KEY).await?;
    delete_global_setting(&cli, KEY).await?;

    let sandbox = cx
        .sandbox("sg")
        .command(["sleep", "infinity"])
        .create_ready()
        .await?;
    set_sandbox_setting(cx, &sandbox, "true").await?.success()?;
    expect_sandbox_setting(cx, &sandbox, "true", "sandbox").await?;

    set_global_setting(&cli, KEY, "false").await?;
    testkit::ensure!(
        read_global_setting(&cli, KEY).await? == "false",
        "the global {KEY} does not read back as false"
    );
    expect_sandbox_setting(cx, &sandbox, "false", "global").await?;

    let blocked = set_sandbox_setting(cx, &sandbox, "true").await?.failure()?;
    testkit::ensure!(
        blocked.report_text().contains("managed globally"),
        "setting a globally managed key on the sandbox failed without saying the key is managed globally: {}",
        blocked.report_text()
    );
    cx.cli(["settings", "delete", sandbox.name(), "--key", KEY])
        .await?
        .failure()?;

    delete_global_setting(&cli, KEY).await?;
    let global = read_global_setting(&cli, KEY).await?;
    testkit::ensure!(
        global == UNSET,
        "the global {KEY} is {global:?} after delete; expected {UNSET:?}"
    );

    set_sandbox_setting(cx, &sandbox, "false")
        .await?
        .success()?;
    expect_sandbox_setting(cx, &sandbox, "false", "sandbox").await
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
async fn read_global_setting(cli: &testkit::Cli, key: &str) -> testkit::Result<String> {
    let settings: Value = cli
        .run(["settings", "get", "--global", "--json"])
        .await?
        .success()?
        .json()?;
    Ok(settings["settings"][key]
        .as_str()
        .unwrap_or(UNSET)
        .to_string())
}

async fn set_global_setting(cli: &testkit::Cli, key: &str, value: &str) -> testkit::Result {
    cli.run([
        "settings", "set", "--global", "--key", key, "--value", value, "--yes",
    ])
    .await?
    .success()?;
    Ok(())
}

async fn delete_global_setting(cli: &testkit::Cli, key: &str) -> testkit::Result {
    cli.run(["settings", "delete", "--global", "--key", key, "--yes"])
        .await?
        .success()?;
    Ok(())
}

/// Record the gateway-global value of `key` and put it back after the test:
/// set it again if it had one, delete it otherwise.
async fn restore_global_setting_on_cleanup(cx: &Context, key: &'static str) -> testkit::Result {
    let cli = cx.cli_handle();
    let prior = read_global_setting(&cli, key).await?;
    testkit::ensure!(
        !prior.starts_with("<bytes:"),
        "the global {key} holds bytes ({prior}), which this test can't restore"
    );
    cx.on_cleanup(format!("restore global setting {key}"), async move || {
        let restored = read_global_setting(&cli, key).await?;
        if restored == prior {
            return Ok(());
        }
        if prior == UNSET {
            delete_global_setting(&cli, key).await
        } else {
            set_global_setting(&cli, key, &prior).await
        }
    });
    Ok(())
}
