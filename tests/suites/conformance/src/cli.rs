// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox lifecycle through the `openshell` CLI.
//!
//! Ported from the `smoke` and `sandbox-lifecycle` scenarios of the old
//! `conformance/cli` suite. The other lifecycle tests act through the SDK; these
//! check that the CLI commands for create, get, list, exec, stop, start, and
//! delete work against the same gateway.

use serde_json::Value;
use testkit::Context;

const PAGE_SIZE: &str = "1000";
/// More pages than any test gateway should have; stops a repeated token from
/// looping forever.
const MAX_PAGES: usize = 1000;

/// `openshell status` succeeds, and a sandbox created with the CLI is
/// retrievable and Ready, appears in `sandbox list`, runs `sandbox exec`, and is
/// gone from `sandbox list` after `sandbox delete`.
#[testkit::test]
async fn cli_create_exec_list_delete(cx: &mut Context) -> testkit::Result {
    cx.cli(["status"]).await?.success()?;

    let name = cx.name("cs");
    cx.track(&name);
    cx.cli(["sandbox", "create", "--name", &name, "--detach"])
        .await?
        .success()?;

    let sandbox = cx.adopt(&name).await?;
    let got: Value = cx
        .cli(["sandbox", "get", &name, "--output", "json"])
        .await?
        .success()?
        .json()?;
    testkit::ensure!(
        got["name"] == name.as_str(),
        "sandbox get returned {:?}; expected {name:?}",
        got["name"]
    );
    testkit::ensure!(
        got["phase"] == "Ready",
        "sandbox {name} is in phase {}; expected Ready",
        got["phase"]
    );

    let listed = find_listed(cx, &name).await?;
    testkit::ensure!(listed.is_some(), "sandbox {name} is not in sandbox list");

    let marker = format!("openshell-e2e-{}", cx.run_id());
    let exec = cx
        .cli([
            "sandbox", "exec", "--name", &name, "--no-tty", "--", "echo", &marker,
        ])
        .await?
        .success()?;
    testkit::ensure!(
        exec.stdout == format!("{marker}\n"),
        "sandbox exec stdout was {:?}; expected {:?}",
        exec.stdout,
        format!("{marker}\n")
    );

    cx.cli(["sandbox", "delete", &name]).await?.success()?;
    wait_unlisted(cx, &name).await?;
    cx.expect_absent(&sandbox).await
}

/// A sandbox created with the CLI can be stopped, rejects `sandbox exec` while
/// stopped, starts again, and can be stopped and deleted.
#[testkit::test]
async fn cli_stop_start_delete(cx: &mut Context) -> testkit::Result {
    let name = cx.name("cl");
    cx.track(&name);
    cx.cli([
        "sandbox",
        "create",
        "--name",
        &name,
        "--detach",
        "--no-tty",
        "--",
        "sh",
        "-c",
        "exec sleep infinity",
    ])
    .await?
    .success()?;
    let sandbox = cx.adopt(&name).await?;
    sandbox.wait_ready().await?;

    cx.cli(["sandbox", "stop", &name]).await?.success()?;
    sandbox
        .wait_phase(testkit::sdk::SandboxPhase::Stopped, testkit::STOP_TIMEOUT)
        .await?;
    cx.cli(["sandbox", "exec", "--name", &name, "--no-tty", "--", "true"])
        .await?
        .failure()?;

    cx.cli(["sandbox", "start", &name]).await?.success()?;
    sandbox.wait_ready().await?;
    cx.cli(["sandbox", "stop", &name]).await?.success()?;
    sandbox
        .wait_phase(testkit::sdk::SandboxPhase::Stopped, testkit::STOP_TIMEOUT)
        .await?;

    cx.cli(["sandbox", "delete", &name]).await?.success()?;
    wait_unlisted(cx, &name).await?;
    cx.expect_absent(&sandbox).await
}

/// Wait until `sandbox list` no longer shows the sandbox.
async fn wait_unlisted(cx: &Context, name: &str) -> testkit::Result {
    testkit::poll_until(
        &format!("sandbox {name} to leave sandbox list"),
        testkit::DELETE_TIMEOUT,
        std::time::Duration::from_secs(1),
        async || {
            Ok(match find_listed(cx, name).await? {
                None => testkit::Poll::Ready(()),
                Some(phase) => testkit::Poll::Pending(format!("still listed in phase {phase}")),
            })
        },
    )
    .await
}

/// The phase of the sandbox in `sandbox list`, if it is listed. Follows every
/// page.
async fn find_listed(cx: &Context, name: &str) -> testkit::Result<Option<String>> {
    let mut token = String::new();
    for _ in 0..MAX_PAGES {
        let page: Value = cx
            .cli([
                "sandbox",
                "list",
                "--page-size",
                PAGE_SIZE,
                "--page-token",
                &token,
                "--output",
                "json",
            ])
            .await?
            .success()?
            .json()?;
        if let Some(entry) = page["sandboxes"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|entry| entry["name"] == name)
        {
            return Ok(Some(
                entry["phase"].as_str().unwrap_or_default().to_string(),
            ));
        }
        token = page["next_page_token"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        if token.is_empty() {
            return Ok(None);
        }
    }
    Err(testkit::Error::msg(format!(
        "sandbox list has more than {MAX_PAGES} pages"
    )))
}
