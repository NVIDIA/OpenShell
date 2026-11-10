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

    let sandbox = cx.cli_sandbox("cs").create().await?;
    let name = sandbox.name().to_string();
    let got = sandbox.get_json().await?;
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
    cx.cli([
        "sandbox", "exec", "--name", &name, "--no-tty", "--", "echo", &marker,
    ])
    .await?
    .expect_stdout(&format!("{marker}\n"))?;

    cx.cli(["sandbox", "delete", &name]).await?.success()?;
    wait_unlisted(cx, &name).await?;
    sandbox.expect_absent().await
}

/// A sandbox created with the CLI can be stopped, rejects `sandbox exec` while
/// stopped, starts again, and can be stopped and deleted.
#[testkit::test]
async fn cli_stop_start_delete(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .cli_sandbox("cl")
        .command(["sh", "-c", "exec sleep infinity"])
        .create_ready()
        .await?;
    let name = sandbox.name().to_string();

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
    sandbox.expect_absent().await
}

/// `sandbox create -- <command>` without `--detach` streams the main
/// process's output and exits with its exit code. The sandbox is kept by
/// default: one whose main exited 0 is listed and Completed, and one whose
/// main exited 7 is in Error with exit code 7.
#[testkit::test]
async fn cli_attached_create_streams_main_and_reports_exit(cx: &mut Context) -> testkit::Result {
    let completed = cx.name("ac0");
    cx.track(&completed);
    let output = cx
        .cli([
            "sandbox", "create", "--name", &completed, "--", "echo", "OK",
        ])
        .await?
        .success()?;
    expect_streamed(&output, "OK")?;
    testkit::ensure!(
        find_listed(cx, &completed).await?.is_some(),
        "sandbox {completed} is not listed after its main exited; sandboxes are kept by default"
    );
    // The phase can trail the CLI's exit by a status update.
    cx.adopt(&completed).await?.wait_finished().await?;
    let got = get_json(cx, &completed).await?;
    testkit::ensure!(
        got["phase"] == "Completed",
        "sandbox {completed} is in phase {}; expected Completed",
        got["phase"]
    );

    let failed = cx.name("ac7");
    cx.track(&failed);
    let output = cx
        .cli([
            "sandbox",
            "create",
            "--name",
            &failed,
            "--",
            "sh",
            "-c",
            "echo failed-main; exit 7",
        ])
        .await?;
    testkit::ensure!(
        output.exit_code == 7,
        "`{}` exited with {}; expected the main process's 7; stderr: {}",
        output.command,
        output.exit_code,
        output.stderr.trim()
    );
    expect_streamed(&output, "failed-main")?;
    cx.adopt(&failed).await?.wait_finished().await?;
    let got = get_json(cx, &failed).await?;
    testkit::ensure!(
        got["phase"] == "Error" && got["exit_code"] == 7,
        "sandbox {failed} is in phase {} with exit code {}; expected Error with 7",
        got["phase"],
        got["exit_code"]
    );
    Ok(())
}

/// `sandbox create --no-keep -- <command>` streams the main process's output,
/// exits with its exit code, and then deletes the sandbox, whether the main
/// exited 0 or 17.
#[testkit::test]
async fn cli_no_keep_removes_sandbox_after_main_exit(cx: &mut Context) -> testkit::Result {
    for (suffix, code, marker) in [("nk0", 0, "OK"), ("nk17", 17, "ephemeral-failure")] {
        let name = cx.name(suffix);
        cx.track(&name);
        let script = format!("echo {marker}; exit {code}");
        let output = cx
            .cli([
                "sandbox",
                "create",
                "--name",
                &name,
                "--no-keep",
                "--",
                "sh",
                "-c",
                &script,
            ])
            .await?;
        testkit::ensure!(
            output.exit_code == code,
            "`{}` exited with {}; expected the main process's {code}; stderr: {}",
            output.command,
            output.exit_code,
            output.stderr.trim()
        );
        expect_streamed(&output, marker)?;
        wait_unlisted(cx, &name).await?;
    }
    Ok(())
}

/// Fail unless the CLI printed `marker` from the main process.
fn expect_streamed(output: &testkit::CliOutput, marker: &str) -> testkit::Result {
    testkit::ensure!(
        output.stdout.contains(marker) || output.stderr.contains(marker),
        "`{}` did not stream {marker:?} from the main process; stdout: {}; stderr: {}",
        output.command,
        output.stdout.trim(),
        output.stderr.trim()
    );
    Ok(())
}

async fn get_json(cx: &Context, name: &str) -> testkit::Result<Value> {
    cx.cli(["sandbox", "get", name, "--output", "json"])
        .await?
        .success()?
        .json()
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
