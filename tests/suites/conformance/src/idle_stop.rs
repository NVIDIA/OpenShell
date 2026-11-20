// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Idle stop suite: the gateway stops a sandbox whose terminal program
//! reports over OSC 7501 that it is waiting on the user.

use std::time::Duration;

use serde_json::Value;
use testkit::sdk::SandboxPhase;
use testkit::sdk::raw::proto;
use testkit::{Context, Poll, Sandbox, poll_until};

const KEY: &str = "idle_stop_after_seconds";

/// Probe for support as Claude Code does, report that the turn is done, and
/// wait at the prompt. Echo is on, so the supervisor's reply is echoed back.
const AGENT: &str = r"printf '\033]7501;?\033\\'; sleep 1; printf '\033]7501;state=done:app=e2e-agent\033\\'; exec sleep infinity";

/// The supervisor reports within a second; allow for session setup.
const REPORT_DEADLINE: Duration = Duration::from_secs(30);
/// The gateway sweeps for idle sandboxes every 30 seconds.
const IDLE_STOP_DEADLINE: Duration = Duration::from_secs(90);

/// A sandbox whose program reports `done` is stopped with reason
/// `IdleStopped` once its idle timeout passes, and a start brings back a
/// program that reports again.
#[testkit::test]
async fn reported_waiting_program_is_stopped_and_restarts(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .sandbox("idle")
        .command(["sh", "-c", AGENT])
        .spec(|spec| spec.tty = true)
        .create_ready()
        .await?;
    expect_program_status(&sandbox, "Done").await?;

    set_idle_timeout(&sandbox, 1).await?;
    sandbox
        .wait_phase(SandboxPhase::Stopped, IDLE_STOP_DEADLINE)
        .await?;
    let stopped = sandbox.get_json().await?;
    let reason = ready_reason(&stopped);
    testkit::ensure!(
        reason == "IdleStopped",
        "sandbox {} stopped with reason {reason:?}; expected IdleStopped",
        sandbox.name()
    );

    // Disable the timeout so the restarted sandbox stays up while it is read.
    set_idle_timeout(&sandbox, 0).await?;
    sandbox.start().await?;
    expect_program_status(&sandbox, "Done").await
}

/// Set the sandbox's idle timeout and check the effective value, which a
/// global setting would override.
async fn set_idle_timeout(sandbox: &Sandbox, seconds: i64) -> testkit::Result {
    sandbox
        .set_setting(KEY, proto::setting_value::Value::IntValue(seconds))
        .await?;
    let config = sandbox.config().await?;
    let value = config
        .settings
        .get(KEY)
        .and_then(|setting| setting.value.as_ref())
        .and_then(|value| value.value.clone());
    testkit::ensure!(
        value == Some(proto::setting_value::Value::IntValue(seconds)),
        "effective {KEY} is {value:?}; delete the global value with `openshell settings delete --global --key {KEY}`"
    );
    Ok(())
}

/// Wait until the sandbox's `ProgramStatus` condition has `reason`.
async fn expect_program_status(sandbox: &Sandbox, reason: &str) -> testkit::Result {
    poll_until(
        &format!(
            "sandbox {} to report program status {reason}",
            sandbox.name()
        ),
        REPORT_DEADLINE,
        Duration::from_secs(1),
        async || {
            let got = sandbox.get_json().await?;
            let program = condition(&got, "ProgramStatus");
            Ok(match program {
                Some(program) if program["reason"] == reason => Poll::Ready(()),
                Some(program) => Poll::Pending(format!("ProgramStatus is {program}")),
                None => Poll::Pending("no ProgramStatus condition".to_string()),
            })
        },
    )
    .await
}

fn condition<'a>(sandbox: &'a Value, kind: &str) -> Option<&'a Value> {
    sandbox["conditions"]
        .as_array()?
        .iter()
        .find(|condition| condition["type"] == kind)
}

fn ready_reason(sandbox: &Value) -> String {
    condition(sandbox, "Ready")
        .and_then(|ready| ready["reason"].as_str())
        .unwrap_or_default()
        .to_string()
}
