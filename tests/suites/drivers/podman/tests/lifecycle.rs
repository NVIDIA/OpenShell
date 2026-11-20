// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Podman driver sandbox lifecycle: what the driver does with its containers
//! when a sandbox's main process stops or an ephemeral sandbox finishes.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use container_engine_support::Engine;
use testkit::sdk::SandboxPhase;
use testkit::{Context, Error, ResultExt as _};

/// Where the driver mounts the sandbox's bootstrap JWT.
const TOKEN_PATH: &str = "/etc/openshell/auth/sandbox.jwt";
/// How long the gateway may take to report a stopped workload as Error.
const ERROR_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the driver may take to remove an ephemeral sandbox's containers.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(90);

/// Stopping a sandbox's workload container is terminal: the driver doesn't
/// relaunch the main process and the sandbox ends in Error. Before the stop,
/// the workload can't read its bootstrap JWT, and the supervisor's copy is
/// unexpired.
#[testkit::test]
async fn stopped_workload_container_is_terminal(cx: &mut Context) -> testkit::Result {
    cx.expect_compute_driver("podman").await?;
    let engine = Engine::from_env()?;
    let sandbox = cx
        .sandbox("st")
        .command(["sleep", "infinity"])
        .create_ready()
        .await?;

    let workload = engine.container_for_role(sandbox.name(), "sandbox").await?;
    engine
        .output([
            "exec",
            &workload,
            "/bin/sh",
            "-c",
            &format!("test ! -r {TOKEN_PATH}"),
        ])
        .await
        .context("the sandbox workload must not be able to read its bootstrap JWT")?;

    let supervisor = engine
        .container_for_role(sandbox.name(), "supervisor")
        .await?;
    let token = engine.copy_from(&supervisor, TOKEN_PATH).await?;
    require_unexpired(&String::from_utf8_lossy(&token))?;

    engine.output(["stop", &workload]).await?;
    engine
        .wait_running(&workload, false, Duration::from_mins(1))
        .await?;
    sandbox
        .wait_phase(SandboxPhase::Error, ERROR_TIMEOUT)
        .await
        .context("a stopped main process makes the sandbox terminal")?;
    Ok(())
}

/// A detached `--no-keep` sandbox's containers are removed once its main
/// command exits, whether it succeeds or fails. Conformance checks that the
/// gateway forgets the sandbox; this checks the driver's containers.
#[testkit::test]
async fn ephemeral_sandbox_containers_are_removed_after_main_exits(
    cx: &mut Context,
) -> testkit::Result {
    cx.expect_compute_driver("podman").await?;
    let engine = Engine::from_env()?;
    let mut sandboxes = Vec::new();
    for (suffix, code) in [("ez", 0), ("ef", 17)] {
        let builder = cx.cli_sandbox(suffix);
        let release_path = format!("/sandbox/.ephemeral-release-{}", builder.name());
        let script =
            format!("while [ ! -e '{release_path}' ]; do sleep 0.1; done; sleep 1; exit {code}");
        let sandbox = builder
            .args(["--no-keep"])
            .command(["sh", "-c", &script])
            .create()
            .await?;
        sandboxes.push((sandbox, release_path, code));
    }

    for (sandbox, release_path, _) in &sandboxes {
        sandbox.wait_ready().await?;
        testkit::ensure!(
            !engine
                .containers_for_sandbox_id(sandbox.id())
                .await?
                .is_empty(),
            "no containers found for sandbox {} ({})",
            sandbox.name(),
            sandbox.id()
        );
        sandbox
            .exec(["touch", release_path.as_str()])
            .await?
            .success()?;
    }
    for (sandbox, _, code) in &sandboxes {
        testkit::poll_until(
            &format!("containers of sandbox {} to be removed", sandbox.name()),
            CLEANUP_TIMEOUT,
            Duration::from_millis(500),
            async || {
                let left = engine.containers_for_sandbox_id(sandbox.id()).await?;
                Ok(if left.is_empty() {
                    testkit::Poll::Ready(())
                } else {
                    testkit::Poll::Pending(format!("containers {left:?}"))
                })
            },
        )
        .await
        .context(format!("ephemeral sandbox exited {code}"))?;
    }
    Ok(())
}

/// Fail unless `token`'s `exp` claim is in the future. Sandbox tokens use
/// `exp = 0` when no TTL is configured.
fn require_unexpired(token: &str) -> testkit::Result {
    let payload = token
        .trim()
        .split('.')
        .nth(1)
        .ok_or_else(|| Error::msg("the sandbox JWT has no payload segment"))?;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|err| Error::msg(format!("decode the sandbox JWT payload: {err}")))?;
    let claims: serde_json::Value =
        serde_json::from_slice(&payload).context("parse the sandbox JWT claims")?;
    let exp = claims["exp"]
        .as_u64()
        .ok_or_else(|| Error::msg(format!("the sandbox JWT has no integer exp: {claims}")))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| Error::msg(format!("read the clock: {err}")))?
        .as_secs();
    testkit::ensure!(
        exp == 0 || exp > now,
        "the supervisor's bootstrap JWT expired: exp={exp}, now={now}"
    );
    Ok(())
}
