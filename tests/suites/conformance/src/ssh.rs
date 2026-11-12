// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A sandbox's SSH host identity, through `sandbox ssh-config` and a plain
//! `ssh` client that pins the host key.
//!
//! Ported from `e2e/rust/tests/ssh_host_identity.rs`. The check across a
//! gateway restart needs gateway control, which testkit doesn't have yet.

use std::path::Path;
use std::time::Duration;

use testkit::sdk::{ListOptions, SandboxPhase};
use testkit::{Context, ResultExt as _, Sandbox};

/// How long one `ssh` command may take.
const SSH_TIMEOUT: Duration = Duration::from_secs(30);
const SSH_OUTPUT: &str = "ssh-identity-ok";

/// A sandbox reports one SSH host key fingerprint in get and list, and that
/// key is the one `ssh` sees. The key stays the same across stop and start,
/// so a pinned `known_hosts` keeps working, and a new sandbox with the same
/// name gets a new key. The workload can't read the supervisor's
/// credentials.
///
/// Needs a named gateway, which `sandbox ssh-config` puts in its
/// `ProxyCommand`, and an `ssh` client on the test host.
#[testkit::test]
async fn ssh_host_identity_stable_across_stop_start_and_new_on_recreate(
    cx: &mut Context,
) -> testkit::Result {
    let cli = cx.cli_handle();
    testkit::ensure!(
        cli.gateway().name.is_some(),
        "this test needs a named gateway for `sandbox ssh-config`; set OPENSHELL_GATEWAY"
    );
    let sandbox = ready_sandbox(cx).await?;
    let name = sandbox.name().to_string();
    let original = fingerprint(cx, &sandbox).await?;

    let directory = tempfile::tempdir().context("create a directory for the SSH config")?;
    let config = directory.path().join("ssh_config");
    let known_hosts = directory.path().join("known_hosts");
    let rendered = cx
        .cli(["sandbox", "ssh-config", &name])
        .await?
        .success()?
        .stdout;
    let alias = rendered
        .lines()
        .find_map(|line| line.trim().strip_prefix("Host "))
        .ok_or_else(|| testkit::Error::msg(format!("no Host line in ssh-config: {rendered}")))?
        .trim()
        .to_string();
    std::fs::write(&config, &rendered).context("write the SSH config")?;

    let ssh = Ssh {
        cli: &cli,
        config: &config,
        known_hosts: &known_hosts,
        alias: &alias,
    };
    ssh.run("accept-new").await?;
    let key = tokio::process::Command::new("ssh-keygen")
        .args(["-l", "-E", "sha256", "-f"])
        .arg(&known_hosts)
        .output()
        .await
        .context("run ssh-keygen")?;
    let listed = String::from_utf8_lossy(&key.stdout);
    testkit::ensure!(
        key.status.success() && listed.split_whitespace().any(|word| word == original),
        "the host key ssh pinned is not {original}; ssh-keygen printed {:?}; stderr: {}",
        listed.trim(),
        String::from_utf8_lossy(&key.stderr).trim()
    );

    let read = sandbox
        .exec(["sh", "-c", "test ! -r /.openshell/supervisor/auth.json"])
        .await?;
    testkit::ensure!(
        read.exit_code == 0,
        "the workload can read the supervisor's auth.json"
    );

    cx.cli(["sandbox", "stop", &name]).await?.success()?;
    sandbox
        .wait_phase(SandboxPhase::Stopped, testkit::STOP_TIMEOUT)
        .await?;
    let stopped = fingerprint(cx, &sandbox).await?;
    testkit::ensure!(
        stopped == original,
        "the fingerprint changed from {original} to {stopped} on stop"
    );
    cx.cli(["sandbox", "start", &name]).await?.success()?;
    sandbox.wait_ready().await?;
    let started = fingerprint(cx, &sandbox).await?;
    testkit::ensure!(
        started == original,
        "the fingerprint changed from {original} to {started} on start"
    );
    ssh.run("yes")
        .await
        .context("ssh with the pinned host key after a restart")?;

    cx.cli(["sandbox", "delete", &name]).await?.success()?;
    // The name stays reserved until the gateway has removed the sandbox.
    cx.client()
        .wait_deleted(&name, testkit::DELETE_TIMEOUT, Some(sandbox.id()))
        .await
        .context(format!("wait for sandbox {name} to be deleted"))?;
    let replacement = ready_sandbox(cx).await?;
    let replaced = fingerprint(cx, &replacement).await?;
    testkit::ensure!(
        replaced != original,
        "a new sandbox named {name} has the deleted one's host key {original}"
    );
    Ok(())
}

async fn ready_sandbox(cx: &Context) -> testkit::Result<Sandbox> {
    cx.sandbox("hk")
        .command(["sleep", "infinity"])
        .create_ready()
        .await
}

/// The sandbox's host key fingerprint, the same in get and list.
async fn fingerprint(cx: &Context, sandbox: &Sandbox) -> testkit::Result<String> {
    let name = sandbox.name();
    let fingerprint = sandbox.get().await?.host_key_fingerprint.ok_or_else(|| {
        testkit::Error::msg(format!("sandbox {name} has no host key fingerprint"))
    })?;
    testkit::ensure!(
        fingerprint.starts_with("SHA256:"),
        "sandbox {name} has fingerprint {fingerprint:?}; expected SHA256:..."
    );
    let listed = cx
        .client()
        .list_all_sandboxes(ListOptions::default())
        .await
        .context("list sandboxes")?
        .into_iter()
        .find(|listed| listed.name == name)
        .ok_or_else(|| testkit::Error::msg(format!("sandbox {name} is not listed")))?;
    testkit::ensure!(
        listed.host_key_fingerprint.as_deref() == Some(fingerprint.as_str()),
        "sandbox {name} is listed with fingerprint {:?}; get says {fingerprint}",
        listed.host_key_fingerprint
    );
    Ok(fingerprint)
}

/// A plain `ssh` client using the config from `sandbox ssh-config` and its
/// own `known_hosts`.
struct Ssh<'a> {
    cli: &'a testkit::Cli,
    config: &'a Path,
    known_hosts: &'a Path,
    alias: &'a str,
}

impl Ssh<'_> {
    /// Run a command over SSH with `StrictHostKeyChecking` set to `strict`.
    async fn run(&self, strict: &str) -> testkit::Result {
        let mut ssh = tokio::process::Command::new("ssh");
        ssh.kill_on_drop(true)
            .arg("-F")
            .arg(self.config)
            .arg("-o")
            .arg(format!("StrictHostKeyChecking={strict}"))
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", self.known_hosts.display()))
            .args(["-o", "BatchMode=yes", self.alias, "printf", SSH_OUTPUT]);
        // The ProxyCommand runs the CLI, which must reach the same gateway.
        self.cli.apply_env(&mut ssh);
        let output = tokio::time::timeout(SSH_TIMEOUT, ssh.output())
            .await
            .map_err(|_| testkit::Error::msg(format!("ssh timed out after {SSH_TIMEOUT:?}")))?
            .context("run ssh; the test host needs an ssh client")?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        testkit::ensure!(
            output.status.success() && stdout == SSH_OUTPUT,
            "ssh to {} exited with {:?} and printed {stdout:?}; stderr: {}",
            self.alias,
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(())
    }
}
