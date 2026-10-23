// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Running a bundle in one tmachine environment: provision it, copy the
//! bundle in, wait for the gateway, run the tests, bring the results back,
//! and always tear it down.
//!
//! Tests find the gateway the way the CLI does, so the runner points them at
//! the one the installer registered with `OPENSHELL_GATEWAY` and at the
//! installed CLI with `OPENSHELL_BIN`.
//!
//! Adapted from the executor in Evan Lezar's NVIDIA/OpenShell#4629.

use std::path::Path;
use std::process::Output;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use tmachine::Session;
use tmachine::config::Config;

use crate::bundle::{Bundle, PROFILE, READY_BINARY};
use crate::report::{Status, decide_status};

const GUEST_DIR: &str = "/var/tmp/openshell-tests";
/// How long the gateway has to become healthy after the environment is up.
// Matches the installers' own wait: an HA k3s gateway booted from a cached
// disk can take minutes to report healthy.
const READY_TIMEOUT_SECS: u64 = 300;
/// How long the nextest run may take in total. Individual tests are bounded
/// by the nextest profile's slow-timeout; this catches a run that stops
/// making progress some other way.
const RUN_TIMEOUT: Duration = Duration::from_mins(45);
/// Slack beyond the readiness check's own timeout for SSH and process start.
const READY_SLACK: Duration = Duration::from_mins(1);

/// One run: a bundle in one tmachine environment.
pub struct Run<'a> {
    /// The tmachine environment, e.g. `ubuntu-docker-rootful`.
    pub environment: &'a str,
    /// The tmachine installer, e.g. `deb`.
    pub installer: &'a str,
    /// The gateway name the installer registers with the CLI. Without one,
    /// tests use the CLI's active gateway.
    pub gateway: Option<&'a str>,
    pub bundle: &'a Bundle,
    /// A nextest filterset (`-E`) narrowing the tests in the bundle.
    pub filter: Option<&'a str>,
    /// Where `junit.xml`, `nextest.log` and, after a failure, the guest's
    /// `diagnostics/` go.
    pub results: &'a Path,
    /// Keep the VM running after the tests until Enter is pressed.
    pub keep: bool,
}

/// Run the tests. Every failure, including provisioning, becomes a status.
pub async fn run(config: &Config, run: &Run<'_>) -> Status {
    let label = format!("{} / {}", run.environment, run.installer);
    if let Err(error) = prepare_results(run.results) {
        return Status::Error(format!("{error:#}"));
    }
    eprintln!("==> {label}: provisioning");
    let session = match provision(config, run.environment, run.installer).await {
        Ok(session) => session,
        Err(error) => return Status::Error(format!("provision environment: {error:#}")),
    };

    eprintln!("==> {label}: running tests");
    let status = match run_tests(&session, run).await {
        Ok(status) => status,
        Err(error) => Status::Error(format!("{error:#}")),
    };
    if status.is_failure()
        && let Err(error) = session
            .collect_diagnostics(&run.results.join("diagnostics"))
            .await
    {
        eprintln!("==> {label}: collecting diagnostics failed: {error:#}");
    }

    if run.keep {
        eprintln!(
            "==> {label}: keeping the VM. Connect with `ssh -p {} tmachine@127.0.0.1` (password `tmachine`). Press Enter to tear it down.",
            tmachine::ssh_port()
        );
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
    }
    eprintln!("==> {label}: tearing down");
    session.down().await;
    status
}

/// Boot a tmachine environment by name, with OpenShell installed by the named
/// installer.
async fn provision(config: &Config, environment: &str, installer: &str) -> Result<Session> {
    let names = |names: &mut dyn Iterator<Item = &String>| {
        names.map(String::as_str).collect::<Vec<_>>().join(", ")
    };
    let environment = config
        .environments
        .iter()
        .find(|candidate| candidate.name == environment)
        .with_context(|| {
            format!(
                "tmachine environment {environment:?} is not defined; choose one of: {}",
                names(&mut config.environments.iter().map(|e| &e.name))
            )
        })?;
    let machine = config
        .machines
        .iter()
        .find(|candidate| candidate.name == environment.machine)
        .with_context(|| format!("tmachine machine {:?} is not defined", environment.machine))?;
    let installer = config
        .installers
        .iter()
        .find(|candidate| candidate.name == installer)
        .with_context(|| {
            format!(
                "tmachine installer {installer:?} is not defined; choose one of: {}",
                names(&mut config.installers.iter().map(|i| &i.name))
            )
        })?;
    Session::up(machine, environment, installer).await
}

/// The environment variables that point the tests at the system under test:
/// the registered gateway, if known, and the installed CLI.
pub fn guest_env(gateway: Option<&str>, openshell_bin: &str) -> Vec<String> {
    let mut vars = Vec::new();
    if let Some(gateway) = gateway {
        vars.push(format!("OPENSHELL_GATEWAY={gateway}"));
    }
    vars.push(format!("OPENSHELL_BIN={openshell_bin}"));
    vars
}

/// Create the results directory, and remove an earlier run's results so they
/// can't pass for this one's.
fn prepare_results(results: &Path) -> Result<()> {
    std::fs::create_dir_all(results).with_context(|| format!("create {}", results.display()))?;
    for stale in ["junit.xml", "nextest.log"] {
        let path = results.join(stale);
        if path.exists() {
            std::fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
        }
    }
    let diagnostics = results.join("diagnostics");
    if diagnostics.exists() {
        std::fs::remove_dir_all(&diagnostics)
            .with_context(|| format!("remove {}", diagnostics.display()))?;
    }
    Ok(())
}

async fn run_tests(session: &Session, run: &Run<'_>) -> Result<Status> {
    let results = run.results;

    let openshell_bin = checked(
        "find the installed openshell CLI",
        session.exec(&["sh", "-c", "command -v openshell"]).await?,
    )?;
    let openshell_bin = openshell_bin.trim();
    ensure!(
        !openshell_bin.is_empty(),
        "the installer did not put openshell on the guest's PATH"
    );
    let env = guest_env(run.gateway, openshell_bin);

    let guest = GUEST_DIR;
    checked(
        "prepare guest directory",
        session
            .exec(&[
                "sh",
                "-c",
                &format!("rm -rf {guest} && mkdir -p {guest}/extract"),
            ])
            .await?,
    )?;
    session
        .copy_in(&run.bundle.path, &format!("{guest}/bundle.tar"))
        .await?;
    checked(
        "unpack bundle",
        session
            .exec(&["tar", "-C", guest, "-xf", &format!("{guest}/bundle.tar")])
            .await?,
    )?;

    // A booted guest restarts its gateway, so wait for it once here rather
    // than in every test. Failing here is an environment error, not a test
    // failure.
    let ready_binary = format!("{guest}/{READY_BINARY}");
    let ready_timeout = READY_TIMEOUT_SECS.to_string();
    let mut ready = vec!["env"];
    ready.extend(env.iter().map(String::as_str));
    ready.extend([ready_binary.as_str(), ready_timeout.as_str()]);
    checked(
        "wait for the gateway",
        session
            .exec_timeout(
                &ready,
                Duration::from_secs(READY_TIMEOUT_SECS) + READY_SLACK,
            )
            .await?,
    )?;

    let archive = format!("{guest}/tests.tar.zst");
    let extract = format!("{guest}/extract");
    let config = format!("{guest}/nextest.toml");
    let mut nextest = vec!["env"];
    nextest.extend(env.iter().map(String::as_str));
    nextest.extend([
        "cargo-nextest",
        "nextest",
        "run",
        "--archive-file",
        &archive,
        "--workspace-remap",
        guest,
        "--extract-to",
        &extract,
        "--extract-overwrite",
        "--config-file",
        &config,
        "--profile",
        PROFILE,
        "--no-capture",
        // Tests share one gateway and the guest has 4 GiB; run them serially
        // whatever --no-capture implies.
        "--test-threads",
        "1",
    ]);
    if let Some(filter) = run.filter {
        nextest.extend(["-E", filter]);
    }
    let output = session.exec_timeout(&nextest, RUN_TIMEOUT).await?;
    let mut log = output.stdout.clone();
    log.extend_from_slice(&output.stderr);
    let log_path = results.join("nextest.log");
    std::fs::write(&log_path, &log)?;

    let junit = results.join("junit.xml");
    let found = checked(
        "find JUnit report",
        session.exec(&["find", guest, "-name", "junit.xml"]).await?,
    )?;
    let xml = match found.lines().next() {
        Some(path) => {
            session.copy_out(path, &junit).await?;
            Some(std::fs::read_to_string(&junit)?)
        }
        None => None,
    };

    Ok(decide_status(
        output.status.success(),
        xml.as_deref(),
        &log_path,
    ))
}

fn checked(step: &str, output: Output) -> Result<String> {
    ensure!(
        output.status.success(),
        "{step}: exited with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    String::from_utf8(output.stdout).with_context(|| format!("{step}: output is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn points_tests_at_the_gateway_and_the_cli() {
        assert_eq!(
            guest_env(Some("openshell"), "/usr/bin/openshell"),
            [
                "OPENSHELL_GATEWAY=openshell",
                "OPENSHELL_BIN=/usr/bin/openshell",
            ]
        );
        assert_eq!(
            guest_env(None, "/usr/bin/openshell"),
            ["OPENSHELL_BIN=/usr/bin/openshell"]
        );
    }
}
