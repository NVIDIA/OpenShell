// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Running a bundle in one tmachine environment: provision it, copy the
//! bundle in, wait for the gateway, run the tests, bring the results back,
//! and always tear it down.
//!
//! Tests find the gateway the way the CLI does, so the runner points them at
//! the one the installer registered with `OPENSHELL_GATEWAY` and at the
//! installed CLI with `OPENSHELL_BIN`. Anything else the environment provides,
//! such as Keycloak, the tests learn from the variables it publishes (see
//! [`crate::test_env`]).

use std::fmt;
use std::path::Path;
use std::process::{ExitCode, ExitStatus, Output};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use tmachine::Session;
use tmachine::config::Config;

use crate::bundle::{Bundle, PROFILE, READY_BINARY};
use crate::test_env;

const GUEST_DIR: &str = "/var/tmp/openshell-tests";
/// The nextest log's name, in the guest directory and in the results.
const NEXTEST_LOG: &str = "nextest.log";
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
/// nextest's exit code when a test failed, as opposed to nextest itself
/// failing.
const NEXTEST_TEST_FAILED: i32 = 100;
/// nextest's exit code when `--no-tests fail` found no tests to run.
const NEXTEST_NO_TESTS_RUN: i32 = 4;
/// How much of the end of the nextest log to print after a failure. nextest
/// ends its output with a summary that names the failed tests.
const LOG_TAIL_LINES: usize = 40;

/// The runner's exit code when a test failed.
const TEST_FAILED_EXIT: u8 = 1;
/// The runner's exit code when the run could not complete. clap also exits
/// with 2 on a usage error.
pub const ERROR_EXIT: u8 = 2;

/// How a run ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    Passed,
    /// At least one test failed.
    Failed,
    /// The runner or nextest could not complete the run.
    Error(String),
}

impl Status {
    pub const fn is_failure(&self) -> bool {
        !matches!(self, Self::Passed)
    }

    /// The runner's exit code: 1 when a test failed and 2 when the run could
    /// not complete, so CI can tell a test failure from a broken environment.
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::Passed => ExitCode::SUCCESS,
            Self::Failed => ExitCode::from(TEST_FAILED_EXIT),
            Self::Error(_) => ExitCode::from(ERROR_EXIT),
        }
    }

    /// The status of a nextest run that exited with `status`. nextest fails
    /// a run that finds no tests.
    fn of_nextest(status: ExitStatus, log: &Path) -> Self {
        match status.code() {
            Some(0) => Self::Passed,
            Some(NEXTEST_TEST_FAILED) => Self::Failed,
            Some(NEXTEST_NO_TESTS_RUN) => {
                Self::Error(format!("no test ran; see {}", log.display()))
            }
            _ => Self::Error(format!(
                "nextest exited with {status}; see {}",
                log.display()
            )),
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Passed => write!(f, "PASS"),
            Self::Failed => write!(f, "FAIL"),
            Self::Error(error) => write!(f, "ERROR: {error}"),
        }
    }
}

/// One run: a bundle in one tmachine environment.
pub struct Run<'a> {
    /// The tmachine environment, e.g. `ubuntu-docker-rootful`.
    pub environment: &'a str,
    /// The tmachine installer, e.g. `deb`.
    pub installer: &'a str,
    /// The gateway name the installer registers with the CLI.
    pub gateway: &'a str,
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
    if let Err(error) = collect_results(&session, run.results).await {
        eprintln!("==> {label}: collecting test results failed: {error:#}");
    }
    if status.is_failure() {
        print_log_tail(&run.results.join(NEXTEST_LOG));
        if let Err(error) = collect_diagnostics(&session, &run.results.join("diagnostics")).await {
            eprintln!("==> {label}: collecting diagnostics failed: {error:#}");
        }
    }

    if run.keep {
        eprintln!(
            "==> {label}: {status}\n==> {label}: keeping the VM. Connect with `ssh -p {} tmachine@127.0.0.1` (password `tmachine`). Press Enter to tear it down.",
            tmachine::ssh_port()
        );
        // Off the runtime thread, so Ctrl-C still reaches the signal handlers.
        let _ =
            tokio::task::spawn_blocking(|| std::io::stdin().read_line(&mut String::new())).await;
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

/// Create the results directory, and remove an earlier run's results so they
/// can't pass for this one's.
fn prepare_results(results: &Path) -> Result<()> {
    std::fs::create_dir_all(results).with_context(|| format!("create {}", results.display()))?;
    for stale in ["junit.xml", NEXTEST_LOG] {
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
    let openshell_bin = checked(
        "find the installed openshell CLI",
        session.exec(&["sh", "-c", "command -v openshell"]).await?,
    )?;
    let openshell_bin = openshell_bin.trim();
    ensure!(
        !openshell_bin.is_empty(),
        "the installer did not put openshell on the guest's PATH"
    );
    let mut env = vec![
        format!("OPENSHELL_GATEWAY={}", run.gateway),
        format!("OPENSHELL_BIN={openshell_bin}"),
    ];
    env.extend(
        test_env::read(session)
            .await
            .context("read the variables the environment publishes for tests")?,
    );

    let guest = GUEST_DIR;
    checked(
        "clear guest directory",
        session.exec(&["rm", "-rf", guest]).await?,
    )?;
    session.copy_in(run.bundle.path(), guest).await?;
    checked(
        "prepare guest directory",
        session
            .exec(&["mkdir", "-p", &format!("{guest}/extract")])
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
        "--no-tests",
        "fail",
    ]);
    if let Some(filter) = run.filter {
        nextest.extend(["-E", filter]);
    }
    // nextest writes its output to a file in the guest, so a run that times
    // out or loses SSH still leaves a log for `collect_results`.
    let log = format!("{guest}/{NEXTEST_LOG}");
    let mut command = vec!["sh", "-c", r#"exec "$@" >"$0" 2>&1"#, &log];
    command.extend(nextest);
    let output = session.exec_timeout(&command, RUN_TIMEOUT).await?;
    Ok(Status::of_nextest(
        output.status,
        &run.results.join(NEXTEST_LOG),
    ))
}

/// Copy the nextest log and the JUnit report out of the guest, whether or not
/// the run finished. Either may be missing, for example when the gateway never
/// became ready.
async fn collect_results(session: &Session, results: &Path) -> Result<()> {
    let found = session
        .exec(&[
            "find",
            GUEST_DIR,
            "-type",
            "f",
            "(",
            "-name",
            NEXTEST_LOG,
            "-o",
            "-name",
            "junit.xml",
            ")",
        ])
        .await?;
    let mut copied = Vec::new();
    for path in String::from_utf8_lossy(&found.stdout).lines() {
        let Some(name) = Path::new(path).file_name() else {
            continue;
        };
        if !copied.contains(&name) {
            session.copy_out(path, &results.join(name)).await?;
            copied.push(name);
        }
    }
    Ok(())
}

/// Print the end of the nextest log, which names the failed tests, or the
/// test that was running when the run stopped.
fn print_log_tail(log: &Path) {
    let Ok(contents) = std::fs::read(log) else {
        return;
    };
    let contents = String::from_utf8_lossy(&contents);
    let lines: Vec<_> = contents.lines().collect();
    eprintln!("==> the end of {}:", log.display());
    for line in &lines[lines.len().saturating_sub(LOG_TAIL_LINES)..] {
        eprintln!("{line}");
    }
}

/// Write the OpenShell gateway's journal to `dir/gateway.log`.
async fn collect_diagnostics(session: &Session, dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let output = session
        .exec(&[
            "sudo",
            "-n",
            "journalctl",
            "--no-pager",
            "--lines",
            "2000",
            "_SYSTEMD_UNIT=openshell-gateway.service",
            "+",
            "_SYSTEMD_USER_UNIT=openshell-gateway.service",
        ])
        .await?;
    let log = dir.join("gateway.log");
    let mut contents = output.stdout;
    contents.extend_from_slice(&output.stderr);
    std::fs::write(&log, contents).with_context(|| format!("write {}", log.display()))
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
    use std::os::unix::process::ExitStatusExt;

    use super::*;

    #[test]
    fn status_follows_the_nextest_exit_code() {
        let status = |code| Status::of_nextest(ExitStatus::from_raw(code << 8), Path::new("log"));
        assert_eq!(status(0), Status::Passed);
        assert_eq!(status(NEXTEST_TEST_FAILED), Status::Failed);
        assert_eq!(
            status(NEXTEST_NO_TESTS_RUN),
            Status::Error("no test ran; see log".to_string())
        );
        assert!(matches!(status(1), Status::Error(_)));
    }

    #[test]
    fn exit_code_separates_test_failures_from_errors() {
        assert_eq!(Status::Passed.exit_code(), ExitCode::SUCCESS);
        assert_eq!(Status::Failed.exit_code(), ExitCode::from(1));
        assert_eq!(
            Status::Error("broken".to_string()).exit_code(),
            ExitCode::from(2)
        );
    }
}
