// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Running a job: provision the environment, run each family's bundle in it,
//! and bring the results back.
//!
//! Tests find the gateway the way the CLI does, so the runner points them at
//! the one the installer registered with `OPENSHELL_GATEWAY` and at the
//! installed CLI with `OPENSHELL_BIN`. There is no target file.
//!
//! Adapted from the executor in Evan Lezar's NVIDIA/OpenShell#4629.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Output;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use tmachine::Session;
use tmachine::config::Config;

use crate::bundle::{Bundle, PROFILE, READY_BINARY};
use crate::jobs::{FamilyJob, Job};
use crate::report::{Outcome, Status, annotate_junit, verify_junit};

const GUEST_ROOT: &str = "/var/tmp/openshell-tests";
/// How long the gateway has to become healthy after the environment is up.
// Matches the installers' own wait: an HA k3s gateway booted from a cached
// disk can take minutes to report healthy.
const READY_TIMEOUT_SECS: u64 = 300;
/// How long one family's nextest run may take in total. Individual tests are
/// bounded by the nextest profile's slow-timeout; this catches a run that
/// stops making progress some other way.
const RUN_TIMEOUT: Duration = Duration::from_mins(45);
/// Slack beyond the readiness check's own timeout for SSH and process start.
const READY_SLACK: Duration = Duration::from_mins(1);

pub struct Options<'a> {
    pub tmachine: &'a Config,
    pub bundles: &'a BTreeMap<String, Bundle>,
    pub results: &'a Path,
    pub keep: bool,
}

/// Run one job. Every family gets an outcome, even when provisioning fails.
pub async fn run(job: &Job, options: &Options<'_>) -> Vec<Outcome> {
    let env_id = &job.environment.id;
    let outcome = |family: &FamilyJob, status| Outcome {
        environment: env_id.clone(),
        family: family.family.clone(),
        status,
    };

    if let Some(reason) = &job.unsupported {
        return job
            .families
            .iter()
            .map(|family| outcome(family, Status::Unsupported(reason.clone())))
            .collect();
    }
    if !job.families.iter().any(FamilyJob::has_tests) {
        return job
            .families
            .iter()
            .map(|family| outcome(family, Status::NothingToRun))
            .collect();
    }

    eprintln!("==> {env_id}: provisioning");
    let session = match provision(job, options.tmachine).await {
        Ok(session) => session,
        Err(error) => {
            let message = format!("provision environment: {error:#}");
            eprintln!("==> {env_id}: {message}");
            return job
                .families
                .iter()
                .map(|family| outcome(family, Status::Error(message.clone())))
                .collect();
        }
    };

    let mut outcomes = Vec::new();
    for family in &job.families {
        if !family.has_tests() {
            outcomes.push(outcome(family, Status::NothingToRun));
            continue;
        }
        let dir = options.results.join(env_id).join(&family.family);
        eprintln!(
            "==> {env_id}: running {} ({})",
            family.family,
            family.filterset()
        );
        let status = match run_family(&session, job, family, options, &dir).await {
            Ok(status) => status,
            Err(error) => Status::Error(format!("{error:#}")),
        };
        if status.is_failure()
            && let Err(error) = session.collect_diagnostics(&dir.join("diagnostics")).await
        {
            eprintln!("==> {env_id}: collecting diagnostics failed: {error:#}");
        }
        eprintln!("==> {env_id}: {} {status:?}", family.family);
        outcomes.push(outcome(family, status));
    }

    if options.keep {
        eprintln!(
            "==> {env_id}: keeping the VM. Connect with `ssh -p {} tmachine@127.0.0.1` (password `tmachine`). Press Enter to tear it down.",
            tmachine::ssh_port()
        );
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
    }
    eprintln!("==> {env_id}: tearing down");
    session.down().await;
    outcomes
}

async fn provision(job: &Job, config: &Config) -> Result<Session> {
    let params = job
        .environment
        .tmachine
        .as_ref()
        .context("environment has no tmachine section")?;
    let environment = config
        .environments
        .iter()
        .find(|candidate| candidate.name == params.environment)
        .with_context(|| {
            format!(
                "tmachine environment {:?} is not defined",
                params.environment
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
        .find(|candidate| candidate.name == params.installer)
        .with_context(|| format!("tmachine installer {:?} is not defined", params.installer))?;
    Session::up(machine, environment, installer).await
}

/// The environment variables that point the tests at the system under test:
/// the registered gateway (when the environment names one), the installed
/// CLI.
pub fn guest_env(job: &Job, openshell_bin: &str) -> Vec<String> {
    let mut vars = Vec::new();
    if let Some(gateway) = &job.environment.gateway {
        vars.push(format!("OPENSHELL_GATEWAY={gateway}"));
    }
    vars.push(format!("OPENSHELL_BIN={openshell_bin}"));
    vars
}

/// Decide a family's status from nextest's exit status and its `JUnit`
/// report. The run passes only if nextest succeeded and the report has a
/// passing case for exactly the tests that were selected.
pub fn decide_status(
    nextest_succeeded: bool,
    junit: Option<&str>,
    expected: &BTreeSet<(String, String)>,
    log: &Path,
) -> Status {
    let Some(xml) = junit else {
        return Status::Error(format!(
            "nextest produced no JUnit report (exit {}); see {}",
            if nextest_succeeded {
                "success"
            } else {
                "failure"
            },
            log.display()
        ));
    };
    let verification = verify_junit(xml, expected);
    if let Some(mismatch) = verification.mismatch() {
        return Status::Error(format!(
            "the JUnit report does not match the selected tests: {mismatch}; see {}",
            log.display()
        ));
    }
    let failures = u32::try_from(verification.failed.len()).unwrap_or(u32::MAX);
    if failures > 0 {
        Status::Failed {
            tests: verification.tests,
            failures,
        }
    } else if nextest_succeeded {
        Status::Passed {
            tests: verification.tests,
        }
    } else {
        Status::Error(format!(
            "nextest failed, but the JUnit report shows no failed test; see {}",
            log.display()
        ))
    }
}

async fn run_family(
    session: &Session,
    job: &Job,
    family: &FamilyJob,
    options: &Options<'_>,
    dir: &Path,
) -> Result<Status> {
    if dir.exists() {
        std::fs::remove_dir_all(dir).with_context(|| format!("clear {}", dir.display()))?;
    }
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let bundle = options
        .bundles
        .get(&family.family)
        .with_context(|| format!("no bundle was built for {}", family.family))?;

    let openshell_bin = checked(
        "find the installed openshell CLI",
        session.exec(&["sh", "-c", "command -v openshell"]).await?,
    )?;
    let openshell_bin = openshell_bin.trim();
    ensure!(
        !openshell_bin.is_empty(),
        "the installer did not put openshell on the guest's PATH"
    );
    let env = guest_env(job, openshell_bin);

    let guest = format!("{GUEST_ROOT}/{}", family.family);
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
        .copy_in(&bundle.path, &format!("{guest}/bundle.tar"))
        .await?;
    checked(
        "unpack bundle",
        session
            .exec(&["tar", "-C", &guest, "-xf", &format!("{guest}/bundle.tar")])
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

    let filterset = family.filterset();
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
        &guest,
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
        "-E",
        &filterset,
    ]);
    let output = session.exec_timeout(&nextest, RUN_TIMEOUT).await?;
    let mut log = output.stdout.clone();
    log.extend_from_slice(&output.stderr);
    let log_path = dir.join("nextest.log");
    std::fs::write(&log_path, &log)?;

    let junit = dir.join("junit.xml");
    let found = checked(
        "find JUnit report",
        session
            .exec(&["find", &guest, "-name", "junit.xml"])
            .await?,
    )?;
    let xml = match found.lines().next() {
        Some(path) => {
            session.copy_out(path, &junit).await?;
            let xml = annotate_junit(&std::fs::read_to_string(&junit)?, &family.test_ids());
            std::fs::write(&junit, &xml)?;
            Some(xml)
        }
        None => None,
    };

    Ok(decide_status(
        output.status.success(),
        xml.as_deref(),
        &family.expected_tests(),
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
    use std::path::PathBuf;

    use super::*;
    use crate::environments::Catalog as Environments;

    fn expected(names: &[&str]) -> BTreeSet<(String, String)> {
        names
            .iter()
            .map(|name| ("p::b".to_string(), (*name).to_string()))
            .collect()
    }

    fn report(cases: &[(&str, &str)]) -> String {
        let body: String = cases
            .iter()
            .map(|(name, child)| {
                format!(
                    "<testcase name=\"{name}\" classname=\"p::b\" time=\"1\">{child}</testcase>"
                )
            })
            .collect();
        format!("<testsuites><testsuite name=\"p::b\">{body}</testsuite></testsuites>")
    }

    fn log() -> PathBuf {
        PathBuf::from("nextest.log")
    }

    #[test]
    fn passes_only_when_every_selected_test_passed() {
        let xml = report(&[("a", ""), ("b", "")]);
        match decide_status(true, Some(&xml), &expected(&["a", "b"]), &log()) {
            Status::Passed { tests } => assert_eq!(tests, 2),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_missing_test_fails_the_lane_even_though_nextest_succeeded() {
        let xml = report(&[("a", "")]);
        match decide_status(true, Some(&xml), &expected(&["a", "b"]), &log()) {
            Status::Error(message) => {
                assert!(message.contains("p::b b"), "{message}");
                assert!(message.contains("does not match"), "{message}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_unselected_test_in_the_report_fails_the_lane() {
        let xml = report(&[("a", ""), ("stray", "")]);
        assert!(matches!(
            decide_status(true, Some(&xml), &expected(&["a"]), &log()),
            Status::Error(_)
        ));
    }

    #[test]
    fn failures_are_reported_as_failed() {
        let xml = report(&[("a", ""), ("b", "<failure message=\"x\"/>")]);
        match decide_status(false, Some(&xml), &expected(&["a", "b"]), &log()) {
            Status::Failed { tests, failures } => assert_eq!((tests, failures), (2, 1)),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_missing_report_is_an_error() {
        assert!(matches!(
            decide_status(true, None, &expected(&["a"]), &log()),
            Status::Error(_)
        ));
        assert!(matches!(
            decide_status(false, None, &expected(&["a"]), &log()),
            Status::Error(_)
        ));
    }

    #[test]
    fn nextest_failing_without_a_failed_case_is_an_error() {
        let xml = report(&[("a", "")]);
        assert!(matches!(
            decide_status(false, Some(&xml), &expected(&["a"]), &log()),
            Status::Error(_)
        ));
    }

    #[test]
    fn points_tests_at_the_gateway_and_the_cli() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("e.yaml"),
            "environments:\n  - id: tmachine.ubuntu2404-amd64.docker-rootful.deb\n    backend: tmachine\n    machine: { os: ubuntu, version: \"24.04\", arch: amd64 }\n    runtime: docker-rootful\n    installer: deb\n    tmachine: { environment: ubuntu-docker-rootful, installer: deb }\n    gateway: openshell\n",
        )
        .unwrap();
        let environments = Environments::load_dir(dir.path()).unwrap();
        let job = Job {
            environment: environments
                .get("tmachine.ubuntu2404-amd64.docker-rootful.deb")
                .unwrap()
                .clone(),
            unsupported: None,
            families: Vec::new(),
        };
        assert_eq!(
            guest_env(&job, "/usr/bin/openshell"),
            [
                "OPENSHELL_GATEWAY=openshell",
                "OPENSHELL_BIN=/usr/bin/openshell",
            ]
        );

        let mut job = job;
        job.environment.gateway = None;
        assert!(
            !guest_env(&job, "/usr/bin/openshell")
                .iter()
                .any(|var| var.starts_with("OPENSHELL_GATEWAY="))
        );
    }
}
