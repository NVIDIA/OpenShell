// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Running a job: provision the environment, run each family's bundle in it,
//! and bring the results back.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Output;

use anyhow::{Context, Result, bail, ensure};
use tmachine::Session;
use tmachine::config::Config;

use crate::bundle::{Bundle, PROFILE, READY_BINARY};
use crate::jobs::{FamilyJob, Job};
use crate::matrix::Exclusion;
use crate::report::{Outcome, Status, annotate_junit, junit_counts};

/// Where the installer describes the gateway in the guest.
const GATEWAY_SECTION: &str = "/etc/openshell-test/gateway.yaml";
const GUEST_ROOT: &str = "/var/tmp/openshell-tests";
/// How long the gateway has to become healthy after the environment is up.
// Matches the installers' own wait: an HA k3s gateway booted from a cached
// disk can take minutes to report healthy.
const READY_TIMEOUT_SECS: u64 = 300;

pub struct Options<'a> {
    pub tmachine: &'a Config,
    pub bundles: &'a BTreeMap<String, Bundle>,
    pub results: &'a Path,
    pub keep: bool,
}

fn count(family: &FamilyJob, kind: impl Fn(&Exclusion) -> bool) -> usize {
    family
        .suites
        .iter()
        .flat_map(|suite| &suite.excluded)
        .filter(|test| kind(&test.reason))
        .count()
}

/// Run one job. Every family gets an outcome, even when provisioning fails.
pub async fn run(job: &Job, options: &Options<'_>) -> Vec<Outcome> {
    let env_id = &job.environment.id;
    let outcome = |family: &FamilyJob, status| Outcome {
        environment: env_id.clone(),
        family: family.family.clone(),
        status,
        unsupported_tests: count(family, |reason| matches!(reason, Exclusion::Missing(_))),
        waived_tests: count(family, |reason| matches!(reason, Exclusion::Waived(_))),
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
            "==> {env_id}: keeping the VM. Connect with `ssh -p 2222 tmachine@127.0.0.1` (password `tmachine`). Press Enter to tear it down."
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

    // The installer knows how to reach the gateway; the environment
    // definition knows what it provides. Together they are the target.
    let gateway = checked(
        "read the installer's gateway description",
        session.exec(&["cat", GATEWAY_SECTION]).await?,
    )?;
    let capabilities = serde_yml::to_string(&BTreeMap::from([(
        "capabilities",
        &job.environment.capabilities,
    )]))?;
    let target = dir.join("target.yaml");
    std::fs::write(&target, format!("{gateway}{capabilities}"))?;

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
    session
        .copy_in(&target, &format!("{guest}/target.yaml"))
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
    let target_env = format!("OPENSHELL_TEST_TARGET={guest}/target.yaml");
    checked(
        "wait for the gateway",
        session
            .exec(&[
                "env",
                &target_env,
                &format!("{guest}/{READY_BINARY}"),
                &READY_TIMEOUT_SECS.to_string(),
            ])
            .await?,
    )?;

    let filterset = family.filterset();
    let output = session
        .exec(&[
            "env",
            &target_env,
            "cargo-nextest",
            "nextest",
            "run",
            "--archive-file",
            &format!("{guest}/tests.tar.zst"),
            "--workspace-remap",
            &guest,
            "--extract-to",
            &format!("{guest}/extract"),
            "--extract-overwrite",
            "--config-file",
            &format!("{guest}/nextest.toml"),
            "--profile",
            PROFILE,
            "--no-capture",
            "-E",
            &filterset,
        ])
        .await?;
    let mut log = output.stdout.clone();
    log.extend_from_slice(&output.stderr);
    std::fs::write(dir.join("nextest.log"), &log)?;

    let junit = dir.join("junit.xml");
    let found = checked(
        "find JUnit report",
        session
            .exec(&["find", &guest, "-name", "junit.xml"])
            .await?,
    )?;
    let counts = match found.lines().next() {
        Some(path) => {
            session.copy_out(path, &junit).await?;
            let xml = annotate_junit(&std::fs::read_to_string(&junit)?, &family.test_ids());
            std::fs::write(&junit, &xml)?;
            junit_counts(&xml)
        }
        None => None,
    };

    Ok(match (output.status.success(), counts) {
        (true, Some((tests, 0))) => Status::Passed { tests },
        (true, counts) => bail!(
            "nextest succeeded but the JUnit report is missing or reports failures ({counts:?}); see {}",
            dir.join("nextest.log").display()
        ),
        (false, Some((tests, failures))) if failures > 0 => Status::Failed { tests, failures },
        (false, _) => Status::Error(format!(
            "nextest exited with {}; see {}",
            output.status,
            dir.join("nextest.log").display()
        )),
    })
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
