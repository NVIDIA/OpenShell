// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `openshell-test-runner`: run `OpenShell` test plans.
//!
//! Run it through `nix run .#openshell-test-runner -- <command>`, which
//! provides the guest cross-compilation toolchain, QEMU, Ansible, and the
//! tmachine configuration.
//!
//! Adapted from the runner in Evan Lezar's NVIDIA/OpenShell#4629.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use openshell_test_runner::bundle::{self, Bundle};
use openshell_test_runner::catalog::Catalog;
use openshell_test_runner::environments::{Arch, Catalog as Environments};
use openshell_test_runner::execute::{self, Options};
use openshell_test_runner::github;
use openshell_test_runner::jobs::{self, Job, Narrowing};
use openshell_test_runner::plan::Plan;
use openshell_test_runner::report;

#[derive(Parser)]
#[command(name = "openshell-test-runner", about = "Run OpenShell test plans")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a test plan.
    Test {
        /// The plan to run, e.g. tests/plans/cpu-tests.yaml.
        #[arg(long)]
        plan: PathBuf,
        /// Print the resolved jobs without building or provisioning anything.
        #[arg(long)]
        dry_run: bool,
        /// Print the GitHub Actions matrix for the plan as JSON, one job per
        /// environment, and exit. The matrix does not depend on this host.
        #[arg(long)]
        emit_github_matrix: bool,
        /// CI mode: fail instead of skipping an environment this host can't
        /// provision, an environment where no test is left to run, or a plan
        /// that selects nothing.
        #[arg(
            long,
            env = "OPENSHELL_TEST_STRICT",
            value_parser = clap::builder::BoolishValueParser::new(),
            default_value_t = false,
            num_args = 0..=1,
            default_missing_value = "true"
        )]
        strict: bool,
        /// Keep each environment running after its tests until Enter is pressed.
        #[arg(long)]
        keep: bool,
        /// Only run these environments from the plan.
        #[arg(long = "env", value_name = "ID")]
        environments: Vec<String>,
        /// Only run these suites from the plan.
        #[arg(long = "suite", value_name = "NAME")]
        suites: Vec<String>,
        /// Results directory [default: artifacts/test-results/<plan name>].
        #[arg(long)]
        results: Option<PathBuf>,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    // A SIGTERM from CI cancellation must not leave QEMU holding the SSH port.
    tmachine::cleanup_on_signals();
    match run(Cli::parse()).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let root = repo_root()?;
    let catalog = Catalog::load(&root)?;
    let environments_catalog = Environments::load_dir(&root.join("tests/environments"))?;

    match cli.command {
        Command::Test {
            plan,
            dry_run,
            emit_github_matrix,
            strict,
            keep,
            environments,
            suites,
            results,
        } => {
            let plan_path = plan;
            let plan = Plan::load(&plan_path)?;

            if emit_github_matrix {
                let name = plan_path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .context("plan path has no file name")?;
                let matrix = github::github_matrix(name, &plan, &catalog, &environments_catalog)?;
                println!("{}", serde_json::to_string(&matrix)?);
                return Ok(ExitCode::SUCCESS);
            }

            let host = Arch::host();
            let narrowing = Narrowing {
                environments,
                suites,
            };
            let jobs = jobs::expand(&plan, &catalog, &environments_catalog, host, &narrowing)?;
            print_jobs(&jobs);
            if strict {
                let problems = jobs::strict_problems(&jobs);
                if !problems.is_empty() {
                    bail!(
                        "strict mode refuses this plan:\n  {}",
                        problems.join("\n  ")
                    );
                }
            }
            if dry_run {
                return Ok(ExitCode::SUCCESS);
            }

            // Absolute, because `load_tmachine` changes the working directory.
            let results = match results {
                Some(results) => std::path::absolute(&results)
                    .with_context(|| format!("resolve {}", results.display()))?,
                None => root.join("artifacts/test-results").join(
                    plan_path
                        .file_stem()
                        .context("plan path has no file name")?,
                ),
            };
            std::fs::create_dir_all(&results)
                .with_context(|| format!("create {}", results.display()))?;
            std::fs::write(
                results.join("suites.json"),
                serde_json::to_string_pretty(&catalog)?,
            )?;

            let bundles = build_bundles(&root, &jobs, &catalog, host)?;
            let tmachine = load_tmachine(&root)?;
            let options = Options {
                tmachine: &tmachine,
                bundles: &bundles,
                results: &results,
                keep,
            };
            let mut outcomes = Vec::new();
            for job in &jobs {
                outcomes.extend(execute::run(job, &options).await);
            }

            eprintln!("{}", report::summary(&outcomes));
            eprintln!("Results: {}", results.display());
            Ok(
                if outcomes.iter().any(|outcome| outcome.status.is_failure()) {
                    ExitCode::FAILURE
                } else {
                    ExitCode::SUCCESS
                },
            )
        }
    }
}

fn print_jobs(jobs: &[Job]) {
    for job in jobs {
        eprintln!("{}", job.environment.id);
        if let Some(reason) = &job.unsupported {
            eprintln!("  unsupported on this host: {reason}");
        }
        for family in &job.families {
            eprintln!("  {}: -E '{}'", family.family, family.filterset());
            for suite in &family.suites {
                if suite.run.is_empty() {
                    eprintln!("    {}: no tests to run", suite.suite.suite);
                } else {
                    eprintln!("    {}: {}", suite.suite.suite, suite.run.join(", "));
                }
            }
        }
    }
}

/// Build one bundle per family, covering every suite that will run.
fn build_bundles(
    root: &Path,
    jobs: &[Job],
    catalog: &Catalog,
    host: Option<Arch>,
) -> Result<BTreeMap<String, Bundle>> {
    let mut suites: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for job in jobs.iter().filter(|job| job.unsupported.is_none()) {
        for family in &job.families {
            for suite in family.suites.iter().filter(|suite| !suite.run.is_empty()) {
                suites
                    .entry(family.family.as_str())
                    .or_default()
                    .insert(suite.suite.suite.as_str());
            }
        }
    }

    let mut bundles = BTreeMap::new();
    if suites.is_empty() {
        return Ok(bundles);
    }
    let target = bundle::guest_target(host.context("the host architecture is not supported")?);
    eprintln!("==> building {} for {target}", bundle::READY_BINARY);
    let ready = bundle::build_ready(root, target)?;
    for (family_name, suite_names) in suites {
        let family = catalog.family(family_name)?;
        let binaries = suite_names
            .iter()
            .map(|name| family.suite(name).map(|suite| suite.binary.clone()))
            .collect::<Result<_>>()?;
        eprintln!("==> building {family_name} bundle for {target}");
        let bundle = bundle::build(
            family,
            &family.packages(suite_names.iter().copied()),
            &binaries,
            target,
            &ready,
        )?;
        bundles.insert(family_name.to_string(), bundle);
    }
    Ok(bundles)
}

/// Load the tmachine configuration and prepare the process to drive it.
///
/// tmachine configs name playbooks and inputs relative to `tests/tmachine/`,
/// and its Ansible runs read `ANSIBLE_CONFIG`.
fn load_tmachine(root: &Path) -> Result<tmachine::config::Config> {
    let path = std::env::var_os("TMACHINE_CONFIG").context(
        "TMACHINE_CONFIG is not set; run through `nix run .#openshell-test-runner`, which provides it",
    )?;
    let config = tmachine::config::Config::load(Path::new(&path))?;
    let tmachine_dir = root.join("tests/tmachine");
    std::env::set_current_dir(&tmachine_dir)
        .with_context(|| format!("enter {}", tmachine_dir.display()))?;
    if std::env::var_os("ANSIBLE_CONFIG").is_none() {
        // SAFETY: single-threaded at this point; no other thread reads the
        // environment concurrently.
        unsafe {
            std::env::set_var("ANSIBLE_CONFIG", tmachine_dir.join("ansible/ansible.cfg"));
        };
    }
    Ok(config)
}

fn repo_root() -> Result<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("run git rev-parse")?;
    anyhow::ensure!(
        output.status.success(),
        "not inside the OpenShell repository"
    );
    Ok(PathBuf::from(String::from_utf8(output.stdout)?.trim()))
}
