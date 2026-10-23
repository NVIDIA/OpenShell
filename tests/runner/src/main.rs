// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `openshell-test-runner`: run a test family in one tmachine environment.
//!
//! Run it through `nix run .#openshell-test-runner -- <flags>`, which
//! provides the guest cross-compilation toolchain, QEMU, Ansible, and the
//! tmachine configuration.
//!
//! Adapted from the runner in Evan Lezar's NVIDIA/OpenShell#4629.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, ensure};
use clap::Parser;
use openshell_test_runner::bundle;
use openshell_test_runner::execute::{self, Run};

/// Build a test family for the guest, boot a tmachine environment with
/// OpenShell installed, run the tests in it, and check the results.
#[derive(Parser)]
#[command(name = "openshell-test-runner")]
struct Cli {
    /// The tmachine environment to boot, e.g. `ubuntu-docker-rootful`.
    #[arg(long)]
    environment: String,
    /// The tmachine installer that installs OpenShell, e.g. `deb`.
    #[arg(long)]
    installer: String,
    /// The test family: a workspace under `tests/suites/`, e.g. `conformance`.
    #[arg(long)]
    family: String,
    /// Only build these packages of the family [default: every package].
    #[arg(long = "package", short = 'p', value_name = "PACKAGE")]
    packages: Vec<String>,
    /// A nextest filterset narrowing the tests that run, e.g.
    /// `binary(smoke)`.
    #[arg(long, value_name = "FILTERSET")]
    filter: Option<String>,
    /// The gateway name the installer registers with the CLI. The packaged
    /// installers register `openshell`.
    #[arg(long, default_value = "openshell")]
    gateway: String,
    /// Keep the VM running after the tests until Enter is pressed.
    #[arg(long)]
    keep: bool,
    /// Where to write `junit.xml`, `nextest.log` and, after a failure, the
    /// guest's diagnostics.
    #[arg(long, default_value = "artifacts/test-results")]
    results: PathBuf,
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
    ensure!(
        !cli.family.is_empty()
            && cli
                .family
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "--family must name a workspace directly under tests/suites/, got {:?}",
        cli.family
    );
    let workspace = root.join("tests/suites").join(&cli.family);
    // Absolute, because `load_tmachine` changes the working directory.
    let results = std::path::absolute(&cli.results)
        .with_context(|| format!("resolve {}", cli.results.display()))?;

    let target = bundle::guest_target()?;
    eprintln!("==> building {} for {target}", bundle::READY_BINARY);
    let ready = bundle::build_ready(&root, target)?;
    eprintln!("==> building the {} tests for {target}", cli.family);
    let bundle = bundle::build(&workspace, &cli.packages, target, &ready)?;

    let tmachine = load_tmachine(&root)?;
    let status = execute::run(
        &tmachine,
        &Run {
            environment: &cli.environment,
            installer: &cli.installer,
            gateway: Some(&cli.gateway),
            bundle: &bundle,
            filter: cli.filter.as_deref(),
            results: &results,
            keep: cli.keep,
        },
    )
    .await;

    eprintln!(
        "\n{} / {} / {}: {status}",
        cli.environment, cli.installer, cli.family
    );
    eprintln!("Results: {}", results.display());
    Ok(if status.is_failure() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
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
    ensure!(
        output.status.success(),
        "not inside the OpenShell repository"
    );
    Ok(PathBuf::from(String::from_utf8(output.stdout)?.trim()))
}
