// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `openshell-test-runner`: run a test family in one tmachine environment.
//!
//! Run it through `nix run .#openshell-test-runner -- <flags>`, which
//! provides the guest cross-compilation toolchain, QEMU, Ansible, and the
//! tmachine configuration.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, ensure};
use clap::Parser;

use crate::execute::{Run, Status};

mod bundle;
mod execute;

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
    let cli = Cli::parse();
    // A SIGTERM from CI cancellation must not leave QEMU holding the SSH port.
    match tmachine::until_signal(run(cli)).await {
        // Exit at once: a blocking build or stdin read would otherwise hold
        // up the runtime's shutdown.
        Err(status) => std::process::exit(status),
        Ok(Ok(code)) => code,
        Ok(Err(error)) => {
            eprintln!("error: {error:#}");
            annotate("E2E suites: runner error", &format!("{error:#}"));
            ExitCode::from(execute::ERROR_EXIT)
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
    // The builds block, so they run off the runtime thread to keep the
    // signal handlers responsive.
    let bundle = tokio::task::spawn_blocking({
        let (root, family, packages) = (root.clone(), cli.family.clone(), cli.packages.clone());
        move || {
            eprintln!("==> building {} for {target}", bundle::READY_BINARY);
            let ready = bundle::build_ready(&root, target)?;
            eprintln!("==> building the {family} tests for {target}");
            bundle::build(&workspace, &packages, target, &ready)
        }
    })
    .await
    .context("build task panicked")??;

    let tmachine = load_tmachine(&root)?;
    let status = execute::run(
        &tmachine,
        &Run {
            environment: &cli.environment,
            installer: &cli.installer,
            gateway: &cli.gateway,
            bundle: &bundle,
            filter: cli.filter.as_deref(),
            results: &results,
            keep: cli.keep,
        },
    )
    .await;

    let label = format!("{} / {} / {}", cli.environment, cli.installer, cli.family);
    eprintln!("\n{label}: {status}");
    eprintln!("Results: {}", results.display());
    match &status {
        Status::Passed => {}
        Status::Failed => annotate("E2E suites: test failure", &format!("{label}: {status}")),
        Status::Error(_) => annotate("E2E suites: runner error", &format!("{label}: {status}")),
    }
    Ok(status.exit_code())
}

/// On GitHub Actions, show `message` as an error on the run's summary page.
fn annotate(title: &str, message: &str) {
    if std::env::var_os("GITHUB_ACTIONS").is_none() {
        return;
    }
    let message = message
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A");
    println!("::error title={title}::{message}");
}

/// Load the tmachine configuration and enter `tests/tmachine/`, which its
/// playbook and input paths are relative to.
fn load_tmachine(root: &Path) -> Result<tmachine::config::Config> {
    let path = std::env::var_os("TMACHINE_CONFIG").context(
        "TMACHINE_CONFIG is not set; run through `nix run .#openshell-test-runner`, which provides it",
    )?;
    let config = tmachine::config::Config::load(Path::new(&path))?;
    let tmachine_dir = root.join("tests/tmachine");
    std::env::set_current_dir(&tmachine_dir)
        .with_context(|| format!("enter {}", tmachine_dir.display()))?;
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
