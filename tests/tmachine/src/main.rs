// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use config::{Config, Environment, Installer, Machine};

mod ansible;
mod config;
mod qemu;

#[derive(Parser)]
#[command(name = "tmachine")]
struct Cli {
    #[arg(long, default_value = "config.yaml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Setup {
        environment: String,
    },
    Install {
        environment: String,
        installer: String,
    },
    Test {
        environment: String,
        installer: String,
        testsuite: String,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;

    match cli.command {
        Command::Setup { environment } => {
            let (machine, environment) = find_environment(&config, &environment)?;
            qemu::setup(&machine, &environment).await?;
        }
        Command::Install {
            environment,
            installer,
        } => {
            let (machine, environment) = find_environment(&config, &environment)?;
            let installer = find_installer(&config, &installer)?;
            qemu::install(&machine, &environment, &installer).await?;
        }
        Command::Test {
            environment,
            installer,
            testsuite,
        } => {
            let (machine, environment) = find_environment(&config, &environment)?;
            let installer = find_installer(&config, &installer)?;
            let testsuite = config
                .testsuites
                .iter()
                .find(|candidate| candidate.name == testsuite)
                .with_context(|| format!("testsuite {testsuite:?} is not defined"))?;
            qemu::test(&machine, &environment, &installer, testsuite).await?;
        }
    }

    Ok(())
}

fn find_installer(config: &Config, name: &str) -> Result<Installer> {
    config
        .installers
        .iter()
        .find(|installer| installer.name == name)
        .with_context(|| format!("installer {name:?} is not defined"))
        .cloned()
}

fn find_environment(config: &Config, name: &str) -> Result<(Machine, Environment)> {
    let environment = config
        .environments
        .iter()
        .find(|environment| environment.name == name)
        .with_context(|| format!("environment {name:?} is not defined"))?
        .clone();
    let machine = config
        .machines
        .iter()
        .find(|machine| machine.name == environment.machine)
        .with_context(|| {
            format!(
                "machine {:?} referenced by environment {:?} is not defined",
                environment.machine, environment.name
            )
        })?
        .clone();

    Ok((machine, environment))
}
