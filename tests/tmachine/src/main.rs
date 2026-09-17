// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use config::{Config, Machine, Scenario};

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
    Setup { scenario: String },
    Install { scenario: String },
    Test { scenario: String, testsuite: String },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;

    match cli.command {
        Command::Setup { scenario } => {
            let (machine, scenario) = find_scenario(&config, &scenario)?;
            qemu::setup(&machine, &scenario).await?;
        }
        Command::Install { scenario } => {
            let (machine, scenario) = find_scenario(&config, &scenario)?;
            qemu::install(&machine, &scenario).await?;
        }
        Command::Test {
            scenario,
            testsuite,
        } => {
            let (machine, scenario) = find_scenario(&config, &scenario)?;
            let testsuite = config
                .testsuites
                .iter()
                .find(|candidate| candidate.name == testsuite)
                .with_context(|| format!("testsuite {testsuite:?} is not defined"))?;
            qemu::test(&machine, &scenario, testsuite).await?;
        }
    }

    Ok(())
}

fn find_scenario(config: &Config, name: &str) -> Result<(Machine, Scenario)> {
    let scenario = config
        .scenarios
        .iter()
        .find(|scenario| scenario.name == name)
        .with_context(|| format!("scenario {name:?} is not defined"))?
        .clone();
    let machine = config
        .machines
        .iter()
        .find(|machine| machine.name == scenario.machine)
        .with_context(|| {
            format!(
                "machine {:?} referenced by scenario {:?} is not defined",
                scenario.machine, scenario.name
            )
        })?
        .clone();

    Ok((machine, scenario))
}
