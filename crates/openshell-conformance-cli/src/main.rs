// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Standalone runner for `OpenShell` CLI conformance scenarios.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use openshell_conformance::{OpenShellRunner, Scenario, scenario, scenarios};
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(
    name = "openshell-conformance",
    about = "Run OpenShell CLI conformance scenarios",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// List registered scenarios.
    List {
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        output: OutputFormat,
    },
    /// Run all registered scenarios, or named scenarios.
    Run {
        /// Scenario names. Omit to run every registered scenario.
        scenarios: Vec<String>,
        /// Explicit path to the `OpenShell` CLI. Defaults to `openshell` on PATH.
        #[arg(long)]
        openshell_bin: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        output: OutputFormat,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Serialize)]
struct ScenarioDescription<'a> {
    name: &'a str,
    description: &'a str,
}

#[derive(Serialize)]
struct ScenarioResult<'a> {
    name: &'a str,
    passed: bool,
    diagnostic: Option<String>,
}

#[derive(Serialize)]
struct RunReport<'a> {
    scenarios: Vec<ScenarioResult<'a>>,
    passed: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    match execute(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("openshell-conformance: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn execute(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::List { output } => list(output),
        Command::Run {
            scenarios: requested,
            openshell_bin,
            output,
        } => run(&requested, openshell_bin, output).await,
    }
}

fn list(output: OutputFormat) -> Result<(), String> {
    match output {
        OutputFormat::Text => {
            for candidate in scenarios() {
                println!("{:<16} {}", candidate.name, candidate.description);
            }
        }
        OutputFormat::Json => {
            let result = scenarios()
                .iter()
                .map(|candidate| ScenarioDescription {
                    name: candidate.name,
                    description: candidate.description,
                })
                .collect::<Vec<_>>();
            println!(
                "{}",
                serde_json::to_string_pretty(&result).map_err(|error| error.to_string())?
            );
        }
    }
    Ok(())
}

async fn run(
    requested: &[String],
    binary: Option<PathBuf>,
    output: OutputFormat,
) -> Result<(), String> {
    let selected = select_scenarios(requested)?;
    let mut results = Vec::with_capacity(selected.len());
    for candidate in selected {
        let runner = binary.as_ref().map_or_else(
            || OpenShellRunner::new(candidate.name),
            |path| OpenShellRunner::with_binary(path.clone(), candidate.name),
        );
        let mut runner = match runner {
            Ok(runner) => runner,
            Err(error) => {
                results.push(ScenarioResult {
                    name: candidate.name,
                    passed: false,
                    diagnostic: Some(error.to_string()),
                });
                continue;
            }
        };
        eprintln!("CLI conformance run ID: {}", runner.id());
        let scenario_result = match runner.check_gateway_status().await {
            Ok(()) => candidate.run(&mut runner).await,
            Err(error) => Err(error),
        };
        let outcome = runner.finish(scenario_result).await;
        results.push(ScenarioResult {
            name: candidate.name,
            passed: outcome.is_ok(),
            diagnostic: outcome.err(),
        });
    }

    let passed = results.iter().all(|result| result.passed);
    match output {
        OutputFormat::Text => {
            for result in &results {
                if result.passed {
                    println!("PASS {}", result.name);
                } else {
                    println!(
                        "FAIL {}\n{}",
                        result.name,
                        result.diagnostic.as_deref().unwrap_or("unknown failure")
                    );
                }
            }
        }
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&RunReport {
                scenarios: results,
                passed
            })
            .map_err(|error| error.to_string())?
        ),
    }
    if passed {
        Ok(())
    } else {
        Err("one or more scenarios failed".to_string())
    }
}

fn select_scenarios(requested: &[String]) -> Result<Vec<&'static Scenario>, String> {
    if requested.is_empty() {
        return Ok(scenarios().iter().collect());
    }
    requested
        .iter()
        .map(|name| {
            scenario(name).ok_or_else(|| {
                format!("unknown scenario '{name}'; run `openshell-conformance list`")
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn selects_all_scenarios_by_default() {
        assert_eq!(
            select_scenarios(&[]).expect("select all").len(),
            scenarios().len()
        );
    }

    #[test]
    fn selects_named_scenario() {
        let selected = select_scenarios(&["smoke".to_string()]).expect("select smoke");
        assert_eq!(selected[0].name, "smoke");
    }

    #[test]
    fn unknown_scenario_has_actionable_diagnostic() {
        let error = select_scenarios(&["missing".to_string()]).expect_err("unknown scenario");
        assert!(error.contains("openshell-conformance list"));
    }

    #[test]
    fn parses_binary_override_and_json_output() {
        let cli = Cli::try_parse_from([
            "openshell-conformance",
            "run",
            "smoke",
            "--openshell-bin",
            "/opt/openshell",
            "--output",
            "json",
        ])
        .expect("parse CLI");
        let Command::Run {
            openshell_bin,
            output,
            ..
        } = cli.command
        else {
            panic!("expected run")
        };
        assert_eq!(openshell_bin, Some(PathBuf::from("/opt/openshell")));
        assert_eq!(output, OutputFormat::Json);
    }
}
