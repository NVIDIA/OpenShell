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
    /// Run default scenarios, named scenarios, or a named group.
    Run {
        /// Scenario names. Omit to run default scenarios.
        scenarios: Vec<String>,
        /// Run every scenario in this group, including opt-in scenarios.
        #[arg(long)]
        group: Option<String>,
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
    group: &'a str,
    default: bool,
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
            group,
            openshell_bin,
            output,
        } => run(&requested, group.as_deref(), openshell_bin, output).await,
    }
}

fn list(output: OutputFormat) -> Result<(), String> {
    match output {
        OutputFormat::Text => {
            for candidate in scenarios() {
                println!(
                    "{:<24} {:<16} {:<8} {}",
                    candidate.name,
                    candidate.group,
                    if candidate.default {
                        "default"
                    } else {
                        "opt-in"
                    },
                    candidate.description
                );
            }
        }
        OutputFormat::Json => {
            let result = scenarios()
                .iter()
                .map(|candidate| ScenarioDescription {
                    name: candidate.name,
                    description: candidate.description,
                    group: candidate.group,
                    default: candidate.default,
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
    group: Option<&str>,
    binary: Option<PathBuf>,
    output: OutputFormat,
) -> Result<(), String> {
    let selected = select_scenarios(requested, group)?;
    let mut results = Vec::with_capacity(selected.len());
    for candidate in selected {
        results.push(run_scenario(candidate, binary.as_ref()).await);
    }

    render_results(results, output)
}

async fn run_scenario(
    candidate: &'static Scenario,
    binary: Option<&PathBuf>,
) -> ScenarioResult<'static> {
    let runner = binary.map_or_else(
        || OpenShellRunner::new(candidate.name),
        |path| OpenShellRunner::with_binary(path.clone(), candidate.name),
    );
    let mut runner = match runner {
        Ok(runner) => runner,
        Err(error) => {
            return ScenarioResult {
                name: candidate.name,
                passed: false,
                diagnostic: Some(error.to_string()),
            };
        }
    };
    eprintln!("CLI conformance run ID: {}", runner.id());
    let scenario_result = match runner.check_gateway_status().await {
        Ok(()) => candidate.run(&mut runner).await,
        Err(error) => Err(error),
    };
    let outcome = runner.finish(scenario_result).await;
    ScenarioResult {
        name: candidate.name,
        passed: outcome.is_ok(),
        diagnostic: outcome.err(),
    }
}

fn render_results(
    results: Vec<ScenarioResult<'static>>,
    output: OutputFormat,
) -> Result<(), String> {
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

fn select_scenarios(
    requested: &[String],
    group: Option<&str>,
) -> Result<Vec<&'static Scenario>, String> {
    if let Some(group) = group {
        if !requested.is_empty() {
            return Err("pass either scenario names or --group".to_string());
        }
        let selected = scenarios()
            .iter()
            .filter(|candidate| candidate.group == group)
            .collect::<Vec<_>>();
        if selected.is_empty() {
            return Err(format!(
                "unknown group '{group}'; run `openshell-conformance list`"
            ));
        }
        return Ok(selected);
    }
    if requested.is_empty() {
        return Ok(scenarios()
            .iter()
            .filter(|candidate| candidate.default)
            .collect());
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
    fn selects_default_scenarios() {
        assert_eq!(
            select_scenarios(&[], None).expect("select defaults").len(),
            scenarios()
                .iter()
                .filter(|candidate| candidate.default)
                .count()
        );
        assert!(
            !select_scenarios(&[], None)
                .unwrap()
                .iter()
                .any(|scenario| scenario.name == "policy-local")
        );
    }

    #[test]
    fn selects_named_scenario() {
        let selected = select_scenarios(&["smoke".to_string()], None).expect("select smoke");
        assert_eq!(selected[0].name, "smoke");
    }

    #[test]
    fn unknown_scenario_has_actionable_diagnostic() {
        let error = select_scenarios(&["missing".to_string()], None).expect_err("unknown scenario");
        assert!(error.contains("openshell-conformance list"));
    }

    #[test]
    fn selects_policy_advisor_group_including_opt_in_scenario() {
        let selected = select_scenarios(&[], Some("policy-advisor")).unwrap();
        assert_eq!(
            selected
                .iter()
                .map(|scenario| scenario.name)
                .collect::<Vec<_>>(),
            ["mechanistic-proposal", "policy-local"]
        );
        assert!(
            select_scenarios(&["smoke".to_string()], Some("policy-advisor"))
                .unwrap_err()
                .contains("either scenario names or --group")
        );
        assert!(select_scenarios(&[], Some("missing")).is_err());
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
