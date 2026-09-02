// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Standalone runner for `OpenShell` CLI conformance scenarios.

use std::fmt::Write;
use std::future::Future;
use std::io::Read;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};
use openshell_conformance::{
    ConformancePlan, HostAction, HostActionExecutor, OpenShellRunner, PlanRun, Scenario,
    default_scenarios, scenario, scenarios,
};
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
    /// Run action-free scenarios, named scenarios, or an explicit plan.
    Run {
        /// Action-free scenario names. Omit to run every action-free scenario.
        scenarios: Vec<String>,
        /// Explicit path to the `OpenShell` CLI. Defaults to `openshell` on PATH.
        #[arg(long)]
        openshell_bin: Option<PathBuf>,
        /// Versioned TOML conformance plan. Use '-' to read the plan from stdin.
        #[arg(long, conflicts_with = "scenarios")]
        plan: Option<PathBuf>,
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
            plan,
            output,
        } => run(&requested, openshell_bin, plan, output).await,
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
    plan_path: Option<PathBuf>,
    output: OutputFormat,
) -> Result<(), String> {
    if let Some(plan_path) = plan_path {
        let plan = read_plan(&plan_path)?;
        return run_plan(&plan, binary, output).await;
    }

    let selected = select_scenarios(requested)?;
    let mut results = Vec::with_capacity(selected.len());
    for candidate in selected {
        let plan_run = default_plan_run(candidate.name);
        results.push(run_scenario(candidate, &plan_run, binary.as_ref(), None).await);
    }

    render_results(results, output)
}

async fn run_plan(
    plan: &ConformancePlan,
    binary: Option<PathBuf>,
    output: OutputFormat,
) -> Result<(), String> {
    let executor: Arc<dyn HostActionExecutor> = Arc::new(ProcessHostAction);
    let mut results = Vec::with_capacity(plan.runs.len());
    for plan_run in &plan.runs {
        let candidate = scenario(&plan_run.scenario)
            .expect("validated conformance plan references a registered scenario");
        let result =
            run_scenario(candidate, plan_run, binary.as_ref(), Some(executor.clone())).await;
        let result = match (result.passed, &plan.diagnostics) {
            (false, Some(diagnostics)) => append_diagnostics(result, &executor, diagnostics).await,
            _ => result,
        };
        let passed = result.passed;
        results.push(result);
        if !passed {
            break;
        }
    }

    render_results(results, output)
}

fn default_plan_run(scenario: &str) -> PlanRun {
    PlanRun {
        scenario: scenario.to_string(),
        workload_expectation: None,
        actions: Vec::new(),
    }
}

async fn run_scenario(
    candidate: &'static Scenario,
    plan_run: &PlanRun,
    binary: Option<&PathBuf>,
    host_action_executor: Option<Arc<dyn HostActionExecutor>>,
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
    if let Some(host_action_executor) = host_action_executor {
        runner = runner.with_host_action_executor(host_action_executor);
    }
    eprintln!("CLI conformance run ID: {}", runner.id());
    let scenario_result = match runner.check_gateway_status().await {
        Ok(()) => candidate.run(&mut runner, plan_run).await,
        Err(error) => Err(error),
    };
    let outcome = runner.finish(scenario_result).await;
    ScenarioResult {
        name: candidate.name,
        passed: outcome.is_ok(),
        diagnostic: outcome.err(),
    }
}

async fn append_diagnostics(
    mut result: ScenarioResult<'static>,
    executor: &Arc<dyn HostActionExecutor>,
    diagnostics: &openshell_conformance::PlanDiagnostics,
) -> ScenarioResult<'static> {
    let action = diagnostics.as_action();
    if let Err(error) = executor.execute(&action).await {
        let diagnostic = result.diagnostic.get_or_insert_default();
        let _ = write!(diagnostic, "\n\nsecondary diagnostics failure:\n{error}");
    }
    result
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

fn read_plan(path: &PathBuf) -> Result<ConformancePlan, String> {
    let contents = if path.as_os_str() == "-" {
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .map_err(|error| format!("read conformance plan from stdin: {error}"))?;
        input
    } else {
        std::fs::read_to_string(path)
            .map_err(|error| format!("read conformance plan {}: {error}", path.display()))?
    };
    ConformancePlan::parse(&contents).map_err(|error| format!("invalid conformance plan: {error}"))
}

fn select_scenarios(requested: &[String]) -> Result<Vec<&'static Scenario>, String> {
    if requested.is_empty() {
        return Ok(default_scenarios().collect());
    }
    requested
        .iter()
        .map(|name| {
            let candidate = scenario(name).ok_or_else(|| {
                format!("unknown scenario '{name}'; run `openshell-conformance list`")
            })?;
            if candidate.requires_plan() {
                return Err(format!(
                    "scenario '{name}' requires an explicit --plan; run `openshell-conformance list`"
                ));
            }
            Ok(candidate)
        })
        .collect()
}

struct ProcessHostAction;

impl HostActionExecutor for ProcessHostAction {
    fn execute(
        &self,
        action: &HostAction,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>> {
        let name = action.name.clone();
        let command = action.command.clone();
        let timeout = action.timeout();
        let timeout_secs = action.timeout_secs;
        Box::pin(async move {
            let mut process = tokio::process::Command::new(&command);
            process.kill_on_drop(true);
            let output = tokio::time::timeout(timeout, process.output())
                .await
                .map_err(|_| {
                    format!(
                        "host action {:?} command '{}' timed out after {}s",
                        name,
                        command.display(),
                        timeout_secs,
                    )
                })?
                .map_err(|error| {
                    format!(
                        "start host action {:?} command '{}': {error}",
                        name,
                        command.display(),
                    )
                })?;
            if output.status.success() {
                return Ok(());
            }
            Err(format!(
                "host action {:?} command '{}' exited {:?}:\nstdout:\n{}\nstderr:\n{}",
                name,
                command.display(),
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn selects_all_scenarios_by_default() {
        assert_eq!(
            select_scenarios(&[]).expect("select all").len(),
            default_scenarios().count()
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
    fn action_scenario_requires_an_explicit_plan() {
        let error = select_scenarios(&["sandbox-continuity".to_string()])
            .expect_err("action scenario requires a plan");

        assert!(error.contains("requires an explicit --plan"));
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

    #[test]
    fn parses_plan_from_stdin() {
        let cli = Cli::try_parse_from(["openshell-conformance", "run", "--plan", "-"])
            .expect("parse plan from stdin");
        let Command::Run { plan, .. } = cli.command else {
            panic!("expected run")
        };
        assert_eq!(plan, Some(PathBuf::from("-")));
    }
}
