// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Versioned, target-supplied execution plans for conformance scenarios.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::scenario;

pub const PLAN_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
pub struct ConformancePlan {
    pub version: u32,
    #[serde(default)]
    pub runs: Vec<PlanRun>,
    pub diagnostics: Option<PlanDiagnostics>,
}

#[derive(Debug, Deserialize)]
pub struct PlanRun {
    pub scenario: String,
    pub workload_expectation: Option<WorkloadExpectation>,
    #[serde(default)]
    pub actions: Vec<HostAction>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum WorkloadExpectation {
    Reconciled,
}

#[derive(Clone, Debug, Deserialize)]
pub struct HostAction {
    pub name: String,
    pub command: PathBuf,
    pub timeout_secs: u64,
}

impl HostAction {
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
}

#[derive(Debug, Deserialize)]
pub struct PlanDiagnostics {
    pub command: PathBuf,
    pub timeout_secs: u64,
}

impl PlanDiagnostics {
    pub fn as_action(&self) -> HostAction {
        HostAction {
            name: "diagnostics".to_string(),
            command: self.command.clone(),
            timeout_secs: self.timeout_secs,
        }
    }
}

impl ConformancePlan {
    pub fn parse(input: &str) -> Result<Self, String> {
        let plan = toml::from_str::<Self>(input).map_err(|error| error.to_string())?;
        plan.validate()?;
        Ok(plan)
    }

    fn validate(&self) -> Result<(), String> {
        if self.version != PLAN_VERSION {
            return Err(format!(
                "unsupported conformance plan version {}; expected {PLAN_VERSION}",
                self.version
            ));
        }
        if self.runs.is_empty() {
            return Err("conformance plan must contain at least one run".to_string());
        }
        if let Some(diagnostics) = &self.diagnostics {
            validate_command(
                "diagnostics",
                &diagnostics.command,
                diagnostics.timeout_secs,
            )?;
        }
        for run in &self.runs {
            let Some(scenario) = scenario(&run.scenario) else {
                return Err(format!(
                    "unknown scenario {:?}; run `openshell-conformance list`",
                    run.scenario
                ));
            };
            scenario.validate_plan_run(run)?;
            for action in &run.actions {
                validate_command(
                    &format!("action {:?}", action.name),
                    &action.command,
                    action.timeout_secs,
                )?;
            }
        }
        Ok(())
    }
}

fn validate_command(label: &str, command: &Path, timeout_secs: u64) -> Result<(), String> {
    if !command.is_absolute() {
        return Err(format!(
            "{label} command must be an absolute path: {}",
            command.display()
        ));
    }
    if timeout_secs == 0 {
        return Err(format!("{label} timeout_secs must be greater than zero"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_smoke_and_continuity_plan() {
        let plan = ConformancePlan::parse(
            r#"
                version = 1

                [[runs]]
                scenario = "smoke"

                [[runs]]
                scenario = "sandbox-continuity"
                workload_expectation = "reconciled"

                [[runs.actions]]
                name = "gateway-upgrade"
                command = "/usr/local/libexec/restart-gateway"
                timeout_secs = 120
            "#,
        )
        .expect("valid plan");

        assert_eq!(plan.runs.len(), 2);
        assert_eq!(plan.runs[1].actions[0].name, "gateway-upgrade");
    }

    #[test]
    fn parses_plan_diagnostics() {
        let plan = ConformancePlan::parse(
            r#"
                version = 1

                [diagnostics]
                command = "/usr/local/libexec/diagnostics"
                timeout_secs = 60

                [[runs]]
                scenario = "smoke"
            "#,
        )
        .expect("valid plan with diagnostics");

        assert_eq!(
            plan.diagnostics
                .expect("diagnostics configured")
                .as_action()
                .name,
            "diagnostics"
        );
    }

    #[test]
    fn rejects_a_relative_action_command() {
        let error = ConformancePlan::parse(
            r#"
                version = 1

                [[runs]]
                scenario = "sandbox-continuity"
                workload_expectation = "reconciled"

                [[runs.actions]]
                name = "gateway-restart"
                command = "restart-gateway"
                timeout_secs = 120
            "#,
        )
        .expect_err("relative command must fail");

        assert!(error.contains("absolute path"));
    }

    #[test]
    fn rejects_an_actionless_continuity_run() {
        let error = ConformancePlan::parse(
            r#"
                version = 1

                [[runs]]
                scenario = "sandbox-continuity"
                workload_expectation = "reconciled"
            "#,
        )
        .expect_err("continuity requires an action");

        assert!(error.contains("requires at least one action"));
    }

    #[test]
    fn default_validation_rejects_actions_for_smoke() {
        let error = ConformancePlan::parse(
            r#"
                version = 1

                [[runs]]
                scenario = "smoke"

                [[runs.actions]]
                name = "gateway-restart"
                command = "/usr/local/libexec/restart-gateway"
                timeout_secs = 120
            "#,
        )
        .expect_err("smoke does not accept actions");

        assert!(error.contains("does not accept workload_expectation or actions"));
    }
}
