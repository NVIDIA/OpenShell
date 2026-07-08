// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{OsStr, OsString};
use std::process::{Command, ExitCode, ExitStatus};

use crate::platform::{MachineOs, parse_machine_os};
use crate::tasks::{TaskResult, exit_code, print_help_if_requested};

const HELP: &str = "Run an e2e suite locally or on a prepared host.

Usage:
  cargo xtask e2e --suite <podman> [--test <name>] [--setup --os <ubuntu-24.04|ubuntu-26.04>]

Execution behavior:
  omit --setup and --os to run locally without preparing or validating the host
  --setup requires --os and prepares and validates the current host";

pub fn run(args: impl Iterator<Item = OsString>) -> TaskResult {
    let mut args = args.peekable();
    if print_help_if_requested(&mut args, HELP) {
        return Ok(ExitCode::SUCCESS);
    }

    let command = E2eCommand::parse(args)?;
    let status = match command.execution {
        E2eExecution::Local => run_local(&command.selection),
        E2eExecution::PreparedHost { os } => crate::e2e_host::run(&command.selection, os),
    }?;
    Ok(exit_code(status))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum E2eSuite {
    Podman,
}

impl E2eSuite {
    pub(crate) const fn id(self) -> &'static str {
        match self {
            Self::Podman => "podman",
        }
    }

    fn parse(value: &OsStr) -> Result<Self, String> {
        match value.to_str() {
            Some("podman") => Ok(Self::Podman),
            Some(value) => Err(format!("unsupported e2e suite: {value} (expected podman)")),
            None => Err("--suite must be valid UTF-8".to_owned()),
        }
    }

    pub(crate) const fn script(self) -> &'static str {
        match self {
            Self::Podman => "e2e/rust/e2e-podman.sh",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct E2eSelection {
    pub(crate) suite: E2eSuite,
    pub(crate) test: Option<String>,
}

impl E2eSelection {
    pub(crate) const fn suite(&self) -> E2eSuite {
        self.suite
    }

    pub(crate) fn test(&self) -> Option<&str> {
        self.test.as_deref()
    }
}

struct E2eCommand {
    selection: E2eSelection,
    execution: E2eExecution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum E2eExecution {
    Local,
    PreparedHost { os: MachineOs },
}

impl E2eCommand {
    fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Self, String> {
        let mut suite = None;
        let mut test = None;
        let mut setup = false;
        let mut os = None;

        while let Some(argument) = args.next() {
            match argument.to_str() {
                Some("--suite") => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--suite requires a value".to_owned())?;
                    if suite.replace(E2eSuite::parse(&value)?).is_some() {
                        return Err("--suite may only be specified once".to_owned());
                    }
                }
                Some("--test") => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--test requires a value".to_owned())?;
                    let value = value
                        .into_string()
                        .map_err(|_| "--test must be valid UTF-8".to_owned())?;
                    if value.is_empty() {
                        return Err("--test may not be empty".to_owned());
                    }
                    if test.replace(value).is_some() {
                        return Err("--test may only be specified once".to_owned());
                    }
                }
                Some("--setup") => {
                    if setup {
                        return Err("--setup may only be specified once".to_owned());
                    }
                    setup = true;
                }
                Some("--os") => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--os requires a value".to_owned())?;
                    if os.replace(parse_machine_os(&value, "--os")?).is_some() {
                        return Err("--os may only be specified once".to_owned());
                    }
                }
                Some(value) => return Err(format!("unknown e2e option: {value}")),
                None => return Err("e2e options must be valid UTF-8".to_owned()),
            }
        }

        let execution = match (setup, os) {
            (true, Some(os)) => E2eExecution::PreparedHost { os },
            (true, None) => return Err("--setup requires --os".to_owned()),
            (false, Some(_)) => return Err("--os requires --setup".to_owned()),
            (false, None) => E2eExecution::Local,
        };

        Ok(Self {
            selection: E2eSelection {
                suite: suite.ok_or_else(|| "e2e requires --suite <suite>".to_owned())?,
                test,
            },
            execution,
        })
    }
}

fn run_local(selection: &E2eSelection) -> Result<ExitStatus, String> {
    local_command(selection).status().map_err(|error| {
        format!(
            "failed to run the {} e2e suite: {error}",
            selection.suite.id()
        )
    })
}

fn local_command(selection: &E2eSelection) -> Command {
    let mut command = Command::new("mise");
    command.args(["exec", "--", selection.suite.script()]);
    if let Some(test) = selection.test() {
        command.args(["--test", test]);
    }
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_local_e2e_selection() {
        let command = E2eCommand::parse(
            ["--suite", "podman", "--test", "smoke"]
                .into_iter()
                .map(OsString::from),
        )
        .expect("local e2e command should parse");

        assert_eq!(command.selection.suite, E2eSuite::Podman);
        assert_eq!(command.selection.test.as_deref(), Some("smoke"));
        assert_eq!(command.execution, E2eExecution::Local);
    }

    #[test]
    fn parses_a_prepared_host_selection() {
        let command = E2eCommand::parse(
            ["--suite", "podman", "--setup", "--os", "ubuntu-24.04"]
                .into_iter()
                .map(OsString::from),
        )
        .expect("prepared-host e2e command should parse");

        assert_eq!(
            command.execution,
            E2eExecution::PreparedHost {
                os: MachineOs::Ubuntu24_04
            }
        );
    }

    #[test]
    fn requires_an_os_for_host_setup() {
        let error = E2eCommand::parse(
            ["--suite", "podman", "--setup"]
                .into_iter()
                .map(OsString::from),
        )
        .err()
        .expect("host setup without an OS should fail");

        assert_eq!(error, "--setup requires --os");
    }

    #[test]
    fn rejects_an_os_without_host_setup() {
        let error = E2eCommand::parse(
            ["--suite", "podman", "--os", "ubuntu-24.04"]
                .into_iter()
                .map(OsString::from),
        )
        .err()
        .expect("an OS without host setup should fail");

        assert_eq!(error, "--os requires --setup");
    }

    #[test]
    fn ubuntu_workflow_prepares_the_host_explicitly() {
        let workflow = include_str!("../../../.github/workflows/e2e-test.yml");
        assert!(
            workflow.contains(r#"cargo xtask e2e --suite podman --setup --os "${{ matrix.os }}""#)
        );
        assert!(!workflow.contains("--provider host"));
    }

    #[test]
    fn configures_the_selected_local_test() {
        let command = local_command(&E2eSelection {
            suite: E2eSuite::Podman,
            test: Some("smoke".to_owned()),
        });

        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["exec", "--", "e2e/rust/e2e-podman.sh", "--test", "smoke"]
        );
        assert!(
            command
                .get_envs()
                .all(|(name, _)| { name != "OPENSHELL_E2E_PODMAN_TEST" })
        );
    }
}
