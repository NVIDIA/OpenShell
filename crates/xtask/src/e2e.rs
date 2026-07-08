// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{OsStr, OsString};
use std::process::{Command, ExitCode, ExitStatus};

use crate::machine::{MachineOptions, MachineOptionsBuilder};
use crate::platform::parse_machine_os;
use crate::tasks::{TaskResult, exit_code, print_help_if_requested};

const HELP: &str = "Run an e2e suite locally or on a target machine.

Usage:
  cargo xtask e2e --suite <podman> [--test <name>] [--os <centos-stream-10|ubuntu-24.04|ubuntu-26.04>] [--provider <lima>] [--arch <amd64|arm64>] [--snapshot] [--rebuild-machine] [--keep-machine]

Defaults for machine execution:
  --provider lima
  --os ubuntu-26.04 when --provider is supplied";

pub fn run(args: impl Iterator<Item = OsString>) -> TaskResult {
    let mut args = args.peekable();
    if print_help_if_requested(&mut args, HELP) {
        return Ok(ExitCode::SUCCESS);
    }

    let command = E2eCommand::parse(args)?;
    let status = match command.machine {
        Some(options) => crate::e2e_machine::run(&command.selection, &options),
        None => run_local(&command.selection),
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

    const fn script(self) -> &'static str {
        match self {
            Self::Podman => "e2e/rust/e2e-podman.sh",
        }
    }

    const fn test_environment(self) -> &'static str {
        match self {
            Self::Podman => "OPENSHELL_E2E_PODMAN_TEST",
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
    machine: Option<MachineOptions>,
}

impl E2eCommand {
    fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Self, String> {
        let mut suite = None;
        let mut os = None;
        let mut test = None;
        let mut machine = MachineOptionsBuilder::default();

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
                Some("--os") => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--os requires a value".to_owned())?;
                    if os.replace(parse_machine_os(&value, "--os")?).is_some() {
                        return Err("--os may only be specified once".to_owned());
                    }
                }
                Some(value) if machine.parse_argument(value, &mut args)? => {}
                Some(value) => return Err(format!("unknown e2e option: {value}")),
                None => return Err("e2e options must be valid UTF-8".to_owned()),
            }
        }

        Ok(Self {
            selection: E2eSelection {
                suite: suite.ok_or_else(|| "e2e requires --suite <suite>".to_owned())?,
                test,
            },
            machine: machine.finish(os)?,
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
        command.env(selection.suite.test_environment(), test);
    }
    command
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::Provider;
    use crate::platform::{Arch, MachineOs};

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
        assert!(command.machine.is_none());
    }

    #[test]
    fn parses_a_machine_e2e_selection() {
        let command = E2eCommand::parse(
            [
                "--suite",
                "podman",
                "--test",
                "smoke",
                "--os",
                "ubuntu-24.04",
                "--provider",
                "lima",
                "--arch",
                "arm64",
                "--keep-machine",
                "--rebuild-machine",
                "--snapshot",
            ]
            .into_iter()
            .map(OsString::from),
        )
        .expect("machine e2e command should parse");

        let machine = command.machine.expect("machine options should be present");
        assert_eq!(machine.os, MachineOs::Ubuntu24_04);
        assert_eq!(machine.arch, Some(Arch::Arm64));
        assert_eq!(machine.provider, Provider::Lima);
        assert!(machine.keep);
        assert!(machine.rebuild);
        assert!(machine.snapshot);
    }

    #[test]
    fn parses_a_centos_stream_machine_selection() {
        let command = E2eCommand::parse(
            ["--suite", "podman", "--os", "centos-stream-10"]
                .into_iter()
                .map(OsString::from),
        )
        .expect("CentOS Stream e2e command should parse");

        let machine = command.machine.expect("an OS should request a machine");
        assert_eq!(machine.os, MachineOs::CentosStream10);
        assert_eq!(machine.provider, Provider::Lima);
    }

    #[test]
    fn rejects_machine_options_without_an_os_or_provider() {
        let error = E2eCommand::parse(
            ["--suite", "podman", "--snapshot"]
                .into_iter()
                .map(OsString::from),
        )
        .err()
        .expect("machine-only options should require an OS or provider");

        assert!(error.contains("--snapshot requires --os or --provider"));
    }

    #[test]
    fn a_provider_uses_the_default_os() {
        let command = E2eCommand::parse(
            ["--suite", "podman", "--provider", "lima"]
                .into_iter()
                .map(OsString::from),
        )
        .expect("a provider should select the default machine OS");

        let machine = command
            .machine
            .expect("a provider should request a machine");
        assert_eq!(machine.provider, Provider::Lima);
        assert_eq!(machine.os, MachineOs::Ubuntu26_04);
    }

    #[test]
    fn builds_the_direct_suite_command() {
        let selection = E2eSelection {
            suite: E2eSuite::Podman,
            test: Some("smoke".to_owned()),
        };
        let command = local_command(&selection);

        assert_eq!(command.get_program(), "mise");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["exec", "--", "e2e/rust/e2e-podman.sh"]
        );
        assert!(command.get_envs().any(|(name, value)| {
            name == "OPENSHELL_E2E_PODMAN_TEST" && value == Some(OsStr::new("smoke"))
        }));
    }
}
