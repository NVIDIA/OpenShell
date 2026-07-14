// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod lima;
mod release_smoke_test;
mod vm;

use std::env;
use std::ffi::OsString;
use std::process::{Command, ExitCode, ExitStatus};

const USAGE: &str = "Usage:\n  cargo xtask run [--no-deps] [--skip-deps] <task> [-- <args>...]\n  cargo xtask release-smoke-test --deb <path> [--arch <amd64|arm64>] [--guest-os <ubuntu-24.04|ubuntu-26.04>] [--snapshot] [--rebuild-vm] [--keep-vm]";

fn main() -> ExitCode {
    match run(env::args_os().skip(1)) {
        Ok(status) => exit_code(status),
        Err(message) => {
            eprintln!("error: {message}");
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: impl Iterator<Item = OsString>) -> Result<ExitStatus, String> {
    let arguments = args.collect::<Vec<_>>();

    match arguments.first().and_then(|argument| argument.to_str()) {
        Some("release-smoke-test") => release_smoke_test::run(arguments.into_iter().skip(1)),
        _ => {
            let command = RunCommand::parse(arguments.into_iter())?;
            run_task(&command)
        }
    }
}

fn run_task(command: &RunCommand) -> Result<ExitStatus, String> {
    match command.task.to_str() {
        Some("rust:format:check") => rust_format_check(&command.task_args),
        _ => legacy_mise_task(command),
    }
}

struct RunCommand {
    mise_options: Vec<OsString>,
    task: OsString,
    task_args: Vec<OsString>,
}

impl RunCommand {
    fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Self, String> {
        match args.next().as_deref() {
            Some(command) if command == "run" => {}
            Some(command) => {
                return Err(format!(
                    "unknown xtask command: {}",
                    command.to_string_lossy()
                ));
            }
            None => return Err("missing xtask command".to_owned()),
        }

        let mut mise_options = Vec::new();
        let task = loop {
            match args.next() {
                Some(argument) if argument == "--no-deps" || argument == "--skip-deps" => {
                    mise_options.push(argument);
                }
                Some(argument) if argument == "--" => {
                    return Err("missing task name before `--`".to_owned());
                }
                Some(argument) => break argument,
                None => return Err("missing task name".to_owned()),
            }
        };

        let task_args = match args.next() {
            Some(separator) if separator == "--" => args.collect(),
            Some(argument) => std::iter::once(argument).chain(args).collect(),
            None => Vec::new(),
        };

        Ok(Self {
            mise_options,
            task,
            task_args,
        })
    }
}

fn rust_format_check(task_args: &[OsString]) -> Result<ExitStatus, String> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    spawn(
        Command::new(cargo)
            .args(["fmt", "--all", "--", "--check"])
            .args(task_args),
        "cargo fmt",
    )
}

fn legacy_mise_task(command: &RunCommand) -> Result<ExitStatus, String> {
    let mut process = Command::new("mise");
    process
        .arg("run")
        .args(&command.mise_options)
        .arg(&command.task);

    if !command.task_args.is_empty() {
        process.arg("--").args(&command.task_args);
    }

    spawn(&mut process, "mise run")
}

fn spawn(command: &mut Command, description: &str) -> Result<ExitStatus, String> {
    command
        .status()
        .map_err(|error| format!("failed to execute {description}: {error}"))
}

fn exit_code(status: ExitStatus) -> ExitCode {
    match status.code() {
        Some(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        None => ExitCode::FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_legacy_options_and_task_arguments() {
        let command = RunCommand::parse(
            [
                "run",
                "--no-deps",
                "--skip-deps",
                "e2e:rust",
                "--",
                "--nocapture",
            ]
            .into_iter()
            .map(OsString::from),
        )
        .expect("command should parse");

        assert_eq!(
            command.mise_options,
            [OsString::from("--no-deps"), OsString::from("--skip-deps")]
        );
        assert_eq!(command.task, "e2e:rust");
        assert_eq!(command.task_args, [OsString::from("--nocapture")]);
    }
}
