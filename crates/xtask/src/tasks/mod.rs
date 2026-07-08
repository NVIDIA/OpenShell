// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::iter::Peekable;
use std::process::{ExitCode, ExitStatus};

pub use crate::e2e::run as e2e;

const HELP: &str = "OpenShell development tasks

Usage:
  cargo xtask <command> [options]

Commands:
  e2e  Run an e2e suite locally or on a prepared host

Run `cargo xtask <command> --help` for command-specific usage.";

pub type TaskResult = Result<ExitCode, String>;

pub fn print_help() {
    println!("{HELP}");
}

pub(crate) fn print_help_if_requested<I>(args: &mut Peekable<I>, help: &str) -> bool
where
    I: Iterator<Item = OsString>,
{
    if args.peek().is_some_and(is_help_argument) {
        println!("{help}");
        return true;
    }

    false
}

fn is_help_argument(argument: &OsString) -> bool {
    argument == "-h" || argument == "--help"
}

pub(crate) fn exit_code(status: ExitStatus) -> ExitCode {
    match status.code() {
        Some(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        None => ExitCode::FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_command_help_arguments() {
        assert!(is_help_argument(&OsString::from("-h")));
        assert!(is_help_argument(&OsString::from("--help")));
        assert!(!is_help_argument(&OsString::from("help")));
    }
}
