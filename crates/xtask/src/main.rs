// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::process::ExitCode;

mod e2e;
mod e2e_machine;
mod lima;
mod machine;
mod platform;
mod provider;
mod release_smoke_test;
pub mod tasks;

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let result = match args.next() {
        None => {
            tasks::print_help();
            return ExitCode::SUCCESS;
        }
        Some(task) => match task.to_str() {
            Some("help" | "-h" | "--help") => {
                tasks::print_help();
                return ExitCode::SUCCESS;
            }
            Some("e2e") => tasks::e2e(args),
            Some("release-smoke-test") => tasks::release_smoke_test(args),
            Some(invalid) => Err(format!("invalid task name: {invalid}")),
            None => Err("task name must be valid UTF-8".to_owned()),
        },
    };

    match result {
        Ok(exit_code) => exit_code,
        Err(message) => {
            eprintln!("error: {message}");
            tasks::print_help();
            ExitCode::FAILURE
        }
    }
}
