// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Command-line helpers for drivers started with `--config`.

use clap::parser::ValueSource;
use clap::{ArgMatches, Command};

/// The first flag other than `config_id` that was given on the command line.
///
/// A driver started from a startup document takes everything from it, so any
/// other flag would make precedence ambiguous. Values from the environment do
/// not count: the document is authoritative over them.
#[must_use]
pub fn first_flag_besides(
    command: &Command,
    matches: &ArgMatches,
    config_id: &str,
) -> Option<String> {
    command
        .get_arguments()
        .filter(|arg| arg.get_id().as_str() != config_id)
        .find(|arg| matches.value_source(arg.get_id().as_str()) == Some(ValueSource::CommandLine))
        .map(|arg| {
            arg.get_long()
                .map_or_else(|| arg.get_id().to_string(), str::to_string)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        config: Option<std::path::PathBuf>,
        #[arg(long, env = "TEST_SDK_CLI_VCPUS", default_value_t = 2)]
        vcpus: u8,
    }

    fn first_flag(arguments: &[&str]) -> Option<String> {
        let command = <Args as clap::CommandFactory>::command();
        let matches = command.clone().try_get_matches_from(arguments).unwrap();
        first_flag_besides(&command, &matches, "config")
    }

    #[test]
    fn only_the_config_flag_is_allowed() {
        assert_eq!(first_flag(&["driver", "--config", "x"]), None);
        assert_eq!(
            first_flag(&["driver", "--config", "x", "--vcpus", "8"]).as_deref(),
            Some("vcpus")
        );
    }
}
