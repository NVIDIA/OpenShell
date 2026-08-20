// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Internal driver-agnostic conformance runner for `OpenShell` installations.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use miette::{Result, WrapErr};
use openshell_e2e::conformance::ConnectionOptions;

#[derive(Parser, Debug)]
#[command(
    name = "openshell-conformance",
    about = "Validate an OpenShell gateway and its configured compute driver"
)]
struct Cli {
    /// Gateway endpoint to test.
    #[arg(long, global = true, env = "OPENSHELL_GATEWAY_ENDPOINT")]
    gateway_endpoint: Option<String>,

    /// Path to the gateway CA certificate.
    #[arg(long, global = true)]
    tls_ca: Option<PathBuf>,

    /// Path to the client certificate.
    #[arg(long, global = true)]
    tls_cert: Option<PathBuf>,

    /// Path to the client private key.
    #[arg(long, global = true)]
    tls_key: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run conformance scenarios against a gateway.
    Run {
        /// Only run scenarios whose name contains this substring.
        #[arg(long, short = 'f')]
        filter: Option<String>,

        /// Maximum duration of each scenario, in seconds.
        #[arg(long, default_value_t = 300)]
        timeout: u64,

        /// Output format.
        #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },

    /// List available conformance scenarios without connecting to a gateway.
    List {
        /// Output format.
        #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Table,
    Yaml,
    Json,
}

impl OutputFormat {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Table => "table",
            Self::Yaml => "yaml",
            Self::Json => "json",
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::List { output } => openshell_e2e::conformance::conformance_list(output.as_str()),
        Command::Run {
            filter,
            timeout,
            output,
        } => {
            let gateway_endpoint = cli.gateway_endpoint.ok_or_else(|| {
                miette::miette!(
                    "gateway endpoint is required; pass --gateway-endpoint or set \
                     OPENSHELL_GATEWAY_ENDPOINT"
                )
            })?;
            let connection = ConnectionOptions {
                tls_ca: cli.tls_ca,
                tls_cert: cli.tls_cert,
                tls_key: cli.tls_key,
            };

            openshell_e2e::conformance::conformance_run(
                &gateway_endpoint,
                &connection,
                filter.as_deref(),
                timeout,
                output.as_str(),
            )
            .await
            .wrap_err_with(|| format!("conformance failed for {gateway_endpoint}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, Command, OutputFormat};
    use clap::Parser;

    #[test]
    fn list_requires_no_gateway_arguments() {
        let cli = Cli::try_parse_from(["openshell-conformance", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::List {
                output: OutputFormat::Table
            }
        ));
    }

    #[test]
    fn run_accepts_filter_timeout_and_structured_output() {
        let cli = Cli::try_parse_from([
            "openshell-conformance",
            "run",
            "--gateway-endpoint",
            "http://127.0.0.1:50051",
            "--filter",
            "lifecycle",
            "--timeout",
            "30",
            "--output",
            "json",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::Run {
                filter: Some(ref filter),
                timeout: 30,
                output: OutputFormat::Json,
            } if filter == "lifecycle"
        ));
    }
}
