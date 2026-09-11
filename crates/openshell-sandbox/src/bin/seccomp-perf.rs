// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Microbenchmark entry point for the production seccomp network broker.

use std::net::SocketAddr;

use clap::builder::{PossibleValue, PossibleValuesParser};
use clap::{Parser, Subcommand, ValueEnum as _};
use openshell_sandbox::perf::{BenchmarkOptions, Layer, Protocol};

#[derive(Debug, Parser)]
#[command(
    about = "Measure native and seccomp-filtered socket performance",
    long_about = "Measure native and seccomp-filtered TCP socket performance."
)]
struct Cli {
    /// Benchmark layer: native, filtered, or all.
    #[arg(long, default_value = "all", value_parser = ["native", "filtered", "all"])]
    layer: String,
    /// Implemented protocol to benchmark, or all.
    #[arg(long, default_value = "all", value_parser = protocol_value_parser())]
    protocol: String,
    #[arg(long, default_value_t = 10_000)]
    iterations: u64,
    #[arg(long, default_value_t = 1_000)]
    warmup: u64,
    #[arg(long, default_value_t = 1)]
    concurrency: usize,
    #[arg(long, default_value_t = 64)]
    payload_bytes: usize,
    #[command(subcommand)]
    command: Option<Command>,
}

fn protocol_value_parser() -> PossibleValuesParser {
    let mut values = vec![PossibleValue::new("all")];
    values.extend(
        Protocol::value_variants()
            .iter()
            .filter_map(clap::ValueEnum::to_possible_value),
    );
    PossibleValuesParser::new(values)
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(hide = true)]
    Worker {
        #[arg(long)]
        protocol: Protocol,
        #[arg(long)]
        target: SocketAddr,
        #[arg(long)]
        iterations: u64,
        #[arg(long)]
        warmup: u64,
        #[arg(long)]
        concurrency: usize,
        #[arg(long)]
        payload_bytes: usize,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if let Some(Command::Worker {
        protocol,
        target,
        iterations,
        warmup,
        concurrency,
        payload_bytes,
    }) = cli.command
    {
        let report = openshell_sandbox::perf::run_worker(
            protocol,
            target,
            iterations,
            warmup,
            concurrency,
            payload_bytes,
        )?;
        println!("{}", serde_json::to_string(&report)?);
        return Ok(());
    }

    let options = BenchmarkOptions {
        layers: Layer::selection(&cli.layer)?,
        protocols: Protocol::selection(&cli.protocol)?,
        iterations: cli.iterations,
        warmup: cli.warmup,
        concurrency: cli.concurrency,
        payload_bytes: cli.payload_bytes,
    };
    for report in openshell_sandbox::perf::run(options)? {
        println!("{}", serde_json::to_string(&report)?);
    }
    Ok(())
}
