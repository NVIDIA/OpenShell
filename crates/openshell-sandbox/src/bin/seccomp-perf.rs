// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Microbenchmark entry point for the production seccomp network broker.

use std::net::SocketAddr;

use clap::{Parser, Subcommand};
use openshell_sandbox::perf::{BenchmarkOptions, Layer, Protocol};

#[derive(Debug, Parser)]
#[command(
    about = "Measure native and seccomp-filtered socket performance",
    long_about = "Measure native and seccomp-filtered socket performance. UDP unconnected means destination-bearing SOCK_DGRAM traffic, not SOCK_RAW. General external UDP and SOCK_RAW are currently denied by the sandbox."
)]
struct Cli {
    /// Benchmark layer: native, filtered, or all.
    #[arg(long, default_value = "all", value_parser = ["native", "filtered", "all"])]
    layer: String,
    /// Protocol: tcp-connect, tcp-stream, udp-connected, udp-unconnected, or all.
    #[arg(
        long,
        default_value = "all",
        value_parser = ["tcp-connect", "tcp-stream", "udp-connected", "udp-unconnected", "all"]
    )]
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
