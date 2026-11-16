// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Microbenchmark entry point for the production seccomp network broker.

// Crate-scoped: Cargo rejects mixing `[lints] workspace = true` with a
// crate-specific lint table (see #5188).
#![warn(clippy::undocumented_unsafe_blocks)]

#[cfg(target_os = "linux")]
use std::net::SocketAddr;

#[cfg(target_os = "linux")]
use clap::builder::{PossibleValue, PossibleValuesParser};
#[cfg(target_os = "linux")]
use clap::{Parser, Subcommand, ValueEnum as _};
#[cfg(target_os = "linux")]
use openshell_sandbox::perf::{BenchmarkOptions, Layer, Protocol, WorkerRun};

#[cfg(target_os = "linux")]
#[derive(Debug, Parser)]
#[command(
    about = "Measure native and seccomp-filtered socket and file-open performance",
    long_about = "Measure native and seccomp-filtered TCP socket and file-open performance.\n\n\
        Layers `notify-only` and `native-opens`, and `--landlock`, attribute the cost of a \
        workload file open; see the perf module documentation."
)]
struct Cli {
    /// Benchmark layer. `all` is native and filtered; `attribution` adds the
    /// harness-only notify-only layer and native provider-file delivery.
    #[arg(
        long,
        default_value = "all",
        value_parser = ["native", "filtered", "notify-only", "native-opens", "all", "attribution"]
    )]
    layer: String,
    /// Protocol to benchmark. `all` is the TCP pair; `file` is the file-open
    /// attribution set; `mixed` runs file opens and TCP operations at the
    /// same time, on `concurrency` threads each, and reports each class.
    #[arg(long, default_value = "all", value_parser = protocol_value_parser())]
    protocol: String,
    /// Confine each worker with a Landlock domain before it measures.
    #[arg(long)]
    landlock: bool,
    /// File the file protocols open.
    #[arg(long, default_value = "/etc/passwd")]
    file_path: std::path::PathBuf,
    /// Publish one synthetic provider file and make the file protocols open
    /// it, so the broker serves each open by injection. Requires
    /// `--layer filtered`; no other layer has virtual provider files.
    #[arg(long, conflicts_with = "file_path")]
    provider_file: bool,
    /// Size of the synthetic provider file.
    #[arg(long, default_value_t = 4_096, requires = "provider_file")]
    provider_file_bytes: usize,
    /// Experiment: request the kernel's synchronous-wakeup hint on the
    /// listener of each filtered layer. The production runtime never does.
    #[arg(long)]
    sync_wakeup: bool,
    /// Experiment: threads answering notifications in the notify-only layer.
    #[arg(long, default_value_t = 1)]
    notify_receivers: usize,
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

#[cfg(target_os = "linux")]
fn protocol_value_parser() -> PossibleValuesParser {
    let mut values = vec![
        PossibleValue::new("all"),
        PossibleValue::new("file"),
        PossibleValue::new("mixed"),
    ];
    values.extend(
        Protocol::value_variants()
            .iter()
            .filter_map(clap::ValueEnum::to_possible_value),
    );
    PossibleValuesParser::new(values)
}

#[cfg(target_os = "linux")]
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
        #[arg(long)]
        landlock: bool,
        #[arg(long, default_value = "/etc/passwd")]
        file_path: std::path::PathBuf,
        #[arg(long)]
        provider_file_bytes: Option<usize>,
    },
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if let Some(Command::Worker {
        protocol,
        target,
        iterations,
        warmup,
        concurrency,
        payload_bytes,
        landlock,
        file_path,
        provider_file_bytes,
    }) = cli.command
    {
        let reports = openshell_sandbox::perf::run_worker(&WorkerRun {
            protocol,
            target,
            iterations,
            warmup,
            concurrency,
            payload_bytes,
            landlock,
            file_path,
            provider_file_bytes,
        })?;
        for report in reports {
            println!("{}", serde_json::to_string(&report)?);
        }
        return Ok(());
    }

    let options = BenchmarkOptions {
        layers: Layer::selection(&cli.layer)?,
        protocols: Protocol::selection(&cli.protocol)?,
        iterations: cli.iterations,
        warmup: cli.warmup,
        concurrency: cli.concurrency,
        payload_bytes: cli.payload_bytes,
        landlock: cli.landlock,
        file_path: cli.file_path,
        sync_wakeup: cli.sync_wakeup,
        notify_receivers: cli.notify_receivers,
        provider_file_bytes: cli.provider_file.then_some(cli.provider_file_bytes),
    };
    for report in openshell_sandbox::perf::run(options)? {
        println!("{}", serde_json::to_string(&report)?);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("the seccomp performance harness requires Linux")
}
