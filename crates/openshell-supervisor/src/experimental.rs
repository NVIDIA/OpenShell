// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Deployment bootstrap only: no sandbox admission, credentials, or session listener.

use clap::Parser;
#[cfg(unix)]
use miette::IntoDiagnostic;
use miette::Result;

#[derive(Debug, Parser)]
#[command(name = "openshell-supervisor experimental-bootstrap")]
#[command(about = "Start an idle experimental supervisor; does not accept sandbox sessions")]
struct Args {
    /// TCP port accepting connections while the process runs; reports process
    /// health, not sandbox readiness.
    #[arg(long)]
    health_port: u16,
}

pub fn run(raw_args: &[String]) -> Result<()> {
    let args = Args::parse_from(raw_args);
    run_platform(args)
}

#[cfg(unix)]
fn run_platform(args: Args) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .into_diagnostic()?;
    runtime.block_on(async {
        // Install shutdown handlers before publishing health.
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .into_diagnostic()?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .into_diagnostic()?;
        let health = openshell_supervisor::bind_readiness_tcp(args.health_port)
            .and_then(tokio::net::TcpListener::from_std)
            .into_diagnostic()?;
        eprintln!("Experimental supervisor bootstrap started; sandbox sessions are disabled");
        loop {
            tokio::select! {
                // A connection is the whole check; nothing is exchanged.
                result = health.accept() => {
                    if let Err(error) = result {
                        eprintln!("experimental supervisor health accept failed: {error}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
                _ = terminate.recv() => break,
                _ = interrupt.recv() => break,
            }
        }
        Ok(())
    })
}

#[cfg(not(unix))]
fn run_platform(_args: Args) -> Result<()> {
    Err(miette::miette!("experimental-bootstrap requires Unix"))
}
