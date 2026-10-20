// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared-host placeholder: no sandbox admission, credentials, or session RPCs.

use clap::Parser;
#[cfg(unix)]
use miette::IntoDiagnostic;
use miette::Result;
use std::net::SocketAddr;

#[derive(Debug, Parser)]
#[command(name = "openshell-supervisor experimental-host")]
#[command(about = "Start a shared supervisor placeholder; sandbox sessions are not implemented")]
struct Args {
    /// Placeholder control listener; also accepts TCP process-health probes.
    #[arg(long)]
    session_control_listen: SocketAddr,
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
        let control = tokio::net::TcpListener::bind(args.session_control_listen)
            .await
            .into_diagnostic()?;
        eprintln!("Shared supervisor started; sandbox sessions are not implemented");
        loop {
            tokio::select! {
                // This placeholder only accepts and closes connections. The same
                // listener will serve session-control RPCs in the next stage.
                result = control.accept() => {
                    if let Err(error) = result {
                        eprintln!("shared supervisor control accept failed: {error}");
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
    Err(miette::miette!("experimental-host requires Unix"))
}
