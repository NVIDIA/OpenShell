// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Deployment bootstrap only: no sandbox admission, credentials, or session listener.

use clap::Parser;
#[cfg(unix)]
use miette::IntoDiagnostic;
use miette::Result;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "openshell-supervisor experimental-bootstrap")]
#[command(about = "Start an idle experimental supervisor; does not accept sandbox sessions")]
struct Args {
    /// Private socket reporting process health, not sandbox readiness.
    #[arg(long)]
    health_socket: PathBuf,
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
        // The private emptyDir survives a container restart after an unclean exit.
        match std::fs::remove_file(&args.health_socket) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).into_diagnostic(),
        }
        let listener = tokio::net::UnixListener::bind(&args.health_socket).into_diagnostic()?;
        eprintln!("Experimental supervisor bootstrap started; sandbox sessions are disabled");
        let result = loop {
            tokio::select! {
                result = listener.accept() => {
                    if let Err(error) = result {
                        break Err(error).into_diagnostic();
                    }
                }
                _ = terminate.recv() => break Ok(()),
                _ = interrupt.recv() => break Ok(()),
            }
        };
        drop(listener);
        std::fs::remove_file(&args.health_socket).into_diagnostic()?;
        result
    })
}

#[cfg(not(unix))]
fn run_platform(_args: Args) -> Result<()> {
    Err(miette::miette!("experimental-bootstrap requires Unix"))
}
