// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared-host placeholder: no sandbox admission, credentials, or session RPCs.

#[cfg(unix)]
use miette::IntoDiagnostic;
use miette::Result;
use std::net::SocketAddr;

// The gateway endpoint is reserved for the shared supervisor's outbound session.
// This plumbing stage only starts the local listener.
pub fn run(address: SocketAddr, _gateway_endpoint: &str) -> Result<()> {
    run_platform(address)
}

#[cfg(unix)]
fn run_platform(address: SocketAddr) -> Result<()> {
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
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .into_diagnostic()?;
        eprintln!(
            "Shared supervisor started; gateway connection and sandbox sessions are not implemented"
        );
        loop {
            tokio::select! {
                // This placeholder only accepts and closes connections, including
                // health probes. Session control will use an outbound gateway stream.
                result = listener.accept() => {
                    if let Err(error) = result {
                        eprintln!("shared supervisor listener accept failed: {error}");
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
fn run_platform(_address: SocketAddr) -> Result<()> {
    Err(miette::miette!("--mode=shared requires Unix"))
}
