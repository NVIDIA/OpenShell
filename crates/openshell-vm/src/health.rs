// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! gRPC health check for verifying the gateway is fully ready.
//!
//! This module provides a proper gRPC health check that verifies the gateway
//! service is not just accepting TCP connections, but is actually responding
//! to gRPC requests. This ensures we don't mark the server as ready before
//! it has fully booted.

use crate::VmError;
use openshell_core::proto::{HealthRequest, ServiceStatus, open_shell_client::OpenShellClient};
use std::path::PathBuf;
use std::time::Duration;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

/// Load mTLS materials from the gateway's cert directory.
fn load_mtls_materials(gateway_name: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let home = std::env::var("HOME").map_err(|_| "HOME not set")?;
    let mtls_dir = PathBuf::from(home)
        .join(".config/openshell/gateways")
        .join(gateway_name)
        .join("mtls");

    let ca = std::fs::read(mtls_dir.join("ca.crt"))
        .map_err(|e| format!("failed to read ca.crt: {e}"))?;
    let cert = std::fs::read(mtls_dir.join("tls.crt"))
        .map_err(|e| format!("failed to read tls.crt: {e}"))?;
    let key = std::fs::read(mtls_dir.join("tls.key"))
        .map_err(|e| format!("failed to read tls.key: {e}"))?;

    Ok((ca, cert, key))
}

/// Build a tonic TLS config from mTLS materials.
fn build_tls_config(ca: Vec<u8>, cert: Vec<u8>, key: Vec<u8>) -> ClientTlsConfig {
    let ca_cert = Certificate::from_pem(ca);
    let identity = Identity::from_pem(cert, key);
    ClientTlsConfig::new()
        .ca_certificate(ca_cert)
        .identity(identity)
}

/// Perform a gRPC health check against the gateway.
///
/// Returns `Ok(())` if the health check succeeds (service reports healthy),
/// or an error describing why the check failed.
async fn grpc_health_check(gateway_port: u16, gateway_name: &str) -> Result<(), String> {
    // Load mTLS materials
    let (ca, cert, key) = load_mtls_materials(gateway_name)?;
    let tls_config = build_tls_config(ca, cert, key);

    // Build the channel with TLS
    let endpoint = format!("https://127.0.0.1:{gateway_port}");
    let channel = Endpoint::from_shared(endpoint.clone())
        .map_err(|e| format!("invalid endpoint: {e}"))?
        .connect_timeout(Duration::from_secs(5))
        .tls_config(tls_config)
        .map_err(|e| format!("TLS config error: {e}"))?
        .connect()
        .await
        .map_err(|e| format!("connection failed: {e}"))?;

    // Create client and call health
    let mut client = OpenShellClient::new(channel);
    let response = client
        .health(HealthRequest {})
        .await
        .map_err(|e| format!("health RPC failed: {e}"))?;

    let health = response.into_inner();
    if health.status == ServiceStatus::Healthy as i32 {
        Ok(())
    } else {
        Err(format!("service not healthy: status={}", health.status))
    }
}

/// Default health check timeout for standard (non-GPU) VMs.
const DEFAULT_HEALTH_TIMEOUT_SECS: u64 = 90;

/// Extended health check timeout for GPU-enabled VMs.
///
/// Cold boot with GPU passthrough involves pulling container images (no layer
/// cache on a fresh state disk) and loading NVIDIA drivers/firmware, which
/// legitimately takes longer than a standard VM boot.
const GPU_HEALTH_TIMEOUT_SECS: u64 = 240;

/// Initial poll interval between health check attempts.
const INITIAL_POLL_INTERVAL_SECS: u64 = 2;

/// Maximum poll interval (exponential backoff cap).
const MAX_POLL_INTERVAL_SECS: u64 = 10;

/// How often to emit a progress log line during the health check wait.
const PROGRESS_LOG_INTERVAL_SECS: u64 = 15;

/// Wait for the gateway service to be fully ready by polling the gRPC health endpoint.
///
/// This replaces the TCP-only probe with a proper gRPC health check that verifies
/// the service is actually responding to requests, not just accepting connections.
///
/// When `gpu_enabled` is true, the timeout is extended to accommodate cold-boot
/// scenarios where container image pulls and NVIDIA driver/firmware loading push
/// total startup well past the standard 90-second window.
///
/// Uses exponential backoff between retry attempts (2s initial, 10s cap) to
/// avoid hammering the endpoint while still detecting readiness promptly.
///
/// Returns `Ok(())` when the gateway is confirmed healthy, or `Err` if the health
/// check fails or times out. Falls back to TCP probe if mTLS materials aren't
/// available yet.
pub fn wait_for_gateway_ready(
    gateway_port: u16,
    gateway_name: &str,
    gpu_enabled: bool,
) -> Result<(), VmError> {
    let start = std::time::Instant::now();
    let timeout_secs = if gpu_enabled {
        GPU_HEALTH_TIMEOUT_SECS
    } else {
        DEFAULT_HEALTH_TIMEOUT_SECS
    };
    let timeout = Duration::from_secs(timeout_secs);
    let mut poll_interval = Duration::from_secs(INITIAL_POLL_INTERVAL_SECS);
    let max_poll_interval = Duration::from_secs(MAX_POLL_INTERVAL_SECS);
    let progress_interval = Duration::from_secs(PROGRESS_LOG_INTERVAL_SECS);

    eprintln!(
        "Waiting for gateway gRPC health check (timeout {timeout_secs}s{})...",
        if gpu_enabled { ", GPU mode" } else { "" }
    );

    // Create a runtime for async health checks
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("  failed to create tokio runtime: {e}, falling back to TCP probe");
            return wait_for_tcp_only(gateway_port, timeout, poll_interval);
        }
    };

    let mut attempt: u32 = 0;
    let mut last_progress_log = start;
    // The initial value is never read (overwritten on each loop iteration before
    // the progress log), but we need a valid String to satisfy the borrow checker.
    #[allow(unused_assignments)]
    let mut last_error = String::new();

    loop {
        attempt += 1;

        // Try gRPC health check
        let result = rt.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(5),
                grpc_health_check(gateway_port, gateway_name),
            )
            .await
        });

        match result {
            Ok(Ok(())) => {
                eprintln!("Gateway healthy [{:.1}s]", start.elapsed().as_secs_f64());
                return Ok(());
            }
            Ok(Err(e)) => {
                last_error = e.clone();
                // gRPC call completed but failed
                if start.elapsed() >= timeout {
                    return Err(VmError::Bootstrap(format!(
                        "gateway health check failed after {:.0}s (attempt {attempt}): {e}",
                        timeout.as_secs_f64()
                    )));
                }
            }
            Err(_) => {
                last_error = "health probe timed out".to_string();
                // Timeout on the health check itself
                if start.elapsed() >= timeout {
                    return Err(VmError::Bootstrap(format!(
                        "gateway health check timed out after {:.0}s (attempt {attempt})",
                        timeout.as_secs_f64()
                    )));
                }
            }
        }

        // Periodic progress logging so operators know the check is still running
        if last_progress_log.elapsed() >= progress_interval {
            eprintln!(
                "  health check: attempt {attempt}, elapsed {:.0}s/{timeout_secs}s ({last_error})",
                start.elapsed().as_secs_f64()
            );
            last_progress_log = std::time::Instant::now();
        }

        std::thread::sleep(poll_interval);

        // Exponential backoff: double the interval up to the cap
        poll_interval = std::cmp::min(poll_interval * 2, max_poll_interval);
    }
}

/// Fallback TCP-only probe when gRPC health check can't be performed.
fn wait_for_tcp_only(
    gateway_port: u16,
    timeout: Duration,
    mut poll_interval: Duration,
) -> Result<(), VmError> {
    let start = std::time::Instant::now();
    let max_poll_interval = Duration::from_secs(MAX_POLL_INTERVAL_SECS);
    let progress_interval = Duration::from_secs(PROGRESS_LOG_INTERVAL_SECS);
    let timeout_secs = timeout.as_secs();
    let mut attempt: u32 = 0;
    let mut last_progress_log = start;

    loop {
        attempt += 1;

        if host_tcp_probe(gateway_port) {
            eprintln!(
                "Service reachable (TCP) [{:.1}s]",
                start.elapsed().as_secs_f64()
            );
            return Ok(());
        }

        if start.elapsed() >= timeout {
            return Err(VmError::Bootstrap(format!(
                "gateway TCP probe failed after {:.0}s (attempt {attempt})",
                timeout.as_secs_f64()
            )));
        }

        // Periodic progress logging
        if last_progress_log.elapsed() >= progress_interval {
            eprintln!(
                "  TCP probe: attempt {attempt}, elapsed {:.0}s/{timeout_secs}s",
                start.elapsed().as_secs_f64()
            );
            last_progress_log = std::time::Instant::now();
        }

        std::thread::sleep(poll_interval);
        poll_interval = std::cmp::min(poll_interval * 2, max_poll_interval);
    }
}

/// Probe `127.0.0.1:port` from the host to verify the TCP path is working.
///
/// This is a fallback when gRPC health check isn't available.
fn host_tcp_probe(gateway_port: u16) -> bool {
    use std::io::Read;
    use std::net::{SocketAddr, TcpStream};

    let addr: SocketAddr = ([127, 0, 0, 1], gateway_port).into();
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) else {
        return false;
    };

    // A short read timeout: if the server is alive it will wait for us
    // to send a TLS ClientHello, so the read will time out (= good).
    // If the connection resets or closes, the server is dead.
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .ok();
    let mut buf = [0u8; 1];
    match stream.read(&mut buf) {
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            true // Timeout = server alive, waiting for ClientHello.
        }
        _ => false, // Reset, EOF, or unexpected data = not healthy.
    }
}
