// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Auto-bootstrap helpers for sandbox creation.
//!
//! When `sandbox create` cannot reach a gateway, these helpers determine whether
//! to attempt gateway bootstrap and execute the local or remote bootstrap flow.
//! Bootstrap proceeds automatically unless the user opts out with `--no-bootstrap`.

use std::time::Duration;

use crate::tls::{TlsOptions, grpc_client};
use miette::Result;
use owo_colors::OwoColorize;

use crate::run::{deploy_gateway_with_panel, print_deploy_summary};

/// Default gateway name used during auto-bootstrap.
const DEFAULT_GATEWAY_NAME: &str = "openshell";

/// Determines if a gRPC connection error indicates the gateway is unreachable
/// and bootstrap should be offered.
///
/// Returns `true` for connectivity errors (connection refused, timeout, DNS failure)
/// and for missing default TLS materials (which implies no gateway has been deployed).
///
/// Returns `false` for explicit TLS configuration errors, auth failures, and other
/// non-connectivity issues.
pub fn should_attempt_bootstrap(error: &miette::Report, tls: &TlsOptions) -> bool {
    // If TLS paths were explicitly provided (e.g. in tests) and they failed,
    // that's a configuration error, not a missing-gateway situation.
    if tls.has_any() {
        return is_connectivity_error(error);
    }

    // With no explicit TLS options, missing default cert files strongly implies
    // no gateway has been bootstrapped yet.
    let msg = format!("{error:?}");
    if is_missing_tls_material(&msg) {
        return true;
    }

    is_connectivity_error(error)
}

/// Check if the error message indicates missing TLS material files at default paths.
fn is_missing_tls_material(msg: &str) -> bool {
    let lower = msg.to_lowercase();
    // require_tls_materials fails with "failed to read TLS ..." when cert files are absent
    (lower.contains("failed to read tls") || lower.contains("tls ca is required"))
        && (lower.contains("no such file")
            || lower.contains("not found")
            || lower.contains("is required"))
}

/// Check if the error represents a network connectivity failure.
fn is_connectivity_error(error: &miette::Report) -> bool {
    let msg = format!("{error:?}");
    let lower = msg.to_lowercase();

    // Connection-level failures
    let connectivity_patterns = [
        "connection refused",
        "connect error",
        "tcp connect",
        "dns error",
        "name resolution",
        "no route to host",
        "network unreachable",
        "connection reset",
        "broken pipe",
        "connection timed out",
        "operation timed out",
    ];

    // TLS/auth errors that should NOT trigger bootstrap
    let non_connectivity_patterns = [
        "certificate",
        "handshake",
        "ssl",
        "tls error",
        "authorization",
        "authentication",
        "permission denied",
        "forbidden",
        "unauthorized",
    ];

    // If any non-connectivity pattern matches, don't offer bootstrap
    if non_connectivity_patterns.iter().any(|p| lower.contains(p)) {
        return false;
    }

    // Check for connectivity patterns
    connectivity_patterns.iter().any(|p| lower.contains(p))
}

/// Decide whether gateway bootstrap should proceed.
///
/// When `override_value` is `Some(false)` (from `--no-bootstrap`), returns
/// `false` to skip bootstrap. Otherwise returns `true` — a gateway is created
/// automatically without prompting the user.
pub fn confirm_bootstrap(override_value: Option<bool>) -> Result<bool> {
    if let Some(false) = override_value {
        return Ok(false);
    }
    Ok(true)
}

/// Resolve the gateway name for bootstrap.
///
/// Respects `$OPENSHELL_GATEWAY` if set, otherwise falls back to the default.
fn resolve_bootstrap_name() -> String {
    std::env::var("OPENSHELL_GATEWAY")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_GATEWAY_NAME.to_string())
}

/// Bootstrap a local gateway and return refreshed TLS options that pick up the
/// newly-written mTLS certificates, along with the gateway name used.
pub async fn run_bootstrap(
    remote: Option<&str>,
    ssh_key: Option<&str>,
    gpu: bool,
) -> Result<(TlsOptions, String, String)> {
    let gateway_name = resolve_bootstrap_name();
    let location = if remote.is_some() { "remote" } else { "local" };

    eprintln!();
    eprintln!(
        "{} No gateway found — starting one automatically.",
        "ℹ".cyan().bold()
    );
    eprintln!();
    eprintln!("  The Gateway provides a secure control plane for OpenShell. It streamlines");
    eprintln!("  access for humans and agents alike — handles sandbox orchestration, and");
    eprintln!("  enables secure, concurrent agent workflows.");
    eprintln!();
    eprintln!(
        "  Manage it later with: {} or {}",
        "openshell gateway status".bold(),
        "openshell gateway stop".bold(),
    );
    eprintln!();

    let mut options = openshell_bootstrap::DeployOptions::new(&gateway_name);
    if let Some(dest) = remote {
        let mut remote_opts = openshell_bootstrap::RemoteOptions::new(dest);
        if let Some(key) = ssh_key {
            remote_opts = remote_opts.with_ssh_key(key);
        }
        options = options.with_remote(remote_opts);
    }
    // Read registry token from environment for the auto-bootstrap path.
    // The explicit `--registry-token` flag is only on `gateway start`;
    // when bootstrapping via `sandbox create`, the env var is the mechanism.
    if let Ok(token) = std::env::var("OPENSHELL_REGISTRY_TOKEN")
        && !token.trim().is_empty()
    {
        options = options.with_registry_token(token);
    }
    options = options.with_gpu(gpu);

    let handle = deploy_gateway_with_panel(options, &gateway_name, location).await?;
    let server = handle.gateway_endpoint().to_string();

    print_deploy_summary(&gateway_name, &handle);

    // Auto-activate the bootstrapped gateway.
    if let Err(err) = openshell_bootstrap::save_active_gateway(&gateway_name) {
        tracing::debug!("failed to set active gateway after bootstrap: {err}");
    }

    // Build fresh TLS options that resolve the newly-written mTLS certs from
    // the default XDG path for this gateway, using the gateway name directly.
    let tls = TlsOptions::default()
        .with_gateway_name(&gateway_name)
        .with_default_paths(&server);

    // Wait for the gateway gRPC endpoint to accept connections before
    // handing back to the caller. The Docker health check may pass before
    // the gRPC listener is fully ready, so retry with backoff.
    wait_for_grpc_ready(&server, &tls).await?;

    Ok((tls, server, gateway_name))
}

/// Retry connecting to the gateway gRPC endpoint until it succeeds or a
/// timeout is reached. Uses exponential backoff starting at 500 ms, doubling
/// up to 4 s, with a total deadline of 30 s.
async fn wait_for_grpc_ready(server: &str, tls: &TlsOptions) -> Result<()> {
    const MAX_WAIT: Duration = Duration::from_secs(30);
    const INITIAL_BACKOFF: Duration = Duration::from_millis(500);

    let start = std::time::Instant::now();
    let mut backoff = INITIAL_BACKOFF;
    let mut last_err = None;

    while start.elapsed() < MAX_WAIT {
        match grpc_client(server, tls).await {
            Ok(_client) => return Ok(()),
            Err(err) => {
                tracing::debug!(
                    elapsed = ?start.elapsed(),
                    "gateway not yet accepting connections: {err:#}"
                );
                last_err = Some(err);
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(4));
    }

    Err(last_err
        .unwrap_or_else(|| miette::miette!("timed out waiting for gateway"))
        .wrap_err("gateway deployed but not accepting connections after 30 s"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- should_attempt_bootstrap / is_connectivity_error tests --

    fn report(msg: &str) -> miette::Report {
        miette::miette!("{}", msg)
    }

    #[test]
    fn connection_refused_triggers_bootstrap() {
        let err = report("tcp connect error: Connection refused (os error 111)");
        assert!(should_attempt_bootstrap(&err, &TlsOptions::default()));
    }

    #[test]
    fn dns_error_triggers_bootstrap() {
        let err = report("dns error: failed to lookup address information");
        assert!(should_attempt_bootstrap(&err, &TlsOptions::default()));
    }

    #[test]
    fn timeout_triggers_bootstrap() {
        let err = report("operation timed out");
        assert!(should_attempt_bootstrap(&err, &TlsOptions::default()));
    }

    #[test]
    fn no_route_triggers_bootstrap() {
        let err = report("connect error: No route to host");
        assert!(should_attempt_bootstrap(&err, &TlsOptions::default()));
    }

    #[test]
    fn network_unreachable_triggers_bootstrap() {
        let err = report("connect error: Network unreachable");
        assert!(should_attempt_bootstrap(&err, &TlsOptions::default()));
    }

    #[test]
    fn missing_default_tls_files_triggers_bootstrap() {
        let err = report(
            "failed to read TLS CA from /home/user/.config/openshell/clusters/openshell/mtls/ca.crt: No such file or directory",
        );
        assert!(should_attempt_bootstrap(&err, &TlsOptions::default()));
    }

    #[test]
    fn tls_ca_required_triggers_bootstrap() {
        let err = report("TLS CA is required for https endpoints");
        assert!(should_attempt_bootstrap(&err, &TlsOptions::default()));
    }

    #[test]
    fn certificate_error_does_not_trigger() {
        let err = report("tls handshake error: certificate verify failed");
        assert!(!should_attempt_bootstrap(&err, &TlsOptions::default()));
    }

    #[test]
    fn auth_error_does_not_trigger() {
        let err = report("authorization failed: permission denied");
        assert!(!should_attempt_bootstrap(&err, &TlsOptions::default()));
    }

    #[test]
    fn generic_error_does_not_trigger() {
        let err = report("sandbox missing from response");
        assert!(!should_attempt_bootstrap(&err, &TlsOptions::default()));
    }

    #[test]
    fn explicit_tls_with_missing_files_does_not_trigger() {
        // When the user explicitly provided TLS paths and they failed to read,
        // that's a config error, not a missing cluster.
        let tls = TlsOptions::new(
            Some("/explicit/path/ca.crt".into()),
            Some("/explicit/path/tls.crt".into()),
            Some("/explicit/path/tls.key".into()),
        );
        let err =
            report("failed to read TLS CA from /explicit/path/ca.crt: No such file or directory");
        assert!(!should_attempt_bootstrap(&err, &tls));
    }

    #[test]
    fn explicit_tls_with_connection_refused_triggers() {
        // Even with explicit TLS, a connectivity error should still trigger bootstrap.
        let tls = TlsOptions::new(
            Some("/path/ca.crt".into()),
            Some("/path/tls.crt".into()),
            Some("/path/tls.key".into()),
        );
        let err = report("tcp connect error: Connection refused");
        assert!(should_attempt_bootstrap(&err, &tls));
    }
}
