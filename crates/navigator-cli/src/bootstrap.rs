// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Auto-bootstrap helpers for sandbox creation.
//!
//! When `sandbox create` cannot reach a cluster, these helpers determine whether
//! to offer cluster bootstrap, prompt the user for confirmation, and execute the
//! local or remote bootstrap flow.

use crate::tls::TlsOptions;
use dialoguer::Confirm;
use miette::Result;
use owo_colors::OwoColorize;
use std::io::IsTerminal;

use crate::run::{deploy_cluster_with_panel, print_deploy_summary};

/// Default cluster name used during auto-bootstrap.
const DEFAULT_CLUSTER_NAME: &str = "nemoclaw";

/// Determines if a gRPC connection error indicates the cluster is unreachable
/// and bootstrap should be offered.
///
/// Returns `true` for connectivity errors (connection refused, timeout, DNS failure)
/// and for missing default TLS materials (which implies no cluster has been deployed).
///
/// Returns `false` for explicit TLS configuration errors, auth failures, and other
/// non-connectivity issues.
pub fn should_attempt_bootstrap(error: &miette::Report, tls: &TlsOptions) -> bool {
    // If TLS paths were explicitly provided (e.g. in tests) and they failed,
    // that's a configuration error, not a missing-cluster situation.
    if tls.has_any() {
        return is_connectivity_error(error);
    }

    // With no explicit TLS options, missing default cert files strongly implies
    // no cluster has been bootstrapped yet.
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

/// Prompt the user to confirm cluster bootstrap.
///
/// When `override_value` is `Some(true)` or `Some(false)`, the decision is
/// made immediately (from `--bootstrap` / `--no-bootstrap`). Otherwise,
/// prompts interactively when stdin is a terminal, or returns an error in
/// non-interactive mode.
pub fn confirm_bootstrap(override_value: Option<bool>) -> Result<bool> {
    // Explicit flag takes precedence over interactive detection.
    if let Some(value) = override_value {
        return Ok(value);
    }

    if !std::io::stdin().is_terminal() {
        return Err(miette::miette!(
            "Gateway not reachable and bootstrap requires confirmation from an interactive terminal.\n\
              Pass --bootstrap to auto-confirm, or run 'nemoclaw gateway start' first."
        ));
    }

    let confirmed = Confirm::new()
        .with_prompt(format!(
            "{} No cluster available to launch sandbox in. Create one now?",
            "!".yellow()
        ))
        .default(true)
        .interact()
        .map_err(|e| miette::miette!("failed to read confirmation: {e}"))?;

    Ok(confirmed)
}

/// Bootstrap a local cluster and return refreshed TLS options that pick up the
/// newly-written mTLS certificates.
pub async fn run_bootstrap(
    remote: Option<&str>,
    ssh_key: Option<&str>,
) -> Result<(TlsOptions, String)> {
    let location = if remote.is_some() { "remote" } else { "local" };

    let mut options = navigator_bootstrap::DeployOptions::new(DEFAULT_CLUSTER_NAME);
    if let Some(dest) = remote {
        let mut remote_opts = navigator_bootstrap::RemoteOptions::new(dest);
        if let Some(key) = ssh_key {
            remote_opts = remote_opts.with_ssh_key(key);
        }
        options = options.with_remote(remote_opts);
    }

    let handle = deploy_cluster_with_panel(options, DEFAULT_CLUSTER_NAME, location).await?;
    let server = handle.gateway_endpoint().to_string();

    print_deploy_summary(DEFAULT_CLUSTER_NAME, &handle);

    // Auto-activate the bootstrapped cluster.
    if let Err(err) = navigator_bootstrap::save_active_cluster(DEFAULT_CLUSTER_NAME) {
        tracing::debug!("failed to set active cluster after bootstrap: {err}");
    }

    // Build fresh TLS options that resolve the newly-written mTLS certs from
    // the default XDG path for this cluster, using the cluster name directly.
    let tls = TlsOptions::default()
        .with_cluster_name(DEFAULT_CLUSTER_NAME)
        .with_default_paths(&server);

    Ok((tls, server))
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
            "failed to read TLS CA from /home/user/.config/nemoclaw/clusters/nemoclaw/mtls/ca.crt: No such file or directory",
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
