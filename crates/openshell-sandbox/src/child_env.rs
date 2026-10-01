// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub fn tls_env_vars(
    ca_cert_path: &Path,
    combined_bundle_path: &Path,
) -> [(&'static str, String); 6] {
    let ca_cert_path = ca_cert_path.display().to_string();
    let combined_bundle_path = combined_bundle_path.display().to_string();
    [
        ("NODE_EXTRA_CA_CERTS", ca_cert_path.clone()),
        ("DENO_CERT", ca_cert_path),
        ("SSL_CERT_FILE", combined_bundle_path.clone()),
        ("REQUESTS_CA_BUNDLE", combined_bundle_path.clone()),
        ("CURL_CA_BUNDLE", combined_bundle_path.clone()),
        // Ubuntu Noble's git links against libcurl-gnutls, which ignores SSL_CERT_FILE.
        // git reads GIT_SSL_CAINFO (or http.sslCAInfo) to locate the CA bundle.
        ("GIT_SSL_CAINFO", combined_bundle_path),
    ]
}

/// Shim materialized for this sandbox, or `None` when the kernel's seccomp
/// listener supports `WAIT_KILLABLE_RECV` and the broker can answer
/// `accept`/`accept4` directly.
static PRELOAD_SHIM: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Record the materialized shim path once, during sandbox startup.
pub fn set_preload_shim(path: Option<PathBuf>) {
    let _ = PRELOAD_SHIM.set(path);
}

/// Path of the materialized shim, if this sandbox installed one.
pub fn preload_shim() -> Option<&'static Path> {
    PRELOAD_SHIM.get()?.as_deref()
}

/// Build the `LD_PRELOAD` entry for a child, preserving any value the
/// workload asked for.
///
/// Children re-inherit this value when they spawn their own children, so the
/// composition must be idempotent rather than prepending on every exec.
pub fn preload_env_var(shim_path: &Path, inherited: Option<&str>) -> (&'static str, String) {
    (
        openshell_accept_shim::PRELOAD_ENV,
        openshell_accept_shim::compose_preload(&shim_path.display().to_string(), inherited),
    )
}

/// Resolve the `LD_PRELOAD` a child would inherit where the environment is
/// not cleared: an explicit workload value wins over the sandbox's own.
#[allow(clippy::implicit_hasher)]
pub fn inherited_preload(user_environment: &HashMap<String, String>) -> Option<String> {
    user_environment
        .get(openshell_accept_shim::PRELOAD_ENV)
        .cloned()
        .or_else(|| std::env::var(openshell_accept_shim::PRELOAD_ENV).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::process::Stdio;

    #[test]
    fn inherited_preload_prefers_the_workload_value() {
        let mut user_environment = HashMap::new();
        user_environment.insert("LD_PRELOAD".to_string(), "/opt/jemalloc.so".to_string());
        assert_eq!(
            inherited_preload(&user_environment).as_deref(),
            Some("/opt/jemalloc.so")
        );
        assert_eq!(inherited_preload(&HashMap::new()).as_deref(), None);
    }

    #[test]
    fn preload_env_var_keeps_a_workload_supplied_value() {
        let (key, value) = preload_env_var(Path::new("/run/openshell-compat/accept_shim.so"), None);
        assert_eq!(key, "LD_PRELOAD");
        assert_eq!(value, "/run/openshell-compat/accept_shim.so");

        let (_, value) = preload_env_var(
            Path::new("/run/openshell-compat/accept_shim.so"),
            Some("/opt/jemalloc.so"),
        );
        assert_eq!(
            value,
            "/run/openshell-compat/accept_shim.so:/opt/jemalloc.so"
        );
    }

    #[test]
    fn preload_env_var_does_not_grow_across_nested_spawns() {
        let shim = Path::new("/run/openshell-compat/accept_shim.so");
        let (_, first) = preload_env_var(shim, None);
        let (_, second) = preload_env_var(shim, Some(&first));
        assert_eq!(first, second);
    }

    #[test]
    fn apply_tls_env_sets_node_and_bundle_paths() {
        let mut cmd = Command::new("/usr/bin/env");
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let ca_cert_path = Path::new("/etc/openshell-tls/openshell-ca.pem");
        let combined_bundle_path = Path::new("/etc/openshell-tls/ca-bundle.pem");
        for (key, value) in tls_env_vars(ca_cert_path, combined_bundle_path) {
            cmd.env(key, value);
        }

        let output = cmd.output().expect("spawn env");
        let stdout = String::from_utf8(output.stdout).expect("utf8");

        assert!(stdout.contains("NODE_EXTRA_CA_CERTS=/etc/openshell-tls/openshell-ca.pem"));
        assert!(stdout.contains("DENO_CERT=/etc/openshell-tls/openshell-ca.pem"));
        assert!(stdout.contains("SSL_CERT_FILE=/etc/openshell-tls/ca-bundle.pem"));
        assert!(stdout.contains("REQUESTS_CA_BUNDLE=/etc/openshell-tls/ca-bundle.pem"));
        assert!(stdout.contains("CURL_CA_BUNDLE=/etc/openshell-tls/ca-bundle.pem"));
        assert!(stdout.contains("GIT_SSL_CAINFO=/etc/openshell-tls/ca-bundle.pem"));
    }
}
