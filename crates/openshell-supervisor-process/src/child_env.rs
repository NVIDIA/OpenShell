// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::path::Path;

const LOCAL_NO_PROXY: &str = "127.0.0.1,localhost,::1";

pub fn proxy_env_vars(proxy_url: &str) -> [(&'static str, String); 9] {
    [
        ("ALL_PROXY", proxy_url.to_owned()),
        ("HTTP_PROXY", proxy_url.to_owned()),
        ("HTTPS_PROXY", proxy_url.to_owned()),
        ("NO_PROXY", LOCAL_NO_PROXY.to_owned()),
        ("http_proxy", proxy_url.to_owned()),
        ("https_proxy", proxy_url.to_owned()),
        ("no_proxy", LOCAL_NO_PROXY.to_owned()),
        ("grpc_proxy", proxy_url.to_owned()),
        // Node.js only honors HTTP(S)_PROXY for built-in fetch/http clients when
        // proxy support is explicitly enabled at process startup.
        ("NODE_USE_ENV_PROXY", "1".to_owned()),
    ]
}

/// Determines whether `OpenShell`'s generated TLS environment must override a
/// caller-provided value or merely supplies a missing default.
///
/// Proxy interception requires the `OpenShell` CA to be authoritative: replacing
/// any of these values is necessary for the workload to trust the generated
/// MITM leaf. Direct additional-destination-CA mode has no interception CA,
/// so caller-supplied values retain precedence and `OpenShell` fills only gaps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsEnvironmentMode {
    ForceOpenShell,
    FillMissing,
}

/// TLS trust variables `OpenShell` supplies to workload and SSH child processes.
pub const TLS_ENVIRONMENT_VARIABLES: [&str; 6] = [
    "NODE_EXTRA_CA_CERTS",
    "DENO_CERT",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
];

/// Whether `key` is one of the workload TLS trust variables.
pub fn is_tls_environment_variable(key: &str) -> bool {
    TLS_ENVIRONMENT_VARIABLES.contains(&key)
}

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

/// Apply child TLS environment variables according to the selected trust mode.
///
/// `user_environment` is the original sandbox environment captured by the
/// driver. It is used instead of inspecting the parent process environment so
/// SSH's `env_clear()` path and the direct entrypoint path have identical,
/// deterministic precedence rules.
pub fn tls_env_vars_for_mode<S: std::hash::BuildHasher>(
    ca_cert_path: &Path,
    combined_bundle_path: &Path,
    mode: TlsEnvironmentMode,
    user_environment: &HashMap<String, String, S>,
) -> Vec<(&'static str, String)> {
    tls_env_vars(ca_cert_path, combined_bundle_path)
        .into_iter()
        .filter(|(key, _)| {
            matches!(mode, TlsEnvironmentMode::ForceOpenShell)
                || !user_environment.contains_key(*key)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::process::Stdio;

    #[test]
    fn apply_proxy_env_includes_node_proxy_opt_in_and_local_bypass() {
        let mut cmd = Command::new("/usr/bin/env");
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        for (key, value) in proxy_env_vars("http://10.200.0.1:3128") {
            cmd.env(key, value);
        }

        let output = cmd.output().expect("spawn env");
        let stdout = String::from_utf8(output.stdout).expect("utf8");

        assert!(stdout.contains("HTTP_PROXY=http://10.200.0.1:3128"));
        assert!(stdout.contains("NO_PROXY=127.0.0.1,localhost,::1"));
        assert!(stdout.contains("NODE_USE_ENV_PROXY=1"));
        assert!(stdout.contains("no_proxy=127.0.0.1,localhost,::1"));
    }

    #[test]
    fn forced_tls_env_sets_node_and_bundle_paths() {
        let mut cmd = Command::new("/usr/bin/env");
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let ca_cert_path = Path::new("/etc/openshell-tls/openshell-ca.pem");
        let combined_bundle_path = Path::new("/etc/openshell-tls/ca-bundle.pem");
        let user_environment = tls_env_vars(ca_cert_path, combined_bundle_path)
            .into_iter()
            .map(|(key, _)| (key.to_string(), format!("/caller/{key}")))
            .collect::<HashMap<_, _>>();
        for (key, value) in &user_environment {
            cmd.env(key, value);
        }
        for (key, value) in tls_env_vars_for_mode(
            ca_cert_path,
            combined_bundle_path,
            TlsEnvironmentMode::ForceOpenShell,
            &user_environment,
        ) {
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

        let keys = tls_env_vars(ca_cert_path, combined_bundle_path).map(|(key, _)| key);
        assert!(
            !keys.contains(&openshell_core::sandbox_env::TLS_CA),
            "destination/child trust must not overwrite gateway mTLS trust"
        );
        assert_ne!(
            ca_cert_path,
            Path::new(openshell_core::container_paths::TLS_CA_MOUNT_PATH)
        );
    }

    #[test]
    fn fill_missing_tls_env_preserves_all_user_values_and_adds_only_gaps() {
        let ca_cert_path = Path::new("/etc/openshell-tls/openshell-ca.pem");
        let combined_bundle_path = Path::new("/etc/openshell-tls/ca-bundle.pem");
        let mut user_environment = HashMap::new();
        for (key, _) in tls_env_vars(ca_cert_path, combined_bundle_path) {
            user_environment.insert(key.to_string(), format!("/caller/{key}"));
        }
        // Exercise the gap separately: five values must retain their exact
        // caller values while the missing one is supplied by OpenShell.
        user_environment.remove("DENO_CERT");

        let mut cmd = Command::new("/usr/bin/env");
        cmd.env_clear();
        for (key, value) in &user_environment {
            cmd.env(key, value);
        }
        for (key, value) in tls_env_vars_for_mode(
            ca_cert_path,
            combined_bundle_path,
            TlsEnvironmentMode::FillMissing,
            &user_environment,
        ) {
            cmd.env(key, value);
        }
        let output = cmd.output().expect("spawn env");
        let stdout = String::from_utf8(output.stdout).expect("utf8");
        for (key, value) in &user_environment {
            assert!(stdout.contains(&format!("{key}={value}")), "{stdout}");
        }
        assert!(stdout.contains("DENO_CERT=/etc/openshell-tls/openshell-ca.pem"));
    }
}
