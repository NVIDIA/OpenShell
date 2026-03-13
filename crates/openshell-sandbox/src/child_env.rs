// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

const LOCAL_NO_PROXY: &str = "127.0.0.1,localhost,::1";

pub(crate) fn proxy_env_vars(proxy_url: &str) -> [(&'static str, String); 9] {
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

pub(crate) fn tls_env_vars(
    ca_cert_path: &Path,
    combined_bundle_path: &Path,
) -> [(&'static str, String); 4] {
    let ca_cert_path = ca_cert_path.display().to_string();
    let combined_bundle_path = combined_bundle_path.display().to_string();
    [
        ("NODE_EXTRA_CA_CERTS", ca_cert_path.clone()),
        ("SSL_CERT_FILE", combined_bundle_path.clone()),
        ("REQUESTS_CA_BUNDLE", combined_bundle_path.clone()),
        ("CURL_CA_BUNDLE", combined_bundle_path),
    ]
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
        assert!(stdout.contains("SSL_CERT_FILE=/etc/openshell-tls/ca-bundle.pem"));
    }
}
