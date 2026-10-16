// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::hash::BuildHasher;
use std::path::Path;

use openshell_core::sandbox_env::{
    OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_PROTOCOL, OTEL_EXPORTER_OTLP_TRACES_ENDPOINT,
    OTLP_RELAY_ENDPOINT,
};

/// Variables that name where an OpenTelemetry SDK exports traces. A layer of
/// the workload environment that sets one has chosen a destination.
const OTLP_ENDPOINT_VARS: [&str; 2] = [
    OTEL_EXPORTER_OTLP_ENDPOINT,
    OTEL_EXPORTER_OTLP_TRACES_ENDPOINT,
];

/// OpenTelemetry exporter variables that point agent SDKs at the
/// supervisor's OTLP relay.
///
/// Only the generic variables are set. Signal-specific variables take
/// precedence over them in every SDK, so an endpoint the workload sets later
/// at any layer, generic or traces-specific, wins over this default.
pub fn otlp_relay_env_vars() -> [(&'static str, &'static str); 2] {
    [
        (OTEL_EXPORTER_OTLP_ENDPOINT, OTLP_RELAY_ENDPOINT),
        (OTEL_EXPORTER_OTLP_PROTOCOL, "http/protobuf"),
    ]
}

/// Whether one layer of the workload environment names an OTLP endpoint,
/// generic or traces-specific.
pub fn names_otlp_endpoint<S: BuildHasher>(environment: &HashMap<String, String, S>) -> bool {
    OTLP_ENDPOINT_VARS
        .iter()
        .any(|key| environment.contains_key(*key))
}

/// Whether the relay default applies: the relay is active and no layer the
/// caller controls names an endpoint. `inherited` reports whether the
/// sandbox's own environment, which carries the image `ENV`, sets a variable.
fn relay_default_applies<S: BuildHasher>(
    relay_active: bool,
    user_environment: &HashMap<String, String, S>,
    exec_environment: &[(String, String)],
    inherited: impl Fn(&str) -> bool,
) -> bool {
    relay_active
        && !names_otlp_endpoint(user_environment)
        && !exec_environment
            .iter()
            .any(|(key, _)| OTLP_ENDPOINT_VARS.contains(&key.as_str()))
        && !OTLP_ENDPOINT_VARS.iter().any(|key| inherited(key))
}

/// Applies the relay default to `cmd` after every other layer except a
/// per-exec environment.
///
/// Nothing is injected while the relay is inactive, or when the creation
/// request (`user_environment`), the image, or `exec_environment` names an
/// endpoint: the agent then exports where it was told to, subject to the
/// sandbox's network policy and outside relay attribution. When the default
/// is injected, a traces-specific endpoint can only have come from a
/// provider, and is removed so a provider cannot redirect traces.
pub fn apply_otlp_relay_env<S: BuildHasher>(
    cmd: &mut impl EnvTarget,
    relay_active: bool,
    user_environment: &HashMap<String, String, S>,
    exec_environment: &[(String, String)],
) {
    if !relay_default_applies(relay_active, user_environment, exec_environment, |key| {
        std::env::var_os(key).is_some()
    }) {
        return;
    }
    cmd.remove_var(OTEL_EXPORTER_OTLP_TRACES_ENDPOINT);
    for (key, value) in otlp_relay_env_vars() {
        cmd.set_var(key, value);
    }
}

/// The environment-editing surface shared by `std` and `tokio` commands.
pub trait EnvTarget {
    fn set_var(&mut self, key: &str, value: &str);
    fn remove_var(&mut self, key: &str);
}

impl EnvTarget for std::process::Command {
    fn set_var(&mut self, key: &str, value: &str) {
        self.env(key, value);
    }

    fn remove_var(&mut self, key: &str) {
        self.env_remove(key);
    }
}

impl EnvTarget for tokio::process::Command {
    fn set_var(&mut self, key: &str, value: &str) {
        self.env(key, value);
    }

    fn remove_var(&mut self, key: &str) {
        self.env_remove(key);
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::process::Stdio;

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

    #[test]
    fn otlp_relay_env_points_sdks_at_the_reserved_endpoint() {
        assert_eq!(
            otlp_relay_env_vars(),
            [
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://192.0.0.8:4318"),
                ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf"),
            ]
        );
    }

    #[test]
    fn relay_default_applies_only_while_active_and_unconfigured() {
        let none: HashMap<String, String> = HashMap::new();
        let nothing_inherited = |_: &str| false;
        assert!(relay_default_applies(true, &none, &[], nothing_inherited));
        assert!(
            !relay_default_applies(false, &none, &[], nothing_inherited),
            "an inactive relay gets no default"
        );

        // Protocol or compression alone do not name a destination.
        let protocol_only = HashMap::from([(
            "OTEL_EXPORTER_OTLP_PROTOCOL".to_string(),
            "grpc".to_string(),
        )]);
        assert!(relay_default_applies(
            true,
            &protocol_only,
            &[],
            nothing_inherited
        ));

        for key in [
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
        ] {
            let value = "http://collector.example:4318".to_string();
            let declared = HashMap::from([(key.to_string(), value.clone())]);
            assert!(
                !relay_default_applies(true, &declared, &[], nothing_inherited),
                "{key} in the creation request names a destination"
            );
            assert!(
                !relay_default_applies(true, &none, &[(key.to_string(), value)], nothing_inherited),
                "{key} in the exec environment names a destination"
            );
            assert!(
                !relay_default_applies(true, &none, &[], |inherited| inherited == key),
                "{key} in the image environment names a destination"
            );
        }
    }
}
