// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-level startup coverage for global network-supervisor trust material.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use rcgen::generate_simple_self_signed;
use tempfile::TempDir;

const CONFIG_FIELD: &str = "openshell.supervisor.network.additional_ca_cert_paths";

struct GatewayFixture {
    root: TempDir,
    config_path: PathBuf,
}

impl GatewayFixture {
    fn new(source_path: &Path) -> Self {
        let root = tempfile::tempdir().expect("create gateway fixture directory");
        let config_path = root.path().join("gateway.toml");
        fs::write(
            &config_path,
            format!(
                "[openshell]\nversion = 2\n\n[openshell.supervisor.network]\nadditional_ca_cert_paths = [\"{}\"]\n",
                source_path.display()
            ),
        )
        .expect("write gateway config");
        Self { root, config_path }
    }

    fn run(&self, driver: &str, socket: Option<&Path>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_openshell-gateway"));
        command
            .args([
                "--config",
                self.config_path.to_str().expect("UTF-8 config path"),
                "--db-url",
                "sqlite::memory:",
                "--disable-tls",
                "--compute-driver",
                driver,
                "--log-level",
                "info",
            ])
            .env("XDG_STATE_HOME", self.root.path().join("state"))
            .env("XDG_CONFIG_HOME", self.root.path().join("config"))
            .env_remove("RUST_LOG")
            .env_remove("OPENSHELL_DRIVERS")
            .env_remove("OPENSHELL_COMPUTE_DRIVER")
            .env_remove("OPENSHELL_COMPUTE_DRIVER_SOCKET")
            .env_remove("OPENSHELL_GATEWAY_CONFIG");
        if let Some(socket) = socket {
            command.args([
                "--compute-driver-socket",
                socket.to_str().expect("UTF-8 socket path"),
            ]);
        }
        command.output().expect("run openshell-gateway")
    }
}

fn combined_output(output: &Output) -> String {
    let raw = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let raw = raw.as_bytes();
    let mut plain = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        if raw[index] == 0x1b {
            index += 1;
            while index < raw.len() {
                let byte = raw[index];
                index += 1;
                if byte.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            plain.push(raw[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&plain)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn pem_payload_marker(pem: &str) -> &str {
    pem.lines()
        .find(|line| line.len() > 32 && !line.starts_with("-----"))
        .expect("PEM fixture payload line")
}

fn generated_certificate() -> rcgen::CertifiedKey {
    generate_simple_self_signed(vec!["destination.example".to_string()])
        .expect("generate certificate fixture")
}

#[test]
fn valid_bundle_reports_only_redacted_metadata_before_custom_driver_rejection() {
    let source_dir = tempfile::tempdir().expect("create source directory");
    let certificate = generated_certificate();
    let source_path = source_dir.path().join("destination-ca.pem");
    let pem = certificate.cert.pem();
    fs::write(&source_path, &pem).expect("write certificate fixture");
    let fixture = GatewayFixture::new(&source_path);

    let output = fixture.run("custom-driver", None);
    let diagnostic = combined_output(&output);

    assert!(!output.status.success(), "custom driver must be rejected");
    assert!(
        diagnostic.contains("Network supervisor additional destination trust configured"),
        "missing startup metadata in:\n{diagnostic}"
    );
    assert!(diagnostic.contains("certificate_count=1"), "{diagnostic}");
    assert!(diagnostic.contains("sha256:"), "{diagnostic}");
    assert!(diagnostic.contains(CONFIG_FIELD), "{diagnostic}");
    assert!(diagnostic.contains("custom-driver"), "{diagnostic}");
    assert!(diagnostic.contains("unsupported"), "{diagnostic}");
    assert!(
        !diagnostic.contains(pem_payload_marker(&pem)),
        "certificate payload leaked"
    );
}

#[test]
fn invalid_bundles_fail_startup_with_actionable_redacted_errors() {
    let source_dir = tempfile::tempdir().expect("create source directory");
    let generated = generated_certificate();
    let private_key = generated.key_pair.serialize_pem();
    let cases = [
        (
            source_dir.path().join("missing.pem"),
            None,
            "could not be read",
        ),
        (
            source_dir.path().join("empty.pem"),
            Some(String::new()),
            "contains no PEM certificate",
        ),
        (
            source_dir.path().join("private-key.pem"),
            Some(private_key.clone()),
            "contains a non-certificate PEM",
        ),
    ];

    for (source_path, contents, expected) in cases {
        if let Some(contents) = contents {
            fs::write(&source_path, contents).expect("write invalid fixture");
        }
        let fixture = GatewayFixture::new(&source_path);
        let output = fixture.run("docker", None);
        let diagnostic = combined_output(&output);

        assert!(!output.status.success(), "invalid bundle must fail startup");
        assert!(diagnostic.contains(CONFIG_FIELD), "{diagnostic}");
        assert!(
            diagnostic.contains(&source_path.display().to_string()),
            "{diagnostic}"
        );
        assert!(diagnostic.contains(expected), "{diagnostic}");
        assert!(
            !diagnostic.contains(pem_payload_marker(&private_key)),
            "private key payload leaked"
        );
        assert!(
            !diagnostic.contains("Starting OpenShell server"),
            "driver/server startup began after invalid material:\n{diagnostic}"
        );
    }
}

#[test]
fn configured_remote_endpoint_is_rejected_before_connection() {
    let source_dir = tempfile::tempdir().expect("create source directory");
    let certificate = generated_certificate();
    let source_path = source_dir.path().join("destination-ca.pem");
    fs::write(&source_path, certificate.cert.pem()).expect("write certificate fixture");
    let fixture = GatewayFixture::new(&source_path);
    let socket_path = fixture.root.path().join("must-not-connect.sock");

    let output = fixture.run("docker", Some(&socket_path));
    let diagnostic = combined_output(&output);

    assert!(!output.status.success(), "remote override must be rejected");
    assert!(diagnostic.contains(CONFIG_FIELD), "{diagnostic}");
    assert!(diagnostic.contains("unsupported remote"), "{diagnostic}");
    assert!(diagnostic.contains("endpoint"), "{diagnostic}");
    assert!(
        !diagnostic.contains("failed to create compute runtime"),
        "gateway attempted remote-driver construction:\n{diagnostic}"
    );
    assert!(
        !diagnostic.contains("No such file or directory"),
        "gateway attempted to connect to the sentinel socket:\n{diagnostic}"
    );
}
