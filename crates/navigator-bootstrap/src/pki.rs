// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use miette::{IntoDiagnostic, Result, WrapErr};
use rcgen::{BasicConstraints, CertificateParams, DnType, Ia5String, IsCa, KeyPair, SanType};
use std::net::IpAddr;

/// All PEM-encoded materials produced by [`generate_pki`].
#[allow(clippy::struct_field_names)]
pub struct PkiBundle {
    pub ca_cert_pem: String,
    #[allow(dead_code)]
    pub ca_key_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
}

/// Default SANs always included on the server certificate.
const DEFAULT_SERVER_SANS: &[&str] = &[
    "openshell",
    "openshell.openshell.svc",
    "openshell.openshell.svc.cluster.local",
    "localhost",
    "host.docker.internal",
    "127.0.0.1",
];

/// Generate a complete PKI bundle: CA, server cert, and client cert.
///
/// `extra_sans` are additional Subject Alternative Names to add to the server
/// certificate (e.g. the remote host's IP or hostname for remote deployments).
///
/// Certificate validity uses the `rcgen` defaults (1975–4096), which effectively
/// never expire. This is appropriate for an internal dev-cluster PKI where certs
/// are ephemeral to the cluster's lifetime.
pub fn generate_pki(extra_sans: &[String]) -> Result<PkiBundle> {
    // --- CA ---
    let ca_key = KeyPair::generate()
        .into_diagnostic()
        .wrap_err("failed to generate CA key")?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())
        .into_diagnostic()
        .wrap_err("failed to create CA params")?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::OrganizationName, "openshell");
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "openshell-ca");

    let ca_cert = ca_params
        .self_signed(&ca_key)
        .into_diagnostic()
        .wrap_err("failed to self-sign CA certificate")?;

    // --- Server cert ---
    let server_key = KeyPair::generate()
        .into_diagnostic()
        .wrap_err("failed to generate server key")?;
    let server_sans = build_server_sans(extra_sans);
    let mut server_params = CertificateParams::new(Vec::<String>::new())
        .into_diagnostic()
        .wrap_err("failed to create server cert params")?;
    server_params.subject_alt_names = server_sans;
    server_params
        .distinguished_name
        .push(DnType::CommonName, "openshell-server");

    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .into_diagnostic()
        .wrap_err("failed to sign server certificate")?;

    // --- Client cert (shared by CLI and sandbox pods) ---
    let client_key = KeyPair::generate()
        .into_diagnostic()
        .wrap_err("failed to generate client key")?;
    let mut client_params = CertificateParams::new(Vec::<String>::new())
        .into_diagnostic()
        .wrap_err("failed to create client cert params")?;
    client_params
        .distinguished_name
        .push(DnType::CommonName, "openshell-client");

    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .into_diagnostic()
        .wrap_err("failed to sign client certificate")?;

    Ok(PkiBundle {
        ca_cert_pem: ca_cert.pem(),
        ca_key_pem: ca_key.serialize_pem(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_cert_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
    })
}

/// Build the SAN list for the server certificate from defaults + extras.
fn build_server_sans(extra_sans: &[String]) -> Vec<SanType> {
    let mut sans = Vec::new();

    for s in DEFAULT_SERVER_SANS {
        add_san(&mut sans, s);
    }
    for s in extra_sans {
        add_san(&mut sans, s);
    }

    sans
}

/// Add a SAN, automatically choosing `IpAddress` or `DnsName` based on the value.
fn add_san(sans: &mut Vec<SanType>, value: &str) {
    if let Ok(ip) = value.parse::<IpAddr>() {
        sans.push(SanType::IpAddress(ip));
    } else if let Ok(dns) = Ia5String::try_from(value) {
        sans.push(SanType::DnsName(dns));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_pki_produces_valid_pem() {
        let bundle = generate_pki(&["10.0.0.1".to_string(), "myhost.example.com".to_string()])
            .expect("generate_pki failed");

        // All PEM strings should be non-empty and contain PEM markers
        assert!(bundle.ca_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(bundle.ca_key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(bundle.server_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(bundle.server_key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(bundle.client_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(bundle.client_key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn generate_pki_no_extra_sans() {
        let bundle = generate_pki(&[]).expect("generate_pki failed");
        assert!(bundle.server_cert_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn build_server_sans_includes_defaults_and_extras() {
        let extras = vec!["192.168.1.100".to_string(), "remote.host".to_string()];
        let sans = build_server_sans(&extras);

        // Should have all default SANs + 2 extras
        assert_eq!(sans.len(), DEFAULT_SERVER_SANS.len() + 2);
    }
}
