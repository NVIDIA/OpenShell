// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose};

use crate::model::{BackendError, SandboxSessionId, SandboxTlsMaterial};

/// Generate a generation-pinned TLS server identity for the Sandbox Protocol.
///
/// The CA private key is local to this function and is discarded after the
/// server leaf is signed. The JWT, rather than certificate time, determines
/// caller authorization and renewal.
pub fn generate_sandbox_tls_material(
    session_id: SandboxSessionId,
) -> Result<SandboxTlsMaterial, BackendError> {
    let server_name = format!("sandbox.{session_id}.openshell.internal");
    let ca_key = openshell_crypto::pki::generate_keypair_for(&rcgen::PKCS_ED25519)
        .map_err(|error| BackendError::Descriptor(format!("generate sandbox CA key: {error}")))?;
    let mut ca_params = CertificateParams::default();
    ca_params.not_before = rcgen::date_time_ymd(1975, 1, 1);
    ca_params.not_after = rcgen::date_time_ymd(4096, 1, 1);
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "OpenShell sandbox session CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = openshell_crypto::pki::self_signed(ca_params, &ca_key).map_err(|error| {
        BackendError::Descriptor(format!("generate sandbox CA certificate: {error}"))
    })?;

    let sandbox_key =
        openshell_crypto::pki::generate_keypair_for(&rcgen::PKCS_ED25519).map_err(|error| {
            BackendError::Descriptor(format!("generate sandbox TLS server key: {error}"))
        })?;
    let mut sandbox_params = CertificateParams::new(vec![server_name.clone()])
        .map_err(|error| BackendError::Descriptor(format!("build sandbox certificate: {error}")))?;
    sandbox_params.not_before = rcgen::date_time_ymd(1975, 1, 1);
    sandbox_params.not_after = rcgen::date_time_ymd(4096, 1, 1);
    sandbox_params
        .distinguished_name
        .push(DnType::CommonName, "OpenShell sandbox runtime");
    sandbox_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let sandbox = openshell_crypto::pki::signed_by(sandbox_params, &sandbox_key, &ca, &ca_key)
        .map_err(|error| {
            BackendError::Descriptor(format!("sign sandbox TLS server certificate: {error}"))
        })?;

    Ok(SandboxTlsMaterial {
        server_name,
        trust_anchor_pem: ca.pem(),
        certificate_chain_pem: sandbox.pem(),
        private_key_pem: sandbox_key
            .serialize_pem()
            .map_err(|error| BackendError::Descriptor(format!("export sandbox key: {error}")))?,
    })
}
