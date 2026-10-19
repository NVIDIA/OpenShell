// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Contract between a compute driver and a supervisor shared by sessions.
//!
//! The driver registers one runtime generation with trusted launch material
//! the gateway issued for it, reads that session's status, and removes it.
//! The exchange runs over mutually authenticated TLS with a credential
//! reserved for session admission; it is never available to a sandbox. A
//! registration grants the supervisor exactly the per-generation gateway and
//! Sandbox Protocol credentials it carries; it confers no other identity.

use std::sync::Arc;

use openshell_isolation_interface::contract::BackendError;
use serde::{Deserialize, Serialize};

use crate::boundary_protocol::{SandboxRuntimeDescriptor, SandboxTransport};

/// Collection path of the session-control API; a session is `{prefix}/{route}`.
pub const SESSIONS_PATH: &str = "/v1/sessions";
/// Largest registration body a supervisor accepts.
pub const MAX_REGISTRATION_BYTES: usize = 256 * 1024;

/// PEM private key that never appears in `Debug` output.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretPem(String);

impl SecretPem {
    #[must_use]
    pub fn new(pem: String) -> Self {
        Self(pem)
    }

    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretPem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretPem([REDACTED])")
    }
}

/// Proxy interception CA issued for one generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyCaMaterial {
    pub certificate_pem: String,
    pub private_key_pem: SecretPem,
}

/// W3C trace context of the operation that created the generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationTraceContext {
    pub traceparent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracestate: Option<String>,
}

/// Trusted launch material for one runtime generation on a shared supervisor.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRegistration {
    /// Route handle the runtime names; also the session's key on the host.
    pub route: String,
    pub sandbox_id: String,
    pub sandbox_name: String,
    /// Supervisor-side launch descriptor using the routed transport.
    pub runtime_descriptor: SandboxRuntimeDescriptor,
    /// Gateway-issued credentials for exactly this generation.
    pub auth: openshell_core::jwt::SupervisorAuthBundle,
    /// Encoded `MainProcessConfig` for the canonical process.
    pub main_process_spec: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    /// Workload image recorded in the session's OCSF events.
    #[serde(default)]
    pub container_image: String,
    pub proxy_ca: ProxyCaMaterial,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_context: Option<RegistrationTraceContext>,
}

impl std::fmt::Debug for SessionRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionRegistration")
            .field("route", &self.route)
            .field("sandbox_id", &self.sandbox_id)
            .field("sandbox_name", &self.sandbox_name)
            .field("runtime_descriptor", &self.runtime_descriptor)
            .field("auth", &self.auth)
            .field("workdir", &self.workdir)
            .field("container_image", &self.container_image)
            .finish_non_exhaustive()
    }
}

impl SessionRegistration {
    /// Check that every part of the registration names the same sandbox,
    /// generation, launch session, and route.
    pub fn validate(&self) -> Result<(), BackendError> {
        crate::runtime_routed::validate_route_handle(&self.route)?;
        let descriptor = &self.runtime_descriptor;
        match &descriptor.transport {
            SandboxTransport::RuntimeInitiatedRouted { route, .. } if *route == self.route => {}
            _ => {
                return Err(BackendError::Descriptor(
                    "shared supervisor sessions require this route's routed transport".to_string(),
                ));
            }
        }
        crate::runtime::validate_runtime_coordinates(descriptor)?;
        if self.sandbox_id.is_empty() || descriptor.boundary_id != self.sandbox_id {
            return Err(BackendError::Descriptor(
                "runtime descriptor does not match the registered sandbox".to_string(),
            ));
        }
        if descriptor.generation != self.auth.runtime_generation.as_str()
            || descriptor.session_id != self.auth.session_id
        {
            return Err(BackendError::Descriptor(
                "launch credentials do not match the runtime generation".to_string(),
            ));
        }
        self.auth
            .validate()
            .map_err(|error| BackendError::Descriptor(error.to_string()))?;
        openshell_core::sandbox_env::MainProcessConfig::decode(&self.main_process_spec)
            .map_err(BackendError::Descriptor)?;
        if self.proxy_ca.certificate_pem.is_empty()
            || self.proxy_ca.private_key_pem.expose_secret().is_empty()
        {
            return Err(BackendError::Descriptor(
                "proxy CA material is required".to_string(),
            ));
        }
        Ok(())
    }
}

/// Lifecycle phase of a hosted session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum SessionPhaseReport {
    Starting,
    Supervising,
    Stopping,
    Exited { exit_code: i32 },
    Failed { error: String },
}

impl SessionPhaseReport {
    /// Supervision has ended and cannot resume for this generation.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Exited { .. } | Self::Failed { .. })
    }
}

/// Status of one hosted session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStatusReport {
    pub route: String,
    pub sandbox_id: String,
    #[serde(flatten)]
    pub phase: SessionPhaseReport,
    /// The gateway currently accepts this session's supervision.
    pub ready: bool,
}

/// Every session a shared supervisor hosts.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionList {
    pub sessions: Vec<SessionStatusReport>,
}

fn pem_certificates(
    pem: &[u8],
    what: &str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, BackendError> {
    let certificates = rustls_pemfile::certs(&mut &*pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| BackendError::Descriptor(format!("parse {what}: {error}")))?;
    if certificates.is_empty() {
        return Err(BackendError::Descriptor(format!(
            "{what} contains no certificates"
        )));
    }
    Ok(certificates)
}

fn pem_private_key(pem: &[u8]) -> Result<rustls::pki_types::PrivateKeyDer<'static>, BackendError> {
    rustls_pemfile::private_key(&mut &*pem)
        .map_err(|error| {
            BackendError::Descriptor(format!("parse session-control private key: {error}"))
        })?
        .ok_or_else(|| {
            BackendError::Descriptor("session-control private key PEM is empty".to_string())
        })
}

fn root_store(ca_pem: &[u8]) -> Result<rustls::RootCertStore, BackendError> {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in pem_certificates(ca_pem, "session-control CA")? {
        roots.add(certificate).map_err(|error| {
            BackendError::Descriptor(format!("load session-control CA: {error}"))
        })?;
    }
    Ok(roots)
}

/// Server TLS for a shared supervisor: TLS 1.3, and only clients presenting a
/// certificate issued by the session-control CA.
pub fn server_tls_config(
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    client_ca_pem: &[u8],
) -> Result<Arc<rustls::ServerConfig>, BackendError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(root_store(client_ca_pem)?),
        provider.clone(),
    )
    .build()
    .map_err(|error| {
        BackendError::Descriptor(format!("build session-control client verifier: {error}"))
    })?;
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| BackendError::Descriptor(error.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            pem_certificates(certificate_pem, "session-control certificate")?,
            pem_private_key(private_key_pem)?,
        )
        .map_err(|error| {
            BackendError::Descriptor(format!("load session-control certificate: {error}"))
        })?;
    Ok(Arc::new(config))
}

/// Client TLS for a compute driver: TLS 1.3, trusting only the
/// session-control CA, and presenting the admission client certificate.
pub fn client_tls_config(
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    server_ca_pem: &[u8],
) -> Result<Arc<rustls::ClientConfig>, BackendError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| BackendError::Descriptor(error.to_string()))?
        .with_root_certificates(root_store(server_ca_pem)?)
        .with_client_auth_cert(
            pem_certificates(certificate_pem, "session-control client certificate")?,
            pem_private_key(private_key_pem)?,
        )
        .map_err(|error| {
            BackendError::Descriptor(format!("load session-control client certificate: {error}"))
        })?;
    Ok(Arc::new(config))
}
