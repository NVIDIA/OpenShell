// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Launch material of a sandbox instance hosted by a supervisor shared by
//! many sandboxes.
//!
//! A sandbox instance is one running generation of a stable Sandbox resource.
//! The gateway assigns instances to the shared supervisor over the private
//! `openshell.supervisor.host.v1` stream; each assignment carries one
//! instance's [`SandboxInstanceRegistration`] as JSON launch material, which
//! the compute driver also persists with the generation so a restarted
//! gateway can recover its assignments. A registration grants the supervisor
//! exactly the per-generation gateway and Sandbox Protocol credentials it
//! carries; it confers no other identity and is never available to a sandbox.

use std::time::Duration;

use openshell_sandbox_backend::boundary_protocol::{SandboxRuntimeDescriptor, SandboxTransport};
use serde::{Deserialize, Serialize};

use crate::proto::SandboxInstanceAssignment;

/// Largest launch material one assignment may carry.
pub const MAX_LAUNCH_MATERIAL_BYTES: usize = 256 * 1024;
/// Time a shared supervisor gives a withdrawn sandbox instance's workload to
/// stop before cancelling the instance.
pub const INSTANCE_REMOVAL_GRACE: Duration = Duration::from_secs(20);

/// Why launch material was refused. The message never quotes field values,
/// which include credentials.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct RegistrationError(String);

impl RegistrationError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

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

impl RegistrationTraceContext {
    /// The trace context of the current span, for the generation created in
    /// it; `None` outside an exported trace.
    #[must_use]
    pub fn current() -> Option<Self> {
        let environment = openshell_otel::current_trace_context_environment();
        let value = |name: &str| {
            environment
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
        };
        value(openshell_otel::TRACEPARENT_ENV).map(|traceparent| Self {
            traceparent,
            tracestate: value(openshell_otel::TRACESTATE_ENV),
        })
    }
}

/// Trusted launch material for one sandbox instance on a shared supervisor.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxInstanceRegistration {
    /// Route handle the runtime names; also the instance's key on the host.
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
    /// Workload image recorded in the instance's OCSF events.
    #[serde(default)]
    pub container_image: String,
    pub proxy_ca: ProxyCaMaterial,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_context: Option<RegistrationTraceContext>,
}

impl std::fmt::Debug for SandboxInstanceRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SandboxInstanceRegistration")
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

impl SandboxInstanceRegistration {
    /// Check that every part of the registration names the same sandbox,
    /// generation, launch session, and route.
    pub fn validate(&self) -> Result<(), RegistrationError> {
        openshell_sandbox_backend::runtime_routed::validate_route_handle(&self.route)
            .map_err(|error| RegistrationError::new(error.to_string()))?;
        let descriptor = &self.runtime_descriptor;
        match &descriptor.transport {
            SandboxTransport::RuntimeInitiatedRouted { route, .. } if *route == self.route => {}
            _ => {
                return Err(RegistrationError::new(
                    "shared supervisor sandbox instances require this route's routed transport",
                ));
            }
        }
        openshell_sandbox_backend::validate_runtime_coordinates(descriptor)
            .map_err(|error| RegistrationError::new(error.to_string()))?;
        if self.sandbox_id.is_empty() || descriptor.boundary_id != self.sandbox_id {
            return Err(RegistrationError::new(
                "runtime descriptor does not match the registered sandbox",
            ));
        }
        if descriptor.generation != self.auth.runtime_generation.as_str()
            || descriptor.session_id != self.auth.session_id
        {
            return Err(RegistrationError::new(
                "launch credentials do not match the runtime generation",
            ));
        }
        self.auth
            .validate()
            .map_err(|error| RegistrationError::new(error.to_string()))?;
        openshell_core::sandbox_env::MainProcessConfig::decode(&self.main_process_spec)
            .map_err(RegistrationError::new)?;
        if self.proxy_ca.certificate_pem.is_empty()
            || self.proxy_ca.private_key_pem.expose_secret().is_empty()
        {
            return Err(RegistrationError::new("proxy CA material is required"));
        }
        Ok(())
    }

    /// Encode this registration as the launch material of one assignment.
    pub fn to_assignment(&self) -> Result<SandboxInstanceAssignment, RegistrationError> {
        let launch_material = serde_json::to_vec(self).map_err(|error| {
            RegistrationError::new(format!("encode sandbox instance registration: {error}"))
        })?;
        if launch_material.len() > MAX_LAUNCH_MATERIAL_BYTES {
            return Err(RegistrationError::new(
                "sandbox instance launch material is too large",
            ));
        }
        Ok(SandboxInstanceAssignment {
            route: self.route.clone(),
            sandbox_id: self.sandbox_id.clone(),
            generation: self.auth.runtime_generation.to_string(),
            launch_material,
        })
    }

    /// Decode persisted or transmitted launch material without validating
    /// it. Decoder errors are not reported, because they can quote field
    /// values, including credentials.
    pub fn from_launch_material(material: &[u8]) -> Result<Self, RegistrationError> {
        if material.len() > MAX_LAUNCH_MATERIAL_BYTES {
            return Err(RegistrationError::new(
                "sandbox instance launch material is too large",
            ));
        }
        serde_json::from_slice(material).map_err(|_| {
            RegistrationError::new("sandbox instance launch material is not a valid registration")
        })
    }

    /// Decode and validate one assignment's launch material, checking that
    /// the assignment's own identifiers agree with it.
    pub fn from_assignment(
        assignment: &SandboxInstanceAssignment,
    ) -> Result<Self, RegistrationError> {
        let registration = Self::from_launch_material(&assignment.launch_material)?;
        if registration.route != assignment.route
            || registration.sandbox_id != assignment.sandbox_id
            || registration.auth.runtime_generation.as_str() != assignment.generation
        {
            return Err(RegistrationError::new(
                "sandbox instance assignment does not match its launch material",
            ));
        }
        registration.validate()?;
        Ok(registration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignments_must_agree_with_their_launch_material() {
        let mismatched = SandboxInstanceAssignment {
            route: "rt-0123456789abcdef".to_string(),
            sandbox_id: "sandbox".to_string(),
            generation: "gen".to_string(),
            launch_material: b"{}".to_vec(),
        };
        let error = SandboxInstanceRegistration::from_assignment(&mismatched).unwrap_err();
        assert!(error.to_string().contains("not a valid registration"));
        let oversized = SandboxInstanceAssignment {
            launch_material: vec![b' '; MAX_LAUNCH_MATERIAL_BYTES + 1],
            ..mismatched
        };
        assert!(
            SandboxInstanceRegistration::from_assignment(&oversized)
                .unwrap_err()
                .to_string()
                .contains("too large")
        );
    }
}
