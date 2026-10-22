// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Launch material and status of a sandbox instance hosted by a supervisor
//! shared by many sandboxes.
//!
//! A sandbox instance is one running generation of a stable Sandbox resource.
//! The gateway assigns instances to the shared supervisor over the private
//! `openshell.supervisor.host.v1` stream; each assignment carries one
//! instance's [`SandboxInstanceRegistration`] as JSON launch material, and the
//! host reports each instance's [`SandboxInstanceStatusReport`] back. A
//! registration grants the supervisor exactly the per-generation gateway and
//! Sandbox Protocol credentials it carries; it confers no other identity and
//! is never available to a sandbox.

use std::time::Duration;

use openshell_core::proto::supervisor_host::v1::{
    SandboxInstanceAssignment, SandboxInstancePhase, SandboxInstanceStatus,
};
use openshell_isolation_interface::contract::BackendError;
use serde::{Deserialize, Serialize};

use crate::boundary_protocol::{SandboxRuntimeDescriptor, SandboxTransport};

/// Largest launch material one assignment may carry.
pub const MAX_LAUNCH_MATERIAL_BYTES: usize = 256 * 1024;
/// Time a shared supervisor gives a withdrawn sandbox instance's workload to
/// stop before cancelling the instance.
pub const INSTANCE_REMOVAL_GRACE: Duration = Duration::from_secs(20);

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
    pub fn validate(&self) -> Result<(), BackendError> {
        crate::runtime_routed::validate_route_handle(&self.route)?;
        let descriptor = &self.runtime_descriptor;
        match &descriptor.transport {
            SandboxTransport::RuntimeInitiatedRouted { route, .. } if *route == self.route => {}
            _ => {
                return Err(BackendError::Descriptor(
                    "shared supervisor sandbox instances require this route's routed transport"
                        .to_string(),
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

    /// Encode this registration as the launch material of one assignment.
    pub fn to_assignment(&self) -> Result<SandboxInstanceAssignment, BackendError> {
        let launch_material = serde_json::to_vec(self).map_err(|error| {
            BackendError::Descriptor(format!("encode sandbox instance registration: {error}"))
        })?;
        if launch_material.len() > MAX_LAUNCH_MATERIAL_BYTES {
            return Err(BackendError::Descriptor(
                "sandbox instance launch material is too large".to_string(),
            ));
        }
        Ok(SandboxInstanceAssignment {
            route: self.route.clone(),
            sandbox_id: self.sandbox_id.clone(),
            generation: self.auth.runtime_generation.to_string(),
            launch_material,
        })
    }

    /// Decode and validate one assignment's launch material, checking that
    /// the assignment's own identifiers agree with it.
    pub fn from_assignment(assignment: &SandboxInstanceAssignment) -> Result<Self, BackendError> {
        if assignment.launch_material.len() > MAX_LAUNCH_MATERIAL_BYTES {
            return Err(BackendError::Descriptor(
                "sandbox instance launch material is too large".to_string(),
            ));
        }
        // Decoder errors can quote field values, including credentials.
        let registration: Self =
            serde_json::from_slice(&assignment.launch_material).map_err(|_| {
                BackendError::Descriptor(
                    "sandbox instance launch material is not a valid registration".to_string(),
                )
            })?;
        if registration.route != assignment.route
            || registration.sandbox_id != assignment.sandbox_id
            || registration.auth.runtime_generation.as_str() != assignment.generation
        {
            return Err(BackendError::Descriptor(
                "sandbox instance assignment does not match its launch material".to_string(),
            ));
        }
        registration.validate()?;
        Ok(registration)
    }
}

/// Lifecycle phase of a hosted sandbox instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum SandboxInstancePhaseReport {
    Starting,
    Supervising,
    Stopping,
    Exited { exit_code: i32 },
    Failed { error: String },
}

impl SandboxInstancePhaseReport {
    /// Supervision has ended and cannot resume for this generation.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Exited { .. } | Self::Failed { .. })
    }
}

/// Status of one hosted sandbox instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxInstanceStatusReport {
    pub route: String,
    pub sandbox_id: String,
    #[serde(flatten)]
    pub phase: SandboxInstancePhaseReport,
    /// The gateway currently accepts this instance's supervision.
    pub ready: bool,
}

impl SandboxInstanceStatusReport {
    /// The wire form of this report.
    #[must_use]
    pub fn to_proto(&self) -> SandboxInstanceStatus {
        let (phase, exit_code, error) = match &self.phase {
            SandboxInstancePhaseReport::Starting => {
                (SandboxInstancePhase::Starting, 0, String::new())
            }
            SandboxInstancePhaseReport::Supervising => {
                (SandboxInstancePhase::Supervising, 0, String::new())
            }
            SandboxInstancePhaseReport::Stopping => {
                (SandboxInstancePhase::Stopping, 0, String::new())
            }
            SandboxInstancePhaseReport::Exited { exit_code } => {
                (SandboxInstancePhase::Exited, *exit_code, String::new())
            }
            SandboxInstancePhaseReport::Failed { error } => {
                (SandboxInstancePhase::Failed, 0, error.clone())
            }
        };
        SandboxInstanceStatus {
            route: self.route.clone(),
            sandbox_id: self.sandbox_id.clone(),
            phase: phase.into(),
            ready: self.ready,
            exit_code,
            error,
        }
    }

    /// Read a wire status. An unknown phase reads as a failure, so a newer
    /// host can never look healthy to an older gateway.
    #[must_use]
    pub fn from_proto(status: &SandboxInstanceStatus) -> Self {
        let phase = match SandboxInstancePhase::try_from(status.phase) {
            Ok(SandboxInstancePhase::Starting) => SandboxInstancePhaseReport::Starting,
            Ok(SandboxInstancePhase::Supervising) => SandboxInstancePhaseReport::Supervising,
            Ok(SandboxInstancePhase::Stopping) => SandboxInstancePhaseReport::Stopping,
            Ok(SandboxInstancePhase::Exited) => SandboxInstancePhaseReport::Exited {
                exit_code: status.exit_code,
            },
            Ok(SandboxInstancePhase::Failed) => SandboxInstancePhaseReport::Failed {
                error: status.error.clone(),
            },
            Ok(SandboxInstancePhase::Unspecified) | Err(_) => SandboxInstancePhaseReport::Failed {
                error: "sandbox instance reported an unknown phase".to_string(),
            },
        };
        let ready = status.ready && !phase.is_terminal();
        Self {
            route: status.route.clone(),
            sandbox_id: status.sandbox_id.clone(),
            phase,
            ready,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_reports_round_trip_and_unknown_phases_fail_closed() {
        for report in [
            SandboxInstanceStatusReport {
                route: "rt-a".to_string(),
                sandbox_id: "sandbox-a".to_string(),
                phase: SandboxInstancePhaseReport::Supervising,
                ready: true,
            },
            SandboxInstanceStatusReport {
                route: "rt-a".to_string(),
                sandbox_id: "sandbox-a".to_string(),
                phase: SandboxInstancePhaseReport::Exited { exit_code: 3 },
                ready: false,
            },
            SandboxInstanceStatusReport {
                route: "rt-a".to_string(),
                sandbox_id: "sandbox-a".to_string(),
                phase: SandboxInstancePhaseReport::Failed {
                    error: "boom".to_string(),
                },
                ready: false,
            },
        ] {
            assert_eq!(
                SandboxInstanceStatusReport::from_proto(&report.to_proto()),
                report
            );
        }
        let unknown = SandboxInstanceStatus {
            route: "rt-a".to_string(),
            sandbox_id: "sandbox-a".to_string(),
            phase: 99,
            ready: true,
            exit_code: 0,
            error: String::new(),
        };
        let report = SandboxInstanceStatusReport::from_proto(&unknown);
        assert!(report.phase.is_terminal());
        assert!(!report.ready);
    }

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
