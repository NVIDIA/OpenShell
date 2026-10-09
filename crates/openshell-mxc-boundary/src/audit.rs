// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MXC-owned containment evidence and its host-side interpretation.

use openshell_isolation_interface::contract::{BackendError, BoundaryProperties, EnforcedProperty};
use openshell_sandbox_backend::audit::BoundaryAuditValidator;
use serde::{Deserialize, Serialize};

/// Windows `ProcessContainer` audit reported by the MXC boundary.
///
/// MXC supplies the outer filesystem and network fence; the in-container
/// sandbox supplies authenticated lifecycle and process I/O. Network assertions
/// currently include a temporary Windows-parity stub, not measured exclusivity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "audit evidence preserves independently measured security results"
)]
pub struct MxcSandboxAuditEvidence {
    pub process_container: bool,
    pub appcontainer_profile: String,
    pub default_deny_filesystem: bool,
    pub default_deny_egress: bool,
    pub loopback_proxy_only: bool,
    pub authenticated_control: bool,
    pub generation_scoped_attribution: bool,
}

impl MxcSandboxAuditEvidence {
    /// Validate all containment and authentication measurements.
    ///
    /// # Errors
    ///
    /// Returns an error when any required measurement is missing or failed.
    pub fn validate(&self) -> Result<(), BackendError> {
        if self.process_container
            && !self.appcontainer_profile.trim().is_empty()
            && self.default_deny_filesystem
            && self.default_deny_egress
            && self.loopback_proxy_only
            && self.authenticated_control
            && self.generation_scoped_attribution
        {
            Ok(())
        } else {
            Err(BackendError::Confirm(
                "MXC sandbox audit evidence is incomplete".to_string(),
            ))
        }
    }

    #[must_use]
    pub fn properties(&self) -> BoundaryProperties {
        BoundaryProperties {
            filesystem_confinement: EnforcedProperty::new(
                self.default_deny_filesystem,
                "mxc-processcontainer-appcontainer",
            ),
            egress_interception: EnforcedProperty::new(
                self.default_deny_egress && self.loopback_proxy_only,
                "mxc-windows-parity-unverified-egress-stub",
            ),
            request_attribution: EnforcedProperty::new(
                self.generation_scoped_attribution,
                "mxc-generation-authenticated-proxy",
            ),
            privilege_floor: EnforcedProperty::new(
                self.process_container,
                "windows-appcontainer-token",
            ),
        }
    }
}

/// MXC wire format; the generic transport does not interpret platform evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "platform", content = "evidence", rename_all = "snake_case")]
pub enum MxcBoundaryAuditEvidence {
    WindowsMxc(MxcSandboxAuditEvidence),
}

/// Host-side MXC evidence interpreter selected by Windows backend composition.
#[derive(Debug)]
pub struct MxcBoundaryAuditValidator;

impl BoundaryAuditValidator for MxcBoundaryAuditValidator {
    fn validate(&self, evidence: &serde_json::Value) -> Result<BoundaryProperties, BackendError> {
        let MxcBoundaryAuditEvidence::WindowsMxc(audit) = serde_json::from_value(evidence.clone())
            .map_err(|error| {
                BackendError::Confirm(format!("decode MXC sandbox audit evidence: {error}"))
            })?;
        audit.validate()?;
        Ok(audit.properties())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_evidence() -> serde_json::Value {
        serde_json::to_value(MxcBoundaryAuditEvidence::WindowsMxc(
            MxcSandboxAuditEvidence {
                process_container: true,
                appcontainer_profile: "measured-profile".to_string(),
                default_deny_filesystem: true,
                default_deny_egress: true,
                loopback_proxy_only: true,
                authenticated_control: true,
                generation_scoped_attribution: true,
            },
        ))
        .unwrap()
    }

    #[test]
    fn accepts_complete_evidence_and_preserves_wire_format() {
        let evidence = valid_evidence();
        assert_eq!(evidence["platform"], "windows_mxc");
        assert!(MxcBoundaryAuditValidator.validate(&evidence).is_ok());
        assert!(
            openshell_sandbox_backend::audit::LinuxBoundaryAuditValidator
                .validate(&evidence)
                .is_err()
        );
    }

    #[test]
    fn rejects_each_missing_or_failed_measurement() {
        for field in [
            "process_container",
            "default_deny_filesystem",
            "default_deny_egress",
            "loopback_proxy_only",
            "authenticated_control",
            "generation_scoped_attribution",
        ] {
            let mut evidence = valid_evidence();
            evidence["evidence"][field] = false.into();
            assert!(
                MxcBoundaryAuditValidator.validate(&evidence).is_err(),
                "{field}"
            );
            evidence["evidence"].as_object_mut().unwrap().remove(field);
            assert!(
                MxcBoundaryAuditValidator.validate(&evidence).is_err(),
                "missing {field}"
            );
        }
        for profile in ["", "   "] {
            let mut evidence = valid_evidence();
            evidence["evidence"]["appcontainer_profile"] = profile.into();
            assert!(MxcBoundaryAuditValidator.validate(&evidence).is_err());
        }
    }

    #[test]
    fn rejects_other_platforms_and_unknown_measurements() {
        for platform in ["linux", "unknown"] {
            let mut evidence = valid_evidence();
            evidence["platform"] = platform.into();
            assert!(MxcBoundaryAuditValidator.validate(&evidence).is_err());
        }
        let mut evidence = valid_evidence();
        evidence["evidence"]["unmeasured_guarantee"] = true.into();
        assert!(MxcBoundaryAuditValidator.validate(&evidence).is_err());
    }
}
