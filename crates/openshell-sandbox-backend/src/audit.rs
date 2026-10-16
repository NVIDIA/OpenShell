// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Backend-selected interpretation of opaque boundary confirmation evidence.

use openshell_isolation_interface::contract::BackendError;

/// Validate native measurements required by the selected backend.
/// Implementations must reject incomplete evidence and unsupported formats.
pub trait BoundaryAuditValidator: std::fmt::Debug + Send + Sync {
    /// # Errors
    /// Returns an error when native enforcement measurements are incomplete.
    fn validate(&self, evidence: &serde_json::Value) -> Result<(), BackendError>;
}

/// Default evidence interpreter for the Linux `OpenShell` sandbox.
#[derive(Debug)]
pub struct LinuxBoundaryAuditValidator;

impl BoundaryAuditValidator for LinuxBoundaryAuditValidator {
    fn validate(&self, evidence: &serde_json::Value) -> Result<(), BackendError> {
        let audit: crate::boundary_protocol::NativeLinuxSandboxAuditEvidence =
            serde_json::from_value(evidence.clone()).map_err(|error| {
                BackendError::Confirm(format!("decode Linux sandbox audit evidence: {error}"))
            })?;
        audit.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::{BoundaryAuditValidator as _, LinuxBoundaryAuditValidator};

    #[test]
    fn default_validator_accepts_complete_linux_evidence() {
        let evidence = serde_json::json!({
                "capabilities": {"inheritable": 0, "permitted": 0, "effective": 0,
                    "bounding": 0, "ambient": 0},
                "no_new_privileges": true, "sandbox_dumpable": false,
                "child_dumpable": true, "core_limit_zero": true,
                "native_architecture": "test", "kernel_release": "test",
                "seccomp": {
                    "new_listener": true, "notification_round_trip": true,
                    "id_validation": true, "addfd_send": true,
                    "retained_socket_operation": true, "proc_fd_identity": true,
                    "task_memory_read": true, "task_memory_write": true, "cancellation": true,
                    "task_memory_writes_disabled": false
                },
                "landlock_abi": 3, "landlock_allow_deny": true,
                "udp_dns_round_trip": true, "tcp_dns_round_trip": true,
                "tcp_allow_round_trip": true, "tcp_deny_round_trip": true,
                "socket_loopback_confinement": true
        });
        LinuxBoundaryAuditValidator.validate(&evidence).unwrap();
        let mut incomplete = evidence;
        incomplete["no_new_privileges"] = false.into();
        assert!(LinuxBoundaryAuditValidator.validate(&incomplete).is_err());
    }

    #[test]
    fn default_validator_rejects_unknown_platform_and_incomplete_evidence() {
        for platform in ["windows_mxc", "unknown", "linux"] {
            let evidence = serde_json::json!({"platform": platform, "evidence": {}});
            assert!(LinuxBoundaryAuditValidator.validate(&evidence).is_err());
        }
    }
}
