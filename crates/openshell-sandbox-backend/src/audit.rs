// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Validation of the built-in Linux backend's audit evidence.

use openshell_isolation_interface::contract::BackendError;

/// Validate the built-in Linux backend's measured enforcement state.
/// Validate the boundary's audit evidence.
///
/// The mode comes from the TRUSTED launch descriptor's `kubevirt.workload_mode`
/// claim (never from anything the boundary reports — a sandboxed guest could
/// otherwise dodge validation by claiming to be privileged). The caller must
/// pass the mode it resolved from the descriptor.
///
/// - Sandboxed (or unknown): the full capability-free posture (zero caps,
///   `no_new_privs`, seccomp, Landlock, DNS/TCP round trips) is required.
/// - Root: the privileged evidence check — only what is still meaningful
///   for a root workload (the boundary honestly reports no caps/Landlock/
///   seccomp because none are enforced). Everything the guest reports
///   after start is advisory.
pub fn validate_native_linux_audit(
    evidence: &serde_json::Value,
    privileged: bool,
) -> Result<(), BackendError> {
    let audit: crate::boundary_protocol::NativeLinuxSandboxAuditEvidence =
        serde_json::from_value(evidence.clone()).map_err(|error| {
            BackendError::Confirm(format!("decode Linux sandbox audit evidence: {error}"))
        })?;
    if privileged {
        audit.validate_privileged()
    } else {
        audit.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::validate_native_linux_audit;

    fn root_evidence() -> serde_json::Value {
        // A privileged boundary honestly reports no caps/seccomp/Landlock:
        // none are enforced. The kernel release and architecture are
        // present (the boundary measured them from the host kernel).
        serde_json::json!({
            "capabilities": {"inheritable": 0, "permitted": 0, "effective": 0,
                             "bounding": 0, "ambient": 0},
            "no_new_privileges": false,
            "sandbox_dumpable": false,
            "child_dumpable": false,
            "core_limit_zero": true,
            "native_architecture": "x86_64",
            "kernel_release": "6.12.114-0-virt",
            "seccomp": {"new_listener": false, "notification_round_trip": false,
                        "id_validation": false, "addfd_send": false,
                        "retained_socket_operation": false,
                        "proc_fd_identity": false, "task_memory_read": false},
            "landlock_abi": 0,
            "landlock_allow_deny": false,
            "udp_dns_round_trip": false,
            "tcp_dns_round_trip": false,
            "tcp_allow_round_trip": false,
            "tcp_deny_round_trip": false,
            "socket_loopback_confinement": false
        })
    }

    #[test]
    fn root_descriptor_with_privileged_evidence_passes() {
        // The privileged mode accepts honest no-evidence reports with
        // kernel info present.
        let evidence = root_evidence();
        validate_native_linux_audit(&evidence, true).unwrap();
    }

    #[test]
    fn sandboxed_descriptor_with_privileged_evidence_fails() {
        // The sandboxed mode requires the full capability-free posture;
        // a privileged (incomplete) evidence report must be rejected.
        // This is the fail-closed direction: a sandboxed guest cannot
        // dodge validation by presenting relaxed evidence.
        let evidence = root_evidence();
        assert!(
            validate_native_linux_audit(&evidence, false).is_err(),
            "sandboxed mode must reject privileged evidence"
        );
    }

    #[test]
    fn root_descriptor_missing_kernel_info_fails() {
        // Even in root mode, the kernel release and architecture are
        // required (the boundary measured them from the host kernel).
        let mut evidence = root_evidence();
        evidence["kernel_release"] = serde_json::json!("");
        assert!(
            validate_native_linux_audit(&evidence, true).is_err(),
            "root mode must still require kernel release and architecture"
        );
    }

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
        validate_native_linux_audit(&evidence, false).unwrap();
        let mut incomplete = evidence;
        incomplete["no_new_privileges"] = false.into();
        assert!(validate_native_linux_audit(&incomplete, false).is_err());
    }

    #[test]
    fn default_validator_rejects_unknown_platform_and_incomplete_evidence() {
        for platform in ["windows_mxc", "unknown", "linux"] {
            let evidence = serde_json::json!({"platform": platform, "evidence": {}});
            assert!(validate_native_linux_audit(&evidence, false).is_err());
        }
    }
}
