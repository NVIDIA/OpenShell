// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Method-level allowlist for sandbox principals.
//!
//! Gateway-minted sandbox JWTs identify a single sandbox supervisor. They
//! must not authorize user-facing or admin APIs. The router rejects sandbox
//! principals for every method outside this supervisor-to-gateway allowlist;
//! handlers still perform same-sandbox checks on request bodies.
//!
//! The allowlist is derived from proto-level `(authorization)` annotations:
//! a method is callable by a sandbox principal when its declared auth mode is
//! `sandbox` or `dual`.

pub fn is_sandbox_callable(path: &str) -> bool {
    super::method_authz::is_sandbox_callable(path)
}

/// Sandbox-callable methods a `Process`-kind credential must NOT call.
///
/// These are the network-supervisor RPCs that read provider secrets or mint
/// upstream credentials. In the `proxy-pod` topology they run only in the
/// separate proxy pod (a `Full`-kind credential); the in-pod process supervisor
/// holds a `Process`-kind credential and is denied them, so a compromised agent
/// pod cannot reach provider secrets even though it holds a gateway credential.
const PROCESS_CALLER_DENIED_METHODS: &[&str] = &[
    "/openshell.v1.OpenShell/GetSandboxProviderEnvironment",
    "/openshell.v1.OpenShell/ExchangeProviderSubjectToken",
    "/openshell.inference.v1.Inference/GetInferenceBundle",
];

/// Whether `path` is denied to a `Process`-kind sandbox credential. Callers
/// apply this only after [`is_sandbox_callable`] has already passed.
#[must_use]
pub fn is_process_caller_denied(path: &str) -> bool {
    PROCESS_CALLER_DENIED_METHODS.contains(&path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_caller_is_denied_network_supervisor_rpcs() {
        for path in PROCESS_CALLER_DENIED_METHODS {
            assert!(is_process_caller_denied(path), "{path}");
            // Everything denied to a process caller must still be sandbox-callable
            // at all (a full-authority credential may call it).
            assert!(is_sandbox_callable(path), "{path}");
        }
    }

    #[test]
    fn process_caller_keeps_control_plane_rpcs() {
        for path in [
            "/openshell.v1.OpenShell/ConnectSupervisor",
            "/openshell.v1.OpenShell/RelayStream",
            "/openshell.v1.OpenShell/PushSandboxLogs",
            "/openshell.v1.OpenShell/ReportMainProcessExit",
            "/openshell.v1.OpenShell/RefreshSandboxToken",
            "/openshell.v1.OpenShell/GetSandboxConfig",
        ] {
            assert!(!is_process_caller_denied(path), "{path}");
        }
    }

    #[test]
    fn supervisor_callbacks_are_allowed() {
        assert!(is_sandbox_callable(
            "/openshell.v1.OpenShell/ConnectSupervisor"
        ));
        assert!(is_sandbox_callable("/openshell.v1.OpenShell/RelayStream"));
        assert!(is_sandbox_callable(
            "/openshell.v1.OpenShell/GetSandboxConfig"
        ));
        assert!(is_sandbox_callable(
            "/openshell.inference.v1.Inference/GetInferenceBundle"
        ));
        assert!(is_sandbox_callable(
            "/openshell.v1.OpenShell/ExchangeProviderSubjectToken"
        ));
    }

    #[test]
    fn user_and_admin_methods_are_not_allowed() {
        assert!(!is_sandbox_callable(
            "/openshell.v1.OpenShell/ListSandboxes"
        ));
        assert!(!is_sandbox_callable(
            "/openshell.v1.OpenShell/DeleteSandbox"
        ));
        assert!(!is_sandbox_callable("/openshell.v1.OpenShell/StopSandbox"));
        assert!(!is_sandbox_callable("/openshell.v1.OpenShell/StartSandbox"));
        assert!(!is_sandbox_callable(
            "/openshell.v1.OpenShell/CreateProvider"
        ));
        assert!(!is_sandbox_callable(
            "/openshell.v1.OpenShell/ApproveDraftChunk"
        ));
        assert!(!is_sandbox_callable(
            "/openshell.inference.v1.Inference/GetInferenceRoute"
        ));
        assert!(!is_sandbox_callable(
            "/openshell.inference.v1.Inference/SetInferenceRoute"
        ));
    }
}
