// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Method-level allowlist for sandbox principals.
//!
//! Gateway-minted sandbox JWTs identify a single sandbox supervisor. They
//! must not authorize user-facing or admin APIs. The router rejects sandbox
//! principals for every method outside this supervisor-to-gateway allowlist;
//! handlers still perform same-sandbox checks on request bodies.

/// Methods a `Principal::Sandbox` may invoke.
const ALLOWED_SANDBOX_METHODS: &[&str] = &[
    "/openshell.v1.OpenShell/IssueSandboxToken",
    "/openshell.v1.OpenShell/RefreshSandboxToken",
    "/openshell.v1.OpenShell/ConnectSupervisor",
    "/openshell.v1.OpenShell/RelayStream",
    "/openshell.v1.OpenShell/GetSandboxConfig",
    "/openshell.v1.OpenShell/GetSandboxProviderEnvironment",
    "/openshell.v1.OpenShell/UpdateConfig",
    "/openshell.v1.OpenShell/ReportPolicyStatus",
    "/openshell.v1.OpenShell/PushSandboxLogs",
    "/openshell.v1.OpenShell/SubmitPolicyAnalysis",
    "/openshell.v1.OpenShell/GetDraftPolicy",
    "/openshell.inference.v1.Inference/GetInferenceBundle",
];

pub fn is_sandbox_callable(path: &str) -> bool {
    ALLOWED_SANDBOX_METHODS.contains(&path)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[test]
    fn user_and_admin_methods_are_not_allowed() {
        assert!(!is_sandbox_callable(
            "/openshell.v1.OpenShell/ListSandboxes"
        ));
        assert!(!is_sandbox_callable(
            "/openshell.v1.OpenShell/DeleteSandbox"
        ));
        assert!(!is_sandbox_callable(
            "/openshell.v1.OpenShell/CreateProvider"
        ));
        assert!(!is_sandbox_callable(
            "/openshell.v1.OpenShell/ApproveDraftChunk"
        ));
        assert!(!is_sandbox_callable(
            "/openshell.inference.v1.Inference/GetClusterInference"
        ));
        assert!(!is_sandbox_callable(
            "/openshell.inference.v1.Inference/SetClusterInference"
        ));
    }
}
