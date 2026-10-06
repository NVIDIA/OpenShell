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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supervisor_callbacks_are_allowed() {
        assert!(is_sandbox_callable("/ryno.v1.Ryno/ConnectSupervisor"));
        assert!(is_sandbox_callable("/ryno.v1.Ryno/RelayStream"));
        assert!(!is_sandbox_callable("/ryno.v1.Ryno/PeerRelay"));
        assert!(is_sandbox_callable("/ryno.v1.Ryno/GetSandboxConfig"));
        assert!(is_sandbox_callable(
            "/ryno.v1.Ryno/ExchangeProviderSubjectToken"
        ));
    }

    #[test]
    fn user_and_admin_methods_are_not_allowed() {
        assert!(!is_sandbox_callable("/ryno.v1.Ryno/ListSandboxes"));
        assert!(!is_sandbox_callable("/ryno.v1.Ryno/DeleteSandbox"));
        assert!(!is_sandbox_callable("/ryno.v1.Ryno/StopSandbox"));
        assert!(!is_sandbox_callable("/ryno.v1.Ryno/StartSandbox"));
        assert!(!is_sandbox_callable("/ryno.v1.Ryno/CreateProvider"));
        assert!(!is_sandbox_callable("/ryno.v1.Ryno/ApproveDraftChunk"));
    }
}
