// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MXC registration and audit interpretation over the shared Sandbox Protocol.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use openshell_isolation_interface::contract::{
    BackendError, BoundBoundary, IsolationBackend, SandboxContext, VerifiedBackendDescriptor,
};

/// The host-side MXC isolation backend. The compute driver owns provisioning;
/// this backend owns attachment and interpretation of Windows confirmation.
#[derive(Debug)]
pub struct MxcRuntimeBackend {
    transport: openshell_sandbox_backend::OpenShellRuntimeBackend,
}

impl MxcRuntimeBackend {
    /// Compose authenticated transport with the MXC-specific evidence validator.
    #[must_use]
    pub fn new(
        ca_file_paths: Arc<Mutex<Option<(PathBuf, PathBuf)>>>,
        provider_credentials: openshell_core::provider_credentials::ProviderCredentialState,
        sandbox_bearer: openshell_core::jwt::SessionBearerTokenSlot,
    ) -> Self {
        Self {
            transport: openshell_sandbox_backend::OpenShellRuntimeBackend::new(
                ca_file_paths,
                provider_credentials,
                sandbox_bearer,
            )
            .with_audit_validator(Arc::new(crate::audit::MxcBoundaryAuditValidator)),
        }
    }
}

#[async_trait]
impl IsolationBackend for MxcRuntimeBackend {
    fn backend_name(&self) -> &str {
        crate::BACKEND_NAME
    }

    async fn attach(
        &self,
        descriptor: VerifiedBackendDescriptor,
        sandbox: SandboxContext,
    ) -> Result<Box<dyn BoundBoundary>, BackendError> {
        if descriptor.backend_name() != crate::BACKEND_NAME {
            return Err(BackendError::Descriptor(
                "MXC backend requires MXC admission".into(),
            ));
        }
        // Keep shared validation of session, generation, identity, resource
        // claims, TLS and outer-fence guarantees; only native audit differs.
        self.transport.attach(descriptor, sandbox).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_isolation_interface::contract::{BackendDescriptor, BackendRegistry};

    fn backend() -> Arc<MxcRuntimeBackend> {
        Arc::new(MxcRuntimeBackend::new(
            Arc::new(Mutex::new(None)),
            openshell_core::provider_credentials::ProviderCredentialState::from_environment(
                0,
                std::collections::HashMap::default(),
                std::collections::HashMap::default(),
                std::collections::HashMap::default(),
            ),
            openshell_core::jwt::SessionBearerTokenSlot::empty(),
        ))
    }

    #[test]
    fn registry_requires_exact_mxc_admission_and_never_falls_back() {
        let mut registry = BackendRegistry::new();
        registry.register(backend()).unwrap();
        let descriptor = || BackendDescriptor {
            backend_name: crate::BACKEND_NAME.into(),
            payload: Vec::new(),
        };
        let (selected, verified) = registry.resolve(descriptor(), crate::BACKEND_NAME).unwrap();
        assert_eq!(selected.backend_name(), "openshell-mxc");
        assert_eq!(verified.backend_name(), selected.backend_name());
        assert!(matches!(
            registry.resolve(descriptor(), "openshell-sandbox"),
            Err(BackendError::Descriptor(_))
        ));
        assert!(matches!(
            registry.resolve(
                BackendDescriptor {
                    backend_name: "openshell-sandbox".into(),
                    payload: Vec::new(),
                },
                "openshell-sandbox"
            ),
            Err(BackendError::NotRegistered(_))
        ));
    }

    #[test]
    fn duplicate_mxc_backend_registration_is_rejected() {
        let mut registry = BackendRegistry::new();
        registry.register(backend()).unwrap();
        assert!(matches!(
            registry.register(backend()),
            Err(BackendError::Descriptor(_))
        ));
    }
}
