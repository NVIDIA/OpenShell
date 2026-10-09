// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Operator-owned endpoint registration; launch payloads never select a route.

pub use openshell_core::isolation_registration::BackendRegistration;
use openshell_sandbox_backend::DelegatedRuntimeBackend;
use openshell_sandbox_backend::boundary_protocol::SandboxRuntimeDescriptor;
use openshell_sandbox_backend::delegated::DelegatedLaunch;
use serde::Deserialize;

use super::{BackendServices, BackendSetup, LaunchIdentity, PreparedBackend};
use miette::Result;
use openshell_core::jwt::SessionBearerTokenSlot;
use openshell_isolation_interface::contract::{BackendError, IsolationBackend};
use std::sync::Arc;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendRegistrations {
    pub backends: Vec<BackendRegistration>,
}

impl BackendRegistrations {
    /// Validate the entire operator file, including unused registrations.
    pub fn validate(&self) -> Result<()> {
        openshell_core::isolation_registration::validate_registrations(&self.backends)
            .map_err(|error| miette::miette!(error))
    }

    /// Exact lookup against separately admitted identity, without fallback.
    pub fn resolve(
        &self,
        admitted_name: &str,
        launch: DelegatedLaunch,
    ) -> Result<RegisteredBackendSetup> {
        self.validate()?;
        if launch.backend_name != admitted_name {
            return Err(miette::miette!(
                "boundary launch backend name does not match admitted backend"
            ));
        }
        let registration = self
            .backends
            .iter()
            .find(|backend| backend.name == admitted_name)
            .ok_or_else(|| {
                miette::miette!("isolation backend {admitted_name:?} is not registered")
            })?;
        Ok(RegisteredBackendSetup {
            name: registration.name.clone(),
            descriptor: launch
                .runtime_descriptor(registration.endpoint.clone())
                .map_err(|error| miette::miette!(error.to_string()))?,
        })
    }
}

/// Trusted composition selected before opaque descriptor decoding or any I/O.
pub struct RegisteredBackendSetup {
    name: String,
    descriptor: SandboxRuntimeDescriptor,
}

impl BackendSetup for RegisteredBackendSetup {
    fn backend_name(&self) -> &str {
        &self.name
    }

    fn decode(
        &self,
        payload: &[u8],
    ) -> std::result::Result<(LaunchIdentity, Box<dyn PreparedBackend>), BackendError> {
        Ok((
            LaunchIdentity {
                sandbox_id: self.descriptor.boundary_id.clone(),
                generation: self.descriptor.generation.clone(),
                session_id: self.descriptor.session_id,
                workload_identity: self.descriptor.workload_identity.clone(),
                vm_policy_identity: None,
            },
            Box::new(RegisteredLaunch {
                name: self.name.clone(),
                descriptor: self.descriptor.clone(),
                payload: payload.to_vec(),
            }),
        ))
    }
}

struct RegisteredLaunch {
    name: String,
    descriptor: SandboxRuntimeDescriptor,
    payload: Vec<u8>,
}

#[tonic::async_trait]
impl PreparedBackend for RegisteredLaunch {
    async fn discover_policy(
        &self,
        bearer: SessionBearerTokenSlot,
    ) -> std::result::Result<(Option<String>, bool), BackendError> {
        DelegatedRuntimeBackend::discover_policy(
            self.name.clone(),
            self.descriptor.clone(),
            self.payload.clone(),
            bearer,
        )
        .await
    }

    fn build(
        self: Box<Self>,
        services: BackendServices,
    ) -> std::result::Result<Arc<dyn IsolationBackend>, BackendError> {
        Ok(Arc::new(DelegatedRuntimeBackend::new(
            self.name,
            self.descriptor,
            self.payload,
            services.ca_file_paths,
            services.provider_credentials,
            services.sandbox_bearer,
        )?))
    }
}
