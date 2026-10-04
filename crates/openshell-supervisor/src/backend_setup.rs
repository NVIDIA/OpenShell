// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Backend-owned launch decoding and client construction for supervisor startup.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use miette::Result;
use openshell_core::SandboxSessionId;
use openshell_core::jwt::{SessionBearerTokenSlot, SupervisorAuthBundle};
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_isolation_interface::AgentSpec;
use openshell_isolation_interface::contract::{
    BackendDescriptor, BackendError, BackendRegistry, BoundBoundary, ConfirmedBoundary,
    IsolationBackend, NetworkMediationSource, ResolvedWorkloadIdentity, RunningBoundary,
    SandboxContext, SandboxPolicy,
};

/// Coordinates decoded by the selected trusted backend. Shared startup checks
/// these against admission before credentials or discovery reach that backend.
pub struct LaunchIdentity {
    pub sandbox_id: String,
    pub generation: String,
    pub session_id: SandboxSessionId,
    pub workload_identity: ResolvedWorkloadIdentity,
    /// Preserve driver-fixed VM selectors during shared startup and reload.
    pub vm_policy_identity: Option<super::VmPolicyIdentity>,
}

/// Runtime state remains owned by the supervisor. Backends retain these same
/// handles so CA publication, provider reload, and bearer rotation stay visible
/// after attachment; copying their current contents would lose later updates.
pub struct BackendServices {
    pub ca_file_paths: Arc<Mutex<Option<(PathBuf, PathBuf)>>>,
    pub provider_credentials: ProviderCredentialState,
    pub sandbox_bearer: SessionBearerTokenSlot,
}

/// Selected by trusted composition, never by payload contents. Decoding and
/// construction may prepare a client but must not launch workload code.
pub trait BackendSetup: Sync {
    /// Name chosen by trusted composition and checked against admission before decoding.
    fn backend_name(&self) -> &str;

    /// Decode native launch data without starting workload code. The returned
    /// identity must describe the same resource retained by the prepared backend.
    fn decode(
        &self,
        payload: &[u8],
    ) -> std::result::Result<(LaunchIdentity, Box<dyn PreparedBackend>), BackendError>;
}

/// Native launch data stays with its backend until client construction. Shared
/// startup admits policy and credentials between discovery and attachment.
#[tonic::async_trait]
pub trait PreparedBackend: Send + Sync {
    /// Read image policy through the backend's authenticated client. An invalid
    /// or unreadable policy must return the invalid flag or an error, never missing.
    async fn discover_policy(
        &self,
        bearer: SessionBearerTokenSlot,
    ) -> std::result::Result<(Option<String>, bool), BackendError>;

    /// Consume prepared launch data and retain the supervisor's live handles.
    /// Construction does not attach the resource or start workload code.
    fn build(
        self: Box<Self>,
        services: BackendServices,
    ) -> std::result::Result<Arc<dyn IsolationBackend>, BackendError>;
}

/// Created only after name and launch identity checks. Consuming attachment
/// prevents reusing one prepared startup to build or attach a second client.
pub struct SelectedBackend {
    descriptor: BackendDescriptor,
    identity: LaunchIdentity,
    prepared: Box<dyn PreparedBackend>,
}

impl SelectedBackend {
    /// Reject absent or mismatched admission before decoding, then bind the
    /// decoded sandbox, session, and generation to trusted launch inputs.
    pub fn select(
        setup: &dyn BackendSetup,
        descriptor: BackendDescriptor,
        admitted_backend: Option<&str>,
        sandbox_id: Option<&str>,
        auth: &SupervisorAuthBundle,
    ) -> Result<Self> {
        let admitted_backend = admitted_backend.ok_or_else(|| {
            miette::miette!("runtime descriptor supplied without an admitted isolation backend")
        })?;
        if descriptor.backend_name != admitted_backend {
            return Err(miette::miette!(
                "descriptor backend {:?} does not match admitted backend {admitted_backend:?}",
                descriptor.backend_name
            ));
        }
        if setup.backend_name() != admitted_backend {
            return Err(miette::miette!(
                "selected backend {:?} does not match admitted backend {admitted_backend:?}",
                setup.backend_name()
            ));
        }

        let (identity, prepared) = setup
            .decode(&descriptor.payload)
            .map_err(|error| miette::miette!(error.to_string()))?;
        if sandbox_id.is_none_or(|id| id.is_empty() || identity.sandbox_id != id) {
            return Err(miette::miette!(
                "runtime descriptor does not match admitted sandbox"
            ));
        }
        if identity.session_id != auth.session_id {
            return Err(miette::miette!(
                "supervisor authentication bundle does not match runtime session"
            ));
        }
        if identity.generation != auth.runtime_generation.as_str() {
            return Err(miette::miette!(
                "supervisor authentication bundle does not match runtime generation"
            ));
        }
        Ok(Self {
            descriptor,
            identity,
            prepared,
        })
    }

    /// Return the backend name already matched to the admitted selection.
    pub fn backend_name(&self) -> &str {
        &self.descriptor.backend_name
    }

    /// Carry the selected backend's VM identity constraint into policy handling.
    pub fn vm_policy_identity(&self) -> Option<super::VmPolicyIdentity> {
        self.identity.vm_policy_identity
    }

    /// Delegate image discovery only after shared name and identity checks.
    /// Callers may retry this read; discovery cannot authorize workload launch.
    pub async fn discover_policy(
        &self,
        bearer: SessionBearerTokenSlot,
    ) -> Result<(Option<String>, bool)> {
        self.prepared
            .discover_policy(bearer)
            .await
            .map_err(|error| miette::miette!("discover workload image policy: {error}"))
    }

    /// Construct and attach the selected client using the admitted policy and
    /// shared services. Registry verification rejects a differently named client.
    pub async fn attach(
        self,
        services: BackendServices,
        policy: SandboxPolicy,
        agent: AgentSpec,
    ) -> Result<BoundBackend> {
        let backend = self
            .prepared
            .build(services)
            .map_err(|error| miette::miette!(error.to_string()))?;
        let mut registry = BackendRegistry::new();
        registry
            .register(backend)
            .map_err(|error| miette::miette!(error.to_string()))?;
        let admitted_backend = self.descriptor.backend_name.clone();
        let (backend, verified) = registry
            .resolve(self.descriptor, &admitted_backend)
            .map_err(|error| miette::miette!(error.to_string()))?;
        let bound = backend
            .attach(
                verified,
                SandboxContext {
                    sandbox_id: self.identity.sandbox_id,
                    session_id: self.identity.session_id,
                    policy,
                    agent,
                    identity: self.identity.workload_identity,
                },
            )
            .await
            .map_err(|error| miette::miette!(error.to_string()))?;
        Ok(BoundBackend { bound })
    }
}

/// The shared startup sequence owns when attachment advances to confirmation.
/// Retain network handles before consuming the bound state, as the contract
/// requires, without exposing the concrete backend to the supervisor.
pub struct BoundBackend {
    bound: Box<dyn BoundBoundary>,
}

impl BoundBackend {
    /// Retain the backend's network request source before consuming attachment.
    pub fn network_mediation_source(&self) -> Arc<dyn NetworkMediationSource> {
        self.bound.network_mediation_source()
    }

    /// Return the backend's trusted host dial address, if one is required.
    pub fn host_gateway_ip(&self) -> Option<std::net::IpAddr> {
        self.bound.host_gateway_ip()
    }

    /// Consume attachment and require the backend's validated enforcement
    /// confirmation. A failure returns no state capable of starting the agent.
    pub async fn confirm(self) -> Result<ReadyBackend> {
        let confirmed = self
            .bound
            .confirm()
            .await
            .map_err(|error| miette::miette!(error.to_string()))?;
        Ok(ReadyBackend { confirmed })
    }
}

/// Shared startup retains confirmation while preparing networking. Only this
/// consumed state can invoke the backend's workload launch operation.
pub struct ReadyBackend {
    confirmed: ConfirmedBoundary,
}

impl ReadyBackend {
    /// Consume confirmation and start the workload once shared networking is
    /// ready. Backend launch failure does not restore a reusable ready state.
    pub async fn start_agent(self) -> Result<Box<dyn RunningBoundary>> {
        self.confirmed
            .into_boundary()
            .start_agent()
            .await
            .map_err(|error| miette::miette!(error.to_string()))
    }
}

/// The standard binary selects the `OpenShell` Sandbox Protocol. Its wire schema
/// and concrete client stay here rather than in the shared startup sequence.
pub struct OpenShellBackendSetup;

impl BackendSetup for OpenShellBackendSetup {
    fn backend_name(&self) -> &str {
        openshell_sandbox_backend::BACKEND_NAME
    }

    fn decode(
        &self,
        payload: &[u8],
    ) -> std::result::Result<(LaunchIdentity, Box<dyn PreparedBackend>), BackendError> {
        let descriptor: openshell_sandbox_backend::boundary_protocol::SandboxRuntimeDescriptor =
            serde_json::from_slice(payload).map_err(|error| {
                BackendError::Descriptor(format!("decode sandbox runtime descriptor: {error}"))
            })?;
        let identity = LaunchIdentity {
            sandbox_id: descriptor.boundary_id.clone(),
            generation: descriptor.generation.clone(),
            session_id: descriptor.session_id,
            workload_identity: descriptor.workload_identity.clone(),
            vm_policy_identity: descriptor
                .resource_claims
                .contains_key("vm.generation")
                .then_some(super::VmPolicyIdentity {
                    uid: descriptor.workload_identity.uid,
                    gid: descriptor.workload_identity.gid,
                }),
        };
        Ok((identity, Box::new(OpenShellLaunch(descriptor))))
    }
}

struct OpenShellLaunch(openshell_sandbox_backend::boundary_protocol::SandboxRuntimeDescriptor);

#[tonic::async_trait]
impl PreparedBackend for OpenShellLaunch {
    async fn discover_policy(
        &self,
        bearer: SessionBearerTokenSlot,
    ) -> std::result::Result<(Option<String>, bool), BackendError> {
        openshell_sandbox_backend::OpenShellRuntimeBackend::discover_policy(self.0.clone(), bearer)
            .await
    }

    fn build(
        self: Box<Self>,
        services: BackendServices,
    ) -> std::result::Result<Arc<dyn IsolationBackend>, BackendError> {
        Ok(Arc::new(
            openshell_sandbox_backend::OpenShellRuntimeBackend::new(
                services.ca_file_paths,
                services.provider_credentials,
                services.sandbox_bearer,
            ),
        ))
    }
}

#[cfg(test)]
mod tests;
