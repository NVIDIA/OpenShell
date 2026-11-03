// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Backend-owned launch decoding and client construction for supervisor startup.

mod registration;
pub use registration::{BackendRegistration, BackendRegistrations, RegisteredBackendSetup};

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use miette::Result;
use openshell_core::SandboxSessionId;
use openshell_core::jwt::{SessionBearerTokenSlot, SupervisorAuthBundle};
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_isolation_interface::AgentSpec;
use openshell_isolation_interface::contract::{
    BackendDescriptor, BackendError, ResolvedWorkloadIdentity, SandboxContext, SandboxPolicy,
};
use openshell_sandbox_backend::BoundBoundary;

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

/// Runtime state remains owned by the supervisor.
///
/// Backends retain these same handles so CA publication, provider reload, and bearer rotation stay visible
/// after attachment; copying their current contents would lose later updates.
pub struct BackendServices {
    pub ca_file_paths: Arc<Mutex<Option<(PathBuf, PathBuf)>>>,
    pub provider_credentials: ProviderCredentialState,
    pub sandbox_bearer: SessionBearerTokenSlot,
    /// Gateway-granted authority to replace the generation's current owner.
    pub takeover: Option<openshell_sandbox_backend::BoundaryTakeover>,
    /// Recovery deadline (seconds) offered to the runtime at every attach.
    pub supervisor_recovery_timeout_secs: Option<u32>,
}

/// Startup result; native payload decoding never reaches shared runtime
/// descriptors or the public isolation interface.
pub struct BuiltBackend {
    pub backend: Arc<openshell_sandbox_backend::OpenShellRuntimeBackend>,
    pub payload: Vec<u8>,
    pub proxy_listener: Option<openshell_supervisor_network::run::ProxyListenerConfig>,
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
    ) -> std::result::Result<BuiltBackend, BackendError>;
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
    /// shared services. Client validation rejects a differently named endpoint selection.
    pub async fn attach(
        mut self,
        services: BackendServices,
        policy: SandboxPolicy,
        agent: AgentSpec,
    ) -> Result<(
        Box<BoundBoundary>,
        Option<openshell_supervisor_network::run::ProxyListenerConfig>,
    )> {
        let built = self
            .prepared
            .build(services)
            .map_err(|error| miette::miette!(error.to_string()))?;
        self.descriptor.payload = built.payload;
        if built.backend.backend_name() != self.descriptor.backend_name {
            return Err(miette::miette!(
                "RPC client backend does not match admitted backend"
            ));
        }
        let backend = built.backend;
        let bound = backend
            .attach(
                self.descriptor,
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
        Ok((bound, built.proxy_listener))
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
        let transport = openshell_sandbox_backend::BoundaryTransport::for_descriptor(&descriptor)?;
        Ok((
            identity,
            Box::new(OpenShellLaunch {
                descriptor,
                transport,
            }),
        ))
    }
}

/// The built-in Sandbox Protocol for one sandbox instance of a shared
/// supervisor.
///
/// The descriptor must use the routed transport for exactly `route`;
/// decoding claims that route on the shared listener for as long as the
/// instance's backend exists.
pub struct RoutedBackendSetup {
    router: Arc<openshell_sandbox_backend::runtime_routed::RuntimeRouter>,
    route: String,
}

impl RoutedBackendSetup {
    #[must_use]
    pub fn new(
        router: Arc<openshell_sandbox_backend::runtime_routed::RuntimeRouter>,
        route: String,
    ) -> Self {
        Self { router, route }
    }
}

impl BackendSetup for RoutedBackendSetup {
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
        openshell_sandbox_backend::validate_runtime_coordinates(&descriptor)?;
        let registration = self.router.register(&self.route, &descriptor.tls)?;
        let transport =
            openshell_sandbox_backend::BoundaryTransport::routed(&descriptor, registration)?;
        let identity = LaunchIdentity {
            sandbox_id: descriptor.boundary_id.clone(),
            generation: descriptor.generation.clone(),
            session_id: descriptor.session_id,
            workload_identity: descriptor.workload_identity.clone(),
            vm_policy_identity: None,
        };
        Ok((
            identity,
            Box::new(OpenShellLaunch {
                descriptor,
                transport,
            }),
        ))
    }
}

/// Launch data plus the transport chosen for it. Discovery and the attached
/// backend use clones of one transport, so a runtime-initiated descriptor binds
/// its control listener once for the supervisor's lifetime.
struct OpenShellLaunch {
    descriptor: openshell_sandbox_backend::boundary_protocol::SandboxRuntimeDescriptor,
    transport: openshell_sandbox_backend::BoundaryTransport,
}

#[tonic::async_trait]
impl PreparedBackend for OpenShellLaunch {
    async fn discover_policy(
        &self,
        bearer: SessionBearerTokenSlot,
    ) -> std::result::Result<(Option<String>, bool), BackendError> {
        openshell_sandbox_backend::OpenShellRuntimeBackend::discover_policy(
            self.descriptor.clone(),
            bearer,
            self.transport.clone(),
        )
        .await
    }

    fn build(
        self: Box<Self>,
        services: BackendServices,
    ) -> std::result::Result<BuiltBackend, BackendError> {
        let payload = self.descriptor.backend_descriptor()?.payload;
        let mut backend = openshell_sandbox_backend::OpenShellRuntimeBackend::new(
            services.ca_file_paths,
            services.provider_credentials,
            services.sandbox_bearer,
        )
        .with_transport(self.transport)
        .with_recovery_timeout_secs(services.supervisor_recovery_timeout_secs);
        if let Some(takeover) = services.takeover {
            backend = backend.with_takeover(takeover);
        }
        Ok(BuiltBackend {
            payload,
            proxy_listener: None,
            backend: Arc::new(backend),
        })
    }
}

#[cfg(test)]
mod tests;
