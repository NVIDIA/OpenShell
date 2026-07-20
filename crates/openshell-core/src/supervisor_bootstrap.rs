// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driver-provided supervisor bootstrap capabilities.
//!
//! These types describe the narrow interface between the gateway and compute
//! drivers for supervisors that cannot start with a gateway-minted sandbox JWT.
//! Kubernetes is the initial implementation: the driver validates projected
//! `ServiceAccount` tokens and classifies pods as already bound or warm-pending.

use tonic::Status;
use tonic::async_trait;

/// Registration-only identity for a supervisor runtime instance.
///
/// This is not a sandbox principal. The gateway may use it only on the
/// bootstrap registration path until a concrete sandbox token is minted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisorBootstrapIdentity {
    /// Driver that produced the identity, for example `kubernetes`.
    pub driver: String,
    /// Driver-native stable instance ID, for example Kubernetes pod UID.
    pub instance_id: String,
    /// Driver-native human-readable instance name, for example Kubernetes pod
    /// name.
    pub instance_name: String,
    /// Driver-native owner object name.
    pub owner_name: String,
    /// Driver-native owner object UID.
    pub owner_uid: String,
    /// Whether the instance is already bound to an `OpenShell` sandbox or is
    /// waiting for a warm-pool claim.
    pub binding: SupervisorBootstrapBinding,
}

/// Binding state returned by a driver bootstrap identity provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SupervisorBootstrapBinding {
    /// The instance is already bound to a concrete `OpenShell` sandbox.
    BoundSandbox { sandbox_id: String },
    /// The instance is valid but not yet claim-bound.
    WarmPending,
}

impl SupervisorBootstrapIdentity {
    /// Return the bound sandbox ID when the identity is already activated by
    /// driver state.
    #[must_use]
    pub fn bound_sandbox_id(&self) -> Option<&str> {
        match &self.binding {
            SupervisorBootstrapBinding::BoundSandbox { sandbox_id } => Some(sandbox_id.as_str()),
            SupervisorBootstrapBinding::WarmPending => None,
        }
    }
}

/// Driver-provided authentication for supervisor bootstrap registration.
#[async_trait]
pub trait SupervisorBootstrapIdentityProvider: Send + Sync {
    /// Authenticate a driver-native bootstrap token.
    ///
    /// `Ok(None)` means the token did not authenticate and another
    /// authenticator may try it. `Err` means authentication could not safely
    /// complete or the token was authenticated but invalid for bootstrap.
    async fn authenticate_registration(
        &self,
        token: &str,
    ) -> Result<Option<SupervisorBootstrapIdentity>, Status>;
}

/// Request sent by a driver-side warm-pool controller to activate a pending
/// bootstrap stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisorBootstrapActivationRequest {
    /// Driver that produced the pending registration.
    pub driver: String,
    /// Driver-native stable instance ID to activate.
    pub instance_id: String,
    /// `OpenShell` sandbox ID the instance should become.
    pub sandbox_id: String,
    /// Driver-native owner UID observed during claim validation.
    pub owner_uid: String,
    /// Short reason for logs and audit messages.
    pub reason: String,
}

/// Gateway-owned activation callback passed to driver-side warm-pool logic.
#[async_trait]
pub trait SupervisorBootstrapActivator: Send + Sync {
    async fn activate_registered_supervisor(
        &self,
        request: SupervisorBootstrapActivationRequest,
    ) -> Result<(), Status>;
}
