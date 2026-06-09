// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Environment-variable names used to configure the sandbox supervisor.
//!
//! These constants are the shared protocol between the compute drivers (which
//! set the variables when launching a sandbox container/VM) and the sandbox
//! supervisor process (which reads them on startup).  Using constants here
//! prevents typos from producing silently broken sandboxes.

/// Name of the sandbox (used for policy sync and identification).
pub const SANDBOX: &str = "OPENSHELL_SANDBOX";

/// gRPC endpoint of the `OpenShell` gateway that the sandbox reports to.
pub const ENDPOINT: &str = "OPENSHELL_ENDPOINT";

/// Unique identifier of the sandbox being supervised.
pub const SANDBOX_ID: &str = "OPENSHELL_SANDBOX_ID";

/// Filesystem path to the UNIX socket used for the in-sandbox SSH server.
pub const SSH_SOCKET_PATH: &str = "OPENSHELL_SSH_SOCKET_PATH";

/// Log level for the sandbox supervisor (e.g. `"debug"`, `"info"`, `"warn"`).
pub const LOG_LEVEL: &str = "OPENSHELL_LOG_LEVEL";

/// Shell command to run inside the sandbox.
pub const SANDBOX_COMMAND: &str = "OPENSHELL_SANDBOX_COMMAND";

/// Deployment-controlled telemetry toggle propagated to the sandbox supervisor.
pub const TELEMETRY_ENABLED: &str = "OPENSHELL_TELEMETRY_ENABLED";

/// Path to the CA certificate for mTLS communication with the gateway.
pub const TLS_CA: &str = "OPENSHELL_TLS_CA";

/// Path to the client certificate for mTLS communication with the gateway.
pub const TLS_CERT: &str = "OPENSHELL_TLS_CERT";

/// Path to the private key for mTLS communication with the gateway.
pub const TLS_KEY: &str = "OPENSHELL_TLS_KEY";

/// Raw gateway-minted JWT identifying this sandbox. Mutually exclusive with
/// [`SANDBOX_TOKEN_FILE`] / [`K8S_SA_TOKEN_FILE`]; used only by test harnesses
/// that bypass the file-mount path.
pub const SANDBOX_TOKEN: &str = "OPENSHELL_SANDBOX_TOKEN";

/// Path to the file holding a gateway-minted sandbox JWT.
///
/// Set by the Docker, Podman, and VM drivers, which write the token to a
/// bundle file at sandbox-create time. Read once at supervisor startup;
/// the token is held in process memory thereafter.
pub const SANDBOX_TOKEN_FILE: &str = "OPENSHELL_SANDBOX_TOKEN_FILE";

/// JSON-serialized map of user-specified environment variables.
///
/// Set by compute drivers from `SandboxSpec.environment`. The sandbox
/// supervisor deserializes this at startup and injects the variables into
/// SSH child processes (which use `env_clear()` for security isolation).
pub const USER_ENVIRONMENT: &str = "OPENSHELL_USER_ENVIRONMENT";

/// Path to the projected `ServiceAccount` JWT (Kubernetes driver).
///
/// Used to bootstrap a gateway-minted JWT via `IssueSandboxToken`. Kubelet
/// writes and rotates this file; the supervisor exchanges its contents
/// for a gateway JWT at startup and on refresh.
pub const K8S_SA_TOKEN_FILE: &str = "OPENSHELL_K8S_SA_TOKEN_FILE";

/// Runtime role selected for the sandbox supervisor binary.
pub const SUPERVISOR_ROLE: &str = "OPENSHELL_SUPERVISOR_ROLE";

/// Network enforcement mode selected for the sandbox supervisor binary.
pub const NETWORK_ENFORCEMENT_MODE: &str = "OPENSHELL_NETWORK_ENFORCEMENT_MODE";

/// Endpoint for an external node/host enforcer.
pub const ENFORCER_ENDPOINT: &str = "OPENSHELL_ENFORCER_ENDPOINT";

/// Node IP injected by Kubernetes when an external node enforcer is used.
pub const NODE_IP: &str = "OPENSHELL_NODE_IP";

/// Pod IP injected by Kubernetes for node-enforcer registration.
pub const POD_IP: &str = "OPENSHELL_POD_IP";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupervisorRole {
    /// Runs inside the sandbox/container and owns workload lifecycle.
    Workload,
    /// Runs as a privileged host/node-side enforcement component.
    Enforcer,
    /// Current local-style topology: one supervisor owns lifecycle and hard controls.
    #[default]
    Combined,
}

impl SupervisorRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Workload => "workload",
            Self::Enforcer => "enforcer",
            Self::Combined => "combined",
        }
    }
}

impl std::fmt::Display for SupervisorRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for SupervisorRole {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "workload" => Ok(Self::Workload),
            "enforcer" => Ok(Self::Enforcer),
            "combined" => Ok(Self::Combined),
            other => Err(format!(
                "unknown supervisor role '{other}'; expected 'workload', 'enforcer', or 'combined'"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkEnforcementMode {
    /// Resolve from the supervisor role and runtime hints.
    #[default]
    Auto,
    /// Cooperative proxy environment only; direct sockets are not kernel-blocked.
    SoftProxy,
    /// Supervisor-managed netns/veth/nft enforcement.
    SupervisorNetns,
    /// Enforcement delegated to a node/host enforcer.
    ExternalEnforcer,
}

impl NetworkEnforcementMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::SoftProxy => "soft-proxy",
            Self::SupervisorNetns => "supervisor-netns",
            Self::ExternalEnforcer => "external-enforcer",
        }
    }
}

impl std::fmt::Display for NetworkEnforcementMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for NetworkEnforcementMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "soft-proxy" => Ok(Self::SoftProxy),
            "supervisor-netns" => Ok(Self::SupervisorNetns),
            "external-enforcer" => Ok(Self::ExternalEnforcer),
            other => Err(format!(
                "unknown network enforcement mode '{other}'; expected 'auto', 'soft-proxy', 'supervisor-netns', or 'external-enforcer'"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{NetworkEnforcementMode, SupervisorRole};

    #[test]
    fn supervisor_role_round_trips_kebab_case() {
        assert_eq!("workload".parse(), Ok(SupervisorRole::Workload));
        assert_eq!(SupervisorRole::Enforcer.to_string(), "enforcer");
        assert_eq!(
            serde_json::to_value(SupervisorRole::Combined).unwrap(),
            serde_json::json!("combined")
        );
    }

    #[test]
    fn network_enforcement_mode_round_trips_kebab_case() {
        assert_eq!("soft-proxy".parse(), Ok(NetworkEnforcementMode::SoftProxy));
        assert_eq!(
            NetworkEnforcementMode::ExternalEnforcer.to_string(),
            "external-enforcer"
        );
        assert_eq!(
            serde_json::to_value(NetworkEnforcementMode::SupervisorNetns).unwrap(),
            serde_json::json!("supervisor-netns")
        );
    }
}
