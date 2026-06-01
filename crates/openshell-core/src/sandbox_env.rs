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

/// Path to the CA certificate for mTLS communication with the gateway.
pub const TLS_CA: &str = "OPENSHELL_TLS_CA";

/// Path to the client certificate for mTLS communication with the gateway.
pub const TLS_CERT: &str = "OPENSHELL_TLS_CERT";

/// Path to the private key for mTLS communication with the gateway.
pub const TLS_KEY: &str = "OPENSHELL_TLS_KEY";

/// Selects how the supervisor bootstraps sandbox authentication and who owns
/// token refresh.
pub const SANDBOX_AUTH_MODE: &str = "OPENSHELL_SANDBOX_AUTH_MODE";

/// Explicit sandbox authentication modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxAuthMode {
    /// Use [`SANDBOX_TOKEN`] as a static gateway JWT.
    ///
    /// This is intended for direct test/debug harnesses. The supervisor does
    /// not refresh the token.
    StaticToken,

    /// Use [`SANDBOX_TOKEN_FILE`] as a gateway-managed token file.
    ///
    /// Docker and Podman use this mode. The gateway refreshes the host-side
    /// file and the supervisor re-reads it on outbound calls.
    GatewayManagedFile,

    /// Use [`SANDBOX_TOKEN_FILE`] as a supervisor-writable token file.
    ///
    /// The VM driver uses this mode. The gateway injects a fresh token into
    /// persisted VM state on resume and pushes live token updates over the
    /// supervisor control stream.
    GatewayManagedSupervisorPush,

    /// Use [`K8S_SA_TOKEN_FILE`] to exchange Kubernetes workload identity for
    /// a gateway JWT.
    ///
    /// The supervisor re-exchanges the projected `ServiceAccount` token when
    /// the gateway JWT needs rotation.
    KubernetesServiceAccountExchange,
}

impl SandboxAuthMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StaticToken => "static-token",
            Self::GatewayManagedFile => "gateway-managed-file",
            Self::GatewayManagedSupervisorPush => "gateway-managed-supervisor-push",
            Self::KubernetesServiceAccountExchange => "kubernetes-service-account-exchange",
        }
    }

    #[must_use]
    pub fn allowed_values() -> &'static str {
        "static-token, gateway-managed-file, gateway-managed-supervisor-push, kubernetes-service-account-exchange"
    }
}

impl std::str::FromStr for SandboxAuthMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "static-token" => Ok(Self::StaticToken),
            "gateway-managed-file" => Ok(Self::GatewayManagedFile),
            "gateway-managed-supervisor-push" => Ok(Self::GatewayManagedSupervisorPush),
            "kubernetes-service-account-exchange" => Ok(Self::KubernetesServiceAccountExchange),
            other => Err(format!(
                "invalid sandbox auth mode '{other}' (expected one of: {})",
                Self::allowed_values()
            )),
        }
    }
}

/// Raw gateway-minted JWT identifying this sandbox. Used only when
/// [`SANDBOX_AUTH_MODE`] is [`SandboxAuthMode::StaticToken`].
pub const SANDBOX_TOKEN: &str = "OPENSHELL_SANDBOX_TOKEN";

/// Path to the file holding a gateway-minted sandbox JWT.
///
/// Set by Docker, Podman, and VM when [`SANDBOX_AUTH_MODE`] is
/// [`SandboxAuthMode::GatewayManagedFile`] or
/// [`SandboxAuthMode::GatewayManagedSupervisorPush`].
pub const SANDBOX_TOKEN_FILE: &str = "OPENSHELL_SANDBOX_TOKEN_FILE";

/// Path to the projected `ServiceAccount` JWT (Kubernetes driver).
///
/// Used when [`SANDBOX_AUTH_MODE`] is
/// [`SandboxAuthMode::KubernetesServiceAccountExchange`].
pub const K8S_SA_TOKEN_FILE: &str = "OPENSHELL_K8S_SA_TOKEN_FILE";
