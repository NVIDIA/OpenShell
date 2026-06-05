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

/// Filesystem path to the SPIFFE Workload API UNIX socket used for provider
/// token grants.
///
/// When set, the supervisor can fetch JWT-SVIDs for upstream provider token
/// exchanges without using SPIFFE for gateway authentication.
pub const PROVIDER_SPIFFE_WORKLOAD_API_SOCKET: &str =
    "OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET";
