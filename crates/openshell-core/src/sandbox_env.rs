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

/// Supervisor pod/runtime topology. Kubernetes sidecar mode sets this to
/// `"sidecar"`; the default combined supervisor path omits it.
pub const SUPERVISOR_TOPOLOGY: &str = "OPENSHELL_SUPERVISOR_TOPOLOGY";

/// Network enforcement backend selected by the compute driver.
pub const NETWORK_ENFORCEMENT_MODE: &str = "OPENSHELL_NETWORK_ENFORCEMENT_MODE";

/// Process enforcement mode selected by the compute driver.
///
/// The default when unset is `"full"`, where the process supervisor enforces
/// filesystem/process policy before spawning workloads. Kubernetes sidecar
/// topology sets this to `"network-only"` so the process wrapper can run as
/// the sandbox UID without Linux capabilities while preserving SSH/session
/// behavior.
pub const PROCESS_ENFORCEMENT_MODE: &str = "OPENSHELL_PROCESS_ENFORCEMENT_MODE";

/// Whether network policy evaluation must bind requests to the peer binary.
///
/// The default when unset is `"required"`. Kubernetes sidecar experiments may
/// set this to `"relaxed"` to enforce endpoint and L7 policy without per-binary
/// `/proc` identity binding.
pub const NETWORK_BINARY_IDENTITY: &str = "OPENSHELL_NETWORK_BINARY_IDENTITY";

/// File written by the network supervisor when sidecar networking is ready.
pub const SUPERVISOR_READY_FILE: &str = "OPENSHELL_SUPERVISOR_READY_FILE";

/// File written by the process supervisor with the workload entrypoint PID and
/// read by the network sidecar for process/binary-bound network policy checks.
pub const ENTRYPOINT_PID_FILE: &str = "OPENSHELL_ENTRYPOINT_PID_FILE";

/// Local protobuf policy snapshot written by the network sidecar and read by
/// the process-only supervisor in Kubernetes sidecar topology.
pub const SIDECAR_POLICY_SNAPSHOT_FILE: &str = "OPENSHELL_SIDECAR_POLICY_SNAPSHOT_FILE";

/// Local provider environment snapshot written by the network sidecar and read
/// by the process-only supervisor in Kubernetes sidecar topology.
pub const SIDECAR_PROVIDER_ENV_SNAPSHOT_FILE: &str = "OPENSHELL_SIDECAR_PROVIDER_ENV_SNAPSHOT_FILE";

/// Optional TLS server name override used when connecting to the gateway.
pub const GATEWAY_TLS_SERVER_NAME: &str = "OPENSHELL_GATEWAY_TLS_SERVER_NAME";

/// Directory where the network supervisor writes the proxy CA files consumed
/// by workload child processes.
pub const PROXY_TLS_DIR: &str = "OPENSHELL_PROXY_TLS_DIR";

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

/// Resolved sandbox UID used to override `run_as_user` when the policy
/// specifies a numeric value instead of the hardcoded "sandbox" user name.
///
/// Set by compute drivers (Kubernetes, Docker, VM) from resolved config or
/// cluster autodetection. The supervisor reads this at startup and uses it
/// directly with `setuid()` / `chown()` without requiring an `/etc/passwd`
/// entry in the sandbox image.
pub const SANDBOX_UID: &str = "OPENSHELL_SANDBOX_UID";

/// Resolved sandbox GID paired with [`SANDBOX_UID`].
///
/// Used alongside UID for PVC init container `chown` operations and when the
/// supervisor drops privileges to a group other than the UID's primary group.
pub const SANDBOX_GID: &str = "OPENSHELL_SANDBOX_GID";
