// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Environment-variable names used to configure the sandbox supervisor.
//!
//! These constants are the shared protocol between the compute drivers (which
//! set the variables when launching a sandbox container/VM) and the sandbox
//! supervisor process (which reads them on startup).  Using constants here
//! prevents typos from producing silently broken sandboxes.

use serde::{Deserialize, Serialize};

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

/// Versioned JSON specification for the exact canonical main process.
pub const MAIN_PROCESS_SPEC: &str = "OPENSHELL_MAIN_PROCESS_SPEC";

/// Lossless driver-to-supervisor representation of the canonical process.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MainProcessConfig {
    pub version: u32,
    pub command: Vec<String>,
    pub tty: bool,
}

impl MainProcessConfig {
    pub const VERSION: u32 = 1;

    #[must_use]
    pub fn scratch() -> Self {
        Self {
            version: Self::VERSION,
            command: vec!["/bin/bash".to_string(), "-l".to_string()],
            tty: true,
        }
    }

    #[must_use]
    pub fn from_driver_spec(spec: Option<&crate::proto::compute::v1::DriverSandboxSpec>) -> Self {
        match spec {
            Some(spec) if !spec.command.is_empty() => Self {
                version: Self::VERSION,
                command: spec.command.clone(),
                tty: spec.tty,
            },
            None | Some(_) => Self::scratch(),
        }
    }

    /// Decode the versioned transport without shell interpretation.
    pub fn decode(json: &str) -> Result<Self, String> {
        let config: Self = serde_json::from_str(json)
            .map_err(|error| format!("invalid {MAIN_PROCESS_SPEC}: {error}"))?;
        if config.version != Self::VERSION {
            return Err(format!(
                "unsupported {MAIN_PROCESS_SPEC} version {}",
                config.version
            ));
        }
        if config.command.is_empty() || config.command[0].is_empty() {
            return Err(format!("{MAIN_PROCESS_SPEC} command must not be empty"));
        }
        Ok(config)
    }

    /// Encode the versioned driver-to-supervisor transport.
    pub fn encode_driver_spec(
        spec: Option<&crate::proto::compute::v1::DriverSandboxSpec>,
    ) -> Result<String, serde_json::Error> {
        serde_json::to_string(&Self::from_driver_spec(spec))
    }
}

/// Deployment-controlled telemetry toggle propagated to the sandbox supervisor.
pub const TELEMETRY_ENABLED: &str = "OPENSHELL_TELEMETRY_ENABLED";

/// Supervisor pod/runtime topology. Kubernetes sidecar mode sets this to
/// `"sidecar"`; the default combined supervisor path omits it.
pub const SUPERVISOR_TOPOLOGY: &str = "OPENSHELL_SUPERVISOR_TOPOLOGY";

/// Network enforcement backend selected by the compute driver.
pub const NETWORK_ENFORCEMENT_MODE: &str = "OPENSHELL_NETWORK_ENFORCEMENT_MODE";

/// Comma-separated runtime networking capabilities supplied by the compute
/// driver. Capabilities describe substrate the shared supervisor may activate;
/// they never move policy evaluation into the driver.
pub const NETWORK_RUNTIME_CAPABILITIES: &str = "OPENSHELL_NETWORK_RUNTIME_CAPABILITIES";

/// Driver capability for policy-gated DNS and transparent TCP interception.
pub const POLICY_DNS_TRANSPARENT_TCP_CAPABILITY: &str = "policy-dns-transparent-tcp";

/// Whether network policy evaluation must bind requests to the peer binary.
///
/// The default when unset is `"required"`. Kubernetes sidecar experiments may
/// set this to `"relaxed"` to enforce endpoint and L7 policy without per-binary
/// `/proc` identity binding.
pub const NETWORK_BINARY_IDENTITY: &str = "OPENSHELL_NETWORK_BINARY_IDENTITY";

/// Unix socket used by Kubernetes sidecar topology for local coordination.
///
/// The network sidecar owns gateway credentials and serves policy/provider
/// state over this socket instead of exposing gateway credentials to the agent
/// container.
pub const SIDECAR_CONTROL_SOCKET: &str = "OPENSHELL_SIDECAR_CONTROL_SOCKET";

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

/// Raw OCI `Config.User` declaration from the immutable image selected by a
/// local container driver.
///
/// Docker and Podman overwrite this value with the image declaration,
/// including an empty string when the image has no `USER`, and clear
/// [`SANDBOX_UID`] and [`SANDBOX_GID`]. Drivers with an authoritative numeric
/// identity overwrite this value with an empty string while supplying both
/// numeric fields. The supervisor resolves omitted policy identity fields from
/// OCI only for the former contract.
pub const OCI_IMAGE_USER: &str = "OPENSHELL_OCI_IMAGE_USER";

// The corporate upstream-proxy configuration deliberately has no reserved
// environment variables: it travels on the supervisor's argv
// (`--upstream-proxy` and friends), which a sandbox image cannot forge the
// way it could bake `ENV` values.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_process_transport_preserves_argument_boundaries() {
        let spec = crate::proto::compute::v1::DriverSandboxSpec {
            command: vec!["/bin/sh".into(), "-c".into(), "printf '%s' 'a b'".into()],
            tty: false,
            ..Default::default()
        };
        let encoded = MainProcessConfig::encode_driver_spec(Some(&spec)).unwrap();
        let decoded = MainProcessConfig::decode(&encoded).unwrap();
        assert_eq!(decoded.command, spec.command);
        assert!(!decoded.tty);
    }

    #[test]
    fn main_process_transport_rejects_unknown_version() {
        let error =
            MainProcessConfig::decode(r#"{"version":2,"command":["/bin/true"],"tty":false}"#)
                .unwrap_err();
        assert!(error.contains("unsupported"));
    }

    #[test]
    fn legacy_driver_spec_without_command_uses_scratch_main() {
        let legacy = crate::proto::compute::v1::DriverSandboxSpec::default();
        let config = MainProcessConfig::from_driver_spec(Some(&legacy));

        assert_eq!(config, MainProcessConfig::scratch());
        let encoded = serde_json::to_string(&config).unwrap();
        assert_eq!(MainProcessConfig::decode(&encoded).unwrap(), config);
    }
}
