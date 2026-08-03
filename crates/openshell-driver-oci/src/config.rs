// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

/// Default path to the system containerd gRPC socket.
pub const DEFAULT_CONTAINERD_SOCKET_PATH: &str = "/run/containerd/containerd.sock";
/// containerd namespace used for all `OpenShell`-managed containers/tasks/
/// snapshots/images.
///
/// Deliberately distinct from `default`, `moby` (Docker), and `k8s.io` (the
/// CRI plugin's namespace) so this driver can never collide with another
/// tenant of the same system containerd.
pub const DEFAULT_CONTAINERD_NAMESPACE: &str = "openshell";
/// Default low-level OCI runtime.
///
/// Configurable (e.g. `crun`, or any other OCI-runtime-spec-compatible
/// binary). Never bundled: this driver execs it directly (see
/// [`crate::runtime`]), so it must already be installed and resolvable on
/// the gateway host. containerd is never involved in invoking it.
pub const DEFAULT_RUNTIME_BINARY: &str = "runc";
/// Default containerd snapshotter.
pub const DEFAULT_SNAPSHOTTER: &str = "overlayfs";
/// Table-name prefix this driver's nftables rulesets use.
///
/// Distinct from the VM driver's `openshell_vm` prefix so both can manage
/// interfaces on the same host without colliding.
pub const NFT_TABLE_PREFIX: &str = "openshell_oci";

/// Base UID a sandbox's containerd user namespace maps container root (0)
/// to, when `rootless` is enabled.
///
/// Reuses the sandbox UID range convention already validated by
/// `openshell-policy` for the Docker/Podman/VM drivers'
/// `run_as_user`/`run_as_group` policy fields.
pub const DEFAULT_USER_NAMESPACE_UID_BASE: u32 = openshell_policy::MIN_SANDBOX_UID;
/// Number of UIDs/GIDs mapped into the sandbox's user namespace.
pub const DEFAULT_USER_NAMESPACE_ID_COUNT: u32 = 65536;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OciComputeConfig {
    /// Path to the system containerd gRPC Unix socket.
    pub containerd_socket_path: PathBuf,
    /// containerd namespace this driver operates in.
    pub containerd_namespace: String,
    /// Low-level OCI runtime binary name (or absolute path) this driver
    /// execs directly (see [`crate::runtime`]). Default `runc`; set to
    /// `crun` or another OCI-runtime-spec-compatible binary already
    /// installed on the host. Never bundled: containerd is never involved
    /// in invoking it.
    pub runtime_binary: String,
    /// containerd snapshotter used for image unpack and per-sandbox
    /// writable layers.
    pub snapshotter: String,
    /// Default OCI image for sandboxes.
    pub default_image: String,
    /// Directory for driver-local state: per-sandbox network namespace
    /// bookkeeping and (optionally) a persisted GPU CDI inventory cache.
    pub state_dir: PathBuf,
    /// Gateway gRPC endpoint the sandbox connects back to.
    pub grpc_endpoint: String,
    /// Port the gateway server is actually listening on. Used to scope the
    /// per-sandbox nftables input chain and as a fallback when
    /// `grpc_endpoint` is empty.
    pub gateway_port: u16,
    /// Unix socket path the in-container supervisor bridges traffic to.
    pub sandbox_ssh_socket_path: String,
    /// Host path to a prebuilt `openshell-sandbox` supervisor binary,
    /// bind-mounted read-only into sandboxes at
    /// `/opt/openshell/bin/openshell-sandbox`.
    ///
    /// The Docker/Podman/VM drivers source the supervisor from an OCI
    /// image (`supervisor_image`) mounted at container-create time. This
    /// driver does not yet implement the equivalent image-based mount
    /// (that requires a second containerd pull + snapshot-view cycle per
    /// sandbox; tracked as follow-up work). A host-path bind mount is a
    /// deliberately smaller, fully working slice for this initial cut.
    pub supervisor_binary_path: Option<PathBuf>,
    /// Container stop timeout in seconds (SIGTERM → SIGKILL).
    pub stop_timeout_secs: u32,
    /// Point-to-point-style /30 subnet base for per-sandbox veth pairs, in
    /// the form of a base IPv4 address. Each sandbox gets the next /30
    /// block (mirrors the VM driver's TAP subnet allocation strategy).
    pub veth_subnet_base: String,
    /// Enable a Linux user namespace per sandbox, mapping container root
    /// (UID/GID 0) to an unprivileged host UID/GID range. This is the
    /// mechanism behind the issue's "rootless by default" goal: the
    /// sandboxed process would run as root only from its own point of
    /// view, never as host root, even though the runtime invocation
    /// this driver performs itself is not rootless.
    ///
    /// **Known gap, defaults to `false` until fixed:** verified against a
    /// real containerd + runc during development, enabling this currently
    /// fails container start with `error mounting "proc" to rootfs ...:
    /// permission denied`. The OCI spec correctly requests the user
    /// namespace and UID/GID mapping, but the writable overlay snapshot
    /// containerd prepares is not remapped to match — its upperdir is
    /// owned by real host root, which the mapped "container root" (a
    /// non-zero host UID) cannot write into. Fixing this needs one of:
    /// chowning the snapshot's upperdir to the mapped range before start,
    /// ID-mapped mounts (Linux 5.12+, `Mount.uid_mappings`/`gid_mappings`
    /// in `oci-spec`), or containerd 1.7+'s remapped-snapshot support. None
    /// of those are implemented yet; this field exists so the OCI spec
    /// plumbing (namespace + mapping generation, tested in `spec.rs`) is in
    /// place ahead of that follow-up work, without shipping a broken
    /// default.
    pub rootless: bool,
    /// Host UID/GID the sandbox's user namespace maps container root to,
    /// when `rootless` is enabled.
    pub user_namespace_id_base: u32,
    /// Number of UIDs/GIDs mapped into the sandbox's user namespace.
    pub user_namespace_id_count: u32,
}

impl Default for OciComputeConfig {
    fn default() -> Self {
        Self {
            containerd_socket_path: PathBuf::from(DEFAULT_CONTAINERD_SOCKET_PATH),
            containerd_namespace: DEFAULT_CONTAINERD_NAMESPACE.to_string(),
            runtime_binary: DEFAULT_RUNTIME_BINARY.to_string(),
            snapshotter: DEFAULT_SNAPSHOTTER.to_string(),
            default_image: String::new(),
            state_dir: Self::default_state_dir(),
            grpc_endpoint: String::new(),
            gateway_port: openshell_core::config::DEFAULT_SERVER_PORT,
            sandbox_ssh_socket_path: "/run/openshell/ssh.sock".to_string(),
            supervisor_binary_path: None,
            stop_timeout_secs: openshell_core::config::DEFAULT_STOP_TIMEOUT_SECS,
            veth_subnet_base: "10.0.132.0".to_string(),
            rootless: false,
            user_namespace_id_base: DEFAULT_USER_NAMESPACE_UID_BASE,
            user_namespace_id_count: DEFAULT_USER_NAMESPACE_ID_COUNT,
        }
    }
}

impl OciComputeConfig {
    #[must_use]
    pub fn default_state_dir() -> PathBuf {
        PathBuf::from("/var/lib/openshell/driver-oci")
    }

    /// Validate configuration invariants that are cheap to check up front,
    /// before ever dialing containerd.
    pub fn validate(&self) -> Result<(), String> {
        if self.containerd_socket_path.as_os_str().is_empty() {
            return Err("containerd_socket_path must not be empty".to_string());
        }
        if self.containerd_namespace.trim().is_empty() {
            return Err("containerd_namespace must not be empty".to_string());
        }
        if self.runtime_binary.trim().is_empty() {
            return Err("runtime_binary must not be empty (e.g. \"runc\" or \"crun\")".to_string());
        }
        if self.snapshotter.trim().is_empty() {
            return Err("snapshotter must not be empty".to_string());
        }
        if self.rootless {
            let base = u64::from(self.user_namespace_id_base);
            let count = u64::from(self.user_namespace_id_count);
            if count == 0 {
                return Err("user_namespace_id_count must be greater than 0".to_string());
            }
            if base == 0 {
                return Err(
                    "user_namespace_id_base must not be 0 (would map container root to host root)"
                        .to_string(),
                );
            }
            if base
                .checked_add(count)
                .is_none_or(|end| end > u64::from(u32::MAX))
            {
                return Err(
                    "user_namespace_id_base + user_namespace_id_count overflows u32".to_string(),
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        OciComputeConfig::default().validate().expect("valid");
    }

    #[test]
    fn rejects_empty_containerd_socket_path() {
        let cfg = OciComputeConfig {
            containerd_socket_path: PathBuf::new(),
            ..OciComputeConfig::default()
        };
        assert!(
            cfg.validate()
                .unwrap_err()
                .contains("containerd_socket_path")
        );
    }

    #[test]
    fn rejects_empty_runtime_binary() {
        let cfg = OciComputeConfig {
            runtime_binary: String::new(),
            ..OciComputeConfig::default()
        };
        assert!(cfg.validate().unwrap_err().contains("runtime_binary"));
    }

    #[test]
    fn accepts_crun_as_runtime_binary() {
        let cfg = OciComputeConfig {
            runtime_binary: "crun".to_string(),
            ..OciComputeConfig::default()
        };
        cfg.validate().expect("crun is a valid runtime_binary");
    }

    #[test]
    fn rejects_zero_user_namespace_id_base_when_rootless() {
        let cfg = OciComputeConfig {
            rootless: true,
            user_namespace_id_base: 0,
            ..OciComputeConfig::default()
        };
        assert!(
            cfg.validate()
                .unwrap_err()
                .contains("user_namespace_id_base")
        );
    }

    #[test]
    fn rejects_zero_user_namespace_id_count_when_rootless() {
        let cfg = OciComputeConfig {
            rootless: true,
            user_namespace_id_count: 0,
            ..OciComputeConfig::default()
        };
        assert!(
            cfg.validate()
                .unwrap_err()
                .contains("user_namespace_id_count")
        );
    }

    #[test]
    fn allows_disabling_rootless_without_id_range_checks() {
        let cfg = OciComputeConfig {
            rootless: false,
            user_namespace_id_base: 0,
            user_namespace_id_count: 0,
            ..OciComputeConfig::default()
        };
        cfg.validate()
            .expect("id range is irrelevant when rootless=false");
    }
}
