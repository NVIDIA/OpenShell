// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Canonical paths reserved for `OpenShell` control state inside sandboxes.
//!
//! Keep fixed in-container and VM guest paths here so the code that creates or
//! consumes control state cannot drift from the mount-collision validator.

use std::path::{Path, PathBuf};

pub const OPT_ROOT: &str = "/opt/openshell";
pub const ETC_ROOT: &str = "/etc/openshell";
pub const TLS_ROOT: &str = "/etc/openshell-tls";
pub const RUN_ROOT: &str = "/run/openshell";
pub const SIDECAR_RUN_ROOT: &str = "/run/openshell-sidecar";
pub const NETNS_MOUNT_ROOT: &str = "/run/netns";
pub const NETNS_IPROUTE2_ROOT: &str = "/var/run/netns";

/// Standard Linux container namespaces that an image-selected workspace must
/// not contain or enter.
///
/// These roots cover the default filesystems and devices defined by the OCI
/// Runtime Specification: procfs, sysfs, cgroups, device nodes, devpts, shared
/// memory, and POSIX message queues.
/// <https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#default-filesystems>
pub const OCI_RUNTIME_MOUNT_ROOTS: &[&str] = &["/proc", "/sys", "/dev"];

/// High-level namespaces mounted or created by `OpenShell` inside sandboxes.
///
/// This is intentionally not a general Linux system-path denylist. Kernel and
/// image-provided paths have separate trust models; see NVIDIA/OpenShell#2578.
pub const CONTROL_ROOTS: &[&str] = &[
    OPT_ROOT,
    ETC_ROOT,
    TLS_ROOT,
    RUN_ROOT,
    SIDECAR_RUN_ROOT,
    NETNS_MOUNT_ROOT,
    // The supervisor currently uses the conventional iproute2 spelling.
    NETNS_IPROUTE2_ROOT,
];

pub const SUPERVISOR_CONTAINER_DIR: &str = "/opt/openshell/bin";
pub const SUPERVISOR_CONTAINER_BINARY: &str = "/opt/openshell/bin/openshell-sandbox";
pub const TLS_CLIENT_DIR: &str = "/etc/openshell/tls/client";
pub const TLS_CA_MOUNT_PATH: &str = "/etc/openshell/tls/client/ca.crt";
pub const TLS_CERT_MOUNT_PATH: &str = "/etc/openshell/tls/client/tls.crt";
pub const TLS_KEY_MOUNT_PATH: &str = "/etc/openshell/tls/client/tls.key";
pub const SANDBOX_TOKEN_MOUNT_PATH: &str = "/etc/openshell/auth/sandbox.jwt";
pub const UPSTREAM_PROXY_AUTH_MOUNT_PATH: &str = "/etc/openshell/auth/upstream-proxy";
pub const CONTAINER_POLICY_PATH: &str = "/etc/openshell/policy.yaml";
pub const POLICY_ADVISOR_SKILL_PATH: &str = "/etc/openshell/skills/policy_advisor.md";

pub const SSH_SOCKET_PATH: &str = "/run/openshell/ssh.sock";
pub const SIDECAR_CONTROL_SOCKET: &str = "/run/openshell-sidecar/control.sock";
pub const SIDECAR_TLS_DIR: &str = "/etc/openshell-tls/proxy";
pub const SIDECAR_CLIENT_TLS_DIR: &str = "/etc/openshell-tls/proxy/client";
pub const CLIENT_TLS_DIR: &str = "/etc/openshell-tls/client";
pub const SUPERVISOR_CA_CERT_PATH: &str = "/etc/openshell-tls/openshell-ca.pem";
pub const SUPERVISOR_CA_BUNDLE_PATH: &str = "/etc/openshell-tls/ca-bundle.pem";

pub const VM_GUEST_TLS_CA_PATH: &str = "/opt/openshell/tls/ca.crt";
pub const VM_GUEST_TLS_CERT_PATH: &str = "/opt/openshell/tls/tls.crt";
pub const VM_GUEST_TLS_KEY_PATH: &str = "/opt/openshell/tls/tls.key";
pub const VM_GUEST_SANDBOX_TOKEN_PATH: &str = "/opt/openshell/auth/sandbox.jwt";
pub const VM_GUEST_INIT_DROPIN_DIR: &str = "/opt/openshell/init.d";
pub const VM_GUEST_INIT_DROPIN_MANIFEST: &str = "/opt/openshell/init.d.manifest";
pub const VM_UMOCI_PATH: &str = "/opt/openshell/bin/umoci";
pub const VM_SANDBOX_OWNER_NORMALIZED_MARKER: &str = "/opt/openshell/.sandbox-owner-normalized";

/// Return the conventional iproute2 path for a named network namespace.
pub fn netns_path(name: &str) -> PathBuf {
    Path::new(NETNS_IPROUTE2_ROOT).join(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_fixed_control_path_is_below_a_reserved_root() {
        let paths = [
            SUPERVISOR_CONTAINER_DIR,
            SUPERVISOR_CONTAINER_BINARY,
            TLS_CLIENT_DIR,
            TLS_CA_MOUNT_PATH,
            TLS_CERT_MOUNT_PATH,
            TLS_KEY_MOUNT_PATH,
            SANDBOX_TOKEN_MOUNT_PATH,
            UPSTREAM_PROXY_AUTH_MOUNT_PATH,
            CONTAINER_POLICY_PATH,
            POLICY_ADVISOR_SKILL_PATH,
            SSH_SOCKET_PATH,
            SIDECAR_CONTROL_SOCKET,
            SIDECAR_TLS_DIR,
            SIDECAR_CLIENT_TLS_DIR,
            CLIENT_TLS_DIR,
            SUPERVISOR_CA_CERT_PATH,
            SUPERVISOR_CA_BUNDLE_PATH,
            VM_GUEST_TLS_CA_PATH,
            VM_GUEST_TLS_CERT_PATH,
            VM_GUEST_TLS_KEY_PATH,
            VM_GUEST_SANDBOX_TOKEN_PATH,
            VM_GUEST_INIT_DROPIN_DIR,
            VM_GUEST_INIT_DROPIN_MANIFEST,
            VM_UMOCI_PATH,
            VM_SANDBOX_OWNER_NORMALIZED_MARKER,
        ];

        for path in paths {
            assert!(
                CONTROL_ROOTS
                    .iter()
                    .any(|root| Path::new(path).starts_with(root)),
                "fixed control path {path} is outside the reserved roots"
            );
        }
    }

    #[test]
    fn runtime_roots_cover_standard_oci_mount_destinations() {
        for path in [
            "/proc",
            "/dev",
            "/dev/pts",
            "/dev/shm",
            "/dev/mqueue",
            "/sys",
            "/sys/fs/cgroup",
        ] {
            assert!(
                OCI_RUNTIME_MOUNT_ROOTS
                    .iter()
                    .any(|root| Path::new(path).starts_with(root)),
                "OCI runtime mount {path} is outside the reserved roots"
            );
        }
    }
}
