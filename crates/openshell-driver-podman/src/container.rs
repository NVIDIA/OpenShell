// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Container spec construction for the Podman driver.

use crate::config::PodmanComputeConfig;
use openshell_core::config::CDI_GPU_DEVICE_ALL;
use openshell_core::proto::compute::v1::DriverSandbox;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

/// Returns `true` when `SELinux` is enabled (enforcing or permissive).
///
/// Checks whether selinuxfs is mounted, matching Podman's own detection
/// logic. Bind-mount relabeling (the `z` mount option) is needed in both
/// enforcing and permissive modes: enforcing blocks access outright, while
/// permissive floods the audit log with AVC denials that mask real issues.
///
/// On non-`SELinux` systems (Ubuntu, macOS, Alpine) the directory does not
/// exist and this returns `false`, leaving mount options unchanged.
#[cfg(target_os = "linux")]
fn is_selinux_enabled() -> bool {
    std::path::Path::new("/sys/fs/selinux").is_dir()
}

#[cfg(not(target_os = "linux"))]
fn is_selinux_enabled() -> bool {
    false
}

/// Label key for the sandbox ID.
pub const LABEL_SANDBOX_ID: &str = "openshell.sandbox-id";
/// Label key for the sandbox name.
pub const LABEL_SANDBOX_NAME: &str = "openshell.sandbox-name";
/// Label key for the sandbox namespace.
pub const LABEL_SANDBOX_NAMESPACE: &str = "openshell.sandbox-namespace";
/// Label applied to all managed containers.
pub const LABEL_MANAGED: &str = "openshell.managed";
/// Label filter string for list/event queries.
pub const LABEL_MANAGED_FILTER: &str = "openshell.managed=true";

/// Container name prefix to avoid collisions with user containers.
const CONTAINER_PREFIX: &str = "openshell-sandbox-";

/// Volume name prefix.
const VOLUME_PREFIX: &str = "openshell-sandbox-";

/// Container-side mount paths for client TLS materials.
const TLS_CA_MOUNT_PATH: &str = "/etc/openshell/tls/client/ca.crt";
const TLS_CERT_MOUNT_PATH: &str = "/etc/openshell/tls/client/tls.crt";
const TLS_KEY_MOUNT_PATH: &str = "/etc/openshell/tls/client/tls.key";

/// Build a Podman container name from the sandbox name.
#[must_use]
pub fn container_name(sandbox_name: &str) -> String {
    format!("{CONTAINER_PREFIX}{sandbox_name}")
}

/// Build the workspace volume name from the sandbox ID.
#[must_use]
pub fn volume_name(sandbox_id: &str) -> String {
    format!("{VOLUME_PREFIX}{sandbox_id}-workspace")
}

/// Podman secret name prefix.
const SECRET_PREFIX: &str = "openshell-handshake-";

/// Build the Podman secret name for a sandbox's SSH handshake secret.
#[must_use]
pub fn secret_name(sandbox_id: &str) -> String {
    format!("{SECRET_PREFIX}{sandbox_id}")
}

/// Truncate a container ID to 12 characters (standard short form).
#[must_use]
pub fn short_id(id: &str) -> String {
    id.chars().take(12).collect()
}

// ---------------------------------------------------------------------------
// Typed container spec structs for the Podman libpod create API.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ContainerSpec {
    name: String,
    image: String,
    labels: BTreeMap<String, String>,
    env: BTreeMap<String, String>,
    volumes: Vec<NamedVolume>,
    image_volumes: Vec<ImageVolume>,
    hostname: String,
    /// Overrides the image's ENTRYPOINT. In Podman's libpod API, `command`
    /// only overrides CMD (appended as args to the entrypoint). We must set
    /// `entrypoint` explicitly so the supervisor binary runs directly,
    /// regardless of what ENTRYPOINT the sandbox image defines.
    entrypoint: Vec<String>,
    command: Vec<String>,
    user: String,
    cap_drop: Vec<String>,
    cap_add: Vec<String>,
    no_new_privileges: bool,
    seccomp_profile_path: String,
    image_pull_policy: String,
    healthconfig: HealthConfig,
    resource_limits: ResourceLimits,
    /// Env-type secrets: map of `ENV_VAR_NAME → secret_name`.
    /// Podman's libpod `SpecGenerator` uses `secret_env` (a flat map) for
    /// environment-variable injection, distinct from `secrets` which only
    /// handles file-mounted secrets under `/run/secrets/`.
    secret_env: BTreeMap<String, String>,
    stop_timeout: u32,
    /// Extra /etc/hosts entries. Used to inject `host.containers.internal`
    /// via Podman's `host-gateway` magic so sandbox containers can reach
    /// the gateway server running on the host in rootless mode.
    hostadd: Vec<String>,
    netns: NetNS,
    // Matches libpod's network spec format, which is `{name: {opts}}` where
    // empty opts is a unit struct rather than `()`. Keep as a map so JSON
    // serialization matches the API exactly.
    #[allow(clippy::zero_sized_map_values)]
    networks: BTreeMap<String, NetworkAttachment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    devices: Option<Vec<LinuxDevice>>,
    /// Extra mounts for the libpod `SpecGenerator` (e.g. tmpfs entries).
    mounts: Vec<Mount>,
    /// Port mappings from host to container. Using `host_port=0` requests an
    /// ephemeral port, readable back from the inspect response.
    portmappings: Vec<PortMapping>,
}

/// A port mapping entry for the libpod `SpecGenerator`.
#[derive(Serialize)]
struct PortMapping {
    host_port: u16,
    container_port: u16,
    protocol: String,
}

/// A mount entry for the libpod container create API `mounts` field.
///
/// Unlike `volumes` (named Podman volumes) or `image_volumes` (OCI image
/// mounts resolved at the libpod layer), these mounts are passed to the
/// libpod `SpecGenerator` and support arbitrary mount types (e.g. tmpfs).
/// Field names must be lowercase to match the libpod JSON schema.
#[derive(Serialize)]
struct Mount {
    #[serde(rename = "type")]
    kind: String,
    source: String,
    destination: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    options: Vec<String>,
}

/// A Podman image volume for the libpod container create API.
///
/// Image volumes mount an OCI image's filesystem into a container without
/// running it. Podman resolves these at the libpod layer before generating
/// the OCI runtime spec, unlike `mounts` which are passed directly to the
/// OCI runtime (crun/runc).
#[derive(Serialize)]
struct ImageVolume {
    source: String,
    destination: String,
    rw: bool,
}

#[derive(Serialize)]
struct NamedVolume {
    name: String,
    dest: String,
    options: Vec<String>,
}

#[derive(Serialize)]
struct HealthConfig {
    test: Vec<String>,
    #[serde(rename = "Interval")]
    interval: u64,
    #[serde(rename = "Timeout")]
    timeout: u64,
    #[serde(rename = "Retries")]
    retries: u32,
    #[serde(rename = "StartPeriod")]
    start_period: u64,
}

#[derive(Serialize)]
struct ResourceLimits {
    cpu: CpuLimits,
    memory: MemoryLimits,
}

#[derive(Serialize)]
struct CpuLimits {
    quota: u64,
    period: u64,
}

#[derive(Serialize)]
struct MemoryLimits {
    limit: u64,
}

#[derive(Serialize)]
struct NetNS {
    nsmode: String,
}

#[derive(Serialize)]
struct NetworkAttachment {}

#[derive(Serialize)]
struct LinuxDevice {
    path: String,
}

/// Default limits: 2 CPU cores (200000µs quota / 100000µs period), 4 GiB memory.
const DEFAULT_CPU_QUOTA: u64 = 200_000;
const DEFAULT_CPU_PERIOD: u64 = 100_000;
const DEFAULT_MEMORY_LIMIT: u64 = 4_294_967_296; // 4 GiB

/// Resolve the OCI image reference for a sandbox, using the template image
/// if provided, otherwise the driver's default image.
#[must_use]
pub fn resolve_image<'a>(sandbox: &'a DriverSandbox, config: &'a PodmanComputeConfig) -> &'a str {
    let spec = sandbox.spec.as_ref();
    let template = spec.and_then(|s| s.template.as_ref());
    template
        .map(|t| t.image.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(&config.default_image)
}

/// Merge environment variables from user spec/template with required driver vars.
///
/// User-supplied vars are inserted first so that the required driver
/// vars always win -- preventing spec/template overrides of security-
/// critical values like `OPENSHELL_ENDPOINT` or `OPENSHELL_SANDBOX_ID`.
fn build_env(
    sandbox: &DriverSandbox,
    config: &PodmanComputeConfig,
    image: &str,
) -> BTreeMap<String, String> {
    let spec = sandbox.spec.as_ref();
    let template = spec.and_then(|s| s.template.as_ref());

    let mut env: BTreeMap<String, String> = BTreeMap::new();

    // 1. User-supplied environment (lowest priority).
    if let Some(s) = spec {
        if !s.log_level.is_empty() {
            env.insert("OPENSHELL_LOG_LEVEL".into(), s.log_level.clone());
        }
        for (k, v) in &s.environment {
            env.insert(k.clone(), v.clone());
        }
    }
    if let Some(t) = template {
        for (k, v) in &t.environment {
            env.insert(k.clone(), v.clone());
        }
    }

    // 2. Required driver vars (highest priority -- always overwrite).
    env.insert("OPENSHELL_SANDBOX".into(), sandbox.name.clone());
    env.insert("OPENSHELL_SANDBOX_ID".into(), sandbox.id.clone());
    env.insert("OPENSHELL_ENDPOINT".into(), config.grpc_endpoint.clone());
    env.insert(
        "OPENSHELL_SSH_SOCKET_PATH".into(),
        config.sandbox_ssh_socket_path.clone(),
    );
    // NOTE: The SSH handshake secret is injected via a Podman secret
    // (see the "secrets" field below) rather than a plaintext env var.
    // This prevents exposure through `podman inspect`.
    env.insert(
        "OPENSHELL_SSH_HANDSHAKE_SKEW_SECS".into(),
        config.ssh_handshake_skew_secs.to_string(),
    );
    env.insert("OPENSHELL_CONTAINER_IMAGE".into(), image.to_string());
    env.insert("OPENSHELL_SANDBOX_COMMAND".into(), "sleep infinity".into());

    // 3. TLS client cert paths (when mTLS is enabled). These point to
    //    the container-side mount paths where the cert files are
    //    bind-mounted from the host.
    if config.tls_enabled() {
        env.insert("OPENSHELL_TLS_CA".into(), TLS_CA_MOUNT_PATH.into());
        env.insert("OPENSHELL_TLS_CERT".into(), TLS_CERT_MOUNT_PATH.into());
        env.insert("OPENSHELL_TLS_KEY".into(), TLS_KEY_MOUNT_PATH.into());
    }

    env
}

/// Merge labels from the sandbox template with required managed labels.
///
/// User-supplied labels are inserted first so that the managed labels
/// always win -- preventing template overrides of internal tracking labels.
fn build_labels(sandbox: &DriverSandbox) -> BTreeMap<String, String> {
    let template = sandbox.spec.as_ref().and_then(|s| s.template.as_ref());

    let mut labels: BTreeMap<String, String> = BTreeMap::new();
    if let Some(t) = template {
        for (k, v) in &t.labels {
            labels.insert(k.clone(), v.clone());
        }
    }
    // Managed labels (highest priority -- always overwrite).
    labels.insert(LABEL_SANDBOX_ID.into(), sandbox.id.clone());
    labels.insert(LABEL_SANDBOX_NAME.into(), sandbox.name.clone());
    labels.insert(LABEL_SANDBOX_NAMESPACE.into(), sandbox.namespace.clone());
    labels.insert(LABEL_MANAGED.into(), "true".into());

    labels
}

/// Parse resource limits from the sandbox template, falling back to defaults.
fn build_resource_limits(sandbox: &DriverSandbox) -> ResourceLimits {
    let resources = sandbox
        .spec
        .as_ref()
        .and_then(|s| s.template.as_ref())
        .and_then(|t| t.resources.as_ref());

    let cpu_micros = resources
        .filter(|r| !r.cpu_limit.is_empty())
        .and_then(|r| parse_cpu_to_microseconds(&r.cpu_limit))
        .unwrap_or(DEFAULT_CPU_QUOTA);

    let mem_bytes = resources
        .filter(|r| !r.memory_limit.is_empty())
        .and_then(|r| parse_memory_to_bytes(&r.memory_limit))
        .unwrap_or(DEFAULT_MEMORY_LIMIT);

    ResourceLimits {
        cpu: CpuLimits {
            quota: cpu_micros,
            period: DEFAULT_CPU_PERIOD,
        },
        memory: MemoryLimits { limit: mem_bytes },
    }
}

/// Build CDI GPU device list if GPU is requested.
fn build_devices(sandbox: &DriverSandbox) -> Option<Vec<LinuxDevice>> {
    if sandbox.spec.as_ref().is_some_and(|s| s.gpu) {
        Some(vec![LinuxDevice {
            path: CDI_GPU_DEVICE_ALL.into(),
        }])
    } else {
        None
    }
}

/// Build the Podman container creation JSON spec.
#[must_use]
pub fn build_container_spec(sandbox: &DriverSandbox, config: &PodmanComputeConfig) -> Value {
    let image = resolve_image(sandbox, config);
    let name = container_name(&sandbox.name);
    let vol = volume_name(&sandbox.id);

    let env = build_env(sandbox, config, image);
    let labels = build_labels(sandbox);
    let resource_limits = build_resource_limits(sandbox);
    let devices = build_devices(sandbox);

    // Network configuration -- always bridge mode.
    // Matches libpod's network spec format `{name: {opts}}`; the unit-struct
    // value mirrors empty opts in the JSON.
    #[allow(clippy::zero_sized_map_values)]
    let mut networks = BTreeMap::new();
    networks.insert(config.network_name.clone(), NetworkAttachment {});

    let container_spec = ContainerSpec {
        name,
        image: image.to_string(),
        labels,
        env,
        volumes: vec![NamedVolume {
            name: vol,
            dest: "/sandbox".into(),
            options: vec!["rw".into()],
        }],
        // Side-load the supervisor binary from a standalone OCI image.
        // Podman resolves image_volumes at the libpod layer, mounting the
        // image's filesystem at the destination path without starting a
        // container from it. The supervisor image is FROM scratch with just
        // the binary at /openshell-sandbox, so it appears at
        // /opt/openshell/bin/openshell-sandbox.
        image_volumes: vec![ImageVolume {
            source: config.supervisor_image.clone(),
            destination: "/opt/openshell/bin".into(),
            rw: false,
        }],
        hostname: format!("sandbox-{}", sandbox.name),
        // Override the image's ENTRYPOINT so the supervisor binary runs
        // directly. Sandbox images (e.g. the community base image) set
        // ENTRYPOINT ["/bin/bash"], and Podman's `command` field only
        // overrides CMD — which gets appended as args to the entrypoint.
        // Without this, the container would run `/bin/bash /opt/openshell/bin/openshell-sandbox`
        // and bash would fail trying to interpret the binary as a script.
        entrypoint: vec!["/opt/openshell/bin/openshell-sandbox".into()],
        command: vec![],
        // Force the supervisor to run as root (UID 0). Sandbox images may
        // set a non-root USER directive (e.g. `USER sandbox`), but the
        // supervisor needs root to create network namespaces, set up the
        // proxy, and configure Landlock/seccomp. This matches the K8s
        // driver's runAsUser: 0.
        user: "0:0".into(),
        // Podman's default container capability set is already restricted:
        //   CHOWN DAC_OVERRIDE FOWNER FSETID KILL SETGID SETUID SETPCAP
        //   NET_BIND_SERVICE SYS_CHROOT SETFCAP
        // We add what the supervisor needs and drop what it doesn't.
        cap_drop: vec![
            // Not needed: standard file permission bits are sufficient; dropping
            // prevents the supervisor from bypassing DAC checks it shouldn't need.
            "DAC_OVERRIDE".into(),
            // Not needed: the supervisor does not create setuid/setgid executables.
            "FSETID".into(),
            // Not needed: the supervisor does not send signals to arbitrary processes.
            "KILL".into(),
            // Not needed: the supervisor does not bind privileged ports (<1024).
            "NET_BIND_SERVICE".into(),
            // Not in Podman's default set but explicitly denied in case the image
            // or runtime adds it; raw sockets are not required.
            "NET_RAW".into(),
            // Not needed: the supervisor does not manipulate file capabilities.
            "SETFCAP".into(),
            // Not needed: the supervisor does not manage its own capability bounding set.
            "SETPCAP".into(),
            // Not needed: the supervisor does not call chroot().
            "SYS_CHROOT".into(),
        ],
        cap_add: vec![
            // seccomp filter installation, namespace creation, Landlock setup.
            "SYS_ADMIN".into(),
            // Network namespace veth setup, IP/route configuration.
            "NET_ADMIN".into(),
            // Reading /proc/<pid>/exe and ancestor walk for process identity in policy.
            "SYS_PTRACE".into(),
            // Reading /dev/kmsg for bypass-detection diagnostics.
            "SYSLOG".into(),
            // Reading /proc/<pid>/fd/ across UIDs for process identity resolution.
            // In rootless Podman the supervisor runs as UID 0 inside a user namespace
            // while sandbox processes run as the sandbox user. The kernel's
            // proc_fd_permission() calls generic_permission() which denies cross-UID
            // access to the dr-x------ fd directory unless this cap is present.
            // Without it the proxy cannot determine which binary made each outbound
            // connection and all traffic is denied.
            "DAC_READ_SEARCH".into(),
        ],
        // SETUID, SETGID, CHOWN, and FOWNER are intentionally kept from Podman's
        // default set and not dropped:
        //   SETUID/SETGID – drop_privileges(): setuid()/setgid()/initgroups() to the
        //                   sandbox user. In rootless Podman cap_drop:ALL removes them
        //                   from the bounding set even though uid=0 owns the user
        //                   namespace — so we keep them by not dropping them explicitly.
        //   CHOWN         – prepare_filesystem(): chown(path, uid, gid) on newly
        //                   created read_write directories so the sandbox user can
        //                   write to them.
        //   FOWNER        – chown on files where the supervisor is not the owner
        //                   (e.g. pre-existing directories owned by another user).
        //
        // Disable the container-level seccomp profile. The sandbox supervisor The sandbox supervisor
        // installs its own policy-aware BPF seccomp filter at runtime via
        // seccompiler (two-phase: clone3 blocker + main filter). The runtime
        // filter is more restrictive than Podman's default — it blocks 20+
        // dangerous syscalls and conditionally restricts socket domains based
        // on network policy. The filter self-seals by blocking further
        // seccomp(SET_MODE_FILTER) calls after installation.
        //
        // A container-level profile would interfere by blocking the landlock
        // and seccomp syscalls the supervisor needs during setup, before it
        // locks itself down.
        no_new_privileges: true,
        seccomp_profile_path: "unconfined".into(),
        image_pull_policy: config.image_pull_policy.as_str().to_string(),
        healthconfig: HealthConfig {
            test: vec![
                "CMD-SHELL".into(),
                format!(
                    "test -e /var/run/openshell-ssh-ready || test -S {} || ss -tlnp | grep -q :{}",
                    config.sandbox_ssh_socket_path, config.ssh_port
                ),
            ],
            interval: 3_000_000_000,
            timeout: 2_000_000_000,
            retries: 10,
            start_period: 5_000_000_000,
        },
        resource_limits,
        // Inject the SSH handshake secret via Podman's secret_env map so it
        // does not appear in `podman inspect` output. The libpod SpecGenerator
        // uses `secret_env` (map of env_var → secret_name) for env-type secrets,
        // distinct from `secrets` which only handles file mounts under /run/secrets/.
        // The secret is created by the driver before the container
        // (see `PodmanComputeDriver::create_sandbox`).
        secret_env: BTreeMap::from([(
            "OPENSHELL_SSH_HANDSHAKE_SECRET".into(),
            secret_name(&sandbox.id),
        )]),
        stop_timeout: config.stop_timeout_secs,
        // Inject stable host aliases into /etc/hosts so sandbox containers can
        // reach services on the host. `host.openshell.internal` is the driver-
        // neutral alias used by policies and e2e tests.
        hostadd: vec![
            "host.containers.internal:host-gateway".into(),
            "host.openshell.internal:host-gateway".into(),
        ],
        netns: NetNS {
            nsmode: "bridge".to_string(),
        },
        networks,
        devices,
        // Mount a tmpfs at /run/netns so the sandbox supervisor can create
        // named network namespaces via `ip netns add`. The `ip` command requires
        // /run/netns to exist and be bind-mountable; in rootless Podman this
        // directory does not exist on the host, so the mkdir inside the container
        // fails with EPERM. A private tmpfs gives the supervisor its own writable
        // /run/netns without needing host filesystem access.
        mounts: {
            let mut m = vec![Mount {
                kind: "tmpfs".into(),
                source: "tmpfs".into(),
                destination: "/run/netns".into(),
                options: vec!["rw".into(), "nosuid".into(), "nodev".into()],
            }];
            // Bind-mount client TLS materials into the container when mTLS
            // is enabled. The supervisor reads these via OPENSHELL_TLS_CA,
            // OPENSHELL_TLS_CERT, and OPENSHELL_TLS_KEY env vars (set in
            // build_env above) to establish an mTLS connection back to the
            // gateway.
            if let (Some(ca), Some(cert), Some(key)) = (
                &config.guest_tls_ca,
                &config.guest_tls_cert,
                &config.guest_tls_key,
            ) {
                let mut ro = vec!["ro".into(), "rbind".into()];
                // On SELinux-enabled systems (Fedora, RHEL), bind-mounted
                // files need the shared relabel option so the container
                // process can read them through the SELinux MAC policy.
                if is_selinux_enabled() {
                    ro.push("z".into());
                }
                m.push(Mount {
                    kind: "bind".into(),
                    source: ca.display().to_string(),
                    destination: TLS_CA_MOUNT_PATH.into(),
                    options: ro.clone(),
                });
                m.push(Mount {
                    kind: "bind".into(),
                    source: cert.display().to_string(),
                    destination: TLS_CERT_MOUNT_PATH.into(),
                    options: ro.clone(),
                });
                m.push(Mount {
                    kind: "bind".into(),
                    source: key.display().to_string(),
                    destination: TLS_KEY_MOUNT_PATH.into(),
                    options: ro,
                });
            }
            m
        },
        // Publish the SSH port with host_port=0 to get an ephemeral host port.
        // In rootless Podman the bridge network (10.89.x.x) is not routable from
        // the host, so we must use the published host port on 127.0.0.1 instead.
        portmappings: vec![PortMapping {
            host_port: 0,
            container_port: config.ssh_port,
            protocol: "tcp".into(),
        }],
    };

    serde_json::to_value(container_spec).expect("ContainerSpec serialization cannot fail")
}

/// Parse a Kubernetes-style CPU quantity to cgroup quota microseconds
/// (for a 100ms period).
///
/// Examples: `"500m"` → 50000, `"2"` → 200000, `"0.5"` → 50000.
fn parse_cpu_to_microseconds(quantity: &str) -> Option<u64> {
    let micros = if let Some(millis_str) = quantity.strip_suffix('m') {
        let millis: u64 = millis_str.parse().ok()?;
        // quota = millis * period / 1000
        millis.checked_mul(100)?
    } else {
        let cores: f64 = quantity.parse().ok()?;
        if cores <= 0.0 || cores.is_nan() || cores.is_infinite() {
            return None;
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let val = (cores * 100_000.0) as u64;
        val
    };
    // A quota of 0 microseconds is invalid — treat as no limit.
    if micros == 0 { None } else { Some(micros) }
}

/// Parse a Kubernetes-style memory quantity to bytes.
///
/// Supports: `Ki`, `Mi`, `Gi`, `Ti` (binary) and `k`, `M`, `G`, `T`
/// (decimal), as well as plain byte values.
fn parse_memory_to_bytes(quantity: &str) -> Option<u64> {
    let suffixes: &[(&str, u64)] = &[
        ("Ti", 1024 * 1024 * 1024 * 1024),
        ("Gi", 1024 * 1024 * 1024),
        ("Mi", 1024 * 1024),
        ("Ki", 1024),
        ("T", 1_000_000_000_000),
        ("G", 1_000_000_000),
        ("M", 1_000_000),
        ("k", 1_000),
    ];

    for (suffix, multiplier) in suffixes {
        if let Some(num_str) = quantity.strip_suffix(suffix) {
            let num: u64 = num_str.parse().ok()?;
            return num.checked_mul(*multiplier);
        }
    }

    // Plain bytes.
    quantity.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cpu_millicore() {
        assert_eq!(parse_cpu_to_microseconds("500m"), Some(50_000));
        assert_eq!(parse_cpu_to_microseconds("1000m"), Some(100_000));
        assert_eq!(parse_cpu_to_microseconds("250m"), Some(25_000));
    }

    #[test]
    fn parse_cpu_whole_cores() {
        assert_eq!(parse_cpu_to_microseconds("1"), Some(100_000));
        assert_eq!(parse_cpu_to_microseconds("2"), Some(200_000));
        assert_eq!(parse_cpu_to_microseconds("0.5"), Some(50_000));
    }

    #[test]
    fn parse_memory_binary_suffixes() {
        assert_eq!(parse_memory_to_bytes("256Mi"), Some(256 * 1024 * 1024));
        assert_eq!(parse_memory_to_bytes("4Gi"), Some(4 * 1024 * 1024 * 1024));
        assert_eq!(parse_memory_to_bytes("1Ki"), Some(1024));
    }

    #[test]
    fn parse_memory_decimal_suffixes() {
        assert_eq!(parse_memory_to_bytes("1G"), Some(1_000_000_000));
        assert_eq!(parse_memory_to_bytes("500M"), Some(500_000_000));
    }

    #[test]
    fn parse_memory_plain_bytes() {
        assert_eq!(parse_memory_to_bytes("1048576"), Some(1_048_576));
    }

    #[test]
    fn container_name_is_prefixed() {
        assert_eq!(container_name("my-sandbox"), "openshell-sandbox-my-sandbox");
    }

    #[test]
    fn volume_name_uses_id() {
        assert_eq!(
            volume_name("abc-123"),
            "openshell-sandbox-abc-123-workspace"
        );
    }

    #[test]
    fn secret_name_uses_id() {
        assert_eq!(secret_name("abc-123"), "openshell-handshake-abc-123");
    }

    #[test]
    fn short_id_truncates() {
        assert_eq!(short_id("abc123def456789"), "abc123def456");
        assert_eq!(short_id("short"), "short");
    }

    #[test]
    fn container_spec_includes_required_capabilities() {
        let sandbox = test_sandbox("test-id", "test-name");
        let config = test_config();
        let spec = build_container_spec(&sandbox, &config);

        let added: Vec<&str> = spec["cap_add"]
            .as_array()
            .expect("cap_add should be an array")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(added.contains(&"SYS_ADMIN"), "missing SYS_ADMIN");
        assert!(added.contains(&"NET_ADMIN"), "missing NET_ADMIN");
        assert!(added.contains(&"SYS_PTRACE"), "missing SYS_PTRACE");
        assert!(added.contains(&"SYSLOG"), "missing SYSLOG");
        assert!(
            added.contains(&"DAC_READ_SEARCH"),
            "missing DAC_READ_SEARCH"
        );

        // SETUID and SETGID are NOT in cap_add — they remain available from the
        // default bounding set because we no longer use cap_drop:ALL. Verify they
        // are also not explicitly dropped. Similarly CHOWN and FOWNER must not be
        // dropped because prepare_filesystem() calls chown() on newly created
        // read_write directories before the supervisor drops privileges.
        let dropped: Vec<&str> = spec["cap_drop"]
            .as_array()
            .expect("cap_drop should be an array")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(!dropped.contains(&"SETUID"), "SETUID must not be dropped");
        assert!(!dropped.contains(&"SETGID"), "SETGID must not be dropped");
        assert!(
            !dropped.contains(&"CHOWN"),
            "CHOWN must not be dropped (needed for prepare_filesystem chown)"
        );
        assert!(
            !dropped.contains(&"FOWNER"),
            "FOWNER must not be dropped (needed for chown on non-owned files)"
        );
        assert!(
            !dropped.contains(&"ALL"),
            "must not use cap_drop:ALL in rootless Podman"
        );
    }

    #[test]
    fn container_spec_uses_secret_env_not_plaintext() {
        let sandbox = test_sandbox("test-id", "test-name");
        let config = test_config();
        let spec = build_container_spec(&sandbox, &config);

        // The handshake secret must NOT appear in the plaintext env map.
        let env_map = spec["env"].as_object().expect("env should be an object");
        assert!(
            !env_map.contains_key("OPENSHELL_SSH_HANDSHAKE_SECRET"),
            "handshake secret should not be in plaintext env"
        );

        // It should appear in secret_env (the libpod env-type secret map) instead.
        let secret_env = spec["secret_env"]
            .as_object()
            .expect("secret_env should be an object");
        assert!(
            secret_env.contains_key("OPENSHELL_SSH_HANDSHAKE_SECRET"),
            "secret_env should map OPENSHELL_SSH_HANDSHAKE_SECRET to its secret name"
        );
        assert_eq!(
            secret_env["OPENSHELL_SSH_HANDSHAKE_SECRET"].as_str(),
            Some("openshell-handshake-test-id"),
            "secret_env value should be the Podman secret name for the sandbox"
        );
    }

    #[test]
    fn container_spec_sets_sandbox_name_in_env() {
        let sandbox = test_sandbox("test-id", "my-sandbox");
        let config = test_config();
        let spec = build_container_spec(&sandbox, &config);

        let env_map = spec["env"].as_object().expect("env should be an object");
        assert_eq!(
            env_map.get("OPENSHELL_SANDBOX").and_then(|v| v.as_str()),
            Some("my-sandbox"),
        );
    }

    #[test]
    fn container_spec_sets_ssh_socket_path_in_env() {
        let sandbox = test_sandbox("test-id", "test-name");
        let config = test_config();
        let spec = build_container_spec(&sandbox, &config);

        let env_map = spec["env"].as_object().expect("env should be an object");
        assert_eq!(
            env_map
                .get("OPENSHELL_SSH_SOCKET_PATH")
                .and_then(|v| v.as_str()),
            Some("/run/openshell/test-ssh.sock"),
        );
    }

    #[test]
    fn container_spec_healthcheck_accepts_supervisor_socket() {
        let sandbox = test_sandbox("test-id", "test-name");
        let config = test_config();
        let spec = build_container_spec(&sandbox, &config);

        let healthcheck = spec["healthconfig"]["test"]
            .as_array()
            .expect("healthcheck test should be an array");
        let command = healthcheck
            .get(1)
            .and_then(|v| v.as_str())
            .expect("healthcheck should include shell command");
        assert!(
            command.contains("test -S /run/openshell/test-ssh.sock"),
            "healthcheck should consider the supervisor Unix socket ready"
        );
    }

    #[test]
    fn container_spec_required_vars_cannot_be_overridden() {
        use openshell_core::proto::compute::v1::{DriverSandboxSpec, DriverSandboxTemplate};

        let mut sandbox = test_sandbox("test-id", "legit-name");
        let mut env_overrides = std::collections::HashMap::new();
        env_overrides.insert(
            "OPENSHELL_ENDPOINT".to_string(),
            "http://evil.example.com".to_string(),
        );
        env_overrides.insert("OPENSHELL_SANDBOX_ID".to_string(), "spoofed-id".to_string());
        env_overrides.insert(
            "OPENSHELL_SSH_SOCKET_PATH".to_string(),
            "/tmp/evil.sock".to_string(),
        );
        sandbox.spec = Some(DriverSandboxSpec {
            environment: env_overrides,
            template: Some(DriverSandboxTemplate::default()),
            ..Default::default()
        });

        let config = test_config();
        let spec = build_container_spec(&sandbox, &config);

        let env_map = spec["env"].as_object().expect("env should be an object");

        assert_eq!(
            env_map.get("OPENSHELL_ENDPOINT").and_then(|v| v.as_str()),
            Some("http://localhost:50051"),
            "OPENSHELL_ENDPOINT must not be overridden by user env"
        );
        assert_eq!(
            env_map.get("OPENSHELL_SANDBOX_ID").and_then(|v| v.as_str()),
            Some("test-id"),
            "OPENSHELL_SANDBOX_ID must not be overridden by user env"
        );
        assert_eq!(
            env_map
                .get("OPENSHELL_SSH_SOCKET_PATH")
                .and_then(|v| v.as_str()),
            Some("/run/openshell/test-ssh.sock"),
            "OPENSHELL_SSH_SOCKET_PATH must not be overridden by user env"
        );
    }

    #[test]
    fn container_spec_required_labels_cannot_be_overridden() {
        use openshell_core::proto::compute::v1::{DriverSandboxSpec, DriverSandboxTemplate};

        let mut sandbox = test_sandbox("real-id", "real-name");
        sandbox.namespace = "real-namespace".to_string();
        let mut label_overrides = std::collections::HashMap::new();
        label_overrides.insert("openshell.sandbox-id".to_string(), "spoofed-id".to_string());
        label_overrides.insert(
            "openshell.sandbox-name".to_string(),
            "spoofed-name".to_string(),
        );
        label_overrides.insert(
            "openshell.sandbox-namespace".to_string(),
            "spoofed-namespace".to_string(),
        );
        sandbox.spec = Some(DriverSandboxSpec {
            template: Some(DriverSandboxTemplate {
                labels: label_overrides,
                ..Default::default()
            }),
            ..Default::default()
        });

        let config = test_config();
        let spec = build_container_spec(&sandbox, &config);

        let labels = spec["labels"]
            .as_object()
            .expect("labels should be an object");
        assert_eq!(
            labels.get("openshell.sandbox-id").and_then(|v| v.as_str()),
            Some("real-id"),
            "openshell.sandbox-id must not be overridden by template labels"
        );
        assert_eq!(
            labels
                .get("openshell.sandbox-name")
                .and_then(|v| v.as_str()),
            Some("real-name"),
            "openshell.sandbox-name must not be overridden by template labels"
        );
        assert_eq!(
            labels
                .get("openshell.sandbox-namespace")
                .and_then(|v| v.as_str()),
            Some("real-namespace"),
            "openshell.sandbox-namespace must not be overridden by template labels"
        );
    }

    #[test]
    fn container_spec_injects_host_aliases() {
        let sandbox = test_sandbox("test-id", "test-name");
        let config = test_config();
        let spec = build_container_spec(&sandbox, &config);

        let hostadd: Vec<&str> = spec["hostadd"]
            .as_array()
            .expect("hostadd should be an array")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();

        assert!(
            hostadd.contains(&"host.containers.internal:host-gateway"),
            "missing Podman host alias"
        );
        assert!(
            hostadd.contains(&"host.openshell.internal:host-gateway"),
            "missing OpenShell stable host alias"
        );
        assert!(
            !hostadd.contains(&"host.docker.internal:host-gateway"),
            "Podman should not inject Docker's host alias"
        );
    }

    #[test]
    fn parse_cpu_negative_returns_none() {
        assert_eq!(parse_cpu_to_microseconds("-1"), None);
        assert_eq!(parse_cpu_to_microseconds("-500m"), None);
    }

    #[test]
    fn parse_cpu_zero_returns_none() {
        assert_eq!(parse_cpu_to_microseconds("0m"), None);
        assert_eq!(parse_cpu_to_microseconds("0"), None);
    }

    fn test_sandbox(id: &str, name: &str) -> DriverSandbox {
        DriverSandbox {
            id: id.to_string(),
            name: name.to_string(),
            namespace: String::new(),
            spec: None,
            status: None,
        }
    }

    fn test_config() -> PodmanComputeConfig {
        PodmanComputeConfig {
            socket_path: std::path::PathBuf::from("/tmp/test.sock"),
            default_image: "test-image:latest".to_string(),
            grpc_endpoint: "http://localhost:50051".to_string(),
            sandbox_ssh_socket_path: "/run/openshell/test-ssh.sock".to_string(),
            ssh_handshake_secret: "test-secret-value".to_string(),
            ..PodmanComputeConfig::default()
        }
    }

    #[test]
    fn container_spec_includes_supervisor_image_volume() {
        let sandbox = test_sandbox("test-id", "test-name");
        let config = test_config();
        let spec = build_container_spec(&sandbox, &config);

        let image_volumes = spec["image_volumes"]
            .as_array()
            .expect("image_volumes should be an array");
        assert_eq!(
            image_volumes.len(),
            1,
            "should have exactly one image volume"
        );

        let vol = &image_volumes[0];
        assert_eq!(
            vol["source"].as_str(),
            Some("openshell/supervisor:latest"),
            "image volume source should be the supervisor image"
        );
        assert_eq!(
            vol["destination"].as_str(),
            Some("/opt/openshell/bin"),
            "image volume destination should be /opt/openshell/bin"
        );
        assert_eq!(
            vol["rw"].as_bool(),
            Some(false),
            "image volume should be read-only"
        );
    }

    #[test]
    fn container_spec_includes_tls_mounts_when_configured() {
        let sandbox = test_sandbox("tls-id", "tls-name");
        let mut config = test_config();
        config.guest_tls_ca = Some(std::path::PathBuf::from("/host/ca.crt"));
        config.guest_tls_cert = Some(std::path::PathBuf::from("/host/tls.crt"));
        config.guest_tls_key = Some(std::path::PathBuf::from("/host/tls.key"));

        let spec = build_container_spec(&sandbox, &config);

        // Verify TLS env vars are set.
        let env_map = spec["env"].as_object().expect("env should be an object");
        assert_eq!(
            env_map.get("OPENSHELL_TLS_CA").and_then(|v| v.as_str()),
            Some("/etc/openshell/tls/client/ca.crt"),
        );
        assert_eq!(
            env_map.get("OPENSHELL_TLS_CERT").and_then(|v| v.as_str()),
            Some("/etc/openshell/tls/client/tls.crt"),
        );
        assert_eq!(
            env_map.get("OPENSHELL_TLS_KEY").and_then(|v| v.as_str()),
            Some("/etc/openshell/tls/client/tls.key"),
        );

        // Verify bind mounts exist for all three cert files.
        let mounts = spec["mounts"]
            .as_array()
            .expect("mounts should be an array");
        let bind_dests: Vec<&str> = mounts
            .iter()
            .filter(|m| m["type"].as_str() == Some("bind"))
            .filter_map(|m| m["destination"].as_str())
            .collect();
        assert!(
            bind_dests.contains(&"/etc/openshell/tls/client/ca.crt"),
            "should bind-mount CA cert"
        );
        assert!(
            bind_dests.contains(&"/etc/openshell/tls/client/tls.crt"),
            "should bind-mount client cert"
        );
        assert!(
            bind_dests.contains(&"/etc/openshell/tls/client/tls.key"),
            "should bind-mount client key"
        );

        // Verify SELinux relabel option is present iff SELinux is enabled.
        let tls_binds: Vec<&Value> = mounts
            .iter()
            .filter(|m| m["type"].as_str() == Some("bind"))
            .collect();
        let has_z = tls_binds.iter().all(|m| {
            m["options"]
                .as_array()
                .is_some_and(|opts| opts.iter().any(|o| o.as_str() == Some("z")))
        });
        assert_eq!(
            has_z,
            is_selinux_enabled(),
            "TLS bind mounts should include 'z' option iff SELinux is enabled"
        );
    }

    #[test]
    fn container_spec_omits_tls_without_config() {
        let sandbox = test_sandbox("notls-id", "notls-name");
        let config = test_config();

        let spec = build_container_spec(&sandbox, &config);

        let env_map = spec["env"].as_object().expect("env should be an object");
        assert!(
            env_map.get("OPENSHELL_TLS_CA").is_none(),
            "TLS env vars should not be set without TLS config"
        );

        let mounts = spec["mounts"]
            .as_array()
            .expect("mounts should be an array");
        let bind_count = mounts
            .iter()
            .filter(|m| m["type"].as_str() == Some("bind"))
            .count();
        assert_eq!(bind_count, 0, "no bind mounts without TLS config");
    }
}
