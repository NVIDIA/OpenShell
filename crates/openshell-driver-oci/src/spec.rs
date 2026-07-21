// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCI runtime-spec (`config.json`) generation.
//!
//! This is where `OpenShell` policy is mapped onto kernel primitives: Linux
//! namespaces, cgroups v2 resource limits, and the capability set. The
//! resulting [`Spec`] is handed to containerd, which drives the configured
//! low-level runtime (`runc`, `crun`, ...) through the standard
//! `create`/`start`/`state`/`delete` contract — this module never invokes
//! that runtime itself.
//!
//! Namespace and capability defaults here intentionally mirror the Podman
//! driver's container spec (`openshell-driver-podman/src/container.rs`) so
//! the security posture of the supervisor's outer boundary is consistent
//! across drivers; see the inline comments there for the full rationale
//! behind each capability.

use std::path::{Path, PathBuf};

use oci_spec::runtime::{
    Capabilities, Capability, LinuxBuilder, LinuxCapabilitiesBuilder, LinuxCpuBuilder,
    LinuxIdMapping, LinuxIdMappingBuilder, LinuxMemoryBuilder, LinuxNamespace, LinuxNamespaceType,
    LinuxPids, LinuxResourcesBuilder, Mount as OciMount, MountBuilder, ProcessBuilder, RootBuilder,
    Spec, SpecBuilder, User, get_default_mounts, get_default_namespaces,
};

use crate::config::OciComputeConfig;

/// Extra bind mount to add to the container spec beyond the rootfs and the
/// OCI-default mounts (proc/sysfs/devpts/shm/mqueue).
pub struct ExtraMount {
    pub destination: String,
    pub source: PathBuf,
    pub read_only: bool,
}

impl ExtraMount {
    fn into_oci(self, selinux_relabel: bool) -> Result<OciMount, String> {
        let mut options = vec!["bind".to_string()];
        options.push(if self.read_only { "ro" } else { "rw" }.to_string());
        if selinux_relabel {
            // Shared relabel so the container process can read the bind
            // mount through the host's SELinux MAC policy (matches the
            // Podman driver's handling of the same TLS bind mounts).
            options.push("z".to_string());
        }
        MountBuilder::default()
            .destination(self.destination)
            .typ("bind".to_string())
            .source(self.source)
            .options(options)
            .build()
            .map_err(|e| e.to_string())
    }
}

/// Effective capability set granted to the sandbox's outer container
/// process (the `openshell-sandbox` supervisor). Computed once, ahead of
/// time, from Podman's documented default set plus the same adds/drops the
/// Podman driver applies — see `openshell-driver-podman/src/container.rs`
/// for the full per-capability rationale. The OCI runtime spec requires an
/// explicit allow-list (unlike Docker/Podman's engine-level add/drop
/// flags), so this is the fully resolved result of that arithmetic:
/// CHOWN, FOWNER, SETGID, SETUID, SETPCAP, `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`,
/// SYSLOG, `DAC_READ_SEARCH`.
fn supervisor_capabilities() -> Capabilities {
    [
        Capability::Chown,
        Capability::Fowner,
        Capability::Setgid,
        Capability::Setuid,
        Capability::Setpcap,
        Capability::SysAdmin,
        Capability::NetAdmin,
        Capability::SysPtrace,
        Capability::Syslog,
        Capability::DacReadSearch,
    ]
    .into_iter()
    .collect()
}

pub struct SpecInput<'a> {
    pub config: &'a OciComputeConfig,
    pub hostname: String,
    pub args: Vec<String>,
    pub env: Vec<String>,
    /// Path to an existing network namespace this sandbox's container
    /// should join (created and torn down by [`crate::network`]).
    pub netns_path: &'a Path,
    /// CPU quota in microseconds per `cpu_period_micros` period. `None`
    /// means unlimited.
    pub cpu_quota_micros: Option<i64>,
    pub cpu_period_micros: u64,
    /// Memory limit in bytes. `None` means unlimited.
    pub memory_limit_bytes: Option<i64>,
    pub pids_limit: Option<i64>,
    pub extra_mounts: Vec<ExtraMount>,
    pub selinux_relabel_bind_mounts: bool,
}

/// Build the OCI runtime spec for a sandbox's outer container.
///
/// # Errors
/// Returns an error if the underlying `oci-spec` builders reject the
/// supplied values (this only happens for internal programming errors —
/// there is no user-controlled input that can trigger a builder failure
/// here).
pub fn build_spec(input: SpecInput<'_>) -> Result<Spec, String> {
    let root = RootBuilder::default()
        .path(PathBuf::from("rootfs"))
        .readonly(false)
        .build()
        .map_err(|e| e.to_string())?;

    let user = {
        let mut u = User::default();
        // Supervisor runs as root *inside* its user namespace (see
        // namespaces() below) — never as host root when `rootless` is
        // enabled. This matches the K8s driver's `runAsUser: 0` and the
        // Podman driver's `user: "0:0"`: the supervisor needs root inside
        // the container to create namespaces, set up cgroups, and install
        // seccomp filters for the workload it further isolates.
        u.set_uid(0);
        u.set_gid(0);
        u
    };

    let capabilities = LinuxCapabilitiesBuilder::default()
        .bounding(supervisor_capabilities())
        .effective(supervisor_capabilities())
        .permitted(supervisor_capabilities())
        .inheritable(supervisor_capabilities())
        .ambient(supervisor_capabilities())
        .build()
        .map_err(|e| e.to_string())?;

    let process = ProcessBuilder::default()
        .terminal(false)
        .user(user)
        .args(input.args)
        .cwd(PathBuf::from("/"))
        .env(input.env)
        .capabilities(capabilities)
        .no_new_privileges(true)
        .build()
        .map_err(|e| e.to_string())?;

    let mut mounts = default_mounts_for_cgroup_v2();
    mounts.push(
        MountBuilder::default()
            .destination(PathBuf::from("/run/netns"))
            .typ("tmpfs".to_string())
            .source(PathBuf::from("tmpfs"))
            .options(vec![
                "rw".to_string(),
                "nosuid".to_string(),
                "nodev".to_string(),
            ])
            .build()
            .map_err(|e| e.to_string())?,
    );
    for extra in input.extra_mounts {
        mounts.push(extra.into_oci(input.selinux_relabel_bind_mounts)?);
    }

    let namespaces = sandbox_namespaces(input.netns_path, input.config.rootless);

    let mut resources_builder = LinuxResourcesBuilder::default();
    let mut cpu = LinuxCpuBuilder::default().period(input.cpu_period_micros);
    if let Some(quota) = input.cpu_quota_micros {
        cpu = cpu.quota(quota);
    }
    resources_builder = resources_builder.cpu(cpu.build().map_err(|e| e.to_string())?);
    if let Some(limit) = input.memory_limit_bytes {
        let memory = LinuxMemoryBuilder::default()
            .limit(limit)
            .build()
            .map_err(|e| e.to_string())?;
        resources_builder = resources_builder.memory(memory);
    }
    if let Some(limit) = input.pids_limit {
        let mut pids = LinuxPids::default();
        pids.set_limit(limit);
        resources_builder = resources_builder.pids(pids);
    }
    let resources = resources_builder.build().map_err(|e| e.to_string())?;

    let mut linux_builder = LinuxBuilder::default()
        .namespaces(namespaces)
        .resources(resources);

    if input.config.rootless {
        let mapping = user_namespace_mapping(input.config);
        linux_builder = linux_builder
            .uid_mappings(vec![mapping])
            .gid_mappings(vec![mapping]);
    }

    let linux = linux_builder.build().map_err(|e| e.to_string())?;

    SpecBuilder::default()
        .version("1.1.0".to_string())
        .root(root)
        .hostname(input.hostname)
        .mounts(mounts)
        .process(process)
        .linux(linux)
        .build()
        .map_err(|e| e.to_string())
}

/// Default namespace set (pid, ipc, uts, mnt, cgroup, net) plus an optional
/// user namespace, with the network namespace pointed at a pre-created,
/// driver-managed netns (see [`crate::network`]) instead of a fresh one —
/// this is what lets the veth pair set up outside the container land
/// exactly where the container's network namespace resolves to. Verified
/// against a real containerd + runc: joining a pre-created empty netns this
/// way isolates the container to `lo` only, with none of the host's
/// interfaces visible.
fn sandbox_namespaces(netns_path: &Path, rootless: bool) -> Vec<LinuxNamespace> {
    let mut namespaces = get_default_namespaces();
    for ns in &mut namespaces {
        if ns.typ() == LinuxNamespaceType::Network {
            ns.set_path(Some(netns_path.to_path_buf()));
        }
    }
    if rootless {
        namespaces.push(LinuxNamespace::default());
        if let Some(user_ns) = namespaces.last_mut() {
            user_ns.set_typ(LinuxNamespaceType::User);
        }
    }
    namespaces
}

/// Map the full configured UID/GID range starting at container ID 0 to the
/// configured host base. Container root (0) therefore never runs as host
/// root when `rootless` is enabled, even though the runtime invocation
/// this driver performs itself is not rootless.
fn user_namespace_mapping(config: &OciComputeConfig) -> LinuxIdMapping {
    LinuxIdMappingBuilder::default()
        .host_id(config.user_namespace_id_base)
        .container_id(0u32)
        .size(config.user_namespace_id_count)
        .build()
        .expect("static mapping fields always build")
}

/// `get_default_mounts()` mounts `/sys/fs/cgroup` as `cgroup` (the cgroup v1
/// per-controller mount type). Almost every current Linux host (including
/// this driver's own development/test environment) runs the cgroup v2
/// unified hierarchy, which needs the single `cgroup2` mount type instead.
fn default_mounts_for_cgroup_v2() -> Vec<OciMount> {
    get_default_mounts()
        .into_iter()
        .map(|mount| {
            if mount.destination() == &PathBuf::from("/sys/fs/cgroup") {
                MountBuilder::default()
                    .destination(PathBuf::from("/sys/fs/cgroup"))
                    .typ("cgroup2".to_string())
                    .source(PathBuf::from("cgroup"))
                    .options(vec![
                        "nosuid".to_string(),
                        "noexec".to_string(),
                        "nodev".to_string(),
                        "relatime".to_string(),
                    ])
                    .build()
                    .expect("static cgroup2 mount always builds")
            } else {
                mount
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> OciComputeConfig {
        OciComputeConfig::default()
    }

    fn minimal_input(config: &OciComputeConfig) -> SpecInput<'_> {
        SpecInput {
            config,
            hostname: "sandbox-test".to_string(),
            args: vec!["/opt/openshell/bin/openshell-sandbox".to_string()],
            env: vec!["OPENSHELL_SANDBOX_ID=test".to_string()],
            netns_path: Path::new("/run/netns/oshtest"),
            cpu_quota_micros: Some(200_000),
            cpu_period_micros: 100_000,
            memory_limit_bytes: Some(4 * 1024 * 1024 * 1024),
            pids_limit: Some(4096),
            extra_mounts: Vec::new(),
            selinux_relabel_bind_mounts: false,
        }
    }

    #[test]
    fn builds_a_valid_spec() {
        let config = test_config();
        let spec = build_spec(minimal_input(&config)).expect("spec builds");
        assert_eq!(spec.hostname().as_deref(), Some("sandbox-test"));
        assert_eq!(
            spec.process().as_ref().unwrap().args().as_ref().unwrap()[0],
            "/opt/openshell/bin/openshell-sandbox"
        );
    }

    #[test]
    fn network_namespace_joins_the_configured_netns_path() {
        let config = test_config();
        let spec = build_spec(minimal_input(&config)).expect("spec builds");
        let linux = spec.linux().as_ref().expect("linux config present");
        let net_ns = linux
            .namespaces()
            .as_ref()
            .expect("namespaces present")
            .iter()
            .find(|ns| ns.typ() == LinuxNamespaceType::Network)
            .expect("network namespace present");
        assert_eq!(
            net_ns.path().as_deref(),
            Some(Path::new("/run/netns/oshtest"))
        );
    }

    #[test]
    fn rootless_adds_user_namespace_with_configured_mapping() {
        // `rootless` defaults to `false` (see `OciComputeConfig::rootless`
        // doc comment for the known containerd-snapshot-ownership gap this
        // is waiting on); this test only exercises the OCI spec generation
        // for when it is explicitly enabled.
        let config = OciComputeConfig {
            rootless: true,
            ..test_config()
        };
        let spec = build_spec(minimal_input(&config)).expect("spec builds");
        let linux = spec.linux().as_ref().unwrap();
        let namespaces = linux.namespaces().as_ref().unwrap();
        assert!(
            namespaces
                .iter()
                .any(|ns| ns.typ() == LinuxNamespaceType::User)
        );
        let uid_mappings = linux.uid_mappings().as_ref().expect("uid mappings set");
        assert_eq!(uid_mappings.len(), 1);
        assert_eq!(uid_mappings[0].container_id(), 0);
        assert_eq!(
            uid_mappings[0].host_id(),
            crate::config::DEFAULT_USER_NAMESPACE_UID_BASE
        );
        assert_eq!(
            uid_mappings[0].size(),
            crate::config::DEFAULT_USER_NAMESPACE_ID_COUNT
        );
    }

    #[test]
    fn non_rootless_has_no_user_namespace() {
        let config = OciComputeConfig {
            rootless: false,
            ..OciComputeConfig::default()
        };
        let spec = build_spec(minimal_input(&config)).expect("spec builds");
        let linux = spec.linux().as_ref().unwrap();
        let namespaces = linux.namespaces().as_ref().unwrap();
        assert!(
            !namespaces
                .iter()
                .any(|ns| ns.typ() == LinuxNamespaceType::User)
        );
        assert!(linux.uid_mappings().is_none());
    }

    #[test]
    fn cgroup_mount_uses_unified_v2_type() {
        let config = test_config();
        let spec = build_spec(minimal_input(&config)).expect("spec builds");
        let cgroup_mount = spec
            .mounts()
            .as_ref()
            .unwrap()
            .iter()
            .find(|m| m.destination() == &PathBuf::from("/sys/fs/cgroup"))
            .expect("cgroup mount present");
        assert_eq!(cgroup_mount.typ().as_deref(), Some("cgroup2"));
    }

    #[test]
    fn capability_set_matches_podman_driver_resolved_set() {
        let config = test_config();
        let spec = build_spec(minimal_input(&config)).expect("spec builds");
        let caps = spec
            .process()
            .as_ref()
            .unwrap()
            .capabilities()
            .as_ref()
            .expect("capabilities set");
        let bounding = caps.bounding().as_ref().expect("bounding set");
        for expected in [
            Capability::Chown,
            Capability::Fowner,
            Capability::Setgid,
            Capability::Setuid,
            Capability::Setpcap,
            Capability::SysAdmin,
            Capability::NetAdmin,
            Capability::SysPtrace,
            Capability::Syslog,
            Capability::DacReadSearch,
        ] {
            assert!(
                bounding.contains(&expected),
                "expected {expected:?} in bounding set"
            );
        }
        // Capabilities the Podman driver explicitly drops must not be
        // present here either.
        for unexpected in [
            Capability::DacOverride,
            Capability::Fsetid,
            Capability::Kill,
            Capability::NetBindService,
            Capability::NetRaw,
            Capability::Setfcap,
            Capability::SysChroot,
        ] {
            assert!(
                !bounding.contains(&unexpected),
                "expected {unexpected:?} to be dropped from bounding set"
            );
        }
    }

    #[test]
    fn no_new_privileges_is_set() {
        let config = test_config();
        let spec = build_spec(minimal_input(&config)).expect("spec builds");
        assert_eq!(
            spec.process().as_ref().unwrap().no_new_privileges(),
            Some(true)
        );
    }

    #[test]
    fn extra_mounts_are_appended_with_bind_options() {
        let config = test_config();
        let mut input = minimal_input(&config);
        input.extra_mounts.push(ExtraMount {
            destination: "/opt/openshell/bin".to_string(),
            source: PathBuf::from("/tmp/supervisor-view"),
            read_only: true,
        });
        let spec = build_spec(input).expect("spec builds");
        let mount = spec
            .mounts()
            .as_ref()
            .unwrap()
            .iter()
            .find(|m| m.destination() == &PathBuf::from("/opt/openshell/bin"))
            .expect("extra mount present");
        let options = mount.options().as_ref().expect("options set");
        assert!(options.contains(&"bind".to_string()));
        assert!(options.contains(&"ro".to_string()));
    }
}
