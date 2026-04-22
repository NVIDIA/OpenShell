// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `MicroVM` runtime using libkrun for hardware-isolated execution.
//!
//! This crate provides a thin wrapper around the libkrun C API to boot
//! lightweight VMs backed by virtio-fs root filesystems. On macOS ARM64,
//! it uses Apple's Hypervisor.framework; on Linux it uses KVM.
//!
//! # Codesigning (macOS)
//!
//! The calling binary must be codesigned with the
//! `com.apple.security.hypervisor` entitlement. See `entitlements.plist`.

#![allow(unsafe_code)]

pub mod backend;
mod embedded;
mod exec;
mod ffi;
mod health;

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::Instant;

pub use exec::{
    VM_EXEC_VSOCK_PORT, VmExecOptions, VmRuntimeState, VsockConnectMode, acquire_rootfs_lock,
    clear_vm_runtime_state, ensure_vm_not_running, exec_capture, exec_running_vm,
    recover_corrupt_kine_db, reset_runtime_state, vm_exec_socket_path, vm_state_path,
    write_vm_runtime_state,
};

// ── Error type ─────────────────────────────────────────────────────────

/// Errors that can occur when configuring or launching a microVM.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum VmError {
    /// A libkrun FFI call returned a negative error code.
    #[error("{func} failed with error code {code}")]
    Krun { func: &'static str, code: i32 },

    /// The rootfs directory does not exist.
    #[error(
        "rootfs directory not found: {path}\nRun `openshell-vm prepare-rootfs` or build one with ./crates/openshell-vm/scripts/build-rootfs.sh <output_dir>"
    )]
    RootfsNotFound { path: String },

    /// The GPU rootfs directory does not exist.
    #[error(
        "GPU rootfs not found: {path}\n\
         The --gpu flag requires a rootfs built with GPU support (NVIDIA drivers,\n\
         nvidia-container-toolkit, and GPU manifests).\n\
         Build one with:\n\
         \x20 mise run vm:rootfs -- --base --gpu\n\
         \x20 mise run vm:build\n\
         Or manually:\n\
         \x20 - Place rootfs-gpu.tar.zst in the openshell-vm.runtime/ sidecar directory\n\
         \x20 - Or set OPENSHELL_VM_GPU_ROOTFS_TARBALL=/path/to/rootfs-gpu.tar.zst\n\
         \x20 - Or copy the extracted rootfs to: {path}\n\
         \x20 - Or use: openshell-vm --gpu --rootfs <path>"
    )]
    GpuRootfsNotFound { path: String },

    /// A path contained invalid UTF-8.
    #[error("path is not valid UTF-8: {0}")]
    InvalidPath(String),

    /// `CString::new` failed (embedded NUL byte).
    #[error("invalid C string: {0}")]
    CString(#[from] std::ffi::NulError),

    /// A required host binary was not found.
    #[error("required binary not found: {path}\n{hint}")]
    BinaryNotFound { path: String, hint: String },

    /// Host-side VM setup failed before boot.
    #[error("host setup failed: {0}")]
    HostSetup(String),

    /// `/dev/kvm` is not accessible (Linux only).
    #[error(
        "cannot open /dev/kvm: {reason}\n\
         KVM access is required to run microVMs on Linux.\n\
         Fix: sudo usermod -aG kvm $USER  then log out and back in\n\
         (or run: newgrp kvm)"
    )]
    KvmAccess { reason: String },

    /// `fork()` failed.
    #[error("fork() failed: {0}")]
    Fork(String),

    /// Post-boot bootstrap failed.
    #[error("bootstrap failed: {0}")]
    Bootstrap(String),

    /// Local VM runtime state could not be read or written.
    #[error("VM runtime state error: {0}")]
    RuntimeState(String),

    /// Exec operation against a running VM failed.
    #[error("VM exec failed: {0}")]
    Exec(String),
}

/// Check a libkrun return code; negative values are errors.
fn check(ret: i32, func: &'static str) -> Result<(), VmError> {
    if ret < 0 {
        Err(VmError::Krun { func, code: ret })
    } else {
        Ok(())
    }
}

// ── Configuration ──────────────────────────────────────────────────────

/// Hypervisor backend selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VmBackendChoice {
    /// Auto-select: cloud-hypervisor when a VFIO device is configured, libkrun otherwise.
    #[default]
    Auto,
    /// Force the libkrun backend.
    Libkrun,
    /// Force the cloud-hypervisor backend (even without GPU/VFIO).
    CloudHypervisor,
}

/// Networking backend for the microVM.
#[derive(Debug, Clone)]
pub enum NetBackend {
    /// TSI (Transparent Socket Impersonation) — default libkrun networking.
    /// Simple but intercepts guest loopback connections, breaking k3s.
    Tsi,

    /// No networking — disable vsock/TSI entirely. For debugging only.
    None,

    /// gvproxy (vfkit mode) — real `eth0` interface via virtio-net.
    /// Requires gvproxy binary on the host. Port forwarding is done
    /// through gvproxy's HTTP API.
    Gvproxy {
        /// Path to the gvproxy binary.
        binary: PathBuf,
    },
}

/// Host Unix socket bridged into the guest as a vsock port.
#[derive(Debug, Clone)]
pub struct VsockPort {
    pub port: u32,
    pub socket_path: PathBuf,
    pub listen: bool,
}

/// Host-backed raw block image attached to the VM for mutable guest state.
#[derive(Debug, Clone)]
pub struct StateDiskConfig {
    /// Path to the sparse raw image on the host.
    pub path: PathBuf,

    /// Size of the raw image in bytes.
    pub size_bytes: u64,

    /// Guest-visible libkrun block ID.
    pub block_id: String,

    /// Guest device path used by the init script.
    pub guest_device: String,
}

impl StateDiskConfig {
    fn for_rootfs(rootfs: &Path) -> Self {
        Self {
            path: default_state_disk_path(rootfs),
            size_bytes: DEFAULT_STATE_DISK_SIZE_BYTES,
            block_id: DEFAULT_STATE_DISK_BLOCK_ID.to_string(),
            guest_device: DEFAULT_STATE_DISK_GUEST_DEVICE.to_string(),
        }
    }
}

/// Configuration for a libkrun microVM.
pub struct VmConfig {
    /// Path to the extracted rootfs directory (aarch64 Linux).
    pub rootfs: PathBuf,

    /// Number of virtual CPUs.
    pub vcpus: u8,

    /// RAM in MiB.
    pub mem_mib: u32,

    /// Executable path inside the VM.
    pub exec_path: String,

    /// Arguments to the executable (argv, excluding argv\[0\]).
    pub args: Vec<String>,

    /// Environment variables in `KEY=VALUE` form.
    /// If empty, a minimal default set is used.
    pub env: Vec<String>,

    /// Working directory inside the VM.
    pub workdir: String,

    /// TCP port mappings in `"host_port:guest_port"` form.
    /// Only used with TSI networking.
    pub port_map: Vec<String>,

    /// Optional host Unix sockets exposed to the guest over vsock.
    pub vsock_ports: Vec<VsockPort>,

    /// libkrun log level (0=Off .. 5=Trace).
    pub log_level: u32,

    /// Optional file path for VM console output. If `None`, console output
    /// goes to the parent directory of the rootfs as `console.log`.
    pub console_output: Option<PathBuf>,

    /// Networking backend.
    pub net: NetBackend,

    /// Wipe all runtime state (containerd tasks/sandboxes, kubelet pods)
    /// before booting. Recovers from corrupted state after a crash.
    pub reset: bool,

    /// Gateway metadata name used for host-side config and mTLS material.
    pub gateway_name: String,

    /// Optional host-backed raw block image for mutable guest state.
    pub state_disk: Option<StateDiskConfig>,

    /// Whether GPU passthrough is enabled for this VM.
    pub gpu_enabled: bool,

    /// VFIO PCI device address for GPU passthrough (e.g. `0000:41:00.0`).
    /// When set, the cloud-hypervisor backend is used instead of libkrun.
    pub vfio_device: Option<String>,

    /// Hypervisor backend override. Defaults to [`VmBackendChoice::Auto`].
    pub backend: VmBackendChoice,
}

impl VmConfig {
    /// Default gateway configuration: boots k3s server inside the VM.
    ///
    /// Runs `/srv/openshell-vm-init.sh` which mounts essential filesystems,
    /// deploys the `OpenShell` helm chart, and execs `k3s server`.
    /// Exposes the `OpenShell` gateway on port 30051.
    pub fn gateway(rootfs: PathBuf) -> Self {
        let state_disk = StateDiskConfig::for_rootfs(&rootfs);
        Self {
            vsock_ports: vec![VsockPort {
                port: VM_EXEC_VSOCK_PORT,
                socket_path: vm_exec_socket_path(&rootfs),
                listen: true,
            }],
            rootfs,
            vcpus: 4,
            mem_mib: 8192,
            exec_path: "/srv/openshell-vm-init.sh".to_string(),
            args: vec![],
            env: vec![
                "HOME=/root".to_string(),
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
                "TERM=xterm".to_string(),
            ],
            workdir: "/".to_string(),
            port_map: vec![
                // OpenShell server — with bridge CNI the pod listens on
                // 8080 inside its own network namespace (10.42.0.x), not
                // on the VM's root namespace. The NodePort service
                // (kube-proxy nftables) forwards VM:30051 → pod:8080.
                // gvproxy maps host:30051 → VM:30051 to complete the path.
                "30051:30051".to_string(),
            ],
            log_level: 3, // Info — for debugging
            console_output: None,
            net: NetBackend::Gvproxy {
                binary: default_runtime_gvproxy_path(),
            },
            reset: false,
            gateway_name: format!("{GATEWAY_NAME_PREFIX}-default"),
            state_disk: Some(state_disk),
            gpu_enabled: false,
            vfio_device: None,
            backend: VmBackendChoice::Auto,
        }
    }
}

/// Base prefix for gateway metadata names.
const GATEWAY_NAME_PREFIX: &str = "openshell-vm";
const DEFAULT_STATE_DISK_SIZE_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const DEFAULT_STATE_DISK_BLOCK_ID: &str = "openshell-state";
const DEFAULT_STATE_DISK_GUEST_DEVICE: &str = "/dev/vda";

/// Resolve the gateway metadata name for an instance name.
pub fn gateway_name(instance_name: &str) -> Result<String, VmError> {
    Ok(format!(
        "{GATEWAY_NAME_PREFIX}-{}",
        sanitize_instance_name(instance_name)?
    ))
}

/// Resolve the rootfs path for a named instance (including the default gateway).
///
/// Layout: `$XDG_DATA_HOME/openshell/openshell-vm/{version}/instances/{name}/rootfs`
pub fn named_rootfs_dir(instance_name: &str) -> Result<PathBuf, VmError> {
    let name = sanitize_instance_name(instance_name)?;
    let base = openshell_bootstrap::paths::openshell_vm_base_dir()
        .map_err(|e| VmError::RuntimeState(format!("resolve openshell-vm base dir: {e}")))?;
    Ok(base
        .join(env!("CARGO_PKG_VERSION"))
        .join("instances")
        .join(name)
        .join("rootfs"))
}

/// Resolve the GPU rootfs path for a named instance.
///
/// Layout: `$XDG_DATA_HOME/openshell/openshell-vm/{version}/instances/{name}/rootfs-gpu`
///
/// The GPU rootfs is built separately with `build-rootfs.sh --gpu` and is
/// never embedded (too large with NVIDIA drivers). If it doesn't exist,
/// callers should return [`VmError::GpuRootfsNotFound`].
pub fn named_gpu_rootfs_dir(instance_name: &str) -> Result<PathBuf, VmError> {
    let name = sanitize_instance_name(instance_name)?;
    let base = openshell_bootstrap::paths::openshell_vm_base_dir()
        .map_err(|e| VmError::RuntimeState(format!("resolve openshell-vm base dir: {e}")))?;
    Ok(base
        .join(env!("CARGO_PKG_VERSION"))
        .join("instances")
        .join(name)
        .join("rootfs-gpu"))
}

/// Ensure a GPU rootfs exists for the named instance.
///
/// When the GPU rootfs directory doesn't exist, looks for a
/// `rootfs-gpu.tar.zst` tarball in these locations (in order):
///
/// 1. Sidecar runtime dir: `<binary_dir>/openshell-vm.runtime/rootfs-gpu.tar.zst`
/// 2. Environment variable: `OPENSHELL_VM_GPU_ROOTFS_TARBALL`
///
/// If found, extracts to the instance `rootfs-gpu` path. This mirrors the
/// pattern used by [`ensure_named_rootfs`] for the standard rootfs.
///
/// Validates that the rootfs contains the `.rootfs-gpu` sentinel written
/// by `build-rootfs.sh --gpu`, catching the case where a regular rootfs
/// was accidentally placed at the `rootfs-gpu` path.
pub fn ensure_gpu_rootfs(instance_name: &str) -> Result<PathBuf, VmError> {
    let gpu_rootfs = named_gpu_rootfs_dir(instance_name)?;
    if !gpu_rootfs.is_dir() {
        if let Some(tarball) = find_gpu_rootfs_tarball() {
            extract_gpu_rootfs_tarball(&tarball, &gpu_rootfs)?;
        } else {
            return Err(VmError::GpuRootfsNotFound {
                path: gpu_rootfs.display().to_string(),
            });
        }
    }

    let sentinel = gpu_rootfs.join("opt/openshell/.rootfs-gpu");
    if !sentinel.is_file() {
        return Err(VmError::GpuRootfsNotFound {
            path: format!(
                "{} (directory exists but missing .rootfs-gpu sentinel — \
                 was it built with --gpu?)",
                gpu_rootfs.display()
            ),
        });
    }

    eprintln!("GPU rootfs: {}", gpu_rootfs.display());
    Ok(gpu_rootfs)
}

const GPU_ROOTFS_TARBALL_ENV: &str = "OPENSHELL_VM_GPU_ROOTFS_TARBALL";
const GPU_ROOTFS_TARBALL_NAME: &str = "rootfs-gpu.tar.zst";

/// Search for a GPU rootfs tarball in known locations.
fn find_gpu_rootfs_tarball() -> Option<PathBuf> {
    // 1. Sidecar runtime dir next to the binary
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            let sidecar = exe_dir
                .join("openshell-vm.runtime")
                .join(GPU_ROOTFS_TARBALL_NAME);
            if sidecar.is_file() {
                return Some(sidecar);
            }
        }
    }

    // 2. Environment variable override
    if let Some(path) = std::env::var_os(GPU_ROOTFS_TARBALL_ENV) {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }

    None
}

/// Extract a `rootfs-gpu.tar.zst` tarball into the given destination directory.
fn extract_gpu_rootfs_tarball(tarball: &Path, dest: &Path) -> Result<(), VmError> {
    eprintln!(
        "Extracting GPU rootfs...\n  source: {}\n  dest:   {}",
        tarball.display(),
        dest.display()
    );

    let file = std::fs::File::open(tarball).map_err(|e| {
        VmError::HostSetup(format!(
            "open GPU rootfs tarball {}: {e}",
            tarball.display()
        ))
    })?;

    let decoder = zstd::Decoder::new(std::io::BufReader::new(file)).map_err(|e| {
        VmError::HostSetup(format!(
            "create zstd decoder for {}: {e}",
            tarball.display()
        ))
    })?;

    std::fs::create_dir_all(dest).map_err(|e| {
        VmError::HostSetup(format!("create GPU rootfs dir {}: {e}", dest.display()))
    })?;

    let mut archive = tar::Archive::new(decoder);
    archive.unpack(dest).map_err(|e| {
        // Clean up partial extraction
        let _ = std::fs::remove_dir_all(dest);
        VmError::HostSetup(format!("extract GPU rootfs tarball: {e}"))
    })?;

    eprintln!("  GPU rootfs extracted to {}", dest.display());
    Ok(())
}

/// Ensure a named instance rootfs exists, extracting from the embedded
/// rootfs tarball on first use.
///
/// The default (unnamed) gateway should be routed here as `"default"`.
pub fn ensure_named_rootfs(instance_name: &str) -> Result<PathBuf, VmError> {
    let instance_rootfs = named_rootfs_dir(instance_name)?;
    if instance_rootfs.is_dir() {
        return Ok(instance_rootfs);
    }

    if embedded::has_embedded_rootfs() {
        // Clean up rootfs directories left by older binary versions.
        embedded::cleanup_old_rootfs()?;

        embedded::extract_rootfs_to(&instance_rootfs)?;
        return Ok(instance_rootfs);
    }

    Err(VmError::RootfsNotFound {
        path: instance_rootfs.display().to_string(),
    })
}

/// Ensure the requested rootfs exists, extracting the embedded rootfs when needed.
///
/// When `rootfs` is `None`, this uses the named-instance layout under
/// `$XDG_DATA_HOME/openshell/openshell-vm/{version}/instances/<name>/rootfs`.
/// When `force_recreate` is true and the target exists, it is removed first.
pub fn prepare_rootfs(
    rootfs: Option<PathBuf>,
    instance_name: &str,
    force_recreate: bool,
) -> Result<PathBuf, VmError> {
    let target = match rootfs {
        Some(path) => path,
        None => named_rootfs_dir(instance_name)?,
    };

    if force_recreate && target.exists() {
        std::fs::remove_dir_all(&target).map_err(|e| {
            VmError::HostSetup(format!("remove existing rootfs {}: {e}", target.display()))
        })?;
    }

    if target.is_dir() {
        return Ok(target);
    }

    if embedded::has_embedded_rootfs() {
        if target == named_rootfs_dir(instance_name)? {
            embedded::cleanup_old_rootfs()?;
        }
        embedded::extract_rootfs_to(&target)?;
        return Ok(target);
    }

    Err(VmError::RootfsNotFound {
        path: target.display().to_string(),
    })
}

fn sanitize_instance_name(name: &str) -> Result<String, VmError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(VmError::RuntimeState(
            "instance name cannot be empty".to_string(),
        ));
    }

    let mut out = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            return Err(VmError::RuntimeState(format!(
                "invalid instance name '{trimmed}': only [A-Za-z0-9_-] are allowed"
            )));
        }
    }

    Ok(out)
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Build a null-terminated C string array from a slice of strings.
///
/// Returns both the `CString` owners (to keep them alive) and the pointer array.
pub(crate) fn c_string_array(
    strings: &[&str],
) -> Result<(Vec<CString>, Vec<*const libc::c_char>), VmError> {
    let owned: Vec<CString> = strings
        .iter()
        .map(|s| CString::new(*s))
        .collect::<Result<Vec<_>, _>>()?;
    let mut ptrs: Vec<*const libc::c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(ptr::null()); // null terminator
    Ok((owned, ptrs))
}

const VM_RUNTIME_DIR_ENV: &str = "OPENSHELL_VM_RUNTIME_DIR";

pub fn configured_runtime_dir() -> Result<PathBuf, VmError> {
    // Allow override for development
    if let Some(path) = std::env::var_os(VM_RUNTIME_DIR_ENV) {
        let path = PathBuf::from(path);
        tracing::debug!(
            path = %path.display(),
            "Using runtime from OPENSHELL_VM_RUNTIME_DIR"
        );
        return Ok(path);
    }

    // Use embedded runtime (extracts on first use)
    embedded::ensure_runtime_extracted()
}

fn validate_runtime_dir(dir: &Path) -> Result<(), VmError> {
    if !dir.is_dir() {
        return Err(VmError::BinaryNotFound {
            path: dir.display().to_string(),
            hint: format!(
                "VM runtime not found. Run `mise run vm:build:embedded` or set {VM_RUNTIME_DIR_ENV}"
            ),
        });
    }

    let libkrun = dir.join(ffi::required_runtime_lib_name());
    if !libkrun.is_file() {
        return Err(VmError::BinaryNotFound {
            path: libkrun.display().to_string(),
            hint: "runtime is incomplete: missing libkrun".to_string(),
        });
    }

    let has_krunfw = std::fs::read_dir(dir)
        .map_err(|e| VmError::HostSetup(format!("read {}: {e}", dir.display())))?
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("libkrunfw.")
        });
    if !has_krunfw {
        return Err(VmError::BinaryNotFound {
            path: dir.display().to_string(),
            hint: "runtime is incomplete: missing libkrunfw".to_string(),
        });
    }

    let gvproxy = dir.join("gvproxy");
    if !gvproxy.is_file() {
        return Err(VmError::BinaryNotFound {
            path: gvproxy.display().to_string(),
            hint: "runtime is incomplete: missing gvproxy".to_string(),
        });
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mode = std::fs::metadata(&gvproxy)
            .map_err(|e| VmError::HostSetup(format!("stat {}: {e}", gvproxy.display())))?
            .permissions()
            .mode();
        if mode & 0o111 == 0 {
            return Err(VmError::HostSetup(format!(
                "gvproxy is not executable: {}",
                gvproxy.display()
            )));
        }
    }

    Ok(())
}

fn resolve_runtime_bundle() -> Result<PathBuf, VmError> {
    let runtime_dir = configured_runtime_dir()?;
    // Validate the directory has required files
    validate_runtime_dir(&runtime_dir)?;
    Ok(runtime_dir.join("gvproxy"))
}

pub fn default_runtime_gvproxy_path() -> PathBuf {
    configured_runtime_dir()
        .or_else(|_| embedded::runtime_cache_path())
        .unwrap_or_else(|_| PathBuf::from("gvproxy"))
        .join("gvproxy")
}

/// Check if the given path looks like an openshell-vm instance rootfs.
fn is_instance_rootfs_path(path: &Path) -> bool {
    // Matches: .../openshell/openshell-vm/.../instances/.../rootfs
    let s = path.to_string_lossy();
    s.contains("openshell/openshell-vm") && s.contains("instances") && path.ends_with("rootfs")
}

#[cfg(target_os = "macos")]
fn configure_runtime_loader_env(runtime_dir: &Path) -> Result<(), VmError> {
    let existing = std::env::var_os("DYLD_FALLBACK_LIBRARY_PATH");
    let mut paths = vec![runtime_dir.to_path_buf()];
    if let Some(existing) = existing {
        paths.extend(std::env::split_paths(&existing));
    }
    let joined = std::env::join_paths(paths)
        .map_err(|e| VmError::HostSetup(format!("join DYLD_FALLBACK_LIBRARY_PATH: {e}")))?;
    unsafe {
        std::env::set_var("DYLD_FALLBACK_LIBRARY_PATH", joined);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn configure_runtime_loader_env(runtime_dir: &Path) -> Result<(), VmError> {
    // On Linux, libkrun.so has a DT_NEEDED for libkrunfw.so. Even though we
    // preload libkrunfw with RTLD_GLOBAL, the ELF dynamic linker still resolves
    // DT_NEEDED entries through LD_LIBRARY_PATH / system paths. Without this,
    // dlopen("libkrun.so") fails if libkrunfw.so is only in the runtime bundle.
    let existing = std::env::var_os("LD_LIBRARY_PATH");
    let mut paths = vec![runtime_dir.to_path_buf()];
    if let Some(existing) = existing {
        paths.extend(std::env::split_paths(&existing));
    }
    let joined = std::env::join_paths(paths)
        .map_err(|e| VmError::HostSetup(format!("join LD_LIBRARY_PATH: {e}")))?;
    unsafe {
        std::env::set_var("LD_LIBRARY_PATH", joined);
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn configure_runtime_loader_env(_runtime_dir: &Path) -> Result<(), VmError> {
    Ok(())
}

fn raise_nofile_limit() {
    #[cfg(unix)]
    unsafe {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut rlim) == 0 {
            rlim.rlim_cur = rlim.rlim_max;
            let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &raw const rlim);
        }
    }
}

/// Log runtime provenance information for diagnostics.
///
/// Prints the libkrun/libkrunfw versions, artifact hashes, and whether
/// a custom runtime is in use. This makes it easy to correlate VM issues
/// with the specific runtime bundle.
fn log_runtime_provenance(runtime_dir: &Path) {
    if let Some(prov) = ffi::runtime_provenance() {
        eprintln!("runtime: {}", runtime_dir.display());
        eprintln!("  libkrun: {}", prov.libkrun_path.display());
        for krunfw in &prov.libkrunfw_paths {
            let name = krunfw.file_name().map_or_else(
                || "unknown".to_string(),
                |n| n.to_string_lossy().to_string(),
            );
            eprintln!("  libkrunfw: {name}");
        }
        if let Some(ref sha) = prov.libkrunfw_sha256 {
            let short = if sha.len() > 12 { &sha[..12] } else { sha };
            eprintln!("  sha256: {short}...");
        }
        if prov.is_custom {
            eprintln!("  type: custom (OpenShell-built)");
            // Parse provenance.json for additional details.
            if let Some(ref json) = prov.provenance_json {
                // Extract key fields from provenance metadata.
                for key in &["libkrunfw_commit", "kernel_version", "build_timestamp"] {
                    if let Some(val) = extract_json_string(json, key) {
                        eprintln!("  {}: {}", key.replace('_', "-"), val);
                    }
                }
            }
        } else {
            eprintln!("  type: stock (system/homebrew)");
        }
    }
}

/// Extract a string value from a JSON object by key.
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(json).ok()?;
    map.get(key)?.as_str().map(ToOwned::to_owned)
}

pub(crate) fn clamp_log_level(level: u32) -> u32 {
    match level {
        0 => ffi::KRUN_LOG_LEVEL_OFF,
        1 => ffi::KRUN_LOG_LEVEL_ERROR,
        2 => ffi::KRUN_LOG_LEVEL_WARN,
        3 => ffi::KRUN_LOG_LEVEL_INFO,
        4 => ffi::KRUN_LOG_LEVEL_DEBUG,
        _ => ffi::KRUN_LOG_LEVEL_TRACE,
    }
}

/// RAII guard that kills and waits on a gvproxy child process when dropped.
///
/// This prevents orphaned gvproxy processes when early `?` returns in the
/// launch function cause the child to be dropped before cleanup code runs.
/// Call [`GvproxyGuard::disarm`] to take ownership of the child when it
/// should outlive the guard (i.e., after a successful fork).
pub(crate) struct GvproxyGuard {
    child: Option<std::process::Child>,
}

impl GvproxyGuard {
    pub(crate) fn new(child: std::process::Child) -> Self {
        Self { child: Some(child) }
    }

    /// Take the child out of the guard, preventing it from being killed on drop.
    /// Use this after the launch is successful and the parent will manage cleanup.
    pub(crate) fn disarm(&mut self) -> Option<std::process::Child> {
        self.child.take()
    }

    /// Get the child's PID without disarming.
    pub(crate) fn id(&self) -> Option<u32> {
        self.child.as_ref().map(std::process::Child::id)
    }
}

impl Drop for GvproxyGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let pid = child.id();
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("gvproxy cleaned up (pid {pid})");
        }
    }
}

/// Issue a gvproxy expose call via its HTTP API (unix socket).
///
/// Sends a raw HTTP/1.1 POST request over the unix socket to avoid
/// depending on `curl` being installed on the host.
pub(crate) fn gvproxy_expose(api_sock: &Path, body: &str) -> Result<(), String> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream =
        UnixStream::connect(api_sock).map_err(|e| format!("connect to gvproxy API socket: {e}"))?;

    let request = format!(
        "POST /services/forwarder/expose HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        body.len(),
        body,
    );

    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write to gvproxy API: {e}"))?;

    // Read just enough of the response to get the status line.
    let mut buf = [0u8; 1024];
    let n = stream
        .read(&mut buf)
        .map_err(|e| format!("read from gvproxy API: {e}"))?;
    let response = String::from_utf8_lossy(&buf[..n]);

    // Parse the HTTP status code from the first line (e.g. "HTTP/1.1 200 OK").
    let status = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("0");

    match status {
        "200" | "204" => Ok(()),
        _ => {
            let first_line = response.lines().next().unwrap_or("<empty>");
            Err(format!("gvproxy API: {first_line}"))
        }
    }
}

/// Kill a stale gvproxy process from a previous openshell-vm run.
///
/// If the CLI crashes or is killed before cleanup, gvproxy keeps running
/// and holds its ports. A new gvproxy instance then fails with
/// "bind: address already in use" when trying to forward ports.
///
/// We first try to kill the specific gvproxy PID recorded in the VM
/// runtime state. If the state file was deleted (e.g. the user ran
/// `rm -rf` on the data directory), we fall back to killing any gvproxy
/// process holding the target ports.
pub(crate) fn kill_stale_gvproxy(rootfs: &Path) {
    kill_stale_gvproxy_by_state(rootfs);
}

/// Kill stale gvproxy using the PID from the VM state file.
fn kill_stale_gvproxy_by_state(rootfs: &Path) {
    let state_path = vm_state_path(rootfs);
    let pid = std::fs::read(&state_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<VmRuntimeState>(&bytes).ok())
        .and_then(|state| state.gvproxy_pid);

    if let Some(gvproxy_pid) = pid {
        kill_gvproxy_pid(gvproxy_pid);
    }
}

/// Kill any gvproxy process holding a specific TCP port.
///
/// Used as a fallback when the VM state file is missing (e.g. after the
/// user deleted the data directory while a VM was running).
pub(crate) fn kill_stale_gvproxy_by_port(port: u16) {
    // Use lsof to find PIDs listening on the target port.
    let output = std::process::Command::new("lsof")
        .args(["-ti", &format!(":{port}")])
        .output();

    let pids = match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return,
    };

    for line in pids.lines() {
        if let Ok(pid) = line.trim().parse::<u32>() {
            let pid_i32 = pid as libc::pid_t;
            if is_process_named(pid_i32, "gvproxy") {
                kill_gvproxy_pid(pid);
            }
        }
    }
}

fn kill_gvproxy_pid(gvproxy_pid: u32) {
    let pid_i32 = gvproxy_pid as libc::pid_t;
    let is_alive = unsafe { libc::kill(pid_i32, 0) } == 0;
    if is_alive {
        // Verify the process is actually gvproxy before killing.
        // Without this check, PID reuse could cause us to kill an
        // unrelated process.
        if !is_process_named(pid_i32, "gvproxy") {
            eprintln!(
                "Stale gvproxy pid {gvproxy_pid} is no longer gvproxy (PID reused), skipping kill"
            );
            return;
        }
        unsafe {
            libc::kill(pid_i32, libc::SIGTERM);
        }
        eprintln!("Killed stale gvproxy process (pid {gvproxy_pid})");
        // Brief pause for the port to be released.
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// Check whether a process with the given PID has the expected name.
///
/// On macOS, shells out to `ps` to query the process name. On Linux, reads
/// `/proc/<pid>/comm`. Returns `false` if the process name cannot be
/// determined (fail-safe: don't kill if we can't verify).
#[cfg(target_os = "macos")]
fn is_process_named(pid: libc::pid_t, expected: &str) -> bool {
    // Use `ps -p <pid> -o comm=` to get just the process name.
    // This avoids depending on libc kinfo_proc struct layout.
    std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .is_some_and(|name| name.trim().contains(expected))
}

#[cfg(target_os = "linux")]
fn is_process_named(pid: libc::pid_t, expected: &str) -> bool {
    let comm_path = format!("/proc/{pid}/comm");
    std::fs::read_to_string(comm_path)
        .map(|name| name.trim().contains(expected))
        .unwrap_or(false)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn is_process_named(_pid: libc::pid_t, _expected: &str) -> bool {
    // Cannot verify on this platform — fail-safe: don't kill.
    false
}

pub(crate) fn vm_rootfs_key(rootfs: &Path) -> String {
    let name = rootfs
        .file_name()
        .and_then(|part| part.to_str())
        .unwrap_or("openshell-vm");
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "openshell-vm".to_string()
    } else {
        out
    }
}

fn default_state_disk_path(rootfs: &Path) -> PathBuf {
    rootfs
        .parent()
        .unwrap_or(rootfs)
        .join(format!("{}-state.raw", vm_rootfs_key(rootfs)))
}

fn ensure_state_disk_image(state_disk: &StateDiskConfig) -> Result<(), VmError> {
    if let Some(parent) = state_disk.path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            VmError::HostSetup(format!("create state disk dir {}: {e}", parent.display()))
        })?;
    }

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&state_disk.path)
        .map_err(|e| {
            VmError::HostSetup(format!(
                "open state disk {}: {e}",
                state_disk.path.display()
            ))
        })?;

    let current_len = file
        .metadata()
        .map_err(|e| {
            VmError::HostSetup(format!(
                "stat state disk {}: {e}",
                state_disk.path.display()
            ))
        })?
        .len();
    if current_len < state_disk.size_bytes {
        file.set_len(state_disk.size_bytes).map_err(|e| {
            VmError::HostSetup(format!(
                "resize state disk {} to {} bytes: {e}",
                state_disk.path.display(),
                state_disk.size_bytes
            ))
        })?;
    }

    Ok(())
}

pub(crate) fn state_disk_sync_mode() -> u32 {
    #[cfg(target_os = "macos")]
    {
        ffi::KRUN_SYNC_RELAXED
    }
    #[cfg(not(target_os = "macos"))]
    {
        ffi::KRUN_SYNC_FULL
    }
}

fn hash_path_id(path: &Path) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in path.to_string_lossy().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{:012x}", hash & 0x0000_ffff_ffff_ffff)
}

/// Return a secure base directory for temporary socket files.
///
/// Prefers `XDG_RUNTIME_DIR` (per-user, restricted permissions on Linux),
/// falls back to `/tmp`. After `create_dir_all`, validates the directory
/// is not a symlink and is owned by the current user.
fn secure_socket_base(subdir: &str) -> Result<PathBuf, VmError> {
    let base = if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
        PathBuf::from(xdg)
    } else {
        let mut base = PathBuf::from("/tmp");
        if !base.is_dir() {
            base = std::env::temp_dir();
        }
        base
    };
    let dir = base.join(subdir);

    // If the path exists, verify it is not a symlink before using it.
    if dir.exists() {
        let meta = dir
            .symlink_metadata()
            .map_err(|e| VmError::HostSetup(format!("lstat {}: {e}", dir.display())))?;
        if meta.file_type().is_symlink() {
            return Err(VmError::HostSetup(format!(
                "socket directory {} is a symlink — refusing to use it",
                dir.display()
            )));
        }
        // Verify ownership matches current user.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let uid = unsafe { libc::getuid() };
            if meta.uid() != uid {
                return Err(VmError::HostSetup(format!(
                    "socket directory {} is owned by uid {} but we are uid {} — refusing to use it",
                    dir.display(),
                    meta.uid(),
                    uid
                )));
            }
        }
    } else {
        std::fs::create_dir_all(&dir)
            .map_err(|e| VmError::HostSetup(format!("create socket dir {}: {e}", dir.display())))?;
        // Set restrictive permissions on the newly created directory.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
    }

    Ok(dir)
}

pub(crate) fn gvproxy_socket_dir(rootfs: &Path) -> Result<PathBuf, VmError> {
    let dir = secure_socket_base("ovm-gv")?;

    // macOS unix socket path limit is tight (~104 bytes). Keep paths very short.
    let id = hash_path_id(rootfs);
    Ok(dir.join(id))
}

/// Validate that a VFIO PCI address matches the BDF format `DDDD:BB:DD.F`.
///
/// Rejects strings containing `/`, `..`, or non-hex characters to prevent
/// path traversal when the address is interpolated into sysfs paths.
fn validate_vfio_address(addr: &str) -> Result<(), VmError> {
    let bytes = addr.as_bytes();
    if bytes.len() == 12
        && bytes[4] == b':'
        && bytes[7] == b':'
        && bytes[10] == b'.'
        && bytes[..4].iter().all(u8::is_ascii_hexdigit)
        && bytes[5..7].iter().all(u8::is_ascii_hexdigit)
        && bytes[8..10].iter().all(u8::is_ascii_hexdigit)
        && bytes[11].is_ascii_digit()
        && bytes[11] <= b'7'
    {
        return Ok(());
    }
    Err(VmError::HostSetup(format!(
        "invalid VFIO PCI address '{addr}': expected BDF format DDDD:BB:DD.F (e.g. 0000:41:00.0)"
    )))
}

pub(crate) fn gateway_host_port(config: &VmConfig) -> u16 {
    config
        .port_map
        .first()
        .and_then(|pm| pm.split(':').next())
        .and_then(|port| port.parse::<u16>().ok())
        .unwrap_or(DEFAULT_GATEWAY_PORT)
}

pub(crate) fn pick_gvproxy_ssh_port() -> Result<u16, VmError> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| VmError::HostSetup(format!("allocate gvproxy ssh port on localhost: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| VmError::HostSetup(format!("read gvproxy ssh port: {e}")))?
        .port();
    drop(listener);
    Ok(port)
}

pub(crate) fn path_to_cstring(path: &Path) -> Result<CString, VmError> {
    let s = path
        .to_str()
        .ok_or_else(|| VmError::InvalidPath(path.display().to_string()))?;
    Ok(CString::new(s)?)
}

/// Check that `/dev/kvm` is readable before attempting to boot.
///
/// libkrun panics with an opaque Rust panic (instead of returning an error
/// code) when `/dev/kvm` is inaccessible. This pre-check turns that into a
/// clear, actionable error message.
#[cfg(target_os = "linux")]
fn check_kvm_access() -> Result<(), VmError> {
    use std::fs::OpenOptions;
    match OpenOptions::new().read(true).open("/dev/kvm") {
        Ok(_) => Ok(()),
        Err(e) => Err(VmError::KvmAccess {
            reason: e.to_string(),
        }),
    }
}

// ── Launch ──────────────────────────────────────────────────────────────

/// Configure and launch a libkrun microVM.
///
/// This forks the process. The child enters the VM (never returns); the
/// parent blocks until the VM exits or a signal is received.
///
/// Returns the VM exit code (from `waitpid`).
#[allow(clippy::similar_names)]
pub fn launch(config: &VmConfig) -> Result<i32, VmError> {
    // Auto-extract embedded rootfs if using an instance path and it doesn't exist
    if !config.rootfs.is_dir()
        && is_instance_rootfs_path(&config.rootfs)
        && embedded::has_embedded_rootfs()
    {
        embedded::extract_rootfs_to(&config.rootfs)?;
    }

    // Validate rootfs
    if !config.rootfs.is_dir() {
        return Err(VmError::RootfsNotFound {
            path: config.rootfs.display().to_string(),
        });
    }

    // On Linux, libkrun uses KVM for hardware virtualization. Check access
    // before starting so a missing kvm group membership produces a clear
    // error instead of a cryptic panic inside krun_start_enter.
    #[cfg(target_os = "linux")]
    check_kvm_access()?;

    if config.exec_path == "/srv/openshell-vm-init.sh" {
        ensure_vm_not_running(&config.rootfs)?;
    }

    // Acquire an exclusive flock on the rootfs lock file. This is held
    // by the parent process for the VM's entire lifetime. If this process
    // is killed (even SIGKILL), the OS releases the lock automatically.
    // This prevents a second launch or rootfs rebuild from corrupting a
    // running VM's filesystem via virtio-fs.
    let _rootfs_lock = if config.exec_path == "/srv/openshell-vm-init.sh" {
        Some(acquire_rootfs_lock(&config.rootfs)?)
    } else {
        None
    };

    // Check for a corrupt kine (SQLite) database and remove it if the
    // header is invalid. Stale bootstrap locks are handled inside the VM
    // by the init script (sqlite3 DELETE before k3s starts). This runs on
    // every normal boot (not --reset, which wipes k3s/server/ entirely).
    // Must happen after the lock so we know no other VM process is using
    // the rootfs.
    if !config.reset && config.exec_path == "/srv/openshell-vm-init.sh" {
        recover_corrupt_kine_db(&config.rootfs)?;
    }

    // Wipe stale containerd/kubelet runtime state if requested.
    // This must happen after the lock (to confirm no other VM is using
    // the rootfs) but before booting (so the new VM starts clean).
    if config.reset {
        reset_runtime_state(&config.rootfs, &config.gateway_name)?;
    }
    if config.reset
        && let Some(state_disk) = &config.state_disk
        && let Err(err) = std::fs::remove_file(&state_disk.path)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        return Err(VmError::HostSetup(format!(
            "remove state disk {}: {err}",
            state_disk.path.display()
        )));
    }
    let fresh_state_disk = if let Some(state_disk) = &config.state_disk {
        let existed_before = state_disk.path.is_file();
        ensure_state_disk_image(state_disk)?;
        !existed_before
    } else {
        false
    };

    // When the state disk is freshly created (deleted by user, --reset, or
    // first boot), the VM will generate new PKI. Clear any cached host-side
    // mTLS certs so `bootstrap_gateway` runs the cold-boot PKI fetch path
    // instead of using stale certs that won't match the new VM CA.
    if fresh_state_disk || config.reset {
        clear_warm_boot_certs(&config.gateway_name);
    }

    eprintln!("rootfs: {}", config.rootfs.display());
    if let Some(state_disk) = &config.state_disk {
        eprintln!(
            "state disk: {} ({} GiB)",
            state_disk.path.display(),
            state_disk.size_bytes / 1024 / 1024 / 1024
        );
    }
    eprintln!("vm: {} vCPU(s), {} MiB RAM", config.vcpus, config.mem_mib);

    raise_nofile_limit();

    // ── Dispatch to the appropriate backend ─────────────────────────

    let use_chv = match config.backend {
        VmBackendChoice::CloudHypervisor => true,
        VmBackendChoice::Libkrun => false,
        VmBackendChoice::Auto => config.gpu_enabled || config.vfio_device.is_some(),
    };

    if use_chv {
        #[cfg(not(target_os = "linux"))]
        return Err(VmError::HostSetup(
            "cloud-hypervisor backend requires Linux with KVM".into(),
        ));

        #[cfg(target_os = "linux")]
        {
            if let Some(ref addr) = config.vfio_device {
                validate_vfio_address(addr)?;
            }
            let chv_backend = backend::cloud_hypervisor::CloudHypervisorBackend::new()?;
            return backend::VmBackend::launch(&chv_backend, config);
        }
    }

    // libkrun path: resolve the embedded runtime bundle and load libkrun.
    // Cloud-hypervisor resolves its own binaries in CloudHypervisorBackend::new().
    let runtime_gvproxy = resolve_runtime_bundle()?;
    let runtime_dir = runtime_gvproxy.parent().ok_or_else(|| {
        VmError::HostSetup(format!(
            "runtime bundle file has no parent directory: {}",
            runtime_gvproxy.display()
        ))
    })?;
    configure_runtime_loader_env(runtime_dir)?;

    let _ = ffi::libkrun()?;
    log_runtime_provenance(runtime_dir);

    let libkrun_backend = backend::libkrun::LibkrunBackend;
    backend::VmBackend::launch(&libkrun_backend, config)
}

// ── Post-boot bootstrap ────────────────────────────────────────────────

/// Default gateway port: host port mapped to the `OpenShell` `NodePort` (30051).
const DEFAULT_GATEWAY_PORT: u16 = 30051;

/// Bootstrap the `OpenShell` control plane after k3s is ready.
///
/// Two paths:
///
/// 1. **Warm boot**: host-side metadata and mTLS certs already exist from a
///    previous run. Fetch PKI via the exec agent to detect cert drift (e.g.
///    after a `--reset`), re-sync if needed, then proceed to the health check.
///
/// 2. **First boot / post-reset**: poll the exec agent to `cat` each PEM file
///    from `/opt/openshell/pki/` until the files exist (PKI generation has
///    finished), then store them in `~/.config/openshell/gateways/<name>/mtls/`.
pub(crate) fn bootstrap_gateway(
    rootfs: &Path,
    gateway_name: &str,
    gateway_port: u16,
) -> Result<(), VmError> {
    let bootstrap_start = Instant::now();

    let metadata = openshell_bootstrap::GatewayMetadata {
        name: gateway_name.to_string(),
        gateway_endpoint: format!("https://127.0.0.1:{gateway_port}"),
        is_remote: false,
        gateway_port,
        remote_host: None,
        resolved_host: None,
        auth_mode: None,
        edge_team_domain: None,
        edge_auth_url: None,
    };

    let exec_socket = vm_exec_socket_path(rootfs);

    // ── Warm boot: host already has certs ──────────────────────────
    if is_warm_boot(gateway_name) {
        // Always (re-)store metadata so port/endpoint changes are picked up.
        openshell_bootstrap::store_gateway_metadata(gateway_name, &metadata)
            .map_err(|e| VmError::Bootstrap(format!("failed to store metadata: {e}")))?;
        openshell_bootstrap::save_active_gateway(gateway_name)
            .map_err(|e| VmError::Bootstrap(format!("failed to set active cluster: {e}")))?;

        // Verify host certs match the VM's PKI. If they diverge (e.g.
        // PKI was regenerated after a --reset, or the state disk was
        // replaced), re-sync the host certs from the VM via the exec agent.
        //
        // On warm boot the exec agent may not be ready yet (the VM is
        // still booting). Use a short timeout — this is a non-critical
        // drift check and the host already has valid certs. If the agent
        // isn't reachable we skip silently rather than blocking boot for
        // 30s.
        match fetch_pki_over_exec(&exec_socket, std::time::Duration::from_secs(5)) {
            Ok(bundle) => {
                if let Err(e) = sync_host_certs_if_stale(gateway_name, &bundle) {
                    eprintln!("Warning: cert sync check failed: {e}");
                }
            }
            Err(_) => {
                // Expected on warm boot — exec agent not ready yet.
            }
        }

        eprintln!(
            "Warm boot [{:.1}s]",
            bootstrap_start.elapsed().as_secs_f64()
        );
        eprintln!("  Cluster:  {gateway_name}");
        eprintln!("  Gateway:  https://127.0.0.1:{gateway_port}");
        eprintln!("  mTLS:     ~/.config/openshell/gateways/{gateway_name}/mtls/");
        return Ok(());
    }

    // ── First boot / post-reset: fetch PKI from VM via exec agent ──
    //
    // The VM init script generates certs on first boot at /opt/openshell/pki/.
    // We poll the exec agent with `cat <file>` for each PEM file until they
    // exist, retrying to handle the window between VM boot and PKI generation.
    eprintln!("Waiting for VM to generate PKI...");
    let pki_bundle = fetch_pki_over_exec(&exec_socket, std::time::Duration::from_secs(120))
        .map_err(|e| VmError::Bootstrap(format!("VM did not produce PKI within 120s: {e}")))?;

    eprintln!("PKI ready — storing client certs on host...");

    openshell_bootstrap::store_gateway_metadata(gateway_name, &metadata)
        .map_err(|e| VmError::Bootstrap(format!("failed to store metadata: {e}")))?;

    openshell_bootstrap::mtls::store_pki_bundle(gateway_name, &pki_bundle)
        .map_err(|e| VmError::Bootstrap(format!("failed to store mTLS creds: {e}")))?;

    openshell_bootstrap::save_active_gateway(gateway_name)
        .map_err(|e| VmError::Bootstrap(format!("failed to set active cluster: {e}")))?;

    eprintln!(
        "Bootstrap complete [{:.1}s]",
        bootstrap_start.elapsed().as_secs_f64()
    );
    eprintln!("  Cluster:  {gateway_name}");
    eprintln!("  Gateway:  https://127.0.0.1:{gateway_port}");
    eprintln!("  mTLS:     ~/.config/openshell/gateways/{gateway_name}/mtls/");

    Ok(())
}

/// PKI file names and the corresponding [`PkiBundle`] fields.
const PKI_FILES: &[(&str, &str)] = &[
    ("ca.crt", "ca_cert_pem"),
    ("ca.key", "ca_key_pem"),
    ("server.crt", "server_cert_pem"),
    ("server.key", "server_key_pem"),
    ("client.crt", "client_cert_pem"),
    ("client.key", "client_key_pem"),
];

/// Fetch all six PEM files from `/opt/openshell/pki/` inside the guest by
/// running `cat` via the exec agent.  Retries until `timeout` elapses,
/// sleeping 500ms between attempts, to handle the window between VM boot
/// and PKI generation completing.
fn fetch_pki_over_exec(
    exec_socket: &Path,
    timeout: std::time::Duration,
) -> Result<openshell_bootstrap::pki::PkiBundle, VmError> {
    let deadline = Instant::now() + timeout;

    loop {
        match try_read_pki_files(exec_socket) {
            Ok(bundle) => return Ok(bundle),
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            Err(e) => {
                return Err(VmError::Bootstrap(format!(
                    "failed to read PKI files via exec agent: {e}"
                )));
            }
        }
    }
}

/// Attempt to read all six PEM files from the guest in one pass.
fn try_read_pki_files(exec_socket: &Path) -> Result<openshell_bootstrap::pki::PkiBundle, VmError> {
    let mut pems = std::collections::HashMap::new();

    for &(filename, _field) in PKI_FILES {
        let path = format!("/opt/openshell/pki/{filename}");
        let output = exec_capture(exec_socket, vec!["cat".to_string(), path])?;
        let content = String::from_utf8(output).map_err(|e| {
            VmError::Bootstrap(format!("PKI file {filename} is not valid UTF-8: {e}"))
        })?;
        if content.is_empty() {
            return Err(VmError::Bootstrap(format!("PKI file {filename} is empty")));
        }
        pems.insert(filename, content);
    }

    let mut get = |key: &str| -> Result<String, VmError> {
        pems.remove(key)
            .ok_or_else(|| VmError::Bootstrap(format!("PKI file {key} missing from exec output")))
    };

    Ok(openshell_bootstrap::pki::PkiBundle {
        ca_cert_pem: get("ca.crt")?,
        ca_key_pem: get("ca.key")?,
        server_cert_pem: get("server.crt")?,
        server_key_pem: get("server.key")?,
        client_cert_pem: get("client.crt")?,
        client_key_pem: get("client.key")?,
    })
}

/// Check whether a previous bootstrap left valid state on disk.
///
/// A warm boot is detected when both:
/// - Cluster metadata exists: `$XDG_CONFIG_HOME/openshell/gateways/openshell-vm/metadata.json`
/// - mTLS certs exist: `$XDG_CONFIG_HOME/openshell/gateways/openshell-vm/mtls/{ca.crt,tls.crt,tls.key}`
///
/// When true, the host-side bootstrap (PKI generation, secret manifest writing,
/// metadata storage) can be skipped because the virtio-fs rootfs persists k3s
/// state (TLS certs, kine/SQLite cluster objects, containerd images, helm
/// releases) across VM restarts. The kine database is preserved on normal
/// boots so that pods and other cluster objects survive restarts.
fn is_warm_boot(gateway_name: &str) -> bool {
    let Ok(home) = std::env::var("HOME") else {
        return false;
    };

    let config_base =
        std::env::var("XDG_CONFIG_HOME").unwrap_or_else(|_| format!("{home}/.config"));

    let config_dir = PathBuf::from(&config_base)
        .join("openshell")
        .join("gateways");

    // Check metadata file.
    let metadata_path = config_dir.join(gateway_name).join("metadata.json");
    if !metadata_path.is_file() {
        return false;
    }

    // Check mTLS cert files.
    let mtls_dir = config_dir.join(gateway_name).join("mtls");
    for name in &["ca.crt", "tls.crt", "tls.key"] {
        let path = mtls_dir.join(name);
        match std::fs::metadata(&path) {
            Ok(m) if m.is_file() && m.len() > 0 => {}
            _ => return false,
        }
    }

    true
}

/// Remove cached mTLS certs from the host so the next `bootstrap_gateway`
/// call treats this as a cold boot and fetches fresh PKI from the VM.
///
/// Called when the state disk is freshly created or `--reset` is used,
/// since the VM will generate new PKI that won't match stale host certs.
fn clear_warm_boot_certs(gateway_name: &str) {
    let Ok(home) = std::env::var("HOME") else {
        return;
    };
    let config_base =
        std::env::var("XDG_CONFIG_HOME").unwrap_or_else(|_| format!("{home}/.config"));
    let mtls_dir = PathBuf::from(&config_base)
        .join("openshell/gateways")
        .join(gateway_name)
        .join("mtls");

    if mtls_dir.is_dir() {
        if let Err(e) = std::fs::remove_dir_all(&mtls_dir) {
            eprintln!("Warning: failed to clear stale mTLS certs: {e}");
        } else {
            eprintln!("Cleared stale host mTLS certs");
        }
    }
}

/// Compare the CA cert on the rootfs (authoritative source) against the
/// host-side copy. If they differ, re-copy all client certs from the rootfs.
///
/// This catches cases where PKI was regenerated (e.g. rootfs rebuilt,
/// manual reset) but host-side certs survived from a previous boot cycle.
fn sync_host_certs_if_stale(
    gateway_name: &str,
    bundle: &openshell_bootstrap::pki::PkiBundle,
) -> Result<(), VmError> {
    let Ok(home) = std::env::var("HOME") else {
        return Ok(());
    };
    let config_base =
        std::env::var("XDG_CONFIG_HOME").unwrap_or_else(|_| format!("{home}/.config"));
    let host_ca = PathBuf::from(&config_base)
        .join("openshell/gateways")
        .join(gateway_name)
        .join("mtls/ca.crt");

    let host_ca_contents = std::fs::read_to_string(&host_ca)
        .map_err(|e| VmError::Bootstrap(format!("failed to read host ca.crt: {e}")))?;

    if bundle.ca_cert_pem.trim() == host_ca_contents.trim() {
        return Ok(());
    }

    eprintln!("Cert drift detected — re-syncing mTLS certs from VM...");

    openshell_bootstrap::mtls::store_pki_bundle(gateway_name, bundle)
        .map_err(|e| VmError::Bootstrap(format!("failed to store mTLS creds: {e}")))?;

    eprintln!("  mTLS certs re-synced from VM");
    Ok(())
}

pub(crate) static CHILD_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

pub(crate) extern "C" fn forward_signal(_sig: libc::c_int) {
    let pid = CHILD_PID.load(std::sync::atomic::Ordering::Relaxed);
    if pid > 0 {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_runtime_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "openshell-vm-runtime-{}-{nanos}",
            std::process::id()
        ))
    }

    fn write_runtime_file(path: &Path) {
        fs::write(path, b"test").expect("failed to write runtime file");
    }

    #[test]
    fn validate_runtime_dir_accepts_minimal_bundle() {
        let dir = temp_runtime_dir();
        fs::create_dir_all(&dir).expect("failed to create runtime dir");

        write_runtime_file(&dir.join(ffi::required_runtime_lib_name()));
        write_runtime_file(&dir.join("libkrunfw.test"));
        let gvproxy = dir.join("gvproxy");
        write_runtime_file(&gvproxy);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let mut perms = fs::metadata(&gvproxy).expect("stat gvproxy").permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&gvproxy, perms).expect("chmod gvproxy");
        }

        validate_runtime_dir(&dir).expect("runtime bundle should validate");
        assert!(gvproxy.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_runtime_dir_requires_gvproxy() {
        let dir = temp_runtime_dir();
        fs::create_dir_all(&dir).expect("failed to create runtime dir");

        write_runtime_file(&dir.join(ffi::required_runtime_lib_name()));
        write_runtime_file(&dir.join("libkrunfw.test"));

        let err = validate_runtime_dir(&dir).expect_err("missing gvproxy should fail");
        match err {
            VmError::BinaryNotFound { hint, .. } => {
                assert!(hint.contains("missing gvproxy"));
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn gateway_config_uses_default_state_disk_next_to_rootfs() {
        let rootfs = PathBuf::from("/tmp/openshell-vm-test/rootfs");

        let config = VmConfig::gateway(rootfs.clone());
        let state_disk = config
            .state_disk
            .expect("gateway should enable a state disk");

        assert_eq!(
            state_disk.path,
            rootfs.parent().unwrap().join("rootfs-state.raw")
        );
        assert_eq!(state_disk.block_id, DEFAULT_STATE_DISK_BLOCK_ID);
        assert_eq!(state_disk.guest_device, DEFAULT_STATE_DISK_GUEST_DEVICE);
        assert_eq!(state_disk.size_bytes, DEFAULT_STATE_DISK_SIZE_BYTES);
    }

    #[test]
    fn ensure_state_disk_image_creates_sparse_file() {
        let dir = temp_runtime_dir();
        fs::create_dir_all(&dir).expect("failed to create runtime dir");

        let state_disk = StateDiskConfig {
            path: dir.join("state.raw"),
            size_bytes: 8 * 1024 * 1024,
            block_id: DEFAULT_STATE_DISK_BLOCK_ID.to_string(),
            guest_device: DEFAULT_STATE_DISK_GUEST_DEVICE.to_string(),
        };

        ensure_state_disk_image(&state_disk).expect("state disk should be created");

        let metadata = fs::metadata(&state_disk.path).expect("stat state disk");
        assert_eq!(metadata.len(), state_disk.size_bytes);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn prepare_rootfs_returns_existing_explicit_rootfs() {
        let dir = temp_runtime_dir();
        let rootfs = dir.join("rootfs");
        fs::create_dir_all(&rootfs).expect("failed to create rootfs dir");

        let prepared =
            prepare_rootfs(Some(rootfs.clone()), "default", false).expect("prepare rootfs");

        assert_eq!(prepared, rootfs);

        let _ = fs::remove_dir_all(&dir);
    }
}
