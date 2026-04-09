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

mod embedded;
mod exec;
mod ffi;
mod health;

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::Instant;

pub use exec::{
    VM_EXEC_VSOCK_PORT, VmExecOptions, VmRuntimeState, acquire_rootfs_lock, clear_vm_runtime_state,
    ensure_vm_not_running, exec_capture, exec_running_vm, recover_corrupt_kine_db,
    reset_runtime_state, vm_exec_socket_path, vm_state_path, write_vm_runtime_state,
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
fn c_string_array(strings: &[&str]) -> Result<(Vec<CString>, Vec<*const libc::c_char>), VmError> {
    let owned: Vec<CString> = strings
        .iter()
        .map(|s| CString::new(*s))
        .collect::<Result<Vec<_>, _>>()?;
    let mut ptrs: Vec<*const libc::c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(ptr::null()); // null terminator
    Ok((owned, ptrs))
}

const VM_RUNTIME_DIR_ENV: &str = "OPENSHELL_VM_RUNTIME_DIR";

pub(crate) fn configured_runtime_dir() -> Result<PathBuf, VmError> {
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

fn clamp_log_level(level: u32) -> u32 {
    match level {
        0 => ffi::KRUN_LOG_LEVEL_OFF,
        1 => ffi::KRUN_LOG_LEVEL_ERROR,
        2 => ffi::KRUN_LOG_LEVEL_WARN,
        3 => ffi::KRUN_LOG_LEVEL_INFO,
        4 => ffi::KRUN_LOG_LEVEL_DEBUG,
        _ => ffi::KRUN_LOG_LEVEL_TRACE,
    }
}

struct VmContext {
    krun: &'static ffi::LibKrun,
    ctx_id: u32,
}

impl VmContext {
    fn create(log_level: u32) -> Result<Self, VmError> {
        let krun = ffi::libkrun()?;
        unsafe {
            check(
                (krun.krun_init_log)(
                    ffi::KRUN_LOG_TARGET_DEFAULT,
                    clamp_log_level(log_level),
                    ffi::KRUN_LOG_STYLE_AUTO,
                    ffi::KRUN_LOG_OPTION_NO_ENV,
                ),
                "krun_init_log",
            )?;
        }

        let ctx_id = unsafe { (krun.krun_create_ctx)() };
        if ctx_id < 0 {
            return Err(VmError::Krun {
                func: "krun_create_ctx",
                code: ctx_id,
            });
        }

        Ok(Self {
            krun,
            ctx_id: ctx_id as u32,
        })
    }

    fn set_vm_config(&self, vcpus: u8, mem_mib: u32) -> Result<(), VmError> {
        unsafe {
            check(
                (self.krun.krun_set_vm_config)(self.ctx_id, vcpus, mem_mib),
                "krun_set_vm_config",
            )
        }
    }

    fn set_root(&self, rootfs: &Path) -> Result<(), VmError> {
        let rootfs_c = path_to_cstring(rootfs)?;
        unsafe {
            check(
                (self.krun.krun_set_root)(self.ctx_id, rootfs_c.as_ptr()),
                "krun_set_root",
            )
        }
    }

    fn add_state_disk(&self, state_disk: &StateDiskConfig) -> Result<(), VmError> {
        let Some(add_disk3) = self.krun.krun_add_disk3 else {
            return Err(VmError::HostSetup(
                "libkrun runtime does not expose krun_add_disk3; rebuild the VM runtime with block support"
                    .to_string(),
            ));
        };

        let block_id_c = CString::new(state_disk.block_id.as_str())?;
        let disk_path_c = path_to_cstring(&state_disk.path)?;
        unsafe {
            check(
                add_disk3(
                    self.ctx_id,
                    block_id_c.as_ptr(),
                    disk_path_c.as_ptr(),
                    ffi::KRUN_DISK_FORMAT_RAW,
                    false,
                    false,
                    state_disk_sync_mode(),
                ),
                "krun_add_disk3",
            )
        }
    }

    fn set_workdir(&self, workdir: &str) -> Result<(), VmError> {
        let workdir_c = CString::new(workdir)?;
        unsafe {
            check(
                (self.krun.krun_set_workdir)(self.ctx_id, workdir_c.as_ptr()),
                "krun_set_workdir",
            )
        }
    }

    fn disable_implicit_vsock(&self) -> Result<(), VmError> {
        unsafe {
            check(
                (self.krun.krun_disable_implicit_vsock)(self.ctx_id),
                "krun_disable_implicit_vsock",
            )
        }
    }

    fn add_vsock(&self, tsi_features: u32) -> Result<(), VmError> {
        unsafe {
            check(
                (self.krun.krun_add_vsock)(self.ctx_id, tsi_features),
                "krun_add_vsock",
            )
        }
    }

    #[cfg(target_os = "macos")]
    fn add_net_unixgram(
        &self,
        socket_path: &Path,
        mac: &[u8; 6],
        features: u32,
        flags: u32,
    ) -> Result<(), VmError> {
        let sock_c = path_to_cstring(socket_path)?;
        unsafe {
            check(
                (self.krun.krun_add_net_unixgram)(
                    self.ctx_id,
                    sock_c.as_ptr(),
                    -1,
                    mac.as_ptr(),
                    features,
                    flags,
                ),
                "krun_add_net_unixgram",
            )
        }
    }

    #[allow(dead_code)] // FFI binding for future use (e.g. Linux networking)
    fn add_net_unixstream(
        &self,
        socket_path: &Path,
        mac: &[u8; 6],
        features: u32,
    ) -> Result<(), VmError> {
        let sock_c = path_to_cstring(socket_path)?;
        unsafe {
            check(
                (self.krun.krun_add_net_unixstream)(
                    self.ctx_id,
                    sock_c.as_ptr(),
                    -1,
                    mac.as_ptr(),
                    features,
                    0,
                ),
                "krun_add_net_unixstream",
            )
        }
    }

    fn set_port_map(&self, port_map: &[String]) -> Result<(), VmError> {
        let port_strs: Vec<&str> = port_map.iter().map(String::as_str).collect();
        let (_port_owners, port_ptrs) = c_string_array(&port_strs)?;
        unsafe {
            check(
                (self.krun.krun_set_port_map)(self.ctx_id, port_ptrs.as_ptr()),
                "krun_set_port_map",
            )
        }
    }

    fn add_vsock_port(&self, port: &VsockPort) -> Result<(), VmError> {
        let socket_c = path_to_cstring(&port.socket_path)?;
        unsafe {
            check(
                (self.krun.krun_add_vsock_port2)(
                    self.ctx_id,
                    port.port,
                    socket_c.as_ptr(),
                    port.listen,
                ),
                "krun_add_vsock_port2",
            )
        }
    }

    fn set_console_output(&self, path: &Path) -> Result<(), VmError> {
        let console_c = path_to_cstring(path)?;
        unsafe {
            check(
                (self.krun.krun_set_console_output)(self.ctx_id, console_c.as_ptr()),
                "krun_set_console_output",
            )
        }
    }

    fn set_exec(&self, exec_path: &str, args: &[String], env: &[String]) -> Result<(), VmError> {
        let exec_c = CString::new(exec_path)?;
        let argv_strs: Vec<&str> = args.iter().map(String::as_str).collect();
        let (_argv_owners, argv_ptrs) = c_string_array(&argv_strs)?;
        let env_strs: Vec<&str> = env.iter().map(String::as_str).collect();
        let (_env_owners, env_ptrs) = c_string_array(&env_strs)?;

        unsafe {
            check(
                (self.krun.krun_set_exec)(
                    self.ctx_id,
                    exec_c.as_ptr(),
                    argv_ptrs.as_ptr(),
                    env_ptrs.as_ptr(),
                ),
                "krun_set_exec",
            )
        }
    }

    fn start_enter(&self) -> i32 {
        unsafe { (self.krun.krun_start_enter)(self.ctx_id) }
    }
}

impl Drop for VmContext {
    fn drop(&mut self) {
        unsafe {
            let ret = (self.krun.krun_free_ctx)(self.ctx_id);
            if ret < 0 {
                eprintln!(
                    "warning: krun_free_ctx({}) failed with code {ret}",
                    self.ctx_id
                );
            }
        }
    }
}

/// RAII guard that kills and waits on a gvproxy child process when dropped.
///
/// This prevents orphaned gvproxy processes when early `?` returns in the
/// launch function cause the child to be dropped before cleanup code runs.
/// Call [`GvproxyGuard::disarm`] to take ownership of the child when it
/// should outlive the guard (i.e., after a successful fork).
struct GvproxyGuard {
    child: Option<std::process::Child>,
}

impl GvproxyGuard {
    fn new(child: std::process::Child) -> Self {
        Self { child: Some(child) }
    }

    /// Take the child out of the guard, preventing it from being killed on drop.
    /// Use this after the launch is successful and the parent will manage cleanup.
    fn disarm(&mut self) -> Option<std::process::Child> {
        self.child.take()
    }

    /// Get the child's PID without disarming.
    fn id(&self) -> Option<u32> {
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
fn gvproxy_expose(api_sock: &Path, body: &str) -> Result<(), String> {
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
/// and holds port 2222. A new gvproxy instance then fails with
/// "bind: address already in use".
///
/// We only kill the specific gvproxy PID recorded in the VM runtime state
/// to avoid disrupting unrelated gvproxy instances (e.g. Podman Desktop).
/// Before sending SIGTERM, we verify the process name contains "gvproxy"
/// to guard against PID reuse.
fn kill_stale_gvproxy(rootfs: &Path) {
    let state_path = vm_state_path(rootfs);
    let pid = std::fs::read(&state_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<VmRuntimeState>(&bytes).ok())
        .and_then(|state| state.gvproxy_pid);

    if let Some(gvproxy_pid) = pid {
        // Verify the process is still alive before killing it.
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

fn vm_rootfs_key(rootfs: &Path) -> String {
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

fn state_disk_sync_mode() -> u32 {
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

fn gvproxy_socket_dir(rootfs: &Path) -> Result<PathBuf, VmError> {
    let dir = secure_socket_base("ovm-gv")?;

    // macOS unix socket path limit is tight (~104 bytes). Keep paths very short.
    let id = hash_path_id(rootfs);
    Ok(dir.join(id))
}

fn gateway_host_port(config: &VmConfig) -> u16 {
    config
        .port_map
        .first()
        .and_then(|pm| pm.split(':').next())
        .and_then(|port| port.parse::<u16>().ok())
        .unwrap_or(DEFAULT_GATEWAY_PORT)
}

fn pick_gvproxy_ssh_port() -> Result<u16, VmError> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| VmError::HostSetup(format!("allocate gvproxy ssh port on localhost: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| VmError::HostSetup(format!("read gvproxy ssh port: {e}")))?
        .port();
    drop(listener);
    Ok(port)
}

fn path_to_cstring(path: &Path) -> Result<CString, VmError> {
    let s = path
        .to_str()
        .ok_or_else(|| VmError::InvalidPath(path.display().to_string()))?;
    Ok(CString::new(s)?)
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
    if let Some(state_disk) = &config.state_disk {
        ensure_state_disk_image(state_disk)?;
    }

    let launch_start = Instant::now();
    eprintln!("rootfs: {}", config.rootfs.display());
    if let Some(state_disk) = &config.state_disk {
        eprintln!(
            "state disk: {} ({} GiB)",
            state_disk.path.display(),
            state_disk.size_bytes / 1024 / 1024 / 1024
        );
    }
    eprintln!("vm: {} vCPU(s), {} MiB RAM", config.vcpus, config.mem_mib);

    // The runtime is embedded in the binary and extracted on first use.
    // Can be overridden via OPENSHELL_VM_RUNTIME_DIR for development.
    let runtime_gvproxy = resolve_runtime_bundle()?;
    let runtime_dir = runtime_gvproxy.parent().ok_or_else(|| {
        VmError::HostSetup(format!(
            "runtime bundle file has no parent directory: {}",
            runtime_gvproxy.display()
        ))
    })?;
    configure_runtime_loader_env(runtime_dir)?;
    raise_nofile_limit();

    // ── Log runtime provenance ─────────────────────────────────────
    // After configuring the loader, trigger library loading so that
    // provenance is captured before we proceed with VM configuration.
    let _ = ffi::libkrun()?;
    log_runtime_provenance(runtime_dir);

    // ── Configure the microVM ──────────────────────────────────────

    let vm = VmContext::create(config.log_level)?;
    vm.set_vm_config(config.vcpus, config.mem_mib)?;
    vm.set_root(&config.rootfs)?;
    if let Some(state_disk) = &config.state_disk {
        vm.add_state_disk(state_disk)?;
    }
    vm.set_workdir(&config.workdir)?;

    // Networking setup — use a drop guard so gvproxy is killed if we
    // return early via `?` before reaching the parent's cleanup code.
    let mut gvproxy_guard: Option<GvproxyGuard> = None;
    let mut gvproxy_api_sock: Option<PathBuf> = None;

    match &config.net {
        NetBackend::Tsi => {
            // Default TSI — no special setup needed.
        }
        NetBackend::None => {
            vm.disable_implicit_vsock()?;
            vm.add_vsock(0)?;
            eprintln!("Networking: disabled (no TSI, no virtio-net)");
        }
        NetBackend::Gvproxy { binary } => {
            if !binary.exists() {
                return Err(VmError::BinaryNotFound {
                    path: binary.display().to_string(),
                    hint: "Install Podman Desktop or place gvproxy in PATH".to_string(),
                });
            }

            // Create temp socket paths
            let run_dir = config
                .rootfs
                .parent()
                .unwrap_or(&config.rootfs)
                .to_path_buf();
            let rootfs_key = vm_rootfs_key(&config.rootfs);
            let sock_base = gvproxy_socket_dir(&config.rootfs)?;
            let net_sock = sock_base.with_extension("v");
            let api_sock = sock_base.with_extension("a");

            // Kill any stale gvproxy process from a previous run.
            // If gvproxy is still holding port 2222, the new instance
            // will fail with "bind: address already in use".
            kill_stale_gvproxy(&config.rootfs);

            // Clean stale sockets (including the -krun.sock file that
            // libkrun creates as its datagram endpoint on macOS).
            let _ = std::fs::remove_file(&net_sock);
            let _ = std::fs::remove_file(&api_sock);
            let krun_sock = sock_base.with_extension("v-krun.sock");
            let _ = std::fs::remove_file(&krun_sock);

            // Start gvproxy
            eprintln!("Starting gvproxy: {}", binary.display());
            let ssh_port = pick_gvproxy_ssh_port()?;
            let gvproxy_log = run_dir.join(format!("{rootfs_key}-gvproxy.log"));
            let gvproxy_log_file = std::fs::File::create(&gvproxy_log)
                .map_err(|e| VmError::Fork(format!("failed to create gvproxy log: {e}")))?;

            // On Linux, gvproxy uses QEMU mode (SOCK_STREAM) since the vfkit
            // unixgram scheme is macOS/vfkit-specific.  On macOS, use vfkit mode.
            #[cfg(target_os = "linux")]
            let (gvproxy_net_flag, gvproxy_net_url) =
                ("-listen-qemu", format!("unix://{}", net_sock.display()));
            #[cfg(target_os = "macos")]
            let (gvproxy_net_flag, gvproxy_net_url) = (
                "-listen-vfkit",
                format!("unixgram://{}", net_sock.display()),
            );

            let child = std::process::Command::new(binary)
                .arg(gvproxy_net_flag)
                .arg(&gvproxy_net_url)
                .arg("-listen")
                .arg(format!("unix://{}", api_sock.display()))
                .arg("-ssh-port")
                .arg(ssh_port.to_string())
                .stdout(std::process::Stdio::null())
                .stderr(gvproxy_log_file)
                .spawn()
                .map_err(|e| VmError::Fork(format!("failed to start gvproxy: {e}")))?;

            eprintln!(
                "gvproxy started (pid {}, ssh port {}) [{:.1}s]",
                child.id(),
                ssh_port,
                launch_start.elapsed().as_secs_f64()
            );

            // Wait for the socket to appear (exponential backoff: 5ms → 100ms).
            {
                let deadline = Instant::now() + std::time::Duration::from_secs(5);
                let mut interval = std::time::Duration::from_millis(5);
                while !net_sock.exists() {
                    if Instant::now() >= deadline {
                        return Err(VmError::Fork(
                            "gvproxy socket did not appear within 5s".to_string(),
                        ));
                    }
                    std::thread::sleep(interval);
                    interval = (interval * 2).min(std::time::Duration::from_millis(100));
                }
            }

            // Disable implicit TSI and add virtio-net via gvproxy
            vm.disable_implicit_vsock()?;
            vm.add_vsock(0)?;
            // This MAC matches gvproxy's default static DHCP lease for
            // 192.168.127.2. Using a different MAC can cause the gVisor
            // network stack to misroute or drop packets.
            let mac: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];

            // COMPAT_NET_FEATURES from libkrun.h
            const NET_FEATURE_CSUM: u32 = 1 << 0;
            const NET_FEATURE_GUEST_CSUM: u32 = 1 << 1;
            const NET_FEATURE_GUEST_TSO4: u32 = 1 << 7;
            const NET_FEATURE_GUEST_UFO: u32 = 1 << 10;
            const NET_FEATURE_HOST_TSO4: u32 = 1 << 11;
            const NET_FEATURE_HOST_UFO: u32 = 1 << 14;
            const COMPAT_NET_FEATURES: u32 = NET_FEATURE_CSUM
                | NET_FEATURE_GUEST_CSUM
                | NET_FEATURE_GUEST_TSO4
                | NET_FEATURE_GUEST_UFO
                | NET_FEATURE_HOST_TSO4
                | NET_FEATURE_HOST_UFO;

            // On Linux use unixstream (SOCK_STREAM) to connect to gvproxy's
            // QEMU listener.  On macOS use unixgram (SOCK_DGRAM) with the vfkit
            // magic byte for the vfkit listener.
            #[cfg(target_os = "linux")]
            vm.add_net_unixstream(&net_sock, &mac, COMPAT_NET_FEATURES)?;
            #[cfg(target_os = "macos")]
            {
                const NET_FLAG_VFKIT: u32 = 1 << 0;
                vm.add_net_unixgram(&net_sock, &mac, COMPAT_NET_FEATURES, NET_FLAG_VFKIT)?;
            }

            eprintln!(
                "Networking: gvproxy (virtio-net) [{:.1}s]",
                launch_start.elapsed().as_secs_f64()
            );
            gvproxy_guard = Some(GvproxyGuard::new(child));
            gvproxy_api_sock = Some(api_sock);
        }
    }

    // Port mapping (TSI only)
    if !config.port_map.is_empty() && matches!(config.net, NetBackend::Tsi) {
        vm.set_port_map(&config.port_map)?;
    }

    for vsock_port in &config.vsock_ports {
        if let Some(parent) = vsock_port.socket_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                VmError::RuntimeState(format!("create vsock socket dir {}: {e}", parent.display()))
            })?;
        }
        // libkrun returns EEXIST if the socket file is already present from a
        // previous run. Remove any stale socket before registering the port.
        let _ = std::fs::remove_file(&vsock_port.socket_path);
        vm.add_vsock_port(vsock_port)?;
    }

    // Console output
    let console_log = config.console_output.clone().unwrap_or_else(|| {
        config
            .rootfs
            .parent()
            .unwrap_or(&config.rootfs)
            .join(format!("{}-console.log", vm_rootfs_key(&config.rootfs)))
    });
    vm.set_console_output(&console_log)?;

    // envp: use provided env or minimal defaults
    let mut env: Vec<String> = if config.env.is_empty() {
        vec![
            "HOME=/root",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM=xterm",
        ]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect()
    } else {
        config.env.clone()
    };
    if let Some(state_disk) = &config.state_disk
        && !env
            .iter()
            .any(|entry| entry.starts_with("OPENSHELL_VM_STATE_DISK_DEVICE="))
    {
        env.push(format!(
            "OPENSHELL_VM_STATE_DISK_DEVICE={}",
            state_disk.guest_device
        ));
    }
    vm.set_exec(&config.exec_path, &config.args, &env)?;

    // ── Fork and enter the VM ──────────────────────────────────────
    //
    // krun_start_enter() never returns — it calls exit() when the guest
    // process exits. We fork so the parent can monitor and report.

    let boot_start = Instant::now();
    eprintln!("Booting microVM...");

    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(VmError::Fork(std::io::Error::last_os_error().to_string())),
        0 => {
            // Child process: enter the VM (never returns on success)
            let ret = vm.start_enter();
            eprintln!("krun_start_enter failed: {ret}");
            std::process::exit(1);
        }
        _ => {
            // Parent: wait for child
            if config.exec_path == "/srv/openshell-vm-init.sh" {
                let gvproxy_pid = gvproxy_guard.as_ref().and_then(GvproxyGuard::id);
                if let Err(err) =
                    write_vm_runtime_state(&config.rootfs, pid, &console_log, gvproxy_pid)
                {
                    unsafe {
                        libc::kill(pid, libc::SIGTERM);
                    }
                    // Guard drop will kill gvproxy automatically
                    drop(gvproxy_guard);
                    clear_vm_runtime_state(&config.rootfs);
                    return Err(err);
                }
            }
            eprintln!(
                "VM started (child pid {pid}) [{:.1}s]",
                boot_start.elapsed().as_secs_f64()
            );
            for pm in &config.port_map {
                let host_port = pm.split(':').next().unwrap_or(pm);
                eprintln!("  port {pm} -> http://localhost:{host_port}");
            }
            eprintln!("Console output: {}", console_log.display());

            // Set up gvproxy port forwarding via its HTTP API.
            // The port_map entries use the same "host:guest" format
            // as TSI, but here we translate them into gvproxy expose
            // calls targeting the guest IP (192.168.127.2).
            //
            // Instead of a fixed 500ms sleep, poll the API socket with
            // exponential backoff (5ms → 200ms, ~1s total budget).
            if let Some(ref api_sock) = gvproxy_api_sock {
                let fwd_start = Instant::now();
                // Wait for the API socket to appear (it lags slightly
                // behind the vfkit data socket).
                {
                    let deadline = Instant::now() + std::time::Duration::from_secs(2);
                    let mut interval = std::time::Duration::from_millis(5);
                    while !api_sock.exists() {
                        if Instant::now() >= deadline {
                            eprintln!(
                                "warning: gvproxy API socket not ready after 2s, attempting anyway"
                            );
                            break;
                        }
                        std::thread::sleep(interval);
                        interval = (interval * 2).min(std::time::Duration::from_millis(200));
                    }
                }

                let guest_ip = "192.168.127.2";

                for pm in &config.port_map {
                    let parts: Vec<&str> = pm.split(':').collect();
                    let (host_port, guest_port) = match parts.len() {
                        2 => (parts[0], parts[1]),
                        1 => (parts[0], parts[0]),
                        _ => {
                            eprintln!("  skipping invalid port mapping: {pm}");
                            continue;
                        }
                    };

                    let expose_body = format!(
                        r#"{{"local":":{host_port}","remote":"{guest_ip}:{guest_port}","protocol":"tcp"}}"#
                    );

                    match gvproxy_expose(api_sock, &expose_body) {
                        Ok(()) => {
                            eprintln!("  port {host_port} -> {guest_ip}:{guest_port}");
                        }
                        Err(e) => {
                            eprintln!("  port {host_port}: {e}");
                        }
                    }
                }
                eprintln!(
                    "Port forwarding ready [{:.1}s]",
                    fwd_start.elapsed().as_secs_f64()
                );
            }

            // Bootstrap the OpenShell control plane and wait for the
            // service to be reachable. Only for the gateway preset, and
            // only when port forwarding is configured (i.e. the gateway
            // is reachable from the host). During rootfs pre-init builds,
            // no --port is specified so there is nothing to health-check
            // — the build script has its own kubectl-based readiness
            // checks inside the VM.
            if config.exec_path == "/srv/openshell-vm-init.sh" && !config.port_map.is_empty() {
                // Bootstrap stores host-side metadata and mTLS creds.
                // With pre-baked rootfs (Path 1) this reads PKI directly
                // from virtio-fs — no kubectl or port forwarding needed.
                // Cold boot (Path 2) writes secret manifests into the
                // k3s auto-deploy directory via virtio-fs.
                let gateway_port = gateway_host_port(config);
                bootstrap_gateway(&config.rootfs, &config.gateway_name, gateway_port)?;

                // Wait for the gRPC health check to pass. This ensures
                // the service is fully operational, not just accepting
                // TCP connections. The health check confirms the full
                // path (gvproxy → kube-proxy nftables → pod:8080) and
                // that the gRPC service is responding to requests.
                health::wait_for_gateway_ready(gateway_port, &config.gateway_name)?;
            }

            eprintln!("Ready [{:.1}s total]", boot_start.elapsed().as_secs_f64());
            eprintln!("Press Ctrl+C to stop.");

            // Forward signals to child
            unsafe {
                libc::signal(
                    libc::SIGINT,
                    forward_signal as *const () as libc::sighandler_t,
                );
                libc::signal(
                    libc::SIGTERM,
                    forward_signal as *const () as libc::sighandler_t,
                );
                CHILD_PID.store(pid, std::sync::atomic::Ordering::Relaxed);
            }

            let mut status: libc::c_int = 0;
            unsafe {
                libc::waitpid(pid, &raw mut status, 0);
            }

            // Clean up gvproxy — disarm the guard and do explicit cleanup
            // so we can print the "stopped" message.
            if config.exec_path == "/srv/openshell-vm-init.sh" {
                clear_vm_runtime_state(&config.rootfs);
            }
            if let Some(mut guard) = gvproxy_guard
                && let Some(mut child) = guard.disarm()
            {
                let _ = child.kill();
                let _ = child.wait();
                eprintln!("gvproxy stopped");
            }

            if libc::WIFEXITED(status) {
                let code = libc::WEXITSTATUS(status);
                eprintln!("VM exited with code {code}");
                return Ok(code);
            } else if libc::WIFSIGNALED(status) {
                let sig = libc::WTERMSIG(status);
                eprintln!("VM killed by signal {sig}");
                return Ok(128 + sig);
            }

            Ok(status)
        }
    }
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
fn bootstrap_gateway(rootfs: &Path, gateway_name: &str, gateway_port: u16) -> Result<(), VmError> {
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

static CHILD_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

extern "C" fn forward_signal(_sig: libc::c_int) {
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
