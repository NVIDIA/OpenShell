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

mod ffi;

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::Instant;

// ── Error type ─────────────────────────────────────────────────────────

/// Errors that can occur when configuring or launching a microVM.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum VmError {
    /// A libkrun FFI call returned a negative error code.
    #[error("{func} failed with error code {code}")]
    Krun { func: &'static str, code: i32 },

    /// The rootfs directory does not exist.
    #[error(
        "rootfs directory not found: {path}\nRun: ./crates/openshell-vm/scripts/build-rootfs.sh"
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
}

impl VmConfig {
    /// Default gateway configuration: boots k3s server inside the VM.
    ///
    /// Runs `/srv/gateway-init.sh` which mounts essential filesystems,
    /// deploys the OpenShell helm chart, and execs `k3s server`.
    /// Exposes the OpenShell gateway on port 30051.
    pub fn gateway(rootfs: PathBuf) -> Self {
        Self {
            rootfs,
            vcpus: 4,
            mem_mib: 8192,
            exec_path: "/srv/gateway-init.sh".to_string(),
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
            vsock_ports: vec![],
            log_level: 3, // Info — for debugging
            console_output: None,
            net: NetBackend::Gvproxy {
                binary: default_runtime_gvproxy_path(),
            },
        }
    }
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

const VM_RUNTIME_DIR_NAME: &str = "gateway.runtime";
const VM_RUNTIME_DIR_ENV: &str = "OPENSHELL_VM_RUNTIME_DIR";

pub(crate) fn configured_runtime_dir() -> Result<PathBuf, VmError> {
    if let Some(path) = std::env::var_os(VM_RUNTIME_DIR_ENV) {
        return Ok(PathBuf::from(path));
    }

    let exe = std::env::current_exe().map_err(|e| VmError::HostSetup(e.to_string()))?;
    let exe_dir = exe.parent().ok_or_else(|| {
        VmError::HostSetup(format!(
            "executable has no parent directory: {}",
            exe.display()
        ))
    })?;
    Ok(exe_dir.join(VM_RUNTIME_DIR_NAME))
}

fn required_runtime_lib_name() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "libkrun.dylib"
    }
    #[cfg(not(target_os = "macos"))]
    {
        "libkrun.so"
    }
}

fn validate_runtime_dir(dir: &Path) -> Result<PathBuf, VmError> {
    if !dir.is_dir() {
        return Err(VmError::BinaryNotFound {
            path: dir.display().to_string(),
            hint: format!(
                "stage the VM runtime bundle with `mise run vm:bundle-runtime` or set {VM_RUNTIME_DIR_ENV}"
            ),
        });
    }

    let libkrun = dir.join(required_runtime_lib_name());
    if !libkrun.is_file() {
        return Err(VmError::BinaryNotFound {
            path: libkrun.display().to_string(),
            hint: "runtime bundle is incomplete: missing libkrun".to_string(),
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
            hint: "runtime bundle is incomplete: missing libkrunfw".to_string(),
        });
    }

    let gvproxy = dir.join("gvproxy");
    if !gvproxy.is_file() {
        return Err(VmError::BinaryNotFound {
            path: gvproxy.display().to_string(),
            hint: "runtime bundle is incomplete: missing gvproxy".to_string(),
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

    // Validate manifest.json if present — warn but don't fail if files
    // listed in the manifest are missing (backwards compatibility).
    let manifest_path = dir.join("manifest.json");
    if manifest_path.is_file() {
        if let Ok(contents) = std::fs::read_to_string(&manifest_path) {
            // Simple check: verify all listed files exist.
            // The manifest lists files as JSON strings in a "files" array.
            for line in contents.lines() {
                let trimmed = line.trim().trim_matches(|c| c == '"' || c == ',');
                if !trimmed.is_empty()
                    && !trimmed.starts_with('{')
                    && !trimmed.starts_with('}')
                    && !trimmed.starts_with('[')
                    && !trimmed.starts_with(']')
                    && !trimmed.contains(':')
                {
                    let file_path = dir.join(trimmed);
                    if !file_path.exists() {
                        eprintln!(
                            "warning: manifest.json references missing file: {}",
                            trimmed
                        );
                    }
                }
            }
        }
    }

    Ok(gvproxy)
}

fn resolve_runtime_bundle() -> Result<PathBuf, VmError> {
    let runtime_dir = configured_runtime_dir()?;
    validate_runtime_dir(&runtime_dir)
}

pub fn default_runtime_gvproxy_path() -> PathBuf {
    configured_runtime_dir()
        .unwrap_or_else(|_| PathBuf::from(VM_RUNTIME_DIR_NAME))
        .join("gvproxy")
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

#[cfg(not(target_os = "macos"))]
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
            let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &rlim);
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
            let name = krunfw
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string());
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
                // Extract key fields without pulling in serde_json for this.
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

/// Simple JSON string value extractor (avoids serde_json dependency
/// for this single use case).
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let idx = json.find(&pattern)?;
    let after_key = &json[idx + pattern.len()..];
    // Skip whitespace and colon
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let after_ws = after_colon.trim_start();
    if after_ws.starts_with('"') {
        let value_start = &after_ws[1..];
        let end = value_start.find('"')?;
        Some(value_start[..end].to_string())
    } else {
        None
    }
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
            let _ = (self.krun.krun_free_ctx)(self.ctx_id);
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

/// Kill any stale gvproxy process from a previous gateway run.
///
/// If the CLI crashes or is killed before cleanup, gvproxy keeps running
/// and holds port 2222. A new gvproxy instance then fails with
/// "bind: address already in use".
fn kill_stale_gvproxy() {
    let output = std::process::Command::new("pkill")
        .args(["-x", "gvproxy"])
        .output();
    if let Ok(o) = output {
        if o.status.success() {
            eprintln!("Killed stale gvproxy process");
            // Brief pause for the port to be released.
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }
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
    // Validate rootfs
    if !config.rootfs.is_dir() {
        return Err(VmError::RootfsNotFound {
            path: config.rootfs.display().to_string(),
        });
    }

    let launch_start = Instant::now();
    eprintln!("rootfs: {}", config.rootfs.display());
    eprintln!("vm: {} vCPU(s), {} MiB RAM", config.vcpus, config.mem_mib);

    // The runtime must already be staged as a sidecar bundle next to the
    // binary (or explicitly pointed to via OPENSHELL_VM_RUNTIME_DIR).
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
    vm.set_workdir(&config.workdir)?;

    // Networking setup
    let mut gvproxy_child: Option<std::process::Child> = None;
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
            let vfkit_sock = run_dir.join("gvproxy-vfkit.sock");
            let api_sock = run_dir.join("gvproxy-api.sock");

            // Kill any stale gvproxy process from a previous run.
            // If gvproxy is still holding port 2222, the new instance
            // will fail with "bind: address already in use".
            kill_stale_gvproxy();

            // Clean stale sockets (including the -krun.sock file that
            // libkrun creates as its datagram endpoint).
            let _ = std::fs::remove_file(&vfkit_sock);
            let _ = std::fs::remove_file(&api_sock);
            let krun_sock = run_dir.join("gvproxy-vfkit.sock-krun.sock");
            let _ = std::fs::remove_file(&krun_sock);

            // Start gvproxy
            eprintln!("Starting gvproxy: {}", binary.display());
            let gvproxy_log = run_dir.join("gvproxy.log");
            let gvproxy_log_file = std::fs::File::create(&gvproxy_log)
                .map_err(|e| VmError::Fork(format!("failed to create gvproxy log: {e}")))?;
            let child = std::process::Command::new(binary)
                .arg("-listen-vfkit")
                .arg(format!("unixgram://{}", vfkit_sock.display()))
                .arg("-listen")
                .arg(format!("unix://{}", api_sock.display()))
                .stdout(std::process::Stdio::null())
                .stderr(gvproxy_log_file)
                .spawn()
                .map_err(|e| VmError::Fork(format!("failed to start gvproxy: {e}")))?;

            eprintln!(
                "gvproxy started (pid {}) [{:.1}s]",
                child.id(),
                launch_start.elapsed().as_secs_f64()
            );

            // Wait for the socket to appear (exponential backoff: 5ms → 100ms).
            {
                let deadline = Instant::now() + std::time::Duration::from_secs(5);
                let mut interval = std::time::Duration::from_millis(5);
                while !vfkit_sock.exists() {
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
            const NET_FLAG_VFKIT: u32 = 1 << 0;

            vm.add_net_unixgram(&vfkit_sock, &mac, COMPAT_NET_FEATURES, NET_FLAG_VFKIT)?;

            eprintln!(
                "Networking: gvproxy (virtio-net) [{:.1}s]",
                launch_start.elapsed().as_secs_f64()
            );
            gvproxy_child = Some(child);
            gvproxy_api_sock = Some(api_sock);
        }
    }

    // Port mapping (TSI only)
    if !config.port_map.is_empty() && matches!(config.net, NetBackend::Tsi) {
        vm.set_port_map(&config.port_map)?;
    }

    for vsock_port in &config.vsock_ports {
        vm.add_vsock_port(vsock_port)?;
    }

    // Console output
    let console_log = config.console_output.clone().unwrap_or_else(|| {
        config
            .rootfs
            .parent()
            .unwrap_or(&config.rootfs)
            .join("console.log")
    });
    vm.set_console_output(&console_log)?;

    // envp: use provided env or minimal defaults
    let env: Vec<String> = if config.env.is_empty() {
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
            // service to be reachable. Only for the gateway preset.
            if config.exec_path == "/srv/gateway-init.sh" {
                // Bootstrap stores host-side metadata and mTLS creds.
                // With pre-baked rootfs (Path 1) this reads PKI directly
                // from virtio-fs — no kubectl or port forwarding needed.
                // Cold boot (Path 2) writes secret manifests into the
                // k3s auto-deploy directory via virtio-fs.
                if let Err(e) = bootstrap_gateway(&config.rootfs) {
                    eprintln!("Bootstrap failed: {e}");
                    eprintln!("  The VM is running but OpenShell may not be fully operational.");
                }

                // Wait for the gRPC service to be reachable via TCP
                // probe on host:30051. This confirms the full path
                // (gvproxy → kube-proxy nftables → pod:8080) is working.
                wait_for_gateway_service();

                // Best-effort: copy kubeconfig for manual debugging.
                // Not blocking — the boot pipeline doesn't need it.
                copy_kubeconfig_best_effort(&config.rootfs);
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

            // Clean up gvproxy
            if let Some(mut child) = gvproxy_child {
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

/// Cluster name used for metadata and mTLS storage.
const GATEWAY_CLUSTER_NAME: &str = "gateway";

/// Gateway port: the host port mapped to the OpenShell `NodePort` (30051).
const GATEWAY_PORT: u16 = 30051;

/// Bootstrap the OpenShell control plane after k3s is ready.
///
/// All operations use the virtio-fs rootfs — no kubectl or API server
/// port forwarding required. This avoids exposing port 6443 outside the
/// VM.
///
/// Three paths, in priority order:
///
/// 1. **Pre-baked rootfs** (from `build-rootfs.sh`): PKI files at
///    `rootfs/opt/openshell/pki/`. TLS secrets already exist in the k3s
///    database. Reads certs from the filesystem and stores metadata on the
///    host.
///
/// 2. **Warm boot**: host-side metadata + mTLS certs survive across VM
///    restarts. Nothing to do — service readiness is confirmed by the TCP
///    probe in `wait_for_gateway_service()`.
///
/// 3. **Cold boot**: generates fresh PKI and writes TLS secret manifests
///    into the k3s auto-deploy directory (`/var/lib/rancher/k3s/server/manifests/`)
///    via virtio-fs. k3s picks them up automatically.
fn bootstrap_gateway(rootfs: &Path) -> Result<(), VmError> {
    let bootstrap_start = Instant::now();

    // Build gateway metadata early — it only depends on knowing the port and
    // gateway name, not on the cluster being ready.
    let metadata = openshell_bootstrap::GatewayMetadata {
        name: GATEWAY_CLUSTER_NAME.to_string(),
        gateway_endpoint: format!("https://127.0.0.1:{GATEWAY_PORT}"),
        is_remote: false,
        gateway_port: GATEWAY_PORT,
        remote_host: None,
        resolved_host: None,
        auth_mode: None,
        edge_team_domain: None,
        edge_auth_url: None,
    };

    // ── Path 1: Pre-baked PKI from build-rootfs.sh ─────────────────
    //
    // If the rootfs was pre-initialized, PKI files are baked into
    // /opt/openshell/pki/. Read them directly — no cluster interaction
    // needed. The TLS secrets already exist inside the cluster from
    // the build-time k3s boot.
    let pki_dir = rootfs.join("opt/openshell/pki");
    if pki_dir.join("ca.crt").is_file() {
        eprintln!("Pre-baked PKI detected — fast bootstrap");

        let read = |name: &str| -> Result<String, VmError> {
            std::fs::read_to_string(pki_dir.join(name))
                .map_err(|e| VmError::Bootstrap(format!("failed to read {name}: {e}")))
        };

        let pki_bundle = openshell_bootstrap::pki::PkiBundle {
            ca_cert_pem: read("ca.crt")?,
            ca_key_pem: read("ca.key")?,
            server_cert_pem: read("server.crt")?,
            server_key_pem: read("server.key")?,
            client_cert_pem: read("client.crt")?,
            client_key_pem: read("client.key")?,
        };

        // Store metadata and credentials on the host.
        openshell_bootstrap::store_gateway_metadata(GATEWAY_CLUSTER_NAME, &metadata)
            .map_err(|e| VmError::Bootstrap(format!("failed to store metadata: {e}")))?;

        openshell_bootstrap::mtls::store_pki_bundle(GATEWAY_CLUSTER_NAME, &pki_bundle)
            .map_err(|e| VmError::Bootstrap(format!("failed to store mTLS creds: {e}")))?;

        openshell_bootstrap::save_active_gateway(GATEWAY_CLUSTER_NAME)
            .map_err(|e| VmError::Bootstrap(format!("failed to set active cluster: {e}")))?;

        eprintln!(
            "Bootstrap complete [{:.1}s]",
            bootstrap_start.elapsed().as_secs_f64()
        );
        eprintln!("  Cluster:  {GATEWAY_CLUSTER_NAME}");
        eprintln!("  Gateway:  https://127.0.0.1:{GATEWAY_PORT}");
        eprintln!("  mTLS:     ~/.config/openshell/gateways/{GATEWAY_CLUSTER_NAME}/mtls/");
        return Ok(());
    }

    // ── Path 2: Warm boot ──────────────────────────────────────────
    //
    // Host-side metadata + mTLS certs survive from a previous boot.
    // Service readiness is confirmed by the TCP probe in
    // `wait_for_gateway_service()` — no kubectl needed here.
    if is_warm_boot() {
        eprintln!("Warm boot detected — reusing existing PKI and metadata.");
        eprintln!(
            "Warm boot ready [{:.1}s]",
            bootstrap_start.elapsed().as_secs_f64()
        );
        eprintln!("  Cluster:  {GATEWAY_CLUSTER_NAME}");
        eprintln!("  Gateway:  https://127.0.0.1:{GATEWAY_PORT}");
        eprintln!("  mTLS:     ~/.config/openshell/gateways/{GATEWAY_CLUSTER_NAME}/mtls/");
        return Ok(());
    }

    // ── Path 3: Cold boot (no pre-baked state) ─────────────────────
    //
    // Generate fresh PKI and write TLS secret manifests into the k3s
    // auto-deploy directory via virtio-fs. k3s watches this directory
    // and applies any YAML files automatically.
    eprintln!("Generating TLS certificates...");
    let pki_bundle = openshell_bootstrap::pki::generate_pki(&[])
        .map_err(|e| VmError::Bootstrap(format!("PKI generation failed: {e}")))?;

    openshell_bootstrap::store_gateway_metadata(GATEWAY_CLUSTER_NAME, &metadata)
        .map_err(|e| VmError::Bootstrap(format!("failed to store cluster metadata: {e}")))?;

    // Write TLS secrets as k3s auto-deploy manifests via virtio-fs.
    // k3s watches /var/lib/rancher/k3s/server/manifests/ and applies
    // any YAML files dropped there, eliminating the need for kubectl
    // or API server port forwarding.
    eprintln!("Writing TLS secret manifests via virtio-fs...");
    write_tls_secret_manifests(rootfs, &pki_bundle)?;

    openshell_bootstrap::mtls::store_pki_bundle(GATEWAY_CLUSTER_NAME, &pki_bundle)
        .map_err(|e| VmError::Bootstrap(format!("failed to store mTLS credentials: {e}")))?;

    openshell_bootstrap::save_active_gateway(GATEWAY_CLUSTER_NAME)
        .map_err(|e| VmError::Bootstrap(format!("failed to set active cluster: {e}")))?;

    eprintln!(
        "Bootstrap complete [{:.1}s]",
        bootstrap_start.elapsed().as_secs_f64()
    );
    eprintln!("  Cluster:  {GATEWAY_CLUSTER_NAME}");
    eprintln!("  Gateway:  https://127.0.0.1:{GATEWAY_PORT}");
    eprintln!("  mTLS:     ~/.config/openshell/gateways/{GATEWAY_CLUSTER_NAME}/mtls/");

    Ok(())
}

/// Check whether a previous bootstrap left valid state on disk.
///
/// A warm boot is detected when both:
/// - Cluster metadata exists: `$XDG_CONFIG_HOME/openshell/gateways/gateway/metadata.json`
/// - mTLS certs exist: `$XDG_CONFIG_HOME/openshell/gateways/gateway/mtls/{ca.crt,tls.crt,tls.key}`
///
/// When true, the host-side bootstrap (PKI generation, secret manifest writing,
/// metadata storage) can be skipped because the virtio-fs rootfs persists k3s
/// state (TLS certs, kine/sqlite, containerd images, helm releases) across VM
/// restarts.
fn is_warm_boot() -> bool {
    let Ok(home) = std::env::var("HOME") else {
        return false;
    };

    let config_base =
        std::env::var("XDG_CONFIG_HOME").unwrap_or_else(|_| format!("{home}/.config"));

    let config_dir = PathBuf::from(&config_base)
        .join("openshell")
        .join("gateways");

    // Check metadata file.
    let metadata_path = config_dir.join(GATEWAY_CLUSTER_NAME).join("metadata.json");
    if !metadata_path.is_file() {
        return false;
    }

    // Check mTLS cert files.
    let mtls_dir = config_dir.join(GATEWAY_CLUSTER_NAME).join("mtls");
    for name in &["ca.crt", "tls.crt", "tls.key"] {
        let path = mtls_dir.join(name);
        match std::fs::metadata(&path) {
            Ok(m) if m.is_file() && m.len() > 0 => {}
            _ => return false,
        }
    }

    true
}

/// Wait for the openshell pod to become Ready inside the k3s cluster
/// and verify the gRPC service is reachable from the host.
///
/// Stale pod/lease records are cleaned from the kine DB at build time
/// (see `build-rootfs.sh`). Containerd metadata (meta.db) is preserved
/// across boots so the native snapshotter doesn't re-extract image layers.
/// Runtime task state is cleaned by `gateway-init.sh` on each boot.
///
/// Wait for the OpenShell gRPC service to be reachable from the host.
///
/// Polls `host_tcp_probe()` on `127.0.0.1:30051` with 1s intervals.
/// The probe confirms the full networking path: gvproxy → kube-proxy
/// nftables → pod:8080. A successful probe means the pod is running,
/// the NodePort service is routing, and the server is accepting
/// connections. No kubectl or API server access required.
fn wait_for_gateway_service() {
    let start = Instant::now();
    let timeout = std::time::Duration::from_secs(90);
    let poll_interval = std::time::Duration::from_secs(1);

    eprintln!("Waiting for gateway service...");

    loop {
        if host_tcp_probe() {
            eprintln!("Service healthy [{:.1}s]", start.elapsed().as_secs_f64());
            return;
        }

        if start.elapsed() >= timeout {
            eprintln!(
                "  gateway service not ready after {:.0}s, continuing anyway",
                timeout.as_secs_f64()
            );
            return;
        }

        std::thread::sleep(poll_interval);
    }
}

/// Probe `127.0.0.1:30051` from the host to verify the full
/// gvproxy → VM → pod path is working.
///
/// gvproxy accepts TCP connections even when the guest port is closed,
/// but those connections are immediately reset. A server that is truly
/// listening will hold the connection open (waiting for a TLS
/// ClientHello). We exploit this: connect, then try a short read. If
/// the read **times out** the server is alive; if it returns an error
/// (reset/EOF) the server is down.
fn host_tcp_probe() -> bool {
    use std::io::Read;
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    let addr: SocketAddr = ([127, 0, 0, 1], GATEWAY_PORT).into();
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) else {
        return false;
    };

    // A short read timeout: if the server is alive it will wait for us
    // to send a TLS ClientHello, so the read will time out (= good).
    // If the connection resets or closes, the server is dead.
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .ok();
    let mut buf = [0u8; 1];
    match stream.read(&mut buf) {
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            true // Timeout = server alive, waiting for ClientHello.
        }
        _ => false, // Reset, EOF, or unexpected data = not healthy.
    }
}

/// Write TLS secret manifests into the k3s auto-deploy directory via virtio-fs.
///
/// k3s watches `/var/lib/rancher/k3s/server/manifests/` and automatically
/// applies any YAML files placed there. This avoids the need for kubectl
/// or API server port forwarding from the host.
fn write_tls_secret_manifests(
    rootfs: &Path,
    bundle: &openshell_bootstrap::pki::PkiBundle,
) -> Result<(), VmError> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let manifests_dir = rootfs.join("var/lib/rancher/k3s/server/manifests");
    std::fs::create_dir_all(&manifests_dir)
        .map_err(|e| VmError::Bootstrap(format!("failed to create manifests dir: {e}")))?;

    let server_tls_name = openshell_bootstrap::constants::SERVER_TLS_SECRET_NAME;
    let client_ca_name = openshell_bootstrap::constants::SERVER_CLIENT_CA_SECRET_NAME;
    let client_tls_name = openshell_bootstrap::constants::CLIENT_TLS_SECRET_NAME;

    // Combine all three secrets into a single multi-document YAML file.
    // k3s applies the entire file atomically.
    let manifest = format!(
        r#"---
apiVersion: v1
kind: Namespace
metadata:
  name: openshell
---
apiVersion: v1
kind: Secret
metadata:
  name: {server_tls_name}
  namespace: openshell
type: kubernetes.io/tls
data:
  tls.crt: {server_crt}
  tls.key: {server_key}
---
apiVersion: v1
kind: Secret
metadata:
  name: {client_ca_name}
  namespace: openshell
type: Opaque
data:
  ca.crt: {ca_crt}
---
apiVersion: v1
kind: Secret
metadata:
  name: {client_tls_name}
  namespace: openshell
type: Opaque
data:
  tls.crt: {client_crt}
  tls.key: {client_key}
  ca.crt: {ca_crt}
"#,
        server_crt = STANDARD.encode(&bundle.server_cert_pem),
        server_key = STANDARD.encode(&bundle.server_key_pem),
        ca_crt = STANDARD.encode(&bundle.ca_cert_pem),
        client_crt = STANDARD.encode(&bundle.client_cert_pem),
        client_key = STANDARD.encode(&bundle.client_key_pem),
    );

    let dest = manifests_dir.join("openshell-tls-secrets.yaml");
    std::fs::write(&dest, manifest)
        .map_err(|e| VmError::Bootstrap(format!("failed to write TLS manifest: {e}")))?;

    eprintln!("  TLS secret manifests written to {}", dest.display());
    Ok(())
}

/// Best-effort: copy the k3s kubeconfig to `~/.kube/gateway.yaml` for
/// manual debugging. Not required for the boot pipeline — runs after
/// the service is already confirmed healthy.
fn copy_kubeconfig_best_effort(rootfs: &Path) {
    let kubeconfig_src = rootfs.join("etc/rancher/k3s/k3s.yaml");
    if !kubeconfig_src.is_file() {
        return;
    }

    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let kube_dir = PathBuf::from(&home).join(".kube");
    let _ = std::fs::create_dir_all(&kube_dir);
    let dest = kube_dir.join("gateway.yaml");

    match std::fs::read_to_string(&kubeconfig_src) {
        Ok(contents) => {
            if let Err(e) = std::fs::write(&dest, &contents) {
                eprintln!("  failed to write kubeconfig: {e}");
            } else {
                eprintln!("Kubeconfig: {}", dest.display());
                eprintln!("  export KUBECONFIG={}", dest.display());
            }
        }
        Err(e) => {
            eprintln!("  failed to read kubeconfig: {e}");
        }
    }
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

        write_runtime_file(&dir.join(required_runtime_lib_name()));
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

        let resolved_gvproxy = validate_runtime_dir(&dir).expect("runtime bundle should validate");
        assert_eq!(resolved_gvproxy, gvproxy);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_runtime_dir_requires_gvproxy() {
        let dir = temp_runtime_dir();
        fs::create_dir_all(&dir).expect("failed to create runtime dir");

        write_runtime_file(&dir.join(required_runtime_lib_name()));
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
}
