// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Minimal runtime-loaded bindings for the libkrun C API.
//!
//! We intentionally do not link libkrun at build time. Instead, the
//! `openshell-vm` binary loads `libkrun` from the staged `openshell-vm.runtime/`
//! sidecar bundle on first use.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use libc::c_char;
use libloading::Library;

use crate::VmError;

/// Runtime provenance information extracted from the bundle.
#[derive(Debug, Clone)]
pub struct RuntimeProvenance {
    /// Path to the libkrun library that was loaded.
    pub libkrun_path: PathBuf,
    /// Paths to all libkrunfw libraries that were preloaded.
    pub libkrunfw_paths: Vec<PathBuf>,
    /// SHA-256 hash of the primary libkrunfw artifact (if computable).
    pub libkrunfw_sha256: Option<String>,
    /// Contents of provenance.json if present in the runtime bundle.
    pub provenance_json: Option<String>,
    /// Whether this is a custom (OpenShell-built) runtime.
    pub is_custom: bool,
}

pub const KRUN_LOG_TARGET_DEFAULT: i32 = -1;
pub const KRUN_LOG_LEVEL_OFF: u32 = 0;
pub const KRUN_LOG_LEVEL_ERROR: u32 = 1;
pub const KRUN_LOG_LEVEL_WARN: u32 = 2;
pub const KRUN_LOG_LEVEL_INFO: u32 = 3;
pub const KRUN_LOG_LEVEL_DEBUG: u32 = 4;
pub const KRUN_LOG_LEVEL_TRACE: u32 = 5;
pub const KRUN_LOG_STYLE_AUTO: u32 = 0;
pub const KRUN_LOG_OPTION_NO_ENV: u32 = 1;
pub const KRUN_DISK_FORMAT_RAW: u32 = 0;
#[allow(dead_code)] // Used only on macOS (cfg-gated in state_disk_sync_mode)
pub const KRUN_SYNC_RELAXED: u32 = 1;
#[allow(dead_code)] // Used only on Linux (cfg-gated in state_disk_sync_mode)
pub const KRUN_SYNC_FULL: u32 = 2;

type KrunInitLog =
    unsafe extern "C" fn(target_fd: i32, level: u32, style: u32, options: u32) -> i32;
type KrunCreateCtx = unsafe extern "C" fn() -> i32;
type KrunFreeCtx = unsafe extern "C" fn(ctx_id: u32) -> i32;
type KrunSetVmConfig = unsafe extern "C" fn(ctx_id: u32, num_vcpus: u8, ram_mib: u32) -> i32;
type KrunSetRoot = unsafe extern "C" fn(ctx_id: u32, root_path: *const c_char) -> i32;
type KrunSetWorkdir = unsafe extern "C" fn(ctx_id: u32, workdir_path: *const c_char) -> i32;
type KrunSetExec = unsafe extern "C" fn(
    ctx_id: u32,
    exec_path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> i32;
type KrunSetPortMap = unsafe extern "C" fn(ctx_id: u32, port_map: *const *const c_char) -> i32;
type KrunSetConsoleOutput = unsafe extern "C" fn(ctx_id: u32, filepath: *const c_char) -> i32;
type KrunAddDisk3 = unsafe extern "C" fn(
    ctx_id: u32,
    block_id: *const c_char,
    disk_path: *const c_char,
    disk_format: u32,
    read_only: bool,
    direct_io: bool,
    sync_mode: u32,
) -> i32;
type KrunAddVsockPort2 =
    unsafe extern "C" fn(ctx_id: u32, port: u32, c_filepath: *const c_char, listen: bool) -> i32;
type KrunStartEnter = unsafe extern "C" fn(ctx_id: u32) -> i32;
type KrunDisableImplicitVsock = unsafe extern "C" fn(ctx_id: u32) -> i32;
type KrunAddVsock = unsafe extern "C" fn(ctx_id: u32, tsi_features: u32) -> i32;
#[cfg(target_os = "macos")]
type KrunAddNetUnixgram = unsafe extern "C" fn(
    ctx_id: u32,
    c_path: *const c_char,
    fd: i32,
    c_mac: *const u8,
    features: u32,
    flags: u32,
) -> i32;
type KrunAddNetUnixstream = unsafe extern "C" fn(
    ctx_id: u32,
    c_path: *const c_char,
    fd: i32,
    c_mac: *const u8,
    features: u32,
    flags: u32,
) -> i32;

#[allow(clippy::struct_field_names)] // FFI struct mirrors libkrun's symbol naming
pub struct LibKrun {
    pub krun_init_log: KrunInitLog,
    pub krun_create_ctx: KrunCreateCtx,
    pub krun_free_ctx: KrunFreeCtx,
    pub krun_set_vm_config: KrunSetVmConfig,
    pub krun_set_root: KrunSetRoot,
    pub krun_set_workdir: KrunSetWorkdir,
    pub krun_set_exec: KrunSetExec,
    pub krun_set_port_map: KrunSetPortMap,
    pub krun_set_console_output: KrunSetConsoleOutput,
    pub krun_add_disk3: Option<KrunAddDisk3>,
    pub krun_add_vsock_port2: KrunAddVsockPort2,
    pub krun_start_enter: KrunStartEnter,
    pub krun_disable_implicit_vsock: KrunDisableImplicitVsock,
    pub krun_add_vsock: KrunAddVsock,
    #[cfg(target_os = "macos")]
    pub krun_add_net_unixgram: KrunAddNetUnixgram,
    #[allow(dead_code)] // FFI symbol loaded for future use
    pub krun_add_net_unixstream: KrunAddNetUnixstream,
}

static LIBKRUN: OnceLock<LibKrun> = OnceLock::new();
static RUNTIME_PROVENANCE: OnceLock<RuntimeProvenance> = OnceLock::new();

pub fn libkrun() -> Result<&'static LibKrun, VmError> {
    if let Some(lib) = LIBKRUN.get() {
        return Ok(lib);
    }

    let loaded = LibKrun::load()?;
    let _ = LIBKRUN.set(loaded);
    Ok(LIBKRUN.get().expect("libkrun should be initialized"))
}

/// Return the provenance information for the loaded runtime.
///
/// Only available after [`libkrun()`] has been called successfully.
pub fn runtime_provenance() -> Option<&'static RuntimeProvenance> {
    RUNTIME_PROVENANCE.get()
}

impl LibKrun {
    fn load() -> Result<Self, VmError> {
        let path = runtime_libkrun_path()?;
        let runtime_dir = path.parent().ok_or_else(|| {
            VmError::HostSetup(format!("libkrun has no parent dir: {}", path.display()))
        })?;
        let krunfw_paths = preload_runtime_support_libraries(runtime_dir)?;

        // Build and store provenance information.
        let provenance_json_path = runtime_dir.join("provenance.json");
        let provenance_json = fs::read_to_string(&provenance_json_path).ok();
        let is_custom = provenance_json.is_some();

        let libkrunfw_sha256 = krunfw_paths.first().and_then(|p| compute_sha256(p).ok());

        let provenance = RuntimeProvenance {
            libkrun_path: path.clone(),
            libkrunfw_paths: krunfw_paths,
            libkrunfw_sha256,
            provenance_json,
            is_custom,
        };
        let _ = RUNTIME_PROVENANCE.set(provenance);

        let library = Box::leak(Box::new(unsafe {
            Library::new(&path).map_err(|e| {
                VmError::HostSetup(format!("load libkrun from {}: {e}", path.display()))
            })?
        }));

        Ok(Self {
            krun_init_log: load_symbol(library, b"krun_init_log\0", &path)?,
            krun_create_ctx: load_symbol(library, b"krun_create_ctx\0", &path)?,
            krun_free_ctx: load_symbol(library, b"krun_free_ctx\0", &path)?,
            krun_set_vm_config: load_symbol(library, b"krun_set_vm_config\0", &path)?,
            krun_set_root: load_symbol(library, b"krun_set_root\0", &path)?,
            krun_set_workdir: load_symbol(library, b"krun_set_workdir\0", &path)?,
            krun_set_exec: load_symbol(library, b"krun_set_exec\0", &path)?,
            krun_set_port_map: load_symbol(library, b"krun_set_port_map\0", &path)?,
            krun_set_console_output: load_symbol(library, b"krun_set_console_output\0", &path)?,
            krun_add_disk3: load_optional_symbol(library, b"krun_add_disk3\0"),
            krun_add_vsock_port2: load_symbol(library, b"krun_add_vsock_port2\0", &path)?,
            krun_start_enter: load_symbol(library, b"krun_start_enter\0", &path)?,
            krun_disable_implicit_vsock: load_symbol(
                library,
                b"krun_disable_implicit_vsock\0",
                &path,
            )?,
            krun_add_vsock: load_symbol(library, b"krun_add_vsock\0", &path)?,
            #[cfg(target_os = "macos")]
            krun_add_net_unixgram: load_symbol(library, b"krun_add_net_unixgram\0", &path)?,
            krun_add_net_unixstream: load_symbol(library, b"krun_add_net_unixstream\0", &path)?,
        })
    }
}

fn runtime_libkrun_path() -> Result<PathBuf, VmError> {
    Ok(crate::configured_runtime_dir()?.join(required_runtime_lib_name()))
}

fn preload_runtime_support_libraries(runtime_dir: &Path) -> Result<Vec<PathBuf>, VmError> {
    let entries = fs::read_dir(runtime_dir)
        .map_err(|e| VmError::HostSetup(format!("read {}: {e}", runtime_dir.display())))?;

    let mut support_libs: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    #[cfg(target_os = "macos")]
                    {
                        name.starts_with("libkrunfw")
                            && Path::new(name)
                                .extension()
                                .is_some_and(|ext| ext.eq_ignore_ascii_case("dylib"))
                    }
                    #[cfg(not(target_os = "macos"))]
                    {
                        name.starts_with("libkrunfw") && name.contains(".so")
                    }
                })
        })
        .collect();

    support_libs.sort();

    for path in &support_libs {
        let path_cstr = std::ffi::CString::new(path.to_string_lossy().as_bytes()).map_err(|e| {
            VmError::HostSetup(format!(
                "invalid support library path {}: {e}",
                path.display()
            ))
        })?;
        let handle =
            unsafe { libc::dlopen(path_cstr.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL) };
        if handle.is_null() {
            let error = unsafe {
                let err = libc::dlerror();
                if err.is_null() {
                    "unknown dlopen error".to_string()
                } else {
                    std::ffi::CStr::from_ptr(err).to_string_lossy().into_owned()
                }
            };
            return Err(VmError::HostSetup(format!(
                "preload runtime support library {}: {error}",
                path.display()
            )));
        }
    }

    Ok(support_libs)
}

pub fn required_runtime_lib_name() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "libkrun.dylib"
    }
    #[cfg(not(target_os = "macos"))]
    {
        "libkrun.so"
    }
}

/// Compute SHA-256 hash of a file, returning hex string.
///
/// Streams the file contents directly to `shasum -a 256` via a pipe,
/// avoiding buffering the entire file in memory.
fn compute_sha256(path: &Path) -> Result<String, std::io::Error> {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    let mut file = fs::File::open(path)?;

    // sha256sum is standard on Linux; shasum ships with macOS/Perl.
    let mut child = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .or_else(|_| {
            Command::new("shasum")
                .args(["-a", "256"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
        })?;

    // Stream file contents directly to shasum's stdin in 8KB chunks.
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("failed to open shasum stdin"))?;
        let mut buf = [0u8; 8192];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            stdin.write_all(&buf[..n])?;
        }
        // stdin is dropped here, closing the pipe so shasum can finish.
    }

    let output = child.wait_with_output()?;
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout
            .split_whitespace()
            .next()
            .unwrap_or("unknown")
            .to_string())
    } else {
        Ok("unknown".to_string())
    }
}

fn load_symbol<T: Copy>(
    library: &'static Library,
    symbol: &[u8],
    path: &Path,
) -> Result<T, VmError> {
    let loaded = unsafe {
        library.get::<T>(symbol).map_err(|e| {
            VmError::HostSetup(format!(
                "resolve {} from {}: {e}",
                String::from_utf8_lossy(symbol).trim_end_matches('\0'),
                path.display()
            ))
        })?
    };
    Ok(*loaded)
}

fn load_optional_symbol<T: Copy>(library: &'static Library, symbol: &[u8]) -> Option<T> {
    let loaded = unsafe { library.get::<T>(symbol).ok()? };
    Some(*loaded)
}
