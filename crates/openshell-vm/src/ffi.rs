// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Minimal runtime-loaded bindings for the libkrun C API.
//!
//! We intentionally do not link libkrun at build time. Instead, the
//! `gateway` binary loads `libkrun` from the staged `gateway.runtime/`
//! sidecar bundle on first use.

use std::path::PathBuf;
use std::sync::OnceLock;

use libc::c_char;
use libloading::Library;

use crate::VmError;

pub const KRUN_LOG_TARGET_DEFAULT: i32 = -1;
pub const KRUN_LOG_LEVEL_OFF: u32 = 0;
pub const KRUN_LOG_LEVEL_ERROR: u32 = 1;
pub const KRUN_LOG_LEVEL_WARN: u32 = 2;
pub const KRUN_LOG_LEVEL_INFO: u32 = 3;
pub const KRUN_LOG_LEVEL_DEBUG: u32 = 4;
pub const KRUN_LOG_LEVEL_TRACE: u32 = 5;
pub const KRUN_LOG_STYLE_AUTO: u32 = 0;
pub const KRUN_LOG_OPTION_NO_ENV: u32 = 1;

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
type KrunAddVsockPort2 =
    unsafe extern "C" fn(ctx_id: u32, port: u32, c_filepath: *const c_char, listen: bool) -> i32;
type KrunStartEnter = unsafe extern "C" fn(ctx_id: u32) -> i32;
type KrunDisableImplicitVsock = unsafe extern "C" fn(ctx_id: u32) -> i32;
type KrunAddVsock = unsafe extern "C" fn(ctx_id: u32, tsi_features: u32) -> i32;
type KrunAddNetUnixgram = unsafe extern "C" fn(
    ctx_id: u32,
    c_path: *const c_char,
    fd: i32,
    c_mac: *const u8,
    features: u32,
    flags: u32,
) -> i32;

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
    pub krun_add_vsock_port2: KrunAddVsockPort2,
    pub krun_start_enter: KrunStartEnter,
    pub krun_disable_implicit_vsock: KrunDisableImplicitVsock,
    pub krun_add_vsock: KrunAddVsock,
    pub krun_add_net_unixgram: KrunAddNetUnixgram,
}

static LIBKRUN: OnceLock<LibKrun> = OnceLock::new();

pub fn libkrun() -> Result<&'static LibKrun, VmError> {
    if let Some(lib) = LIBKRUN.get() {
        return Ok(lib);
    }

    let loaded = LibKrun::load()?;
    let _ = LIBKRUN.set(loaded);
    Ok(LIBKRUN.get().expect("libkrun should be initialized"))
}

impl LibKrun {
    fn load() -> Result<Self, VmError> {
        let path = runtime_libkrun_path()?;
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
            krun_add_vsock_port2: load_symbol(library, b"krun_add_vsock_port2\0", &path)?,
            krun_start_enter: load_symbol(library, b"krun_start_enter\0", &path)?,
            krun_disable_implicit_vsock: load_symbol(
                library,
                b"krun_disable_implicit_vsock\0",
                &path,
            )?,
            krun_add_vsock: load_symbol(library, b"krun_add_vsock\0", &path)?,
            krun_add_net_unixgram: load_symbol(library, b"krun_add_net_unixgram\0", &path)?,
        })
    }
}

fn runtime_libkrun_path() -> Result<PathBuf, VmError> {
    Ok(crate::configured_runtime_dir()?.join(required_runtime_lib_name()))
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

fn load_symbol<T: Copy>(
    library: &'static Library,
    symbol: &[u8],
    path: &std::path::Path,
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
