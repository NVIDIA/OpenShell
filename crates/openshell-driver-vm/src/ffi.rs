// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Minimal runtime-loaded bindings for the libkrun C API used by the VM driver.

#![allow(unsafe_code)]

use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use libc::c_char;
use libloading::Library;

use crate::runtime::validate_runtime_dir;

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
type KrunSetConsoleOutput = unsafe extern "C" fn(ctx_id: u32, filepath: *const c_char) -> i32;
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

pub struct LibKrun {
    pub krun_init_log: KrunInitLog,
    pub krun_create_ctx: KrunCreateCtx,
    pub krun_free_ctx: KrunFreeCtx,
    pub krun_set_vm_config: KrunSetVmConfig,
    pub krun_set_root: KrunSetRoot,
    pub krun_set_workdir: KrunSetWorkdir,
    pub krun_set_exec: KrunSetExec,
    pub krun_set_console_output: KrunSetConsoleOutput,
    pub krun_start_enter: KrunStartEnter,
    pub krun_disable_implicit_vsock: KrunDisableImplicitVsock,
    pub krun_add_vsock: KrunAddVsock,
    #[cfg(target_os = "macos")]
    pub krun_add_net_unixgram: KrunAddNetUnixgram,
    #[allow(dead_code)] // Used on Linux when gvproxy runs in qemu/unixstream mode.
    pub krun_add_net_unixstream: KrunAddNetUnixstream,
}

static LIBKRUN: OnceLock<LibKrun> = OnceLock::new();

pub fn libkrun(runtime_dir: &Path) -> Result<&'static LibKrun, String> {
    if let Some(lib) = LIBKRUN.get() {
        return Ok(lib);
    }

    validate_runtime_dir(runtime_dir)?;
    let loaded = LibKrun::load(runtime_dir)?;
    let _ = LIBKRUN.set(loaded);
    Ok(LIBKRUN.get().expect("libkrun should be initialized"))
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

impl LibKrun {
    fn load(runtime_dir: &Path) -> Result<Self, String> {
        let libkrun_path = runtime_dir.join(required_runtime_lib_name());
        preload_runtime_support_libraries(runtime_dir)?;

        let library = Box::leak(Box::new(unsafe {
            Library::new(&libkrun_path)
                .map_err(|e| format!("load libkrun from {}: {e}", libkrun_path.display()))?
        }));

        Ok(Self {
            krun_init_log: load_symbol(library, b"krun_init_log\0", &libkrun_path)?,
            krun_create_ctx: load_symbol(library, b"krun_create_ctx\0", &libkrun_path)?,
            krun_free_ctx: load_symbol(library, b"krun_free_ctx\0", &libkrun_path)?,
            krun_set_vm_config: load_symbol(library, b"krun_set_vm_config\0", &libkrun_path)?,
            krun_set_root: load_symbol(library, b"krun_set_root\0", &libkrun_path)?,
            krun_set_workdir: load_symbol(library, b"krun_set_workdir\0", &libkrun_path)?,
            krun_set_exec: load_symbol(library, b"krun_set_exec\0", &libkrun_path)?,
            krun_set_console_output: load_symbol(
                library,
                b"krun_set_console_output\0",
                &libkrun_path,
            )?,
            krun_start_enter: load_symbol(library, b"krun_start_enter\0", &libkrun_path)?,
            krun_disable_implicit_vsock: load_symbol(
                library,
                b"krun_disable_implicit_vsock\0",
                &libkrun_path,
            )?,
            krun_add_vsock: load_symbol(library, b"krun_add_vsock\0", &libkrun_path)?,
            #[cfg(target_os = "macos")]
            krun_add_net_unixgram: load_symbol(library, b"krun_add_net_unixgram\0", &libkrun_path)?,
            krun_add_net_unixstream: load_symbol(
                library,
                b"krun_add_net_unixstream\0",
                &libkrun_path,
            )?,
        })
    }
}

fn preload_runtime_support_libraries(runtime_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = std::fs::read_dir(runtime_dir)
        .map_err(|e| format!("read {}: {e}", runtime_dir.display()))?;

    let mut support_libs: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    #[cfg(target_os = "macos")]
                    {
                        name.starts_with("libkrunfw") && name.ends_with(".dylib")
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
        let path_cstr = CString::new(path.to_string_lossy().as_bytes())
            .map_err(|e| format!("invalid support library path {}: {e}", path.display()))?;
        let handle =
            unsafe { libc::dlopen(path_cstr.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL) };
        if handle.is_null() {
            let error = unsafe {
                let err = libc::dlerror();
                if err.is_null() {
                    "unknown dlopen error".to_string()
                } else {
                    CStr::from_ptr(err).to_string_lossy().into_owned()
                }
            };
            return Err(format!(
                "preload runtime support library {}: {error}",
                path.display()
            ));
        }
    }

    Ok(support_libs)
}

fn load_symbol<T: Copy>(library: &'static Library, name: &[u8], path: &Path) -> Result<T, String> {
    unsafe {
        library.get::<T>(name).map(|symbol| *symbol).map_err(|e| {
            format!(
                "load symbol {} from {}: {e}",
                String::from_utf8_lossy(name).trim_end_matches('\0'),
                path.display()
            )
        })
    }
}
