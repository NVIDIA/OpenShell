// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! libkrun hypervisor backend.
//!
//! Implements [`VmBackend`] using the libkrun C API for lightweight microVMs.
//! This is the original backend — on macOS it uses Hypervisor.framework,
//! on Linux it uses KVM.

use std::ffi::CString;
use std::path::Path;
use std::time::Instant;

use super::{VmBackend, setup_gvproxy_port_forwarding, start_gvproxy};
use crate::exec::{clear_vm_runtime_state, write_vm_runtime_state};
use crate::{
    GvproxyGuard, NetBackend, StateDiskConfig, VmConfig, VmError, VsockPort, bootstrap_gateway,
    c_string_array, check, ffi, gateway_host_port, health, path_to_cstring, vm_rootfs_key,
};

/// libkrun hypervisor backend.
pub struct LibkrunBackend;

impl VmBackend for LibkrunBackend {
    fn launch(&self, config: &VmConfig) -> Result<i32, VmError> {
        launch_libkrun(config)
    }
}

/// VM context wrapping the libkrun FFI context ID.
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
                    crate::clamp_log_level(log_level),
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
                    crate::state_disk_sync_mode(),
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

    #[allow(dead_code)]
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

/// Launch a VM using the libkrun backend.
///
/// This contains the VM-specific configuration, networking, fork/exec,
/// signal forwarding, bootstrap, and cleanup logic that was previously
/// inline in `lib.rs::launch()`.
#[allow(clippy::similar_names)]
fn launch_libkrun(config: &VmConfig) -> Result<i32, VmError> {
    let launch_start = Instant::now();

    let vm = VmContext::create(config.log_level)?;
    vm.set_vm_config(config.vcpus, config.mem_mib)?;
    vm.set_root(&config.rootfs)?;
    if let Some(state_disk) = &config.state_disk {
        vm.add_state_disk(state_disk)?;
    }
    vm.set_workdir(&config.workdir)?;

    let mut gvproxy_guard: Option<GvproxyGuard> = None;
    let mut gvproxy_api_sock: Option<std::path::PathBuf> = None;

    match &config.net {
        NetBackend::Tsi => {}
        NetBackend::None => {
            vm.disable_implicit_vsock()?;
            vm.add_vsock(0)?;
            eprintln!("Networking: disabled (no TSI, no virtio-net)");
        }
        NetBackend::Gvproxy { .. } => {
            let gvproxy_setup = start_gvproxy(config, launch_start)?;

            vm.disable_implicit_vsock()?;
            vm.add_vsock(0)?;
            let mac: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];

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

            #[cfg(target_os = "linux")]
            vm.add_net_unixstream(&gvproxy_setup.net_sock, &mac, COMPAT_NET_FEATURES)?;
            #[cfg(target_os = "macos")]
            {
                const NET_FLAG_VFKIT: u32 = 1 << 0;
                vm.add_net_unixgram(
                    &gvproxy_setup.net_sock,
                    &mac,
                    COMPAT_NET_FEATURES,
                    NET_FLAG_VFKIT,
                )?;
            }

            eprintln!(
                "Networking: gvproxy (virtio-net) [{:.1}s]",
                launch_start.elapsed().as_secs_f64()
            );
            gvproxy_api_sock = Some(gvproxy_setup.api_sock);
            gvproxy_guard = Some(gvproxy_setup.guard);
        }
    }

    if !config.port_map.is_empty() && matches!(config.net, NetBackend::Tsi) {
        vm.set_port_map(&config.port_map)?;
    }

    for vsock_port in &config.vsock_ports {
        if let Some(parent) = vsock_port.socket_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                VmError::RuntimeState(format!("create vsock socket dir {}: {e}", parent.display()))
            })?;
        }
        let _ = std::fs::remove_file(&vsock_port.socket_path);
        vm.add_vsock_port(vsock_port)?;
    }

    let console_log = config.console_output.clone().unwrap_or_else(|| {
        config
            .rootfs
            .parent()
            .unwrap_or(&config.rootfs)
            .join(format!("{}-console.log", vm_rootfs_key(&config.rootfs)))
    });
    vm.set_console_output(&console_log)?;

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
    if config.gpu_enabled {
        env.push("GPU_ENABLED=true".to_string());
    }
    vm.set_exec(&config.exec_path, &config.args, &env)?;

    // Fork and enter the VM
    let boot_start = Instant::now();
    eprintln!("Booting microVM...");

    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(VmError::Fork(std::io::Error::last_os_error().to_string())),
        0 => {
            let ret = vm.start_enter();
            eprintln!("krun_start_enter failed: {ret}");
            std::process::exit(1);
        }
        _ => {
            if config.exec_path == "/srv/openshell-vm-init.sh" {
                let gvproxy_pid = gvproxy_guard.as_ref().and_then(GvproxyGuard::id);
                if let Err(err) =
                    write_vm_runtime_state(&config.rootfs, pid, &console_log, gvproxy_pid, false)
                {
                    unsafe {
                        libc::kill(pid, libc::SIGTERM);
                    }
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

            if let Some(ref api_sock) = gvproxy_api_sock {
                setup_gvproxy_port_forwarding(api_sock, &config.port_map)?;
            }

            if config.exec_path == "/srv/openshell-vm-init.sh" && !config.port_map.is_empty() {
                let gateway_port = gateway_host_port(config);
                bootstrap_gateway(&config.rootfs, &config.gateway_name, gateway_port)?;
                health::wait_for_gateway_ready(gateway_port, &config.gateway_name)?;
            }

            eprintln!("Ready [{:.1}s total]", boot_start.elapsed().as_secs_f64());
            eprintln!("Press Ctrl+C to stop.");

            unsafe {
                libc::signal(
                    libc::SIGINT,
                    crate::forward_signal as *const () as libc::sighandler_t,
                );
                libc::signal(
                    libc::SIGTERM,
                    crate::forward_signal as *const () as libc::sighandler_t,
                );
                crate::CHILD_PID.store(pid, std::sync::atomic::Ordering::Relaxed);
            }

            let mut status: libc::c_int = 0;
            unsafe {
                libc::waitpid(pid, &raw mut status, 0);
            }

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
