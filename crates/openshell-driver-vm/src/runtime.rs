// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(unsafe_code)]

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};
use std::ptr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

use crate::{embedded_runtime, ffi, procguard, rootfs};

pub const VM_RUNTIME_DIR_ENV: &str = "OPENSHELL_VM_RUNTIME_DIR";
const KRUN_INIT_PID1_ENV: &str = "KRUN_INIT_PID1=1";

/// PID of the VM worker process (libkrun fork or QEMU). Zero when not running.
/// Used by the SIGTERM/SIGINT handler to forward signals to the VM.
static CHILD_PID: AtomicI32 = AtomicI32::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmBackend {
    Libkrun,
    Qemu,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VsockPortMap {
    pub guest_port: u32,
    pub host_socket: PathBuf,
    pub host_initiated: bool,
}

pub struct VmLaunchConfig {
    pub root_disk: PathBuf,
    pub overlay_disk: PathBuf,
    pub image_disk: Option<PathBuf>,
    pub kernel_image: Option<PathBuf>,
    pub vcpus: u8,
    pub mem_mib: u32,
    pub exec_path: String,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub workdir: String,
    pub log_level: u32,
    pub console_output: PathBuf,
    pub backend: VmBackend,
    pub gpu_bdf: Option<String>,
    pub vsock_cid: Option<u32>,
    pub vsock_port_map: Option<VsockPortMap>,
}

pub fn run_vm(config: &VmLaunchConfig) -> Result<(), String> {
    match config.backend {
        VmBackend::Qemu => run_qemu_vm(config),
        VmBackend::Libkrun => run_libkrun_vm(config),
    }
}

fn run_qemu_vm(config: &VmLaunchConfig) -> Result<(), String> {
    let gpu_bdf = config
        .gpu_bdf
        .as_deref()
        .ok_or("gpu_bdf is required for QEMU backend")?;
    let vsock_cid = config
        .vsock_cid
        .ok_or("vsock_cid is required for QEMU backend")?;

    if !config.root_disk.is_file() {
        return Err(format!(
            "root disk image not found: {}",
            config.root_disk.display()
        ));
    }
    if !config.overlay_disk.is_file() {
        return Err(format!(
            "overlay disk image not found: {}",
            config.overlay_disk.display()
        ));
    }
    if let Some(image_disk) = &config.image_disk
        && !image_disk.is_file()
    {
        return Err(format!("image disk not found: {}", image_disk.display()));
    }

    if let Err(err) = procguard::die_with_parent_cleanup(procguard_kill_children) {
        return Err(format!("procguard arm failed: {err}"));
    }

    #[cfg(target_os = "linux")]
    check_kvm_access()?;

    let guest_env = qemu_guest_env_vars(config);
    write_guest_env_file(&config.overlay_disk, &guest_env)?;

    let vmlinux = if let Some(kernel_image) = &config.kernel_image {
        kernel_image.clone()
    } else {
        qemu_runtime_dir()?.join("vmlinux")
    };
    if !vmlinux.is_file() {
        return Err(format!("VM kernel not found: {}", vmlinux.display()));
    }

    let kernel_cmdline = build_kernel_cmdline(config);

    let mut qemu_cmd = StdCommand::new("qemu-system-x86_64");
    qemu_cmd
        .arg("-machine")
        .arg("q35,accel=kvm")
        .arg("-cpu")
        .arg("host")
        .arg("-smp")
        .arg(config.vcpus.to_string())
        .arg("-m")
        .arg(format!("{}M", config.mem_mib))
        .arg("-nographic")
        .arg("-no-reboot")
        .args(qemu_network_args())
        .arg("-kernel")
        .arg(&vmlinux)
        .arg("-append")
        .arg(&kernel_cmdline)
        .args(qemu_disk_args(config))
        .arg("-device")
        .arg("pcie-root-port,id=vsock_root,slot=1")
        .arg("-device")
        .arg(format!(
            "vhost-vsock-pci,guest-cid={vsock_cid},bus=vsock_root"
        ))
        .arg("-device")
        .arg("pcie-root-port,id=gpu_root,slot=2")
        .arg("-device")
        .arg(format!("vfio-pci,host={gpu_bdf},bus=gpu_root"))
        .arg("-serial")
        .arg(format!("file:{}", config.console_output.display()));

    qemu_cmd.stdin(Stdio::null());
    qemu_cmd.stdout(Stdio::inherit());
    qemu_cmd.stderr(Stdio::inherit());

    #[cfg(target_os = "linux")]
    {
        use nix::sys::signal::Signal;
        use std::os::unix::process::CommandExt as _;
        unsafe {
            qemu_cmd.pre_exec(|| {
                nix::sys::prctl::set_pdeathsig(Signal::SIGKILL)
                    .map_err(|err| std::io::Error::other(format!("pdeathsig: {err}")))
            });
        }
    }

    let mut qemu_child = qemu_cmd
        .spawn()
        .map_err(|e| format!("failed to start QEMU: {e}"))?;

    let qemu_pid = qemu_child.id().cast_signed();
    install_signal_forwarding(qemu_pid);

    let status = qemu_child
        .wait()
        .map_err(|e| format!("failed to wait for QEMU: {e}"))?;

    CHILD_PID.store(0, Ordering::Relaxed);

    if status.success() {
        Ok(())
    } else {
        Err(format!("QEMU exited with status {status}"))
    }
}

fn qemu_network_args() -> [&'static str; 2] {
    ["-nic", "none"]
}

fn qemu_disk_args(config: &VmLaunchConfig) -> Vec<String> {
    let mut args = vec![
        "-drive".to_string(),
        format!(
            "file={},if=none,format=raw,id=rootfs,readonly=on",
            config.root_disk.display()
        ),
        "-device".to_string(),
        "virtio-blk-pci,drive=rootfs".to_string(),
        "-drive".to_string(),
        format!(
            "file={},if=none,format=raw,id=overlay",
            config.overlay_disk.display()
        ),
        "-device".to_string(),
        "virtio-blk-pci,drive=overlay".to_string(),
    ];
    if let Some(image_disk) = &config.image_disk {
        args.extend([
            "-drive".to_string(),
            format!(
                "file={},if=none,format=raw,id=image,readonly=on",
                image_disk.display()
            ),
            "-device".to_string(),
            "virtio-blk-pci,drive=image".to_string(),
        ]);
    }
    args
}

/// Write environment variables into the overlay disk so the guest init script
/// can source them after the overlay root is mounted. QEMU does not provide a
/// `krun_set_exec` equivalent, so the launcher injects this small per-sandbox
/// file into the overlay upperdir before boot.
fn write_guest_env_file(overlay_disk: &Path, env_vars: &[String]) -> Result<(), String> {
    let mut content = String::new();
    for var in env_vars {
        if let Some((key, value)) = var.split_once('=') {
            use std::fmt::Write as _;
            let _ = writeln!(content, "export {key}=\"{}\"", shell_escape(value));
        }
    }
    rootfs::write_rootfs_image_file(
        overlay_disk,
        "/upper/srv/openshell-env.sh",
        content.as_bytes(),
    )
}

fn qemu_guest_env_vars(config: &VmLaunchConfig) -> Vec<String> {
    let mut env_vars = config.env.clone();
    if config.gpu_bdf.is_some() {
        env_vars.push("GPU_ENABLED=true".to_string());
    }

    env_vars
}

/// Escape a string for use inside bash double quotes.
fn shell_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('$', "\\$")
        .replace('`', "\\`")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn build_kernel_cmdline(config: &VmLaunchConfig) -> String {
    let mut parts = vec![
        "console=ttyS0".to_string(),
        "root=/dev/vda".to_string(),
        "rootfstype=ext4".to_string(),
        "ro".to_string(),
        "panic=-1".to_string(),
        format!("init={}", config.exec_path),
    ];

    if config.gpu_bdf.is_some() {
        parts.push("firmware_class.path=/lib/firmware".to_string());
    }

    parts.join(" ")
}

/// Shared procguard cleanup callback for both libkrun and QEMU paths.
/// Only async-signal-safe calls: atomic loads and `kill(2)`.
fn procguard_kill_children() {
    let child_pid = CHILD_PID.load(Ordering::Relaxed);
    if child_pid > 0 {
        unsafe {
            libc::kill(child_pid, libc::SIGTERM);
        }
    }
    std::thread::sleep(Duration::from_millis(200));
    if child_pid > 0 {
        unsafe {
            libc::kill(child_pid, libc::SIGKILL);
        }
    }
}

fn run_libkrun_vm(config: &VmLaunchConfig) -> Result<(), String> {
    if let Some(kernel_image) = &config.kernel_image {
        return Err(format!(
            "selected kernel image is not supported by this VM backend: {}",
            kernel_image.display()
        ));
    }
    if !config.root_disk.is_file() {
        return Err(format!(
            "root disk image not found: {}",
            config.root_disk.display()
        ));
    }
    if !config.overlay_disk.is_file() {
        return Err(format!(
            "overlay disk image not found: {}",
            config.overlay_disk.display()
        ));
    }
    if let Some(image_disk) = &config.image_disk
        && !image_disk.is_file()
    {
        return Err(format!("image disk not found: {}", image_disk.display()));
    }

    // Arm procguard before forking libkrun so the VM worker cannot outlive
    // the launcher. No network helper is started: the only host/guest data
    // path is the protected vsock mapping below.
    if let Err(err) = procguard::die_with_parent_cleanup(procguard_kill_children) {
        return Err(format!("procguard arm failed: {err}"));
    }

    #[cfg(target_os = "linux")]
    check_kvm_access()?;

    let runtime_dir = configured_runtime_dir()?;
    validate_runtime_dir(&runtime_dir)?;
    configure_runtime_loader_env(&runtime_dir)?;
    raise_nofile_limit();

    let vm = VmContext::create(&runtime_dir, config.log_level)?;
    vm.set_vm_config(config.vcpus, config.mem_mib)?;
    vm.set_disks(
        &config.root_disk,
        &config.overlay_disk,
        config.image_disk.as_deref(),
    )?;
    vm.set_workdir(&config.workdir)?;

    vm.disable_implicit_vsock()?;
    vm.add_vsock(0)?;
    if let Some(port_map) = &config.vsock_port_map {
        let _ = std::fs::remove_file(&port_map.host_socket);
        vm.add_vsock_port(port_map)?;
    }

    vm.set_console_output(&config.console_output)?;

    let env = libkrun_guest_env(config);
    vm.set_exec(&config.exec_path, &config.args, &env)?;

    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(format!("fork failed: {}", std::io::Error::last_os_error())),
        0 => {
            // We are the libkrun worker (the VM's PID 1 inside the guest
            // kernel, but a normal host process until krun_start_enter
            // fires). Arm procguard so this fork is SIGKILLed if the
            // parent launcher dies abruptly. On Linux this uses
            // `PR_SET_PDEATHSIG`; on macOS this spawns a kqueue
            // NOTE_EXIT watcher thread.
            //
            // We also SIGKILL ourselves if arming fails — there's no
            // safe way to continue if we can't guarantee cleanup.
            if let Err(err) = procguard::die_with_parent() {
                eprintln!("libkrun worker: procguard arm failed: {err}");
                std::process::exit(1);
            }
            let ret = vm.start_enter();
            eprintln!("krun_start_enter failed: {ret}");
            std::process::exit(1);
        }
        _ => {
            install_signal_forwarding(pid);

            let status = wait_for_child(pid)?;
            CHILD_PID.store(0, Ordering::Relaxed);
            if libc::WIFEXITED(status) {
                match libc::WEXITSTATUS(status) {
                    0 => Ok(()),
                    code => Err(format!("VM exited with status {code}")),
                }
            } else if libc::WIFSIGNALED(status) {
                let sig = libc::WTERMSIG(status);
                Err(format!("VM killed by signal {sig}"))
            } else {
                Err(format!("VM exited with unexpected wait status {status}"))
            }
        }
    }
}

fn libkrun_guest_env(config: &VmLaunchConfig) -> Vec<String> {
    let mut env = if config.env.is_empty() {
        vec![
            "HOME=/root".to_string(),
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            "TERM=xterm".to_string(),
        ]
    } else {
        config.env.clone()
    };

    // libkrun normally keeps /init.krun as PID 1 and forks the configured
    // executable. OpenShell's guest init is itself an init process and ends
    // by exec'ing the supervisor, so ask libkrun to exec it directly. Keep
    // this driver-owned setting authoritative over sandbox image/user env.
    env.retain(|value| !value.starts_with("KRUN_INIT_PID1="));
    env.push(KRUN_INIT_PID1_ENV.to_string());
    env
}

pub fn validate_runtime_dir(dir: &Path) -> Result<(), String> {
    if !dir.is_dir() {
        return Err(format!(
            "VM runtime not found at {}. Run `mise run vm:setup` or set {VM_RUNTIME_DIR_ENV}",
            dir.display()
        ));
    }

    embedded_runtime::validate_runtime_dir(dir)
}

pub fn configured_runtime_dir() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os(VM_RUNTIME_DIR_ENV) {
        return Ok(PathBuf::from(path));
    }
    embedded_runtime::ensure_runtime_extracted()
}

fn qemu_runtime_dir() -> Result<PathBuf, String> {
    configured_runtime_dir().map_err(|_| {
        "QEMU backend requires OPENSHELL_VM_RUNTIME_DIR to be set (pointing to a directory \
         containing vmlinux). Set the env var or run `mise run vm:setup`."
            .to_string()
    })
}

#[cfg(target_os = "macos")]
fn configure_runtime_loader_env(runtime_dir: &Path) -> Result<(), String> {
    let existing = std::env::var_os("DYLD_FALLBACK_LIBRARY_PATH");
    let mut paths = vec![runtime_dir.to_path_buf()];
    if let Some(existing) = existing {
        paths.extend(std::env::split_paths(&existing));
    }
    let joined =
        std::env::join_paths(paths).map_err(|e| format!("join DYLD_FALLBACK_LIBRARY_PATH: {e}"))?;
    unsafe {
        std::env::set_var("DYLD_FALLBACK_LIBRARY_PATH", joined);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn configure_runtime_loader_env(runtime_dir: &Path) -> Result<(), String> {
    let existing = std::env::var_os("LD_LIBRARY_PATH");
    let mut paths = vec![runtime_dir.to_path_buf()];
    if let Some(existing) = existing {
        paths.extend(std::env::split_paths(&existing));
    }
    let joined = std::env::join_paths(paths).map_err(|e| format!("join LD_LIBRARY_PATH: {e}"))?;
    unsafe {
        std::env::set_var("LD_LIBRARY_PATH", joined);
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn configure_runtime_loader_env(_runtime_dir: &Path) -> Result<(), String> {
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
    fn create(runtime_dir: &Path, log_level: u32) -> Result<Self, String> {
        let krun = ffi::libkrun(runtime_dir)?;
        check(
            unsafe {
                (krun.krun_init_log)(
                    ffi::KRUN_LOG_TARGET_DEFAULT,
                    clamp_log_level(log_level),
                    ffi::KRUN_LOG_STYLE_AUTO,
                    ffi::KRUN_LOG_OPTION_NO_ENV,
                )
            },
            "krun_init_log",
        )?;

        let ctx_id = unsafe { (krun.krun_create_ctx)() };
        if ctx_id < 0 {
            return Err(format!("krun_create_ctx failed with error code {ctx_id}"));
        }

        Ok(Self {
            krun,
            ctx_id: ctx_id.cast_unsigned(),
        })
    }

    fn set_vm_config(&self, vcpus: u8, mem_mib: u32) -> Result<(), String> {
        check(
            unsafe { (self.krun.krun_set_vm_config)(self.ctx_id, vcpus, mem_mib) },
            "krun_set_vm_config",
        )
    }

    fn set_disks(
        &self,
        root_disk: &Path,
        overlay_disk: &Path,
        image_disk: Option<&Path>,
    ) -> Result<(), String> {
        let root_disk_c = path_to_cstring(root_disk)?;
        let block_id_c = CString::new("root").map_err(|e| format!("invalid block id: {e}"))?;
        check(
            unsafe {
                (self.krun.krun_add_disk)(
                    self.ctx_id,
                    block_id_c.as_ptr(),
                    root_disk_c.as_ptr(),
                    true,
                )
            },
            "krun_add_disk",
        )?;

        let overlay_disk_c = path_to_cstring(overlay_disk)?;
        let overlay_block_id_c =
            CString::new("overlay").map_err(|e| format!("invalid block id: {e}"))?;
        check(
            unsafe {
                (self.krun.krun_add_disk)(
                    self.ctx_id,
                    overlay_block_id_c.as_ptr(),
                    overlay_disk_c.as_ptr(),
                    false,
                )
            },
            "krun_add_disk",
        )?;

        if let Some(image_disk) = image_disk {
            let image_disk_c = path_to_cstring(image_disk)?;
            let image_block_id_c =
                CString::new("image").map_err(|e| format!("invalid image block id: {e}"))?;
            check(
                unsafe {
                    (self.krun.krun_add_disk)(
                        self.ctx_id,
                        image_block_id_c.as_ptr(),
                        image_disk_c.as_ptr(),
                        true,
                    )
                },
                "krun_add_disk",
            )?;
        }

        let device_c =
            CString::new("/dev/vda").map_err(|e| format!("invalid root disk device: {e}"))?;
        let fstype_c =
            CString::new("ext4").map_err(|e| format!("invalid root disk fstype: {e}"))?;
        let options_c =
            CString::new("ro").map_err(|e| format!("invalid root disk options: {e}"))?;
        check(
            unsafe {
                (self.krun.krun_set_root_disk_remount)(
                    self.ctx_id,
                    device_c.as_ptr(),
                    fstype_c.as_ptr(),
                    options_c.as_ptr(),
                )
            },
            "krun_set_root_disk_remount",
        )
    }

    fn set_workdir(&self, workdir: &str) -> Result<(), String> {
        let workdir_c = CString::new(workdir).map_err(|e| format!("invalid workdir: {e}"))?;
        check(
            unsafe { (self.krun.krun_set_workdir)(self.ctx_id, workdir_c.as_ptr()) },
            "krun_set_workdir",
        )
    }

    fn disable_implicit_vsock(&self) -> Result<(), String> {
        check(
            unsafe { (self.krun.krun_disable_implicit_vsock)(self.ctx_id) },
            "krun_disable_implicit_vsock",
        )
    }

    fn add_vsock(&self, tsi_features: u32) -> Result<(), String> {
        check(
            unsafe { (self.krun.krun_add_vsock)(self.ctx_id, tsi_features) },
            "krun_add_vsock",
        )
    }

    fn add_vsock_port(&self, port_map: &VsockPortMap) -> Result<(), String> {
        let socket_c = path_to_cstring(&port_map.host_socket)?;
        check(
            unsafe {
                (self.krun.krun_add_vsock_port2)(
                    self.ctx_id,
                    port_map.guest_port,
                    socket_c.as_ptr(),
                    port_map.host_initiated,
                )
            },
            "krun_add_vsock_port2",
        )
    }

    fn set_console_output(&self, path: &Path) -> Result<(), String> {
        let console_c = path_to_cstring(path)?;
        check(
            unsafe { (self.krun.krun_set_console_output)(self.ctx_id, console_c.as_ptr()) },
            "krun_set_console_output",
        )
    }

    fn set_exec(&self, exec_path: &str, args: &[String], env: &[String]) -> Result<(), String> {
        let exec_c = CString::new(exec_path).map_err(|e| format!("invalid exec path: {e}"))?;
        let argv_slices: Vec<&str> = args.iter().map(String::as_str).collect();
        let (_argv_owners, argv_ptrs) = c_string_array(&argv_slices)?;
        let env_slices: Vec<&str> = env.iter().map(String::as_str).collect();
        let (_env_owners, env_ptrs) = c_string_array(&env_slices)?;

        check(
            unsafe {
                (self.krun.krun_set_exec)(
                    self.ctx_id,
                    exec_c.as_ptr(),
                    argv_ptrs.as_ptr(),
                    env_ptrs.as_ptr(),
                )
            },
            "krun_set_exec",
        )
    }

    fn start_enter(&self) -> i32 {
        unsafe { (self.krun.krun_start_enter)(self.ctx_id) }
    }
}

impl Drop for VmContext {
    fn drop(&mut self) {
        let ret = unsafe { (self.krun.krun_free_ctx)(self.ctx_id) };
        if ret < 0 {
            eprintln!(
                "warning: krun_free_ctx({}) failed with code {ret}",
                self.ctx_id
            );
        }
    }
}

fn install_signal_forwarding(pid: i32) {
    unsafe {
        libc::signal(
            libc::SIGINT,
            forward_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            forward_signal as *const () as libc::sighandler_t,
        );
    }
    CHILD_PID.store(pid, Ordering::Relaxed);
}

/// Async-signal-safe handler that forwards SIGTERM to the VM worker.
///
/// Only async-signal-safe libc calls are used — `kill(2)` is listed in
/// POSIX.1-2017 as async-signal-safe, atomic loads are lock-free on the
/// platforms we target.
extern "C" fn forward_signal(_sig: libc::c_int) {
    let vm_pid = CHILD_PID.load(Ordering::Relaxed);
    if vm_pid > 0 {
        unsafe {
            libc::kill(vm_pid, libc::SIGTERM);
        }
    }
}

fn wait_for_child(pid: i32) -> Result<libc::c_int, String> {
    let mut status: libc::c_int = 0;
    let rc = unsafe { libc::waitpid(pid, &raw mut status, 0) };
    if rc < 0 {
        return Err(format!(
            "waitpid({pid}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(status)
}

fn check(ret: i32, func: &'static str) -> Result<(), String> {
    if ret < 0 {
        Err(format!("{func} failed with error code {ret}"))
    } else {
        Ok(())
    }
}

fn c_string_array(strings: &[&str]) -> Result<(Vec<CString>, Vec<*const libc::c_char>), String> {
    let owned: Vec<CString> = strings
        .iter()
        .map(|s| CString::new(*s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("invalid string array entry: {e}"))?;
    let mut ptrs: Vec<*const libc::c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(ptr::null());
    Ok((owned, ptrs))
}

fn path_to_cstring(path: &Path) -> Result<CString, String> {
    let path = path
        .to_str()
        .ok_or_else(|| format!("path is not valid UTF-8: {}", path.display()))?;
    CString::new(path).map_err(|e| format!("invalid path string {path}: {e}"))
}

#[cfg(target_os = "linux")]
fn check_kvm_access() -> Result<(), String> {
    std::fs::OpenOptions::new()
        .read(true)
        .open("/dev/kvm")
        .map(|_| ())
        .map_err(|e| {
            format!("cannot open /dev/kvm: {e}\nKVM access is required to run microVMs on Linux.")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn qemu_config() -> VmLaunchConfig {
        VmLaunchConfig {
            root_disk: PathBuf::from("/rootfs.ext4"),
            overlay_disk: PathBuf::from("/overlay.ext4"),
            image_disk: None,
            kernel_image: None,
            vcpus: 2,
            mem_mib: 2048,
            exec_path: "/srv/openshell-vm-sandbox-init.sh".to_string(),
            args: Vec::new(),
            env: vec!["OPENSHELL_ENDPOINT=http://10.0.128.1:8080".to_string()],
            workdir: "/".to_string(),
            log_level: 0,
            console_output: PathBuf::from("/console.log"),
            backend: VmBackend::Qemu,
            gpu_bdf: Some("0000:01:00.0".to_string()),
            vsock_cid: Some(4),
            vsock_port_map: None,
        }
    }

    #[test]
    fn qemu_guest_env_vars_omit_network_metadata() {
        let env = qemu_guest_env_vars(&qemu_config());

        assert!(env.contains(&"OPENSHELL_ENDPOINT=http://10.0.128.1:8080".to_string()));
        assert!(!env.iter().any(|value| value.starts_with("VM_NET_")));
        assert!(env.contains(&"GPU_ENABLED=true".to_string()));
    }

    #[test]
    fn libkrun_guest_env_runs_guest_init_as_pid_one() {
        let env = libkrun_guest_env(&qemu_config());

        assert!(env.contains(&"OPENSHELL_ENDPOINT=http://10.0.128.1:8080".to_string()));
        assert!(env.contains(&KRUN_INIT_PID1_ENV.to_string()));
    }

    #[test]
    fn libkrun_guest_env_overrides_caller_pid_one_setting() {
        let mut config = qemu_config();
        config.env.extend([
            "KRUN_INIT_PID1=0".to_string(),
            "KRUN_INIT_PID1=unexpected".to_string(),
        ]);

        let env = libkrun_guest_env(&config);
        let pid_one_settings = env
            .iter()
            .filter(|value| value.starts_with("KRUN_INIT_PID1="))
            .collect::<Vec<_>>();

        assert_eq!(pid_one_settings.len(), 1);
        assert_eq!(pid_one_settings[0], KRUN_INIT_PID1_ENV);
    }

    #[test]
    fn libkrun_guest_env_keeps_defaults_when_no_env_is_configured() {
        let mut config = qemu_config();
        config.env.clear();

        let env = libkrun_guest_env(&config);

        assert!(env.contains(&"HOME=/root".to_string()));
        assert!(env.contains(&"TERM=xterm".to_string()));
        assert!(env.contains(&KRUN_INIT_PID1_ENV.to_string()));
    }

    #[test]
    fn kernel_cmdline_has_no_guest_network_configuration() {
        let cmdline = build_kernel_cmdline(&qemu_config());

        assert!(cmdline.contains("root=/dev/vda"));
        assert!(cmdline.contains("rootfstype=ext4"));
        assert!(cmdline.contains(" ro"));
        assert!(!cmdline.contains("ip="));
        assert!(cmdline.contains("firmware_class.path=/lib/firmware"));
        assert!(!cmdline.contains("VM_NET_IP="));
        assert!(!cmdline.contains("VM_NET_GW="));
        assert!(!cmdline.contains("VM_NET_DNS="));
        assert!(!cmdline.contains("GPU_ENABLED="));
    }

    #[test]
    fn qemu_disk_args_attach_base_readonly_and_overlay_readwrite() {
        let args = qemu_disk_args(&qemu_config());

        assert!(args.contains(&"-drive".to_string()));
        assert!(
            args.contains(
                &"file=/rootfs.ext4,if=none,format=raw,id=rootfs,readonly=on".to_string()
            )
        );
        assert!(args.contains(&"virtio-blk-pci,drive=rootfs".to_string()));
        assert!(args.contains(&"file=/overlay.ext4,if=none,format=raw,id=overlay".to_string()));
        assert!(
            !args
                .iter()
                .any(|arg| arg.contains("id=overlay,readonly=on"))
        );
        assert!(args.contains(&"virtio-blk-pci,drive=overlay".to_string()));
    }

    #[test]
    fn qemu_explicitly_disables_implicit_network_devices() {
        assert_eq!(qemu_network_args(), ["-nic", "none"]);
    }

    #[test]
    fn qemu_disk_args_attach_prepared_image_readonly_when_present() {
        let mut config = qemu_config();
        config.image_disk = Some(PathBuf::from("/image-rootfs.ext4"));

        let args = qemu_disk_args(&config);

        assert!(args.contains(
            &"file=/image-rootfs.ext4,if=none,format=raw,id=image,readonly=on".to_string()
        ));
        assert!(args.contains(&"virtio-blk-pci,drive=image".to_string()));
    }
}
