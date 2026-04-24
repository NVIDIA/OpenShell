// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(unsafe_code)]

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::process::{Child as StdChild, Command as StdCommand, Stdio};
use std::ptr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use crate::{embedded_runtime, ffi, procguard};

pub const VM_RUNTIME_DIR_ENV: &str = "OPENSHELL_VM_RUNTIME_DIR";

/// PID of the forked libkrun worker (the VM's PID 1). Zero when not running.
/// Used by the SIGTERM/SIGINT handler to forward signals to the VM.
static CHILD_PID: AtomicI32 = AtomicI32::new(0);

/// PID of the gvproxy helper process. Zero when not running. Used by the
/// SIGTERM/SIGINT handler to make sure gvproxy doesn't survive the
/// launcher on macOS (where we can't use `PR_SET_PDEATHSIG`).
static GVPROXY_PID: AtomicI32 = AtomicI32::new(0);

pub struct VmLaunchConfig {
    pub rootfs: PathBuf,
    pub vcpus: u8,
    pub mem_mib: u32,
    pub exec_path: String,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub workdir: String,
    pub log_level: u32,
    pub console_output: PathBuf,
}

pub fn run_vm(config: &VmLaunchConfig) -> Result<(), String> {
    if !config.rootfs.is_dir() {
        return Err(format!(
            "rootfs directory not found: {}",
            config.rootfs.display()
        ));
    }

    // Arm procguard first, BEFORE we spawn gvproxy or fork libkrun, so
    // that the launcher can't be orphaned during setup. The cleanup
    // callback reads the GVPROXY_PID atomic (initially 0 — no-op) and
    // the CHILD_PID atomic (the libkrun fork), so it stays correct as
    // those slots get populated later in this function. Only ONE arm
    // per process: racing two watchers for the same NOTE_EXIT event
    // would cause whichever wins to skip the cleanup.
    if let Err(err) = procguard::die_with_parent_cleanup(|| {
        // Cleanup order: SIGTERM gvproxy and the libkrun fork first so
        // they can drain cleanly, then SIGKILL after a brief grace
        // window. We can't rely on Rust destructors here; when
        // procguard's watcher thread returns we call `std::process::exit`
        // and the process tears down. Only async-signal-safe calls here:
        // atomic loads and `kill(2)` are both on the POSIX list.
        let gv_pid = GVPROXY_PID.load(Ordering::Relaxed);
        let child_pid = CHILD_PID.load(Ordering::Relaxed);
        if gv_pid > 0 {
            unsafe {
                libc::kill(gv_pid, libc::SIGTERM);
            }
        }
        if child_pid > 0 {
            unsafe {
                libc::kill(child_pid, libc::SIGTERM);
            }
        }
        std::thread::sleep(Duration::from_millis(200));
        if gv_pid > 0 {
            unsafe {
                libc::kill(gv_pid, libc::SIGKILL);
            }
        }
        if child_pid > 0 {
            unsafe {
                libc::kill(child_pid, libc::SIGKILL);
            }
        }
    }) {
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
    vm.set_root(&config.rootfs)?;
    vm.set_workdir(&config.workdir)?;

    // Run gvproxy strictly as the guest's virtual NIC / DHCP / router.
    //
    // After the supervisor-initiated relay migration (#867), the driver
    // no longer forwards any host-side ports into the guest — all ingress
    // traffic for SSH and exec rides the outbound `ConnectSupervisor`
    // gRPC stream the guest opens to the gateway. What gvproxy still
    // provides here is the TCP/IP *plane* the guest kernel needs:
    //
    //   * a virtio-net backend attached to libkrun via a Unix
    //     SOCK_STREAM (Linux) or SOCK_DGRAM (macOS vfkit), which
    //     surfaces as `eth0` inside the guest;
    //   * the DHCP server + default router the guest's udhcpc client
    //     talks to on boot (IPs 192.168.127.1 / .2, defaults for
    //     gvisor-tap-vsock);
    //   * the host-facing gateway identity the guest uses for callbacks:
    //     the init script seeds `/etc/hosts` with
    //     `host.openshell.internal` pointing at 192.168.127.1 while
    //     leaving gvproxy's legacy `host.containers.internal` /
    //     `host.docker.internal` DNS answers intact, which is how the guest's
    //     `rewrite_openshell_endpoint_if_needed` probe reaches the host
    //     gateway when the bare loopback address doesn't resolve from
    //     inside the VM.
    //
    // That network plane is also what the sandbox supervisor's
    // per-sandbox netns (veth pair + iptables, see
    // `openshell-sandbox/src/sandbox/linux/netns.rs`) branches off of;
    // libkrun's built-in TSI socket impersonation would not satisfy
    // those kernel-level primitives.
    //
    // The `-listen` API socket and `-ssh-port` forwarder are both
    // deliberately omitted: nothing in the driver enqueues port
    // forwards on the API any more, and the host-side SSH listener is
    // dead plumbing.
    let gvproxy_guard = {
        let gvproxy_binary = runtime_dir.join("gvproxy");
        if !gvproxy_binary.is_file() {
            return Err(format!(
                "missing runtime file: {}",
                gvproxy_binary.display()
            ));
        }

        let sock_base = gvproxy_socket_base(&config.rootfs)?;
        let net_sock = sock_base.with_extension("v");
        let _ = std::fs::remove_file(&net_sock);
        let _ = std::fs::remove_file(sock_base.with_extension("v-krun.sock"));

        let run_dir = config.rootfs.parent().unwrap_or(&config.rootfs);
        let gvproxy_log = run_dir.join("gvproxy.log");
        let gvproxy_log_file = std::fs::File::create(&gvproxy_log)
            .map_err(|e| format!("create gvproxy log {}: {e}", gvproxy_log.display()))?;

        #[cfg(target_os = "linux")]
        let (gvproxy_net_flag, gvproxy_net_url) =
            ("-listen-qemu", format!("unix://{}", net_sock.display()));
        #[cfg(target_os = "macos")]
        let (gvproxy_net_flag, gvproxy_net_url) = (
            "-listen-vfkit",
            format!("unixgram://{}", net_sock.display()),
        );

        // `-ssh-port -1` tells gvproxy to skip its default SSH forward
        // (127.0.0.1:2222 → guest:22). We don't use it — all gateway
        // ingress rides the supervisor-initiated relay — and leaving
        // the default on would bind a host-side TCP listener per
        // sandbox, racing concurrent sandboxes for port 2222 and
        // surfacing a misleading "sshd is reachable" endpoint. See
        // https://github.com/containers/gvisor-tap-vsock `cmd/gvproxy/main.go`
        // (`getForwardsMap` returns an empty map when `sshPort == -1`).
        let mut gvproxy_cmd = StdCommand::new(&gvproxy_binary);
        gvproxy_cmd
            .arg(gvproxy_net_flag)
            .arg(&gvproxy_net_url)
            .arg("-ssh-port")
            .arg("-1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(gvproxy_log_file);

        // On Linux the kernel will SIGKILL gvproxy the moment this
        // launcher dies (or is SIGKILLed). `pre_exec` runs in the child
        // between fork and execve, so the PR_SET_PDEATHSIG flag is
        // inherited across execve and applies to gvproxy proper. On
        // macOS/BSDs there is no equivalent; we fall back to killing
        // gvproxy explicitly from the launcher's procguard cleanup
        // callback (see `run_vm` above) and SIGTERM handler
        // (see `install_signal_forwarding` below).
        #[cfg(target_os = "linux")]
        {
            use nix::sys::signal::Signal;
            use std::os::unix::process::CommandExt as _;
            unsafe {
                gvproxy_cmd.pre_exec(|| {
                    nix::sys::prctl::set_pdeathsig(Signal::SIGKILL)
                        .map_err(|err| std::io::Error::other(format!("pdeathsig: {err}")))
                });
            }
        }

        let child = gvproxy_cmd
            .spawn()
            .map_err(|e| format!("failed to start gvproxy {}: {e}", gvproxy_binary.display()))?;
        // The procguard cleanup reads GVPROXY_PID atomically. Storing it
        // here makes the callback able to SIGTERM gvproxy if the driver
        // dies from this moment onward.
        GVPROXY_PID.store(child.id() as i32, Ordering::Relaxed);

        wait_for_path(&net_sock, Duration::from_secs(5), "gvproxy data socket")?;

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
        vm.add_net_unixstream(&net_sock, &mac, COMPAT_NET_FEATURES)?;
        #[cfg(target_os = "macos")]
        {
            const NET_FLAG_VFKIT: u32 = 1 << 0;
            vm.add_net_unixgram(&net_sock, &mac, COMPAT_NET_FEATURES, NET_FLAG_VFKIT)?;
        }

        Some(GvproxyGuard::new(child))
    };

    vm.set_console_output(&config.console_output)?;

    let env = if config.env.is_empty() {
        vec![
            "HOME=/root".to_string(),
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            "TERM=xterm".to_string(),
        ]
    } else {
        config.env.clone()
    };
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
            // NOTE_EXIT watcher thread. Either way it closes the same
            // leak gvproxy does above.
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
            cleanup_gvproxy(gvproxy_guard);
            GVPROXY_PID.store(0, Ordering::Relaxed);

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
            ctx_id: ctx_id as u32,
        })
    }

    fn set_vm_config(&self, vcpus: u8, mem_mib: u32) -> Result<(), String> {
        check(
            unsafe { (self.krun.krun_set_vm_config)(self.ctx_id, vcpus, mem_mib) },
            "krun_set_vm_config",
        )
    }

    fn set_root(&self, rootfs: &Path) -> Result<(), String> {
        let rootfs_c = path_to_cstring(rootfs)?;
        check(
            unsafe { (self.krun.krun_set_root)(self.ctx_id, rootfs_c.as_ptr()) },
            "krun_set_root",
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

    #[cfg(target_os = "macos")]
    fn add_net_unixgram(
        &self,
        socket_path: &Path,
        mac: &[u8; 6],
        features: u32,
        flags: u32,
    ) -> Result<(), String> {
        let sock_c = path_to_cstring(socket_path)?;
        check(
            unsafe {
                (self.krun.krun_add_net_unixgram)(
                    self.ctx_id,
                    sock_c.as_ptr(),
                    -1,
                    mac.as_ptr(),
                    features,
                    flags,
                )
            },
            "krun_add_net_unixgram",
        )
    }

    #[allow(dead_code)] // Used on Linux when gvproxy runs in qemu/unixstream mode.
    fn add_net_unixstream(
        &self,
        socket_path: &Path,
        mac: &[u8; 6],
        features: u32,
    ) -> Result<(), String> {
        let sock_c = path_to_cstring(socket_path)?;
        check(
            unsafe {
                (self.krun.krun_add_net_unixstream)(
                    self.ctx_id,
                    sock_c.as_ptr(),
                    -1,
                    mac.as_ptr(),
                    features,
                    0,
                )
            },
            "krun_add_net_unixstream",
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
        let argv_strs: Vec<&str> = args.iter().map(String::as_str).collect();
        let (_argv_owners, argv_ptrs) = c_string_array(&argv_strs)?;
        let env_strs: Vec<&str> = env.iter().map(String::as_str).collect();
        let (_env_owners, env_ptrs) = c_string_array(&env_strs)?;

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

struct GvproxyGuard {
    child: Option<StdChild>,
}

impl GvproxyGuard {
    fn new(child: StdChild) -> Self {
        Self { child: Some(child) }
    }

    fn disarm(&mut self) -> Option<StdChild> {
        self.child.take()
    }
}

impl Drop for GvproxyGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn wait_for_path(path: &Path, timeout: Duration, label: &str) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let mut interval = Duration::from_millis(5);
    while !path.exists() {
        if Instant::now() >= deadline {
            return Err(format!(
                "{label} did not appear within {:.1}s: {}",
                timeout.as_secs_f64(),
                path.display()
            ));
        }
        std::thread::sleep(interval);
        interval = (interval * 2).min(Duration::from_millis(200));
    }
    Ok(())
}

fn hash_path_id(path: &Path) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in path.to_string_lossy().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{:012x}", hash & 0x0000_ffff_ffff_ffff)
}

fn secure_socket_base(subdir: &str) -> Result<PathBuf, String> {
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

    if dir.exists() {
        let meta = dir
            .symlink_metadata()
            .map_err(|e| format!("lstat {}: {e}", dir.display()))?;
        if meta.file_type().is_symlink() {
            return Err(format!(
                "socket directory {} is a symlink; refusing to use it",
                dir.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let uid = unsafe { libc::getuid() };
            if meta.uid() != uid {
                return Err(format!(
                    "socket directory {} is owned by uid {} but we are uid {}",
                    dir.display(),
                    meta.uid(),
                    uid
                ));
            }
        }
    } else {
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("create socket dir {}: {e}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
    }

    Ok(dir)
}

fn gvproxy_socket_base(rootfs: &Path) -> Result<PathBuf, String> {
    Ok(secure_socket_base("osd-gv")?.join(hash_path_id(rootfs)))
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

/// Async-signal-safe handler that forwards SIGTERM to every process we
/// own: the libkrun VM worker and the gvproxy helper. We cannot rely on
/// Rust destructors (`GvproxyGuard::drop`, `ManagedDriverProcess::drop`)
/// running on signal-driven exit, so we explicitly deliver the signal
/// here. The `wait_for_child` loop reaps libkrun and `cleanup_gvproxy`
/// reaps gvproxy before `run_vm` returns.
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
    let gv_pid = GVPROXY_PID.load(Ordering::Relaxed);
    if gv_pid > 0 {
        // gvproxy handles SIGTERM cleanly; no need for SIGKILL.
        unsafe {
            libc::kill(gv_pid, libc::SIGTERM);
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

fn cleanup_gvproxy(mut guard: Option<GvproxyGuard>) {
    if let Some(mut guard) = guard.take()
        && let Some(mut child) = guard.disarm()
    {
        let _ = child.kill();
        let _ = child.wait();
    }
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
    CString::new(path).map_err(|e| format!("invalid path string {}: {e}", path))
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
