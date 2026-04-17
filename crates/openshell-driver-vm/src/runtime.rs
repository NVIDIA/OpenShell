// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(unsafe_code)]

use std::ffi::CString;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child as StdChild, Command as StdCommand, Stdio};
use std::ptr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use crate::{GUEST_SSH_PORT, embedded_runtime, ffi};

pub const VM_RUNTIME_DIR_ENV: &str = "OPENSHELL_VM_RUNTIME_DIR";

static CHILD_PID: AtomicI32 = AtomicI32::new(0);

pub struct VmLaunchConfig {
    pub rootfs: PathBuf,
    pub vcpus: u8,
    pub mem_mib: u32,
    pub exec_path: String,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub workdir: String,
    pub port_map: Vec<String>,
    pub log_level: u32,
    pub console_output: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PortMapping {
    host_port: u16,
    guest_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GvproxyPortPlan {
    ssh_port: u16,
    forwarded_ports: Vec<String>,
}

pub fn run_vm(config: &VmLaunchConfig) -> Result<(), String> {
    if !config.rootfs.is_dir() {
        return Err(format!(
            "rootfs directory not found: {}",
            config.rootfs.display()
        ));
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

    let mut forwarded_port_map = config.port_map.clone();
    let mut gvproxy_guard = None;
    let mut gvproxy_api_sock = None;
    if !config.port_map.is_empty() {
        let gvproxy_binary = runtime_dir.join("gvproxy");
        if !gvproxy_binary.is_file() {
            return Err(format!(
                "missing runtime file: {}",
                gvproxy_binary.display()
            ));
        }

        kill_stale_gvproxy_by_port_map(&config.port_map);

        let sock_base = gvproxy_socket_base(&config.rootfs)?;
        let net_sock = sock_base.with_extension("v");
        let api_sock = sock_base.with_extension("a");
        let _ = std::fs::remove_file(&net_sock);
        let _ = std::fs::remove_file(&api_sock);
        let _ = std::fs::remove_file(sock_base.with_extension("v-krun.sock"));

        let run_dir = config.rootfs.parent().unwrap_or(&config.rootfs);
        let gvproxy_log = run_dir.join("gvproxy.log");
        let gvproxy_log_file = std::fs::File::create(&gvproxy_log)
            .map_err(|e| format!("create gvproxy log {}: {e}", gvproxy_log.display()))?;

        let gvproxy_ports = plan_gvproxy_ports(&config.port_map)?;
        forwarded_port_map = gvproxy_ports.forwarded_ports;

        #[cfg(target_os = "linux")]
        let (gvproxy_net_flag, gvproxy_net_url) =
            ("-listen-qemu", format!("unix://{}", net_sock.display()));
        #[cfg(target_os = "macos")]
        let (gvproxy_net_flag, gvproxy_net_url) = (
            "-listen-vfkit",
            format!("unixgram://{}", net_sock.display()),
        );

        let child = StdCommand::new(&gvproxy_binary)
            .arg(gvproxy_net_flag)
            .arg(&gvproxy_net_url)
            .arg("-listen")
            .arg(format!("unix://{}", api_sock.display()))
            .arg("-ssh-port")
            .arg(gvproxy_ports.ssh_port.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(gvproxy_log_file)
            .spawn()
            .map_err(|e| format!("failed to start gvproxy {}: {e}", gvproxy_binary.display()))?;

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

        gvproxy_guard = Some(GvproxyGuard::new(child));
        gvproxy_api_sock = Some(api_sock);
    }

    if !config.port_map.is_empty() && gvproxy_api_sock.is_none() {
        vm.set_port_map(&config.port_map)?;
    }
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
            let ret = vm.start_enter();
            eprintln!("krun_start_enter failed: {ret}");
            std::process::exit(1);
        }
        _ => {
            install_signal_forwarding(pid);

            let port_forward_result = if let Some(api_sock) = gvproxy_api_sock.as_ref() {
                expose_port_map(api_sock, &forwarded_port_map)
            } else {
                Ok(())
            };

            if let Err(err) = port_forward_result {
                unsafe {
                    libc::kill(pid, libc::SIGTERM);
                }
                let _ = wait_for_child(pid);
                cleanup_gvproxy(gvproxy_guard);
                return Err(err);
            }

            let status = wait_for_child(pid)?;
            CHILD_PID.store(0, Ordering::Relaxed);
            cleanup_gvproxy(gvproxy_guard);

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

    fn set_port_map(&self, port_map: &[String]) -> Result<(), String> {
        let port_strs: Vec<&str> = port_map.iter().map(String::as_str).collect();
        let (_owners, ptrs) = c_string_array(&port_strs)?;
        check(
            unsafe { (self.krun.krun_set_port_map)(self.ctx_id, ptrs.as_ptr()) },
            "krun_set_port_map",
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

fn expose_port_map(api_sock: &Path, port_map: &[String]) -> Result<(), String> {
    wait_for_path(api_sock, Duration::from_secs(2), "gvproxy API socket")?;
    let guest_ip = "192.168.127.2";

    for pm in port_map {
        let mapping = parse_port_mapping(pm)?;

        let expose_body = format!(
            r#"{{"local":":{}","remote":"{guest_ip}:{}","protocol":"tcp"}}"#,
            mapping.host_port, mapping.guest_port
        );

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut retry_interval = Duration::from_millis(100);
        loop {
            match gvproxy_expose(api_sock, &expose_body) {
                Ok(()) => break,
                Err(err) if Instant::now() < deadline => {
                    std::thread::sleep(retry_interval);
                    retry_interval = (retry_interval * 2).min(Duration::from_secs(1));
                    if retry_interval == Duration::from_secs(1) {
                        eprintln!("retrying gvproxy port expose {pm}: {err}");
                    }
                }
                Err(err) => {
                    return Err(format!(
                        "failed to forward port {} via gvproxy: {err}",
                        mapping.host_port
                    ));
                }
            }
        }
    }

    Ok(())
}

fn gvproxy_expose(api_sock: &Path, body: &str) -> Result<(), String> {
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

    let mut buf = [0u8; 1024];
    let n = stream
        .read(&mut buf)
        .map_err(|e| format!("read from gvproxy API: {e}"))?;
    let response = String::from_utf8_lossy(&buf[..n]);
    let status = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("0");

    match status {
        "200" | "204" => Ok(()),
        _ => Err(format!(
            "gvproxy API: {}",
            response.lines().next().unwrap_or("<empty>")
        )),
    }
}

fn plan_gvproxy_ports(port_map: &[String]) -> Result<GvproxyPortPlan, String> {
    let mut ssh_port = None;
    let mut forwarded_ports = Vec::with_capacity(port_map.len());

    for pm in port_map {
        let mapping = parse_port_mapping(pm)?;
        if ssh_port.is_none() && mapping.guest_port == GUEST_SSH_PORT && mapping.host_port >= 1024 {
            ssh_port = Some(mapping.host_port);
            continue;
        }
        forwarded_ports.push(pm.clone());
    }

    Ok(GvproxyPortPlan {
        ssh_port: match ssh_port {
            Some(port) => port,
            None => pick_gvproxy_ssh_port()?,
        },
        forwarded_ports,
    })
}

fn parse_port_mapping(pm: &str) -> Result<PortMapping, String> {
    let parts: Vec<&str> = pm.split(':').collect();
    let (host, guest) = match parts.as_slice() {
        [host, guest] => (*host, *guest),
        [port] => (*port, *port),
        _ => return Err(format!("invalid port mapping '{pm}'")),
    };

    let host_port = host
        .parse::<u16>()
        .map_err(|_| format!("invalid port mapping '{pm}'"))?;
    let guest_port = guest
        .parse::<u16>()
        .map_err(|_| format!("invalid port mapping '{pm}'"))?;

    Ok(PortMapping {
        host_port,
        guest_port,
    })
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

fn pick_gvproxy_ssh_port() -> Result<u16, String> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| format!("allocate gvproxy ssh port on localhost: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("read gvproxy ssh port: {e}"))?
        .port();
    drop(listener);
    Ok(port)
}

fn kill_stale_gvproxy_by_port_map(port_map: &[String]) {
    for pm in port_map {
        if let Some(host_port) = pm
            .split(':')
            .next()
            .and_then(|port| port.parse::<u16>().ok())
        {
            kill_stale_gvproxy_by_port(host_port);
        }
    }
}

fn kill_stale_gvproxy_by_port(port: u16) {
    let output = StdCommand::new("lsof")
        .args(["-ti", &format!(":{port}")])
        .output();

    let pids = match output {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).to_string()
        }
        _ => return,
    };

    for line in pids.lines() {
        if let Ok(pid) = line.trim().parse::<u32>()
            && is_process_named(pid as libc::pid_t, "gvproxy")
        {
            kill_gvproxy_pid(pid);
        }
    }
}

fn kill_gvproxy_pid(pid: u32) {
    let pid = pid as libc::pid_t;
    if unsafe { libc::kill(pid, 0) } != 0 {
        return;
    }
    if !is_process_named(pid, "gvproxy") {
        return;
    }
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    std::thread::sleep(Duration::from_millis(200));
}

#[cfg(target_os = "macos")]
fn is_process_named(pid: libc::pid_t, expected: &str) -> bool {
    StdCommand::new("ps")
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
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|name| name.trim().contains(expected))
        .unwrap_or(false)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn is_process_named(_pid: libc::pid_t, _expected: &str) -> bool {
    false
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

extern "C" fn forward_signal(_sig: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::Relaxed);
    if pid > 0 {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_gvproxy_ports_reuses_sandbox_ssh_mapping() {
        let plan = plan_gvproxy_ports(&["64739:2222".to_string()]).expect("plan should succeed");

        assert_eq!(plan.ssh_port, 64739);
        assert!(plan.forwarded_ports.is_empty());
    }

    #[test]
    fn plan_gvproxy_ports_keeps_non_ssh_mappings_for_forwarder() {
        let plan = plan_gvproxy_ports(&["64739:8080".to_string()]).expect("plan should succeed");

        assert_ne!(plan.ssh_port, 64739);
        assert_eq!(plan.forwarded_ports, vec!["64739:8080".to_string()]);
    }

    #[test]
    fn plan_gvproxy_ports_ignores_privileged_host_ports_for_direct_ssh() {
        let plan = plan_gvproxy_ports(&["22:2222".to_string()]).expect("plan should succeed");

        assert_ne!(plan.ssh_port, 22);
        assert_eq!(plan.forwarded_ports, vec!["22:2222".to_string()]);
    }

    #[test]
    fn parse_port_mapping_rejects_invalid_entries() {
        let err = parse_port_mapping("bad:mapping").expect_err("invalid mapping should fail");
        assert!(err.contains("invalid port mapping"));
    }
}
