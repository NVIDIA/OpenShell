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

/// PID of the VM worker process (libkrun fork or QEMU). Zero when not running.
/// Used by the SIGTERM/SIGINT handler to forward signals to the VM.
static CHILD_PID: AtomicI32 = AtomicI32::new(0);

/// PID of the helper process (gvproxy for libkrun, virtiofsd for QEMU).
/// Zero when not running. Used by the SIGTERM/SIGINT handler and
/// procguard cleanup callback to ensure the helper doesn't outlive the
/// launcher (especially on macOS where `PR_SET_PDEATHSIG` is absent).
static GVPROXY_PID: AtomicI32 = AtomicI32::new(0);

#[derive(Debug, Clone, PartialEq)]
pub enum VmBackend {
    Libkrun,
    Qemu,
}

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
    pub backend: VmBackend,
    pub gpu_bdf: Option<String>,
    pub tap_device: Option<String>,
    pub guest_ip: Option<String>,
    pub host_ip: Option<String>,
    pub vsock_cid: Option<u32>,
    pub guest_mac: Option<String>,
    pub gateway_port: Option<u16>,
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
    let tap_device = config
        .tap_device
        .as_deref()
        .ok_or("tap_device is required for QEMU backend")?;
    let guest_mac = config
        .guest_mac
        .as_deref()
        .ok_or("guest_mac is required for QEMU backend")?;
    let vsock_cid = config
        .vsock_cid
        .ok_or("vsock_cid is required for QEMU backend")?;
    let _guest_ip = config
        .guest_ip
        .as_deref()
        .ok_or("guest_ip is required for QEMU backend")?;
    let host_ip = config
        .host_ip
        .as_deref()
        .ok_or("host_ip is required for QEMU backend")?;

    if !config.rootfs.is_dir() {
        return Err(format!(
            "rootfs directory not found: {}",
            config.rootfs.display()
        ));
    }

    if let Err(err) = procguard::die_with_parent_cleanup(procguard_kill_children) {
        return Err(format!("procguard arm failed: {err}"));
    }

    #[cfg(target_os = "linux")]
    check_kvm_access()?;

    write_guest_env_file(&config.rootfs, &config.env)?;

    let rootfs_str = config.rootfs.to_str().ok_or("rootfs path not UTF-8")?;
    let sandbox_dir = config.rootfs.parent().unwrap_or(&config.rootfs);
    let sock_prefix = tap_device.trim_start_matches("vmtap-");
    let virtiofsd_sock_dir = PathBuf::from(format!("/tmp/ovm-qemu-{sock_prefix}"));
    std::fs::create_dir_all(&virtiofsd_sock_dir)
        .map_err(|e| format!("create virtiofsd sock dir: {e}"))?;
    let virtiofsd_sock = virtiofsd_sock_dir.join("virtiofsd.sock");
    let shm_path = format!("/dev/shm/ovm-qemu-{sock_prefix}");

    std::fs::create_dir_all(&shm_path).map_err(|e| format!("create shm dir: {e}"))?;

    let runtime_dir = qemu_runtime_dir()?;

    let gw_port = config.gateway_port.unwrap_or(0);
    setup_tap_networking(tap_device, host_ip, gw_port)?;
    let mut tap_guard = TapGuard::new(tap_device.to_string(), host_ip.to_string(), gw_port);

    let virtiofsd_log = sandbox_dir.join("virtiofsd.log");
    let virtiofsd_log_file =
        std::fs::File::create(&virtiofsd_log).map_err(|e| format!("create virtiofsd log: {e}"))?;

    let virtiofsd_bin = {
        let runtime_virtiofsd = runtime_dir.join("virtiofsd");
        if runtime_virtiofsd.is_file() {
            runtime_virtiofsd
        } else {
            PathBuf::from("virtiofsd")
        }
    };

    let mut virtiofsd_cmd = StdCommand::new(&virtiofsd_bin);
    virtiofsd_cmd
        .arg("--socket-path")
        .arg(&virtiofsd_sock)
        .arg("--shared-dir")
        .arg(rootfs_str)
        .arg("--cache=auto")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(virtiofsd_log_file);

    #[cfg(target_os = "linux")]
    {
        use nix::sys::signal::Signal;
        use std::os::unix::process::CommandExt as _;
        unsafe {
            virtiofsd_cmd.pre_exec(|| {
                nix::sys::prctl::set_pdeathsig(Signal::SIGKILL)
                    .map_err(|err| std::io::Error::other(format!("pdeathsig: {err}")))
            });
        }
    }

    let virtiofsd_child = virtiofsd_cmd
        .spawn()
        .map_err(|e| format!("failed to start virtiofsd: {e}"))?;
    let virtiofsd_pid = virtiofsd_child.id() as i32;
    GVPROXY_PID.store(virtiofsd_pid, Ordering::Relaxed);
    let mut virtiofsd_guard = GvproxyGuard::new(virtiofsd_child);

    wait_for_path(&virtiofsd_sock, Duration::from_secs(5), "virtiofsd socket")?;

    let vmlinux = runtime_dir.join("vmlinux");
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
        .arg("-kernel")
        .arg(&vmlinux)
        .arg("-append")
        .arg(&kernel_cmdline)
        .arg("-chardev")
        .arg(format!(
            "socket,id=virtiofs,path={}",
            virtiofsd_sock.display()
        ))
        .arg("-device")
        .arg("vhost-user-fs-pci,chardev=virtiofs,tag=rootfs")
        .arg("-object")
        .arg(format!(
            "memory-backend-memfd,id=mem,size={}M,share=on",
            config.mem_mib
        ))
        .arg("-numa")
        .arg("node,memdev=mem")
        .arg("-netdev")
        .arg(format!(
            "tap,id=net0,ifname={tap_device},script=no,downscript=no"
        ))
        .arg("-device")
        .arg("pcie-root-port,id=net_root,slot=3")
        .arg("-device")
        .arg(format!(
            "virtio-net-pci-non-transitional,netdev=net0,mac={guest_mac},bus=net_root"
        ))
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

    let qemu_pid = qemu_child.id() as i32;
    install_signal_forwarding(qemu_pid);

    let status = qemu_child
        .wait()
        .map_err(|e| format!("failed to wait for QEMU: {e}"))?;

    CHILD_PID.store(0, Ordering::Relaxed);
    unsafe {
        libc::kill(virtiofsd_pid, libc::SIGTERM);
    }
    virtiofsd_guard.disarm();
    GVPROXY_PID.store(0, Ordering::Relaxed);
    teardown_tap_networking(tap_device, host_ip, gw_port);
    tap_guard.disarm();
    let _ = std::fs::remove_dir_all(&shm_path);
    let _ = std::fs::remove_dir_all(&virtiofsd_sock_dir);

    if status.success() {
        Ok(())
    } else {
        Err(format!("QEMU exited with status {status}"))
    }
}

/// Write environment variables into the rootfs so the guest init script
/// can source them. virtiofs shares the host rootfs directory into the guest.
fn write_guest_env_file(rootfs: &Path, env_vars: &[String]) -> Result<(), String> {
    let srv_dir = rootfs.join("srv");
    std::fs::create_dir_all(&srv_dir).map_err(|e| format!("create /srv in rootfs: {e}"))?;
    let env_file = srv_dir.join("openshell-env.sh");
    let mut content = String::new();
    for var in env_vars {
        if let Some((key, value)) = var.split_once('=') {
            content.push_str(&format!("export {key}=\"{}\"\n", shell_escape(value)));
        }
    }
    std::fs::write(&env_file, &content).map_err(|e| format!("write guest env file: {e}"))?;
    Ok(())
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
        "root=rootfs".to_string(),
        "rootfstype=virtiofs".to_string(),
        "rw".to_string(),
        "panic=-1".to_string(),
        format!("init={}", config.exec_path),
    ];

    if let Some(ip) = &config.guest_ip {
        if let Some(host_ip) = &config.host_ip {
            parts.push(format!("ip={ip}::{host_ip}:255.255.255.252:sandbox::off"));
            parts.push(format!("VM_NET_IP={ip}"));
            parts.push(format!("VM_NET_GW={host_ip}"));
        }
    }

    if let Some(dns) = host_dns_server() {
        parts.push(format!("VM_NET_DNS={dns}"));
    }

    if config.gpu_bdf.is_some() {
        parts.push("GPU_ENABLED=true".to_string());
        parts.push("firmware_class.path=/lib/firmware".to_string());
    }

    parts.join(" ")
}

fn host_dns_server() -> Option<String> {
    // Prefer systemd-resolved upstream config (skips the 127.0.0.53
    // stub listener which is unreachable from inside QEMU/TAP guests).
    for path in &["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"] {
        let Ok(resolv) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in resolv.lines() {
            let line = line.trim();
            if let Some(server) = line.strip_prefix("nameserver") {
                let server = server.trim();
                if server == "127.0.0.53" || server.starts_with("127.") {
                    continue;
                }
                if !server.is_empty() {
                    return Some(server.to_string());
                }
            }
        }
    }
    None
}

/// Remove leftover `vmtap-*` interfaces from previous driver runs that
/// were not torn down (e.g. the launcher was SIGKILLed before teardown).
/// Called once at driver startup so stale interfaces cannot cause subnet
/// routing conflicts with newly allocated TAPs.
pub fn cleanup_stale_tap_interfaces() {
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with("vmtap-") {
            continue;
        }
        // Read the IP address so we can clean up iptables rules too.
        // Port 0 tells teardown we don't know the original gateway port;
        // the blanket legacy rule is still cleaned up best-effort.
        let ip = read_tap_host_ip(name);
        if let Some(ref host_ip) = ip {
            teardown_tap_networking(name, host_ip, 0);
        } else {
            let _ = run_cmd("ip", &["link", "set", name, "down"]);
            let _ = run_cmd("ip", &["tuntap", "del", "dev", name, "mode", "tap"]);
        }
        tracing::warn!(interface = %name, "removed stale TAP interface from previous run");
    }
}

/// Read the first IPv4 address assigned to a network interface.
fn read_tap_host_ip(device: &str) -> Option<String> {
    let output = StdCommand::new("ip")
        .args(["-4", "-o", "addr", "show", "dev", device])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Format: "28: vmtap-xxx    inet 10.0.128.1/30 ..."
    for token in stdout.split_whitespace() {
        if let Some((ip, _prefix)) = token.split_once('/') {
            if ip.parse::<std::net::Ipv4Addr>().is_ok() {
                return Some(ip.to_string());
            }
        }
    }
    None
}

fn setup_tap_networking(tap_device: &str, host_ip: &str, gateway_port: u16) -> Result<(), String> {
    run_cmd("ip", &["tuntap", "add", "dev", tap_device, "mode", "tap"])?;
    run_cmd(
        "ip",
        &["addr", "add", &format!("{host_ip}/30"), "dev", tap_device],
    )?;
    run_cmd("ip", &["link", "set", tap_device, "up"])?;

    // Deprioritize routes through down interfaces so a stale vmtap-*
    // that somehow survives cleanup cannot shadow the active one.
    let _ = std::fs::write(
        format!("/proc/sys/net/ipv4/conf/{tap_device}/ignore_routes_with_linkdown"),
        "1",
    );

    enable_ip_forwarding()?;

    let subnet = tap_subnet_from_host_ip(host_ip);
    let _ = run_cmd(
        "iptables",
        &[
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            &subnet,
            "-j",
            "MASQUERADE",
        ],
    );
    run_cmd(
        "iptables",
        &[
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            &subnet,
            "-j",
            "MASQUERADE",
        ],
    )?;
    let _ = run_cmd(
        "iptables",
        &["-D", "FORWARD", "-i", tap_device, "-j", "ACCEPT"],
    );
    run_cmd(
        "iptables",
        &["-A", "FORWARD", "-i", tap_device, "-j", "ACCEPT"],
    )?;
    let _ = run_cmd(
        "iptables",
        &[
            "-D",
            "FORWARD",
            "-o",
            tap_device,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
    );
    run_cmd(
        "iptables",
        &[
            "-A",
            "FORWARD",
            "-o",
            tap_device,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
    )?;
    // Allow guest → host traffic only to the gateway gRPC port.
    // Previous versions accepted ALL inbound traffic from the TAP
    // interface; scope to the specific port so the guest cannot reach
    // other host services.
    let port_str = gateway_port.to_string();
    let _ = run_cmd(
        "iptables",
        &[
            "-D", "INPUT", "-i", tap_device, "-p", "tcp", "--dport", &port_str, "-j", "ACCEPT",
        ],
    );
    run_cmd(
        "iptables",
        &[
            "-A", "INPUT", "-i", tap_device, "-p", "tcp", "--dport", &port_str, "-j", "ACCEPT",
        ],
    )?;

    Ok(())
}

fn teardown_tap_networking(tap_device: &str, host_ip: &str, gateway_port: u16) {
    let subnet = tap_subnet_from_host_ip(host_ip);
    let _ = run_cmd(
        "iptables",
        &[
            "-D",
            "FORWARD",
            "-o",
            tap_device,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
    );
    let _ = run_cmd(
        "iptables",
        &["-D", "FORWARD", "-i", tap_device, "-j", "ACCEPT"],
    );
    // Remove the port-scoped INPUT rule. Also try the legacy blanket
    // rule so stale rules from older driver versions are cleaned up.
    if gateway_port > 0 {
        let port_str = gateway_port.to_string();
        let _ = run_cmd(
            "iptables",
            &[
                "-D", "INPUT", "-i", tap_device, "-p", "tcp", "--dport", &port_str, "-j", "ACCEPT",
            ],
        );
    }
    let _ = run_cmd(
        "iptables",
        &["-D", "INPUT", "-i", tap_device, "-j", "ACCEPT"],
    );
    let _ = run_cmd(
        "iptables",
        &[
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            &subnet,
            "-j",
            "MASQUERADE",
        ],
    );
    let _ = run_cmd("ip", &["link", "set", tap_device, "down"]);
    let _ = run_cmd("ip", &["tuntap", "del", "dev", tap_device, "mode", "tap"]);
}

fn tap_subnet_from_host_ip(host_ip: &str) -> String {
    if let Ok(ip) = host_ip.parse::<std::net::Ipv4Addr>() {
        let base = u32::from(ip) & !3;
        let base_ip = std::net::Ipv4Addr::from(base);
        format!("{base_ip}/30")
    } else {
        format!("{host_ip}/30")
    }
}

fn enable_ip_forwarding() -> Result<(), String> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
        .map_err(|e| format!("enable ip_forward: {e}"))
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<(), String> {
    let output = StdCommand::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("failed to run {cmd}: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("{cmd} {} failed: {stderr}", args.join(" ")))
    }
}

/// RAII guard that tears down TAP networking on drop.
struct TapGuard {
    tap_device: String,
    host_ip: String,
    gateway_port: u16,
    disarmed: bool,
}

impl TapGuard {
    fn new(tap_device: String, host_ip: String, gateway_port: u16) -> Self {
        Self {
            tap_device,
            host_ip,
            gateway_port,
            disarmed: false,
        }
    }

    fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl Drop for TapGuard {
    fn drop(&mut self) {
        if !self.disarmed {
            teardown_tap_networking(&self.tap_device, &self.host_ip, self.gateway_port);
        }
    }
}

/// Shared procguard cleanup callback for both libkrun and QEMU paths.
/// Only async-signal-safe calls: atomic loads and `kill(2)`.
fn procguard_kill_children() {
    let helper_pid = GVPROXY_PID.load(Ordering::Relaxed);
    let child_pid = CHILD_PID.load(Ordering::Relaxed);
    if helper_pid > 0 {
        unsafe {
            libc::kill(helper_pid, libc::SIGTERM);
        }
    }
    if child_pid > 0 {
        unsafe {
            libc::kill(child_pid, libc::SIGTERM);
        }
    }
    std::thread::sleep(Duration::from_millis(200));
    if helper_pid > 0 {
        unsafe {
            libc::kill(helper_pid, libc::SIGKILL);
        }
    }
    if child_pid > 0 {
        unsafe {
            libc::kill(child_pid, libc::SIGKILL);
        }
    }
}

fn run_libkrun_vm(config: &VmLaunchConfig) -> Result<(), String> {
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
