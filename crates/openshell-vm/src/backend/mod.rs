// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! VM backend abstraction layer.
//!
//! Defines the [`VmBackend`] trait that all hypervisor backends implement,
//! and shared infrastructure (gvproxy startup, networking helpers) used by
//! the libkrun and QEMU backends.

pub mod libkrun;
pub mod qemu;

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::{
    GvproxyGuard, NetBackend, VmConfig, VmError, gvproxy_expose, gvproxy_socket_dir,
    kill_stale_gvproxy, kill_stale_gvproxy_by_port, pick_gvproxy_ssh_port, vm_rootfs_key,
};

/// Trait implemented by each hypervisor backend (libkrun, QEMU).
pub trait VmBackend {
    /// Launch a VM with the given configuration.
    ///
    /// Returns the VM exit code.
    fn launch(&self, config: &VmConfig) -> Result<i32, VmError>;
}

/// Result of starting a gvproxy instance, used by both backends.
pub(crate) struct GvproxySetup {
    pub(crate) guard: GvproxyGuard,
    pub(crate) api_sock: PathBuf,
    pub(crate) net_sock: PathBuf,
}

/// Start gvproxy for the given configuration.
///
/// Shared between libkrun and QEMU backends. Handles stale process
/// cleanup, socket setup, and process spawning with exponential backoff
/// waiting for the network socket.
pub(crate) fn start_gvproxy(
    config: &VmConfig,
    launch_start: Instant,
) -> Result<GvproxySetup, VmError> {
    let binary = match &config.net {
        NetBackend::Gvproxy { binary } => binary,
        _ => {
            return Err(VmError::HostSetup(
                "start_gvproxy called without Gvproxy net backend".into(),
            ));
        }
    };

    if !binary.exists() {
        return Err(VmError::BinaryNotFound {
            path: binary.display().to_string(),
            hint: "Install Podman Desktop or place gvproxy in PATH".to_string(),
        });
    }

    let run_dir = config
        .rootfs
        .parent()
        .unwrap_or(&config.rootfs)
        .to_path_buf();
    let rootfs_key = vm_rootfs_key(&config.rootfs);
    let sock_base = gvproxy_socket_dir(&config.rootfs)?;
    let net_sock = sock_base.with_extension("v");
    let api_sock = sock_base.with_extension("a");

    kill_stale_gvproxy(&config.rootfs);
    for pm in &config.port_map {
        if let Some(host_port) = pm.split(':').next().and_then(|p| p.parse::<u16>().ok()) {
            kill_stale_gvproxy_by_port(host_port);
        }
    }

    let _ = std::fs::remove_file(&net_sock);
    let _ = std::fs::remove_file(&api_sock);
    let krun_sock = sock_base.with_extension("v-krun.sock");
    let _ = std::fs::remove_file(&krun_sock);

    eprintln!("Starting gvproxy: {}", binary.display());
    let ssh_port = pick_gvproxy_ssh_port()?;
    let gvproxy_log = run_dir.join(format!("{rootfs_key}-gvproxy.log"));
    let gvproxy_log_file = std::fs::File::create(&gvproxy_log)
        .map_err(|e| VmError::Fork(format!("failed to create gvproxy log: {e}")))?;

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

    {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut interval = Duration::from_millis(5);
        while !net_sock.exists() {
            if Instant::now() >= deadline {
                return Err(VmError::Fork(
                    "gvproxy socket did not appear within 5s".to_string(),
                ));
            }
            std::thread::sleep(interval);
            interval = (interval * 2).min(Duration::from_millis(100));
        }
    }

    Ok(GvproxySetup {
        guard: GvproxyGuard::new(child),
        api_sock,
        net_sock,
    })
}

/// Set up port forwarding via the gvproxy HTTP API.
///
/// Translates `host:guest` port map entries into gvproxy expose calls.
pub(crate) fn setup_gvproxy_port_forwarding(
    api_sock: &Path,
    port_map: &[String],
) -> Result<(), VmError> {
    let fwd_start = Instant::now();
    {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut interval = Duration::from_millis(5);
        while !api_sock.exists() {
            if Instant::now() >= deadline {
                eprintln!("warning: gvproxy API socket not ready after 2s, attempting anyway");
                break;
            }
            std::thread::sleep(interval);
            interval = (interval * 2).min(Duration::from_millis(200));
        }
    }

    let guest_ip = "192.168.127.2";

    for pm in port_map {
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

        let mut expose_ok = false;
        let mut retry_interval = Duration::from_millis(100);
        let expose_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match gvproxy_expose(api_sock, &expose_body) {
                Ok(()) => {
                    eprintln!("  port {host_port} -> {guest_ip}:{guest_port}");
                    expose_ok = true;
                    break;
                }
                Err(e) => {
                    if Instant::now() >= expose_deadline {
                        eprintln!("  port {host_port}: {e} (retries exhausted)");
                        break;
                    }
                    std::thread::sleep(retry_interval);
                    retry_interval = (retry_interval * 2).min(Duration::from_secs(1));
                }
            }
        }
        if !expose_ok {
            return Err(VmError::HostSetup(format!(
                "failed to forward port {host_port} via gvproxy"
            )));
        }
    }
    eprintln!(
        "Port forwarding ready [{:.1}s]",
        fwd_start.elapsed().as_secs_f64()
    );

    Ok(())
}

// ── TAP networking constants ────────────────────────────────────────────
// The QEMU backend uses 192.168.249.1/24 on the host side of the TAP
// device. The guest uses .2 with the host as its gateway.

/// Fixed MAC for the guest TAP interface. Only one VM runs per host.
pub(crate) const GUEST_MAC: &str = "5a:94:ef:e4:0c:ee";

pub(crate) const TAP_HOST_IP: &str = "192.168.249.1";
pub(crate) const TAP_GUEST_IP: &str = "192.168.249.2";
pub(crate) const TAP_SUBNET: &str = "192.168.249.0/24";

/// Wait for a Unix socket to appear on the filesystem.
pub(crate) fn wait_for_socket(
    socket_path: &Path,
    label: &str,
    timeout: Duration,
) -> Result<(), VmError> {
    let deadline = Instant::now() + timeout;
    let mut interval = Duration::from_millis(10);

    while !socket_path.exists() {
        if Instant::now() >= deadline {
            return Err(VmError::HostSetup(format!(
                "{label} socket did not appear within {}s: {}",
                timeout.as_secs(),
                socket_path.display(),
            )));
        }
        std::thread::sleep(interval);
        interval = (interval * 2).min(Duration::from_millis(200));
    }

    Ok(())
}

/// Run a command, returning an error if it fails.
pub(crate) fn run_cmd(cmd: &str, args: &[&str]) -> Result<(), VmError> {
    let output = std::process::Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| VmError::HostSetup(format!("{cmd}: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VmError::HostSetup(format!(
            "{cmd} {}: {}",
            args.join(" "),
            stderr.trim()
        )));
    }

    Ok(())
}

/// Escape a string for use in a shell script.
///
/// Uses an allowlist of safe characters; anything outside the list gets
/// single-quoted. Single quotes inside the value are escaped with the
/// standard `'\''` idiom.
pub(crate) fn shell_escape(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    if s.bytes().all(|b| {
        matches!(b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'_' | b'-' | b'.' | b'/' | b':' | b'@' | b'='
        )
    }) {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Parse a DNS server from resolv.conf content.
///
/// Returns the first non-`127.x.x.x` nameserver, or `8.8.8.8` if none found.
pub(crate) fn parse_dns_server(content: &str) -> String {
    content
        .lines()
        .filter(|line| line.starts_with("nameserver"))
        .filter_map(|line| line.split_whitespace().nth(1))
        .find(|ip| !ip.starts_with("127."))
        .map(String::from)
        .unwrap_or_else(|| "8.8.8.8".to_string())
}

/// Read the host's primary DNS server.
///
/// Checks `/etc/resolv.conf` first. If every nameserver there is a loopback
/// address (e.g. systemd-resolved's `127.0.0.53`), falls back to the
/// upstream resolv.conf at `/run/systemd/resolve/resolv.conf` which
/// contains the real upstream nameservers. Final fallback is `8.8.8.8`.
pub(crate) fn host_dns_server() -> String {
    for path in &["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"] {
        if let Ok(content) = std::fs::read_to_string(path) {
            let server = parse_dns_server(&content);
            if server != "8.8.8.8" {
                return server;
            }
        }
    }
    "8.8.8.8".to_string()
}

// ── Kernel command line ─────────────────────────────────────────────────

/// Build the kernel command line shared by all backends that use virtiofs
/// rootfs and the standard init path.
pub(crate) fn build_kernel_cmdline(
    config: &VmConfig,
    effective_exec_path: &str,
    use_tap_net: bool,
) -> String {
    let mut parts = vec![
        "console=ttyS0".to_string(),
        "root=rootfs".to_string(),
        "rootfstype=virtiofs".to_string(),
        "rw".to_string(),
        "panic=-1".to_string(),
        format!("init={effective_exec_path}"),
    ];

    if config.gpu_enabled && config.vfio_device.is_some() {
        parts.push("GPU_ENABLED=true".to_string());
        // Tell the kernel firmware loader to search /lib/firmware explicitly.
        // The init script stages firmware to tmpfs and overrides this via
        // sysfs, but the cmdline provides an early fallback so
        // request_firmware() can find GSP blobs on the virtiofs rootfs even
        // before init runs the staging logic.
        parts.push("firmware_class.path=/lib/firmware".to_string());
    }
    if let Some(state_disk) = &config.state_disk {
        parts.push(format!(
            "OPENSHELL_VM_STATE_DISK_DEVICE={}",
            state_disk.guest_device
        ));
    }
    for var in &config.env {
        if var.contains('=') && !var.contains(' ') && !var.contains('"') {
            parts.push(var.clone());
        }
    }

    if use_tap_net {
        parts.push(format!("VM_NET_IP={TAP_GUEST_IP}"));
        parts.push(format!("VM_NET_GW={TAP_HOST_IP}"));
        parts.push(format!("VM_NET_DNS={}", host_dns_server()));
    }

    parts.join(" ")
}

// ── TAP host networking ─────────────────────────────────────────────────

/// Set up host-side networking so the guest can reach the internet via TAP.
///
/// 1. Enable IP forwarding (saving the original value for teardown)
/// 2. MASQUERADE outbound traffic from the VM subnet
/// 3. Allow forwarding to/from the VM subnet
///
/// Returns the original value of `ip_forward` so the caller can restore it.
pub(crate) fn setup_tap_host_networking() -> Result<String, VmError> {
    let original_ip_forward = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "0".to_string());

    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
        .map_err(|e| VmError::HostSetup(format!("enable IP forwarding: {e}")))?;

    let _ = run_cmd(
        "iptables",
        &[
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            TAP_SUBNET,
            "!",
            "-d",
            TAP_SUBNET,
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
            TAP_SUBNET,
            "!",
            "-d",
            TAP_SUBNET,
            "-j",
            "MASQUERADE",
        ],
    )?;

    let _ = run_cmd(
        "iptables",
        &["-D", "FORWARD", "-s", TAP_SUBNET, "-j", "ACCEPT"],
    );
    run_cmd(
        "iptables",
        &["-A", "FORWARD", "-s", TAP_SUBNET, "-j", "ACCEPT"],
    )?;

    let _ = run_cmd(
        "iptables",
        &["-D", "FORWARD", "-d", TAP_SUBNET, "-j", "ACCEPT"],
    );
    run_cmd(
        "iptables",
        &["-A", "FORWARD", "-d", TAP_SUBNET, "-j", "ACCEPT"],
    )?;

    eprintln!("host networking: IP forwarding + NAT masquerade for {TAP_SUBNET}");
    Ok(original_ip_forward)
}

/// Remove the iptables rules added by [`setup_tap_host_networking`] and
/// restore the original `ip_forward` sysctl value.
pub(crate) fn teardown_tap_host_networking(original_ip_forward: &str) {
    let _ = run_cmd(
        "iptables",
        &[
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            TAP_SUBNET,
            "!",
            "-d",
            TAP_SUBNET,
            "-j",
            "MASQUERADE",
        ],
    );
    let _ = run_cmd(
        "iptables",
        &["-D", "FORWARD", "-s", TAP_SUBNET, "-j", "ACCEPT"],
    );
    let _ = run_cmd(
        "iptables",
        &["-D", "FORWARD", "-d", TAP_SUBNET, "-j", "ACCEPT"],
    );
    if original_ip_forward != "1" {
        let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", original_ip_forward);
    }
    eprintln!(
        "host networking: cleaned up iptables rules, restored ip_forward={original_ip_forward}"
    );
}

// ── TCP port forwarding ─────────────────────────────────────────────────

/// Start a background TCP proxy that forwards `127.0.0.1:{host_port}`
/// to `{guest_ip}:{guest_port}`.
///
/// Each accepted connection spawns two threads for bidirectional copy.
/// The listener thread runs until the process exits.
pub(crate) fn start_tcp_port_forwarder(
    host_port: u16,
    guest_ip: &str,
    guest_port: u16,
) -> Result<(), VmError> {
    use std::net::{TcpListener, TcpStream};

    let listener = TcpListener::bind(("127.0.0.1", host_port))
        .map_err(|e| VmError::HostSetup(format!("bind port forwarder on :{host_port}: {e}")))?;

    let guest_addr = format!("{guest_ip}:{guest_port}");
    eprintln!("port forwarder: 127.0.0.1:{host_port} -> {guest_addr}");

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let client = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };

            let addr = guest_addr.clone();
            std::thread::spawn(move || {
                if let Ok(remote) = TcpStream::connect(&addr) {
                    forward_tcp_bidirectional(client, remote);
                }
            });
        }
    });

    Ok(())
}

/// Copy data bidirectionally between two TCP streams until either side closes.
fn forward_tcp_bidirectional(client: std::net::TcpStream, remote: std::net::TcpStream) {
    let Ok(mut client_r) = client.try_clone() else {
        return;
    };
    let mut client_w = client;
    let Ok(mut remote_r) = remote.try_clone() else {
        return;
    };
    let mut remote_w = remote;

    std::thread::spawn(move || {
        let _ = std::io::copy(&mut client_r, &mut remote_w);
    });
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut remote_r, &mut client_w);
    });
}

// ── Bidirectional Unix stream bridge ────────────────────────────────────

/// Spawn two threads that copy data between two Unix streams.
pub(crate) fn bridge_bidirectional(client: UnixStream, guest: UnixStream) {
    let Ok(mut client_r) = client.try_clone() else {
        return;
    };
    let mut client_w = client;
    let Ok(mut guest_r) = guest.try_clone() else {
        return;
    };
    let mut guest_w = guest;

    std::thread::spawn(move || {
        let _ = std::io::copy(&mut client_r, &mut guest_w);
    });
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut guest_r, &mut client_w);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dns_server_returns_first_non_loopback() {
        let content = "nameserver 10.0.0.1\nnameserver 8.8.8.8\n";
        assert_eq!(parse_dns_server(content), "10.0.0.1");
    }

    #[test]
    fn parse_dns_server_skips_systemd_resolved() {
        let content = "nameserver 127.0.0.53\nnameserver 1.1.1.1\n";
        assert_eq!(parse_dns_server(content), "1.1.1.1");
    }

    #[test]
    fn parse_dns_server_skips_all_loopback_variants() {
        let content = "nameserver 127.0.0.1\nnameserver 127.0.0.53\nnameserver 172.16.0.1\n";
        assert_eq!(parse_dns_server(content), "172.16.0.1");
    }

    #[test]
    fn parse_dns_server_falls_back_when_only_loopback() {
        let content = "nameserver 127.0.0.1\nnameserver 127.0.0.53\n";
        assert_eq!(parse_dns_server(content), "8.8.8.8");
    }

    #[test]
    fn parse_dns_server_handles_empty_content() {
        assert_eq!(parse_dns_server(""), "8.8.8.8");
    }

    #[test]
    fn parse_dns_server_ignores_comments_and_other_lines() {
        let content = "# Generated by NetworkManager\nsearch example.com\nnameserver 10.1.2.3\n";
        assert_eq!(parse_dns_server(content), "10.1.2.3");
    }

    #[test]
    fn shell_escape_empty_string() {
        assert_eq!(shell_escape(""), "''");
    }

    #[test]
    fn shell_escape_simple_string() {
        assert_eq!(shell_escape("hello"), "hello");
    }

    #[test]
    fn shell_escape_string_with_single_quotes() {
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn shell_escape_string_with_spaces() {
        assert_eq!(shell_escape("hello world"), "'hello world'");
    }

    #[test]
    fn shell_escape_string_with_double_quotes() {
        assert_eq!(shell_escape(r#"say "hi""#), r#"'say "hi"'"#);
    }

    #[test]
    fn shell_escape_string_with_backslash() {
        assert_eq!(shell_escape("path\\to"), "'path\\to'");
    }
}
