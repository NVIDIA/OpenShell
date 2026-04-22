// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! VM backend abstraction layer.
//!
//! Defines the [`VmBackend`] trait that all hypervisor backends implement,
//! and shared infrastructure (gvproxy startup, networking helpers) used by
//! both the libkrun and cloud-hypervisor backends.

pub mod cloud_hypervisor;
pub mod libkrun;

use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::{
    GvproxyGuard, NetBackend, VmConfig, VmError, gvproxy_expose, gvproxy_socket_dir,
    kill_stale_gvproxy, kill_stale_gvproxy_by_port, pick_gvproxy_ssh_port, vm_rootfs_key,
};

/// Trait implemented by each hypervisor backend (libkrun, cloud-hypervisor).
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
/// Shared between libkrun and cloud-hypervisor backends. Handles stale
/// process cleanup, socket setup, and process spawning with exponential
/// backoff waiting for the network socket.
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
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let mut interval = std::time::Duration::from_millis(5);
        while !net_sock.exists() {
            if Instant::now() >= deadline {
                return Err(VmError::Fork(
                    "gvproxy socket did not appear within 5s".to_string(),
                ));
            }
            std::thread::sleep(interval);
            interval = (interval * 2).min(std::time::Duration::from_millis(100));
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
        let deadline = Instant::now() + std::time::Duration::from_secs(2);
        let mut interval = std::time::Duration::from_millis(5);
        while !api_sock.exists() {
            if Instant::now() >= deadline {
                eprintln!("warning: gvproxy API socket not ready after 2s, attempting anyway");
                break;
            }
            std::thread::sleep(interval);
            interval = (interval * 2).min(std::time::Duration::from_millis(200));
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
        let mut retry_interval = std::time::Duration::from_millis(100);
        let expose_deadline = Instant::now() + std::time::Duration::from_secs(10);
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
                    retry_interval = (retry_interval * 2).min(std::time::Duration::from_secs(1));
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
