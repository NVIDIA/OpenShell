// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! cloud-hypervisor backend for GPU passthrough VMs.
//!
//! Uses the cloud-hypervisor REST API over a Unix socket to manage VMs
//! with VFIO device passthrough. This backend is Linux-only and requires
//! a separate kernel image (`vmlinux`) and `virtiofsd` for the root
//! filesystem.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::{
    GUEST_MAC, TAP_GUEST_IP, TAP_HOST_IP, TAP_NETMASK, VmBackend, bridge_bidirectional,
    build_kernel_cmdline, setup_tap_host_networking, shell_escape, start_tcp_port_forwarder,
    teardown_tap_host_networking, wait_for_socket,
};
use crate::exec::{
    VM_EXEC_VSOCK_PORT, clear_vm_runtime_state, vm_exec_socket_path, write_vm_runtime_state,
};
use crate::{NetBackend, VmConfig, VmError, vm_rootfs_key};

/// cloud-hypervisor hypervisor backend for GPU passthrough.
pub struct CloudHypervisorBackend {
    /// Path to the cloud-hypervisor binary.
    chv_binary: PathBuf,
    /// Path to the vmlinux kernel image.
    vmlinux: PathBuf,
    /// Path to the virtiofsd binary.
    virtiofsd: PathBuf,
}

impl CloudHypervisorBackend {
    /// Create a new cloud-hypervisor backend, validating required binaries.
    pub fn new() -> Result<Self, VmError> {
        let runtime_dir = crate::configured_runtime_dir()?;

        let chv_binary = runtime_dir.join("cloud-hypervisor");
        if !chv_binary.is_file() {
            return Err(VmError::BinaryNotFound {
                path: chv_binary.display().to_string(),
                hint: "GPU passthrough requires cloud-hypervisor. Run the GPU build pipeline or set OPENSHELL_VM_RUNTIME_DIR".to_string(),
            });
        }

        let vmlinux = runtime_dir.join("vmlinux");
        if !vmlinux.is_file() {
            return Err(VmError::BinaryNotFound {
                path: vmlinux.display().to_string(),
                hint: "GPU passthrough requires a vmlinux kernel. Run the GPU build pipeline"
                    .to_string(),
            });
        }

        let virtiofsd = runtime_dir.join("virtiofsd");
        if !virtiofsd.is_file() {
            return Err(VmError::BinaryNotFound {
                path: virtiofsd.display().to_string(),
                hint: "GPU passthrough requires virtiofsd. Run the GPU build pipeline".to_string(),
            });
        }

        Ok(Self {
            chv_binary,
            vmlinux,
            virtiofsd,
        })
    }
}

impl VmBackend for CloudHypervisorBackend {
    fn launch(&self, config: &VmConfig) -> Result<i32, VmError> {
        launch_cloud_hypervisor(self, config)
    }
}

// ── REST API client ─────────────────────────────────────────────────────

/// Send a raw HTTP/1.1 request over a Unix socket and return the response body.
///
/// Parses the response headers to determine Content-Length so we read exactly
/// the right number of bytes without relying on EOF or Connection: close.
fn http_request_unix(
    socket_path: &Path,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<(u16, String), String> {
    use std::io::BufRead;

    let stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("connect to cloud-hypervisor API: {e}"))?;

    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| format!("set read timeout: {e}"))?;

    let request = if let Some(body) = body {
        format!(
            "{method} {path} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {body}",
            body.len(),
        )
    } else {
        format!(
            "{method} {path} HTTP/1.1\r\n\
             Host: localhost\r\n\
             \r\n"
        )
    };

    {
        let mut writer = &stream;
        writer
            .write_all(request.as_bytes())
            .map_err(|e| format!("write to cloud-hypervisor API: {e}"))?;
    }

    let mut reader = std::io::BufReader::new(&stream);

    // Read status line
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .map_err(|e| format!("read status line: {e}"))?;

    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);

    // Read headers to find Content-Length
    let mut content_length: usize = 0;
    loop {
        let mut header_line = String::new();
        reader
            .read_line(&mut header_line)
            .map_err(|e| format!("read header: {e}"))?;
        if header_line.trim().is_empty() {
            break;
        }
        if let Some(val) = header_line
            .strip_prefix("Content-Length:")
            .or_else(|| header_line.strip_prefix("content-length:"))
        {
            if let Ok(len) = val.trim().parse::<usize>() {
                content_length = len;
            }
        }
    }

    // Read body based on Content-Length
    let mut body_bytes = vec![0u8; content_length];
    if content_length > 0 {
        reader
            .read_exact(&mut body_bytes)
            .map_err(|e| format!("read body ({content_length} bytes): {e}"))?;
    }

    let body_str = String::from_utf8_lossy(&body_bytes).to_string();
    Ok((status_code, body_str))
}

/// Create the VM via the cloud-hypervisor REST API.
fn api_vm_create(socket_path: &Path, payload: &str) -> Result<(), VmError> {
    let (status, body) = http_request_unix(socket_path, "PUT", "/api/v1/vm.create", Some(payload))
        .map_err(|e| VmError::HostSetup(format!("vm.create: {e}")))?;

    if status >= 200 && status < 300 {
        Ok(())
    } else {
        Err(VmError::HostSetup(format!(
            "vm.create returned HTTP {status}: {body}"
        )))
    }
}

/// Boot the VM.
fn api_vm_boot(socket_path: &Path) -> Result<(), VmError> {
    let (status, body) = http_request_unix(socket_path, "PUT", "/api/v1/vm.boot", None)
        .map_err(|e| VmError::HostSetup(format!("vm.boot: {e}")))?;

    if status >= 200 && status < 300 {
        Ok(())
    } else {
        Err(VmError::HostSetup(format!(
            "vm.boot returned HTTP {status}: {body}"
        )))
    }
}

/// Request a graceful shutdown.
fn api_vm_shutdown(socket_path: &Path) -> Result<(), VmError> {
    let (status, body) = http_request_unix(socket_path, "PUT", "/api/v1/vm.shutdown", None)
        .map_err(|e| VmError::HostSetup(format!("vm.shutdown: {e}")))?;

    if status >= 200 && status < 300 {
        Ok(())
    } else {
        Err(VmError::HostSetup(format!(
            "vm.shutdown returned HTTP {status}: {body}"
        )))
    }
}

/// Query VM info/status.
#[allow(dead_code)]
fn api_vm_info(socket_path: &Path) -> Result<String, VmError> {
    let (status, body) = http_request_unix(socket_path, "GET", "/api/v1/vm.info", None)
        .map_err(|e| VmError::HostSetup(format!("vm.info: {e}")))?;

    if status >= 200 && status < 300 {
        Ok(body)
    } else {
        Err(VmError::HostSetup(format!(
            "vm.info returned HTTP {status}: {body}"
        )))
    }
}

/// Delete the VM.
#[allow(dead_code)]
fn api_vm_delete(socket_path: &Path) -> Result<(), VmError> {
    let (status, body) = http_request_unix(socket_path, "PUT", "/api/v1/vm.delete", None)
        .map_err(|e| VmError::HostSetup(format!("vm.delete: {e}")))?;

    if status >= 200 && status < 300 {
        Ok(())
    } else {
        Err(VmError::HostSetup(format!(
            "vm.delete returned HTTP {status}: {body}"
        )))
    }
}

// ── Build the VM create payload ─────────────────────────────────────────

fn build_vm_create_payload(
    backend: &CloudHypervisorBackend,
    config: &VmConfig,
    effective_exec_path: &str,
    vfio_device: Option<&str>,
    virtiofsd_sock: &Path,
    state_disk_path: Option<&Path>,
    use_tap_net: bool,
    vsock_sock: &Path,
    console_log: &Path,
) -> Result<String, VmError> {
    let mem_bytes = u64::from(config.mem_mib) * 1024 * 1024;

    let cmdline = build_kernel_cmdline(config, effective_exec_path, use_tap_net);

    let mut payload = serde_json::json!({
        "cpus": {
            "boot_vcpus": config.vcpus,
            "max_vcpus": config.vcpus,
        },
        "memory": {
            "size": mem_bytes,
            "shared": true,
        },
        "payload": {
            "kernel": backend.vmlinux.display().to_string(),
            "cmdline": cmdline,
        },
        "fs": [{
            "tag": "rootfs",
            "socket": virtiofsd_sock.display().to_string(),
            "num_queues": 1,
            "queue_size": 1024,
        }],
        "vsock": {
            "cid": VSOCK_GUEST_CID,
            "socket": vsock_sock.display().to_string(),
        },
        "serial": {
            "mode": "File",
            "file": console_log.display().to_string(),
        },
        "console": {
            "mode": "Off",
        },
    });

    if let Some(disk_path) = state_disk_path {
        payload["disks"] = serde_json::json!([{
            "path": disk_path.display().to_string(),
            "readonly": false,
        }]);
    }

    // Cloud-hypervisor uses TAP devices for networking (requires root or
    // CAP_NET_ADMIN). The gvproxy QEMU-style socket protocol is not
    // compatible with CHV's NetConfig. GPU passthrough already requires
    // elevated privileges, so TAP access is expected.
    if use_tap_net {
        payload["net"] = serde_json::json!([{
            "mac": GUEST_MAC,
            "ip": TAP_HOST_IP,
            "mask": TAP_NETMASK,
        }]);
    }

    if let Some(vfio_path) = vfio_device {
        payload["devices"] = serde_json::json!([{
            "path": format!("/sys/bus/pci/devices/{vfio_path}/"),
        }]);
    }

    serde_json::to_string(&payload)
        .map_err(|e| VmError::HostSetup(format!("serialize vm.create payload: {e}")))
}

// ── Launch ──────────────────────────────────────────────────────────────

#[allow(clippy::similar_names)]
fn launch_cloud_hypervisor(
    backend: &CloudHypervisorBackend,
    config: &VmConfig,
) -> Result<i32, VmError> {
    let launch_start = Instant::now();

    let run_dir = config
        .rootfs
        .parent()
        .unwrap_or(&config.rootfs)
        .to_path_buf();
    let rootfs_key = vm_rootfs_key(&config.rootfs);

    // Unix domain sockets are limited to 108 characters (SUN_LEN).
    // Instance rootfs paths can be deeply nested, so place sockets
    // under /tmp to stay within the limit.
    let sock_dir = PathBuf::from(format!("/tmp/ovm-chv-{}", std::process::id()));
    std::fs::create_dir_all(&sock_dir).map_err(|e| {
        VmError::HostSetup(format!("create socket dir {}: {e}", sock_dir.display()))
    })?;

    let api_sock_path = sock_dir.join("api.sock");
    let vsock_sock_path = sock_dir.join("vsock.sock");
    let virtiofsd_sock_path = sock_dir.join("virtiofsd.sock");
    let console_log = config
        .console_output
        .clone()
        .unwrap_or_else(|| run_dir.join(format!("{rootfs_key}-console.log")));

    // Clean stale sockets
    let _ = std::fs::remove_file(&api_sock_path);
    let _ = std::fs::remove_file(&vsock_sock_path);
    let _ = std::fs::remove_file(&virtiofsd_sock_path);

    // Start virtiofsd for the rootfs
    eprintln!("Starting virtiofsd: {}", backend.virtiofsd.display());
    let virtiofsd_log = run_dir.join(format!("{rootfs_key}-virtiofsd.log"));
    let virtiofsd_log_file = std::fs::File::create(&virtiofsd_log)
        .map_err(|e| VmError::Fork(format!("create virtiofsd log: {e}")))?;

    let mut virtiofsd_cmd = std::process::Command::new(&backend.virtiofsd);
    virtiofsd_cmd
        .arg(format!("--socket-path={}", virtiofsd_sock_path.display()))
        .arg(format!("--shared-dir={}", config.rootfs.display()))
        .arg("--cache=always")
        .stdout(std::process::Stdio::null())
        .stderr(virtiofsd_log_file);
    #[allow(unsafe_code)]
    unsafe {
        virtiofsd_cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            Ok(())
        });
    }
    let mut virtiofsd_child = virtiofsd_cmd.spawn()
        .map_err(|e| VmError::Fork(format!("start virtiofsd: {e}")))?;

    eprintln!(
        "virtiofsd started (pid {}) [{:.1}s]",
        virtiofsd_child.id(),
        launch_start.elapsed().as_secs_f64()
    );

    // Wait for virtiofsd socket
    wait_for_socket(&virtiofsd_sock_path, "virtiofsd", Duration::from_secs(5))?;

    // CHV uses TAP networking (requires root/CAP_NET_ADMIN). The gvproxy
    // QEMU-style socket protocol is not compatible with cloud-hypervisor's
    // NetConfig. GPU passthrough already requires elevated privileges.
    let use_tap_net = !matches!(config.net, NetBackend::None);

    // For --exec mode: wrap the command so the VM powers off after it exits.
    // Unlike libkrun (which exits when init terminates), cloud-hypervisor
    // keeps running after PID 1 exits (kernel panics). A wrapper init script
    // runs the command then calls `poweroff -f` for a clean ACPI shutdown.
    let is_exec_mode = config.is_exec_mode();
    let wrapper_path = config.rootfs.join("tmp/chv-exec-wrapper.sh");
    let effective_exec_path;
    if is_exec_mode {
        let args_str = config
            .args
            .iter()
            .map(|a| shell_escape(a))
            .collect::<Vec<_>>()
            .join(" ");

        let env_str = config
            .env
            .iter()
            .map(|v| format!("export {}", shell_escape(v)))
            .collect::<Vec<_>>()
            .join("\n");

        let wrapper = format!(
            "#!/bin/sh\n\
             mount -t proc proc /proc 2>/dev/null\n\
             mount -t sysfs sysfs /sys 2>/dev/null\n\
             mount -t devtmpfs devtmpfs /dev 2>/dev/null\n\
             {env_str}\n\
             cd {workdir}\n\
             {exec} {args}\n\
             RC=$?\n\
             # Trigger ACPI power-off so cloud-hypervisor exits cleanly.\n\
             # The rootfs may not have a `poweroff` binary, so try multiple methods.\n\
             if command -v poweroff >/dev/null 2>&1; then\n\
               poweroff -f\n\
             elif [ -x /usr/bin/busybox ]; then\n\
               /usr/bin/busybox poweroff -f\n\
             else\n\
               echo o > /proc/sysrq-trigger\n\
             fi\n\
             exit $RC\n",
            env_str = env_str,
            workdir = shell_escape(&config.workdir),
            exec = shell_escape(&config.exec_path),
            args = args_str,
        );

        if let Some(parent) = wrapper_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| VmError::HostSetup(format!("create wrapper dir: {e}")))?;
        }
        std::fs::write(&wrapper_path, &wrapper)
            .map_err(|e| VmError::HostSetup(format!("write exec wrapper: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&wrapper_path, std::fs::Permissions::from_mode(0o755));
        }
        effective_exec_path = "/tmp/chv-exec-wrapper.sh".to_string();
    } else {
        effective_exec_path = config.exec_path.clone();
    }

    // Start cloud-hypervisor process
    eprintln!(
        "Starting cloud-hypervisor: {}",
        backend.chv_binary.display()
    );

    let chv_log = run_dir.join(format!("{rootfs_key}-cloud-hypervisor.log"));
    let chv_log_file = std::fs::File::create(&chv_log)
        .map_err(|e| VmError::Fork(format!("create cloud-hypervisor log: {e}")))?;

    let mut chv_cmd = std::process::Command::new(&backend.chv_binary);
    chv_cmd
        .arg("--api-socket")
        .arg(&api_sock_path)
        .stdout(std::process::Stdio::null())
        .stderr(chv_log_file);
    #[allow(unsafe_code)]
    unsafe {
        chv_cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            Ok(())
        });
    }
    let mut chv_child = chv_cmd.spawn()
        .map_err(|e| VmError::Fork(format!("start cloud-hypervisor: {e}")))?;

    let chv_pid = chv_child.id() as i32;
    eprintln!(
        "cloud-hypervisor started (pid {chv_pid}) [{:.1}s]",
        launch_start.elapsed().as_secs_f64()
    );

    // Wait for API socket
    wait_for_socket(&api_sock_path, "cloud-hypervisor", Duration::from_secs(10))?;

    // Build and send VM create payload
    let state_disk_path = config.state_disk.as_ref().map(|sd| sd.path.as_path());
    let payload = build_vm_create_payload(
        backend,
        config,
        &effective_exec_path,
        config.vfio_device.as_deref(),
        &virtiofsd_sock_path,
        state_disk_path,
        use_tap_net,
        &vsock_sock_path,
        &console_log,
    )?;

    api_vm_create(&api_sock_path, &payload)?;
    eprintln!("VM created [{:.1}s]", launch_start.elapsed().as_secs_f64());

    api_vm_boot(&api_sock_path)?;
    let boot_start = Instant::now();
    eprintln!("VM booting [{:.1}s]", launch_start.elapsed().as_secs_f64());

    // Set up host-side networking for TAP (NAT, IP forwarding, masquerade)
    // so the guest can reach the internet through the host.
    let mut original_ip_forward: Option<String> = None;
    if use_tap_net {
        match setup_tap_host_networking() {
            Ok(orig) => original_ip_forward = Some(orig),
            Err(e) => {
                eprintln!("WARNING: host networking setup failed: {e}");
                eprintln!("  The VM may not have internet access.");
            }
        }
    }

    // Write runtime state (vsock_bridge: true — CHV uses Unix socket vsock
    // bridging with a text protocol, not kernel AF_VSOCK)
    if !config.is_exec_mode() {
        if let Err(err) = write_vm_runtime_state(&config.rootfs, chv_pid, &console_log, None, true)
        {
            let _ = api_vm_shutdown(&api_sock_path);
            let _ = chv_child.kill();
            let _ = chv_child.wait();
            let _ = virtiofsd_child.kill();
            let _ = virtiofsd_child.wait();
            if let Some(ref orig) = original_ip_forward {
                teardown_tap_host_networking(orig);
            }
            clear_vm_runtime_state(&config.rootfs);
            return Err(err);
        }
    }

    let exec_socket = vm_exec_socket_path(&config.rootfs);
    // CHV TAP networking doesn't provide built-in port forwarding like
    // gvproxy. Start a TCP proxy for each port mapping so the host can
    // reach guest services (e.g., the gateway health check on :30051).
    if use_tap_net {
        for pm in &config.port_map {
            let parts: Vec<&str> = pm.split(':').collect();
            if parts.len() == 2 {
                if let (Ok(hp), Ok(gp)) = (parts[0].parse::<u16>(), parts[1].parse::<u16>()) {
                    if let Err(e) = start_tcp_port_forwarder(hp, TAP_GUEST_IP, gp) {
                        let _ = chv_child.kill();
                        let _ = chv_child.wait();
                        let _ = virtiofsd_child.kill();
                        let _ = virtiofsd_child.wait();
                        if let Some(ref orig) = original_ip_forward {
                            teardown_tap_host_networking(orig);
                        }
                        clear_vm_runtime_state(&config.rootfs);
                        let _ = std::fs::remove_dir_all(&sock_dir);
                        let _ = std::fs::remove_file(&exec_socket);
                        return Err(e);
                    }
                }
            }
        }
    }

    for pm in &config.port_map {
        let host_port = pm.split(':').next().unwrap_or(pm);
        eprintln!("  port {pm} -> http://localhost:{host_port}");
    }
    eprintln!("Console output: {}", console_log.display());

    // Start vsock exec bridge (exec Unix socket → CHV vsock Unix socket).
    // The bridge allows `openshell-vm exec` and bootstrap to communicate
    // with the guest exec agent over the standard exec socket path.
    start_vsock_exec_bridge(&exec_socket, &vsock_sock_path, VM_EXEC_VSOCK_PORT)?;

    // Gateway bootstrap and health check (mirrors libkrun backend).
    if !config.is_exec_mode() && !config.port_map.is_empty() {
        let gateway_port = crate::gateway_host_port(config);
        if let Err(e) = crate::bootstrap_gateway(&config.rootfs, &config.gateway_name, gateway_port)
            .and_then(|_| crate::health::wait_for_gateway_ready(gateway_port, &config.gateway_name))
        {
            let _ = chv_child.kill();
            let _ = chv_child.wait();
            let _ = virtiofsd_child.kill();
            let _ = virtiofsd_child.wait();
            if let Some(ref orig) = original_ip_forward {
                teardown_tap_host_networking(orig);
            }
            clear_vm_runtime_state(&config.rootfs);
            let _ = std::fs::remove_dir_all(&sock_dir);
            let _ = std::fs::remove_file(&exec_socket);
            return Err(e);
        }
    }

    eprintln!("Ready [{:.1}s total]", boot_start.elapsed().as_secs_f64());
    eprintln!("Press Ctrl+C to stop.");

    // Signal forwarding: SIGINT/SIGTERM -> graceful shutdown
    crate::CHILD_PID.store(chv_pid, std::sync::atomic::Ordering::Relaxed);
    unsafe {
        libc::signal(
            libc::SIGINT,
            crate::forward_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            crate::forward_signal as *const () as libc::sighandler_t,
        );
    }

    // Wait for cloud-hypervisor to exit
    let status = chv_child
        .wait()
        .map_err(|e| VmError::HostSetup(format!("wait for cloud-hypervisor: {e}")))?;
    crate::CHILD_PID.store(0, std::sync::atomic::Ordering::Relaxed);

    // Clean up host networking rules
    if let Some(ref orig) = original_ip_forward {
        teardown_tap_host_networking(orig);
    }

    // Cleanup
    if !config.is_exec_mode() {
        clear_vm_runtime_state(&config.rootfs);
    }
    let _ = virtiofsd_child.kill();
    let _ = virtiofsd_child.wait();
    eprintln!("virtiofsd stopped");

    // Clean up sockets and wrapper
    let _ = std::fs::remove_dir_all(&sock_dir);
    let _ = std::fs::remove_file(&exec_socket);
    if is_exec_mode {
        let _ = std::fs::remove_file(&wrapper_path);
    }

    let code = status.code().unwrap_or(1);
    eprintln!("VM exited with code {code}");
    Ok(code)
}

// ── Vsock exec bridge ───────────────────────────────────────────────────

/// Guest CID assigned in the cloud-hypervisor vsock config.
const VSOCK_GUEST_CID: u32 = 3;

/// Start a background bridge: exec Unix socket → CHV vsock Unix socket.
///
/// cloud-hypervisor exposes guest vsock via a host-side Unix socket with a
/// text protocol: connect to the socket, send `CONNECT <port>\n`, read
/// back `OK <port>\n`, then the stream is a raw bidirectional channel to
/// the guest vsock port. This is different from kernel `AF_VSOCK` (which
/// `vhost-vsock` uses) — CHV manages its own transport.
///
/// This bridge creates a Unix socket at `exec_socket` and, for each
/// incoming connection, opens a connection to the CHV vsock socket,
/// performs the CONNECT handshake, and forwards data bidirectionally.
fn start_vsock_exec_bridge(
    exec_socket: &Path,
    chv_vsock_socket: &Path,
    guest_port: u32,
) -> Result<(), VmError> {
    use std::os::unix::net::UnixListener;

    if let Some(parent) = exec_socket.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            VmError::HostSetup(format!("create exec bridge dir {}: {e}", parent.display()))
        })?;
    }
    let _ = std::fs::remove_file(exec_socket);

    let listener = UnixListener::bind(exec_socket).map_err(|e| {
        VmError::HostSetup(format!(
            "bind vsock exec bridge {}: {e}",
            exec_socket.display()
        ))
    })?;

    let chv_vsock = chv_vsock_socket.to_path_buf();
    eprintln!(
        "vsock exec bridge: {} → {} port {}",
        exec_socket.display(),
        chv_vsock.display(),
        guest_port,
    );

    std::thread::spawn(move || {
        vsock_bridge_accept_loop(listener, &chv_vsock, guest_port);
    });

    Ok(())
}

/// Accept loop for the vsock bridge background thread.
///
/// "CONNECT rejected" (empty response) is normal during boot — the guest
/// exec agent isn't listening yet. We keep retrying those indefinitely
/// since the bootstrap caller has its own 120s timeout. Only fatal errors
/// (socket gone = VM died) cause the bridge to give up.
fn vsock_bridge_accept_loop(
    listener: std::os::unix::net::UnixListener,
    chv_vsock_socket: &Path,
    port: u32,
) {
    let mut fatal_failures: u32 = 0;
    let mut logged_transient = false;

    for stream in listener.incoming() {
        let client = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("vsock bridge: accept: {e}");
                continue;
            }
        };

        match chv_vsock_connect(chv_vsock_socket, port) {
            Ok(guest) => {
                fatal_failures = 0;
                bridge_bidirectional(client, guest);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fatal_failures += 1;
                if fatal_failures <= 2 {
                    eprintln!("vsock bridge: CHV socket gone (VM exited?): {e}");
                }
                if fatal_failures >= 3 {
                    eprintln!("vsock bridge: CHV socket not found, stopping bridge");
                    return;
                }
            }
            Err(e) => {
                if !logged_transient {
                    eprintln!(
                        "vsock bridge: guest not ready on port {port} ({e}), \
                         will keep retrying..."
                    );
                    logged_transient = true;
                }
            }
        }
    }
}

/// Connect to a guest vsock port via cloud-hypervisor's Unix socket protocol.
///
/// CHV exposes guest vsock through a host Unix socket. The protocol is:
///   1. Connect to the CHV vsock Unix socket
///   2. Send: `CONNECT <port>\n`
///   3. Read: `OK <port>\n` on success
///   4. The stream is now a raw bidirectional channel to the guest port
fn chv_vsock_connect(chv_vsock_socket: &Path, port: u32) -> std::io::Result<UnixStream> {
    let mut stream = UnixStream::connect(chv_vsock_socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let connect_msg = format!("CONNECT {port}\n");
    stream.write_all(connect_msg.as_bytes())?;

    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf)?;
    let response = std::str::from_utf8(&buf[..n]).unwrap_or("");

    if !response.starts_with("OK") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("CHV vsock CONNECT rejected: {}", response.trim()),
        ));
    }

    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_request_format_with_body() {
        let payload = r#"{"cpus":{"boot_vcpus":4}}"#;
        let request = format!(
            "PUT /api/v1/vm.create HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {payload}",
            payload.len(),
        );
        assert!(request.contains("Content-Length: 25"));
        assert!(request.contains("boot_vcpus"));
    }

    #[test]
    fn http_request_format_without_body() {
        let request = format!(
            "GET /api/v1/vm.info HTTP/1.1\r\n\
             Host: localhost\r\n\
             Connection: close\r\n\
             \r\n"
        );
        assert!(request.contains("GET /api/v1/vm.info"));
        assert!(!request.contains("Content-Length"));
    }

    #[test]
    fn build_payload_includes_vfio_device() {
        use crate::{NetBackend, VmConfig};

        let config = VmConfig {
            rootfs: "/tmp/rootfs".into(),
            vcpus: 4,
            mem_mib: 8192,
            exec_path: "/srv/openshell-vm-init.sh".into(),
            args: vec![],
            env: vec![],
            workdir: "/".into(),
            port_map: vec![],
            vsock_ports: vec![],
            log_level: 1,
            console_output: None,
            net: NetBackend::None,
            reset: false,
            gateway_name: "test".into(),
            state_disk: None,
            gpu_enabled: true,
            gpu_has_msix: true,
            vfio_device: Some("0000:41:00.0".into()),
            backend: crate::VmBackendChoice::CloudHypervisor,
        };

        let backend = CloudHypervisorBackend {
            chv_binary: "/usr/bin/cloud-hypervisor".into(),
            vmlinux: "/boot/vmlinux".into(),
            virtiofsd: "/usr/bin/virtiofsd".into(),
        };

        let payload = build_vm_create_payload(
            &backend,
            &config,
            &config.exec_path,
            config.vfio_device.as_deref(),
            Path::new("/tmp/virtiofsd.sock"),
            None,
            false,
            Path::new("/tmp/vsock.sock"),
            Path::new("/tmp/console.log"),
        )
        .unwrap();

        assert!(
            payload.contains("0000:41:00.0"),
            "payload should contain VFIO device"
        );
        assert!(
            payload.contains("boot_vcpus"),
            "payload should contain vcpus config"
        );
        assert!(
            payload.contains("GPU_ENABLED=true"),
            "payload should contain GPU_ENABLED in cmdline"
        );
    }

    #[test]
    fn build_payload_without_vfio() {
        use crate::{NetBackend, VmConfig};

        let config = VmConfig {
            rootfs: "/tmp/rootfs".into(),
            vcpus: 2,
            mem_mib: 4096,
            exec_path: "/srv/openshell-vm-init.sh".into(),
            args: vec![],
            env: vec![],
            workdir: "/".into(),
            port_map: vec![],
            vsock_ports: vec![],
            log_level: 1,
            console_output: None,
            net: NetBackend::None,
            reset: false,
            gateway_name: "test".into(),
            state_disk: None,
            gpu_enabled: false,
            gpu_has_msix: true,
            vfio_device: None,
            backend: crate::VmBackendChoice::Auto,
        };

        let backend = CloudHypervisorBackend {
            chv_binary: "/usr/bin/cloud-hypervisor".into(),
            vmlinux: "/boot/vmlinux".into(),
            virtiofsd: "/usr/bin/virtiofsd".into(),
        };

        let payload = build_vm_create_payload(
            &backend,
            &config,
            &config.exec_path,
            None,
            Path::new("/tmp/virtiofsd.sock"),
            None,
            false,
            Path::new("/tmp/vsock.sock"),
            Path::new("/tmp/console.log"),
        )
        .unwrap();

        assert!(
            !payload.contains("devices"),
            "payload without VFIO should not have devices key"
        );
        assert!(
            !payload.contains("GPU_ENABLED"),
            "payload should not contain GPU_ENABLED"
        );
    }

    #[test]
    fn build_payload_with_tap_net_includes_ip_and_cmdline() {
        use crate::{NetBackend, VmConfig};

        let config = VmConfig {
            rootfs: "/tmp/rootfs".into(),
            vcpus: 4,
            mem_mib: 8192,
            exec_path: "/srv/openshell-vm-init.sh".into(),
            args: vec![],
            env: vec![],
            workdir: "/".into(),
            port_map: vec!["30051:30051".into()],
            vsock_ports: vec![],
            log_level: 1,
            console_output: None,
            net: NetBackend::Gvproxy {
                binary: "/usr/bin/gvproxy".into(),
            },
            reset: false,
            gateway_name: "test".into(),
            state_disk: None,
            gpu_enabled: true,
            gpu_has_msix: true,
            vfio_device: Some("0000:41:00.0".into()),
            backend: crate::VmBackendChoice::CloudHypervisor,
        };

        let backend = CloudHypervisorBackend {
            chv_binary: "/usr/bin/cloud-hypervisor".into(),
            vmlinux: "/boot/vmlinux".into(),
            virtiofsd: "/usr/bin/virtiofsd".into(),
        };

        let payload = build_vm_create_payload(
            &backend,
            &config,
            &config.exec_path,
            config.vfio_device.as_deref(),
            Path::new("/tmp/virtiofsd.sock"),
            None,
            true, // use_tap_net
            Path::new("/tmp/vsock.sock"),
            Path::new("/tmp/console.log"),
        )
        .unwrap();

        assert!(
            payload.contains("192.168.249.1"),
            "net should contain TAP host IP"
        );
        assert!(
            payload.contains("255.255.255.0"),
            "net should contain TAP netmask"
        );
        assert!(
            payload.contains("VM_NET_IP=192.168.249.2"),
            "cmdline should contain guest IP"
        );
        assert!(
            payload.contains("VM_NET_GW=192.168.249.1"),
            "cmdline should contain gateway IP"
        );
        assert!(
            payload.contains("VM_NET_DNS="),
            "cmdline should contain DNS server"
        );
    }

    #[test]
    fn build_payload_tap_net_false_omits_net_and_vm_net_vars() {
        use crate::{NetBackend, VmConfig};

        let config = VmConfig {
            rootfs: "/tmp/rootfs".into(),
            vcpus: 2,
            mem_mib: 4096,
            exec_path: "/srv/openshell-vm-init.sh".into(),
            args: vec![],
            env: vec![],
            workdir: "/".into(),
            port_map: vec![],
            vsock_ports: vec![],
            log_level: 1,
            console_output: None,
            net: NetBackend::None,
            reset: false,
            gateway_name: "test".into(),
            state_disk: None,
            gpu_enabled: false,
            gpu_has_msix: true,
            vfio_device: None,
            backend: crate::VmBackendChoice::Auto,
        };

        let backend = CloudHypervisorBackend {
            chv_binary: "/usr/bin/cloud-hypervisor".into(),
            vmlinux: "/boot/vmlinux".into(),
            virtiofsd: "/usr/bin/virtiofsd".into(),
        };

        let payload = build_vm_create_payload(
            &backend,
            &config,
            &config.exec_path,
            None,
            Path::new("/tmp/virtiofsd.sock"),
            None,
            false,
            Path::new("/tmp/vsock.sock"),
            Path::new("/tmp/console.log"),
        )
        .unwrap();

        assert!(
            !payload.contains("\"net\""),
            "no-tap payload should not contain net section"
        );
        assert!(
            !payload.contains("VM_NET_IP"),
            "no-tap payload should not contain VM_NET_IP"
        );
        assert!(
            !payload.contains("VM_NET_GW"),
            "no-tap payload should not contain VM_NET_GW"
        );
        assert!(
            !payload.contains("VM_NET_DNS"),
            "no-tap payload should not contain VM_NET_DNS"
        );
    }

    #[test]
    fn build_payload_tap_net_has_correct_mac_ip_mask() {
        use crate::{NetBackend, VmConfig};

        let config = VmConfig {
            rootfs: "/tmp/rootfs".into(),
            vcpus: 2,
            mem_mib: 4096,
            exec_path: "/srv/openshell-vm-init.sh".into(),
            args: vec![],
            env: vec![],
            workdir: "/".into(),
            port_map: vec![],
            vsock_ports: vec![],
            log_level: 1,
            console_output: None,
            net: NetBackend::Gvproxy {
                binary: "/usr/bin/gvproxy".into(),
            },
            reset: false,
            gateway_name: "test".into(),
            state_disk: None,
            gpu_enabled: false,
            gpu_has_msix: true,
            vfio_device: None,
            backend: crate::VmBackendChoice::CloudHypervisor,
        };

        let backend = CloudHypervisorBackend {
            chv_binary: "/usr/bin/cloud-hypervisor".into(),
            vmlinux: "/boot/vmlinux".into(),
            virtiofsd: "/usr/bin/virtiofsd".into(),
        };

        let payload = build_vm_create_payload(
            &backend,
            &config,
            &config.exec_path,
            None,
            Path::new("/tmp/virtiofsd.sock"),
            None,
            true,
            Path::new("/tmp/vsock.sock"),
            Path::new("/tmp/console.log"),
        )
        .unwrap();

        let json: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let net = &json["net"][0];
        assert_eq!(net["mac"], GUEST_MAC);
        assert_eq!(net["ip"], "192.168.249.1");
        assert_eq!(net["mask"], "255.255.255.0");
    }

    #[test]
    fn build_payload_vfio_and_tap_net_coexist() {
        use crate::{NetBackend, VmConfig};

        let config = VmConfig {
            rootfs: "/tmp/rootfs".into(),
            vcpus: 4,
            mem_mib: 8192,
            exec_path: "/srv/openshell-vm-init.sh".into(),
            args: vec![],
            env: vec![],
            workdir: "/".into(),
            port_map: vec![],
            vsock_ports: vec![],
            log_level: 1,
            console_output: None,
            net: NetBackend::Gvproxy {
                binary: "/usr/bin/gvproxy".into(),
            },
            reset: false,
            gateway_name: "test".into(),
            state_disk: None,
            gpu_enabled: true,
            gpu_has_msix: true,
            vfio_device: Some("0000:41:00.0".into()),
            backend: crate::VmBackendChoice::CloudHypervisor,
        };

        let backend = CloudHypervisorBackend {
            chv_binary: "/usr/bin/cloud-hypervisor".into(),
            vmlinux: "/boot/vmlinux".into(),
            virtiofsd: "/usr/bin/virtiofsd".into(),
        };

        let payload = build_vm_create_payload(
            &backend,
            &config,
            &config.exec_path,
            config.vfio_device.as_deref(),
            Path::new("/tmp/virtiofsd.sock"),
            None,
            true,
            Path::new("/tmp/vsock.sock"),
            Path::new("/tmp/console.log"),
        )
        .unwrap();

        let json: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert!(
            json["devices"].is_array(),
            "devices section should exist for VFIO"
        );
        assert!(json["net"].is_array(), "net section should exist for TAP");
        assert!(
            json["devices"][0]["path"]
                .as_str()
                .unwrap()
                .contains("0000:41:00.0"),
            "VFIO device path should be present"
        );
        assert_eq!(json["net"][0]["ip"], "192.168.249.1");
    }

}
