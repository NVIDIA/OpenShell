// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! QEMU backend for GPU passthrough VMs (devices without MSI-X support).
//!
//! Uses QEMU's command-line interface with KVM acceleration and VFIO device
//! passthrough. This backend is Linux-only and requires a separate kernel
//! image (`vmlinux`) and `virtiofsd` for the root filesystem.
//!
//! Unlike cloud-hypervisor, QEMU handles VFIO devices that lack MSI-X
//! capability by falling back to legacy interrupt emulation.

use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::{
    GUEST_MAC, TAP_GUEST_IP, TAP_HOST_IP, VmBackend, bridge_bidirectional, build_kernel_cmdline,
    run_cmd, setup_tap_host_networking, shell_escape, start_tcp_port_forwarder,
    teardown_tap_host_networking, wait_for_socket,
};
use crate::exec::{
    VM_EXEC_VSOCK_PORT, clear_vm_runtime_state, vm_exec_socket_path, write_vm_runtime_state,
};
use crate::{NetBackend, VmConfig, VmError, vm_rootfs_key};

const VSOCK_GUEST_CID: u32 = 3;
const QEMU_BINARY_NAME: &str = "qemu-system-x86_64";

/// QEMU hypervisor backend for GPU passthrough (non-MSI-X devices).
pub struct QemuBackend {
    qemu_binary: PathBuf,
    vmlinux: PathBuf,
    virtiofsd: PathBuf,
}

impl QemuBackend {
    /// Create a new QEMU backend, validating required binaries.
    pub fn new() -> Result<Self, VmError> {
        let runtime_dir = crate::configured_runtime_dir()?;

        let qemu_binary = {
            let bundled = runtime_dir.join(QEMU_BINARY_NAME);
            if bundled.is_file() {
                bundled
            } else {
                find_in_path(QEMU_BINARY_NAME).ok_or_else(|| VmError::BinaryNotFound {
                    path: bundled.display().to_string(),
                    hint: "QEMU backend requires qemu-system-x86_64. Install QEMU or set OPENSHELL_VM_RUNTIME_DIR".to_string(),
                })?
            }
        };

        let vmlinux = runtime_dir.join("vmlinux");
        if !vmlinux.is_file() {
            return Err(VmError::BinaryNotFound {
                path: vmlinux.display().to_string(),
                hint: "QEMU backend requires a vmlinux kernel. Run the GPU build pipeline"
                    .to_string(),
            });
        }

        let virtiofsd = runtime_dir.join("virtiofsd");
        if !virtiofsd.is_file() {
            return Err(VmError::BinaryNotFound {
                path: virtiofsd.display().to_string(),
                hint: "QEMU backend requires virtiofsd. Run the GPU build pipeline".to_string(),
            });
        }

        // Verify vhost-vsock is available. QEMU's vhost-vsock-pci device
        // needs /dev/vhost-vsock (provided by the vhost_vsock kernel module).
        // A plain AF_VSOCK socket() can succeed with just the vsock module,
        // but connect() will fail with ENODEV if vhost_vsock isn't loaded.
        if !Path::new("/dev/vhost-vsock").exists() {
            return Err(VmError::HostSetup(
                "/dev/vhost-vsock not found.\n\
                 QEMU backend requires the vhost_vsock kernel module.\n\
                 Fix: sudo modprobe vhost_vsock"
                    .to_string(),
            ));
        }
        {
            let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
            if fd < 0 {
                let err = std::io::Error::last_os_error();
                return Err(VmError::HostSetup(format!(
                    "AF_VSOCK socket creation failed: {err}\n\
                     QEMU backend requires the vhost_vsock kernel module.\n\
                     Fix: sudo modprobe vhost_vsock"
                )));
            }
            unsafe { libc::close(fd) };
        }

        Ok(Self {
            qemu_binary,
            vmlinux,
            virtiofsd,
        })
    }
}

impl VmBackend for QemuBackend {
    fn launch(&self, config: &VmConfig) -> Result<i32, VmError> {
        launch_qemu(self, config)
    }
}

/// Search `$PATH` for a binary by name.
fn find_in_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

const TAP_DEVICE_NAME: &str = "vmtap0";

/// Create and configure the TAP device before QEMU starts.
///
/// Unlike cloud-hypervisor (which creates its own TAP via the `net` config),
/// QEMU with `script=no` expects the TAP device to already exist.
fn setup_tap_device() -> Result<(), VmError> {
    // Clean up stale TAP device from a previous crashed run.
    if Path::new(&format!("/sys/class/net/{TAP_DEVICE_NAME}")).exists() {
        eprintln!("TAP device {TAP_DEVICE_NAME} already exists, removing stale device");
        let _ = run_cmd("ip", &["link", "delete", TAP_DEVICE_NAME]);
    }
    run_cmd("ip", &["tuntap", "add", "dev", TAP_DEVICE_NAME, "mode", "tap"])?;
    run_cmd(
        "ip",
        &[
            "addr", "add",
            &format!("{TAP_HOST_IP}/24"),
            "dev", TAP_DEVICE_NAME,
        ],
    )?;
    run_cmd("ip", &["link", "set", TAP_DEVICE_NAME, "up"])?;
    eprintln!("TAP device {TAP_DEVICE_NAME} created with {TAP_HOST_IP}");
    Ok(())
}

/// Remove the TAP device created by [`setup_tap_device`].
fn teardown_tap_device() {
    let _ = run_cmd("ip", &["link", "delete", TAP_DEVICE_NAME]);
    eprintln!("TAP device {TAP_DEVICE_NAME} removed");
}

// ── Build QEMU command-line arguments ───────────────────────────────────

fn build_qemu_args(
    backend: &QemuBackend,
    config: &VmConfig,
    effective_exec_path: &str,
    vfio_device: Option<&str>,
    virtiofsd_sock: &Path,
    state_disk_path: Option<&Path>,
    use_tap_net: bool,
    guest_cid: u32,
    console_log: &Path,
) -> Vec<String> {
    let mut args = Vec::new();

    // Machine, CPU, resources
    args.extend([
        "-machine".into(),
        "q35,accel=kvm".into(),
        "-cpu".into(),
        "host".into(),
        "-smp".into(),
        config.vcpus.to_string(),
        "-m".into(),
        format!("{}M", config.mem_mib),
    ]);

    // Kernel
    args.extend([
        "-kernel".into(),
        backend.vmlinux.display().to_string(),
    ]);

    // Kernel cmdline (shared builder with CHV)
    let cmdline = build_kernel_cmdline(config, effective_exec_path, use_tap_net);
    args.extend(["-append".into(), cmdline]);

    // virtiofs rootfs
    args.extend([
        "-chardev".into(),
        format!("socket,id=vfsock,path={}", virtiofsd_sock.display()),
        "-device".into(),
        "vhost-user-fs-pci,chardev=vfsock,tag=rootfs".into(),
        "-object".into(),
        format!(
            "memory-backend-file,id=mem,size={}M,mem-path=/dev/shm,share=on",
            config.mem_mib
        ),
        "-numa".into(),
        "node,memdev=mem".into(),
    ]);

    // State disk
    if let Some(disk_path) = state_disk_path {
        args.extend([
            "-drive".into(),
            format!(
                "file={},format=raw,if=virtio",
                disk_path.display()
            ),
        ]);
    }

    // PCIe root ports — Q35's pcie.0 root bus does not support
    // hotplugging. VFIO and vhost-vsock-pci need dedicated root ports
    // to initialize correctly under the Q35 PCIe topology.
    // virtio-net-pci and vhost-user-fs-pci are QEMU-emulated devices
    // that work directly on the root bus without dedicated root ports.
    const PCIE_SLOT_VFIO: u8 = 1;
    const PCIE_SLOT_VSOCK: u8 = 2;

    // VFIO device passthrough
    if let Some(bdf) = vfio_device {
        args.extend([
            "-device".into(),
            format!("pcie-root-port,id=vfio-rp,chassis={PCIE_SLOT_VFIO},slot={PCIE_SLOT_VFIO}"),
            "-device".into(),
            format!("vfio-pci,host={bdf},bus=vfio-rp"),
        ]);
    }

    // vsock
    args.extend([
        "-device".into(),
        format!("pcie-root-port,id=vsock-rp,chassis={PCIE_SLOT_VSOCK},slot={PCIE_SLOT_VSOCK}"),
        "-device".into(),
        format!("vhost-vsock-pci,guest-cid={guest_cid},bus=vsock-rp"),
    ]);

    // TAP networking
    if use_tap_net {
        args.extend([
            "-netdev".into(),
            "tap,id=net0,ifname=vmtap0,script=no,downscript=no".into(),
            "-device".into(),
            format!("virtio-net-pci,netdev=net0,mac={GUEST_MAC}"),
        ]);
    }

    // Console / display — disable monitor explicitly to prevent
    // stdin from being interpreted as monitor commands.
    args.extend([
        "-serial".into(),
        format!("file:{}", console_log.display()),
        "-display".into(),
        "none".into(),
        "-monitor".into(),
        "none".into(),
        "-no-reboot".into(),
    ]);

    args
}

// ── Launch ──────────────────────────────────────────────────────────────

#[allow(clippy::similar_names)]
fn launch_qemu(backend: &QemuBackend, config: &VmConfig) -> Result<i32, VmError> {
    let launch_start = Instant::now();

    let run_dir = config
        .rootfs
        .parent()
        .unwrap_or(&config.rootfs)
        .to_path_buf();
    let rootfs_key = vm_rootfs_key(&config.rootfs);

    let sock_dir = PathBuf::from(format!("/tmp/ovm-qemu-{}", std::process::id()));
    if let Ok(entries) = std::fs::read_dir("/tmp") {
        for entry in entries.filter_map(Result::ok) {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("ovm-qemu-") && entry.path() != sock_dir {
                let is_stale = name
                    .strip_prefix("ovm-qemu-")
                    .and_then(|pid_str| pid_str.parse::<i32>().ok())
                    .map(|pid| unsafe { libc::kill(pid, 0) } != 0)
                    .unwrap_or(true);
                if is_stale {
                    let _ = std::fs::remove_dir_all(entry.path());
                }
            }
        }
    }
    std::fs::create_dir_all(&sock_dir).map_err(|e| {
        VmError::HostSetup(format!("create socket dir {}: {e}", sock_dir.display()))
    })?;

    let virtiofsd_sock_path = sock_dir.join("virtiofsd.sock");
    let console_log = config
        .console_output
        .clone()
        .unwrap_or_else(|| run_dir.join(format!("{rootfs_key}-console.log")));

    let _ = std::fs::remove_file(&virtiofsd_sock_path);

    // Start virtiofsd
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

    wait_for_socket(&virtiofsd_sock_path, "virtiofsd", Duration::from_secs(5))?;

    let use_tap_net = !matches!(config.net, NetBackend::None);

    // Build exec wrapper (same pattern as CHV)
    let is_exec_mode = config.is_exec_mode();
    let wrapper_path = config.rootfs.join("tmp/qemu-exec-wrapper.sh");
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
        effective_exec_path = "/tmp/qemu-exec-wrapper.sh".to_string();
    } else {
        effective_exec_path = config.exec_path.clone();
    }

    // Build QEMU command line
    let state_disk_path = config.state_disk.as_ref().map(|sd| sd.path.as_path());
    let qemu_args = build_qemu_args(
        backend,
        config,
        &effective_exec_path,
        config.vfio_device.as_deref(),
        &virtiofsd_sock_path,
        state_disk_path,
        use_tap_net,
        VSOCK_GUEST_CID,
        &console_log,
    );

    // Create TAP device before QEMU starts (QEMU with script=no expects it).
    if use_tap_net {
        setup_tap_device()?;
    }

    // Spawn QEMU
    eprintln!("Starting QEMU: {}", backend.qemu_binary.display());
    let qemu_log = run_dir.join(format!("{rootfs_key}-qemu.log"));
    let qemu_log_file = std::fs::File::create(&qemu_log)
        .map_err(|e| VmError::Fork(format!("create QEMU log: {e}")))?;

    let mut qemu_cmd = std::process::Command::new(&backend.qemu_binary);
    qemu_cmd
        .args(&qemu_args)
        .stdout(std::process::Stdio::null())
        .stderr(qemu_log_file);
    #[allow(unsafe_code)]
    unsafe {
        qemu_cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            Ok(())
        });
    }
    let mut qemu_child = qemu_cmd.spawn()
        .map_err(|e| VmError::Fork(format!("start QEMU: {e}")))?;

    let qemu_pid = qemu_child.id() as i32;
    eprintln!(
        "QEMU started (pid {qemu_pid}) [{:.1}s]",
        launch_start.elapsed().as_secs_f64()
    );

    // Set up host-side TAP networking
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

    // Start AF_VSOCK exec bridge
    let exec_socket = vm_exec_socket_path(&config.rootfs);
    start_vsock_exec_bridge_af_vsock(
        &exec_socket,
        VSOCK_GUEST_CID,
        VM_EXEC_VSOCK_PORT,
        qemu_child.id(),
    )?;

    // Write runtime state (vsock_bridge: true — uses AF_VSOCK bridging)
    if !config.is_exec_mode() {
        if let Err(err) =
            write_vm_runtime_state(&config.rootfs, qemu_pid, &console_log, None, true)
        {
            let _ = qemu_child.kill();
            let _ = qemu_child.wait();
            let _ = virtiofsd_child.kill();
            let _ = virtiofsd_child.wait();
            if let Some(ref orig) = original_ip_forward {
                teardown_tap_host_networking(orig);
            }
            if use_tap_net {
                teardown_tap_device();
            }
            clear_vm_runtime_state(&config.rootfs);
            return Err(err);
        }
    }

    // TCP port forwarding (same pattern as CHV)
    if use_tap_net {
        for pm in &config.port_map {
            let parts: Vec<&str> = pm.split(':').collect();
            if parts.len() == 2 {
                if let (Ok(hp), Ok(gp)) = (parts[0].parse::<u16>(), parts[1].parse::<u16>()) {
                    if let Err(e) = start_tcp_port_forwarder(hp, TAP_GUEST_IP, gp) {
                        let _ = qemu_child.kill();
                        let _ = qemu_child.wait();
                        let _ = virtiofsd_child.kill();
                        let _ = virtiofsd_child.wait();
                        if let Some(ref orig) = original_ip_forward {
                            teardown_tap_host_networking(orig);
                        }
                        if use_tap_net {
                            teardown_tap_device();
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

    // Gateway bootstrap and health check
    if !config.is_exec_mode() && !config.port_map.is_empty() {
        let gateway_port = crate::gateway_host_port(config);
        if let Err(e) = crate::bootstrap_gateway(&config.rootfs, &config.gateway_name, gateway_port)
            .and_then(|_| crate::health::wait_for_gateway_ready(gateway_port, &config.gateway_name))
        {
            let _ = qemu_child.kill();
            let _ = qemu_child.wait();
            let _ = virtiofsd_child.kill();
            let _ = virtiofsd_child.wait();
            if let Some(ref orig) = original_ip_forward {
                teardown_tap_host_networking(orig);
            }
            if use_tap_net {
                teardown_tap_device();
            }
            clear_vm_runtime_state(&config.rootfs);
            let _ = std::fs::remove_dir_all(&sock_dir);
            let _ = std::fs::remove_file(&exec_socket);
            return Err(e);
        }
    }

    eprintln!(
        "Ready [{:.1}s total]",
        launch_start.elapsed().as_secs_f64()
    );
    eprintln!("Press Ctrl+C to stop.");

    // Signal forwarding
    crate::CHILD_PID.store(qemu_pid, std::sync::atomic::Ordering::Relaxed);
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

    // Wait for QEMU to exit
    let status = qemu_child
        .wait()
        .map_err(|e| VmError::HostSetup(format!("wait for QEMU: {e}")))?;
    crate::CHILD_PID.store(0, std::sync::atomic::Ordering::Relaxed);

    // Clean up host networking rules
    if let Some(ref orig) = original_ip_forward {
        teardown_tap_host_networking(orig);
    }
    if use_tap_net {
        teardown_tap_device();
    }

    // Cleanup
    if !config.is_exec_mode() {
        clear_vm_runtime_state(&config.rootfs);
    }
    let _ = virtiofsd_child.kill();
    let _ = virtiofsd_child.wait();
    eprintln!("virtiofsd stopped");

    let _ = std::fs::remove_dir_all(&sock_dir);
    let _ = std::fs::remove_file(&exec_socket);
    if is_exec_mode {
        let _ = std::fs::remove_file(&wrapper_path);
    }

    let code = status.code().unwrap_or(1);
    eprintln!("VM exited with code {code}");
    Ok(code)
}

// ── AF_VSOCK exec bridge ────────────────────────────────────────────────

/// Start a background bridge: exec Unix socket → guest AF_VSOCK.
///
/// QEMU uses kernel `vhost-vsock-pci` which exposes guest vsock via the
/// kernel's `AF_VSOCK` address family. This is different from
/// cloud-hypervisor's text protocol — here we connect directly to the
/// guest CID and port using raw `AF_VSOCK` sockets.
fn start_vsock_exec_bridge_af_vsock(
    exec_socket: &Path,
    guest_cid: u32,
    guest_port: u32,
    qemu_pid: u32,
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

    eprintln!(
        "vsock exec bridge (AF_VSOCK): {} → CID {} port {}",
        exec_socket.display(),
        guest_cid,
        guest_port,
    );

    std::thread::spawn(move || {
        af_vsock_bridge_accept_loop(listener, guest_cid, guest_port, qemu_pid);
    });

    Ok(())
}

/// Connect to a guest vsock port via kernel AF_VSOCK.
///
/// Returns the connected socket wrapped as a `UnixStream`. The `UnixStream`
/// type is used solely for its `Read`/`Write` trait impls which delegate to
/// raw `read()`/`write()` syscalls — address-family-specific methods like
/// `peer_addr()` must not be called on the returned stream.
fn connect_af_vsock(cid: u32, port: u32) -> std::io::Result<UnixStream> {
    use std::os::unix::io::FromRawFd;

    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let addr = libc::sockaddr_vm {
        svm_family: libc::AF_VSOCK as u16,
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: cid,
        svm_zero: [0; 4],
    };

    let ret = unsafe {
        libc::connect(
            fd,
            std::ptr::from_ref(&addr).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    // SAFETY: fd is a valid, connected socket. We wrap it as UnixStream
    // purely for Read/Write access used by bridge_bidirectional().
    Ok(unsafe { UnixStream::from_raw_fd(fd) })
}

/// Whether a vsock connect error is transient (expected during VM boot).
///
/// The guest exec agent takes time to start, and the vhost-vsock transport
/// may not be fully initialized when QEMU first launches. These errors
/// resolve on their own once the guest is ready.
fn is_transient_vsock_error(e: &std::io::Error) -> bool {
    if e.kind() == std::io::ErrorKind::ConnectionRefused {
        return true;
    }
    match e.raw_os_error() {
        Some(code) => {
            code == libc::ENODEV         // vsock transport not ready
                || code == libc::EHOSTUNREACH // guest CID not reachable yet
                || code == libc::ECONNRESET   // connection reset during startup
                || code == libc::ETIMEDOUT    // connect timed out
        }
        None => false,
    }
}

/// Accept loop for the AF_VSOCK bridge background thread.
///
/// Connection failures during boot are expected — the guest exec agent
/// isn't listening yet. We keep retrying since the bootstrap caller has
/// its own 120s timeout. If the QEMU process exits, we stop immediately
/// rather than retrying against a dead CID for 120s.
fn af_vsock_bridge_accept_loop(
    listener: std::os::unix::net::UnixListener,
    guest_cid: u32,
    port: u32,
    qemu_pid: u32,
) {
    // Give QEMU time to initialize the vhost-vsock-pci device and register
    // the CID with the kernel transport before accepting connections.
    std::thread::sleep(Duration::from_secs(2));

    let mut fatal_failures: u32 = 0;
    let mut logged_transient = false;

    for stream in listener.incoming() {
        if !is_process_alive(qemu_pid) {
            eprintln!("vsock bridge: QEMU (pid {qemu_pid}) exited, stopping bridge");
            return;
        }

        let client = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("vsock bridge: accept: {e}");
                continue;
            }
        };

        match connect_af_vsock(guest_cid, port) {
            Ok(guest) => {
                fatal_failures = 0;
                bridge_bidirectional(client, guest);
            }
            Err(e) if is_transient_vsock_error(&e) => {
                if !is_process_alive(qemu_pid) {
                    eprintln!(
                        "vsock bridge: QEMU (pid {qemu_pid}) exited — \
                         check console log for VM boot errors"
                    );
                    return;
                }
                if !logged_transient {
                    eprintln!(
                        "vsock bridge: guest not ready on CID {guest_cid} port {port} ({e}), \
                         will keep retrying..."
                    );
                    logged_transient = true;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
            Err(e) => {
                fatal_failures += 1;
                if fatal_failures <= 2 {
                    eprintln!("vsock bridge: AF_VSOCK connect failed: {e}");
                }
                if fatal_failures >= 5 {
                    eprintln!("vsock bridge: too many AF_VSOCK failures, stopping bridge");
                    return;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

fn is_process_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_backend() -> QemuBackend {
        QemuBackend {
            qemu_binary: "/usr/bin/qemu-system-x86_64".into(),
            vmlinux: "/boot/vmlinux".into(),
            virtiofsd: "/usr/bin/virtiofsd".into(),
        }
    }

    fn base_config() -> VmConfig {
        VmConfig {
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
            gpu_enabled: false,
            gpu_has_msix: false,
            vfio_device: None,
            backend: crate::VmBackendChoice::Qemu,
        }
    }

    #[test]
    fn build_qemu_args_basic() {
        let backend = test_backend();
        let config = base_config();

        let args = build_qemu_args(
            &backend,
            &config,
            &config.exec_path,
            None,
            Path::new("/tmp/virtiofsd.sock"),
            None,
            false,
            VSOCK_GUEST_CID,
            Path::new("/tmp/console.log"),
        );

        assert!(args.contains(&"-machine".to_string()));
        assert!(args.contains(&"q35,accel=kvm".to_string()));
        assert!(args.contains(&"-cpu".to_string()));
        assert!(args.contains(&"host".to_string()));
        assert!(args.contains(&"-smp".to_string()));
        assert!(args.contains(&"4".to_string()));
        assert!(args.contains(&"-m".to_string()));
        assert!(args.contains(&"8192M".to_string()));
        assert!(args.contains(&"-monitor".to_string()));
        assert!(args.contains(&"none".to_string()));
        assert!(args.contains(&"-no-reboot".to_string()));
        assert!(!args.iter().any(|a| a.contains("vfio-pci")));
        assert!(!args.iter().any(|a| a.contains("tap")));
        assert!(
            args.iter()
                .any(|a| a.contains("pcie-root-port,id=vsock-rp")),
            "args should contain PCIe root port for vsock: {args:?}"
        );
        assert!(
            args.iter()
                .any(|a| a.contains("vhost-vsock-pci,guest-cid=3,bus=vsock-rp")),
            "args should contain vsock on root port: {args:?}"
        );
    }

    #[test]
    fn build_qemu_args_with_vfio() {
        let backend = test_backend();
        let mut config = base_config();
        config.gpu_enabled = true;
        config.vfio_device = Some("0000:41:00.0".into());

        let args = build_qemu_args(
            &backend,
            &config,
            &config.exec_path,
            config.vfio_device.as_deref(),
            Path::new("/tmp/virtiofsd.sock"),
            None,
            false,
            VSOCK_GUEST_CID,
            Path::new("/tmp/console.log"),
        );

        assert!(
            args.iter()
                .any(|a| a.contains("vfio-pci,host=0000:41:00.0,bus=vfio-rp")),
            "args should contain VFIO device on root port: {args:?}"
        );
        assert!(
            args.iter().any(|a| a.contains("pcie-root-port,id=vfio-rp")),
            "args should contain PCIe root port for VFIO: {args:?}"
        );
    }

    #[test]
    fn build_qemu_args_with_tap_net() {
        let backend = test_backend();
        let mut config = base_config();
        config.net = NetBackend::Gvproxy {
            binary: "/usr/bin/gvproxy".into(),
        };

        let args = build_qemu_args(
            &backend,
            &config,
            &config.exec_path,
            None,
            Path::new("/tmp/virtiofsd.sock"),
            None,
            true,
            VSOCK_GUEST_CID,
            Path::new("/tmp/console.log"),
        );

        assert!(
            args.iter().any(|a| a.contains("tap,id=net0")),
            "args should contain TAP netdev: {args:?}"
        );
        assert!(
            args.iter()
                .any(|a| a.contains("virtio-net-pci,netdev=net0")),
            "args should contain virtio-net device: {args:?}"
        );
    }

    #[test]
    fn build_qemu_args_without_net() {
        let backend = test_backend();
        let config = base_config();

        let args = build_qemu_args(
            &backend,
            &config,
            &config.exec_path,
            None,
            Path::new("/tmp/virtiofsd.sock"),
            None,
            false,
            VSOCK_GUEST_CID,
            Path::new("/tmp/console.log"),
        );

        assert!(
            !args.iter().any(|a| a.contains("tap")),
            "args should not contain TAP: {args:?}"
        );
        assert!(
            !args.iter().any(|a| a.contains("virtio-net")),
            "args should not contain virtio-net: {args:?}"
        );
    }

    #[test]
    fn build_qemu_args_gpu_enabled_cmdline() {
        let backend = test_backend();
        let mut config = base_config();
        config.gpu_enabled = true;
        config.vfio_device = Some("0000:41:00.0".into());

        let args = build_qemu_args(
            &backend,
            &config,
            &config.exec_path,
            config.vfio_device.as_deref(),
            Path::new("/tmp/virtiofsd.sock"),
            None,
            false,
            VSOCK_GUEST_CID,
            Path::new("/tmp/console.log"),
        );

        let append_idx = args.iter().position(|a| a == "-append").unwrap();
        let cmdline = &args[append_idx + 1];
        assert!(
            cmdline.contains("GPU_ENABLED=true"),
            "cmdline should contain GPU_ENABLED=true: {cmdline}"
        );
    }

    #[test]
    fn transient_vsock_errors_classified_correctly() {
        // Kind-based: ConnectionRefused
        let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        assert!(
            is_transient_vsock_error(&refused),
            "ConnectionRefused should be transient"
        );

        // OS-error-based transient codes
        let enodev = std::io::Error::from_raw_os_error(libc::ENODEV);
        assert!(
            is_transient_vsock_error(&enodev),
            "ENODEV should be transient"
        );

        let ehostunreach = std::io::Error::from_raw_os_error(libc::EHOSTUNREACH);
        assert!(
            is_transient_vsock_error(&ehostunreach),
            "EHOSTUNREACH should be transient"
        );

        let econnreset = std::io::Error::from_raw_os_error(libc::ECONNRESET);
        assert!(
            is_transient_vsock_error(&econnreset),
            "ECONNRESET should be transient"
        );

        let etimedout = std::io::Error::from_raw_os_error(libc::ETIMEDOUT);
        assert!(
            is_transient_vsock_error(&etimedout),
            "ETIMEDOUT should be transient"
        );

        // Non-transient errors
        let eperm = std::io::Error::from_raw_os_error(libc::EPERM);
        assert!(
            !is_transient_vsock_error(&eperm),
            "EPERM should not be transient"
        );

        let eacces = std::io::Error::from_raw_os_error(libc::EACCES);
        assert!(
            !is_transient_vsock_error(&eacces),
            "EACCES should not be transient"
        );

        let other = std::io::Error::new(std::io::ErrorKind::Other, "something else");
        assert!(
            !is_transient_vsock_error(&other),
            "ErrorKind::Other should not be transient"
        );
    }
}
