// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell` capability-free in-workload sandbox boundary.

#[cfg(target_os = "linux")]
use std::mem::size_of;
use std::path::Path;

use clap::Parser;
use miette::{IntoDiagnostic, Result};
#[cfg(target_os = "linux")]
use openshell_ocsf::OcsfShorthandLayer;
#[cfg(target_os = "linux")]
use tracing_subscriber::EnvFilter;
#[cfg(target_os = "linux")]
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

/// Subcommand name used to self-copy the sandbox binary into a shared volume.
///
/// Init containers invoke the binary directly instead of relying on `sh`/`cp`
/// to copy the binary out. Invoking the binary itself with this argument
/// performs the copy in pure Rust.
const COPY_SELF_SUBCOMMAND: &str = "copy-self";
const BOOTSTRAP_SUBCOMMAND: &str = "bootstrap";
const SEED_WORKSPACE_SUBCOMMAND: &str = "seed-workspace";
#[cfg(target_os = "linux")]
const BOOTSTRAP_INPUT_ROOT: &str = "/.openshell/bootstrap-input";
#[cfg(target_os = "linux")]
const SANDBOX_RUNTIME_ROOT: &str = "/.openshell/runtime";
#[cfg(target_os = "linux")]
const SANDBOX_STATE_ROOT: &str = "/.openshell/state";

const VALIDATE_WORKSPACE_SUBCOMMAND: &str = "validate-workspace";
const CAPABILITY_PROBE_SUBCOMMAND: &str = "capability-probe";
const CAPABILITY_PROBE_LAUNCH_SUBCOMMAND: &str = "capability-probe-launch";
const CAPABILITY_SOCKET_CHILD_SUBCOMMAND: &str = "capability-socket-child";
const CAPABILITY_LANDLOCK_CHILD_SUBCOMMAND: &str = "capability-landlock-child";
const CAPABILITY_FREE_LAUNCH_SUBCOMMAND: &str = "launch-capability-free";
#[cfg(target_os = "linux")]
const PROBE_DENIED_TCP_PEER: &str = "203.0.113.1:9";
#[cfg(target_os = "linux")]
const PROBE_SOCKADDR_IN_LEN: usize = size_of::<libc::sockaddr_in>();
#[cfg(target_os = "linux")]
const LINUX_SIGNAL_LIMIT: i32 = 65;

#[derive(Parser, Debug)]
#[command(name = "openshell-sandbox")]
#[command(version = openshell_core::VERSION)]
#[command(about = "OpenShell in-workload isolation boundary")]
struct BoundaryArgs {
    /// Protected one-use bootstrap configuration staged by the driver.
    #[arg(long)]
    bootstrap: std::path::PathBuf,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "warn", env = openshell_core::sandbox_env::LOG_LEVEL)]
    log_level: String,
}

/// Internal one-shot command used by trusted driver bootstrap to validate an
/// image-provided workdir as the final sandbox identity.
#[derive(Parser, Debug)]
#[command(name = "validate-workspace", hide = true)]
struct ValidateWorkspaceArgs {
    #[arg(long)]
    workdir: String,
    #[arg(long)]
    expected_uid: u32,
    #[arg(long)]
    expected_gid: u32,
}

#[cfg(target_os = "linux")]
fn validate_workspace(args: &[String]) -> Result<()> {
    let args = ValidateWorkspaceArgs::try_parse_from(
        std::iter::once(VALIDATE_WORKSPACE_SUBCOMMAND.to_string()).chain(args.iter().cloned()),
    )
    .into_diagnostic()?;
    let actual = (
        nix::unistd::geteuid().as_raw(),
        nix::unistd::getegid().as_raw(),
    );
    if actual != (args.expected_uid, args.expected_gid) {
        return Err(miette::miette!(
            "workspace validator privilege drop failed: expected {}:{}, got {}:{}",
            args.expected_uid,
            args.expected_gid,
            actual.0,
            actual.1
        ));
    }
    openshell_sandbox::process::validate_oci_workspace_as_effective_identity(Path::new(
        &args.workdir,
    ))
}

#[cfg(not(target_os = "linux"))]
fn validate_workspace(_args: &[String]) -> Result<()> {
    Err(miette::miette!(
        "workspace validation is only supported on Unix"
    ))
}

/// Run the active Phase 0 probe inside the exact workload runtime profile.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn run_capability_probe() -> Result<()> {
    let (qualification, report) = qualify_runtime()?;
    debug_assert!(qualification.seccomp.notification_round_trip);
    println!("{report}");
    Ok(())
}

/// Actively qualify every kernel primitive used by the capability-free
/// sandbox. Callers decide whether to emit the resulting diagnostic report.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn qualify_runtime() -> Result<(openshell_sandbox::RuntimeQualification, serde_json::Value)> {
    use miette::Context as _;

    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    if uid == 0 || gid == 0 {
        return Err(miette::miette!(
            "capability-free sandbox probe requires non-root UID and GID, got {uid}:{gid}"
        ));
    }
    let status = std::fs::read_to_string("/proc/self/status")
        .into_diagnostic()
        .wrap_err("read /proc/self/status")?;
    for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let value = proc_status_hex(&status, field)?;
        if value != 0 {
            return Err(miette::miette!(
                "capability-free sandbox probe found {field}=0x{value:x}"
            ));
        }
    }
    // SAFETY: PR_GET_NO_NEW_PRIVS reads one scalar process property.
    let no_new_privileges = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if no_new_privileges != 1 {
        return Err(miette::miette!(
            "capability-free sandbox probe requires no_new_privs=1"
        ));
    }

    // The trusted sandbox must be nondumpable before it handles bootstrap or
    // channel secrets. Perform the parent-to-child observation probe after
    // tightening the parent; the synthetic child explicitly becomes dumpable.
    // SAFETY: PR_SET_DUMPABLE accepts one scalar and only tightens this process.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } < 0 {
        return Err(miette::miette!(
            "set sandbox probe nondumpable: {}",
            std::io::Error::last_os_error()
        ));
    }
    openshell_isolation_interface::linux::task_memory::probe_child_access()
        .into_diagnostic()
        .wrap_err("same-UID task-memory probe")?;
    probe_landlock_allow_deny().wrap_err("Landlock allow/deny probe")?;
    let notification =
        openshell_isolation_interface::linux::seccomp_notify::probe_notification_api()
            .into_diagnostic()
            .wrap_err("seccomp notification probe")?;
    probe_socket_virtualization().wrap_err("socket virtualization probe")?;
    probe_dns_relay_bind().wrap_err("DNS relay bind probe")?;
    let landlock_abi = openshell_isolation_interface::linux::landlock::abi_version()
        .into_diagnostic()
        .wrap_err("Landlock ABI probe")?;
    if landlock_abi == 0 {
        return Err(miette::miette!("Landlock ABI version is zero"));
    }

    let groups = nix::unistd::getgroups()
        .into_diagnostic()?
        .into_iter()
        .map(nix::unistd::Gid::as_raw)
        .collect::<Vec<_>>();
    let report = serde_json::json!({
        "qualified": true,
        "uid": uid,
        "gid": gid,
        "supplementary_groups": groups,
        "capabilities_zero": true,
        "no_new_privileges": true,
        "sandbox_dumpable": false,
        "child_dumpable": true,
        "child_core_limit_zero": true,
        "same_uid_self_protection": true,
        "landlock_abi": landlock_abi,
        "landlock_allow_deny": true,
        "seccomp_notification": notification.notification_round_trip(),
        "seccomp_addfd_send": notification.addfd_send(),
        "task_memory_copy": notification.task_memory_copy(),
        "connected_send_fast_path": notification.connected_send_fast_path(),
        "socket_virtualization": true,
        "dns_relay_bind": true,
        "udp_dns_round_trip": true,
        "tcp_dns_round_trip": true,
        "tcp_allow_round_trip": true,
        "tcp_deny_round_trip": true,
        "wait_killable_recv": notification.wait_killable_recv,
    });
    let qualification = openshell_sandbox::RuntimeQualification {
        seccomp: openshell_isolation_interface::contract::SeccompEvidence {
            new_listener: notification.notification_round_trip(),
            notification_round_trip: notification.notification_round_trip(),
            id_validation: notification.notification_round_trip(),
            addfd_send: notification.addfd_send(),
            retained_socket_operation: true,
            proc_fd_identity: true,
            task_memory_read: notification.task_memory_copy(),
            task_memory_write: notification.task_memory_copy(),
            cancellation: notification.wait_killable_recv,
        },
        landlock_abi,
        landlock_allow_deny: true,
        udp_dns_round_trip: true,
        tcp_dns_round_trip: true,
        tcp_allow_round_trip: true,
        tcp_deny_round_trip: true,
    };
    Ok((qualification, report))
}

#[cfg(target_os = "linux")]
fn probe_dns_relay_bind() -> Result<()> {
    use std::net::{TcpListener, UdpSocket};

    let unprivileged_port_start =
        std::fs::read_to_string("/proc/sys/net/ipv4/ip_unprivileged_port_start")
            .into_diagnostic()?
            .trim()
            .parse::<u16>()
            .into_diagnostic()?;
    if unprivileged_port_start != 0 {
        return Err(miette::miette!(
            "DNS relay requires net.ipv4.ip_unprivileged_port_start=0, got {unprivileged_port_start}"
        ));
    }
    let tcp = TcpListener::bind("127.0.0.53:53").into_diagnostic()?;
    let udp = UdpSocket::bind("127.0.0.53:53").into_diagnostic()?;
    drop((tcp, udp));
    Ok(())
}

/// Prove that the exact unprivileged runtime can install a hard Landlock
/// allow-list which admits one path and rejects an adjacent path. Landlock is
/// irreversible, so the restriction is exercised in a fresh trusted child.
#[cfg(target_os = "linux")]
fn probe_landlock_allow_deny() -> Result<()> {
    use miette::Context as _;

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .into_diagnostic()?
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "openshell-landlock-probe-{}-{nonce}",
        std::process::id()
    ));
    let allowed = root.join("allowed");
    let denied = root.join("denied");
    std::fs::create_dir(&root)
        .into_diagnostic()
        .wrap_err("create Landlock probe root")?;
    let probe_result = (|| -> Result<()> {
        std::fs::create_dir(&allowed).into_diagnostic()?;
        std::fs::create_dir(&denied).into_diagnostic()?;
        std::fs::write(allowed.join("sentinel"), b"allowed").into_diagnostic()?;
        std::fs::write(denied.join("sentinel"), b"denied").into_diagnostic()?;
        let status = std::process::Command::new(std::env::current_exe().into_diagnostic()?)
            .arg(CAPABILITY_LANDLOCK_CHILD_SUBCOMMAND)
            .arg(&allowed)
            .arg(&denied)
            .env_clear()
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .status()
            .into_diagnostic()
            .wrap_err("run Landlock probe child")?;
        if !status.success() {
            return Err(miette::miette!(
                "Landlock probe child exited with status {status}"
            ));
        }
        Ok(())
    })();
    let cleanup_result = std::fs::remove_dir_all(&root).into_diagnostic();
    probe_result?;
    cleanup_result.wrap_err("remove Landlock probe root")
}

#[cfg(target_os = "linux")]
fn run_capability_landlock_child(args: &[String]) -> Result<()> {
    use openshell_core::policy::{
        FilesystemPolicy, LandlockCompatibility, LandlockPolicy, NetworkPolicy, ProcessPolicy,
        SandboxPolicy,
    };

    let [allowed, denied] = args else {
        return Err(miette::miette!(
            "usage: {CAPABILITY_LANDLOCK_CHILD_SUBCOMMAND} <ALLOWED> <DENIED>"
        ));
    };
    let allowed = Path::new(allowed);
    let denied = Path::new(denied);
    let policy = SandboxPolicy {
        version: 1,
        filesystem: FilesystemPolicy {
            read_only: vec![allowed.to_path_buf()],
            read_write: Vec::new(),
            include_workdir: false,
        },
        network: NetworkPolicy::default(),
        landlock: LandlockPolicy {
            compatibility: LandlockCompatibility::HardRequirement,
        },
        process: ProcessPolicy::default(),
    };
    let prepared = openshell_sandbox::sandbox::linux::prepare_capability_free(&policy, None)?;
    openshell_sandbox::sandbox::linux::enforce(prepared)?;
    if std::fs::read(allowed.join("sentinel")).into_diagnostic()? != b"allowed" {
        return Err(miette::miette!("Landlock probe allowed-path mismatch"));
    }
    match std::fs::read(denied.join("sentinel")) {
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(()),
        Err(error) => Err(error).into_diagnostic(),
        Ok(_) => Err(miette::miette!(
            "Landlock probe unexpectedly read the denied path"
        )),
    }
}

#[cfg(not(target_os = "linux"))]
fn run_capability_landlock_child(_args: &[String]) -> Result<()> {
    Err(miette::miette!(
        "Landlock qualification is supported only on Linux"
    ))
}

/// Exercise the production listener inheritance and socket-time ADDFD shape.
///
/// One dedicated launcher thread installs the non-TSYNC listener, moves the
/// listener FD to this unfiltered broker through an in-process channel, then
/// execs the child. The child proves that the injected open-file description
/// survives dup and epoll registration before connect and that the broker can
/// return the original peer rather than the local relay endpoint.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn probe_socket_virtualization() -> Result<()> {
    use std::io::{Read as _, Write as _};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    use std::os::unix::process::CommandExt as _;
    use std::sync::mpsc;

    use miette::Context as _;
    use openshell_isolation_interface::linux::seccomp_notify::NotificationListener;
    use openshell_isolation_interface::linux::socket_registry::{
        InetFamily, InetKind, SocketMetadata, SocketRegistry, SocketState,
    };

    let relay = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .into_diagnostic()
        .wrap_err("bind socket probe relay")?;
    let original_peer = relay.local_addr().into_diagnostic()?;
    let relay_thread = std::thread::Builder::new()
        .name("openshell-probe-relay".to_string())
        .spawn(move || -> std::io::Result<()> {
            let (mut stream, _) = relay.accept()?;
            stream.set_nodelay(true)?;
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request)?;
            if &request != b"ping" {
                return Err(std::io::Error::other("socket probe payload mismatch"));
            }
            stream.write_all(b"pong")
        })
        .into_diagnostic()?;
    let dns_relay_addr = "127.0.0.53:53"
        .parse::<SocketAddr>()
        .expect("fixed DNS relay address is valid");
    let dns_relay = UdpSocket::bind(dns_relay_addr)
        .into_diagnostic()
        .wrap_err("bind socket probe DNS relay")?;
    let dns_thread = std::thread::Builder::new()
        .name("openshell-probe-dns".to_string())
        .spawn(move || -> std::io::Result<()> {
            let mut query = [0_u8; 512];
            let (length, peer) = dns_relay.recv_from(&mut query)?;
            let response = build_probe_dns_response(&query[..length])?;
            let sent = dns_relay.send_to(&response, peer)?;
            if sent != response.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "short DNS probe response",
                ));
            }
            Ok(())
        })
        .into_diagnostic()?;
    let dns_tcp_relay = TcpListener::bind(dns_relay_addr)
        .into_diagnostic()
        .wrap_err("bind socket probe TCP DNS relay")?;
    let dns_tcp_thread = std::thread::Builder::new()
        .name("openshell-probe-dns-tcp".to_string())
        .spawn(move || -> std::io::Result<()> {
            let (mut stream, _) = dns_tcp_relay.accept()?;
            let mut length = [0_u8; 2];
            stream.read_exact(&mut length)?;
            let length = usize::from(u16::from_be_bytes(length));
            if length == 0 || length > 512 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid TCP DNS probe length",
                ));
            }
            let mut query = vec![0_u8; length];
            stream.read_exact(&mut query)?;
            let response = build_probe_dns_response(&query)?;
            stream.write_all(
                &u16::try_from(response.len())
                    .expect("probe DNS response fits u16")
                    .to_be_bytes(),
            )?;
            stream.write_all(&response)
        })
        .into_diagnostic()?;

    let executable = std::env::current_exe()
        .into_diagnostic()
        .wrap_err("resolve socket probe executable")?;
    let sandbox_tgid = std::process::id();
    let mut child_hardening =
        openshell_isolation_interface::linux::child_seccomp::prepare(sandbox_tgid)
            .into_diagnostic()
            .wrap_err("prepare socket probe child hardening")?;
    let (listener_tx, listener_rx) = mpsc::sync_channel::<std::io::Result<NotificationListener>>(1);
    let (child_tx, child_rx) = mpsc::sync_channel::<std::io::Result<std::process::Child>>(1);
    let launcher = std::thread::Builder::new()
        .name("openshell-probe-launcher".to_string())
        .spawn(move || {
            if let Err(error) = block_launcher_signals() {
                let _ = listener_tx.send(Err(error));
                return;
            }
            let listener =
                openshell_isolation_interface::linux::seccomp_notify::install_listener(&[
                    libc::SYS_socket,
                    libc::SYS_connect,
                    libc::SYS_getpeername,
                    libc::SYS_sendto,
                ]);
            let Ok(listener) = listener else {
                let _ = listener_tx.send(listener);
                return;
            };
            if listener_tx.send(Ok(listener)).is_err() {
                return;
            }
            let mut command = std::process::Command::new(executable);
            command
                .arg(CAPABILITY_SOCKET_CHILD_SUBCOMMAND)
                .arg(original_peer.to_string())
                .arg(sandbox_tgid.to_string())
                .env_clear()
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::inherit());
            // SAFETY: the hook uses only raw signal/process syscalls and the
            // prebuilt, allocation-free seccomp installation path.
            unsafe {
                command.pre_exec(move || {
                    if libc::setpgid(0, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    set_child_core_limit()?;
                    reset_child_signal_dispositions()?;
                    child_hardening.install()?;
                    install_child_signal_mask()
                });
            }
            let child = command.spawn();
            let _ = child_tx.send(child);
        })
        .into_diagnostic()?;

    let listener = listener_rx
        .recv()
        .into_diagnostic()
        .wrap_err("socket probe launcher stopped before listener handoff")?
        .into_diagnostic()
        .wrap_err("install socket probe listener")?;
    let mut child = child_rx
        .recv()
        .into_diagnostic()
        .wrap_err("socket probe launcher stopped before child spawn")?
        .into_diagnostic()
        .wrap_err("spawn socket probe child")?;
    let mut registry = SocketRegistry::new(1, 8).into_diagnostic()?;
    let mut observed_tcp_sockets = 0_u8;
    let mut observed_dns_socket = false;
    let mut observed_connect = false;
    let mut observed_dns_tcp_connect = false;
    let mut observed_denied_connect = false;
    let mut observed_peer = false;
    let mut observed_dns_send = false;

    while !(observed_tcp_sockets == 3
        && observed_dns_socket
        && observed_connect
        && observed_dns_tcp_connect
        && observed_denied_connect
        && observed_peer
        && observed_dns_send)
    {
        let notification = listener
            .receive()
            .into_diagnostic()
            .wrap_err("receive socket probe notification")?;
        match i64::from(notification.syscall) {
            libc::SYS_socket => {
                if notification.args[0] != u64::try_from(libc::AF_INET).unwrap() {
                    listener
                        .respond_errno(notification.id, libc::EPROTONOSUPPORT)
                        .into_diagnostic()?;
                    return Err(miette::miette!("unexpected socket probe request"));
                }
                let requested_type = i32::try_from(notification.args[1])
                    .map_err(|_| miette::miette!("socket type does not fit i32"))?;
                let base_type = requested_type & !(libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK);
                let protocol = i32::try_from(notification.args[2])
                    .map_err(|_| miette::miette!("socket protocol does not fit i32"))?;
                let (kind, canonical_protocol) = match (base_type, protocol) {
                    (libc::SOCK_STREAM, 0 | libc::IPPROTO_TCP) if observed_tcp_sockets < 3 => {
                        observed_tcp_sockets += 1;
                        (InetKind::Tcp, libc::IPPROTO_TCP)
                    }
                    (libc::SOCK_DGRAM, 0 | libc::IPPROTO_UDP) if !observed_dns_socket => {
                        observed_dns_socket = true;
                        (InetKind::DnsUdp, libc::IPPROTO_UDP)
                    }
                    _ => {
                        listener
                            .respond_errno(notification.id, libc::EPROTONOSUPPORT)
                            .into_diagnostic()?;
                        return Err(miette::miette!("unexpected socket probe request"));
                    }
                };
                // SAFETY: scalar validated AF_INET/TCP arguments return one
                // newly owned descriptor on success.
                let source =
                    unsafe { libc::socket(libc::AF_INET, requested_type, canonical_protocol) };
                if source < 0 {
                    return Err(std::io::Error::last_os_error()).into_diagnostic();
                }
                // SAFETY: successful socket returned one newly owned FD.
                let source = unsafe { OwnedFd::from_raw_fd(source) };
                let close_on_exec = requested_type & libc::SOCK_CLOEXEC != 0;
                let tentative = registry
                    .stage(
                        source,
                        SocketMetadata {
                            family: InetFamily::V4,
                            kind,
                            close_on_exec,
                            nonblocking: requested_type & libc::SOCK_NONBLOCK != 0,
                            creator_generation: 1,
                        },
                    )
                    .into_diagnostic()?;
                listener
                    .add_fd_and_send(notification.id, tentative.source_fd(), close_on_exec)
                    .into_diagnostic()?;
                registry.commit(tentative).into_diagnostic()?;
            }
            libc::SYS_connect => {
                let fd = i32::try_from(notification.args[0])
                    .map_err(|_| miette::miette!("connect FD does not fit i32"))?;
                let destination = read_probe_sockaddr(
                    notification.tid,
                    notification.args[1],
                    notification.args[2],
                )?;
                let denied_peer = PROBE_DENIED_TCP_PEER
                    .parse::<SocketAddr>()
                    .expect("fixed denied peer is valid");
                if destination == denied_peer && !observed_denied_connect {
                    listener
                        .respond_errno(notification.id, libc::EACCES)
                        .into_diagnostic()?;
                    observed_denied_connect = true;
                    continue;
                }
                if destination != original_peer && destination != dns_relay_addr {
                    listener
                        .respond_errno(notification.id, libc::EACCES)
                        .into_diagnostic()?;
                    return Err(miette::miette!("unexpected socket probe destination"));
                }
                if (destination == original_peer && observed_connect)
                    || (destination == dns_relay_addr && observed_dns_tcp_connect)
                {
                    listener
                        .respond_errno(notification.id, libc::EALREADY)
                        .into_diagnostic()?;
                    return Err(miette::miette!("duplicate socket probe connect"));
                }
                let entry = registry
                    .resolve_mut(notification.tid, fd)
                    .into_diagnostic()?;
                entry.validate_retained_identity().into_diagnostic()?;
                let (sockaddr, length) = encode_probe_sockaddr(destination)?;
                // SAFETY: the retained FD is the registered injected socket;
                // `sockaddr` is live for the declared IPv4 length.
                let connected = unsafe {
                    libc::connect(
                        entry.retained_preconnect().into_diagnostic()?.as_raw_fd(),
                        sockaddr.as_ptr().cast(),
                        length,
                    )
                };
                if connected != 0 {
                    return Err(std::io::Error::last_os_error()).into_diagnostic();
                }
                if destination == dns_relay_addr {
                    entry.set_state(SocketState::DnsTcp {
                        relay: dns_relay_addr,
                    });
                    observed_dns_tcp_connect = true;
                } else {
                    entry.set_state(SocketState::Connected { original_peer });
                    observed_connect = true;
                }
                entry.release_preconnect();
                listener
                    .respond_value(notification.id, 0)
                    .into_diagnostic()?;
            }
            libc::SYS_getpeername => {
                let fd = i32::try_from(notification.args[0])
                    .map_err(|_| miette::miette!("peer FD does not fit i32"))?;
                let entry = registry.resolve(notification.tid, fd).into_diagnostic()?;
                let SocketState::Connected { original_peer } = entry.state() else {
                    listener
                        .respond_errno(notification.id, libc::ENOTCONN)
                        .into_diagnostic()?;
                    return Err(miette::miette!("peer query preceded mediated connect"));
                };
                write_probe_sockaddr(
                    notification.tid,
                    notification.args[1],
                    notification.args[2],
                    *original_peer,
                )?;
                listener
                    .respond_value(notification.id, 0)
                    .into_diagnostic()?;
                observed_peer = true;
            }
            libc::SYS_sendto => {
                let fd = i32::try_from(notification.args[0])
                    .map_err(|_| miette::miette!("sendto FD does not fit i32"))?;
                let length = usize::try_from(notification.args[2])
                    .map_err(|_| miette::miette!("DNS payload length does not fit usize"))?;
                if length == 0 || length > 512 || notification.args[3] != 0 {
                    listener
                        .respond_errno(notification.id, libc::EMSGSIZE)
                        .into_diagnostic()?;
                    return Err(miette::miette!("unexpected DNS probe payload shape"));
                }
                let destination = read_probe_sockaddr(
                    notification.tid,
                    notification.args[4],
                    notification.args[5],
                )?;
                if observed_dns_send || destination != dns_relay_addr {
                    listener
                        .respond_errno(notification.id, libc::EACCES)
                        .into_diagnostic()?;
                    return Err(miette::miette!("unexpected DNS probe destination"));
                }
                let mut payload = vec![0_u8; length];
                openshell_isolation_interface::linux::task_memory::read_exact(
                    notification.tid,
                    notification.args[1],
                    &mut payload,
                )
                .into_diagnostic()?;
                validate_probe_dns_query(&payload)?;
                let entry = registry
                    .resolve_mut(notification.tid, fd)
                    .into_diagnostic()?;
                if entry.metadata().kind != InetKind::DnsUdp
                    || !matches!(entry.state(), SocketState::Created)
                {
                    listener
                        .respond_errno(notification.id, libc::EACCES)
                        .into_diagnostic()?;
                    return Err(miette::miette!("DNS probe socket is not eligible"));
                }
                let (sockaddr, sockaddr_length) = encode_probe_sockaddr(destination)?;
                let retained = entry.retained_preconnect().into_diagnostic()?;
                // SAFETY: the retained source is the exact injected OFD and
                // both copied buffers remain live for their declared lengths.
                if unsafe {
                    libc::connect(
                        retained.as_raw_fd(),
                        sockaddr.as_ptr().cast(),
                        sockaddr_length,
                    )
                } != 0
                {
                    return Err(std::io::Error::last_os_error()).into_diagnostic();
                }
                let sent = unsafe {
                    libc::send(
                        retained.as_raw_fd(),
                        payload.as_ptr().cast(),
                        payload.len(),
                        libc::MSG_NOSIGNAL,
                    )
                };
                if sent != isize::try_from(payload.len()).expect("DNS payload fits isize") {
                    return Err(std::io::Error::last_os_error()).into_diagnostic();
                }
                entry.set_state(SocketState::DnsUdp {
                    relay: dns_relay_addr,
                });
                entry.release_preconnect();
                listener
                    .respond_value(
                        notification.id,
                        i64::try_from(length).expect("length fits i64"),
                    )
                    .into_diagnostic()?;
                observed_dns_send = true;
            }
            _ => {
                listener
                    .respond_errno(notification.id, libc::EPERM)
                    .into_diagnostic()?;
                return Err(miette::miette!("unexpected socket probe syscall"));
            }
        }
    }

    let status = child
        .wait()
        .into_diagnostic()
        .wrap_err("wait for socket probe child")?;
    launcher
        .join()
        .map_err(|_| miette::miette!("socket probe launcher panicked"))?;
    relay_thread
        .join()
        .map_err(|_| miette::miette!("socket probe relay panicked"))?
        .into_diagnostic()?;
    dns_thread
        .join()
        .map_err(|_| miette::miette!("socket probe DNS relay panicked"))?
        .into_diagnostic()?;
    dns_tcp_thread
        .join()
        .map_err(|_| miette::miette!("socket probe TCP DNS relay panicked"))?
        .into_diagnostic()?;
    if !status.success() {
        return Err(miette::miette!(
            "socket probe child exited with status {status}"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_probe_dns_query(query: &[u8]) -> Result<()> {
    const EXPECTED_QUESTION: &[u8] = b"\x05probe\x09openshell\x04test\x00\x00\x01\x00\x01";
    if query.len() != 12 + EXPECTED_QUESTION.len()
        || query[2] & 0x80 != 0
        || query[4..6] != [0, 1]
        || &query[12..] != EXPECTED_QUESTION
    {
        return Err(miette::miette!("DNS probe query is malformed"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn build_probe_dns_response(query: &[u8]) -> std::io::Result<Vec<u8>> {
    validate_probe_dns_query(query).map_err(std::io::Error::other)?;
    let mut response = query.to_vec();
    response[2..4].copy_from_slice(&[0x81, 0x80]);
    response[6..8].copy_from_slice(&[0, 1]);
    response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 7]);
    Ok(response)
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn block_launcher_signals() -> std::io::Result<()> {
    let mut signals = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: `signals` points to writable sigset storage and pthread_sigmask
    // copies it during the call.
    if unsafe { libc::sigfillset(signals.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: sigfillset initialized the value above.
    let signals = unsafe { signals.assume_init() };
    // SAFETY: changing the mask affects only the dedicated launcher thread.
    let result =
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &raw const signals, std::ptr::null_mut()) };
    if result != 0 {
        return Err(std::io::Error::from_raw_os_error(result));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
unsafe fn set_child_core_limit() -> std::io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a live fixed-size rlimit and this child-only update
    // permanently disables core dumps before any untrusted instruction.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const limit) } < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
unsafe fn reset_child_signal_dispositions() -> std::io::Result<()> {
    // SAFETY: an all-zero sigaction is a valid base before the explicit
    // default handler and empty mask are installed below.
    let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
    action.sa_sigaction = libc::SIG_DFL;
    // SAFETY: action.sa_mask points to writable sigset storage.
    if unsafe { libc::sigemptyset(&raw mut action.sa_mask) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    for signal in 1..LINUX_SIGNAL_LIMIT {
        if signal == libc::SIGKILL || signal == libc::SIGSTOP {
            continue;
        }
        // SAFETY: action contains the default disposition and the null output
        // pointer requests no previous action.
        if unsafe { libc::sigaction(signal, &raw const action, std::ptr::null_mut()) } < 0 {
            let error = std::io::Error::last_os_error();
            // glibc reserves two real-time signals for its threading runtime;
            // Linux rejects sigaction for those numbers with EINVAL.
            if error.raw_os_error() != Some(libc::EINVAL) {
                return Err(error);
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn install_child_signal_mask() -> std::io::Result<()> {
    let mut signals = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: `signals` points to writable sigset storage.
    if unsafe { libc::sigemptyset(signals.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: sigemptyset initialized the value above.
    let signals = unsafe { signals.assume_init() };
    // SAFETY: this installs the declared empty target mask immediately before
    // exec, after copied sandbox dispositions have been reset.
    let result = unsafe {
        libc::pthread_sigmask(libc::SIG_SETMASK, &raw const signals, std::ptr::null_mut())
    };
    if result != 0 {
        return Err(std::io::Error::from_raw_os_error(result));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_probe_sockaddr(tid: u32, address: u64, length: u64) -> Result<std::net::SocketAddr> {
    let length =
        usize::try_from(length).map_err(|_| miette::miette!("sockaddr length too large"))?;
    if length != PROBE_SOCKADDR_IN_LEN {
        return Err(miette::miette!("socket probe requires an IPv4 sockaddr"));
    }
    let mut bytes = vec![0_u8; length];
    openshell_isolation_interface::linux::task_memory::read_exact(tid, address, &mut bytes)
        .into_diagnostic()?;
    decode_probe_sockaddr(&bytes)
}

#[cfg(target_os = "linux")]
fn encode_probe_sockaddr(
    address: std::net::SocketAddr,
) -> Result<([u8; PROBE_SOCKADDR_IN_LEN], libc::socklen_t)> {
    let std::net::SocketAddr::V4(address) = address else {
        return Err(miette::miette!("socket probe requires IPv4"));
    };
    let mut bytes = [0_u8; PROBE_SOCKADDR_IN_LEN];
    bytes[0..2].copy_from_slice(
        &libc::sa_family_t::try_from(libc::AF_INET)
            .expect("AF_INET fits sa_family_t")
            .to_ne_bytes(),
    );
    bytes[2..4].copy_from_slice(&address.port().to_be_bytes());
    bytes[4..8].copy_from_slice(&address.ip().octets());
    Ok((
        bytes,
        libc::socklen_t::try_from(PROBE_SOCKADDR_IN_LEN)
            .expect("sockaddr_in length fits socklen_t"),
    ))
}

#[cfg(target_os = "linux")]
fn decode_probe_sockaddr(bytes: &[u8]) -> Result<std::net::SocketAddr> {
    if bytes.len() != PROBE_SOCKADDR_IN_LEN {
        return Err(miette::miette!("socket probe requires an IPv4 sockaddr"));
    }
    let family = libc::sa_family_t::from_ne_bytes([bytes[0], bytes[1]]);
    if i32::from(family) != libc::AF_INET {
        return Err(miette::miette!("socket probe sockaddr is not IPv4"));
    }
    Ok(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]),
        u16::from_be_bytes([bytes[2], bytes[3]]),
    )))
}

#[cfg(target_os = "linux")]
fn write_probe_sockaddr(
    tid: u32,
    address: u64,
    length_address: u64,
    peer: std::net::SocketAddr,
) -> Result<()> {
    use std::mem::size_of;

    let (sockaddr, sockaddr_length) = encode_probe_sockaddr(peer)?;
    let mut requested_length = [0_u8; size_of::<libc::socklen_t>()];
    openshell_isolation_interface::linux::task_memory::read_exact(
        tid,
        length_address,
        &mut requested_length,
    )
    .into_diagnostic()?;
    let requested_length = libc::socklen_t::from_ne_bytes(requested_length);
    if requested_length < sockaddr_length {
        return Err(miette::miette!("peer sockaddr buffer is too small"));
    }
    openshell_isolation_interface::linux::task_memory::write_exact(tid, address, &sockaddr)
        .into_diagnostic()?;
    openshell_isolation_interface::linux::task_memory::write_exact(
        tid,
        length_address,
        &sockaddr_length.to_ne_bytes(),
    )
    .into_diagnostic()?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn run_capability_socket_child(args: &[String]) -> Result<()> {
    use std::io::Read as _;
    use std::net::SocketAddr;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

    let [expected_peer, sandbox_tgid] = args else {
        return Err(miette::miette!(
            "usage: {CAPABILITY_SOCKET_CHILD_SUBCOMMAND} <IPv4:PORT> <SANDBOX_TGID>"
        ));
    };
    let expected_peer = expected_peer
        .parse::<SocketAddr>()
        .into_diagnostic()
        .map_err(|error| miette::miette!("parse socket probe peer: {error}"))?;
    let sandbox_tgid = sandbox_tgid
        .parse::<libc::pid_t>()
        .into_diagnostic()
        .map_err(|error| miette::miette!("parse sandbox TGID: {error}"))?;
    let (sockaddr, sockaddr_length) = encode_probe_sockaddr(expected_peer)?;

    // SAFETY: this call is intentionally intercepted and completed with one
    // newly injected socket descriptor.
    let socket = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            libc::IPPROTO_TCP,
        )
    };
    if socket < 0 {
        return Err(std::io::Error::last_os_error()).into_diagnostic();
    }
    // SAFETY: successful socket returned one newly owned descriptor.
    let socket = unsafe { OwnedFd::from_raw_fd(socket) };
    // SAFETY: dup creates an alias of the same open-file description.
    let alias = unsafe { libc::dup(socket.as_raw_fd()) };
    if alias < 0 {
        return Err(std::io::Error::last_os_error()).into_diagnostic();
    }
    // SAFETY: successful dup returned one newly owned descriptor.
    let alias = unsafe { OwnedFd::from_raw_fd(alias) };

    // SAFETY: epoll_create1 returns one owned descriptor; epoll_ctl consumes
    // only the live event value for this call.
    let epoll = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epoll < 0 {
        return Err(std::io::Error::last_os_error()).into_diagnostic();
    }
    // SAFETY: successful epoll_create1 returned one newly owned descriptor.
    let epoll = unsafe { OwnedFd::from_raw_fd(epoll) };
    let mut event = libc::epoll_event {
        events: u32::try_from(libc::EPOLLIN | libc::EPOLLOUT).expect("epoll flags fit u32"),
        u64: 1,
    };
    // SAFETY: descriptors and event pointer are live for this call.
    if unsafe {
        libc::epoll_ctl(
            epoll.as_raw_fd(),
            libc::EPOLL_CTL_ADD,
            socket.as_raw_fd(),
            std::ptr::addr_of_mut!(event),
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error()).into_diagnostic();
    }

    // SAFETY: the sockaddr is live and the alias references the mediated OFD.
    if unsafe { libc::connect(alias.as_raw_fd(), sockaddr.as_ptr().cast(), sockaddr_length) } != 0 {
        return Err(std::io::Error::last_os_error()).into_diagnostic();
    }

    let mut observed_peer = [0_u8; PROBE_SOCKADDR_IN_LEN];
    let mut observed_length =
        libc::socklen_t::try_from(PROBE_SOCKADDR_IN_LEN).expect("sockaddr length fits socklen_t");
    // SAFETY: the output objects are live for the full declared length.
    if unsafe {
        libc::getpeername(
            socket.as_raw_fd(),
            observed_peer.as_mut_ptr().cast(),
            std::ptr::addr_of_mut!(observed_length),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).into_diagnostic();
    }
    let observed = decode_probe_sockaddr(&observed_peer)?;
    if observed != expected_peer {
        return Err(miette::miette!(
            "socket probe peer mismatch: expected {expected_peer}, got {observed}"
        ));
    }

    let request = b"ping";
    // SAFETY: null destination on a connected socket follows the cBPF fast
    // path and reads only the live request buffer.
    let sent = unsafe {
        libc::sendto(
            alias.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            libc::MSG_NOSIGNAL,
            std::ptr::null(),
            0,
        )
    };
    if sent != isize::try_from(request.len()).expect("request length fits isize") {
        return Err(std::io::Error::last_os_error()).into_diagnostic();
    }
    let mut ready = libc::epoll_event { events: 0, u64: 0 };
    // SAFETY: event points to storage for one returned event.
    if unsafe { libc::epoll_wait(epoll.as_raw_fd(), std::ptr::addr_of_mut!(ready), 1, 5_000) } <= 0
    {
        return Err(std::io::Error::last_os_error()).into_diagnostic();
    }
    let mut stream = std::net::TcpStream::from(socket);
    let mut response = [0_u8; 4];
    stream.read_exact(&mut response).into_diagnostic()?;
    if &response != b"pong" {
        return Err(miette::miette!("socket probe response mismatch"));
    }
    probe_dns_socket_round_trip()?;
    probe_tcp_dns_socket_round_trip()?;
    probe_tcp_denial()?;
    probe_child_self_protection(sandbox_tgid, alias.as_raw_fd())?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run_capability_socket_child(_args: &[String]) -> Result<()> {
    Err(miette::miette!(
        "socket qualification is supported only on Linux"
    ))
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn probe_dns_socket_round_trip() -> Result<()> {
    use std::net::SocketAddr;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

    const DNS_QUERY: &[u8] =
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05probe\x09openshell\x04test\x00\x00\x01\x00\x01";
    let relay = "127.0.0.53:53"
        .parse::<SocketAddr>()
        .expect("fixed DNS relay address is valid");
    let (sockaddr, sockaddr_length) = encode_probe_sockaddr(relay)?;
    // SAFETY: the syscall is intercepted and completed with a DNS-only
    // registered socket descriptor.
    let socket = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::IPPROTO_UDP,
        )
    };
    if socket < 0 {
        return Err(std::io::Error::last_os_error()).into_diagnostic();
    }
    // SAFETY: successful socket returned one newly owned descriptor.
    let socket = unsafe { OwnedFd::from_raw_fd(socket) };
    // SAFETY: the destination and query buffers are live for the call. The
    // broker copies and emulates this send before replying to the notification.
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            DNS_QUERY.as_ptr().cast(),
            DNS_QUERY.len(),
            0,
            sockaddr.as_ptr().cast(),
            sockaddr_length,
        )
    };
    if sent != isize::try_from(DNS_QUERY.len()).expect("DNS query length fits isize") {
        return Err(std::io::Error::last_os_error()).into_diagnostic();
    }

    let mut response = [0_u8; 512];
    let mut source = [0_u8; PROBE_SOCKADDR_IN_LEN];
    let mut source_length =
        libc::socklen_t::try_from(source.len()).expect("sockaddr length fits socklen_t");
    // SAFETY: all output buffers are live for their declared lengths.
    let received = unsafe {
        libc::recvfrom(
            socket.as_raw_fd(),
            response.as_mut_ptr().cast(),
            response.len(),
            0,
            source.as_mut_ptr().cast(),
            std::ptr::addr_of_mut!(source_length),
        )
    };
    if received < 0 {
        return Err(std::io::Error::last_os_error()).into_diagnostic();
    }
    let source = decode_probe_sockaddr(&source)?;
    if source != relay {
        return Err(miette::miette!(
            "DNS response source mismatch: expected {relay}, got {source}"
        ));
    }
    let received = usize::try_from(received).expect("positive recv length fits usize");
    if received < 16
        || response[0..2] != DNS_QUERY[0..2]
        || response[2] & 0x80 == 0
        || response[received - 4..received] != [203, 0, 113, 7]
    {
        return Err(miette::miette!("DNS probe response is malformed"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn probe_tcp_dns_socket_round_trip() -> Result<()> {
    use std::io::{Read as _, Write as _};

    const DNS_QUERY: &[u8] =
        b"\x56\x78\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05probe\x09openshell\x04test\x00\x00\x01\x00\x01";
    let mut stream = std::net::TcpStream::connect("127.0.0.53:53").into_diagnostic()?;
    stream.set_nodelay(true).into_diagnostic()?;
    stream
        .write_all(
            &u16::try_from(DNS_QUERY.len())
                .expect("probe DNS query fits u16")
                .to_be_bytes(),
        )
        .into_diagnostic()?;
    stream.write_all(DNS_QUERY).into_diagnostic()?;
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length).into_diagnostic()?;
    let length = usize::from(u16::from_be_bytes(length));
    if length == 0 || length > 512 {
        return Err(miette::miette!("TCP DNS probe response length is invalid"));
    }
    let mut response = vec![0_u8; length];
    stream.read_exact(&mut response).into_diagnostic()?;
    if length < 16
        || response[0..2] != DNS_QUERY[0..2]
        || response[2] & 0x80 == 0
        || response[length - 4..] != [203, 0, 113, 7]
    {
        return Err(miette::miette!("TCP DNS probe response is malformed"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn probe_tcp_denial() -> Result<()> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

    let peer = PROBE_DENIED_TCP_PEER
        .parse::<std::net::SocketAddr>()
        .expect("fixed denied peer is valid");
    let (sockaddr, length) = encode_probe_sockaddr(peer)?;
    // SAFETY: socket creation is intercepted and returns one injected FD.
    let socket = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            libc::IPPROTO_TCP,
        )
    };
    if socket < 0 {
        return Err(std::io::Error::last_os_error()).into_diagnostic();
    }
    // SAFETY: successful socket returned one newly owned descriptor.
    let socket = unsafe { OwnedFd::from_raw_fd(socket) };
    // SAFETY: both the injected FD and encoded sockaddr are live.
    let result = unsafe { libc::connect(socket.as_raw_fd(), sockaddr.as_ptr().cast(), length) };
    require_probe_errno(
        isize::try_from(result).expect("connect result fits isize"),
        libc::EACCES,
        "denied TCP connect",
    )
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn probe_child_self_protection(sandbox_tgid: libc::pid_t, socket: libc::c_int) -> Result<()> {
    // SAFETY: PR_GET_DUMPABLE reads one scalar property. Normal exec of the
    // trusted child image must make it observable to the same-UID sandbox.
    if unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 1 {
        return Err(miette::miette!("workload child is not dumpable after exec"));
    }
    let mut core_limit = libc::rlimit {
        rlim_cur: libc::rlim_t::MAX,
        rlim_max: libc::rlim_t::MAX,
    };
    // SAFETY: `core_limit` is writable storage for the current limit.
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &raw mut core_limit) } < 0 {
        return Err(std::io::Error::last_os_error()).into_diagnostic();
    }
    if core_limit.rlim_cur != 0 || core_limit.rlim_max != 0 {
        return Err(miette::miette!("workload child core limit is not zero"));
    }
    let mut local = 0_u8;
    let remote = 0_u8;
    let local_iov = libc::iovec {
        iov_base: std::ptr::addr_of_mut!(local).cast(),
        iov_len: 1,
    };
    let remote_iov = libc::iovec {
        iov_base: std::ptr::addr_of!(remote).cast_mut().cast(),
        iov_len: 1,
    };
    // SAFETY: live one-byte iovecs are supplied. The child filter must reject
    // the operation before the kernel inspects the remote pointer.
    let read = unsafe {
        libc::process_vm_readv(
            sandbox_tgid,
            &raw const local_iov,
            1,
            &raw const remote_iov,
            1,
            0,
        )
    };
    require_probe_errno(read, libc::EPERM, "process_vm_readv sandbox")?;
    // SAFETY: signal zero would only probe process existence if the filter did
    // not reject the trusted sandbox target.
    require_probe_errno(
        isize::try_from(unsafe { libc::kill(sandbox_tgid, 0) }).expect("kill result fits isize"),
        libc::EPERM,
        "kill sandbox",
    )?;
    // SAFETY: scalar syscall arguments request a read-only resource query;
    // the child filter rejects non-self targets.
    require_probe_errno(
        isize::try_from(unsafe {
            libc::syscall(libc::SYS_prlimit64, sandbox_tgid, libc::RLIMIT_CORE, 0, 0)
        })
        .expect("prlimit result fits isize"),
        libc::EPERM,
        "prlimit sandbox",
    )?;
    require_probe_errno(
        isize::try_from(unsafe { libc::kill(-sandbox_tgid, 0) }).expect("kill result fits isize"),
        libc::EPERM,
        "process-group signal",
    )?;
    require_probe_errno(
        isize::try_from(unsafe { libc::fcntl(socket, libc::F_SETOWN, sandbox_tgid) })
            .expect("fcntl result fits isize"),
        libc::EPERM,
        "fcntl F_SETOWN",
    )?;
    let mut owner = sandbox_tgid;
    require_probe_errno(
        isize::try_from(unsafe {
            libc::syscall(libc::SYS_ioctl, socket, 0x8901_u32, &raw mut owner)
        })
        .expect("ioctl result fits isize"),
        libc::EPERM,
        "ioctl FIOSETOWN",
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_probe_errno(result: isize, expected: i32, operation: &str) -> Result<()> {
    if result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(expected) {
        Ok(())
    } else {
        Err(miette::miette!(
            "{operation} was not rejected with errno {expected}"
        ))
    }
}

/// Exercise the trusted VM bootstrap transition before running the Phase 0
/// capability probe. This command is intentionally hidden: it exists so the
/// VM conformance lane can prove that a privileged guest init can hand off to
/// a non-root, capability-free sandbox without relying on a shell utility.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn enter_capability_free_identity(uid: u32, gid: u32) -> Result<()> {
    use miette::{Context as _, IntoDiagnostic as _};

    #[repr(C)]
    struct CapabilityHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapabilityData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    if uid == 0 || gid == 0 {
        return Err(miette::miette!(
            "capability-free launch requires non-root UID and GID"
        ));
    }
    if nix::unistd::geteuid().as_raw() != 0 {
        return Err(miette::miette!("capability-free launch must start as root"));
    }

    let cap_last_cap = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .into_diagnostic()
        .wrap_err("read cap_last_cap")?
        .trim()
        .parse::<u32>()
        .into_diagnostic()
        .wrap_err("parse cap_last_cap")?;
    for capability in 0..=cap_last_cap {
        // SAFETY: PR_CAPBSET_DROP only removes one capability from the current
        // process' bounding set. The loop runs while guest init still has the
        // authority required to perform the transition.
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) } < 0 {
            return Err(miette::miette!(
                "drop capability {capability} from bounding set: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    // SAFETY: the process is single-threaded at this pre-clap bootstrap path;
    // the null pointer is valid for a zero-length supplementary group list.
    if unsafe { libc::setgroups(0, std::ptr::null()) } < 0 {
        return Err(miette::miette!(
            "clear supplementary groups: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: scalar credential transition to the operator-selected guest
    // identity. All saved IDs are changed so the process cannot regain root.
    if unsafe { libc::setresgid(gid, gid, gid) } < 0 {
        return Err(miette::miette!(
            "set guest GID {gid}: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: see setresgid above.
    if unsafe { libc::setresuid(uid, uid, uid) } < 0 {
        return Err(miette::miette!(
            "set guest UID {uid}: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut header = CapabilityHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [CapabilityData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: capset reads the fixed-size header and two zeroed V3 data words.
    if unsafe { libc::syscall(libc::SYS_capset, &raw mut header, data.as_ptr()) } < 0 {
        return Err(miette::miette!(
            "clear process capability sets: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: clears any ambient capabilities, then permanently forbids
    // privilege gain across the following exec.
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } < 0
    {
        return Err(miette::miette!(
            "clear ambient capabilities: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: PR_SET_NO_NEW_PRIVS is a one-way process hardening transition.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        return Err(miette::miette!(
            "set no_new_privs: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn launch_capability_probe(args: &[String]) -> Result<()> {
    use miette::{Context as _, IntoDiagnostic as _};

    let [uid, gid] = args else {
        return Err(miette::miette!(
            "usage: openshell-sandbox {CAPABILITY_PROBE_LAUNCH_SUBCOMMAND} <UID> <GID>"
        ));
    };
    let uid = uid.parse::<u32>().into_diagnostic().wrap_err("parse UID")?;
    let gid = gid.parse::<u32>().into_diagnostic().wrap_err("parse GID")?;
    enter_capability_free_identity(uid, gid)?;
    run_capability_probe()
}

#[cfg(not(target_os = "linux"))]
fn launch_capability_probe(_args: &[String]) -> Result<()> {
    Err(miette::miette!(
        "capability probe launch is supported only on Linux"
    ))
}

#[cfg(target_os = "linux")]
fn launch_capability_free(args: &[String]) -> Result<()> {
    use miette::{Context as _, IntoDiagnostic as _};

    let [uid, gid, bootstrap] = args else {
        return Err(miette::miette!(
            "usage: openshell-sandbox {CAPABILITY_FREE_LAUNCH_SUBCOMMAND} <UID> <GID> <BOOTSTRAP>"
        ));
    };
    let uid = uid.parse::<u32>().into_diagnostic().wrap_err("parse UID")?;
    let gid = gid.parse::<u32>().into_diagnostic().wrap_err("parse GID")?;
    enter_capability_free_identity(uid, gid)?;
    let log_level = std::env::var(openshell_core::sandbox_env::LOG_LEVEL)
        .unwrap_or_else(|_| "warn".to_string());
    run_boundary(Path::new(bootstrap), &log_level)
}

#[cfg(not(target_os = "linux"))]
fn launch_capability_free(_args: &[String]) -> Result<()> {
    Err(miette::miette!(
        "capability-free launch is only supported on Linux"
    ))
}

#[cfg(not(target_os = "linux"))]
fn run_capability_probe() -> Result<()> {
    Err(miette::miette!(
        "capability-free sandbox probe is supported only on Linux"
    ))
}

#[cfg(target_os = "linux")]
fn proc_status_hex(status: &str, field: &str) -> Result<u64> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{field}:")))
        .map(str::trim)
        .ok_or_else(|| miette::miette!("/proc/self/status is missing {field}"))?;
    u64::from_str_radix(value, 16)
        .map_err(|error| miette::miette!("invalid {field} value {value:?}: {error}"))
}

/// Copy the running executable to `dest`, creating parent directories as
/// needed and ensuring the result is executable (mode `0755`).
///
/// If `dest` already exists as a directory, the binary is placed inside it
/// using the source executable's file name. This mirrors `cp` semantics so
/// callers can pass either a full target path or a directory.
fn copy_self(dest: &str) -> Result<()> {
    let exe = std::env::current_exe().into_diagnostic()?;

    let dest_path = Path::new(dest);
    let final_path = if dest_path.is_dir() {
        let file_name = exe
            .file_name()
            .ok_or_else(|| miette::miette!("current_exe has no file name: {}", exe.display()))?;
        dest_path.join(file_name)
    } else {
        dest_path.to_path_buf()
    };

    if let Some(parent) = final_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).into_diagnostic()?;
    }

    std::fs::copy(&exe, &final_path).into_diagnostic()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&final_path)
            .into_diagnostic()?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&final_path, perms).into_diagnostic()?;
    }

    Ok(())
}

/// Stage the immutable Kubernetes bootstrap Secret into private writable
/// memory-backed volumes. The projected Secret remains mounted only in this
/// trusted init container; the long-lived sandbox consumes and unlinks the
/// staged configuration before it starts workload code.
#[cfg(target_os = "linux")]
fn stage_kubernetes_bootstrap() -> Result<()> {
    stage_kubernetes_bootstrap_at(
        Path::new(BOOTSTRAP_INPUT_ROOT),
        Path::new(SANDBOX_RUNTIME_ROOT),
        Path::new(SANDBOX_STATE_ROOT),
    )
}

/// Stage protected state without performing a duplicate runtime probe. The
/// long-lived sandbox actively qualifies its own exact admitted profile before
/// consuming this material.
#[cfg(target_os = "linux")]
fn run_kubernetes_bootstrap() -> Result<()> {
    stage_kubernetes_bootstrap()
}

#[cfg(not(target_os = "linux"))]
fn run_kubernetes_bootstrap() -> Result<()> {
    Err(miette::miette!(
        "Kubernetes sandbox bootstrap requires Linux"
    ))
}

#[cfg(any(target_os = "linux", test))]
fn stage_kubernetes_bootstrap_at(source: &Path, runtime: &Path, state: &Path) -> Result<()> {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::PermissionsExt as _;

    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    if uid == 0 || gid == 0 {
        return Err(miette::miette!(
            "Kubernetes bootstrap staging requires a non-root UID and GID, got {uid}:{gid}"
        ));
    }

    fs::create_dir_all(runtime).into_diagnostic()?;
    fs::create_dir_all(state).into_diagnostic()?;

    let nonce = format!(
        "{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .into_diagnostic()?
            .as_nanos()
    );
    let runtime_tmp = runtime.join(format!(".openshell-sandbox.{nonce}"));
    let runtime_final = runtime.join("openshell-sandbox");
    let executable = std::env::current_exe().into_diagnostic()?;
    copy_regular_file(&executable, &runtime_tmp, 0o500)?;
    fs::rename(&runtime_tmp, &runtime_final).into_diagnostic()?;

    let bundle_tmp = state.join(format!(".bootstrap.{nonce}"));
    let bundle_final = state.join("bootstrap");
    fs::create_dir(&bundle_tmp).into_diagnostic()?;
    fs::set_permissions(&bundle_tmp, fs::Permissions::from_mode(0o700)).into_diagnostic()?;
    for name in ["boundary.json", "tls.crt", "tls.key", "client-ca.crt"] {
        copy_projected_secret_file(source, name, &bundle_tmp.join(name), 0o600)?;
    }
    fs::rename(&bundle_tmp, &bundle_final).into_diagnostic()?;

    // Flush the two directory entries before the init container exits. Both
    // targets are tmpfs in production, but keeping the staging operation
    // durable also makes the helper safe in local conformance tests.
    OpenOptions::new()
        .read(true)
        .open(runtime)
        .into_diagnostic()?
        .sync_all()
        .into_diagnostic()?;
    OpenOptions::new()
        .read(true)
        .open(state)
        .into_diagnostic()?
        .sync_all()
        .into_diagnostic()?;
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn copy_projected_secret_file(
    source_root: &Path,
    name: &str,
    destination: &Path,
    mode: u32,
) -> Result<()> {
    let canonical_root = std::fs::canonicalize(source_root).into_diagnostic()?;
    let canonical_source = std::fs::canonicalize(source_root.join(name)).into_diagnostic()?;
    if !canonical_source.starts_with(&canonical_root) {
        return Err(miette::miette!(
            "projected bootstrap input escapes its mounted Secret: {}",
            source_root.join(name).display()
        ));
    }
    copy_regular_file(&canonical_source, destination, mode)
}

#[cfg(any(target_os = "linux", test))]
fn copy_regular_file(source: &Path, destination: &Path, mode: u32) -> Result<()> {
    use std::fs::{self, OpenOptions};
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::OpenOptionsExt as _;

    let metadata = fs::symlink_metadata(source).into_diagnostic()?;
    if !metadata.file_type().is_file() || metadata.len() == 0 {
        return Err(miette::miette!(
            "bootstrap input must be a non-empty regular file: {}",
            source.display()
        ));
    }
    let mut input = OpenOptions::new()
        .read(true)
        .open(source)
        .into_diagnostic()?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(destination)
        .into_diagnostic()?;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let length = input.read(&mut buffer).into_diagnostic()?;
        if length == 0 {
            break;
        }
        output.write_all(&buffer[..length]).into_diagnostic()?;
    }
    output.sync_all().into_diagnostic()?;
    Ok(())
}

/// Seed the persistent workspace from the agent image as the final workload
/// identity. This replaces the former root shell/tar init container.
fn seed_kubernetes_workspace() -> Result<()> {
    seed_kubernetes_workspace_at(Path::new("/sandbox"), Path::new("/mnt/openshell-workspace"))
}

fn copy_workspace_tree(source: &Path, destination: &Path) -> Result<()> {
    use std::fs::{self, OpenOptions};
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, symlink};

    for entry in fs::read_dir(source).into_diagnostic()? {
        let entry = entry.into_diagnostic()?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path).into_diagnostic()?;
        if metadata.file_type().is_symlink() {
            symlink(
                fs::read_link(&source_path).into_diagnostic()?,
                &destination_path,
            )
            .into_diagnostic()?;
        } else if metadata.is_dir() {
            fs::create_dir(&destination_path).into_diagnostic()?;
            fs::set_permissions(&destination_path, fs::Permissions::from_mode(0o700))
                .into_diagnostic()?;
            copy_workspace_tree(&source_path, &destination_path)?;
        } else if metadata.is_file() {
            let mut input = OpenOptions::new()
                .read(true)
                .open(&source_path)
                .into_diagnostic()?;
            let mode = 0o600 | (metadata.permissions().mode() & 0o100);
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&destination_path)
                .into_diagnostic()?;
            let mut buffer = [0_u8; 16 * 1024];
            loop {
                let length = input.read(&mut buffer).into_diagnostic()?;
                if length == 0 {
                    break;
                }
                output.write_all(&buffer[..length]).into_diagnostic()?;
            }
            output.sync_all().into_diagnostic()?;
        } else {
            return Err(miette::miette!(
                "workspace seed contains unsupported file type: {}",
                source_path.display()
            ));
        }
    }
    Ok(())
}

fn seed_kubernetes_workspace_at(source: &Path, destination: &Path) -> Result<()> {
    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let sentinel = destination.join(".openshell-initialized");
    if sentinel.try_exists().into_diagnostic()? {
        return Ok(());
    }
    let destination_metadata = fs::symlink_metadata(destination).into_diagnostic()?;
    if !destination_metadata.is_dir() || destination_metadata.file_type().is_symlink() {
        return Err(miette::miette!(
            "workspace target must be a real directory: {}",
            destination.display()
        ));
    }

    if source.try_exists().into_diagnostic()? {
        let metadata = fs::symlink_metadata(source).into_diagnostic()?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(miette::miette!(
                "image workspace must be a real directory: {}",
                source.display()
            ));
        }
        copy_workspace_tree(source, destination)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&sentinel)
        .into_diagnostic()?;
    file.write_all(b"initialized\n").into_diagnostic()?;
    file.sync_all().into_diagnostic()?;
    OpenOptions::new()
        .read(true)
        .open(destination)
        .into_diagnostic()?
        .sync_all()
        .into_diagnostic()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_boundary(bootstrap: &Path, log_level: &str) -> Result<()> {
    let console_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));
    let _ = tracing_subscriber::registry()
        .with(
            OcsfShorthandLayer::new(std::io::stderr())
                .with_non_ocsf(true)
                .with_filter(console_filter),
        )
        .try_init();
    let (qualification, _) = qualify_runtime()?;
    openshell_sandbox::run(bootstrap, qualification)
}

#[cfg(not(target_os = "linux"))]
fn run_boundary(_bootstrap: &Path, _log_level: &str) -> Result<()> {
    Err(miette::miette!("openshell-sandbox requires Linux"))
}

fn main() -> Result<()> {
    let raw_args = std::env::args().collect::<Vec<_>>();
    if raw_args.get(1).map(String::as_str) == Some(COPY_SELF_SUBCOMMAND) {
        let dest = raw_args.get(2).ok_or_else(|| {
            miette::miette!("usage: openshell-sandbox {COPY_SELF_SUBCOMMAND} <DEST>")
        })?;
        return copy_self(dest);
    }
    if raw_args.get(1).map(String::as_str) == Some(BOOTSTRAP_SUBCOMMAND) {
        if raw_args.len() != 2 {
            return Err(miette::miette!(
                "usage: openshell-sandbox {BOOTSTRAP_SUBCOMMAND}"
            ));
        }
        return run_kubernetes_bootstrap();
    }
    if raw_args.get(1).map(String::as_str) == Some(SEED_WORKSPACE_SUBCOMMAND) {
        if raw_args.len() != 2 {
            return Err(miette::miette!(
                "usage: openshell-sandbox {SEED_WORKSPACE_SUBCOMMAND}"
            ));
        }
        return seed_kubernetes_workspace();
    }
    if raw_args.get(1).map(String::as_str) == Some(VALIDATE_WORKSPACE_SUBCOMMAND) {
        return validate_workspace(&raw_args[2..]);
    }
    if raw_args.get(1).map(String::as_str) == Some(CAPABILITY_PROBE_SUBCOMMAND) {
        return run_capability_probe();
    }
    if raw_args.get(1).map(String::as_str) == Some(CAPABILITY_PROBE_LAUNCH_SUBCOMMAND) {
        return launch_capability_probe(&raw_args[2..]);
    }
    if raw_args.get(1).map(String::as_str) == Some(CAPABILITY_SOCKET_CHILD_SUBCOMMAND) {
        return run_capability_socket_child(&raw_args[2..]);
    }
    if raw_args.get(1).map(String::as_str) == Some(CAPABILITY_LANDLOCK_CHILD_SUBCOMMAND) {
        return run_capability_landlock_child(&raw_args[2..]);
    }
    if raw_args.get(1).map(String::as_str) == Some(CAPABILITY_FREE_LAUNCH_SUBCOMMAND) {
        return launch_capability_free(&raw_args[2..]);
    }

    let args = BoundaryArgs::parse();
    run_boundary(&args.bootstrap, &args.log_level)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn kubernetes_bootstrap_stages_private_memory_bundle() {
        if nix::unistd::geteuid().is_root() || nix::unistd::getegid().as_raw() == 0 {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("input");
        let runtime = root.path().join("runtime");
        let state = root.path().join("state");
        std::fs::create_dir(&source).unwrap();
        let revision = source.join("..2026_09_04_00_00_00");
        std::fs::create_dir(&revision).unwrap();
        for (name, contents) in [
            ("boundary.json", b"{}".as_slice()),
            ("tls.crt", b"certificate".as_slice()),
            ("tls.key", b"private-key".as_slice()),
            ("client-ca.crt", b"client-ca".as_slice()),
        ] {
            std::fs::write(revision.join(name), contents).unwrap();
            std::os::unix::fs::symlink(format!("..data/{name}"), source.join(name)).unwrap();
        }
        std::os::unix::fs::symlink(revision.file_name().unwrap(), source.join("..data")).unwrap();

        stage_kubernetes_bootstrap_at(&source, &runtime, &state).unwrap();

        assert!(runtime.join("openshell-sandbox").is_file());
        assert_eq!(
            std::fs::metadata(runtime.join("openshell-sandbox"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o500
        );
        for name in ["boundary.json", "tls.crt", "tls.key", "client-ca.crt"] {
            let staged = state.join("bootstrap").join(name);
            assert_eq!(
                std::fs::read(&staged).unwrap(),
                std::fs::read(source.join(name)).unwrap()
            );
            assert_eq!(
                std::fs::metadata(staged).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn kubernetes_workspace_seed_preserves_files_and_symlinks_without_root() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let destination = root.path().join("destination");
        std::fs::create_dir_all(source.join("bin")).unwrap();
        std::fs::create_dir(&destination).unwrap();
        std::fs::write(source.join("README"), b"workspace").unwrap();
        std::fs::write(source.join("bin/tool"), b"tool").unwrap();
        let mut executable = std::fs::metadata(source.join("bin/tool"))
            .unwrap()
            .permissions();
        executable.set_mode(0o755);
        std::fs::set_permissions(source.join("bin/tool"), executable).unwrap();
        std::os::unix::fs::symlink("README", source.join("latest")).unwrap();

        seed_kubernetes_workspace_at(&source, &destination).unwrap();
        seed_kubernetes_workspace_at(&source, &destination).unwrap();

        assert_eq!(
            std::fs::read(destination.join("README")).unwrap(),
            b"workspace"
        );
        assert_eq!(
            std::fs::read_link(destination.join("latest")).unwrap(),
            Path::new("README")
        );
        assert_ne!(
            std::fs::metadata(destination.join("bin/tool"))
                .unwrap()
                .permissions()
                .mode()
                & 0o100,
            0
        );
        assert!(destination.join(".openshell-initialized").is_file());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn workspace_validation_subcommand_uses_final_policy_identity() {
        let uid = nix::unistd::geteuid().as_raw();
        let gid = nix::unistd::getegid().as_raw();
        if uid < 1000 || gid < 1000 {
            return;
        }
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o711)).unwrap();
        let root = dir.path().canonicalize().unwrap().join("workspace");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let args = vec![
            "--workdir".to_string(),
            root.display().to_string(),
            "--expected-uid".to_string(),
            uid.to_string(),
            "--expected-gid".to_string(),
            gid.to_string(),
        ];

        validate_workspace(&args).expect("current identity should retain workspace authority");
    }

    /// Drives `copy_self`'s file-copy logic against an arbitrary source path
    /// so tests don't depend on `current_exe()`.
    fn copy_executable(src: &Path, dest: &Path) -> Result<()> {
        let final_path = if dest.is_dir() {
            dest.join(src.file_name().unwrap())
        } else {
            dest.to_path_buf()
        };
        if let Some(parent) = final_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).into_diagnostic()?;
        }
        std::fs::copy(src, &final_path).into_diagnostic()?;
        let mut perms = std::fs::metadata(&final_path)
            .into_diagnostic()?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&final_path, perms).into_diagnostic()?;
        Ok(())
    }

    #[test]
    fn copy_self_writes_executable_at_target_path() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("source-bin");
        std::fs::write(&src, b"#!/bin/false\n").unwrap();

        let dest = tmp.path().join("subdir/openshell-sandbox");
        copy_executable(&src, &dest).unwrap();

        assert!(dest.exists(), "destination file should exist");
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755, "destination must be 0755");
        let copied = std::fs::read(&dest).unwrap();
        assert_eq!(copied, b"#!/bin/false\n");
    }

    #[test]
    fn copy_self_into_existing_directory_uses_source_filename() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("openshell-sandbox");
        std::fs::write(&src, b"binary").unwrap();

        let dest_dir = tmp.path().join("bin");
        std::fs::create_dir_all(&dest_dir).unwrap();

        copy_executable(&src, &dest_dir).unwrap();

        let final_path = dest_dir.join("openshell-sandbox");
        assert!(final_path.exists(), "binary should land inside dest dir");
    }
}
