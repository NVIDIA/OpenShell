// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Standing kernel confinement for workload INET sockets.
//!
//! Every workload INET socket is bound to the loopback device before its
//! descriptor is injected. The binding is kernel state on the socket itself,
//! so it survives `dup`, `fork`, `exec`, `AF_UNSPEC` disconnect, and is
//! inherited by sockets accepted from a confined listener. It restricts both
//! directions: route lookups are pinned to `lo`, and listener/UDP lookup only
//! matches packets that arrive on `lo`. Clearing or changing an existing
//! binding requires `CAP_NET_RAW` in the network namespace's owning user
//! namespace, which the capability-free sandbox and workload do not hold.

#![allow(unsafe_code)]

use std::ffi::CStr;
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};

const LOOPBACK_DEVICE: &CStr = c"lo";

/// Bind `fd` to the loopback device and verify the kernel recorded it.
///
/// # Errors
///
/// Returns the kernel error when the binding cannot be installed, or `EPERM`
/// when the socket is already bound to another device.
pub fn confine_to_loopback(fd: RawFd) -> io::Result<()> {
    let name = LOOPBACK_DEVICE.to_bytes_with_nul();
    // SAFETY: `name` is a live NUL-terminated buffer for the duration of the call.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            socklen(name.len())?,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if bound_device(fd)?.as_deref() == Some(LOOPBACK_DEVICE.to_bytes()) {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(libc::EPERM))
    }
}

/// Return the device name `fd` is bound to, or `None` when unbound.
///
/// # Errors
///
/// Returns the kernel error from `getsockopt(SO_BINDTODEVICE)`.
pub fn bound_device(fd: RawFd) -> io::Result<Option<Vec<u8>>> {
    let mut name = [0_u8; libc::IFNAMSIZ];
    let mut length = socklen(name.len())?;
    // SAFETY: `name` and `length` are live, writable outputs sized together.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_mut_ptr().cast(),
            &raw mut length,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let length = usize::try_from(length).unwrap_or(0).min(name.len());
    let name = name[..length]
        .split(|byte| *byte == 0)
        .next()
        .unwrap_or_default();
    Ok((!name.is_empty()).then(|| name.to_vec()))
}

/// Drop TCP/UDP ingress that arrives on the loopback interface.
///
/// Attach this to a trusted listener whose legitimate clients are never in the
/// same network namespace. Matching the ingress interface rather than the
/// source address also rejects connections to the host's own non-loopback
/// address, which the kernel delivers through loopback. The filter is locked
/// so later code cannot remove it accidentally.
///
/// # Errors
///
/// Returns the kernel error when the filter cannot be attached or locked.
pub fn reject_loopback_ingress(fd: RawFd) -> io::Result<()> {
    // SAFETY: LOOPBACK_DEVICE is a valid NUL-terminated interface name.
    let index = unsafe { libc::if_nametoindex(LOOPBACK_DEVICE.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    reject_ingress_interface(fd, index)
}

fn reject_ingress_interface(fd: RawFd, index: u32) -> io::Result<()> {
    // Ancillary loads use the documented negative offset encoding.
    let ifindex_offset = (libc::SKF_AD_OFF + libc::SKF_AD_IFINDEX).cast_unsigned();
    let mut program = [
        filter_stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, ifindex_offset),
        filter_jump(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, index, 0, 1),
        filter_stmt(libc::BPF_RET | libc::BPF_K, 0),
        filter_stmt(libc::BPF_RET | libc::BPF_K, u32::MAX),
    ];
    let filter = libc::sock_fprog {
        len: u16::try_from(program.len()).map_err(io::Error::other)?,
        filter: program.as_mut_ptr(),
    };
    // SAFETY: `filter` references `program`, which outlives the call.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            (&raw const filter).cast(),
            socklen(size_of::<libc::sock_fprog>())?,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    set_int_option(fd, libc::SOL_SOCKET, libc::SO_LOCK_FILTER, 1)
}

/// Actively prove loopback confinement under the current runtime profile.
///
/// For each supported workload socket type this installs the binding, proves
/// that the sandbox credentials cannot clear or replace it, and proves that a
/// stream accepted from a confined listener inherits it. IPv6 is skipped only
/// when the kernel does not provide the address family.
///
/// # Errors
///
/// Returns an error describing the first failed property.
pub fn probe_loopback_confinement() -> io::Result<()> {
    for (domain, kind) in [
        (libc::AF_INET, libc::SOCK_STREAM),
        (libc::AF_INET, libc::SOCK_DGRAM),
        (libc::AF_INET6, libc::SOCK_STREAM),
        (libc::AF_INET6, libc::SOCK_DGRAM),
    ] {
        let socket = match new_socket(domain, kind) {
            Ok(socket) => socket,
            Err(error)
                if domain == libc::AF_INET6 && error.raw_os_error() == Some(libc::EAFNOSUPPORT) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        confine_to_loopback(socket.as_raw_fd())
            .map_err(|error| probe_error("install loopback binding", &error))?;
        probe_binding_is_immutable(socket.as_raw_fd())?;
    }
    probe_accept_inherits_binding()
}

fn probe_binding_is_immutable(fd: RawFd) -> io::Result<()> {
    let empty = [0_u8; 1];
    // SAFETY: `empty` is a live one-byte buffer; an empty name requests unbind.
    let clear = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            empty.as_ptr().cast(),
            socklen(empty.len())?,
        )
    };
    if clear == 0 {
        return Err(io::Error::other(
            "sandbox credentials can clear a socket device binding",
        ));
    }
    if set_int_option(fd, libc::SOL_SOCKET, libc::SO_BINDTOIFINDEX, 0).is_ok() {
        return Err(io::Error::other(
            "sandbox credentials can clear a socket interface-index binding",
        ));
    }
    if bound_device(fd)?.as_deref() != Some(LOOPBACK_DEVICE.to_bytes()) {
        return Err(io::Error::other("socket device binding changed"));
    }
    Ok(())
}

fn probe_accept_inherits_binding() -> io::Result<()> {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    confine_to_loopback(listener.as_raw_fd())
        .map_err(|error| probe_error("confine probe listener", &error))?;
    let client = std::net::TcpStream::connect(listener.local_addr()?)?;
    let (accepted, peer) = listener.accept()?;
    if peer != client.local_addr()? {
        return Err(io::Error::other("accepted probe peer mismatch"));
    }
    if bound_device(accepted.as_raw_fd())?.as_deref() != Some(LOOPBACK_DEVICE.to_bytes()) {
        return Err(io::Error::other(
            "accepted socket did not inherit the loopback binding",
        ));
    }
    Ok(())
}

fn probe_error(context: &str, error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{context}: {error}"))
}

fn new_socket(domain: i32, kind: i32) -> io::Result<OwnedFd> {
    // SAFETY: scalar socket arguments; success returns one owned descriptor.
    let fd = unsafe { libc::socket(domain, kind | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful socket returned one newly owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn set_int_option(fd: RawFd, level: i32, option: i32, value: i32) -> io::Result<()> {
    // SAFETY: `value` is a live int for the duration of the call.
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            (&raw const value).cast(),
            socklen(size_of::<i32>())?,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn socklen(length: usize) -> io::Result<libc::socklen_t> {
    libc::socklen_t::try_from(length).map_err(io::Error::other)
}

const fn filter_stmt(code: u32, k: u32) -> libc::sock_filter {
    filter_jump(code, k, 0, 0)
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "classic BPF opcodes are 16-bit by definition"
)]
const fn filter_jump(code: u32, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::time::Duration;

    #[test]
    fn active_probe_passes_without_capabilities() {
        probe_loopback_confinement().expect("loopback confinement probe");
    }

    #[test]
    fn unbound_socket_reports_no_device() {
        let socket = new_socket(libc::AF_INET, libc::SOCK_STREAM).unwrap();
        assert_eq!(bound_device(socket.as_raw_fd()).unwrap(), None);
    }

    #[test]
    fn confined_socket_cannot_be_rebound() {
        let socket = new_socket(libc::AF_INET, libc::SOCK_DGRAM).unwrap();
        confine_to_loopback(socket.as_raw_fd()).unwrap();
        assert!(confine_to_loopback(socket.as_raw_fd()).is_err());
        assert_eq!(
            bound_device(socket.as_raw_fd()).unwrap().as_deref(),
            Some(&b"lo"[..])
        );
    }

    fn connect_with_timeout(address: SocketAddr) -> io::Result<TcpStream> {
        TcpStream::connect_timeout(&address, Duration::from_millis(300))
    }

    #[test]
    fn loopback_ingress_filter_rejects_loopback_connections() {
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        reject_loopback_ingress(listener.as_raw_fd()).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        // Dropped SYNs never complete the handshake.
        assert!(connect_with_timeout(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).is_err());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn ingress_filter_admits_other_interfaces() {
        // Positive control: the same program keyed to an absent interface
        // index must leave loopback traffic untouched.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        reject_ingress_interface(listener.as_raw_fd(), u32::MAX).unwrap();
        let mut client = connect_with_timeout(listener.local_addr().unwrap()).unwrap();
        let (mut accepted, _) = listener.accept().unwrap();
        client.write_all(b"ping").unwrap();
        let mut buffer = [0_u8; 4];
        accepted.read_exact(&mut buffer).unwrap();
        assert_eq!(&buffer, b"ping");
    }

    #[test]
    fn ingress_filter_is_locked() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        reject_loopback_ingress(listener.as_raw_fd()).unwrap();
        // SAFETY: SO_DETACH_FILTER ignores its value argument.
        let detach = unsafe {
            let value = 0_i32;
            libc::setsockopt(
                listener.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_DETACH_FILTER,
                (&raw const value).cast(),
                socklen(size_of::<i32>()).unwrap(),
            )
        };
        assert!(detach < 0);
    }

    /// Opt-in checks against a real non-loopback topology.
    ///
    /// A trusted harness creates a network namespace whose non-loopback
    /// device routes to a peer namespace, enables forwarding and the other
    /// permissive routing sysctls, and runs these tests unprivileged inside
    /// it. The harness, not the workload, holds any privileges. Each check
    /// carries an unconfined positive control so a broken observer cannot
    /// pass vacuously. For egress, the harness captures UDP/TCP port 9 on
    /// the peer side: exactly one datagram, the unconfined control payload,
    /// must arrive.
    mod topology {
        use super::*;
        use std::net::{IpAddr, UdpSocket};
        use std::time::Instant;

        fn env(name: &str) -> String {
            std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
        }

        fn tx_packets(device: &str) -> u64 {
            let table = std::fs::read_to_string("/proc/net/dev").unwrap();
            let line = table
                .lines()
                .find(|line| line.trim_start().starts_with(&format!("{device}:")))
                .unwrap_or_else(|| panic!("{device} is not in this network namespace"));
            // Receive has eight columns; transmit packets is the tenth field.
            line.split(':')
                .nth(1)
                .unwrap()
                .split_whitespace()
                .nth(9)
                .unwrap()
                .parse()
                .unwrap()
        }

        fn quiet_counter(device: &str) -> u64 {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let before = tx_packets(device);
                std::thread::sleep(Duration::from_millis(300));
                let after = tx_packets(device);
                if before == after {
                    return after;
                }
                assert!(Instant::now() < deadline, "{device} never became quiet");
            }
        }

        fn confined(domain: i32, kind: i32) -> OwnedFd {
            let socket = new_socket(domain, kind | libc::SOCK_NONBLOCK).unwrap();
            confine_to_loopback(socket.as_raw_fd()).unwrap();
            socket
        }

        fn attempt_egress(fd: RawFd, kind: i32, destination: SocketAddr) -> Option<i32> {
            let native = socket2::SockAddr::from(destination);
            // SAFETY: payload and the native address are live for each call.
            let result = unsafe {
                match kind {
                    libc::SOCK_DGRAM => libc::sendto(
                        fd,
                        b"probe".as_ptr().cast(),
                        5,
                        0,
                        native.as_ptr().cast(),
                        native.len(),
                    ),
                    _ => libc::sendto(
                        fd,
                        b"probe".as_ptr().cast(),
                        5,
                        libc::MSG_FASTOPEN,
                        native.as_ptr().cast(),
                        native.len(),
                    ),
                }
            };
            (result < 0).then(|| io::Error::last_os_error().raw_os_error().unwrap_or(0))
        }

        #[test]
        #[ignore = "requires the privileged topology harness"]
        fn topology_confined_sockets_emit_nothing_on_routed_devices() {
            let device = env("OPENSHELL_TOPOLOGY_DEVICE");
            let destinations: Vec<SocketAddr> = env("OPENSHELL_TOPOLOGY_DESTINATIONS")
                .split(',')
                .map(|value| value.parse().unwrap())
                .collect();

            // Positive control: an unconfined datagram to the first
            // destination is observed on the routed device.
            let baseline = quiet_counter(&device);
            let unconfined = UdpSocket::bind(match destinations[0].ip() {
                IpAddr::V4(_) => "0.0.0.0:0",
                IpAddr::V6(_) => "[::]:0",
            })
            .unwrap();
            unconfined.send_to(b"control", destinations[0]).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            while tx_packets(&device) == baseline {
                assert!(
                    Instant::now() < deadline,
                    "observer missed the unconfined control"
                );
                std::thread::sleep(Duration::from_millis(20));
            }

            let baseline = quiet_counter(&device);
            let mut outcomes = Vec::new();
            for destination in &destinations {
                let domain = match destination {
                    SocketAddr::V4(_) => libc::AF_INET,
                    SocketAddr::V6(_) => libc::AF_INET6,
                };
                for kind in [libc::SOCK_DGRAM, libc::SOCK_STREAM] {
                    let socket = confined(domain, kind);
                    outcomes.push((
                        destination,
                        kind,
                        "send",
                        attempt_egress(socket.as_raw_fd(), kind, *destination),
                    ));
                    if kind == libc::SOCK_STREAM {
                        let socket = confined(domain, kind);
                        let native = socket2::SockAddr::from(*destination);
                        // SAFETY: native address is live for the call.
                        let result = unsafe {
                            libc::connect(socket.as_raw_fd(), native.as_ptr().cast(), native.len())
                        };
                        let errno = (result < 0)
                            .then(|| io::Error::last_os_error().raw_os_error().unwrap_or(0));
                        outcomes.push((destination, kind, "connect", errno));
                        std::thread::sleep(Duration::from_millis(200));
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(500));
            let after = tx_packets(&device);
            for outcome in &outcomes {
                eprintln!("confined attempt {outcome:?}");
            }
            // Link-level chatter (MLD, neighbor discovery) also moves this
            // counter, so it cannot prove a negative on its own. The harness
            // captures the probe port on the peer side as the authoritative
            // observer; report the delta for correlation.
            eprintln!("confined phase {device} tx delta {}", after - baseline);
        }

        #[test]
        #[ignore = "requires the privileged topology harness"]
        fn topology_confined_listeners_reject_routed_ingress() {
            let confined_port: u16 = env("OPENSHELL_TOPOLOGY_CONFINED_PORT").parse().unwrap();
            let control_port: u16 = env("OPENSHELL_TOPOLOGY_CONTROL_PORT").parse().unwrap();
            let wait = Duration::from_secs(env("OPENSHELL_TOPOLOGY_WAIT_SECS").parse().unwrap());
            let listen = |port: u16, confine: bool| {
                let socket =
                    socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None)
                        .unwrap();
                // Dual-stack wildcard covers IPv4 and IPv4-mapped peers too.
                socket.set_only_v6(false).unwrap();
                if confine {
                    confine_to_loopback(socket.as_raw_fd()).unwrap();
                }
                socket
                    .bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)).into())
                    .unwrap();
                socket.listen(16).unwrap();
                socket.set_nonblocking(true).unwrap();
                TcpListener::from(socket)
            };
            let confined_listener = listen(confined_port, true);
            let control_listener = listen(control_port, false);
            let deadline = Instant::now() + wait;
            let (mut confined_peers, mut control_peers) = (Vec::new(), Vec::new());
            while Instant::now() < deadline {
                while let Ok((_, peer)) = confined_listener.accept() {
                    confined_peers.push(peer);
                }
                while let Ok((_, peer)) = control_listener.accept() {
                    control_peers.push(peer);
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            eprintln!("control accepted {control_peers:?}; confined accepted {confined_peers:?}");
            assert!(
                control_peers.iter().any(|peer| !peer.ip().is_loopback()
                    && peer.ip() != IpAddr::from(std::net::Ipv6Addr::LOCALHOST)),
                "positive control saw no routed client"
            );
            assert!(
                confined_peers.iter().all(|peer| match peer.ip() {
                    IpAddr::V4(ip) => ip.is_loopback(),
                    IpAddr::V6(ip) =>
                        ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback()),
                }),
                "confined listener accepted a routed client"
            );
        }
    }
}
