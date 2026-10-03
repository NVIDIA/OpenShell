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

use std::io;
use std::os::fd::AsFd;

use socket2::{Domain, SockFilter, SockRef, Socket, Type};

const LOOPBACK_DEVICE: &[u8] = b"lo";

/// Bind `fd` to the loopback device and verify the kernel recorded it.
///
/// # Errors
///
/// Returns the kernel error when the binding cannot be installed, or `EPERM`
/// when the socket is already bound to another device.
pub fn confine_to_loopback(fd: impl AsFd) -> io::Result<()> {
    let socket = SockRef::from(&fd);
    socket.bind_device(Some(LOOPBACK_DEVICE))?;
    if socket.device()?.as_deref() == Some(LOOPBACK_DEVICE) {
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
pub fn bound_device(fd: impl AsFd) -> io::Result<Option<Vec<u8>>> {
    SockRef::from(&fd).device()
}

/// Drop TCP/UDP ingress that arrives on the loopback interface.
///
/// Attach this to a trusted listener whose legitimate clients are never in the
/// same network namespace. Matching the ingress interface rather than the
/// source address also rejects connections to the host's own non-loopback
/// address, which the kernel delivers through loopback. The filter is not
/// locked: the listener descriptor never leaves the trusted sandbox process,
/// which marks every descriptor above stdio close-on-exec before running
/// workload code.
///
/// # Errors
///
/// Returns the kernel error when the interface index cannot be resolved or
/// the filter cannot be attached.
pub fn reject_loopback_ingress(fd: impl AsFd) -> io::Result<()> {
    let index = rustix::net::netdevice::name_to_index(&fd, "lo")?;
    reject_ingress_interface(fd, index)
}

fn reject_ingress_interface(fd: impl AsFd, index: u32) -> io::Result<()> {
    // Ancillary loads use the documented negative offset encoding.
    let ifindex_offset = (libc::SKF_AD_OFF + libc::SKF_AD_IFINDEX).cast_unsigned();
    let program = [
        filter(
            libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
            0,
            0,
            ifindex_offset,
        ),
        filter(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 0, 1, index),
        filter(libc::BPF_RET | libc::BPF_K, 0, 0, 0),
        filter(libc::BPF_RET | libc::BPF_K, 0, 0, u32::MAX),
    ];
    SockRef::from(&fd).attach_filter(&program)
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "classic BPF opcodes are 16-bit by definition"
)]
const fn filter(code: u32, jt: u8, jf: u8, k: u32) -> SockFilter {
    SockFilter::new(code as u16, jt, jf, k)
}

/// Actively prove loopback confinement under the current runtime profile.
///
/// For each supported workload socket type this installs the binding and
/// proves that the sandbox credentials cannot clear or replace it. For IPv4
/// and IPv6 it proves that a stream accepted from a confined listener inherits
/// the binding and keeps it after an `AF_UNSPEC` disconnect. IPv6 is skipped
/// only when the kernel or namespace does not provide it. Routed ingress and
/// egress cannot be exercised without a non-loopback route, so those
/// guarantees rest on the kernel behavior verified per target kernel.
///
/// # Errors
///
/// Returns an error describing the first failed property.
pub fn probe_loopback_confinement() -> io::Result<()> {
    for (domain, kind) in [
        (Domain::IPV4, Type::STREAM),
        (Domain::IPV4, Type::DGRAM),
        (Domain::IPV6, Type::STREAM),
        (Domain::IPV6, Type::DGRAM),
    ] {
        let socket = match Socket::new(domain, kind, None) {
            Ok(socket) => socket,
            Err(error)
                if domain == Domain::IPV6 && error.raw_os_error() == Some(libc::EAFNOSUPPORT) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        confine_to_loopback(&socket)
            .map_err(|error| probe_error("install loopback binding", &error))?;
        probe_binding_is_immutable(&socket)?;
    }
    probe_accept_inherits_binding()
}

fn probe_binding_is_immutable(socket: &Socket) -> io::Result<()> {
    // `None` requests an unbind; replacing the device takes the same path.
    if socket.bind_device(None).is_ok() {
        return Err(io::Error::other(
            "sandbox credentials can clear a socket device binding",
        ));
    }
    if socket.device()?.as_deref() != Some(LOOPBACK_DEVICE) {
        return Err(io::Error::other("socket device binding changed"));
    }
    Ok(())
}

fn probe_accept_inherits_binding() -> io::Result<()> {
    for loopback in [
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
    ] {
        let listener = match std::net::TcpListener::bind((loopback, 0)) {
            Ok(listener) => listener,
            // Kernels or namespaces without IPv6 have no ::1 to bind.
            Err(error)
                if loopback.is_ipv6()
                    && matches!(
                        error.raw_os_error(),
                        Some(libc::EAFNOSUPPORT | libc::EADDRNOTAVAIL)
                    ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        confine_to_loopback(&listener)
            .map_err(|error| probe_error("confine probe listener", &error))?;
        let client = std::net::TcpStream::connect(listener.local_addr()?)?;
        let (accepted, peer) = listener.accept()?;
        if peer != client.local_addr()? {
            return Err(io::Error::other("accepted probe peer mismatch"));
        }
        if bound_device(&accepted)?.as_deref() != Some(LOOPBACK_DEVICE) {
            return Err(io::Error::other(
                "accepted socket did not inherit the loopback binding",
            ));
        }
        // Natively accepted sockets are not tracked by the broker, so a
        // workload can disconnect and reconnect them. The binding must
        // survive that transition.
        rustix::net::connect_unspec(&accepted)
            .map_err(|error| probe_error("disconnect accepted probe socket", &error.into()))?;
        if bound_device(&accepted)?.as_deref() != Some(LOOPBACK_DEVICE) {
            return Err(io::Error::other(
                "accepted socket lost the loopback binding after disconnect",
            ));
        }
    }
    Ok(())
}

fn probe_error(context: &str, error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::time::Duration;

    fn new_socket(domain: Domain, kind: Type) -> Socket {
        Socket::new(domain, kind, None).unwrap()
    }

    #[test]
    fn active_probe_passes_without_capabilities() {
        probe_loopback_confinement().expect("loopback confinement probe");
    }

    #[test]
    fn unbound_socket_reports_no_device() {
        let socket = new_socket(Domain::IPV4, Type::STREAM);
        assert_eq!(bound_device(&socket).unwrap(), None);
    }

    #[test]
    fn confined_socket_cannot_be_rebound() {
        let socket = new_socket(Domain::IPV4, Type::DGRAM);
        confine_to_loopback(&socket).unwrap();
        assert!(confine_to_loopback(&socket).is_err());
        assert_eq!(bound_device(&socket).unwrap().as_deref(), Some(&b"lo"[..]));
    }

    fn connect_with_timeout(address: SocketAddr) -> io::Result<TcpStream> {
        TcpStream::connect_timeout(&address, Duration::from_millis(300))
    }

    #[test]
    fn loopback_ingress_filter_rejects_loopback_connections() {
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        reject_loopback_ingress(&listener).unwrap();
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
        reject_ingress_interface(&listener, u32::MAX).unwrap();
        let mut client = connect_with_timeout(listener.local_addr().unwrap()).unwrap();
        let (mut accepted, _) = listener.accept().unwrap();
        client.write_all(b"ping").unwrap();
        let mut buffer = [0_u8; 4];
        accepted.read_exact(&mut buffer).unwrap();
        assert_eq!(&buffer, b"ping");
    }

    /// Return a local non-loopback address, if this namespace has one.
    fn local_non_loopback_address() -> Option<Ipv4Addr> {
        let probe = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
        probe.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
        match probe.local_addr().ok()?.ip() {
            std::net::IpAddr::V4(address) if !address.is_loopback() => Some(address),
            _ => None,
        }
    }

    #[test]
    fn confined_listener_peers_are_limited_to_this_network_namespace() {
        // Packets that arrive on another interface never match a listener
        // bound to loopback. The only non-loopback peer address it can see is
        // a client in the same namespace that binds its source to a local
        // non-loopback address and connects to loopback; that client could
        // equally connect from 127.0.0.1. Workload sockets cannot bind such a
        // source, because the broker only permits loopback or unspecified
        // binds.
        let Some(local) = local_non_loopback_address() else {
            eprintln!("skipping: no non-loopback IPv4 address in this namespace");
            return;
        };
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        confine_to_loopback(&listener).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();

        let connect_from = |source: Ipv4Addr, destination: Ipv4Addr| {
            let client = new_socket(Domain::IPV4, Type::STREAM);
            client.bind(&SocketAddr::from((source, 0)).into()).unwrap();
            client
                .connect_timeout(
                    &SocketAddr::from((destination, port)).into(),
                    Duration::from_millis(300),
                )
                .map(|()| client)
        };

        // The host's own address is matched against its real interface.
        assert!(connect_from(local, local).is_err());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

        let client = connect_from(local, Ipv4Addr::LOCALHOST).expect("same-namespace client");
        let (_, peer) = listener.accept().unwrap();
        assert_eq!(peer, client.local_addr().unwrap().as_socket().unwrap());
        assert_eq!(peer.ip(), std::net::IpAddr::V4(local));
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

        fn confined(domain: Domain, kind: Type) -> Socket {
            let socket = new_socket(domain, kind.nonblocking());
            confine_to_loopback(&socket).unwrap();
            socket
        }

        fn errno(result: io::Result<impl Sized>) -> Option<i32> {
            result.err().map(|error| error.raw_os_error().unwrap_or(0))
        }

        fn attempt_egress(socket: &Socket, kind: Type, destination: SocketAddr) -> Option<i32> {
            // Streams use Fast Open so the send itself attempts a connect.
            let flags = if kind == Type::DGRAM {
                0
            } else {
                libc::MSG_FASTOPEN
            };
            errno(socket.send_to_with_flags(b"probe", &destination.into(), flags))
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
                let domain = Domain::for_address(*destination);
                for kind in [Type::DGRAM, Type::STREAM] {
                    let socket = confined(domain, kind);
                    outcomes.push((
                        destination,
                        kind,
                        "send",
                        attempt_egress(&socket, kind, *destination),
                    ));
                    if kind == Type::STREAM {
                        let socket = confined(domain, kind);
                        let result = socket.connect(&(*destination).into());
                        outcomes.push((destination, kind, "connect", errno(result)));
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
                let socket = new_socket(Domain::IPV6, Type::STREAM);
                // Dual-stack wildcard covers IPv4 and IPv4-mapped peers too.
                socket.set_only_v6(false).unwrap();
                if confine {
                    confine_to_loopback(&socket).unwrap();
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
