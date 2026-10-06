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

/// Bind `fd` to the loopback device.
///
/// # Errors
///
/// Returns the kernel error, including `EPERM` when the socket is already
/// bound to a device.
pub fn confine_to_loopback(fd: impl AsFd) -> io::Result<()> {
    SockRef::from(&fd).bind_device(Some(LOOPBACK_DEVICE))
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
/// only when the kernel or namespace does not provide it.
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
        let _client = std::net::TcpStream::connect(listener.local_addr()?)?;
        let (accepted, _) = listener.accept()?;
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
        // Root holds CAP_NET_RAW, which may change a device binding.
        if rustix::process::geteuid().is_root() {
            return;
        }
        probe_loopback_confinement().expect("loopback confinement probe");
    }

    #[test]
    fn unbound_socket_reports_no_device() {
        let socket = new_socket(Domain::IPV4, Type::STREAM);
        assert_eq!(bound_device(&socket).unwrap(), None);
    }

    #[test]
    fn confined_socket_cannot_be_rebound() {
        if rustix::process::geteuid().is_root() {
            return;
        }
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
        // Only a same-namespace client can reach a loopback-bound listener;
        // connecting to the host's own address is refused.
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
}
