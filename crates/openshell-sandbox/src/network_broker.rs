// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Seccomp-notification broker owned by the in-workload sandbox.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openshell_binary_identity::ProcfsIdentityResolver;
use openshell_isolation_interface::contract::{
    BinaryIdentity, DnsTransport, NetworkOpenResult, NetworkSocketMetadata, ResolveError,
};
use openshell_isolation_interface::linux::seccomp_notify::{Notification, NotificationListener};
use openshell_isolation_interface::linux::socket_registry::{
    InetFamily, InetKind, SocketMetadata, SocketRegistry, SocketState,
};
use openshell_isolation_interface::linux::task_memory;
use tokio::sync::{mpsc, oneshot};

const SOCKET_CAPACITY: usize = 4_096;
const OPEN_QUEUE_CAPACITY: usize = 256;
const ACCEPT_WORKER_CAPACITY: usize = 64;
const DNS_QUEUE_CAPACITY: usize = 256;
const DNS_WORKER_CAPACITY: usize = 256;
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(250);
const DNS_RELAY_ADDRESS: SocketAddr = SocketAddr::V4(std::net::SocketAddrV4::new(
    Ipv4Addr::new(127, 0, 0, 53),
    53,
));
const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct PendingOpenSlot(Arc<AtomicUsize>);

impl Drop for PendingOpenSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug)]
struct PendingDnsSlot(Arc<AtomicUsize>);

impl Drop for PendingDnsSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn acquire_pending_dns_slot(active: &Arc<AtomicUsize>) -> io::Result<PendingDnsSlot> {
    active
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < DNS_WORKER_CAPACITY).then_some(current + 1)
        })
        .map(|_| PendingDnsSlot(Arc::clone(active)))
        .map_err(|_| io::Error::from_raw_os_error(libc::EAGAIN))
}

struct PendingAcceptSlot {
    active: Arc<AtomicUsize>,
}

impl Drop for PendingAcceptSlot {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

fn acquire_pending_accept_slot(active: &Arc<AtomicUsize>) -> io::Result<PendingAcceptSlot> {
    active
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < ACCEPT_WORKER_CAPACITY).then_some(current + 1)
        })
        .map_err(|_| io::Error::from_raw_os_error(libc::EAGAIN))?;
    Ok(PendingAcceptSlot {
        active: Arc::clone(active),
    })
}

fn acquire_pending_open_slot(active: &Arc<AtomicUsize>) -> io::Result<PendingOpenSlot> {
    active
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < OPEN_QUEUE_CAPACITY).then_some(current + 1)
        })
        .map(|_| PendingOpenSlot(Arc::clone(active)))
        .map_err(|_| io::Error::from_raw_os_error(libc::EAGAIN))
}

/// One external TCP open blocked in `connect(2)` until the supervisor decides.
pub struct PendingTcpOpen {
    pub(crate) destination: SocketAddr,
    pub(crate) identity: Result<BinaryIdentity, ResolveError>,
    pub(crate) socket: NetworkSocketMetadata,
    decision: std::sync::mpsc::SyncSender<NetworkOpenResult>,
    relay: oneshot::Receiver<io::Result<TcpStream>>,
    _slot: PendingOpenSlot,
}

impl PendingTcpOpen {
    pub(crate) async fn complete(
        self,
        decision: NetworkOpenResult,
    ) -> io::Result<Option<TcpStream>> {
        self.decision
            .send(decision)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "network broker stopped"))?;
        if matches!(decision, NetworkOpenResult::Denied { .. }) {
            return Ok(None);
        }
        self.relay
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "network relay setup was cancelled",
                )
            })?
            .map(Some)
    }
}

/// One DNS exchange received by the exact sandbox-local resolver endpoint.
pub struct PendingDnsQuery {
    pub(crate) request: Vec<u8>,
    pub(crate) transport: DnsTransport,
    pub(crate) identity: Result<BinaryIdentity, ResolveError>,
    response: std::sync::mpsc::SyncSender<io::Result<Vec<u8>>>,
}

impl PendingDnsQuery {
    pub(crate) fn complete(self, response: io::Result<Vec<u8>>) -> io::Result<()> {
        self.response
            .send(response)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "DNS relay stopped"))
    }
}

#[derive(Clone)]
struct DnsRelay {
    address: SocketAddr,
    udp_attribution: Arc<Mutex<HashMap<SocketAddr, Result<BinaryIdentity, ResolveError>>>>,
    tcp_attribution: Arc<Mutex<HashMap<SocketAddr, Result<BinaryIdentity, ResolveError>>>>,
}

#[derive(Clone)]
struct NotificationQueues {
    pending: mpsc::Sender<PendingTcpOpen>,
    dns_relay: DnsRelay,
    active_opens: Arc<AtomicUsize>,
    active_accepts: Arc<AtomicUsize>,
}

/// Live broker handle retained by the sandbox boundary.
#[derive(Clone)]
pub struct NetworkBroker {
    pending: Arc<tokio::sync::Mutex<mpsc::Receiver<PendingTcpOpen>>>,
    pending_dns: Arc<tokio::sync::Mutex<mpsc::Receiver<PendingDnsQuery>>>,
    dns_address: SocketAddr,
    healthy: Arc<AtomicBool>,
}

impl NetworkBroker {
    pub(crate) fn start(listener: NotificationListener) -> io::Result<Self> {
        Self::start_with_dns_address(listener, DNS_RELAY_ADDRESS)
    }

    #[cfg(test)]
    pub(crate) fn start_for_test(listener: NotificationListener) -> io::Result<Self> {
        Self::start_with_dns_address(
            listener,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
    }

    fn start_with_dns_address(
        listener: NotificationListener,
        dns_address: SocketAddr,
    ) -> io::Result<Self> {
        let listener = Arc::new(listener);
        let (pending_tx, pending_rx) = mpsc::channel(OPEN_QUEUE_CAPACITY);
        let (pending_dns_tx, pending_dns_rx) = mpsc::channel(DNS_QUEUE_CAPACITY);
        let registry = Arc::new(Mutex::new(SocketRegistry::new(1, SOCKET_CAPACITY)?));
        let active_opens = Arc::new(AtomicUsize::new(0));
        let active_accepts = Arc::new(AtomicUsize::new(0));
        let dns_relay = start_dns_relay(dns_address, pending_dns_tx)?;
        let dns_address = dns_relay.address;
        let queues = NotificationQueues {
            pending: pending_tx,
            dns_relay,
            active_opens,
            active_accepts,
        };
        let healthy = Arc::new(AtomicBool::new(true));
        let broker_healthy = healthy.clone();
        std::thread::Builder::new()
            .name("openshell-network-broker".to_string())
            .spawn(move || {
                while broker_healthy.load(Ordering::Acquire) {
                    let notification = match listener.receive() {
                        Ok(notification) => notification,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => {
                            tracing::error!(%error, "sandbox network broker listener failed");
                            broker_healthy.store(false, Ordering::Release);
                            break;
                        }
                    };
                    if let Err(error) = dispatch_notification(
                        Arc::clone(&registry),
                        Arc::clone(&listener),
                        notification,
                        queues.clone(),
                    ) {
                        tracing::warn!(
                            tid = notification.tid,
                            syscall = notification.syscall,
                            %error,
                            "sandbox network notification denied (tid={}, syscall={}): {error}",
                            notification.tid,
                            notification.syscall
                        );
                        let _ = listener.respond_errno(notification.id, error_to_errno(&error));
                    }
                }
            })
            .map_err(|error| io::Error::other(format!("start network broker: {error}")))?;
        Ok(Self {
            pending: Arc::new(tokio::sync::Mutex::new(pending_rx)),
            pending_dns: Arc::new(tokio::sync::Mutex::new(pending_dns_rx)),
            dns_address,
            healthy,
        })
    }

    pub(crate) async fn accept(&self) -> io::Result<PendingTcpOpen> {
        self.pending
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "network broker queue closed"))
    }

    pub(crate) async fn accept_dns(&self) -> io::Result<PendingDnsQuery> {
        self.pending_dns
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "DNS broker queue closed"))
    }

    #[cfg(test)]
    fn dns_address(&self) -> SocketAddr {
        self.dns_address
    }

    pub(crate) fn confirm_healthy(&self) -> io::Result<()> {
        if self.healthy.load(Ordering::Acquire) && self.dns_address.port() != 0 {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "network broker is not running",
            ))
        }
    }
}

fn start_dns_relay(
    address: SocketAddr,
    pending: mpsc::Sender<PendingDnsQuery>,
) -> io::Result<DnsRelay> {
    let (udp, tcp, address) = bind_dns_relay_sockets(address)?;
    let udp_attribution = Arc::new(Mutex::new(HashMap::new()));
    let tcp_attribution = Arc::new(Mutex::new(HashMap::new()));
    let active_workers = Arc::new(AtomicUsize::new(0));
    let relay = DnsRelay {
        address,
        udp_attribution: Arc::clone(&udp_attribution),
        tcp_attribution: Arc::clone(&tcp_attribution),
    };

    let udp_active_workers = Arc::clone(&active_workers);
    let udp_pending = pending.clone();
    std::thread::Builder::new()
        .name("openshell-dns-udp".to_string())
        .spawn(move || {
            let mut request = vec![0_u8; u16::MAX as usize];
            while let Ok((length, peer)) = udp.recv_from(&mut request) {
                let Some(identity) = lock(&udp_attribution).get(&peer).cloned() else {
                    tracing::warn!(%peer, "dropping DNS datagram from unattributed socket");
                    continue;
                };
                let Ok(worker_slot) = acquire_pending_dns_slot(&udp_active_workers) else {
                    tracing::warn!(%peer, "dropping DNS datagram because the worker quota is full");
                    continue;
                };
                let (response_tx, response_rx) = std::sync::mpsc::sync_channel(1);
                let query = PendingDnsQuery {
                    request: request[..length].to_vec(),
                    transport: DnsTransport::Udp,
                    identity,
                    response: response_tx,
                };
                if pending_try_send(&udp_pending, query).is_err() {
                    continue;
                }
                let Ok(udp_response) = udp.try_clone() else {
                    continue;
                };
                let _ = std::thread::Builder::new()
                    .name("openshell-dns-udp-query".to_string())
                    .spawn(move || {
                        let _worker_slot = worker_slot;
                        if let Ok(Ok(response)) = response_rx.recv_timeout(DNS_QUERY_TIMEOUT) {
                            let _ = udp_response.send_to(&response, peer);
                        }
                    });
            }
        })
        .map_err(|error| io::Error::other(format!("start UDP DNS relay: {error}")))?;

    let tcp_active_workers = active_workers;
    std::thread::Builder::new()
        .name("openshell-dns-tcp".to_string())
        .spawn(move || {
            for accepted in tcp.incoming() {
                let Ok((stream, peer)) = accepted.and_then(|stream| {
                    let peer = stream.peer_addr()?;
                    Ok((stream, peer))
                }) else {
                    break;
                };
                let identity = lock(&tcp_attribution).get(&peer).cloned();
                let Some(identity) = identity else {
                    tracing::warn!(%peer, "dropping DNS stream from unattributed socket");
                    continue;
                };
                let Ok(worker_slot) = acquire_pending_dns_slot(&tcp_active_workers) else {
                    tracing::warn!(%peer, "dropping DNS stream because the worker quota is full");
                    continue;
                };
                let tcp_pending = pending.clone();
                let _ = std::thread::Builder::new()
                    .name("openshell-dns-tcp-query".to_string())
                    .spawn(move || {
                        let _worker_slot = worker_slot;
                        serve_dns_tcp(stream, identity, tcp_pending);
                    });
            }
        })
        .map_err(|error| io::Error::other(format!("start TCP DNS relay: {error}")))?;
    Ok(relay)
}

fn bind_dns_relay_sockets(address: SocketAddr) -> io::Result<(UdpSocket, TcpListener, SocketAddr)> {
    const EPHEMERAL_BIND_ATTEMPTS: usize = 32;

    if address.port() != 0 {
        let udp = UdpSocket::bind(address)?;
        let tcp = TcpListener::bind(address)?;
        return Ok((udp, tcp, address));
    }

    // TCP and UDP have independent ephemeral-port allocators. The port picked
    // by the first bind can therefore already be occupied by the other
    // protocol, especially while the test suite starts several brokers in
    // parallel. Retry the pair rather than treating that collision as an
    // unavailable network broker.
    for _ in 0..EPHEMERAL_BIND_ATTEMPTS {
        let udp = UdpSocket::bind(address)?;
        let selected = udp.local_addr()?;
        match TcpListener::bind(selected) {
            Ok(tcp) => return Ok((udp, tcp, selected)),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
            Err(error) => return Err(error),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "could not reserve a shared ephemeral TCP/UDP DNS relay port",
    ))
}

fn pending_try_send(
    pending: &mpsc::Sender<PendingDnsQuery>,
    query: PendingDnsQuery,
) -> Result<(), ()> {
    pending.try_send(query).map_err(|error| {
        tracing::warn!(%error, "dropping DNS query because mediation queue is unavailable");
    })
}

fn serve_dns_tcp(
    mut stream: TcpStream,
    identity: Result<BinaryIdentity, ResolveError>,
    pending: mpsc::Sender<PendingDnsQuery>,
) {
    use std::io::{Read as _, Write as _};

    let _ = stream.set_read_timeout(Some(DNS_QUERY_TIMEOUT));
    let _ = stream.set_write_timeout(Some(DNS_QUERY_TIMEOUT));
    loop {
        let mut length = [0_u8; 2];
        if stream.read_exact(&mut length).is_err() {
            return;
        }
        let message_length = usize::from(u16::from_be_bytes(length));
        let mut request = Vec::with_capacity(message_length + 2);
        request.extend_from_slice(&length);
        request.resize(message_length + 2, 0);
        if stream.read_exact(&mut request[2..]).is_err() {
            return;
        }
        let (response_tx, response_rx) = std::sync::mpsc::sync_channel(1);
        let query = PendingDnsQuery {
            request,
            transport: DnsTransport::Tcp,
            identity: identity.clone(),
            response: response_tx,
        };
        if pending_try_send(&pending, query).is_err() {
            return;
        }
        let Ok(Ok(response)) = response_rx.recv_timeout(DNS_QUERY_TIMEOUT) else {
            return;
        };
        if stream.write_all(&response).is_err() {
            return;
        }
    }
}

fn dispatch_notification(
    registry: Arc<Mutex<SocketRegistry>>,
    listener: Arc<NotificationListener>,
    notification: Notification,
    queues: NotificationQueues,
) -> io::Result<()> {
    let syscall = i64::from(notification.syscall);
    if syscall == libc::SYS_socket {
        return create_socket(&registry, &listener, notification);
    }
    if syscall == libc::SYS_connect {
        return connect_socket(
            registry,
            listener,
            notification,
            queues.pending,
            &queues.dns_relay,
            queues.active_opens,
        );
    }
    if syscall == libc::SYS_bind {
        return bind_socket(&registry, &listener, notification);
    }
    if syscall == libc::SYS_listen {
        return listen_socket(&registry, &listener, notification);
    }
    if matches!(syscall, libc::SYS_accept | libc::SYS_accept4) {
        return accept_socket(registry, listener, notification, queues.active_accepts);
    }
    if matches!(
        syscall,
        libc::SYS_sendto | libc::SYS_sendmsg | libc::SYS_sendmmsg
    ) {
        return classify_send(&registry, &listener, notification, &queues.dns_relay);
    }
    if syscall == libc::SYS_getpeername {
        return get_peer_name(&registry, &listener, notification);
    }
    if syscall == libc::SYS_setsockopt {
        let level = i32::try_from(notification.args[1])
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        let option = i32::try_from(notification.args[2])
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        if (level == libc::IPPROTO_TCP && option == libc::TCP_FASTOPEN_CONNECT)
            || (level == libc::IPPROTO_IPV6 && option == libc::IPV6_ADDRFORM)
        {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        return listener.respond_continue(notification.id);
    }
    Err(io::Error::from_raw_os_error(libc::EPERM))
}

fn create_socket(
    registry: &Mutex<SocketRegistry>,
    listener: &NotificationListener,
    notification: Notification,
) -> io::Result<()> {
    let domain = i32::try_from(notification.args[0])
        .map_err(|_| io::Error::from_raw_os_error(libc::EAFNOSUPPORT))?;
    if !matches!(domain, libc::AF_INET | libc::AF_INET6) {
        return listener.respond_continue(notification.id);
    }
    let raw_kind = i32::try_from(notification.args[1])
        .map_err(|_| io::Error::from_raw_os_error(libc::EPROTONOSUPPORT))?;
    let protocol = i32::try_from(notification.args[2])
        .map_err(|_| io::Error::from_raw_os_error(libc::EPROTONOSUPPORT))?;
    let base_kind = raw_kind & !(libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK);
    let kind = match (base_kind, protocol) {
        (libc::SOCK_STREAM, 0 | libc::IPPROTO_TCP) => InetKind::Tcp,
        (libc::SOCK_DGRAM, 0 | libc::IPPROTO_UDP) => InetKind::DnsUdp,
        _ => return Err(io::Error::from_raw_os_error(libc::EPROTONOSUPPORT)),
    };
    let family = if domain == libc::AF_INET {
        InetFamily::V4
    } else {
        InetFamily::V6
    };
    // SAFETY: arguments were reduced to the supported native INET matrix. A
    // successful call returns one newly owned descriptor.
    let mut source = unsafe { libc::socket(domain, raw_kind, protocol) };
    if source < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EMFILE) {
        collect_closed_socket_entries(registry)?;
        // SAFETY: same validated native INET socket creation after reclaiming
        // broker-held descriptors for closed workload sockets.
        source = unsafe { libc::socket(domain, raw_kind, protocol) };
    }
    if source < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful socket returned one owned descriptor.
    let source = unsafe { OwnedFd::from_raw_fd(source) };
    let metadata = SocketMetadata {
        family,
        kind,
        close_on_exec: raw_kind & libc::SOCK_CLOEXEC != 0,
        nonblocking: raw_kind & libc::SOCK_NONBLOCK != 0,
        creator_generation: u64::from(notification.tid),
    };
    let mut registry = lock(registry);
    if registry.is_full() {
        collect_closed_socket_entries_locked(&mut registry)?;
    }
    let tentative = registry.stage(source, metadata)?;
    listener.add_fd_and_send(
        notification.id,
        tentative.source_fd(),
        metadata.close_on_exec,
    )?;
    registry.commit(tentative)?;
    Ok(())
}

fn connect_socket(
    registry: Arc<Mutex<SocketRegistry>>,
    listener: Arc<NotificationListener>,
    notification: Notification,
    pending: mpsc::Sender<PendingTcpOpen>,
    dns_relay: &DnsRelay,
    active_opens: Arc<AtomicUsize>,
) -> io::Result<()> {
    let fd = raw_fd(notification.args[0])?;
    if !socket_address_is_inet(notification.tid, notification.args[1], notification.args[2])? {
        if lock(&registry).resolve(notification.tid, fd).is_ok() {
            // Every registered descriptor is an injected INET socket. Never
            // CONTINUE based on a mutable workload sockaddr for such an FD.
            return Err(io::Error::from_raw_os_error(libc::EAFNOSUPPORT));
        }
        // Native non-INET descriptors remain kernel-driven.
        return listener.respond_continue(notification.id);
    }
    let destination =
        read_socket_addr(notification.tid, notification.args[1], notification.args[2])?;
    let (kind, socket_cookie, nonblocking) = {
        let registry = lock(&registry);
        let entry = registry.resolve(notification.tid, fd)?;
        (
            entry.metadata().kind,
            entry.identity().cookie,
            entry.metadata().nonblocking,
        )
    };
    if destination == dns_relay.address {
        let identity = ProcfsIdentityResolver::for_pid_namespace().resolve(notification.tid);
        let mut registry = lock(&registry);
        let entry = registry.resolve_mut(notification.tid, fd)?;
        if !matches!(
            entry.state(),
            SocketState::Created | SocketState::Bound { .. }
        ) {
            return Err(io::Error::from_raw_os_error(libc::EISCONN));
        }
        let source_fd = entry.retained_preconnect()?.as_raw_fd();
        let peer = ensure_dns_source_bound(source_fd, entry.metadata().family)?;
        let attribution = match kind {
            InetKind::Tcp => &dns_relay.tcp_attribution,
            InetKind::DnsUdp => &dns_relay.udp_attribution,
        };
        lock(attribution).insert(peer, identity);
        if let Err(error) = connect_exact(source_fd, destination) {
            lock(attribution).remove(&peer);
            return Err(error);
        }
        entry.set_state(match kind {
            InetKind::Tcp => SocketState::DnsTcp { relay: destination },
            InetKind::DnsUdp => SocketState::DnsUdp { relay: destination },
        });
        entry.release_preconnect();
        return listener.respond_value(notification.id, 0);
    }
    if destination.ip().is_loopback() {
        let mut registry = lock(&registry);
        let entry = registry.resolve_mut(notification.tid, fd)?;
        connect_exact(entry.retained_preconnect()?.as_raw_fd(), destination)?;
        entry.set_state(SocketState::Local { peer: destination });
        entry.release_preconnect();
        return listener.respond_value(notification.id, 0);
    }
    if kind != InetKind::Tcp {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }

    let identity = ProcfsIdentityResolver::for_pid_namespace().resolve(notification.tid);
    let (decision_tx, decision_rx) = std::sync::mpsc::sync_channel(1);
    let (relay_tx, relay_rx) = oneshot::channel();
    let slot = acquire_pending_open_slot(&active_opens)?;
    pending
        .try_send(PendingTcpOpen {
            destination,
            identity,
            socket: NetworkSocketMetadata {
                socket_cookie,
                nonblocking,
                process_generation: u64::from(notification.tid),
            },
            decision: decision_tx,
            relay: relay_rx,
            _slot: slot,
        })
        .map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => io::Error::from_raw_os_error(libc::EAGAIN),
            mpsc::error::TrySendError::Closed(_) => {
                io::Error::new(io::ErrorKind::BrokenPipe, "network-open queue closed")
            }
        })?;
    let worker_listener = Arc::clone(&listener);
    std::thread::Builder::new()
        .name("openshell-network-open".to_string())
        .spawn(move || {
            let result = decision_rx.recv().unwrap_or(NetworkOpenResult::Denied {
                errno: libc::ECANCELED,
            });
            match result {
                NetworkOpenResult::Denied { errno } => {
                    let _ = worker_listener.respond_errno(notification.id, errno);
                }
                NetworkOpenResult::RelayReady => {
                    match establish_relay(&registry, notification.tid, fd, destination) {
                        Ok(stream) => {
                            let result = worker_listener
                                .respond_value(notification.id, 0)
                                .map(|()| stream);
                            let _ = relay_tx.send(result);
                        }
                        Err(error) => {
                            let _ = worker_listener
                                .respond_errno(notification.id, error_to_errno(&error));
                            let _ = relay_tx.send(Err(error));
                        }
                    }
                }
            }
        })
        .map_err(|error| io::Error::other(format!("start network-open worker: {error}")))?;
    Ok(())
}

fn ensure_dns_source_bound(fd: RawFd, family: InetFamily) -> io::Result<SocketAddr> {
    let mut address = socket_local_addr(fd)?;
    let loopback = match family {
        InetFamily::V4 => IpAddr::V4(Ipv4Addr::LOCALHOST),
        InetFamily::V6 => IpAddr::V6(Ipv6Addr::LOCALHOST),
    };
    if address.port() == 0 {
        bind_exact(fd, SocketAddr::new(loopback, 0))?;
        address = socket_local_addr(fd)?;
    }
    // Async resolvers commonly bind an unspecified address before sendto(2).
    // A loopback destination makes the kernel select loopback as the actual
    // source, so key attribution by that effective peer rather than by the
    // wildcard returned before connect/send. Otherwise the relay observes
    // 127.0.0.1:<port> (or ::1:<port>) and drops a valid query registered as
    // 0.0.0.0:<port> (or [::]:<port>).
    if address.ip().is_unspecified() {
        address.set_ip(loopback);
    }
    Ok(address)
}

fn establish_relay(
    registry: &Mutex<SocketRegistry>,
    tid: u32,
    fd: RawFd,
    destination: SocketAddr,
) -> io::Result<TcpStream> {
    let relay = TcpListener::bind(match destination {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
    })?;
    relay.set_nonblocking(false)?;
    let relay_address = relay.local_addr()?;
    let expected_peer = {
        let mut registry = lock(registry);
        let entry = registry.resolve_mut(tid, fd)?;
        connect_exact(entry.retained_preconnect()?.as_raw_fd(), relay_address)?;
        let expected_peer = socket_local_addr(entry.retained_preconnect()?.as_raw_fd())?;
        entry.set_state(SocketState::Connected {
            original_peer: destination,
        });
        entry.release_preconnect();
        expected_peer
    };
    relay.set_nonblocking(true)?;
    let deadline = std::time::Instant::now() + RELAY_CONNECT_TIMEOUT;
    let stream = loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(io::Error::from_raw_os_error(libc::ETIMEDOUT));
        }
        let timeout = deadline.saturating_duration_since(now);
        let mut poll = libc::pollfd {
            fd: relay.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        // SAFETY: poll points to one live descriptor record.
        if unsafe { libc::poll(&raw mut poll, 1, timeout) } <= 0 {
            return Err(io::Error::from_raw_os_error(libc::ETIMEDOUT));
        }
        match relay.accept() {
            Ok((stream, peer)) if peer == expected_peer => break stream,
            Ok((_stream, peer)) => {
                tracing::warn!(%peer, %expected_peer, "rejected unexpected sandbox relay peer");
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    };
    stream.set_nodelay(true)?;
    Ok(stream)
}

fn bind_socket(
    registry: &Mutex<SocketRegistry>,
    listener: &NotificationListener,
    notification: Notification,
) -> io::Result<()> {
    let fd = raw_fd(notification.args[0])?;
    if !socket_address_is_inet(notification.tid, notification.args[1], notification.args[2])? {
        if lock(registry).resolve(notification.tid, fd).is_ok() {
            return Err(io::Error::from_raw_os_error(libc::EAFNOSUPPORT));
        }
        return listener.respond_continue(notification.id);
    }
    let local = read_socket_addr(notification.tid, notification.args[1], notification.args[2])?;
    if !local.ip().is_loopback() && !local.ip().is_unspecified() {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }
    let bind_result = {
        let mut registry = lock(registry);
        let entry = registry.resolve_mut(notification.tid, fd)?;
        bind_exact(entry.retained_preconnect()?.as_raw_fd(), local)
    };
    if bind_result
        .as_ref()
        .is_err_and(|error| error.raw_os_error() == Some(libc::EADDRINUSE))
    {
        collect_closed_socket_entries(registry)?;
        let mut registry = lock(registry);
        let entry = registry.resolve_mut(notification.tid, fd)?;
        bind_exact(entry.retained_preconnect()?.as_raw_fd(), local)?;
        entry.set_state(SocketState::Bound { local });
    } else {
        bind_result?;
        lock(registry)
            .resolve_mut(notification.tid, fd)?
            .set_state(SocketState::Bound { local });
    }
    listener.respond_value(notification.id, 0)
}

fn collect_closed_socket_entries(registry: &Mutex<SocketRegistry>) -> io::Result<()> {
    let mut registry = lock(registry);
    collect_closed_socket_entries_locked(&mut registry)
}

fn collect_closed_socket_entries_locked(registry: &mut SocketRegistry) -> io::Result<()> {
    let installed =
        openshell_isolation_interface::linux::proc_fd::installed_socket_inodes_excluding(
            std::process::id(),
        )?;
    registry.retain_installed(&installed);
    Ok(())
}

fn listen_socket(
    registry: &Mutex<SocketRegistry>,
    listener: &NotificationListener,
    notification: Notification,
) -> io::Result<()> {
    let fd = raw_fd(notification.args[0])?;
    let backlog = i32::try_from(notification.args[1]).unwrap_or(i32::MAX);
    let mut registry = lock(registry);
    let Ok(entry) = registry.resolve_mut(notification.tid, fd) else {
        return listener.respond_continue(notification.id);
    };
    // SAFETY: retained descriptor is the exact registered socket OFD.
    if unsafe { libc::listen(entry.retained_preconnect()?.as_raw_fd(), backlog) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let local = socket_local_addr(entry.retained_preconnect()?.as_raw_fd())?;
    entry.set_state(SocketState::Listening { local });
    listener.respond_value(notification.id, 0)
}

fn accept_socket(
    registry: Arc<Mutex<SocketRegistry>>,
    listener: Arc<NotificationListener>,
    notification: Notification,
    active_accepts: Arc<AtomicUsize>,
) -> io::Result<()> {
    let fd = raw_fd(notification.args[0])?;
    let flags = if i64::from(notification.syscall) == libc::SYS_accept4 {
        i32::try_from(notification.args[3])
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?
    } else {
        0
    };
    if flags & !(libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) != 0 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    if (notification.args[1] == 0) != (notification.args[2] == 0) {
        return Err(io::Error::from_raw_os_error(libc::EFAULT));
    }
    let (listener_inode, metadata, source) = {
        let registry = lock(&registry);
        let Ok(entry) = registry.resolve(notification.tid, fd) else {
            return listener.respond_continue(notification.id);
        };
        if !matches!(entry.state(), SocketState::Listening { .. })
            || entry.metadata().kind != InetKind::Tcp
        {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let source = duplicate_close_on_exec(entry.retained_preconnect()?.as_raw_fd())?;
        (entry.identity().inode, entry.metadata(), source)
    };
    let slot = acquire_pending_accept_slot(&active_accepts)?;
    let worker_listener = Arc::clone(&listener);
    std::thread::Builder::new()
        .name("openshell-local-accept".to_string())
        .spawn(move || {
            let _slot = slot;
            if let Err(error) = accept_and_inject(
                &registry,
                &worker_listener,
                notification,
                flags,
                listener_inode,
                metadata,
                source,
            ) {
                let _ = worker_listener.respond_errno(notification.id, error_to_errno(&error));
            }
        })
        .map_err(|error| io::Error::other(format!("start local-accept worker: {error}")))?;
    Ok(())
}

fn accept_and_inject(
    registry: &Mutex<SocketRegistry>,
    listener: &NotificationListener,
    notification: Notification,
    flags: i32,
    listener_inode: u64,
    metadata: SocketMetadata,
    source: OwnedFd,
) -> io::Result<()> {
    let mut poll = libc::pollfd {
        fd: source.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: F_GETFL reads the live listener OFD flags.
    let current_flags = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_GETFL) };
    if current_flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let nonblocking = current_flags & libc::O_NONBLOCK != 0;
    let timeout = if nonblocking {
        0
    } else {
        i32::try_from(ACCEPT_POLL_INTERVAL.as_millis()).expect("accept poll interval fits i32")
    };
    loop {
        listener.validate_id(notification.id)?;
        // SAFETY: poll references one live pollfd for this call.
        let ready = unsafe { libc::poll(&raw mut poll, 1, timeout) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if ready == 0 {
            if nonblocking {
                return Err(io::Error::from_raw_os_error(libc::EAGAIN));
            }
            continue;
        }
        break;
    }

    let mut storage = std::mem::MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut length = libc::socklen_t::try_from(size_of::<libc::sockaddr_storage>())
        .expect("sockaddr storage size fits");
    // Always keep the broker-side descriptor close-on-exec. ADDFD separately
    // applies the workload's requested descriptor flag.
    let accepted_flags = flags | libc::SOCK_CLOEXEC;
    // SAFETY: storage and length are live outputs and source is a listening
    // socket proven by the registry.
    let accepted = unsafe {
        libc::accept4(
            source.as_raw_fd(),
            storage.as_mut_ptr().cast(),
            &raw mut length,
            accepted_flags,
        )
    };
    if accepted < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful accept4 returned one newly owned descriptor.
    let accepted = unsafe { OwnedFd::from_raw_fd(accepted) };
    // SAFETY: accept4 initialized the reported prefix of storage.
    let peer = decode_sockaddr(
        unsafe { storage.assume_init() },
        usize::try_from(length).unwrap_or(0),
    )?;
    if !peer.ip().is_loopback() {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }
    if notification.args[1] != 0 {
        write_socket_addr(
            listener,
            notification.id,
            notification.tid,
            notification.args[1],
            notification.args[2],
            peer,
        )?;
    }

    let accepted_metadata = SocketMetadata {
        family: metadata.family,
        kind: InetKind::Tcp,
        close_on_exec: flags & libc::SOCK_CLOEXEC != 0,
        nonblocking: flags & libc::SOCK_NONBLOCK != 0,
        creator_generation: u64::from(notification.tid),
    };
    let mut registry = lock(registry);
    let notifying_fd = raw_fd(notification.args[0])?;
    if registry
        .resolve(notification.tid, notifying_fd)?
        .identity()
        .inode
        != listener_inode
    {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }
    if registry.is_full() {
        collect_closed_socket_entries_locked(&mut registry)?;
    }
    let tentative = registry.stage(accepted, accepted_metadata)?;
    listener.add_fd_and_send(
        notification.id,
        tentative.source_fd(),
        accepted_metadata.close_on_exec,
    )?;
    registry.commit_with_state(tentative, SocketState::AcceptedLocal { peer })?;
    Ok(())
}

fn duplicate_close_on_exec(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: F_DUPFD_CLOEXEC returns an independent owned descriptor for the
    // same open-file description.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fcntl returned one newly owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

fn classify_send(
    registry: &Mutex<SocketRegistry>,
    listener: &NotificationListener,
    notification: Notification,
    dns_relay: &DnsRelay,
) -> io::Result<()> {
    let fd = raw_fd(notification.args[0])?;
    let syscall = i64::from(notification.syscall);
    let (state, metadata) = {
        let registry = lock(registry);
        let Ok(entry) = registry.resolve(notification.tid, fd) else {
            // Non-INET sockets are never injected into the registry. Leave
            // their native sendmsg/control-message semantics to the kernel.
            return listener.respond_continue(notification.id);
        };
        (entry.state().clone(), entry.metadata())
    };
    if matches!(
        &state,
        SocketState::Connected { .. } | SocketState::AcceptedLocal { .. }
    ) || (metadata.kind == InetKind::Tcp && matches!(&state, SocketState::Local { .. }))
    {
        return listener.respond_continue(notification.id);
    }
    let messages = match syscall {
        libc::SYS_sendto => vec![read_sendto_message(notification)?],
        libc::SYS_sendmsg => vec![read_sendmsg_message(
            notification.tid,
            notification.args[1],
            i32::try_from(notification.args[2])
                .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?,
            None,
        )?],
        libc::SYS_sendmmsg => read_sendmmsg_messages(notification)?,
        _ => return Err(io::Error::from_raw_os_error(libc::ENOSYS)),
    };

    let mut registry = lock(registry);
    let resolution = registry.resolve(notification.tid, fd);
    match resolution {
        Ok(entry)
            if entry.metadata().kind == InetKind::DnsUdp
                && matches!(entry.state(), SocketState::Local { .. }) =>
        {
            if messages.iter().all(|message| message.destination.is_none()) {
                listener.respond_continue(notification.id)
            } else {
                Err(io::Error::from_raw_os_error(libc::EACCES))
            }
        }
        Ok(entry) if matches!(entry.state(), SocketState::DnsUdp { .. }) => {
            if messages.iter().all(|message| message.destination.is_none()) {
                listener.respond_continue(notification.id)
            } else {
                Err(io::Error::from_raw_os_error(libc::EACCES))
            }
        }
        Ok(entry)
            if entry.metadata().kind == InetKind::DnsUdp
                && matches!(
                    entry.state(),
                    SocketState::Created | SocketState::Bound { .. }
                )
                && messages.iter().all(|message| {
                    message
                        .destination
                        .is_some_and(|value| value == dns_relay.address)
                }) =>
        {
            let identity = ProcfsIdentityResolver::for_pid_namespace().resolve(notification.tid);
            let entry = registry.resolve_mut(notification.tid, fd)?;
            let source_fd = entry.retained_preconnect()?.as_raw_fd();
            let peer = ensure_dns_source_bound(source_fd, entry.metadata().family)?;
            lock(&dns_relay.udp_attribution).insert(peer, identity);
            if let Err(error) = connect_exact(source_fd, dns_relay.address) {
                lock(&dns_relay.udp_attribution).remove(&peer);
                return Err(error);
            }
            for message in &messages {
                send_dns_message(source_fd, message)?;
                if let Some(length_address) = message.result_length_address {
                    let length = u32::try_from(message.data.len())
                        .map_err(|_| io::Error::from_raw_os_error(libc::EMSGSIZE))?;
                    listener.validate_id(notification.id)?;
                    task_memory::write_exact(
                        notification.tid,
                        length_address,
                        &length.to_ne_bytes(),
                    )?;
                }
            }
            entry.set_state(SocketState::DnsUdp {
                relay: dns_relay.address,
            });
            entry.release_preconnect();
            let result = if syscall == libc::SYS_sendmmsg {
                i64::try_from(messages.len()).unwrap_or(i64::MAX)
            } else {
                i64::try_from(messages[0].data.len()).unwrap_or(i64::MAX)
            };
            listener.respond_value(notification.id, result)
        }
        Ok(_) => Err(io::Error::from_raw_os_error(libc::EDESTADDRREQ)),
        // Non-INET sockets and accepted local sockets were never registered.
        // The mandatory outer fence still prevents an external kernel route.
        Err(_) => listener.respond_continue(notification.id),
    }
}

struct SendMessage {
    data: Vec<u8>,
    destination: Option<SocketAddr>,
    flags: i32,
    result_length_address: Option<u64>,
}

fn read_sendto_message(notification: Notification) -> io::Result<SendMessage> {
    let length = usize::try_from(notification.args[2])
        .map_err(|_| io::Error::from_raw_os_error(libc::EMSGSIZE))?;
    if u16::try_from(length).is_err() {
        return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
    }
    let mut data = vec![0_u8; length];
    task_memory::read_exact(notification.tid, notification.args[1], &mut data)?;
    let destination = if notification.args[4] == 0 {
        None
    } else {
        Some(read_socket_addr(
            notification.tid,
            notification.args[4],
            notification.args[5],
        )?)
    };
    Ok(SendMessage {
        data,
        destination,
        flags: i32::try_from(notification.args[3])
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?,
        result_length_address: None,
    })
}

fn read_sendmsg_message(
    tid: u32,
    address: u64,
    flags: i32,
    result_length_address: Option<u64>,
) -> io::Result<SendMessage> {
    let header = read_task_value::<libc::msghdr>(tid, address)?;
    if header.msg_controllen != 0 {
        return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
    }
    let destination = if header.msg_name.is_null() {
        None
    } else {
        Some(read_socket_addr(
            tid,
            header.msg_name as u64,
            u64::from(header.msg_namelen),
        )?)
    };
    #[cfg(target_env = "musl")]
    let iov_count = usize::try_from(header.msg_iovlen)
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    #[cfg(not(target_env = "musl"))]
    let iov_count = header.msg_iovlen;
    if iov_count > 32 {
        return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
    }
    let mut data = Vec::new();
    for index in 0..iov_count {
        let offset = index
            .checked_mul(size_of::<libc::iovec>())
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        let iov = read_task_value::<libc::iovec>(
            tid,
            (header.msg_iov as u64)
                .checked_add(u64::try_from(offset).unwrap_or(u64::MAX))
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?,
        )?;
        let start = data.len();
        let end = start
            .checked_add(iov.iov_len)
            .filter(|length| u16::try_from(*length).is_ok())
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EMSGSIZE))?;
        data.resize(end, 0);
        task_memory::read_exact(tid, iov.iov_base as u64, &mut data[start..end])?;
    }
    Ok(SendMessage {
        data,
        destination,
        flags,
        result_length_address,
    })
}

fn read_sendmmsg_messages(notification: Notification) -> io::Result<Vec<SendMessage>> {
    let count = usize::try_from(notification.args[2])
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    if count == 0 || count > 32 {
        return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
    }
    let flags = i32::try_from(notification.args[3])
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    (0..count)
        .map(|index| {
            let offset = index
                .checked_mul(size_of::<libc::mmsghdr>())
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
            let base = notification.args[1]
                .checked_add(u64::try_from(offset).unwrap_or(u64::MAX))
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
            read_sendmsg_message(
                notification.tid,
                base,
                flags,
                Some(
                    base.checked_add(
                        u64::try_from(std::mem::offset_of!(libc::mmsghdr, msg_len))
                            .unwrap_or(u64::MAX),
                    )
                    .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?,
                ),
            )
        })
        .collect()
}

fn read_task_value<T: Copy>(tid: u32, address: u64) -> io::Result<T> {
    let mut bytes = vec![0_u8; size_of::<T>()];
    task_memory::read_exact(tid, address, &mut bytes)?;
    // SAFETY: `bytes` contains exactly one copied native value; unaligned read
    // avoids imposing alignment on the task-memory scratch allocation.
    Ok(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) })
}

fn send_dns_message(fd: RawFd, message: &SendMessage) -> io::Result<()> {
    // SAFETY: `fd` is the retained exact UDP socket and the buffer remains
    // valid for the duration of the syscall.
    let sent = unsafe {
        libc::send(
            fd,
            message.data.as_ptr().cast(),
            message.data.len(),
            message.flags,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(sent).ok() == Some(message.data.len()) {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(libc::EIO))
    }
}

fn get_peer_name(
    registry: &Mutex<SocketRegistry>,
    listener: &NotificationListener,
    notification: Notification,
) -> io::Result<()> {
    let fd = raw_fd(notification.args[0])?;
    let registry = lock(registry);
    let Ok(entry) = registry.resolve(notification.tid, fd) else {
        return listener.respond_continue(notification.id);
    };
    let peer = match entry.state() {
        SocketState::Connected { original_peer } => *original_peer,
        SocketState::Local { peer } | SocketState::AcceptedLocal { peer } => *peer,
        _ => return Err(io::Error::from_raw_os_error(libc::ENOTCONN)),
    };
    write_socket_addr(
        listener,
        notification.id,
        notification.tid,
        notification.args[1],
        notification.args[2],
        peer,
    )?;
    listener.respond_value(notification.id, 0)
}

fn connect_exact(fd: RawFd, address: SocketAddr) -> io::Result<()> {
    // Never let a blocking connect pin the single notification dispatcher.
    // O_NONBLOCK is an OFD flag, so restore the workload's original setting
    // after the bounded connect attempt completes.
    // SAFETY: F_GETFL/F_SETFL operate on the live retained socket descriptor.
    let original_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if original_flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let changed_flags = original_flags & libc::O_NONBLOCK == 0;
    if changed_flags
        && unsafe { libc::fcntl(fd, libc::F_SETFL, original_flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let result = with_sockaddr(address, |pointer, length| {
        // SAFETY: pointer/length describe a live native sockaddr and `fd` is
        // the retained exact socket OFD.
        let result = unsafe { libc::connect(fd, pointer, length) };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error);
        }
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: poll points to one live pollfd.
        let timeout = i32::try_from(RELAY_CONNECT_TIMEOUT.as_millis())
            .expect("relay timeout fits poll milliseconds");
        if unsafe { libc::poll(&raw mut poll, 1, timeout) } <= 0 {
            return Err(io::Error::from_raw_os_error(libc::ETIMEDOUT));
        }
        let mut socket_error = 0_i32;
        let mut size = libc::socklen_t::try_from(size_of::<i32>()).expect("SO_ERROR size fits");
        // SAFETY: getsockopt writes one i32 into live storage.
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&raw mut socket_error).cast(),
                &raw mut size,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        if socket_error == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(socket_error))
        }
    });
    let restore = if changed_flags && unsafe { libc::fcntl(fd, libc::F_SETFL, original_flags) } < 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    };
    result.and(restore)
}

fn bind_exact(fd: RawFd, address: SocketAddr) -> io::Result<()> {
    with_sockaddr(address, |pointer, length| {
        // SAFETY: pointer/length describe a live native sockaddr.
        if unsafe { libc::bind(fd, pointer, length) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    })
}

fn socket_local_addr(fd: RawFd) -> io::Result<SocketAddr> {
    let mut storage = std::mem::MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut length = libc::socklen_t::try_from(size_of::<libc::sockaddr_storage>())
        .expect("sockaddr storage size fits");
    // SAFETY: storage and length are live output buffers.
    if unsafe { libc::getsockname(fd, storage.as_mut_ptr().cast(), &raw mut length) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: getsockname initialized `length` bytes, including the family.
    decode_sockaddr(
        unsafe { storage.assume_init() },
        usize::try_from(length).unwrap_or(0),
    )
}

fn read_socket_addr(tid: u32, address: u64, length: u64) -> io::Result<SocketAddr> {
    let length = usize::try_from(length).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    if length < size_of::<libc::sa_family_t>() || length > size_of::<libc::sockaddr_storage>() {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let mut bytes = vec![0_u8; length];
    task_memory::read_exact(tid, address, &mut bytes)?;
    let mut storage = std::mem::MaybeUninit::<libc::sockaddr_storage>::zeroed();
    // SAFETY: destination spans sockaddr_storage and `length` was bounded.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), storage.as_mut_ptr().cast(), length);
        decode_sockaddr(storage.assume_init(), length)
    }
}

fn socket_address_is_inet(tid: u32, address: u64, length: u64) -> io::Result<bool> {
    let length = usize::try_from(length).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    if address == 0 || length < size_of::<libc::sa_family_t>() {
        return Err(io::Error::from_raw_os_error(libc::EFAULT));
    }
    let mut family = [0_u8; size_of::<libc::sa_family_t>()];
    task_memory::read_exact(tid, address, &mut family)?;
    Ok(matches!(
        i32::from(libc::sa_family_t::from_ne_bytes(family)),
        libc::AF_INET | libc::AF_INET6
    ))
}

fn decode_sockaddr(storage: libc::sockaddr_storage, length: usize) -> io::Result<SocketAddr> {
    match i32::from(storage.ss_family) {
        libc::AF_INET if length >= size_of::<libc::sockaddr_in>() => {
            // SAFETY: family and length establish sockaddr_in layout.
            let address = unsafe { *(&raw const storage).cast::<libc::sockaddr_in>() };
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes())),
                u16::from_be(address.sin_port),
            ))
        }
        libc::AF_INET6 if length >= size_of::<libc::sockaddr_in6>() => {
            // SAFETY: family and length establish sockaddr_in6 layout.
            let address = unsafe { *(&raw const storage).cast::<libc::sockaddr_in6>() };
            Ok(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)),
                u16::from_be(address.sin6_port),
            ))
        }
        _ => Err(io::Error::from_raw_os_error(libc::EAFNOSUPPORT)),
    }
}

fn write_socket_addr(
    listener: &NotificationListener,
    notification_id: u64,
    tid: u32,
    address: u64,
    length_address: u64,
    value: SocketAddr,
) -> io::Result<()> {
    let mut supplied_length = [0_u8; size_of::<libc::socklen_t>()];
    task_memory::read_exact(tid, length_address, &mut supplied_length)?;
    let supplied_length = libc::socklen_t::from_ne_bytes(supplied_length);
    let (bytes, actual_length) = sockaddr_bytes(value);
    let copied = usize::try_from(supplied_length)
        .unwrap_or(0)
        .min(bytes.len());
    listener.validate_id(notification_id)?;
    if copied != 0 {
        task_memory::write_exact(tid, address, &bytes[..copied])?;
    }
    listener.validate_id(notification_id)?;
    task_memory::write_exact(tid, length_address, &actual_length.to_ne_bytes())
}

fn sockaddr_bytes(address: SocketAddr) -> (Vec<u8>, libc::socklen_t) {
    match address {
        SocketAddr::V4(address) => {
            let native = libc::sockaddr_in {
                sin_family: libc::sa_family_t::try_from(libc::AF_INET)
                    .expect("AF_INET fits sa_family_t"),
                sin_port: address.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: native is plain initialized storage.
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    (&raw const native).cast::<u8>(),
                    size_of::<libc::sockaddr_in>(),
                )
            };
            (
                bytes.to_vec(),
                libc::socklen_t::try_from(size_of::<libc::sockaddr_in>())
                    .expect("sockaddr_in size fits socklen_t"),
            )
        }
        SocketAddr::V6(address) => {
            let native = libc::sockaddr_in6 {
                sin6_family: libc::sa_family_t::try_from(libc::AF_INET6)
                    .expect("AF_INET6 fits sa_family_t"),
                sin6_port: address.port().to_be(),
                sin6_flowinfo: address.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: address.ip().octets(),
                },
                sin6_scope_id: address.scope_id(),
            };
            // SAFETY: native is plain initialized storage.
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    (&raw const native).cast::<u8>(),
                    size_of::<libc::sockaddr_in6>(),
                )
            };
            (
                bytes.to_vec(),
                libc::socklen_t::try_from(size_of::<libc::sockaddr_in6>())
                    .expect("sockaddr_in6 size fits socklen_t"),
            )
        }
    }
}

fn with_sockaddr<T>(
    address: SocketAddr,
    operation: impl FnOnce(*const libc::sockaddr, libc::socklen_t) -> io::Result<T>,
) -> io::Result<T> {
    match address {
        SocketAddr::V4(address) => {
            let native = libc::sockaddr_in {
                sin_family: libc::sa_family_t::try_from(libc::AF_INET)
                    .expect("AF_INET fits sa_family_t"),
                sin_port: address.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            operation(
                (&raw const native).cast(),
                libc::socklen_t::try_from(size_of::<libc::sockaddr_in>())
                    .expect("sockaddr_in size fits socklen_t"),
            )
        }
        SocketAddr::V6(address) => {
            let native = libc::sockaddr_in6 {
                sin6_family: libc::sa_family_t::try_from(libc::AF_INET6)
                    .expect("AF_INET6 fits sa_family_t"),
                sin6_port: address.port().to_be(),
                sin6_flowinfo: address.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: address.ip().octets(),
                },
                sin6_scope_id: address.scope_id(),
            };
            operation(
                (&raw const native).cast(),
                libc::socklen_t::try_from(size_of::<libc::sockaddr_in6>())
                    .expect("sockaddr_in6 size fits socklen_t"),
            )
        }
    }
}

fn raw_fd(value: u64) -> io::Result<RawFd> {
    RawFd::try_from(value).map_err(|_| io::Error::from_raw_os_error(libc::EBADF))
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn error_to_errno(error: &io::Error) -> i32 {
    error.raw_os_error().unwrap_or(libc::EACCES).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::{UnixListener, UnixStream};

    #[test]
    fn pending_external_open_slots_are_bounded_and_reusable() {
        let active = Arc::new(AtomicUsize::new(OPEN_QUEUE_CAPACITY - 1));
        let last = acquire_pending_open_slot(&active).expect("last available slot");
        assert_eq!(
            acquire_pending_open_slot(&active)
                .expect_err("open limit must fail closed")
                .raw_os_error(),
            Some(libc::EAGAIN)
        );
        drop(last);
        let reused = acquire_pending_open_slot(&active).expect("released slot");
        drop(reused);
        assert_eq!(active.load(Ordering::Acquire), OPEN_QUEUE_CAPACITY - 1);
    }

    #[test]
    fn dns_worker_slots_are_bounded_and_reusable() {
        let active = Arc::new(AtomicUsize::new(DNS_WORKER_CAPACITY - 1));
        let last = acquire_pending_dns_slot(&active).expect("last available slot");
        assert_eq!(
            acquire_pending_dns_slot(&active)
                .expect_err("DNS worker limit must fail closed")
                .raw_os_error(),
            Some(libc::EAGAIN)
        );
        drop(last);
        let reused = acquire_pending_dns_slot(&active).expect("released slot");
        drop(reused);
        assert_eq!(active.load(Ordering::Acquire), DNS_WORKER_CAPACITY - 1);
    }

    #[test]
    fn unix_connect_remains_kernel_driven() {
        let directory = tempfile::tempdir().expect("temporary Unix socket directory");
        let path = directory.path().join("service.sock");
        let service = UnixListener::bind(&path).expect("bind Unix service");
        let (launcher, listener) = openshell_isolation_interface::linux::workload_launcher::start()
            .expect("start workload launcher");
        let _broker = NetworkBroker::start_for_test(listener).expect("start network broker");
        let client = std::thread::spawn(move || {
            launcher
                .execute(move || -> io::Result<()> {
                    let mut stream = UnixStream::connect(path)?;
                    stream.write_all(b"unix")
                })
                .expect("launcher result")
        });
        let (mut stream, _) = service.accept().expect("accept Unix client");
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).expect("read Unix payload");
        assert_eq!(&payload, b"unix");
        client.join().expect("join client").expect("Unix client");
    }

    #[test]
    fn accepted_loopback_stream_is_registered_for_notified_operations() {
        let reservation = TcpListener::bind("127.0.0.1:0").expect("reserve loopback port");
        let address = reservation.local_addr().expect("reserved address");
        drop(reservation);

        let (launcher, listener) = openshell_isolation_interface::linux::workload_launcher::start()
            .expect("start workload launcher");
        let _broker = NetworkBroker::start_for_test(listener).expect("start network broker");
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let workload = std::thread::spawn(move || {
            launcher
                .execute(move || -> io::Result<SocketAddr> {
                    let listener = TcpListener::bind(address)?;
                    ready_tx
                        .send(())
                        .map_err(|_| io::Error::other("test client disappeared"))?;
                    let (stream, _) = listener.accept()?;
                    let peer = stream.peer_addr()?;
                    let payload = b"accepted";
                    let iov = libc::iovec {
                        iov_base: payload.as_ptr().cast_mut().cast(),
                        iov_len: payload.len(),
                    };
                    let message = libc::msghdr {
                        msg_name: std::ptr::null_mut(),
                        msg_namelen: 0,
                        msg_iov: (&raw const iov).cast_mut(),
                        msg_iovlen: 1,
                        msg_control: std::ptr::null_mut(),
                        msg_controllen: 0,
                        msg_flags: 0,
                    };
                    // SAFETY: message references one live immutable payload;
                    // the accepted stream remains open for the call.
                    let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &raw const message, 0) };
                    if sent != isize::try_from(payload.len()).expect("payload fits isize") {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(peer)
                })
                .expect("launcher result")
        });

        ready_rx.recv().expect("listener ready");
        let mut client = TcpStream::connect(address).expect("connect loopback client");
        let mut payload = [0_u8; 8];
        client
            .read_exact(&mut payload)
            .expect("read accepted stream");
        assert_eq!(&payload, b"accepted");
        assert!(
            workload
                .join()
                .expect("join workload")
                .expect("accepted workload")
                .ip()
                .is_loopback()
        );
    }

    #[test]
    fn external_connect_waits_for_explicit_relay_decision() {
        let (launcher, listener) = openshell_isolation_interface::linux::workload_launcher::start()
            .expect("start workload launcher");
        let broker = NetworkBroker::start_for_test(listener).expect("start network broker");
        let client = std::thread::spawn(move || {
            launcher
                .execute(|| -> io::Result<()> {
                    let mut stream = TcpStream::connect("203.0.113.7:443")?;
                    stream.write_all(b"request")?;
                    let mut response = [0_u8; 8];
                    stream.read_exact(&mut response)?;
                    if &response != b"response" {
                        return Err(io::Error::other("relay returned wrong response"));
                    }
                    Ok(())
                })
                .expect("launcher result")
        });

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let pending = runtime.block_on(broker.accept()).expect("pending TCP open");
        assert_eq!(pending.destination, "203.0.113.7:443".parse().unwrap());
        assert!(pending.socket.socket_cookie != 0);
        let mut relay = runtime
            .block_on(pending.complete(NetworkOpenResult::RelayReady))
            .expect("complete relay")
            .expect("authorized relay stream");
        let mut request = [0_u8; 7];
        relay
            .read_exact(&mut request)
            .expect("read relayed request");
        assert_eq!(&request, b"request");
        relay.write_all(b"response").expect("write relay response");
        client.join().expect("join client").expect("client relay");
    }

    #[test]
    fn denied_external_connect_keeps_socket_unconnected() {
        let (launcher, listener) = openshell_isolation_interface::linux::workload_launcher::start()
            .expect("start workload launcher");
        let broker = NetworkBroker::start_for_test(listener).expect("start network broker");
        let client = std::thread::spawn(move || {
            launcher
                .execute(|| TcpStream::connect("198.51.100.9:80"))
                .expect("launcher result")
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let pending = runtime.block_on(broker.accept()).expect("pending TCP open");
        assert!(
            runtime
                .block_on(pending.complete(NetworkOpenResult::Denied {
                    errno: libc::EACCES,
                }))
                .expect("complete denial")
                .is_none()
        );
        assert_eq!(
            client
                .join()
                .expect("join client")
                .expect_err("connect must be denied")
                .raw_os_error(),
            Some(libc::EACCES)
        );
    }

    #[test]
    fn udp_dns_normalizes_wildcard_source_for_relay_attribution() {
        let (launcher, listener) = openshell_isolation_interface::linux::workload_launcher::start()
            .expect("start workload launcher");
        let broker = NetworkBroker::start_for_test(listener).expect("start network broker");
        let dns_address = broker.dns_address();
        let client = std::thread::spawn(move || {
            launcher
                .execute(move || -> io::Result<SocketAddr> {
                    // Tokio/Hickory-style resolvers bind a wildcard source
                    // before sending to the configured nameserver.
                    let socket = UdpSocket::bind("0.0.0.0:0")?;
                    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                    socket.send_to(b"dns-query", dns_address)?;
                    let mut response = [0_u8; 32];
                    let (length, source) = socket.recv_from(&mut response)?;
                    if &response[..length] != b"dns-response" {
                        return Err(io::Error::other("wrong DNS response"));
                    }
                    Ok(source)
                })
                .expect("launcher result")
        });

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let query = runtime.block_on(broker.accept_dns()).expect("DNS query");
        assert_eq!(query.transport, DnsTransport::Udp);
        assert_eq!(query.request, b"dns-query");
        query.complete(Ok(b"dns-response".to_vec())).unwrap();
        assert_eq!(
            client.join().expect("join client").expect("DNS client"),
            dns_address
        );
    }

    #[test]
    fn tcp_dns_preserves_length_framing() {
        let (launcher, listener) = openshell_isolation_interface::linux::workload_launcher::start()
            .expect("start workload launcher");
        let broker = NetworkBroker::start_for_test(listener).expect("start network broker");
        let dns_address = broker.dns_address();
        let client = std::thread::spawn(move || {
            launcher
                .execute(move || -> io::Result<Vec<u8>> {
                    let mut stream = TcpStream::connect(dns_address)?;
                    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                    stream.write_all(&[0, 3, 1, 2, 3])?;
                    let mut response = vec![0_u8; 5];
                    stream.read_exact(&mut response)?;
                    Ok(response)
                })
                .expect("launcher result")
        });

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let query = runtime.block_on(broker.accept_dns()).expect("DNS query");
        assert_eq!(query.transport, DnsTransport::Tcp);
        assert_eq!(query.request, [0, 3, 1, 2, 3]);
        query.complete(Ok(vec![0, 3, 4, 5, 6])).unwrap();
        assert_eq!(
            client.join().expect("join client").expect("DNS client"),
            [0, 3, 4, 5, 6]
        );
    }
}
