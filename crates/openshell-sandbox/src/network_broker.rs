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
use std::time::{Duration, Instant};

use openshell_binary_identity::ProcfsIdentityResolver;
use openshell_isolation_interface::contract::{
    BinaryIdentity, DnsTransport, NetworkSocketMetadata, ResolveError, TcpOpenDecision,
    TcpOpenDenial,
};
use openshell_isolation_interface::linux::seccomp_notify::{Notification, NotificationListener};
use openshell_isolation_interface::linux::socket_registry::{
    InetFamily, InetKind, SocketIdentity, SocketMetadata, SocketRegistry, SocketState,
};
use openshell_isolation_interface::linux::task_memory;
use tokio::sync::{mpsc, oneshot};

const SOCKET_CAPACITY: usize = 4_096;
const SOCKET_FD_HEADROOM: usize = 64;
const OPEN_QUEUE_CAPACITY: usize = 256;
const DNS_QUEUE_CAPACITY: usize = 256;
const DNS_WORKER_CAPACITY: usize = 256;
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_RELAY_ADDRESS: SocketAddr = SocketAddr::V4(std::net::SocketAddrV4::new(
    Ipv4Addr::new(127, 0, 0, 53),
    53,
));
const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const NETWORK_DECISION_TIMEOUT: Duration = Duration::from_secs(30);

fn retry_notification_receive(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::Interrupted || error.raw_os_error() == Some(libc::ENOENT)
}

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
    pub(crate) notification_to_queue: Duration,
    pub(crate) queued_at: Instant,
    decision: std::sync::mpsc::SyncSender<TcpOpenDecision>,
    relay: oneshot::Receiver<io::Result<TcpStream>>,
}

impl PendingTcpOpen {
    pub(crate) async fn complete(self, decision: TcpOpenDecision) -> io::Result<Option<TcpStream>> {
        self.decision
            .send(decision)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "network broker stopped"))?;
        if matches!(decision, TcpOpenDecision::Denied(_)) {
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
    pub(crate) notification_to_queue: Duration,
    pub(crate) queued_at: Instant,
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
    udp_admissions: Arc<Mutex<HashMap<SocketAddr, SocketIdentity>>>,
    tcp_admissions: Arc<Mutex<HashMap<SocketAddr, SocketIdentity>>>,
}

fn dns_sender_identity() -> Result<BinaryIdentity, ResolveError> {
    // Native writes can come from an inheriting process or after execve. A
    // connect-time identity (or a later procfs holder scan) cannot identify
    // the sender of an already queued query. Never assert that it can.
    Err(ResolveError::Failed(
        "DNS sender identity is unavailable for kernel-driven socket writes".to_string(),
    ))
}

fn register_dns_socket(
    admissions: &Mutex<HashMap<SocketAddr, SocketIdentity>>,
    peer: SocketAddr,
    identity: SocketIdentity,
) -> io::Result<()> {
    let mut admissions = lock(admissions);
    if admissions.len() >= SOCKET_CAPACITY && !admissions.contains_key(&peer) {
        let installed =
            openshell_isolation_interface::linux::proc_fd::installed_socket_inodes_excluding(
                std::process::id(),
            )?;
        admissions.retain(|_, socket| installed.contains(&socket.inode));
        if admissions.len() >= SOCKET_CAPACITY {
            return Err(io::Error::from_raw_os_error(libc::EMFILE));
        }
    }
    admissions.insert(peer, identity);
    Ok(())
}

#[derive(Clone)]
struct NotificationQueues {
    provider_files: crate::provider_files::ProviderFiles,
    protected_control_port: Option<u16>,
    identity_resolver: ProcfsIdentityResolver,
    pending: mpsc::Sender<PendingTcpOpen>,
    dns_relay: DnsRelay,
    active_opens: Arc<AtomicUsize>,
    retained_socket_capacity: usize,
    decision_timeout: Duration,
}

/// Live broker handle retained by the sandbox boundary.
#[derive(Clone)]
pub struct NetworkBroker {
    provider_files: crate::provider_files::ProviderFiles,
    pending: Arc<tokio::sync::Mutex<mpsc::Receiver<PendingTcpOpen>>>,
    pending_dns: Arc<tokio::sync::Mutex<mpsc::Receiver<PendingDnsQuery>>>,
    dns_address: SocketAddr,
    healthy: Arc<AtomicBool>,
}

impl NetworkBroker {
    pub(crate) fn start(
        listener: NotificationListener,
        protected_control_port: Option<u16>,
    ) -> io::Result<Self> {
        Self::start_with_dns_address(listener, DNS_RELAY_ADDRESS, protected_control_port)
    }

    #[cfg(any(test, feature = "perf-harness"))]
    pub(crate) fn start_for_test(listener: NotificationListener) -> io::Result<Self> {
        Self::start_with_dns_address(
            listener,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            None,
        )
    }

    fn start_with_dns_address(
        listener: NotificationListener,
        dns_address: SocketAddr,
        protected_control_port: Option<u16>,
    ) -> io::Result<Self> {
        Self::start_with_decision_timeout(
            listener,
            dns_address,
            protected_control_port,
            NETWORK_DECISION_TIMEOUT,
        )
    }

    fn start_with_decision_timeout(
        listener: NotificationListener,
        dns_address: SocketAddr,
        protected_control_port: Option<u16>,
        decision_timeout: Duration,
    ) -> io::Result<Self> {
        let listener = Arc::new(listener);
        let (pending_tx, pending_rx) = mpsc::channel(OPEN_QUEUE_CAPACITY);
        let (pending_dns_tx, pending_dns_rx) = mpsc::channel(DNS_QUEUE_CAPACITY);
        let active_opens = Arc::new(AtomicUsize::new(0));
        let dns_relay = start_dns_relay(dns_address, pending_dns_tx)?;
        let dns_address = dns_relay.address;
        let retained_socket_capacity = retained_socket_capacity()?;
        let registry = Arc::new(Mutex::new(SocketRegistry::new(1, SOCKET_CAPACITY)?));
        let provider_files = crate::provider_files::ProviderFiles::default();
        let queues = NotificationQueues {
            provider_files: provider_files.clone(),
            protected_control_port,
            identity_resolver: ProcfsIdentityResolver::for_pid_namespace(),
            pending: pending_tx,
            dns_relay,
            active_opens,
            retained_socket_capacity,
            decision_timeout,
        };
        let healthy = Arc::new(AtomicBool::new(true));
        let broker_healthy = healthy.clone();
        std::thread::Builder::new()
            .name("openshell-network-broker".to_string())
            .spawn(move || {
                while broker_healthy.load(Ordering::Acquire) {
                    let notification = match listener.receive() {
                        Ok(notification) => notification,
                        // ENOENT is a documented seccomp user-notification
                        // race: the target thread exited or its blocked
                        // syscall was interrupted while the kernel was
                        // preparing the notification. It does not mean the
                        // listener itself is unhealthy.
                        Err(error) if retry_notification_receive(&error) => continue,
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
            provider_files,
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
    pub(crate) fn dns_address(&self) -> SocketAddr {
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

    pub(crate) fn provider_files(&self) -> &crate::provider_files::ProviderFiles {
        &self.provider_files
    }
}

fn start_dns_relay(
    address: SocketAddr,
    pending: mpsc::Sender<PendingDnsQuery>,
) -> io::Result<DnsRelay> {
    let (udp, tcp, address) = bind_dns_relay_sockets(address)?;
    let udp_admissions = Arc::new(Mutex::new(HashMap::new()));
    let tcp_admissions = Arc::new(Mutex::new(HashMap::new()));
    let active_workers = Arc::new(AtomicUsize::new(0));
    let relay = DnsRelay {
        address,
        udp_admissions: Arc::clone(&udp_admissions),
        tcp_admissions: Arc::clone(&tcp_admissions),
    };

    let udp_active_workers = Arc::clone(&active_workers);
    let udp_pending = pending.clone();
    std::thread::Builder::new()
        .name("openshell-dns-udp".to_string())
        .spawn(move || {
            let mut request = vec![0_u8; u16::MAX as usize];
            while let Ok((length, peer)) = udp.recv_from(&mut request) {
                if !lock(&udp_admissions).contains_key(&peer) {
                    tracing::warn!(%peer, "dropping DNS datagram from unregistered socket");
                    continue;
                }
                let Ok(worker_slot) = acquire_pending_dns_slot(&udp_active_workers) else {
                    tracing::warn!(%peer, "dropping DNS datagram because the worker quota is full");
                    continue;
                };
                let (response_tx, response_rx) = std::sync::mpsc::sync_channel(1);
                let query = PendingDnsQuery {
                    request: request[..length].to_vec(),
                    transport: DnsTransport::Udp,
                    identity: dns_sender_identity(),
                    notification_to_queue: Duration::ZERO,
                    queued_at: Instant::now(),
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
                // One admission authorizes exactly one accepted TCP stream;
                // no peer mapping needs to outlive this accept.
                if lock(&tcp_admissions).remove(&peer).is_none() {
                    tracing::warn!(%peer, "dropping DNS stream from unregistered socket");
                    continue;
                }
                let Ok(worker_slot) = acquire_pending_dns_slot(&tcp_active_workers) else {
                    tracing::warn!(%peer, "dropping DNS stream because the worker quota is full");
                    continue;
                };
                let tcp_pending = pending.clone();
                let _ = std::thread::Builder::new()
                    .name("openshell-dns-tcp-query".to_string())
                    .spawn(move || {
                        let _worker_slot = worker_slot;
                        serve_dns_tcp(stream, tcp_pending);
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

fn serve_dns_tcp(mut stream: TcpStream, pending: mpsc::Sender<PendingDnsQuery>) {
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
            identity: dns_sender_identity(),
            notification_to_queue: Duration::ZERO,
            queued_at: Instant::now(),
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
    if syscall == libc::SYS_openat || syscall == libc::SYS_openat2 {
        return queues.provider_files.handle_open(&listener, notification);
    }
    #[cfg(target_arch = "x86_64")]
    if syscall == libc::SYS_open {
        return queues.provider_files.handle_open(&listener, notification);
    }
    if matches!(syscall, libc::SYS_kill | libc::SYS_rt_sigqueueinfo) {
        return openshell_isolation_interface::linux::process_signal::mediate_process_signal(
            &listener,
            notification,
            std::process::id(),
        );
    }
    if syscall == libc::SYS_tkill {
        return openshell_isolation_interface::linux::process_signal::mediate_thread_signal(
            &listener,
            notification,
            std::process::id(),
        );
    }
    if syscall == libc::SYS_socket {
        return create_socket(
            &registry,
            &listener,
            notification,
            queues.retained_socket_capacity,
        );
    }
    if syscall == libc::SYS_connect {
        return connect_socket(registry, listener, notification, queues);
    }
    if syscall == libc::SYS_bind {
        return bind_socket(&registry, &listener, notification);
    }
    if syscall == libc::SYS_listen {
        return listen_socket(&registry, &listener, notification);
    }
    if matches!(
        syscall,
        libc::SYS_sendto | libc::SYS_sendmsg | libc::SYS_sendmmsg
    ) {
        return classify_send(&registry, &listener, notification, &queues.dns_relay);
    }
    if syscall == libc::SYS_setsockopt {
        let level = i32::try_from(notification.args[1])
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        let option = i32::try_from(notification.args[2])
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        if socket_option_is_denied(level, option) {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        return listener.respond_continue(notification.id);
    }
    Err(io::Error::from_raw_os_error(libc::EPERM))
}

/// Options the workload may never set, decided from scalar syscall arguments
/// that another thread cannot replace before the kernel reads them.
///
/// Interface-selection options could redirect or unpin a socket's loopback
/// device binding. The kernel already refuses to change an existing binding
/// without `CAP_NET_RAW`; denying them here keeps confinement independent of
/// the capability state of the namespace that owns the network namespace.
fn socket_option_is_denied(level: i32, option: i32) -> bool {
    matches!(
        (level, option),
        (libc::IPPROTO_TCP, libc::TCP_FASTOPEN_CONNECT)
            | (
                libc::IPPROTO_IPV6,
                libc::IPV6_ADDRFORM | libc::IPV6_UNICAST_IF | libc::IPV6_MULTICAST_IF
            )
            | (
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE | libc::SO_BINDTOIFINDEX
            )
            | (
                libc::IPPROTO_IP,
                libc::IP_UNICAST_IF | libc::IP_MULTICAST_IF
            )
    )
}

fn create_socket(
    registry: &Mutex<SocketRegistry>,
    listener: &NotificationListener,
    notification: Notification,
    retained_socket_capacity: usize,
) -> io::Result<()> {
    let domain = i32::try_from(notification.args[0])
        .map_err(|_| io::Error::from_raw_os_error(libc::EAFNOSUPPORT))?;
    if !matches!(domain, libc::AF_INET | libc::AF_INET6) {
        // The workload filter already refuses other families. Repeat the
        // decision here so a filter change cannot let a kernel transport
        // socket bypass loopback confinement; the domain is a scalar argument.
        if matches!(domain, libc::AF_UNIX | libc::AF_NETLINK) {
            return listener.respond_continue(notification.id);
        }
        return Err(io::Error::from_raw_os_error(libc::EAFNOSUPPORT));
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
    // Reclaim stale descriptors before the broker exhausts its process limit.
    // Connected sockets remain in the metadata registry without consuming
    // this broker-owned descriptor budget.
    if let Err(error) = prepare_registry_for_socket(registry, retained_socket_capacity) {
        return listener.respond_errno(notification.id, error_to_errno(&error));
    }
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
    // Confinement is standing kernel state that must exist before the workload
    // can observe the descriptor. Natively accepted children inherit it, so
    // local accept needs no per-connection broker inspection.
    openshell_isolation_interface::linux::socket_confinement::confine_to_loopback(&source)?;
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

fn retained_socket_capacity() -> io::Result<usize> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: limit points to writable storage for one rlimit value.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let soft_limit = usize::try_from(limit.rlim_cur).unwrap_or(usize::MAX);
    let open_descriptors = std::fs::read_dir("/proc/self/fd")?.count();
    Ok(retained_socket_capacity_for_limit(
        soft_limit,
        open_descriptors,
    ))
}

fn retained_socket_capacity_for_limit(soft_limit: usize, open_descriptors: usize) -> usize {
    soft_limit
        .saturating_sub(open_descriptors)
        .saturating_sub(SOCKET_FD_HEADROOM)
        .clamp(1, SOCKET_CAPACITY)
}

fn prepare_registry_for_socket(
    registry: &Mutex<SocketRegistry>,
    retained_socket_capacity: usize,
) -> io::Result<()> {
    let mut registry = lock(registry);
    if registry.is_full() || registry.retained_preconnect_count() >= retained_socket_capacity {
        collect_closed_socket_entries_locked(&mut registry)?;
    }
    if registry.is_full() || registry.retained_preconnect_count() >= retained_socket_capacity {
        return Err(io::Error::from_raw_os_error(libc::EMFILE));
    }
    Ok(())
}

fn reject_protected_control_destination(
    destination: SocketAddr,
    protected_port: Option<u16>,
) -> io::Result<()> {
    // Reserve the listener's port across loopback aliases, IPv4-mapped IPv6,
    // and wildcard Pod listeners. A workload must never reach its control
    // endpoint, including through a supervisor-authorized external relay.
    if protected_port == Some(destination.port()) {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }
    Ok(())
}

fn connect_socket(
    registry: Arc<Mutex<SocketRegistry>>,
    listener: Arc<NotificationListener>,
    notification: Notification,
    queues: NotificationQueues,
) -> io::Result<()> {
    let NotificationQueues {
        pending,
        dns_relay,
        active_opens,
        identity_resolver,
        decision_timeout,
        protected_control_port,
        ..
    } = queues;
    let notification_started = Instant::now();
    let fd = raw_fd(notification.args[0])?;
    let address_family =
        read_socket_family(notification.tid, notification.args[1], notification.args[2])?;
    if !matches!(address_family, libc::AF_INET | libc::AF_INET6) {
        if address_family == libc::AF_UNSPEC {
            let mut registry = lock(&registry);
            if let Ok(entry) = registry.resolve_mut(notification.tid, fd)
                && entry.metadata().kind == InetKind::DnsUdp
                && matches!(
                    entry.state(),
                    SocketState::Created | SocketState::Bound { .. }
                )
            {
                // Address-selection implementations disconnect a temporary
                // UDP route-probe socket with AF_UNSPEC before trying the next
                // candidate. The probe below never connects the real OFD, so
                // this is an idempotent no-op rather than a kernel CONTINUE.
                return listener.respond_value(notification.id, 0);
            }
        }
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
    reject_protected_control_destination(destination, protected_control_port)?;
    let (kind, socket_identity, nonblocking, repeated) = {
        let registry = lock(&registry);
        let entry = registry.resolve(notification.tid, fd)?;
        (
            entry.metadata().kind,
            entry.identity(),
            entry.metadata().nonblocking,
            repeated_connect_outcome(entry.state(), entry.metadata().kind, destination),
        )
    };
    match repeated {
        Some(0) => return listener.respond_value(notification.id, 0),
        Some(errno) => return Err(io::Error::from_raw_os_error(errno)),
        None => {}
    }
    if kind == InetKind::DnsUdp && destination.port() == 0 {
        let mut registry = lock(&registry);
        let entry = registry.resolve_mut(notification.tid, fd)?;
        if !matches!(
            entry.state(),
            SocketState::Created | SocketState::Bound { .. }
        ) {
            return Err(io::Error::from_raw_os_error(libc::EISCONN));
        }
        let destination_family = match destination {
            SocketAddr::V4(_) => InetFamily::V4,
            SocketAddr::V6(_) => InetFamily::V6,
        };
        if entry.metadata().family != destination_family {
            return Err(io::Error::from_raw_os_error(libc::EAFNOSUPPORT));
        }
        listener.validate_id(notification.id)?;
        // glibc and uv use UDP connect(..., port 0), getsockname(), and an
        // AF_UNSPEC disconnect to rank resolved addresses. Bind only to the
        // matching loopback family and report success; never connect the
        // kernel socket to the external candidate. write(2) therefore remains
        // EDESTADDRREQ and destination-bearing sends remain broker-denied.
        let local = ensure_dns_source_bound(
            entry.retained_preconnect()?.as_raw_fd(),
            entry.metadata().family,
        )?;
        entry.set_state(SocketState::Bound { local });
        return listener.respond_value(notification.id, 0);
    }
    if destination == dns_relay.address {
        let mut registry = lock(&registry);
        let entry = registry.resolve_mut(notification.tid, fd)?;
        if !matches!(
            entry.state(),
            SocketState::Created | SocketState::Bound { .. }
        ) {
            return Err(io::Error::from_raw_os_error(libc::EISCONN));
        }
        let source_fd = entry.retained_preconnect()?.as_raw_fd();
        listener.validate_id(notification.id)?;
        let peer = ensure_dns_source_bound(source_fd, entry.metadata().family)?;
        let admissions = match kind {
            InetKind::Tcp => &dns_relay.tcp_admissions,
            InetKind::DnsUdp => &dns_relay.udp_admissions,
        };
        register_dns_socket(admissions, peer, entry.identity())?;
        if let Err(error) = connect_exact(source_fd, destination) {
            lock(admissions).remove(&peer);
            return Err(error);
        }
        entry.set_state(match kind {
            InetKind::Tcp => SocketState::DnsTcp { relay: destination },
            InetKind::DnsUdp => SocketState::DnsUdp { relay: destination },
        });
        entry.release_preconnect();
        return listener.respond_value(notification.id, 0);
    }
    // The metadata service lives in the supervisor, even though SDKs address
    // it through loopback. Relay it before the ordinary local socket path.
    if destination.ip().is_loopback()
        && !openshell_core::google_cloud::is_metadata_destination(destination)
    {
        let mut registry = lock(&registry);
        let entry = registry.resolve_mut(notification.tid, fd)?;
        listener.validate_id(notification.id)?;
        connect_exact(entry.retained_preconnect()?.as_raw_fd(), destination)?;
        entry.set_state(SocketState::Local { peer: destination });
        entry.release_preconnect();
        return listener.respond_value(notification.id, 0);
    }
    if kind != InetKind::Tcp {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }

    let identity = identity_resolver.resolve(notification.tid);
    let (decision_tx, decision_rx) = std::sync::mpsc::sync_channel(1);
    let (relay_tx, relay_rx) = oneshot::channel();
    let slot = acquire_pending_open_slot(&active_opens)?;
    pending
        .try_send(PendingTcpOpen {
            destination,
            identity,
            socket: NetworkSocketMetadata {
                socket_cookie: socket_identity.cookie,
                nonblocking,
                process_generation: u64::from(notification.tid),
            },
            notification_to_queue: notification_started.elapsed(),
            queued_at: Instant::now(),
            decision: decision_tx,
            relay: relay_rx,
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
            // The worker owns its quota: an unresponsive supervisor must not
            // retain a blocked syscall or worker slot indefinitely.
            let _slot = slot;
            let result = match decision_rx.recv_timeout(decision_timeout) {
                Ok(decision) => decision,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    let _ = worker_listener.respond_errno(notification.id, libc::ETIMEDOUT);
                    return;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    TcpOpenDecision::Denied(TcpOpenDenial::MediationUnavailable)
                }
            };
            match result {
                TcpOpenDecision::Denied(reason) => {
                    let _ =
                        worker_listener.respond_errno(notification.id, tcp_denial_errno(reason));
                }
                TcpOpenDecision::RelayReady => {
                    match worker_listener.validate_id(notification.id).and_then(|()| {
                        establish_relay(
                            &registry,
                            notification.tid,
                            fd,
                            socket_identity,
                            destination,
                        )
                    }) {
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

/// Result for a `connect` on a socket the broker already connected, as the
/// kernel would report it: `Some(0)` for success, `Some(errno)` for an error,
/// `None` when the socket is not yet connected.
///
/// A notified syscall interrupted by a signal is restarted after the broker
/// may already have completed it, so a repeat must not depend on the broker's
/// released pre-connect descriptor.
fn repeated_connect_outcome(
    state: &SocketState,
    kind: InetKind,
    destination: SocketAddr,
) -> Option<i32> {
    match state {
        SocketState::Created | SocketState::Bound { .. } | SocketState::Listening { .. } => None,
        SocketState::Failed { errno } => Some(*errno),
        // UDP connect replaces the association; repeating the same one succeeds.
        SocketState::DnsUdp { relay } if *relay == destination => Some(0),
        SocketState::Local { peer } if kind == InetKind::DnsUdp && *peer == destination => Some(0),
        _ if kind == InetKind::Tcp => Some(libc::EISCONN),
        _ => None,
    }
}

const fn tcp_denial_errno(reason: TcpOpenDenial) -> i32 {
    match reason {
        TcpOpenDenial::PolicyDenied
        | TcpOpenDenial::IdentityUnavailable
        | TcpOpenDenial::InvalidDestination => libc::EACCES,
        TcpOpenDenial::ResourceExhausted => libc::EAGAIN,
        TcpOpenDenial::MediationUnavailable => libc::ECANCELED,
    }
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
    expected_socket: SocketIdentity,
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
        if entry.identity() != expected_socket {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        connect_exact(entry.retained_preconnect()?.as_raw_fd(), relay_address)?;
        let expected_peer = socket_local_addr(entry.retained_preconnect()?.as_raw_fd())?;
        entry.set_state(SocketState::Connected {
            original_peer: destination,
        });
        entry.release_preconnect();
        expected_peer
    };
    relay.set_nonblocking(true)?;
    let deadline = Instant::now() + RELAY_CONNECT_TIMEOUT;
    let stream = loop {
        let now = Instant::now();
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
        // A native bind is never restarted, but a notified one can be after a
        // signal. Report a repeat of the bind the broker completed as success.
        if entry.state() == &(SocketState::Bound { local }) {
            return listener.respond_value(notification.id, 0);
        }
        listener.validate_id(notification.id)?;
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
    // listen(2) may be repeated natively, so a restart needs no special case.
    listener.validate_id(notification.id)?;
    // SAFETY: retained descriptor is the exact registered socket OFD.
    if unsafe { libc::listen(entry.retained_preconnect()?.as_raw_fd(), backlog) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let local = socket_local_addr(entry.retained_preconnect()?.as_raw_fd())?;
    entry.set_state(SocketState::Listening { local });
    listener.respond_value(notification.id, 0)
}

fn classify_send(
    registry: &Mutex<SocketRegistry>,
    listener: &NotificationListener,
    notification: Notification,
    dns_relay: &DnsRelay,
) -> io::Result<()> {
    let fd = raw_fd(notification.args[0])?;
    let syscall = i64::from(notification.syscall);
    // Fast Open turns a send into a connect. Decide from the scalar flags
    // argument, which another thread cannot replace, so the denial also
    // covers natively accepted and other unregistered descriptors.
    if send_flags(syscall, notification.args) & libc::MSG_FASTOPEN != 0 {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    let (state, metadata) = {
        let registry = lock(registry);
        let Ok(entry) = registry.resolve(notification.tid, fd) else {
            // Non-INET sockets are never injected into the registry. Leave
            // their native sendmsg/control-message semantics to the kernel.
            return listener.respond_continue(notification.id);
        };
        (entry.state().clone(), entry.metadata())
    };
    if matches!(&state, SocketState::Connected { .. })
        || (metadata.kind == InetKind::Tcp && matches!(&state, SocketState::Local { .. }))
    {
        return listener.respond_continue(notification.id);
    }
    let messages = match syscall {
        libc::SYS_sendto => vec![read_sendto_message(notification)?],
        libc::SYS_sendmsg => vec![read_sendmsg_message(
            notification.tid,
            notification.args[1],
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
            let SocketState::DnsUdp { relay } = entry.state() else {
                unreachable!("guard requires DNS UDP state");
            };
            // musl-based resolvers, including the statically linked `uv`
            // client, send A and AAAA as separate destination-bearing
            // datagrams on one socket. The first send pins the socket to the
            // private relay; permit later sends only when their copied
            // destination is absent or names that same relay. The mandatory
            // outer network fence remains the fail-closed backstop for the
            // sibling-thread pointer race inherent in seccomp CONTINUE.
            if messages.iter().all(|message| {
                message
                    .destination
                    .is_none_or(|destination| destination == *relay)
            }) {
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
            let entry = registry.resolve_mut(notification.tid, fd)?;
            let source_fd = entry.retained_preconnect()?.as_raw_fd();
            listener.validate_id(notification.id)?;
            let peer = ensure_dns_source_bound(source_fd, entry.metadata().family)?;
            register_dns_socket(&dns_relay.udp_admissions, peer, entry.identity())?;
            if let Err(error) = connect_exact(source_fd, dns_relay.address) {
                lock(&dns_relay.udp_admissions).remove(&peer);
                return Err(error);
            }
            entry.set_state(SocketState::DnsUdp {
                relay: dns_relay.address,
            });
            entry.release_preconnect();
            // The socket is now pinned to the relay and bound to loopback. The
            // kernel performs the send and writes any per-message results, so
            // the broker never writes workload memory.
            listener.respond_continue(notification.id)
        }
        Ok(_) => Err(io::Error::from_raw_os_error(libc::EDESTADDRREQ)),
        // Non-INET sockets and natively accepted sockets were never
        // registered. Accepted sockets inherit their listener's loopback
        // binding, and the mandatory outer fence remains an independent
        // backstop against an external kernel route.
        Err(_) => listener.respond_continue(notification.id),
    }
}

fn send_flags(syscall: i64, args: [u64; 6]) -> i32 {
    let flags = match syscall {
        libc::SYS_sendmsg => args[2],
        libc::SYS_sendto | libc::SYS_sendmmsg => args[3],
        _ => 0,
    };
    // Syscall flag arguments are C ints; the kernel ignores the upper word.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the kernel reads only the low 32 bits of the flags argument"
    )]
    let flags = flags as u32;
    flags.cast_signed()
}

struct SendMessage {
    destination: Option<SocketAddr>,
}

fn read_sendto_message(notification: Notification) -> io::Result<SendMessage> {
    let destination = if notification.args[4] == 0 {
        None
    } else {
        Some(read_socket_addr(
            notification.tid,
            notification.args[4],
            notification.args[5],
        )?)
    };
    Ok(SendMessage { destination })
}

fn read_sendmsg_message(tid: u32, address: u64) -> io::Result<SendMessage> {
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
    Ok(SendMessage { destination })
}

fn read_sendmmsg_messages(notification: Notification) -> io::Result<Vec<SendMessage>> {
    let count = usize::try_from(notification.args[2])
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    if count == 0 || count > 32 {
        return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
    }
    (0..count)
        .map(|index| {
            let offset = index
                .checked_mul(size_of::<libc::mmsghdr>())
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
            let base = notification.args[1]
                .checked_add(u64::try_from(offset).unwrap_or(u64::MAX))
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
            read_sendmsg_message(notification.tid, base)
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
        let timeout = i32::try_from(RELAY_CONNECT_TIMEOUT.as_millis()).map_err(io::Error::other)?;
        if unsafe { libc::poll(&raw mut poll, 1, timeout) } <= 0 {
            return Err(io::Error::from_raw_os_error(libc::ETIMEDOUT));
        }
        let mut socket_error = 0_i32;
        let mut size = libc::socklen_t::try_from(size_of::<i32>()).map_err(io::Error::other)?;
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
    let mut length =
        libc::socklen_t::try_from(size_of::<libc::sockaddr_storage>()).map_err(io::Error::other)?;
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
    Ok(matches!(
        read_socket_family(tid, address, length)?,
        libc::AF_INET | libc::AF_INET6
    ))
}

fn read_socket_family(tid: u32, address: u64, length: u64) -> io::Result<i32> {
    let length = usize::try_from(length).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    if address == 0 || length < size_of::<libc::sa_family_t>() {
        return Err(io::Error::from_raw_os_error(libc::EFAULT));
    }
    let mut family = [0_u8; size_of::<libc::sa_family_t>()];
    task_memory::read_exact(tid, address, &mut family)?;
    Ok(i32::from(libc::sa_family_t::from_ne_bytes(family)))
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

fn with_sockaddr<T>(
    address: SocketAddr,
    operation: impl FnOnce(*const libc::sockaddr, libc::socklen_t) -> io::Result<T>,
) -> io::Result<T> {
    match address {
        SocketAddr::V4(address) => {
            let native = libc::sockaddr_in {
                sin_family: libc::sa_family_t::try_from(libc::AF_INET).map_err(io::Error::other)?,
                sin_port: address.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            operation(
                (&raw const native).cast(),
                libc::socklen_t::try_from(size_of::<libc::sockaddr_in>())
                    .map_err(io::Error::other)?,
            )
        }
        SocketAddr::V6(address) => {
            let native = libc::sockaddr_in6 {
                sin6_family: libc::sa_family_t::try_from(libc::AF_INET6)
                    .map_err(io::Error::other)?,
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
                    .map_err(io::Error::other)?,
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
    use openshell_isolation_interface::linux::socket_confinement;

    #[test]
    fn provider_files_are_opened_on_demand_and_replaced() {
        let (launcher, listener) = openshell_isolation_interface::linux::workload_launcher::start()
            .expect("start workload launcher");
        let broker = NetworkBroker::start_for_test(listener).expect("start broker");
        let path = "/run/openshell/providers/acme/client.toml".to_string();
        broker
            .provider_files()
            .replace(HashMap::from([(path.clone(), "version = 1\n".into())]))
            .unwrap();
        let first = launcher
            .execute({
                let path = path.clone();
                move || std::fs::read_to_string(path)
            })
            .unwrap()
            .expect("first open");
        assert_eq!(first, "version = 1\n");
        let mut old_descriptor = launcher
            .execute({
                let path = path.clone();
                move || std::fs::File::open(path)
            })
            .unwrap()
            .expect("open old version");
        let denied_write = launcher
            .execute({
                let path = path.clone();
                move || std::fs::OpenOptions::new().write(true).open(path)
            })
            .unwrap()
            .expect_err("provider file is read only");
        assert_eq!(denied_write.raw_os_error(), Some(libc::EACCES));
        broker
            .provider_files()
            .replace(HashMap::from([(path.clone(), "version = 2\n".into())]))
            .unwrap();
        let mut old_content = String::new();
        io::Read::read_to_string(&mut old_descriptor, &mut old_content).unwrap();
        assert_eq!(old_content, "version = 1\n");
        let second = launcher
            .execute({
                let path = path.clone();
                move || std::fs::read_to_string(path)
            })
            .unwrap()
            .expect("second open");
        assert_eq!(second, "version = 2\n");
        let via_openat2 = launcher
            .execute({
                let path = path.clone();
                move || -> io::Result<String> {
                    let path = std::ffi::CString::new(path).unwrap();
                    let how = [libc::O_CLOEXEC as u64, 0, 0];
                    let fd = unsafe {
                        libc::syscall(
                            libc::SYS_openat2,
                            libc::AT_FDCWD,
                            path.as_ptr(),
                            how.as_ptr(),
                            24_usize,
                        )
                    };
                    if fd < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    let mut file = unsafe {
                        std::fs::File::from_raw_fd(i32::try_from(fd).expect("open fd fits"))
                    };
                    let mut content = String::new();
                    io::Read::read_to_string(&mut file, &mut content)?;
                    Ok(content)
                }
            })
            .unwrap();
        assert_eq!(via_openat2.unwrap(), "version = 2\n");
        broker.provider_files().replace(HashMap::new()).unwrap();
        let detached = launcher.execute(move || std::fs::read(path)).unwrap();
        assert_eq!(detached.unwrap_err().raw_os_error(), Some(libc::ENOENT));
    }
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::{UnixListener, UnixStream};

    #[test]
    fn retained_socket_capacity_reserves_process_descriptor_headroom() {
        assert_eq!(retained_socket_capacity_for_limit(1_024, 24), 936);
        assert_eq!(retained_socket_capacity_for_limit(128, 32), 32);
        assert_eq!(retained_socket_capacity_for_limit(64, 0), 1);
        assert_eq!(
            retained_socket_capacity_for_limit(usize::MAX, 0),
            SOCKET_CAPACITY
        );
    }

    #[test]
    fn retained_socket_limit_reclaims_stale_entry_before_opening_another_socket() {
        // SAFETY: socket returns one newly owned descriptor on success.
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                libc::IPPROTO_TCP,
            )
        };
        assert!(fd >= 0, "socket: {}", io::Error::last_os_error());
        // SAFETY: successful socket returned one owned descriptor.
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        let metadata = SocketMetadata {
            family: InetFamily::V4,
            kind: InetKind::Tcp,
            close_on_exec: true,
            nonblocking: false,
            creator_generation: 1,
        };
        let mut registry = SocketRegistry::new(1, 2).unwrap();
        let tentative = registry.stage(socket, metadata).unwrap();
        registry.commit(tentative).unwrap();
        assert!(!registry.is_full());
        assert_eq!(registry.retained_preconnect_count(), 1);

        let registry = Mutex::new(registry);
        prepare_registry_for_socket(&registry, 1).unwrap();

        assert!(lock(&registry).is_empty());
    }

    #[test]
    fn retained_socket_limit_does_not_cap_connected_metadata() {
        // SAFETY: socket returns one newly owned descriptor on success.
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                libc::IPPROTO_TCP,
            )
        };
        assert!(fd >= 0, "socket: {}", io::Error::last_os_error());
        // SAFETY: successful socket returned one owned descriptor.
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        let metadata = SocketMetadata {
            family: InetFamily::V4,
            kind: InetKind::Tcp,
            close_on_exec: true,
            nonblocking: false,
            creator_generation: 1,
        };
        let mut registry = SocketRegistry::new(1, 2).unwrap();
        let tentative = registry.stage(socket, metadata).unwrap();
        registry
            .commit_with_state(
                tentative,
                SocketState::Connected {
                    original_peer: "127.0.0.1:443".parse().unwrap(),
                },
            )
            .unwrap();
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.retained_preconnect_count(), 0);

        let registry = Mutex::new(registry);
        prepare_registry_for_socket(&registry, 1).unwrap();

        assert_eq!(lock(&registry).len(), 1);
    }

    #[test]
    fn notification_receive_retries_interrupted_and_disappeared_targets() {
        assert!(retry_notification_receive(&io::Error::from(
            io::ErrorKind::Interrupted
        )));
        assert!(retry_notification_receive(&io::Error::from_raw_os_error(
            libc::ENOENT
        )));
        assert!(!retry_notification_receive(&io::Error::from_raw_os_error(
            libc::EBADF
        )));
    }

    #[test]
    fn relay_rejects_descriptor_replaced_after_policy_decision() {
        let metadata = SocketMetadata {
            family: InetFamily::V4,
            kind: InetKind::Tcp,
            close_on_exec: true,
            nonblocking: false,
            creator_generation: 1,
        };
        let mut registry = SocketRegistry::new(1, 2).unwrap();
        let mut create = || {
            let socket = OwnedFd::from(
                socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap(),
            );
            let installed = rustix::io::fcntl_dupfd_cloexec(&socket, 3).unwrap();
            let tentative = registry.stage(socket, metadata).unwrap();
            let identity = registry.commit(tentative).unwrap();
            (installed, identity)
        };
        let (original, original_identity) = create();
        let (replacement, replacement_identity) = create();
        // SAFETY: both descriptors are live; replace only the test-owned FD.
        assert_eq!(
            unsafe { libc::dup2(replacement.as_raw_fd(), original.as_raw_fd()) },
            original.as_raw_fd()
        );
        let registry = Mutex::new(registry);
        let error = establish_relay(
            &registry,
            std::process::id(),
            original.as_raw_fd(),
            original_identity,
            "203.0.113.7:443".parse().unwrap(),
        )
        .expect_err("an approval for the old socket must not connect its replacement");
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
        let registry = lock(&registry);
        let entry = registry
            .resolve(std::process::id(), original.as_raw_fd())
            .unwrap();
        assert_eq!(entry.identity(), replacement_identity);
        assert_eq!(entry.state(), &SocketState::Created);
        assert_eq!(
            socket_local_addr(replacement.as_raw_fd()).unwrap().port(),
            0
        );
    }

    #[test]
    fn metadata_reservation_preserves_other_loopback_and_rejects_udp() {
        let (launcher, listener) =
            openshell_isolation_interface::linux::workload_launcher::start().unwrap();
        let _broker = NetworkBroker::start_for_test(listener).unwrap();
        let local_server = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = local_server.local_addr().unwrap();
        let connection = launcher
            .execute(move || TcpStream::connect(address))
            .unwrap()
            .unwrap();
        assert_eq!(connection.peer_addr().unwrap(), address);
        let error = launcher
            .execute(|| {
                let socket = UdpSocket::bind("127.0.0.1:0")?;
                socket.connect(openshell_core::google_cloud::METADATA_LOOPBACK_ADDR)
            })
            .unwrap()
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EACCES));
    }

    #[test]
    fn metadata_loopback_connect_is_relayed_to_supervisor() {
        use std::io::{Read as _, Write as _};
        let (launcher, listener) =
            openshell_isolation_interface::linux::workload_launcher::start().unwrap();
        let broker = NetworkBroker::start_for_test(listener).unwrap();
        let client = std::thread::spawn(move || {
            launcher
                .execute(|| {
                    let mut stream =
                        TcpStream::connect(openshell_core::google_cloud::METADATA_LOOPBACK_ADDR)?;
                    stream.write_all(b"metadata-probe")?;
                    let mut reply = [0; 2];
                    stream.read_exact(&mut reply)?;
                    Ok::<_, io::Error>(reply)
                })
                .unwrap()
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

            let pending = tokio::time::timeout(Duration::from_secs(30), broker.accept())
                .await
                .unwrap()
                .unwrap();
            assert!(openshell_core::google_cloud::is_metadata_destination(
                pending.destination
            ));
            let stream = pending
                .complete(TcpOpenDecision::RelayReady)
                .await
                .unwrap()
                .unwrap();
            stream.set_nonblocking(true).unwrap();
            let mut stream = tokio::net::TcpStream::from_std(stream).unwrap();
            let mut probe = [0; 14];
            stream.read_exact(&mut probe).await.unwrap();
            assert_eq!(&probe, b"metadata-probe");
            stream.write_all(b"ok").await.unwrap();
        });
        assert_eq!(&client.join().unwrap().unwrap(), b"ok");
    }

    #[test]
    fn external_connect_times_out_when_supervisor_retains_the_decision() {
        let (launcher, listener) = openshell_isolation_interface::linux::workload_launcher::start()
            .expect("start workload launcher");
        let broker = NetworkBroker::start_with_decision_timeout(
            listener,
            "127.0.0.1:0".parse().unwrap(),
            None,
            Duration::from_millis(50),
        )
        .unwrap();
        let client = std::thread::spawn(move || {
            launcher
                .execute(|| TcpStream::connect("203.0.113.7:443"))
                .unwrap()
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let pending = runtime.block_on(broker.accept()).unwrap();
        // Keep the request alive: channel disconnection must not be what
        // releases the workload's blocked connect.
        let error = client
            .join()
            .unwrap()
            .expect_err("unanswered connect must time out");
        assert_eq!(error.raw_os_error(), Some(libc::ETIMEDOUT));
        assert!(
            runtime
                .block_on(pending.complete(TcpOpenDecision::RelayReady))
                .is_err()
        );
    }

    #[test]
    fn dns_admissions_reclaim_closed_sockets_at_the_bound() {
        let admissions = Mutex::new(HashMap::new());
        let stale = SocketIdentity {
            listener_generation: 1,
            inode: 0,
            cookie: 1,
        };
        for port in 1..=SOCKET_CAPACITY {
            lock(&admissions).insert(
                SocketAddr::from(([127, 0, 0, 1], u16::try_from(port).unwrap())),
                stale,
            );
        }
        let peer = "127.0.0.1:50000".parse().unwrap();
        register_dns_socket(&admissions, peer, stale).unwrap();
        assert_eq!(lock(&admissions).len(), 1);
        assert_eq!(lock(&admissions).get(&peer), Some(&stale));
    }

    #[test]
    fn inherited_dns_socket_after_exec_never_claims_the_connecting_binary() {
        use std::process::{Command, Stdio};

        for transport in [DnsTransport::Udp, DnsTransport::Tcp] {
            let (launcher, listener) =
                openshell_isolation_interface::linux::workload_launcher::start().unwrap();
            let broker = NetworkBroker::start_for_test(listener).unwrap();
            let address = broker.dns_address();
            let child = std::thread::spawn(move || {
                launcher
                    .execute(move || -> io::Result<()> {
                        let (socket, script): (OwnedFd, &str) = match transport {
                            DnsTransport::Udp => {
                                let socket = UdpSocket::bind("127.0.0.1:0")?;
                                socket.connect(address)?;
                                (socket.into(), "printf dns >&0")
                            }
                            DnsTransport::Tcp => (
                                TcpStream::connect(address)?.into(),
                                "printf '\\000\\003dns' >&0",
                            ),
                        };
                        // The socket was connected by this executable. A forked
                        // child inherits it, execs a different binary, and writes
                        // without a new connect or a destination-bearing send.
                        let status = Command::new("/bin/sh")
                            .args(["-c", script])
                            .stdin(Stdio::from(socket))
                            .status()?;
                        if !status.success() {
                            return Err(io::Error::other("DNS-writing child failed"));
                        }
                        Ok(())
                    })
                    .unwrap()
            });
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let query = runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(5), broker.accept_dns())
                    .await
                    .unwrap()
                    .unwrap()
            });
            assert_eq!(query.transport, transport);
            assert!(matches!(
                query.identity,
                Err(ResolveError::Failed(ref message)) if message.contains("unavailable")
            ));
            query.complete(Ok(Vec::new())).unwrap();
            child.join().unwrap().unwrap();
        }
    }

    #[test]
    fn protected_control_port_rejects_loopback_aliases_and_pod_addresses() {
        for address in [
            "127.0.0.1:7443",
            "127.0.0.2:7443",
            "[::1]:7443",
            "[::ffff:127.0.0.1]:7443",
            "10.42.0.8:7443",
        ] {
            assert_eq!(
                reject_protected_control_destination(address.parse().unwrap(), Some(7443))
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EACCES)
            );
        }
        assert!(
            reject_protected_control_destination("127.0.0.1:8080".parse().unwrap(), Some(7443))
                .is_ok()
        );
    }

    #[test]
    fn workload_cannot_fill_control_listener_with_loopback_connections() {
        let control = TcpListener::bind("127.0.0.1:0").unwrap();
        control.set_nonblocking(true).unwrap();
        let address = control.local_addr().unwrap();
        let (launcher, listener) =
            openshell_isolation_interface::linux::workload_launcher::start().unwrap();
        let _broker = NetworkBroker::start_with_dns_address(
            listener,
            "127.0.0.1:0".parse().unwrap(),
            Some(address.port()),
        )
        .unwrap();
        launcher
            .execute(move || -> io::Result<()> {
                for _ in 0..160 {
                    let error =
                        TcpStream::connect(address).expect_err("control port must be unreachable");
                    assert_eq!(error.raw_os_error(), Some(libc::EACCES));
                }
                Ok(())
            })
            .unwrap()
            .unwrap();
        assert_eq!(
            control.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

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
    fn native_accept_inherits_loopback_confinement() {
        let (launcher, listener) = openshell_isolation_interface::linux::workload_launcher::start()
            .expect("start workload launcher");
        let _broker = NetworkBroker::start_for_test(listener).expect("start network broker");
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let workload = std::thread::spawn(move || {
            launcher
                .execute(
                    move || -> io::Result<(SocketAddr, SocketAddr, Option<Vec<u8>>)> {
                        let listener = TcpListener::bind("127.0.0.1:0")?;
                        ready_tx
                            .send(listener.local_addr()?)
                            .map_err(|_| io::Error::other("test client disappeared"))?;
                        // std passes a peer-address buffer; native accept
                        // fills it directly from the kernel.
                        let (stream, accepted_peer) = listener.accept()?;
                        let peer = stream.peer_addr()?;
                        let device = socket_confinement::bound_device(&stream)?;
                        // sendmsg with no destination is notified and must
                        // continue for an untracked accepted stream.
                        let payload = b"accepted";
                        let sent = rustix::net::sendmsg(
                            &stream,
                            &[io::IoSlice::new(payload)],
                            &mut rustix::net::SendAncillaryBuffer::default(),
                            rustix::net::SendFlags::empty(),
                        )?;
                        if sent != payload.len() {
                            return Err(io::Error::from_raw_os_error(libc::EIO));
                        }
                        Ok((accepted_peer, peer, device))
                    },
                )
                .expect("launcher result")
        });

        let Ok(address) = ready_rx.recv() else {
            let error = workload
                .join()
                .expect("join workload")
                .expect_err("listener not ready");
            panic!("workload listener failed: {error}");
        };
        let mut client = TcpStream::connect(address).expect("connect loopback client");
        let mut payload = [0_u8; 8];
        client
            .read_exact(&mut payload)
            .expect("read accepted stream");
        assert_eq!(&payload, b"accepted");
        let (accepted_peer, peer, device) = workload
            .join()
            .expect("join workload")
            .expect("accepted workload");
        let client_address = client.local_addr().unwrap();
        assert_eq!(accepted_peer, client_address);
        assert_eq!(peer, client_address);
        assert_eq!(device.as_deref(), Some(&b"lo"[..]));
    }

    /// Bound device name and the errno from an attempted rebind.
    type ConfinementObservation = (Option<Vec<u8>>, Option<i32>);

    #[test]
    fn direct_syscall_accept_and_getpeername_report_native_peer() {
        // Static binaries and Go issue raw syscalls without a libc wrapper.
        let (launcher, listener) = openshell_isolation_interface::linux::workload_launcher::start()
            .expect("start workload launcher");
        let _broker = NetworkBroker::start_for_test(listener).expect("start network broker");
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let workload = std::thread::spawn(move || {
            launcher
                .execute(move || -> io::Result<(SocketAddr, SocketAddr)> {
                    let listener = TcpListener::bind("127.0.0.1:0")?;
                    ready_tx
                        .send(listener.local_addr()?)
                        .map_err(|_| io::Error::other("test client disappeared"))?;
                    // rustix issues accept4 and getpeername as raw syscalls.
                    let (accepted, accepted_peer) =
                        rustix::net::acceptfrom_with(&listener, rustix::net::SocketFlags::CLOEXEC)?;
                    let as_socket_addr = |address: Option<rustix::net::SocketAddrAny>| {
                        address
                            .and_then(|address| SocketAddr::try_from(address).ok())
                            .ok_or_else(|| io::Error::from_raw_os_error(libc::EAFNOSUPPORT))
                    };
                    let accepted_peer = as_socket_addr(accepted_peer)?;
                    let peer = as_socket_addr(rustix::net::getpeername(&accepted)?)?;
                    Ok((accepted_peer, peer))
                })
                .expect("launcher result")
        });
        let address = ready_rx.recv().expect("workload listener ready");
        let client = TcpStream::connect(address).expect("connect loopback client");
        let (accepted_peer, peer) = workload
            .join()
            .expect("join workload")
            .expect("direct-syscall accept");
        assert_eq!(accepted_peer, client.local_addr().unwrap());
        assert_eq!(peer, accepted_peer);
    }

    #[test]
    #[ignore = "requires OPENSHELL_STATIC_SERVER pointing at a static test server"]
    fn static_server_accepts_under_workload_filter() {
        // The server listens on argv[1], prints "ready", accepts one
        // connection, and writes the peer address it observed.
        use std::io::BufRead as _;
        let server = std::env::var("OPENSHELL_STATIC_SERVER").expect("OPENSHELL_STATIC_SERVER");
        let address = {
            let probe = TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap()
        };
        let (launcher, listener) = openshell_isolation_interface::linux::workload_launcher::start()
            .expect("start workload launcher");
        let _broker = NetworkBroker::start_for_test(listener).expect("start network broker");
        let connections: usize = std::env::var("OPENSHELL_STATIC_SERVER_CONNECTIONS")
            .map_or(1, |value| value.parse().expect("connection count"));
        let mut child = launcher
            .execute(move || {
                std::process::Command::new(server)
                    .arg(address.to_string())
                    .arg(connections.to_string())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
            })
            .unwrap()
            .expect("spawn static server under the workload filter");
        let mut stdout = io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "ready", "server did not start");
        // Earlier connections measure accept latency through the workload
        // filter; the last one also verifies the observed peer below.
        let mut latencies = Vec::with_capacity(connections);
        let started = Instant::now();
        for _ in 1..connections {
            let begin = Instant::now();
            let mut client = TcpStream::connect(address).expect("connect to static server");
            let mut reply = String::new();
            client.read_to_string(&mut reply).unwrap();
            latencies.push(begin.elapsed());
        }
        let begin = Instant::now();
        let mut client = TcpStream::connect(address).expect("connect to static server");
        let mut reply = String::new();
        client.read_to_string(&mut reply).unwrap();
        latencies.push(begin.elapsed());
        let total = started.elapsed();
        latencies.sort_unstable();
        let percentile = |p: usize| latencies[(latencies.len() - 1) * p / 100];
        eprintln!(
            "static server: {connections} connections in {total:?}; p50 {:?} p99 {:?} max {:?}",
            percentile(50),
            percentile(99),
            latencies[latencies.len() - 1]
        );
        let status = child.wait().unwrap();
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert!(status.success(), "static server failed: {stderr}");
        assert_eq!(
            reply.trim(),
            client.local_addr().unwrap().to_string(),
            "server observed the wrong peer"
        );
    }

    #[test]
    fn workload_sockets_are_bound_to_loopback_and_cannot_be_rebound() {
        let (launcher, listener) = openshell_isolation_interface::linux::workload_launcher::start()
            .expect("start workload launcher");
        let _broker = NetworkBroker::start_for_test(listener).expect("start network broker");
        let results = launcher
            .execute(|| -> io::Result<Vec<ConfinementObservation>> {
                let mut results = Vec::new();
                for (domain, kind) in [
                    (socket2::Domain::IPV4, socket2::Type::STREAM),
                    (socket2::Domain::IPV4, socket2::Type::DGRAM),
                    (socket2::Domain::IPV6, socket2::Type::STREAM),
                ] {
                    let socket = socket2::Socket::new(domain, kind, None)?;
                    let device = socket_confinement::bound_device(&socket)?;
                    let rebind_error = socket
                        .bind_device(Some(b"eth0"))
                        .err()
                        .and_then(|error| error.raw_os_error());
                    results.push((device, rebind_error));
                }
                Ok(results)
            })
            .expect("launcher result")
            .expect("workload sockets");
        for (device, rebind_error) in results {
            assert_eq!(device.as_deref(), Some(&b"lo"[..]));
            assert_eq!(rebind_error, Some(libc::EPERM));
        }
    }

    #[test]
    fn fast_open_sends_are_denied_for_every_descriptor() {
        let local = TcpListener::bind("127.0.0.1:0").unwrap();
        local.set_nonblocking(true).unwrap();
        let address = local.local_addr().unwrap();
        let (launcher, listener) = openshell_isolation_interface::linux::workload_launcher::start()
            .expect("start workload launcher");
        let _broker = NetworkBroker::start_for_test(listener).expect("start network broker");
        let error = launcher
            .execute(move || -> io::Result<()> {
                let socket =
                    socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
                socket
                    .send_to_with_flags(b"x", &address.into(), libc::MSG_FASTOPEN)
                    .map(drop)
            })
            .unwrap()
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EPERM));
        assert_eq!(
            local.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn send_flags_read_the_scalar_argument_for_each_syscall() {
        let flags = u64::try_from(libc::MSG_FASTOPEN).unwrap();
        assert_eq!(
            send_flags(libc::SYS_sendto, [0, 0, 0, flags, 0, 0]),
            libc::MSG_FASTOPEN
        );
        assert_eq!(
            send_flags(libc::SYS_sendmsg, [0, 0, flags, 0, 0, 0]),
            libc::MSG_FASTOPEN
        );
        assert_eq!(
            send_flags(libc::SYS_sendmmsg, [0, 0, 0, flags | (1 << 32), 0, 0]),
            libc::MSG_FASTOPEN
        );
    }

    #[test]
    fn broker_refuses_socket_families_it_cannot_confine() {
        // Independent of the static workload filter: the broker continues
        // only Unix and netlink sockets and creates INET sockets itself.
        let (launcher, listener) = openshell_isolation_interface::linux::workload_launcher::start()
            .expect("start workload launcher");
        let _broker = NetworkBroker::start_for_test(listener).expect("start network broker");
        let results = launcher
            .execute(|| {
                [
                    (libc::AF_UNIX, socket2::Type::STREAM),
                    (libc::AF_RXRPC, socket2::Type::DGRAM),
                    (libc::AF_ALG, socket2::Type::SEQPACKET),
                ]
                .map(|(domain, kind)| {
                    socket2::Socket::new(socket2::Domain::from(domain), kind, None)
                        .map(drop)
                        .map_err(|error| error.raw_os_error())
                })
            })
            .expect("launcher result");
        assert_eq!(
            results,
            [
                Ok(()),
                Err(Some(libc::EAFNOSUPPORT)),
                Err(Some(libc::EAFNOSUPPORT))
            ]
        );
    }

    #[test]
    fn repeated_connects_report_what_the_kernel_would() {
        let relay: SocketAddr = "127.0.0.53:53".parse().unwrap();
        let peer: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let other: SocketAddr = "127.0.0.1:9090".parse().unwrap();
        for (state, kind, destination, expected) in [
            (SocketState::Created, InetKind::Tcp, peer, None),
            (
                SocketState::Bound { local: peer },
                InetKind::Tcp,
                peer,
                None,
            ),
            (
                SocketState::Local { peer },
                InetKind::Tcp,
                peer,
                Some(libc::EISCONN),
            ),
            (
                SocketState::Connected {
                    original_peer: "203.0.113.7:443".parse().unwrap(),
                },
                InetKind::Tcp,
                peer,
                Some(libc::EISCONN),
            ),
            (
                SocketState::DnsTcp { relay },
                InetKind::Tcp,
                relay,
                Some(libc::EISCONN),
            ),
            (
                SocketState::DnsUdp { relay },
                InetKind::DnsUdp,
                relay,
                Some(0),
            ),
            (SocketState::DnsUdp { relay }, InetKind::DnsUdp, other, None),
            (SocketState::Local { peer }, InetKind::DnsUdp, peer, Some(0)),
            (
                SocketState::Failed {
                    errno: libc::ECONNRESET,
                },
                InetKind::Tcp,
                peer,
                Some(libc::ECONNRESET),
            ),
        ] {
            assert_eq!(
                repeated_connect_outcome(&state, kind, destination),
                expected,
                "{state:?} {kind:?} {destination}"
            );
        }
    }

    #[test]
    fn restarted_bind_and_connect_are_answered_consistently() {
        // Without killable notification waits a signal can restart a
        // syscall the broker already completed. A repeat must not fail on
        // the broker's released pre-connect descriptor.
        let service = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = service.local_addr().unwrap();
        let (launcher, listener) = openshell_isolation_interface::linux::workload_launcher::start()
            .expect("start workload launcher");
        let _broker = NetworkBroker::start_for_test(listener).expect("start network broker");
        let (bind_again, connect_again) = launcher
            .execute(move || -> io::Result<(io::Result<()>, Option<i32>)> {
                let socket =
                    socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
                let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
                socket.bind(&local.into())?;
                let bind_again = socket.bind(&local.into());
                socket.connect(&address.into())?;
                let connect_again = socket
                    .connect(&address.into())
                    .err()
                    .and_then(|error| error.raw_os_error());
                Ok((bind_again, connect_again))
            })
            .expect("launcher result")
            .expect("workload socket");
        bind_again.expect("repeated bind of the same address");
        assert_eq!(connect_again, Some(libc::EISCONN));
    }

    #[test]
    fn workload_cannot_bind_a_non_loopback_source_address() {
        // Workload sockets can only present loopback source addresses. A
        // non-loopback peer on a loopback-bound workload listener is therefore
        // a non-workload process in the same network namespace.
        let (launcher, listener) = openshell_isolation_interface::linux::workload_launcher::start()
            .expect("start workload launcher");
        let _broker = NetworkBroker::start_for_test(listener).expect("start network broker");
        let errors = launcher
            .execute(|| {
                ["192.0.2.10:0", "[2001:db8::10]:0"].map(|address| {
                    UdpSocket::bind(address)
                        .err()
                        .and_then(|error| error.raw_os_error())
                })
            })
            .expect("launcher result");
        assert_eq!(errors, [Some(libc::EACCES), Some(libc::EACCES)]);
    }

    #[test]
    fn interface_selection_options_are_denied() {
        for (level, option) in [
            (libc::SOL_SOCKET, libc::SO_BINDTODEVICE),
            (libc::SOL_SOCKET, libc::SO_BINDTOIFINDEX),
            (libc::IPPROTO_IP, libc::IP_UNICAST_IF),
            (libc::IPPROTO_IP, libc::IP_MULTICAST_IF),
            (libc::IPPROTO_IPV6, libc::IPV6_UNICAST_IF),
            (libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_IF),
            (libc::IPPROTO_IPV6, libc::IPV6_ADDRFORM),
            (libc::IPPROTO_TCP, libc::TCP_FASTOPEN_CONNECT),
        ] {
            assert!(socket_option_is_denied(level, option), "{level}/{option}");
        }
        assert!(!socket_option_is_denied(
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR
        ));
        assert!(!socket_option_is_denied(
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY
        ));
        assert!(!socket_option_is_denied(
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY
        ));
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
            .block_on(pending.complete(TcpOpenDecision::RelayReady))
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
                .block_on(pending.complete(TcpOpenDecision::Denied(TcpOpenDenial::PolicyDenied)),)
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
    fn udp_dns_allows_repeated_destination_sends_to_the_pinned_relay() {
        let (launcher, listener) = openshell_isolation_interface::linux::workload_launcher::start()
            .expect("start workload launcher");
        let broker = NetworkBroker::start_for_test(listener).expect("start network broker");
        let dns_address = broker.dns_address();
        let client = std::thread::spawn(move || {
            launcher
                .execute(move || -> io::Result<Vec<Vec<u8>>> {
                    // Static musl clients send A and AAAA with two sendto(2)
                    // calls on the same initially-unconnected socket.
                    let socket = UdpSocket::bind("0.0.0.0:0")?;
                    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                    socket.send_to(b"dns-query-a", dns_address)?;
                    socket.send_to(b"dns-query-aaaa", dns_address)?;
                    let mut responses = Vec::new();
                    for _ in 0..2 {
                        let mut response = [0_u8; 32];
                        let (length, source) = socket.recv_from(&mut response)?;
                        if source != dns_address {
                            return Err(io::Error::other("wrong DNS response source"));
                        }
                        responses.push(response[..length].to_vec());
                    }
                    responses.sort();
                    Ok(responses)
                })
                .expect("launcher result")
        });

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        for _ in 0..2 {
            let query = runtime.block_on(broker.accept_dns()).expect("DNS query");
            let response = if query.request == b"dns-query-a" {
                b"dns-response-a".to_vec()
            } else if query.request == b"dns-query-aaaa" {
                b"dns-response-aaaa".to_vec()
            } else {
                panic!("unexpected DNS query: {:?}", query.request);
            };
            query.complete(Ok(response)).unwrap();
        }
        assert_eq!(
            client.join().expect("join client").expect("DNS client"),
            vec![b"dns-response-a".to_vec(), b"dns-response-aaaa".to_vec()]
        );
    }

    #[test]
    fn udp_port_zero_route_probes_are_local_and_reusable() {
        let (launcher, listener) = openshell_isolation_interface::linux::workload_launcher::start()
            .expect("start workload launcher");
        let _broker = NetworkBroker::start_for_test(listener).expect("start network broker");
        launcher
            .execute(|| -> io::Result<()> {
                // Address-selection probes create an unbound datagram socket;
                // binding to INADDR_ANY first would intentionally preserve an
                // unspecified local address and would not model that path.
                // SAFETY: the return value is checked before ownership moves
                // into UdpSocket.
                let raw_socket = unsafe {
                    libc::socket(
                        libc::AF_INET,
                        libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                        libc::IPPROTO_UDP,
                    )
                };
                if raw_socket < 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: raw_socket is a new, owned socket descriptor.
                let socket = unsafe { UdpSocket::from_raw_fd(raw_socket) };
                socket.connect("198.51.100.7:0")?;
                let local = socket.local_addr()?;
                if !local.ip().is_loopback() || local.port() == 0 {
                    return Err(io::Error::other(format!(
                        "route probe did not expose a local source: {local}"
                    )));
                }

                let unspecified = libc::sockaddr {
                    sa_family: libc::sa_family_t::try_from(libc::AF_UNSPEC)
                        .expect("AF_UNSPEC fits sa_family_t"),
                    sa_data: [0; 14],
                };
                // SAFETY: unspecified is a live native sockaddr used for the
                // conventional UDP disconnect operation.
                let disconnected = unsafe {
                    libc::connect(
                        socket.as_raw_fd(),
                        (&raw const unspecified).cast(),
                        libc::socklen_t::try_from(size_of::<libc::sockaddr>())
                            .expect("sockaddr size fits socklen_t"),
                    )
                };
                if disconnected != 0 {
                    return Err(io::Error::last_os_error());
                }
                socket.connect("203.0.113.9:0")?;

                // The route probe never commits an external UDP peer. A
                // destination-free send must therefore remain kernel-denied.
                // SAFETY: payload is live for the duration of this syscall.
                let sent = unsafe {
                    libc::send(
                        socket.as_raw_fd(),
                        b"blocked".as_ptr().cast(),
                        b"blocked".len(),
                        0,
                    )
                };
                if sent >= 0 {
                    return Err(io::Error::other("route probe became a data path"));
                }
                let error = io::Error::last_os_error();
                if !matches!(
                    error.raw_os_error(),
                    Some(libc::EDESTADDRREQ | libc::ENOTCONN)
                ) {
                    return Err(error);
                }
                Ok(())
            })
            .expect("launcher result")
            .expect("route-probe workload");
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
