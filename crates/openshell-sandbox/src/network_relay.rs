// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The transparent network relay for privileged (root-workload) sandboxes
//! (commit 5).
//!
//! In sandboxed mode the seccomp broker intercepts `connect(2)` and the
//! supervisor decides each open over the Mediate control stream. A root
//! workload defeats in-guest interception by design, so the privileged
//! boundary instead installs an nftables DNAT ruleset that transparently
//! captures outbound workload traffic inside the guest:
//!
//! - Outbound TCP (any destination except loopback and the boundary's own
//!   supervisor control endpoints) is redirected to a local relay listener.
//!   The relay recovers the ORIGINAL destination from conntrack
//!   (`SO_ORIGINAL_DST`) — for policy-DNS answers that is the synthetic
//!   address the supervisor maps back to the hostname — and feeds the
//!   connection into the SAME Mediate accept/decision/bridge flow the
//!   seccomp broker uses. The supervisor's proxy enforces policy and
//!   carries the bytes.
//! - DNS: the loopback relay at 127.0.0.53 answers via the Mediate DNS
//!   stream (policy DNS returns synthetic addresses). Non-loopback UDP/53
//!   is redirected there too, closing the masquerade dnsmasq bypass.
//! - All other UDP is dropped (IPv4 and IPv6): QUIC and arbitrary UDP
//!   datagrams are never relayed — defence in depth matching the fence.
//! - IPv6 TCP is redirected the same way (synthetic AAAA answers).
//!
//! Fail-closed: a root workload that deletes the ruleset restores direct
//! egress through the guest's eth0, which the launcher-side network fence
//! blocks — deleting the rules only breaks its own connectivity.
//! QUIC/UDP (other than DNS) is never relayed and is blocked by the fence.

use std::fmt::Write as _;
use std::mem::size_of_val;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd as _;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use tokio::net::TcpListener;

use crate::network_broker::{NetworkBroker, PendingTcpOpen};

use openshell_isolation_interface::contract::{
    BinaryIdentity, NetworkSocketMetadata, ResolveError, TcpOpenDecision,
};

/// The port of the transparent TCP relay listener (loopback only).
pub(crate) const TRANSPARENT_RELAY_PORT: u16 = 15500;

/// The relay ruleset's nftables table name.
const NFT_TABLE: &str = "openshell_relay";

/// Install the transparent-relay nftables ruleset (idempotent: any previous
/// instance of the table is destroyed first). The boundary's own control
/// endpoints are excluded so the relay never captures its own supervisor
/// connections.
pub(crate) fn install_relay_rules(
    control_endpoints: &[SocketAddr],
    relay_port: u16,
) -> std::io::Result<()> {
    // One accept rule per supervisor control endpoint (the boundary dials
    // them; the relay must not eat its own control stream).
    let mut v4_accepts = String::new();
    let mut v6_accepts = String::new();
    for endpoint in control_endpoints {
        match endpoint.ip() {
            IpAddr::V4(addr) => {
                let _ = writeln!(
                    v4_accepts,
                    "        ip daddr {addr} tcp dport {} accept",
                    endpoint.port()
                );
            }
            IpAddr::V6(addr) => {
                let _ = writeln!(
                    v6_accepts,
                    "        ip6 daddr {addr} tcp dport {} accept",
                    endpoint.port()
                );
            }
        }
    }
    let ruleset = format!(
        r"destroy table ip {NFT_TABLE}
table ip {NFT_TABLE} {{
    chain output {{
        type nat hook output priority -100; policy accept;
{v4_accepts}        ip daddr 127.0.0.0/8 accept
        meta l4proto tcp dnat to 127.0.0.1:{relay_port}
        udp dport 53 ip daddr != 127.0.0.0/8 dnat to 127.0.0.53
        meta l4proto udp drop
    }}
}}
destroy table ip6 {NFT_TABLE}
table ip6 {NFT_TABLE} {{
    chain output {{
        type nat hook output priority -100; policy accept;
{v6_accepts}        ip6 daddr ::1/128 accept
        meta l4proto tcp dnat to [::1]:{relay_port}
        meta l4proto udp drop
    }}
}}
"
    );
    // The nftables kernel modules are modular in the Alpine -virt kernel:
    // load them before applying the ruleset (a missing module surfaces as
    // "Operation not supported" from nft). Each child is registered with
    // the managed-children registry: the orphan reaper reaps UNREGISTERED
    // children process-wide, racing the wait and failing it with ECHILD.
    for module in ["nf_tables", "nft_chain_nat", "nft_nat", "ipv6"] {
        let _ = spawn_registered(
            std::process::Command::new("/usr/sbin/modprobe")
                .arg(module)
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
        );
    }
    // Absolute path: PATH resolution from the static musl binary after the
    // verified-boot chroot has proven unreliable; nft is at a fixed
    // usr-merged location.
    let nft_path = "/usr/sbin/nft";
    if !std::path::Path::new(nft_path).exists() {
        return Err(std::io::Error::other(format!(
            "{nft_path} not found (PATH={:?})",
            std::env::var("PATH").unwrap_or_default()
        )));
    }
    // Hold the registry guard across spawn+register (see spawn_registered):
    // the orphan reaper takes the same guard while deciding whether to
    // reap, so it cannot run between the child existing and its
    // registration landing.
    let mut guard = crate::managed_children::lock();
    let child = std::process::Command::new(nft_path)
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map(|child| {
            let registered = guard.register(child.id());
            (child, registered)
        });
    drop(guard);
    let (mut child, registered) = child?;
    {
        use std::io::Write as _;
        let stdin = child
            .stdin
            .as_mut()
            .expect("piped stdin exists before wait");
        if let Err(error) = stdin.write_all(ruleset.as_bytes()) {
            // The ruleset write failed after registration: release the
            // PID so the reaper can reap the exiting child (otherwise it
            // stays registered forever and the wait below never runs).
            if let Some(managed) = registered {
                crate::managed_children::unregister(managed);
            }
            return Err(error);
        }
    }
    let output = child.wait_with_output();
    if let Some(managed) = registered {
        crate::managed_children::unregister(managed);
    }
    let output = output?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "nft -f failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

/// Spawn a subprocess and register it with the managed-children registry
/// before waiting: the boundary's orphan reaper reaps UNREGISTERED children
/// process-wide (it answers the same SIGCHLD), racing any direct wait and
/// failing it with ECHILD. The registry entry is released after the wait.
///
/// The registry guard (`managed_children::lock()`) is held from before
/// spawn until the PID is registered — the primitive documented for
/// exactly this window. The reaper holds the same guard while deciding
/// whether to reap, so it cannot run between the child existing and its
/// registration landing. (A SIGCHLD mask does NOT close this race: the
/// reaper is a separate thread woken by an eventfd from a process-wide
/// handler, and a process-directed SIGCHLD goes to any thread not
/// blocking it.)
fn spawn_registered(
    command: &mut std::process::Command,
) -> std::io::Result<std::process::ExitStatus> {
    // Hold the registry guard from before spawn until the PID is
    // registered — the primitive documented for exactly this window.
    let mut guard = crate::managed_children::lock();
    let spawn_result = command.spawn().map(|child| {
        let registered = guard.register(child.id());
        (child, registered)
    });
    drop(guard);
    let (mut child, registered) = spawn_result?;
    let result = child.wait();
    if let Some(managed) = registered {
        crate::managed_children::unregister(managed);
    }
    result
}

/// Recover the pre-DNAT destination of a transparently redirected
/// connection (the address the workload dialed, e.g. a policy-DNS
/// synthetic address).
/// connection (the address the workload dialed, e.g. a policy-DNS
/// synthetic address). Duplicates the fd so the tokio stream stays owned
/// by the caller.
#[allow(
    unsafe_code,
    reason = "dup(2) plus from_raw_fd is the standard fd-ownership transfer; both sides are                scoped to this function"
)]
fn original_destination(stream: &tokio::net::TcpStream) -> std::io::Result<SocketAddr> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    // SAFETY: dup(2) on a live fd duplicates the descriptor; ownership of
    // the copy is taken over by the std stream below.
    let duplicated = unsafe { libc::dup(stream.as_raw_fd()) };
    if duplicated < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the fd is a live, connected TCP socket owned by this scope.
    let std_stream = unsafe { std::net::TcpStream::from_raw_fd(duplicated) };
    let result = original_destination_of(&std_stream);
    drop(std_stream);
    result
}

fn original_destination_of(std_stream: &std::net::TcpStream) -> std::io::Result<SocketAddr> {
    use nix::sys::socket::{getsockopt, sockopt};
    if std_stream.local_addr()?.is_ipv4() {
        let address = getsockopt(std_stream, sockopt::OriginalDst)?;
        Ok(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::from(
                address.sin_addr.s_addr.to_ne_bytes(),
            )),
            u16::from_be(address.sin_port),
        ))
    } else {
        let address = getsockopt(std_stream, sockopt::Ip6tOriginalDst)?;
        Ok(SocketAddr::new(
            IpAddr::V6(std::net::Ipv6Addr::from(address.sin6_addr.s6_addr)),
            u16::from_be(address.sin6_port),
        ))
    }
}

/// The relay's own binary identity: the boundary executable. Root-mode
/// policy does not require per-binary identity (the workload owns the
/// guest by design); the identity is carried for auditability and TOFU
/// pinning like any other mediated open.
fn relay_identity() -> Result<BinaryIdentity, ResolveError> {
    // The boundary's own executable identity: root-mode policy does not
    // require per-binary identity (the workload owns the guest by design),
    // but the identity is carried for auditability and TOFU pinning like
    // any other mediated open.
    openshell_binary_identity::ProcfsIdentityResolver::for_pid_namespace()
        .resolve(std::process::id())
}

/// Serve one redirected connection: recover the original destination,
/// register it as a pending open for the supervisor's decision, and on an
/// allow hand the accepted stream to the Mediate bridge.
async fn serve_relayed_connection(
    stream: tokio::net::TcpStream,
    pending: tokio::sync::mpsc::Sender<PendingTcpOpen>,
    active_opens: Arc<AtomicUsize>,
    connected_at: Instant,
) {
    let destination = match original_destination(&stream) {
        Ok(destination) => destination,
        Err(error) => {
            tracing::warn!(%error, "transparent relay: no original destination; dropping");
            return;
        }
    };
    let identity = relay_identity();
    let (decision_tx, decision_rx) = std::sync::mpsc::sync_channel(1);
    let (relay_tx, relay_rx) = tokio::sync::oneshot::channel();
    // Mirror the broker's admission control: at most OPEN_QUEUE_CAPACITY
    // undecided opens.
    if active_opens
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < crate::network_broker::open_queue_capacity()).then_some(current + 1)
        })
        .is_err()
    {
        return;
    }
    let _slot = ActiveOpenSlot(active_opens);
    let queued_at = Instant::now();
    let open = PendingTcpOpen::for_relayed_connection(
        destination,
        identity,
        NetworkSocketMetadata {
            socket_cookie: 0,
            nonblocking: false,
            process_generation: 0,
        },
        connected_at.elapsed(),
        queued_at,
        decision_tx,
        relay_rx,
    );
    if pending.try_send(open).is_err() {
        return;
    }
    // The supervisor's decision arrives on the sync channel. Allowed: hand
    // the workload connection to the Mediate bridge. Denied (or channel
    // closed): close the connection — the workload sees a refused
    // connection, same as the sandboxed denial.
    //
    // The wait runs on the blocking pool: a plain recv() would park a
    // runtime worker, and the guest VM has as few workers as cores (one),
    // so a parked worker would freeze the whole boundary (the cluster
    // failure: the supervisor's control stream stopped responding).
    let decision = tokio::task::spawn_blocking(move || decision_rx.recv())
        .await
        .unwrap_or(Err(std::sync::mpsc::RecvError));
    if decision == Ok(TcpOpenDecision::RelayReady) {
        if let Ok(stream) = stream.into_std() {
            let _ = relay_tx.send(Ok(stream));
        }
    } else {
        // Denied: close with an immediate RST (SO_LINGER 0) so the client
        // fails fast on the first read/write instead of waiting out its
        // timeout. The workload completed the TCP handshake with the local
        // relay; the sandboxed denial completes the intercepted connect
        // with a refusal, and the RST is the relay-mode equivalent.
        reset_stream(&stream);
        drop(stream);
    }
}

/// Close a TCP stream with an immediate `RST`: set `SO_LINGER` with a zero
/// timeout, then close. The close converts to an `RST` instead of a `FIN`,
/// so a denied client fails fast on the first read/write.
#[allow(
    unsafe_code,
    reason = "setsockopt with a plain repr(C) linger struct; the pointer and size are scoped here"
)]
fn reset_stream(stream: &tokio::net::TcpStream) {
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: `libc::linger` is a plain repr(C) struct of two scalars;
    // `setsockopt` reads exactly its size from the pointer.
    let _ = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            std::ptr::addr_of!(linger).cast(),
            u32::try_from(size_of_val(&linger)).unwrap_or(u32::MAX),
        )
    };
    // The caller drops the stream after this returns; the linger option
    // converts that close into an RST.
}

struct ActiveOpenSlot(Arc<AtomicUsize>);

impl Drop for ActiveOpenSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Start the transparent TCP relay: listeners on the loopback (v4 and v6)
/// relay port feeding redirected connections into the broker's pending
/// queue.
pub(crate) fn start_tcp_relay(
    pending: tokio::sync::mpsc::Sender<PendingTcpOpen>,
    active_opens: Arc<AtomicUsize>,
    runtime: &tokio::runtime::Handle,
) -> std::io::Result<()> {
    // from_std needs the runtime reactor in context; enter the caller's
    // handle for the conversions below.
    let _guard = runtime.enter();
    let v4 = std::net::TcpListener::bind(("127.0.0.1", TRANSPARENT_RELAY_PORT))?;
    v4.set_nonblocking(true)?;
    let v4 = TcpListener::from_std(v4)?;
    // The IPv6 loopback listener is best effort: the Alpine -virt kernel
    // carries IPv6 as a module, and without it there is no IPv6 traffic to
    // capture (fail-closed by absence — the fence still blocks any v6
    // egress if the stack appears later).
    let v6 = std::net::TcpListener::bind(("::1", TRANSPARENT_RELAY_PORT))
        .and_then(|v6| {
            v6.set_nonblocking(true)?;
            TcpListener::from_std(v6)
        })
        .ok();
    let mut listeners = vec![v4];
    if let Some(v6) = v6 {
        listeners.push(v6);
    } else {
        tracing::warn!(
            "transparent relay: no IPv6 loopback (module unavailable); \
             IPv6 TCP is not relayed"
        );
    }
    for listener in listeners {
        let pending = pending.clone();
        let active_opens = active_opens.clone();
        runtime.spawn(async move {
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    break;
                };
                openshell_core::net::set_tcp_nodelay_best_effort(&stream);
                let connected_at = Instant::now();
                let pending = pending.clone();
                let active_opens = active_opens.clone();
                tokio::spawn(async move {
                    serve_relayed_connection(stream, pending, active_opens, connected_at).await;
                });
            }
        });
    }
    Ok(())
}

/// Construct the transparent relay broker for a privileged boundary.
///
/// The loopback DNS relay, the transparent TCP relay, and the nftables
/// capture ruleset. The pending queues feed the SAME Mediate
/// accept/decision/bridge flow the sandboxed seccomp broker uses.
pub fn start_transparent_relay(
    control_endpoints: &[SocketAddr],
    runtime: &tokio::runtime::Handle,
) -> std::io::Result<NetworkBroker> {
    NetworkBroker::start_transparent_relay(control_endpoints, runtime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_ruleset_installs_and_captures() {
        // Requires root + the nftables kernel modules + the nft binary:
        // run under `docker run --privileged` (the CI/e2e path).
        if !nix::unistd::geteuid().is_root() || !std::path::Path::new("/usr/sbin/nft").exists() {
            eprintln!("skipping: needs root + nft (run in the privileged container)");
            return;
        }
        install_relay_rules(&["10.43.0.1:5500".parse().unwrap()], TRANSPARENT_RELAY_PORT)
            .expect("install the relay ruleset");
        let listing = std::process::Command::new("nft")
            .args(["list", "table", "ip", NFT_TABLE])
            .output()
            .expect("list the ruleset");
        let text = String::from_utf8_lossy(&listing.stdout);
        assert!(text.contains("dnat to 127.0.0.1:15500"), "{text}");
        assert!(
            text.contains("meta l4proto udp drop"),
            "non-DNS UDP must be dropped (defence in depth): {text}"
        );
        assert!(
            text.contains("ip daddr 10.43.0.1 tcp dport 5500 accept"),
            "{text}"
        );
        let listing = std::process::Command::new("nft")
            .args(["list", "table", "ip6", NFT_TABLE])
            .output()
            .expect("list the v6 ruleset");
        let text = String::from_utf8_lossy(&listing.stdout);
        assert!(text.contains("dnat to [::1]:15500"), "{text}");
        // Idempotent re-install.
        install_relay_rules(&["10.43.0.1:5500".parse().unwrap()], TRANSPARENT_RELAY_PORT)
            .expect("re-install the relay ruleset");
    }
}
