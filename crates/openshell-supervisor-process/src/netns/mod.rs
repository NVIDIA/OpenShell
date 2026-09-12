// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Network namespace isolation for sandboxed processes.
//!
//! Creates an isolated network namespace with a veth pair connecting
//! the sandbox to the host. This ensures the sandboxed process can only
//! communicate through the proxy running on the host side of the veth.

mod netlink;
mod nft_ruleset;

use miette::{IntoDiagnostic, Result};
use std::net::IpAddr;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::process::Command;
use tracing::{debug, warn};
use uuid::Uuid;

/// Default subnet for sandbox networking.
const SUBNET_PREFIX: &str = "10.200.0";
const HOST_IP_SUFFIX: u8 = 1;
const SANDBOX_IP_SUFFIX: u8 = 2;
/// Unprivileged port owned by the supervisor's policy DNS service. Workload
/// queries still target the standard DNS port and nftables redirects them to
/// this listener before the bypass fence runs.
pub const POLICY_DNS_PORT: u16 = 15_053;
pub const TRANSPARENT_TCP_PORT: u16 = 15_001;
const NSENTER_SEARCH_PATHS: &[&str] = &[
    "/usr/bin/nsenter",
    "/bin/nsenter",
    "/usr/sbin/nsenter",
    "/sbin/nsenter",
];

/// Handle to a network namespace with veth pair.
///
/// The namespace and veth interfaces are automatically cleaned up on drop.
#[derive(Debug)]
pub struct NetworkNamespace {
    /// Namespace name (e.g., "sandbox-{uuid}")
    name: String,
    /// Host-side veth interface name
    veth_host: String,
    /// Sandbox-side veth interface name (inside namespace, used only during setup)
    _veth_sandbox: String,
    /// Host-side IP address (proxy binds here)
    host_ip: IpAddr,
    /// Sandbox-side IP address
    sandbox_ip: IpAddr,
    /// File descriptor for the namespace (for setns)
    ns_fd: Option<RawFd>,
}

impl NetworkNamespace {
    /// Create a new isolated network namespace with veth pair.
    ///
    /// Sets up:
    /// - A new network namespace named `sandbox-{uuid}`
    /// - A veth pair connecting host and sandbox
    /// - IP addresses on both ends (10.200.0.1/24 and 10.200.0.2/24)
    /// - Default route in sandbox pointing to host
    ///
    /// # Errors
    ///
    /// Returns an error if namespace creation or network setup fails.
    pub fn create() -> Result<Self> {
        let id = Uuid::new_v4();
        let short_id = &id.to_string()[..8];
        let name = format!("sandbox-{short_id}");
        let veth_host = format!("veth-h-{short_id}");
        let veth_sandbox = format!("veth-s-{short_id}");

        let host_ip: IpAddr = format!("{SUBNET_PREFIX}.{HOST_IP_SUFFIX}").parse().unwrap();
        let sandbox_ip: IpAddr = format!("{SUBNET_PREFIX}.{SANDBOX_IP_SUFFIX}")
            .parse()
            .unwrap();

        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(openshell_ocsf::SeverityId::Informational)
                .status(openshell_ocsf::StatusId::Success)
                .state(openshell_ocsf::StateId::Enabled, "creating")
                .message(format!(
                    "Creating network namespace [ns:{name} host_veth:{veth_host} sandbox_veth:{veth_sandbox}]"
                ))
                .build()
        );

        // Create the FD-owned namespace, bind-mounted at netns_path via
        // `mount(2)` (not `ip netns add`) so the nsenter-based nft path still
        // reaches it. Returns a persistent fd for the setns paths.
        let ns_fd = netlink::create_netns_fd(&name)?;

        // Host side: veth pair, move peer into the namespace, host addr + up.
        if let Err(e) = netlink::setup_host_side(&veth_host, &veth_sandbox, host_ip, 24, ns_fd) {
            let _ = netlink::destroy_netns(&name, ns_fd);
            return Err(e);
        }

        // Sandbox side: addr on veth-s, veth-s up, lo up, default route.
        if let Err(e) = netlink::setup_sandbox_side(ns_fd, &veth_sandbox, sandbox_ip, 24, host_ip) {
            let _ = netlink::delete_link(&veth_host);
            let _ = netlink::destroy_netns(&name, ns_fd);
            return Err(e);
        }

        let ns_fd = Some(ns_fd);

        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(openshell_ocsf::SeverityId::Informational)
                .status(openshell_ocsf::StatusId::Success)
                .state(openshell_ocsf::StateId::Enabled, "created")
                .message(format!(
                    "Network namespace created [ns:{name} host_ip:{host_ip} sandbox_ip:{sandbox_ip}]"
                ))
                .build()
        );

        Ok(Self {
            name,
            veth_host,
            _veth_sandbox: veth_sandbox,
            host_ip,
            sandbox_ip,
            ns_fd,
        })
    }

    /// Get the host-side IP address (proxy should bind to this).
    #[must_use]
    pub const fn host_ip(&self) -> IpAddr {
        self.host_ip
    }

    /// Get the sandbox-side IP address.
    #[must_use]
    pub const fn sandbox_ip(&self) -> IpAddr {
        self.sandbox_ip
    }

    /// Get the namespace name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Enter this network namespace.
    ///
    /// Must be called from the child process after fork, before exec.
    /// Uses `setns()` to switch the calling process into the namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if setns fails.
    ///
    /// # Safety
    ///
    /// This function should only be called in a `pre_exec` context after fork.
    pub fn enter(&self) -> Result<()> {
        if let Some(fd) = self.ns_fd {
            debug!(namespace = %self.name, "Entering network namespace via setns");
            // SAFETY: setns is safe to call after fork, before exec
            // libc/syscall FFI requires unsafe
            #[allow(unsafe_code)]
            let result = unsafe { libc::setns(fd, libc::CLONE_NEWNET) };
            if result != 0 {
                return Err(miette::miette!(
                    "setns failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(())
        } else {
            Err(miette::miette!(
                "No namespace file descriptor available for setns"
            ))
        }
    }

    /// Get the namespace file descriptor for use with clone/unshare.
    #[must_use]
    pub const fn ns_fd(&self) -> Option<RawFd> {
        self.ns_fd
    }

    /// Install nftables rules for bypass detection inside the namespace.
    ///
    /// Sets up OUTPUT chain rules that:
    /// 1. ACCEPT traffic destined for the proxy (`host_ip:proxy_port`)
    /// 2. ACCEPT loopback traffic
    /// 3. ACCEPT established/related connections (response packets)
    /// 4. LOG + REJECT all other TCP/UDP traffic (bypass attempts)
    ///
    /// This provides two benefits:
    /// - **Fast-fail UX**: applications get immediate ECONNREFUSED instead of
    ///   a 30-second timeout when they bypass the proxy
    /// - **Diagnostics**: nftables LOG entries are picked up by the bypass
    ///   monitor to emit structured tracing events
    ///
    /// Degrades gracefully if `nft` is not available — the namespace
    /// still provides isolation via routing, just without fast-fail and
    /// diagnostic logging.
    pub fn install_bypass_rules(&self, proxy_port: u16) -> Result<()> {
        let Some(nft_path) = find_nft() else {
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                    .severity(openshell_ocsf::SeverityId::Medium)
                    .status(openshell_ocsf::StatusId::Failure)
                    .state(openshell_ocsf::StateId::Disabled, "degraded")
                    .message(format!(
                        "nft not found; bypass detection rules will not be installed [ns:{}]",
                        self.name
                    ))
                    .build()
            );
            return Ok(());
        };

        let host_ip_str = self.host_ip.to_string();
        let log_prefix = format!("openshell:bypass:{}:", &self.name);

        // The kernel's nf_log_syslog module suppresses log output from
        // non-init network namespaces by default. Enable it so the bypass
        // monitor can see log entries from the sandbox namespace.
        enable_nf_log_all_netns();

        let commands =
            nft_ruleset::generate_bypass_commands(&host_ip_str, proxy_port, Some(&log_prefix));

        if let Err(e) = run_nft_commands_netns(&self.name, &nft_path, &commands) {
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                    .severity(openshell_ocsf::SeverityId::Medium)
                    .status(openshell_ocsf::StatusId::Failure)
                    .state(openshell_ocsf::StateId::Disabled, "failed")
                    .message(format!(
                        "Failed to install bypass detection rules [ns:{}]: {e}",
                        self.name
                    ))
                    .build()
            );
            return Err(e);
        }

        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(openshell_ocsf::SeverityId::Informational)
                .status(openshell_ocsf::StatusId::Success)
                .state(openshell_ocsf::StateId::Enabled, "installed")
                .message(format!(
                    "Bypass detection rules installed [ns:{}]",
                    self.name
                ))
                .build()
        );

        Ok(())
    }

    /// Replace the ordinary bypass fence with the policy-DNS and transparent
    /// TCP ruleset. This is fail-closed: callers must not release workload
    /// execution unless every required rule was installed.
    pub fn install_transparent_tcp_rules(
        &self,
        proxy_port: u16,
        synthetic_ipv4_cidr: &str,
        synthetic_ipv6_cidr: &str,
    ) -> Result<()> {
        self.validate_synthetic_pool_routes(synthetic_ipv4_cidr, synthetic_ipv6_cidr)?;
        // The inner namespace has an IPv4 default route, but not an IPv6
        // default route. Install only the active synthetic IPv6 epoch so the
        // kernel reaches the nft OUTPUT hook; REDIRECT then reroutes it to
        // the local transparent listener.
        let ns_fd = self
            .ns_fd
            .ok_or_else(|| miette::miette!("no namespace fd available for route setup"))?;
        let v6_cidr: ipnet::IpNet = synthetic_ipv6_cidr.parse().into_diagnostic()?;
        netlink::replace_route_dev_lo_in_netns(ns_fd, v6_cidr)?;
        let nft_path = find_nft().ok_or_else(|| {
            miette::miette!(
                "trusted nft helper not found; policy DNS and transparent TCP require nftables"
            )
        })?;
        let host_ip = self.host_ip.to_string();
        let log_prefix = format!("openshell:bypass:{}:", self.name);
        let commands = nft_ruleset::generate_transparent_tcp_commands(
            &host_ip,
            proxy_port,
            POLICY_DNS_PORT,
            TRANSPARENT_TCP_PORT,
            synthetic_ipv4_cidr,
            synthetic_ipv6_cidr,
            Some(&log_prefix),
        );
        run_nft_commands_netns(&self.name, &nft_path, &commands)?;
        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(openshell_ocsf::SeverityId::Informational)
                .status(openshell_ocsf::StatusId::Success)
                .state(openshell_ocsf::StateId::Enabled, "installed")
                .message(format!(
                    "Policy DNS and transparent TCP capture installed [ns:{}]",
                    self.name
                ))
                .build()
        );
        Ok(())
    }

    fn validate_synthetic_pool_routes(
        &self,
        synthetic_ipv4_cidr: &str,
        synthetic_ipv6_cidr: &str,
    ) -> Result<()> {
        let reserved = [
            synthetic_ipv4_cidr
                .parse::<ipnet::IpNet>()
                .into_diagnostic()?,
            synthetic_ipv6_cidr
                .parse::<ipnet::IpNet>()
                .into_diagnostic()?,
        ];
        let ns_fd = self
            .ns_fd
            .ok_or_else(|| miette::miette!("no namespace fd available for route validation"))?;
        for v6 in [false, true] {
            let routes = netlink::dump_route_prefixes_in_netns(ns_fd, v6)?;
            if let Some((route, pool)) = first_route_overlap(&routes, &reserved) {
                return Err(miette::miette!(
                    "synthetic address pool {pool} overlaps workload route {route}; refusing to enable policy DNS"
                ));
            }
        }
        Ok(())
    }

    /// Bind IPv4 and IPv6 transparent listeners inside the workload network
    /// namespace without moving an async runtime worker into that namespace.
    pub async fn bind_transparent_tcp_listeners(
        &self,
    ) -> std::io::Result<Vec<tokio::net::TcpListener>> {
        let ns_fd = self
            .ns_fd
            .ok_or_else(|| std::io::Error::other("no namespace fd available for bind"))?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let result = (|| -> std::io::Result<Vec<std::net::TcpListener>> {
                #[allow(unsafe_code)]
                if unsafe { libc::setns(ns_fd, libc::CLONE_NEWNET) } != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let mut listeners = Vec::with_capacity(2);
                for (domain, address) in [
                    (
                        socket2::Domain::IPV4,
                        format!("0.0.0.0:{TRANSPARENT_TCP_PORT}"),
                    ),
                    (
                        socket2::Domain::IPV6,
                        format!("[::]:{TRANSPARENT_TCP_PORT}"),
                    ),
                ] {
                    let socket = socket2::Socket::new(
                        domain,
                        socket2::Type::STREAM,
                        Some(socket2::Protocol::TCP),
                    )?;
                    socket.set_reuse_address(true)?;
                    if domain == socket2::Domain::IPV6 {
                        socket.set_only_v6(true)?;
                    }
                    let address: std::net::SocketAddr = address.parse().map_err(|error| {
                        std::io::Error::other(format!("invalid listener address: {error}"))
                    })?;
                    socket.bind(&address.into())?;
                    socket.listen(128)?;
                    let listener: std::net::TcpListener = socket.into();
                    listener.set_nonblocking(true)?;
                    listeners.push(listener);
                }
                Ok(listeners)
            })();
            let _ = tx.send(result);
        });
        rx.await
            .map_err(|_| std::io::Error::other("netns bind thread panicked"))??
            .into_iter()
            .map(tokio::net::TcpListener::from_std)
            .collect()
    }

    /// Bind UDP and TCP DNS listeners inside the workload network namespace.
    /// The workload keeps its image-provided resolver configuration; nftables
    /// redirects port 53 to these sockets before the bypass fence runs.
    pub async fn bind_policy_dns_sockets(
        &self,
    ) -> std::io::Result<(tokio::net::UdpSocket, tokio::net::TcpListener)> {
        let ns_fd = self
            .ns_fd
            .ok_or_else(|| std::io::Error::other("no namespace fd available for bind"))?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let result = (|| -> std::io::Result<(std::net::UdpSocket, std::net::TcpListener)> {
                #[allow(unsafe_code)]
                if unsafe { libc::setns(ns_fd, libc::CLONE_NEWNET) } != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // Bind the exact REDIRECT destination instead of INADDR_ANY.
                // For UDP this keeps replies sourced from loopback so
                // conntrack can reverse the port/address translation before
                // delivering them to libc in nested rootless namespaces.
                let address: std::net::SocketAddr = format!("127.0.0.1:{POLICY_DNS_PORT}")
                    .parse()
                    .map_err(|error| {
                        std::io::Error::other(format!("invalid DNS listener address: {error}"))
                    })?;

                let udp = socket2::Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::DGRAM,
                    Some(socket2::Protocol::UDP),
                )?;
                udp.set_reuse_address(true)?;
                udp.bind(&address.into())?;
                udp.set_nonblocking(true)?;

                let tcp = socket2::Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::STREAM,
                    Some(socket2::Protocol::TCP),
                )?;
                tcp.set_reuse_address(true)?;
                tcp.bind(&address.into())?;
                tcp.listen(128)?;
                tcp.set_nonblocking(true)?;

                Ok((udp.into(), tcp.into()))
            })();
            let _ = tx.send(result);
        });
        let (udp, tcp) = rx
            .await
            .map_err(|_| std::io::Error::other("netns DNS bind thread panicked"))??;
        Ok((
            tokio::net::UdpSocket::from_std(udp)?,
            tokio::net::TcpListener::from_std(tcp)?,
        ))
    }

    /// Bind a TCP listener inside this network namespace on a dedicated thread.
    ///
    /// Spawns a short-lived OS thread that enters the namespace via `setns`,
    /// binds a `std::net::TcpListener`, then exits. The listener fd is handed
    /// back as a non-blocking `tokio::net::TcpListener`. Using a dedicated
    /// thread (not `spawn_blocking`) avoids contaminating the tokio thread
    /// pool's namespace state.
    ///
    /// Returns `Err` if the namespace has no fd, `setns` fails, or bind fails.
    pub async fn bind_tcp_in_netns(&self, addr: &str) -> std::io::Result<tokio::net::TcpListener> {
        let ns_fd = self
            .ns_fd
            .ok_or_else(|| std::io::Error::other("no namespace fd available for bind"))?;
        let addr = addr.to_string();
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let result = (|| -> std::io::Result<std::net::TcpListener> {
                // SAFETY: setns is safe to call; this is a dedicated thread
                // that exits after binding. The thread's namespace state does
                // not contaminate any thread pool.
                #[allow(unsafe_code)]
                let rc = unsafe { libc::setns(ns_fd, libc::CLONE_NEWNET) };
                if rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                std::net::TcpListener::bind(&addr)
            })();
            let _ = tx.send(result);
        });

        let std_listener = rx
            .await
            .map_err(|_| std::io::Error::other("netns bind thread panicked"))??;
        std_listener.set_nonblocking(true)?;
        tokio::net::TcpListener::from_std(std_listener)
    }
}

impl Drop for NetworkNamespace {
    fn drop(&mut self) {
        debug!(namespace = %self.name, "Cleaning up network namespace");

        // Delete the host-side veth (this also removes the sandbox peer).
        // Do this before freeing the namespace so ordering stays explicit.
        if let Err(e) = netlink::delete_link(&self.veth_host) {
            warn!(
                error = %e,
                veth = %self.veth_host,
                "Failed to delete veth interface"
            );
        }

        // Free the namespace: close the fd, unmount the bind mount, remove the
        // target file (no `ip netns delete`).
        if let Some(fd) = self.ns_fd.take() {
            if let Err(e) = netlink::destroy_netns(&self.name, fd) {
                warn!(
                    error = %e,
                    namespace = %self.name,
                    "Failed to remove network namespace mount"
                );
            }
        }

        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(openshell_ocsf::SeverityId::Informational)
                .status(openshell_ocsf::StatusId::Success)
                .state(openshell_ocsf::StateId::Disabled, "cleaned_up")
                .message(format!("Network namespace cleaned up [ns:{}]", self.name))
                .build()
        );
    }
}

/// Create the workload's network namespace and install bypass detection
/// rules. Returns `None` when the policy is not in proxy mode.
///
/// The namespace is shared infrastructure: the proxy binds to its host-side
/// veth IP and reads /dev/kmsg from inside it for bypass detection, while
/// the workload child and SSH sessions enter it via `setns()`.
///
/// # Errors
///
/// Returns an error if proxy mode is requested but the namespace cannot be
/// created (e.g., missing `CAP_NET_ADMIN` / `CAP_SYS_ADMIN`). Failure to
/// install nftables bypass-detection rules is non-fatal and is reported via
/// OCSF instead.
pub fn create_netns_for_proxy(
    policy: &openshell_core::policy::SandboxPolicy,
) -> Result<Option<NetworkNamespace>> {
    use openshell_core::policy::NetworkMode;
    use openshell_ocsf::{ConfigStateChangeBuilder, SeverityId, StateId, StatusId, ocsf_emit};

    if !matches!(policy.network.mode, NetworkMode::Proxy) {
        return Ok(None);
    }
    match NetworkNamespace::create() {
        Ok(ns) => {
            let proxy_port = policy
                .network
                .proxy
                .as_ref()
                .and_then(|p| p.http_addr)
                .map_or(3128, |addr| addr.port());
            if let Err(e) = ns.install_bypass_rules(proxy_port) {
                ocsf_emit!(
                    ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                        .severity(SeverityId::Medium)
                        .status(StatusId::Failure)
                        .state(StateId::Disabled, "degraded")
                        .message(format!(
                            "Failed to install bypass detection rules (non-fatal): {e}"
                        ))
                        .build()
                );
            }
            Ok(Some(ns))
        }
        Err(e) => Err(miette::miette!(
            "Network namespace creation failed and proxy mode requires isolation. \
             Ensure CAP_NET_ADMIN and CAP_SYS_ADMIN are available. \
             Error: {e}"
        )),
    }
}

/// Install pod-network bypass enforcement for Kubernetes sidecar topology.
///
/// This runs in the current network namespace, not in a per-workload netns.
/// The rules allow loopback and the sidecar proxy UID, then reject direct
/// TCP/UDP egress from other UIDs so traffic must use the sidecar's local
/// proxy.
///
/// # Errors
///
/// Returns an error when `nft` is unavailable or the ruleset cannot be loaded.
pub fn install_sidecar_bypass_rules(proxy_uid: u32) -> Result<()> {
    match install_sidecar_nft_bypass_rules(proxy_uid) {
        Ok(()) => Ok(()),
        Err(nft_error) => {
            warn!(
                error = %nft_error,
                "Failed to install nftables sidecar rules; trying iptables-legacy fallback"
            );
            install_sidecar_iptables_legacy_bypass_rules(proxy_uid).map_err(|iptables_error| {
                miette::miette!(
                    "sidecar nft ruleset load failed: {nft_error}; sidecar iptables-legacy fallback failed: {iptables_error}"
                )
            })
        }
    }
}

fn install_sidecar_nft_bypass_rules(proxy_uid: u32) -> Result<()> {
    let nft_cmd = find_nft().ok_or_else(|| {
        miette::miette!(
            "trusted nft helper not found; sidecar network enforcement requires nftables"
        )
    })?;
    let log_prefix = Some("openshell:sidecar-bypass:");
    let commands = nft_ruleset::generate_sidecar_bypass_commands(proxy_uid, log_prefix);
    run_nft_commands_current_namespace(&nft_cmd, &commands)
}

const SIDECAR_IPTABLES_CHAIN: &str = "OPENSHELL_SIDECAR_BYPASS";
const PROC_NET_IF_INET6_PATH: &str = "/proc/net/if_inet6";

fn install_sidecar_iptables_legacy_bypass_rules(proxy_uid: u32) -> Result<()> {
    let ipv4_filter_tool = find_iptables_legacy().ok_or_else(|| {
        miette::miette!(
            "trusted iptables-legacy helper not found; sidecar network enforcement fallback unavailable"
        )
    })?;

    let ipv6_fence_tool = if current_namespace_has_non_loopback_ipv6()? {
        Some(find_ip6tables_legacy().ok_or_else(|| {
            miette::miette!(
                "trusted ip6tables-legacy helper not found; sidecar network enforcement fallback cannot fence IPv6"
            )
        })?)
    } else {
        warn!(
            "Skipping IPv6 sidecar iptables-legacy fallback because the current namespace has no non-loopback IPv6 interface"
        );
        None
    };

    cleanup_sidecar_iptables_legacy_rule_families(&ipv4_filter_tool, ipv6_fence_tool.as_deref());

    if let Err(e) = install_sidecar_iptables_legacy_family_rules(
        &ipv4_filter_tool,
        proxy_uid,
        "icmp-port-unreachable",
    ) {
        cleanup_sidecar_iptables_legacy_rule_families(
            &ipv4_filter_tool,
            ipv6_fence_tool.as_deref(),
        );
        return Err(e);
    }

    if let Some(ipv6_fence_tool) = ipv6_fence_tool
        && let Err(e) = install_sidecar_iptables_legacy_family_rules(
            &ipv6_fence_tool,
            proxy_uid,
            "icmp6-port-unreachable",
        )
    {
        cleanup_sidecar_iptables_legacy_rule_families(&ipv4_filter_tool, Some(&ipv6_fence_tool));
        return Err(e);
    }

    Ok(())
}

fn current_namespace_has_non_loopback_ipv6() -> Result<bool> {
    match std::fs::read_to_string(PROC_NET_IF_INET6_PATH) {
        Ok(content) => Ok(has_non_loopback_ipv6_interface(&content)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(miette::miette!(
            "failed to inspect {PROC_NET_IF_INET6_PATH} before installing sidecar IPv6 fence: {e}"
        )),
    }
}

fn has_non_loopback_ipv6_interface(content: &str) -> bool {
    content.lines().any(|line| {
        line.split_whitespace()
            .nth(5)
            .is_some_and(|iface| iface != "lo")
    })
}

fn install_sidecar_iptables_legacy_family_rules(
    cmd: &str,
    proxy_uid: u32,
    udp_reject_with: &str,
) -> Result<()> {
    let proxy_uid_arg = proxy_uid.to_string();
    let commands: Vec<Vec<&str>> = vec![
        vec!["-N", SIDECAR_IPTABLES_CHAIN],
        vec!["-A", SIDECAR_IPTABLES_CHAIN, "-o", "lo", "-j", "ACCEPT"],
        vec![
            "-A",
            SIDECAR_IPTABLES_CHAIN,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
        vec![
            "-A",
            SIDECAR_IPTABLES_CHAIN,
            "-m",
            "owner",
            "--uid-owner",
            &proxy_uid_arg,
            "-j",
            "ACCEPT",
        ],
        vec![
            "-A",
            SIDECAR_IPTABLES_CHAIN,
            "-p",
            "tcp",
            "-j",
            "REJECT",
            "--reject-with",
            "tcp-reset",
        ],
        vec![
            "-A",
            SIDECAR_IPTABLES_CHAIN,
            "-p",
            "udp",
            "-j",
            "REJECT",
            "--reject-with",
            udp_reject_with,
        ],
        vec!["-A", "OUTPUT", "-j", SIDECAR_IPTABLES_CHAIN],
    ];

    for args in commands {
        if let Err(e) = run_iptables_legacy_current_namespace(cmd, &args) {
            cleanup_sidecar_iptables_legacy_rules(cmd);
            return Err(e);
        }
    }

    Ok(())
}

fn cleanup_sidecar_iptables_legacy_rules(iptables_cmd: &str) {
    while run_iptables_legacy_current_namespace(
        iptables_cmd,
        &["-D", "OUTPUT", "-j", SIDECAR_IPTABLES_CHAIN],
    )
    .is_ok()
    {}
    let _ = run_iptables_legacy_current_namespace(iptables_cmd, &["-F", SIDECAR_IPTABLES_CHAIN]);
    let _ = run_iptables_legacy_current_namespace(iptables_cmd, &["-X", SIDECAR_IPTABLES_CHAIN]);
}

fn cleanup_sidecar_iptables_legacy_rule_families(ipv4_cmd: &str, ipv6_cmd: Option<&str>) {
    cleanup_sidecar_iptables_legacy_rules(ipv4_cmd);
    if let Some(ipv6_cmd) = ipv6_cmd {
        cleanup_sidecar_iptables_legacy_rules(ipv6_cmd);
    }
}

fn run_iptables_legacy_current_namespace(iptables_cmd: &str, args: &[&str]) -> Result<()> {
    debug!(
        command = %format!("{iptables_cmd} {}", args.join(" ")),
        "Running iptables-legacy sidecar command"
    );

    let output = Command::new(iptables_cmd)
        .args(args)
        .output()
        .into_diagnostic()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(miette::miette!(
            "{iptables_cmd} {} failed: {}",
            args.join(" "),
            stderr.trim()
        ));
    }

    Ok(())
}

/// Run a sequence of nft commands in the current network namespace.
///
/// Each command is executed as a separate `nft` invocation to avoid atomic
/// batch rollback (where one unsupported expression like `ct state` or `log`
/// causes the entire transaction, including table creation, to fail).
///
/// Commands marked as non-required are allowed to fail with a warning.
/// Required commands that fail abort the sequence immediately.
fn run_nft_commands_current_namespace(
    nft_cmd: &str,
    commands: &[nft_ruleset::NftCommand],
) -> Result<()> {
    for cmd in commands {
        let args_str = cmd.args.join(" ");
        debug!(command = %format!("{nft_cmd} {args_str}"), "Running nft command");

        let output = Command::new(nft_cmd)
            .args(&cmd.args)
            .output()
            .into_diagnostic()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if cmd.required {
                return Err(miette::miette!(
                    "{nft_cmd} {args_str} failed: {}",
                    stderr.trim()
                ));
            }
            warn!(
                command = %args_str,
                error = %stderr.trim(),
                "non-required nft command failed (continuing)"
            );
        }
    }
    Ok(())
}

fn first_route_overlap(
    routes: &[ipnet::IpNet],
    reserved: &[ipnet::IpNet],
) -> Option<(ipnet::IpNet, ipnet::IpNet)> {
    routes.iter().find_map(|route| {
        // A default route (0.0.0.0/0 or ::/0) covers everything but never
        // shadows a specific synthetic pool, so it is not a real overlap.
        if route.prefix_len() == 0 {
            return None;
        }
        reserved
            .iter()
            .copied()
            .find(|pool| {
                let same_family = route.addr().is_ipv4() == pool.addr().is_ipv4();
                let overlaps = route.contains(&pool.network()) || pool.contains(&route.network());
                same_family && overlaps
            })
            .map(|pool| (*route, pool))
    })
}

/// Run a sequence of nft commands inside a network namespace via `nsenter --net=`.
///
/// Each command is executed as a separate invocation to avoid atomic batch
/// rollback. See [`run_nft_commands_current_namespace`] for rationale.
fn run_nft_commands_netns(
    netns: &str,
    nft_cmd: &str,
    commands: &[nft_ruleset::NftCommand],
) -> Result<()> {
    let nsenter_path = find_trusted_binary("nsenter", NSENTER_SEARCH_PATHS)?;
    let ns_path = openshell_core::container_paths::netns_path(netns);
    let net_flag = format!("--net={}", ns_path.display());

    for cmd in commands {
        let args_str = cmd.args.join(" ");
        debug!(
            command = %format!("{nsenter_path} {net_flag} -- {nft_cmd} {args_str}"),
            "Running nft command in namespace"
        );

        let mut full_args = vec![net_flag.as_str(), "--", nft_cmd];
        let arg_refs: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
        full_args.extend(&arg_refs);

        let output = Command::new(nsenter_path)
            .args(&full_args)
            .output()
            .into_diagnostic()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if cmd.required {
                return Err(miette::miette!(
                    "nft {args_str} failed in netns {netns}: {}",
                    stderr.trim()
                ));
            }
            warn!(
                command = %args_str,
                error = %stderr.trim(),
                netns = %netns,
                "non-required nft command failed in namespace (continuing)"
            );
        }
    }
    Ok(())
}

const NF_LOG_ALL_NETNS_PATH: &str = "/proc/sys/net/netfilter/nf_log_all_netns";

/// Enable nftables logging from non-init network namespaces.
///
/// The kernel's `nf_log_syslog` module silently suppresses log output from
/// non-init network namespaces unless `net.netfilter.nf_log_all_netns` is
/// set to 1. Since sandbox bypass rules live in a per-sandbox network
/// namespace, the bypass monitor can't see log entries without this.
fn enable_nf_log_all_netns() {
    use std::path::Path;
    if !Path::new(NF_LOG_ALL_NETNS_PATH).exists() {
        debug!("nf_log_all_netns sysctl not available (may already be set by init)");
        return;
    }
    match std::fs::write(NF_LOG_ALL_NETNS_PATH, "1") {
        Ok(()) => {
            debug!("Enabled nf_log_all_netns for non-init namespace logging");
        }
        Err(e) => {
            debug!(
                error = %e,
                "Could not enable nf_log_all_netns; bypass log rules may not produce output"
            );
        }
    }
}

/// Well-known paths where nft may be installed.
const NFT_SEARCH_PATHS: &[&str] = &["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"];
const IPTABLES_LEGACY_SEARCH_PATHS: &[&str] = &[
    "/usr/sbin/iptables-legacy",
    "/sbin/iptables-legacy",
    "/usr/bin/iptables-legacy",
];
const IP6TABLES_LEGACY_SEARCH_PATHS: &[&str] = &[
    "/usr/sbin/ip6tables-legacy",
    "/sbin/ip6tables-legacy",
    "/usr/bin/ip6tables-legacy",
];

fn find_trusted_binary<'a>(name: &str, paths: &'a [&str]) -> Result<&'a str> {
    paths
        .iter()
        .copied()
        .find(|path| {
            let path = Path::new(path);
            path.is_absolute() && path.is_file()
        })
        .ok_or_else(|| {
            miette::miette!(
                "trusted {name} helper not found; checked {}",
                paths.join(", ")
            )
        })
}

/// Find the nft binary path, checking well-known locations.
fn find_nft() -> Option<String> {
    find_trusted_binary("nft", NFT_SEARCH_PATHS)
        .ok()
        .map(String::from)
}

fn find_iptables_legacy() -> Option<String> {
    find_trusted_binary("iptables-legacy", IPTABLES_LEGACY_SEARCH_PATHS)
        .ok()
        .map(String::from)
}

fn find_ip6tables_legacy() -> Option<String> {
    find_trusted_binary("ip6tables-legacy", IP6TABLES_LEGACY_SEARCH_PATHS)
        .ok()
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // These tests require root and network namespace support
    // Run with: sudo cargo test -- --ignored

    /// Root-only: create() builds a working namespace with host veth, sandbox
    /// address, and default route — with no external `ip`/`nsenter` process.
    #[test]
    #[ignore = "requires root / CAP_NET_ADMIN"]
    fn create_builds_namespace_via_netlink() {
        let ns = NetworkNamespace::create().expect("create netns");
        assert_eq!(ns.host_ip().to_string(), "10.200.0.1");
        assert_eq!(ns.sandbox_ip().to_string(), "10.200.0.2");
        assert!(ns.name().starts_with("sandbox-"));
        assert!(ns.ns_fd().is_some(), "namespace must be FD-owned");
        // Dropping ns tears everything down via netlink + fd close.
    }

    #[test]
    fn find_trusted_binary_uses_absolute_existing_file() {
        let tempdir = tempfile::tempdir().unwrap();
        let helper = tempdir.path().join("ip");
        fs::write(&helper, b"test helper").unwrap();
        let helper = helper.to_str().unwrap();

        assert_eq!(
            find_trusted_binary("ip", &["relative-ip", "/missing/ip", helper]).unwrap(),
            helper
        );
    }

    #[test]
    fn find_trusted_binary_rejects_missing_helpers() {
        let err =
            find_trusted_binary("nsenter", &["relative-nsenter", "/missing/nsenter"]).unwrap_err();

        assert!(err.to_string().contains("trusted nsenter helper not found"));
    }

    #[test]
    fn nft_search_paths_are_absolute() {
        for path in NFT_SEARCH_PATHS {
            assert!(
                path.starts_with('/'),
                "NFT_SEARCH_PATHS entry must be absolute: {path}"
            );
        }
    }

    #[test]
    fn iptables_legacy_search_paths_are_absolute() {
        for path in IPTABLES_LEGACY_SEARCH_PATHS {
            assert!(
                path.starts_with('/'),
                "IPTABLES_LEGACY_SEARCH_PATHS entry must be absolute: {path}"
            );
        }
    }

    #[test]
    fn ip6tables_legacy_search_paths_are_absolute() {
        for path in IP6TABLES_LEGACY_SEARCH_PATHS {
            assert!(
                path.starts_with('/'),
                "IP6TABLES_LEGACY_SEARCH_PATHS entry must be absolute: {path}"
            );
        }
    }

    #[test]
    fn non_loopback_ipv6_detector_ignores_empty_input() {
        assert!(!has_non_loopback_ipv6_interface(""));
        assert!(!has_non_loopback_ipv6_interface("\n\n"));
    }

    #[test]
    fn non_loopback_ipv6_detector_ignores_loopback() {
        let content = "00000000000000000000000000000001 01 80 10 80 lo\n";

        assert!(!has_non_loopback_ipv6_interface(content));
    }

    #[test]
    fn non_loopback_ipv6_detector_detects_pod_interface() {
        let content = "\
00000000000000000000000000000001 01 80 10 80 lo
fe800000000000000000000000000001 02 40 20 80 eth0
";

        assert!(has_non_loopback_ipv6_interface(content));
    }

    #[test]
    fn route_overlap_detects_reserved_pool_collision() {
        let reserved = [
            "198.18.1.0/25".parse().unwrap(),
            "fd23:6f70:656e:1::/120".parse().unwrap(),
        ];
        let routes: Vec<ipnet::IpNet> = ["0.0.0.0/0", "198.18.0.0/15"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let (route, pool) = first_route_overlap(&routes, &reserved).expect("collision");
        assert_eq!(route.to_string(), "198.18.0.0/15");
        assert_eq!(pool.to_string(), "198.18.1.0/25");
    }

    #[test]
    fn route_overlap_ignores_default_and_unrelated_routes() {
        let reserved = [
            "198.18.1.0/25".parse().unwrap(),
            "fd23:6f70:656e:1::/120".parse().unwrap(),
        ];
        let routes: Vec<ipnet::IpNet> = ["0.0.0.0/0", "10.200.0.0/24"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(first_route_overlap(&routes, &reserved), None);
    }

    #[test]
    #[ignore = "requires root privileges"]
    fn test_create_and_drop_namespace() {
        let ns = NetworkNamespace::create().expect("Failed to create namespace");
        let name = ns.name().to_string();

        // Verify namespace exists
        let ns_path = openshell_core::container_paths::netns_path(&name);
        assert!(ns_path.exists(), "Namespace file should exist");

        // Verify IPs are set correctly
        assert_eq!(
            ns.host_ip().to_string(),
            format!("{SUBNET_PREFIX}.{HOST_IP_SUFFIX}")
        );
        assert_eq!(
            ns.sandbox_ip().to_string(),
            format!("{SUBNET_PREFIX}.{SANDBOX_IP_SUFFIX}")
        );

        // Drop should clean up
        drop(ns);

        // Verify namespace is gone
        assert!(
            !Path::new(&ns_path).exists(),
            "Namespace should be cleaned up"
        );
    }
}
