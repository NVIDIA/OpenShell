// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime-owned policy DNS listeners for combined Linux supervisors.

#[cfg(test)]
use openshell_sandbox_backend::test_support as rpc_test;

use crate::opa::OpaEngine;
use crate::policy_dns::resolver::MAX_DNS_MESSAGE_BYTES;
use crate::policy_dns::store::{ResolvedEndpointStore, StoreConfig, SyntheticPools};
use crate::policy_dns::{POLICY_LOCAL_ADDRESS, PolicyDnsService, SocketTrustedResolver, wire};
use futures::{FutureExt as _, StreamExt as _, stream::FuturesUnordered};
use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::net::set_tcp_nodelay_best_effort;
use openshell_isolation_interface::contract::{DnsTransport, PendingDnsQuery};
use openshell_ocsf::{ConfigStateChangeBuilder, SeverityId, StateId, StatusId};
use openshell_sandbox_backend::NetworkMediationSource;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

const IPV4_POOL_PREFIX: u8 = 23;
const IPV6_POOL_PREFIX: u8 = 119;
const IPV4_EPOCH_WINDOWS: u64 = 1 << (IPV4_POOL_PREFIX - 15);
const MAX_MAPPINGS: usize = 1024;
const MAX_CONCURRENT_UDP_QUERIES: usize = 64;
const MEDIATION_ACCEPT_WINDOW: usize = 32;
const MEDIATION_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(100);
const MEDIATION_MAX_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

async fn accept_mediated_dns(source: Arc<NetworkMediationSource>) -> PendingDnsQuery {
    let mut delay = MEDIATION_RETRY_DELAY;
    loop {
        match source.accept_dns().await {
            Ok(query) => return query,
            Err(error) => {
                tracing::warn!(%error, "mediated DNS accept failed; retrying");
                tokio::time::sleep(delay).await;
                delay = delay.saturating_mul(2).min(MEDIATION_MAX_RETRY_DELAY);
            }
        }
    }
}

/// Whether policy DNS answers AAAA queries with synthetic IPv6 addresses.
///
/// When IPv6 egress is disabled, AAAA queries receive an empty successful
/// answer without an upstream query so dual-stack clients fall back to A.
/// That fallback cannot help on IPv6-only hosts (for example NAT64/DNS64
/// networks), where the trusted resolver returns no A records at all.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PolicyDnsIpv6Egress {
    /// Enable IPv6 answers only when the supervisor network namespace has an
    /// IPv6 default route and no IPv4 default route.
    #[default]
    Auto,
    /// Always resolve AAAA queries through the trusted resolver.
    Enabled,
    /// Never resolve AAAA queries; answer them with NOERROR/NODATA.
    Disabled,
}

impl PolicyDnsIpv6Egress {
    /// Resolve the mode to a concrete decision for this supervisor.
    #[must_use]
    pub fn resolve(self) -> bool {
        match self {
            Self::Enabled => true,
            Self::Disabled => false,
            Self::Auto => ipv6_only_default_route(
                std::fs::read_to_string("/proc/net/route").ok().as_deref(),
                std::fs::read_to_string("/proc/net/ipv6_route")
                    .ok()
                    .as_deref(),
            ),
        }
    }
}

const RTF_UP: u32 = 0x0001;
const RTF_REJECT: u32 = 0x0200;

/// Report whether the routing tables describe an IPv6-only uplink. An
/// unreadable table keeps the IPv4-only default.
fn ipv6_only_default_route(ipv4_routes: Option<&str>, ipv6_routes: Option<&str>) -> bool {
    let (Some(ipv4_routes), Some(ipv6_routes)) = (ipv4_routes, ipv6_routes) else {
        return false;
    };
    !has_ipv4_default_route(ipv4_routes) && has_ipv6_default_route(ipv6_routes)
}

/// Parse `/proc/net/route` for a usable `0.0.0.0/0` route.
fn has_ipv4_default_route(table: &str) -> bool {
    table.lines().skip(1).any(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        fields.len() >= 8
            && fields[1] == "00000000"
            && fields[7] == "00000000"
            && route_flags_usable(fields[3])
    })
}

/// Parse `/proc/net/ipv6_route` for a usable `::/0` route. The kernel lists
/// an unreachable `::/0` entry on `lo`, which is not an uplink.
fn has_ipv6_default_route(table: &str) -> bool {
    table.lines().any(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        fields.len() >= 10
            && fields[0].bytes().all(|byte| byte == b'0')
            && fields[0].len() == 32
            && fields[1] == "00"
            && fields[9] != "lo"
            && route_flags_usable(fields[8])
    })
}

fn route_flags_usable(flags: &str) -> bool {
    u32::from_str_radix(flags, 16).is_ok_and(|flags| flags & RTF_UP != 0 && flags & RTF_REJECT == 0)
}

#[derive(Debug, Clone)]
pub(crate) struct PolicyDnsRuntimeConfig {
    pub(crate) ipv4_cidr: ipnet::Ipv4Net,
    pub(crate) ipv6_cidr: ipnet::Ipv6Net,
    pools: SyntheticPools,
    ipv6_egress: bool,
}

impl PolicyDnsRuntimeConfig {
    pub(crate) fn for_epoch(epoch: u64) -> Result<Self> {
        let ipv4_parent: ipnet::Ipv4Net = "198.18.0.0/15".parse().unwrap();
        let ipv4_window = epoch % IPV4_EPOCH_WINDOWS;
        let ipv4_start = u32::from(ipv4_parent.network())
            + u32::try_from(ipv4_window * (1 << (32 - IPV4_POOL_PREFIX))).unwrap();
        let ipv4_cidr = ipnet::Ipv4Net::new(Ipv4Addr::from(ipv4_start), IPV4_POOL_PREFIX)
            .map_err(|error| miette::miette!(error.to_string()))?;

        let ipv6_parent: ipnet::Ipv6Net = "fd23:6f70:656e::/48".parse().unwrap();
        let ipv6_window = u128::from(epoch);
        let ipv6_start =
            u128::from(ipv6_parent.network()) + (ipv6_window << (128 - IPV6_POOL_PREFIX));
        let ipv6_cidr = ipnet::Ipv6Net::new(Ipv6Addr::from(ipv6_start), IPV6_POOL_PREFIX)
            .map_err(|error| miette::miette!(error.to_string()))?;

        // Keep the sandbox-local API address out of the external mapping pool.
        let ipv4_pool_start = if ipv4_cidr.contains(&POLICY_LOCAL_ADDRESS) {
            Ipv4Addr::from(u32::from(POLICY_LOCAL_ADDRESS) + 1)
        } else {
            ipv4_cidr.network()
        };
        let pools = SyntheticPools::new(
            ipv4_pool_start..=ipv4_cidr.broadcast(),
            ipv6_cidr.network()..=ipv6_cidr.broadcast(),
        )
        .map_err(|error| miette::miette!(error.to_string()))?;
        Ok(Self {
            ipv4_cidr,
            ipv6_cidr,
            pools,
            ipv6_egress: false,
        })
    }

    /// Answer AAAA queries from the synthetic IPv6 pool instead of returning
    /// NOERROR/NODATA.
    #[must_use]
    pub(crate) fn with_ipv6_egress(mut self, enabled: bool) -> Self {
        self.ipv6_egress = enabled;
        self
    }
}

pub(crate) struct PolicyDnsRuntime {
    pub(crate) service: Arc<PolicyDnsService>,
    tasks: Vec<JoinHandle<()>>,
}

impl PolicyDnsRuntime {
    /// Start policy DNS over an isolation-backend exchange source. No UDP or
    /// TCP listener is bound in the supervisor namespace.
    pub(crate) fn start_mediated(
        policy: Arc<OpaEngine>,
        source: Arc<NetworkMediationSource>,
        trusted_host_gateway: Option<IpAddr>,
        config: PolicyDnsRuntimeConfig,
        mut engine_ready: tokio::sync::watch::Receiver<bool>,
    ) -> Result<Self> {
        let upstream = trusted_resolver_from_resolv_conf()?;
        let ipv6_egress = config.ipv6_egress;
        let store = Arc::new(ResolvedEndpointStore::new(
            StoreConfig::new(config.pools, MAX_MAPPINGS)
                .map_err(|error| miette::miette!(error.to_string()))?,
        ));
        let service = Arc::new(PolicyDnsService::new(
            policy,
            SocketTrustedResolver::new(upstream),
            store.clone(),
            trusted_host_gateway,
        ));
        let dns_service = service.clone();
        let task = tokio::spawn(async move {
            if engine_ready.wait_for(|ready| *ready).await.is_err() {
                return;
            }
            let mut accepts = FuturesUnordered::new();
            for _ in 0..MEDIATION_ACCEPT_WINDOW {
                let source = source.clone();
                accepts.push(accept_mediated_dns(source).boxed());
            }
            loop {
                let Some(query) = accepts.next().await else {
                    return;
                };
                let source = source.clone();
                accepts.push(accept_mediated_dns(source).boxed());
                let service = dns_service.clone();
                tokio::spawn(async move {
                    let timing = query.timing.clone();
                    let response = match query.transport {
                        DnsTransport::Udp => {
                            wire::handle_udp_query_with_ipv6(&service, &query.message, ipv6_egress)
                                .await
                        }
                        DnsTransport::Tcp => {
                            wire::handle_tcp_query_with_ipv6(&service, &query.message, ipv6_egress)
                                .await
                        }
                    }
                    .map_err(|error| {
                        openshell_isolation_interface::contract::BackendError::Process(format!(
                            "policy DNS response failed: {error}"
                        ))
                    });
                    if query.response.send(response).is_err() {
                        tracing::warn!("sandbox DNS response channel closed before delivery");
                    }
                    tracing::debug!(
                        target: "openshell::dns_timing",
                        notification_to_queue_us = timing
                            .sandbox_notification_to_queue
                            .as_micros(),
                        queue_wait_us = timing.sandbox_queue_wait.as_micros(),
                        supervisor_processing_us = timing
                            .supervisor_received_at
                            .elapsed()
                            .as_micros(),
                        "mediated DNS query timing"
                    );
                });
            }
        });
        let expiry_store = store;
        let expiry_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                interval.tick().await;
                let _ = expiry_store.expire(std::time::Instant::now());
            }
        });
        crate::telemetry::egress_emit!(
            ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .state(StateId::Enabled, "ready")
                .unmapped("ipv6_egress", ipv6_egress)
                .message(format!(
                    "Policy DNS connected to isolation boundary (IPv6 egress {})",
                    if ipv6_egress { "enabled" } else { "disabled" }
                ))
                .build()
        );
        Ok(Self {
            service,
            tasks: vec![task, expiry_task],
        })
    }

    pub(crate) fn start(
        policy: Arc<OpaEngine>,
        udp: tokio::net::UdpSocket,
        tcp: tokio::net::TcpListener,
        trusted_host_gateway: Option<IpAddr>,
        config: PolicyDnsRuntimeConfig,
        engine_ready: tokio::sync::watch::Receiver<bool>,
    ) -> Result<Self> {
        let upstream = trusted_resolver_from_resolv_conf()?;
        let ipv6_egress = config.ipv6_egress;
        let store = Arc::new(ResolvedEndpointStore::new(
            StoreConfig::new(config.pools, MAX_MAPPINGS)
                .map_err(|error| miette::miette!(error.to_string()))?,
        ));
        let service = Arc::new(PolicyDnsService::new(
            policy,
            SocketTrustedResolver::new(upstream),
            store.clone(),
            trusted_host_gateway,
        ));
        let address = udp.local_addr().into_diagnostic()?;

        let udp_service = service.clone();
        let udp = Arc::new(udp);
        let udp_concurrency = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_UDP_QUERIES));
        let mut udp_engine_ready = engine_ready.clone();
        let udp_task = tokio::spawn(async move {
            if udp_engine_ready.wait_for(|ready| *ready).await.is_err() {
                return;
            }
            let mut request = vec![0_u8; MAX_DNS_MESSAGE_BYTES + 1];
            loop {
                let Ok(permit) = udp_concurrency.clone().acquire_owned().await else {
                    break;
                };
                let Ok((length, peer)) = udp.recv_from(&mut request).await else {
                    break;
                };
                let request = request[..length].to_vec();
                let service = udp_service.clone();
                let udp = udp.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    // Without IPv6 egress, AAAA receives NOERROR/NODATA so
                    // dual-stack clients fall back to the usable IPv4 path.
                    if let Ok(response) =
                        wire::handle_udp_query_with_ipv6(&service, &request, ipv6_egress).await
                    {
                        let _ = udp.send_to(&response, peer).await;
                    }
                });
            }
        });

        let mut tcp_engine_ready = engine_ready;
        let tcp_service = service.clone();
        let tcp_task = tokio::spawn(async move {
            if tcp_engine_ready.wait_for(|ready| *ready).await.is_err() {
                return;
            }
            loop {
                let Ok((mut stream, _)) = tcp.accept().await else {
                    break;
                };
                set_tcp_nodelay_best_effort(&stream);
                let service = tcp_service.clone();
                tokio::spawn(async move {
                    // DNS-over-TCP connections may carry multiple sequential
                    // length-prefixed messages. libc commonly reuses one
                    // connection for A and AAAA during getaddrinfo().
                    while let Ok(wire_length) = stream.read_u16().await {
                        let length = usize::from(wire_length);
                        if length > MAX_DNS_MESSAGE_BYTES {
                            return;
                        }
                        let mut frame = Vec::with_capacity(length + 2);
                        frame.extend_from_slice(&wire_length.to_be_bytes());
                        frame.resize(length + 2, 0);
                        if stream.read_exact(&mut frame[2..]).await.is_err() {
                            return;
                        }
                        let Ok(response) =
                            wire::handle_tcp_query_with_ipv6(&service, &frame, ipv6_egress).await
                        else {
                            return;
                        };
                        if stream.write_all(&response).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        let expiry_store = store;
        let expiry_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                interval.tick().await;
                let _ = expiry_store.expire(std::time::Instant::now());
            }
        });

        crate::telemetry::egress_emit!(
            ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .state(StateId::Enabled, "ready")
                .unmapped("ipv6_egress", ipv6_egress)
                .message(format!("Policy DNS listening on {address}"))
                .build()
        );
        Ok(Self {
            service,
            tasks: vec![udp_task, tcp_task, expiry_task],
        })
    }
}

impl Drop for PolicyDnsRuntime {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn trusted_resolver_from_resolv_conf() -> Result<SocketAddr> {
    let contents = std::fs::read_to_string("/etc/resolv.conf")
        .into_diagnostic()
        .wrap_err("failed to read trusted supervisor resolver configuration")?;
    for line in contents.lines() {
        let line = line.split('#').next().unwrap_or_default();
        let mut fields = line.split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        let Some(value) = fields.next() else {
            continue;
        };
        if let Ok(ip) = value.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, 53));
        }
    }
    Err(miette::miette!(
        "no literal nameserver is configured in supervisor /etc/resolv.conf"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mediated_dns_accept_retries_errors_with_backoff() {
        use openshell_isolation_interface::contract::{
            BackendError, MediationTiming, ResolveError,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct RecoveringSource(AtomicUsize);

        #[async_trait::async_trait]
        impl rpc_test::NetworkMediationSource for RecoveringSource {
            async fn accept_tcp(
                &self,
            ) -> std::result::Result<
                openshell_isolation_interface::contract::PendingTcpOpen,
                BackendError,
            > {
                Err(BackendError::Unavailable(
                    "TCP not used by this test".into(),
                ))
            }

            async fn accept_dns(&self) -> std::result::Result<PendingDnsQuery, BackendError> {
                if self.0.fetch_add(1, Ordering::AcqRel) < 2 {
                    return Err(BackendError::Unavailable("injected disconnect".into()));
                }
                let (response, _) = tokio::sync::oneshot::channel();
                Ok(PendingDnsQuery {
                    message: b"recovered query".to_vec(),
                    transport: DnsTransport::Udp,
                    binary_identity: Err(ResolveError::Failed("unknown sender".into())),
                    timing: MediationTiming::default(),
                    response,
                })
            }
        }

        let source = Arc::new(RecoveringSource(AtomicUsize::new(0)));
        let start = tokio::time::Instant::now();
        let query = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            accept_mediated_dns(rpc_test::network(source.clone())),
        )
        .await
        .expect("RPC DNS source did not recover");
        assert_eq!(query.message, b"recovered query");
        // The RPC mediation stream may prefetch additional bounded queries.
        assert!(source.0.load(Ordering::Acquire) >= 3);
        assert!(start.elapsed() >= MEDIATION_RETRY_DELAY * 3);
        // The same source remains usable when the accept window replenishes.
        assert_eq!(
            accept_mediated_dns(rpc_test::network(source)).await.message,
            b"recovered query"
        );
    }

    #[test]
    fn production_pool_is_disjoint_from_workload_veth() {
        let workload: ipnet::IpNet = "10.200.0.0/24".parse().unwrap();
        let config = PolicyDnsRuntimeConfig::for_epoch(42).unwrap();
        for address in [
            IpAddr::V4(config.ipv4_cidr.network()),
            IpAddr::V4(config.ipv4_cidr.broadcast()),
        ] {
            assert!(!workload.contains(&address));
        }
    }

    #[test]
    fn adjacent_boot_epochs_use_disjoint_capture_ranges() {
        let first = PolicyDnsRuntimeConfig::for_epoch(1).unwrap();
        let second = PolicyDnsRuntimeConfig::for_epoch(2).unwrap();
        assert_ne!(first.ipv4_cidr, second.ipv4_cidr);
        assert_ne!(first.ipv6_cidr, second.ipv6_cidr);
        let parent: ipnet::Ipv4Net = "198.18.0.0/15".parse().unwrap();
        for address in [first.ipv4_cidr.network(), second.ipv4_cidr.broadcast()] {
            assert!(parent.contains(&address));
        }
    }

    const IPV4_ROUTE_HEADER: &str =
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n";
    const IPV4_DEFAULT_ROUTE: &str =
        "eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
    const IPV4_SUBNET_ROUTE: &str =
        "eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
    const IPV6_DEFAULT_ROUTE: &str = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n";
    const IPV6_LOOPBACK_UNREACHABLE: &str = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n";
    const IPV6_SUBNET_ROUTE: &str = "20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n";

    #[test]
    fn explicit_ipv6_egress_modes_ignore_routing_tables() {
        assert!(PolicyDnsIpv6Egress::Enabled.resolve());
        assert!(!PolicyDnsIpv6Egress::Disabled.resolve());
        assert_eq!(PolicyDnsIpv6Egress::default(), PolicyDnsIpv6Egress::Auto);
    }

    #[test]
    fn auto_ipv6_egress_enables_only_ipv6_only_uplinks() {
        let ipv4_without_default = format!("{IPV4_ROUTE_HEADER}{IPV4_SUBNET_ROUTE}");
        let ipv4_with_default = format!("{IPV4_ROUTE_HEADER}{IPV4_DEFAULT_ROUTE}");
        let ipv6_with_default = format!("{IPV6_SUBNET_ROUTE}{IPV6_DEFAULT_ROUTE}");

        // IPv6-only (NAT64/DNS64) uplink.
        assert!(ipv6_only_default_route(
            Some(&ipv4_without_default),
            Some(&ipv6_with_default)
        ));
        assert!(ipv6_only_default_route(
            Some(IPV4_ROUTE_HEADER),
            Some(IPV6_DEFAULT_ROUTE)
        ));
        // Dual-stack keeps the IPv4 fallback behavior.
        assert!(!ipv6_only_default_route(
            Some(&ipv4_with_default),
            Some(&ipv6_with_default)
        ));
        // IPv4-only, and the kernel's unreachable ::/0 entry on lo.
        assert!(!ipv6_only_default_route(
            Some(&ipv4_with_default),
            Some(IPV6_LOOPBACK_UNREACHABLE)
        ));
        assert!(!ipv6_only_default_route(
            Some(IPV4_ROUTE_HEADER),
            Some(&format!("{IPV6_SUBNET_ROUTE}{IPV6_LOOPBACK_UNREACHABLE}"))
        ));
        // Unreadable tables keep the IPv4-only default.
        assert!(!ipv6_only_default_route(None, Some(IPV6_DEFAULT_ROUTE)));
        assert!(!ipv6_only_default_route(Some(IPV4_ROUTE_HEADER), None));
    }

    #[test]
    fn down_or_reject_default_routes_are_not_uplinks() {
        let down_ipv4 = format!(
            "{IPV4_ROUTE_HEADER}eth0\t00000000\t0100A8C0\t0002\t0\t0\t100\t00000000\t0\t0\t0\n"
        );
        assert!(!has_ipv4_default_route(&down_ipv4));
        let reject_ipv6 = IPV6_DEFAULT_ROUTE.replace("00000003", "00000201");
        assert!(!has_ipv6_default_route(&reject_ipv6));
    }

    #[test]
    fn runtime_config_keeps_ipv6_egress_disabled_by_default() {
        let config = PolicyDnsRuntimeConfig::for_epoch(3).unwrap();
        assert!(!config.ipv6_egress);
        assert!(config.with_ipv6_egress(true).ipv6_egress);
    }

    #[test]
    fn production_pools_and_store_capacity_expand_together() {
        let config = PolicyDnsRuntimeConfig::for_epoch(7).unwrap();
        let ipv4_capacity = 1_usize << (32 - config.ipv4_cidr.prefix_len());
        let ipv6_capacity = 1_usize << (128 - config.ipv6_cidr.prefix_len());
        assert_eq!(ipv4_capacity, 512);
        assert_eq!(ipv6_capacity, 512);
        assert_eq!(MAX_MAPPINGS, ipv4_capacity + ipv6_capacity);
    }
}
