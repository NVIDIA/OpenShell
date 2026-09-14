// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime-owned policy DNS listeners for combined Linux supervisors.

use super::resolver::MAX_DNS_MESSAGE_BYTES;
use super::store::{ResolvedEndpointStore, StoreConfig, SyntheticPools};
use super::{PolicyDnsService, SocketTrustedResolver, wire};
use crate::opa::OpaEngine;
use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::net::set_tcp_nodelay_best_effort;
use openshell_ocsf::{ConfigStateChangeBuilder, SeverityId, StateId, StatusId, ocsf_emit};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

const IPV4_POOL_PREFIX: u8 = 23;
const IPV6_POOL_PREFIX: u8 = 119;
const IPV4_EPOCH_WINDOWS: u64 = 1 << (IPV4_POOL_PREFIX - 15);
const MAX_MAPPINGS: usize = 1024;
const MAX_CONCURRENT_UDP_QUERIES: usize = 64;

#[derive(Debug, Clone)]
pub(crate) struct PolicyDnsRuntimeConfig {
    pub(crate) ipv4_cidr: ipnet::Ipv4Net,
    pub(crate) ipv6_cidr: ipnet::Ipv6Net,
    pools: SyntheticPools,
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

        let pools = SyntheticPools::new(
            ipv4_cidr.network()..=ipv4_cidr.broadcast(),
            ipv6_cidr.network()..=ipv6_cidr.broadcast(),
        )
        .map_err(|error| miette::miette!(error.to_string()))?;
        Ok(Self {
            ipv4_cidr,
            ipv6_cidr,
            pools,
        })
    }
}

pub(crate) struct PolicyDnsRuntime {
    pub(crate) store: Arc<ResolvedEndpointStore>,
    tasks: Vec<JoinHandle<()>>,
}

impl PolicyDnsRuntime {
    pub(crate) fn start(
        policy: Arc<OpaEngine>,
        udp: tokio::net::UdpSocket,
        tcp: tokio::net::TcpListener,
        trusted_host_gateway: Option<IpAddr>,
        config: PolicyDnsRuntimeConfig,
        engine_ready: tokio::sync::watch::Receiver<bool>,
    ) -> Result<Self> {
        let upstream = trusted_resolver_from_resolv_conf()?;
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
                    // Docker and Podman do not currently prove usable IPv6
                    // egress. Return NOERROR/NODATA for AAAA so dual-stack
                    // clients can fall back to the usable IPv4 path.
                    if let Ok(response) =
                        wire::handle_udp_query_with_ipv6(&service, &request, false).await
                    {
                        let _ = udp.send_to(&response, peer).await;
                    }
                });
            }
        });

        let mut tcp_engine_ready = engine_ready;
        let tcp_task = tokio::spawn(async move {
            if tcp_engine_ready.wait_for(|ready| *ready).await.is_err() {
                return;
            }
            loop {
                let Ok((mut stream, _)) = tcp.accept().await else {
                    break;
                };
                set_tcp_nodelay_best_effort(&stream);
                let service = service.clone();
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
                            wire::handle_tcp_query_with_ipv6(&service, &frame, false).await
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
        let expiry_store = store.clone();
        let expiry_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                interval.tick().await;
                let _ = expiry_store.expire(std::time::Instant::now());
            }
        });

        ocsf_emit!(
            ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .state(StateId::Enabled, "ready")
                .message(format!("Policy DNS listening on {address}"))
                .build()
        );
        Ok(Self {
            store,
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
