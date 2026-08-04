// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::compute::GatewayListenerRequirement;
use openshell_core::{ComputeDriverKind, Error, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpListener;
use tracing::info;

/// Authorization scope associated with a gateway listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayListenerScope {
    Primary,
    ComputeDriverCallback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoveredGatewayAddress {
    pub address: SocketAddr,
    pub scope: GatewayListenerScope,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayListenerSpec {
    pub address: SocketAddr,
    pub scope: GatewayListenerScope,
    covered_addresses: Vec<CoveredGatewayAddress>,
    provenance: Option<GatewayListenerProvenance>,
}

/// Diagnostic source of a driver-requested listener.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayListenerProvenance {
    pub driver_name: String,
    pub reason: String,
}

/// A gateway listener together with the context needed to serve it.
pub struct BoundGatewayListener {
    pub listener: TcpListener,
    pub spec: GatewayListenerSpec,
}

impl GatewayListenerSpec {
    pub fn new(address: SocketAddr, scope: GatewayListenerScope) -> Self {
        Self {
            address,
            scope,
            covered_addresses: Vec::new(),
            provenance: None,
        }
    }

    pub fn scope_for_local_addr(&self, local_addr: SocketAddr) -> GatewayListenerScope {
        self.covered_addresses
            .iter()
            .find(|covered| covered.address == local_addr)
            .map_or(self.scope, |covered| covered.scope)
    }

    fn bind_to(mut self, local_addr: SocketAddr) -> Self {
        let requested_addr = self.address;
        self.address = local_addr;
        self.covered_addresses =
            resolve_bound_covered_addresses(&self.covered_addresses, requested_addr, local_addr);
        self
    }
}

fn gateway_listener_specs(
    bind_address: SocketAddr,
    requirements: &[GatewayListenerRequirement],
) -> Result<Vec<GatewayListenerSpec>> {
    let needs_default_route_resolution = requirements.iter().any(|requirement| {
        matches!(
            requirement,
            GatewayListenerRequirement::DefaultRouteInterface { .. }
        )
    });
    let default_route_ip = if needs_default_route_resolution {
        Some(gateway_default_route_ip()?)
    } else {
        None
    };
    gateway_listener_specs_with_default_route_ip(bind_address, requirements, default_route_ip)
}

fn gateway_listener_specs_with_default_route_ip(
    bind_address: SocketAddr,
    requirements: &[GatewayListenerRequirement],
    default_route_ip: Option<IpAddr>,
) -> Result<Vec<GatewayListenerSpec>> {
    let mut specs = vec![GatewayListenerSpec::new(
        bind_address,
        GatewayListenerScope::Primary,
    )];

    // Resolve exact requirements first so they can satisfy a later semantic
    // requirement regardless of driver response ordering.
    for requirement in requirements {
        let GatewayListenerRequirement::Exact { address, .. } = requirement else {
            continue;
        };
        validate_gateway_listener_requirement(bind_address, requirement)?;
        add_callback_listener_spec(&mut specs, *address, requirement)?;
    }

    for requirement in requirements {
        let GatewayListenerRequirement::DefaultRouteInterface { .. } = requirement else {
            continue;
        };
        validate_gateway_listener_requirement(bind_address, requirement)?;
        let Some(ip) = default_route_ip else {
            return Err(Error::config(format!(
                "compute driver '{}' requested the gateway default-route interface, but no IPv4 source address was resolved (reason: {})",
                requirement.driver_name(),
                requirement.reason()
            )));
        };
        if !gateway_default_route_ip_is_usable(ip) {
            return Err(Error::config(format!(
                "compute driver '{}' requested the gateway default-route interface, but its resolved address {ip} is not a private IPv4 address (reason: {})",
                requirement.driver_name(),
                requirement.reason()
            )));
        }
        let address = SocketAddr::new(ip, bind_address.port());
        validate_resolved_gateway_listener(bind_address, address)?;
        add_callback_listener_spec(&mut specs, address, requirement)?;
    }

    for requirement in requirements {
        let GatewayListenerRequirement::LoopbackInterface { .. } = requirement else {
            continue;
        };
        validate_gateway_listener_requirement(bind_address, requirement)?;
        let address = SocketAddr::from(([127, 0, 0, 1], bind_address.port()));
        validate_resolved_gateway_listener(bind_address, address)?;
        add_callback_listener_spec(&mut specs, address, requirement)?;
    }

    Ok(specs)
}

fn add_callback_listener_spec(
    specs: &mut Vec<GatewayListenerSpec>,
    address: SocketAddr,
    requirement: &GatewayListenerRequirement,
) -> Result<()> {
    let scope = GatewayListenerScope::ComputeDriverCallback;
    if let Some(existing) = specs
        .iter_mut()
        .find(|existing| listener_covers(existing.address, address))
    {
        if existing.address == address {
            if existing.scope == GatewayListenerScope::Primary {
                return Err(Error::config(format!(
                    "compute driver '{}' requested gateway callback listener {address}, but it is the same address as the primary listener; callback-only authorization cannot be preserved",
                    requirement.driver_name()
                )));
            }
            return Ok(());
        }
        if !existing
            .covered_addresses
            .iter()
            .any(|covered| covered.address == address)
        {
            existing
                .covered_addresses
                .push(CoveredGatewayAddress { address, scope });
        }
        return Ok(());
    }
    specs.push(callback_listener_spec(address, requirement));
    Ok(())
}

fn callback_listener_spec(
    address: SocketAddr,
    requirement: &GatewayListenerRequirement,
) -> GatewayListenerSpec {
    GatewayListenerSpec {
        address,
        scope: GatewayListenerScope::ComputeDriverCallback,
        covered_addresses: Vec::new(),
        provenance: Some(GatewayListenerProvenance {
            driver_name: requirement.driver_name().to_string(),
            reason: requirement.reason().to_string(),
        }),
    }
}

fn validate_gateway_listener_requirement(
    primary_listener: SocketAddr,
    requirement: &GatewayListenerRequirement,
) -> Result<()> {
    match requirement {
        GatewayListenerRequirement::Exact {
            address,
            driver_name,
            ..
        } if driver_name == ComputeDriverKind::Docker.as_str()
            || driver_name == ComputeDriverKind::Podman.as_str() =>
        {
            validate_resolved_gateway_listener(primary_listener, *address)
        }
        GatewayListenerRequirement::DefaultRouteInterface { driver_name, .. }
        | GatewayListenerRequirement::LoopbackInterface { driver_name, .. }
            if driver_name == ComputeDriverKind::Podman.as_str() =>
        {
            Ok(())
        }
        _ => Err(Error::config(format!(
            "compute driver '{}' is not authorized to request this gateway listener selector",
            requirement.driver_name()
        ))),
    }
}

fn validate_resolved_gateway_listener(
    primary_listener: SocketAddr,
    requested_listener: SocketAddr,
) -> Result<()> {
    if requested_listener.ip().is_unspecified() {
        return Err(Error::config(format!(
            "compute driver requested wildcard gateway listener {requested_listener}"
        )));
    }
    if requested_listener.ip().is_multicast() {
        return Err(Error::config(format!(
            "compute driver requested multicast gateway listener {requested_listener}"
        )));
    }
    if requested_listener.port() == 0 {
        return Err(Error::config(format!(
            "compute driver requested zero-port gateway listener {requested_listener}"
        )));
    }
    if requested_listener.port() != primary_listener.port() {
        return Err(Error::config(format!(
            "compute driver requested gateway listener {requested_listener} with port {}, but the primary listener uses port {}",
            requested_listener.port(),
            primary_listener.port()
        )));
    }
    Ok(())
}

fn gateway_default_route_ip_is_usable(address: IpAddr) -> bool {
    matches!(address, IpAddr::V4(address) if address.is_private())
}

#[cfg(target_os = "linux")]
fn gateway_default_route_ip() -> Result<IpAddr> {
    // UDP connect performs a local route lookup without sending a packet. The
    // selected source address follows the IPv4 default route, matching pasta's
    // default upstream-interface selection.
    let socket =
        std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).map_err(|err| {
            Error::config(format!("failed to open default-route probe socket: {err}"))
        })?;
    socket
        .connect((std::net::Ipv4Addr::new(192, 0, 2, 1), 9))
        .map_err(|err| Error::config(format!("failed to resolve IPv4 default route: {err}")))?;
    socket
        .local_addr()
        .map(|address| address.ip())
        .map_err(|err| Error::config(format!("failed to read IPv4 default-route address: {err}")))
}

#[cfg(not(target_os = "linux"))]
fn gateway_default_route_ip() -> Result<IpAddr> {
    Err(Error::config(
        "default-route gateway listener requirements are supported only on Linux",
    ))
}

pub async fn bind_gateway_listeners(
    bind_address: SocketAddr,
    requirements: &[GatewayListenerRequirement],
) -> Result<Vec<BoundGatewayListener>> {
    let specs = gateway_listener_specs(bind_address, requirements)?;
    let mut listeners = Vec::with_capacity(specs.len());
    for spec in &specs {
        let ipv6_only = matches!(
            spec.address.ip(),
            IpAddr::V6(address) if address.is_unspecified()
        ) && specs.iter().any(|candidate| {
            candidate.address.port() == spec.address.port() && candidate.address.is_ipv4()
        });
        let listener = bind_gateway_listener(spec.address, ipv6_only)
            .await
            .map_err(|e| Error::transport(format!("failed to bind to {}: {e}", spec.address)))?;
        let local_addr = listener.local_addr().unwrap_or(spec.address);
        match spec.scope {
            GatewayListenerScope::Primary => {
                info!(
                    address = %local_addr,
                    listener_purpose = "primary",
                    authorization_scope = "full-multiplexed-api",
                    "Gateway listener bound"
                );
            }
            GatewayListenerScope::ComputeDriverCallback => {
                let provenance = spec
                    .provenance
                    .as_ref()
                    .expect("callback listener spec must include provenance");
                info!(
                    address = %local_addr,
                    listener_purpose = "compute-driver-callback",
                    driver = %provenance.driver_name,
                    reason = %provenance.reason,
                    authorization_scope = "sandbox-callable-grpc-only",
                    "Gateway listener bound"
                );
            }
        }
        listeners.push(BoundGatewayListener {
            listener,
            spec: spec.clone().bind_to(local_addr),
        });
    }
    Ok(listeners)
}

fn resolve_bound_covered_addresses(
    covered_addresses: &[CoveredGatewayAddress],
    requested_listener_addr: SocketAddr,
    bound_listener_addr: SocketAddr,
) -> Vec<CoveredGatewayAddress> {
    covered_addresses
        .iter()
        .map(|covered| CoveredGatewayAddress {
            address: resolve_ephemeral_port(
                covered.address,
                requested_listener_addr,
                bound_listener_addr,
            ),
            scope: covered.scope,
        })
        .collect()
}

fn resolve_ephemeral_port(
    address: SocketAddr,
    requested_listener_addr: SocketAddr,
    bound_listener_addr: SocketAddr,
) -> SocketAddr {
    if requested_listener_addr.port() == 0 && address.port() == 0 {
        SocketAddr::new(address.ip(), bound_listener_addr.port())
    } else {
        address
    }
}

async fn bind_gateway_listener(
    address: SocketAddr,
    ipv6_only: bool,
) -> std::io::Result<TcpListener> {
    if ipv6_only {
        let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_reuse_address(true)?;
        socket.set_only_v6(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&address.into())?;
        socket.listen(1024)?;
        let listener: std::net::TcpListener = socket.into();
        return TcpListener::from_std(listener);
    }

    TcpListener::bind(address).await
}

fn listener_covers(existing: SocketAddr, requested: SocketAddr) -> bool {
    if existing == requested {
        return true;
    }
    if existing.port() != requested.port() {
        return false;
    }

    match (existing.ip(), requested.ip()) {
        (IpAddr::V4(existing), IpAddr::V4(_)) => existing.is_unspecified(),
        (IpAddr::V6(existing), IpAddr::V6(_)) => existing.is_unspecified(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CoveredGatewayAddress, GatewayListenerProvenance, GatewayListenerScope,
        GatewayListenerSpec, bind_gateway_listeners, gateway_listener_specs,
        gateway_listener_specs_with_default_route_ip,
    };
    use crate::compute::GatewayListenerRequirement;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::net::TcpListener;

    #[test]
    fn gateway_listener_specs_track_driver_address_covered_by_wildcard() {
        let primary: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let docker: SocketAddr = "172.18.0.1:8080".parse().unwrap();
        let requirements = [
            docker_listener_requirement(docker),
            docker_listener_requirement(docker),
        ];

        assert_eq!(
            gateway_listener_specs(primary, &requirements).unwrap(),
            vec![GatewayListenerSpec {
                address: primary,
                scope: GatewayListenerScope::Primary,
                covered_addresses: vec![CoveredGatewayAddress {
                    address: docker,
                    scope: GatewayListenerScope::ComputeDriverCallback,
                }],
                provenance: None,
            }]
        );
    }

    #[test]
    fn gateway_listener_scope_for_local_addr_uses_covered_address_scope() {
        let primary: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let docker: SocketAddr = "172.18.0.1:8080".parse().unwrap();
        let loopback: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let [spec] = gateway_listener_specs(primary, &[docker_listener_requirement(docker)])
            .unwrap()
            .try_into()
            .unwrap();

        assert_eq!(
            spec.scope_for_local_addr(docker),
            GatewayListenerScope::ComputeDriverCallback,
        );
        assert_eq!(
            spec.scope_for_local_addr(loopback),
            GatewayListenerScope::Primary,
        );
    }

    #[test]
    fn gateway_listener_specs_preserve_driver_callback_scope() {
        let primary: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let docker: SocketAddr = "172.18.0.1:8080".parse().unwrap();
        let requirements = [
            docker_listener_requirement(docker),
            docker_listener_requirement(docker),
        ];

        assert_eq!(
            gateway_listener_specs(primary, &requirements).unwrap(),
            vec![
                GatewayListenerSpec {
                    address: primary,
                    scope: GatewayListenerScope::Primary,
                    covered_addresses: Vec::new(),
                    provenance: None,
                },
                GatewayListenerSpec {
                    address: docker,
                    scope: GatewayListenerScope::ComputeDriverCallback,
                    covered_addresses: Vec::new(),
                    provenance: Some(GatewayListenerProvenance {
                        driver_name: "docker".to_string(),
                        reason: "managed bridge".to_string(),
                    }),
                },
            ]
        );
    }

    #[test]
    fn gateway_listener_specs_reject_unauthorized_external_driver() {
        let primary: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let requirement = GatewayListenerRequirement::Exact {
            address: "172.18.0.1:8080".parse().unwrap(),
            driver_name: "external-test".to_string(),
            reason: "external bridge".to_string(),
        };

        let err = gateway_listener_specs(primary, &[requirement]).unwrap_err();
        assert!(err.to_string().contains("not authorized"));
    }

    #[test]
    fn gateway_listener_specs_reject_invalid_exact_addresses() {
        let primary: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        for address in [
            "0.0.0.0:8080",
            "224.0.0.1:8080",
            "172.18.0.1:0",
            "172.18.0.1:9090",
        ] {
            let requirement = docker_listener_requirement(address.parse().unwrap());
            assert!(
                gateway_listener_specs(primary, &[requirement]).is_err(),
                "{address} should be rejected"
            );
        }
    }

    #[test]
    fn gateway_listener_specs_use_exact_podman_network_gateway() {
        let primary: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let podman_gateway: SocketAddr = "10.89.1.1:8080".parse().unwrap();

        assert_eq!(
            gateway_listener_specs(primary, &[podman_listener_requirement(podman_gateway)])
                .unwrap(),
            vec![
                primary_listener_spec(primary),
                callback_listener_spec(podman_gateway, "podman", "Podman managed bridge",),
            ]
        );
    }

    #[test]
    fn gateway_listener_specs_track_podman_exact_when_primary_covers_it() {
        let primary: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let podman_gateway: SocketAddr = "10.89.1.1:8080".parse().unwrap();

        assert_eq!(
            gateway_listener_specs(primary, &[podman_listener_requirement(podman_gateway)],)
                .unwrap(),
            vec![primary_listener_spec_with_covered(primary, podman_gateway,)]
        );
    }

    #[test]
    fn gateway_listener_specs_resolve_podman_default_route_source() {
        let primary: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let default_route_ip = "192.168.20.20".parse().unwrap();

        assert_eq!(
            gateway_listener_specs_with_default_route_ip(
                primary,
                &[podman_default_route_listener_requirement()],
                Some(default_route_ip),
            )
            .unwrap(),
            vec![
                primary_listener_spec(primary),
                callback_listener_spec(
                    "192.168.20.20:8080".parse().unwrap(),
                    "podman",
                    "rootless pasta upstream interface",
                ),
            ]
        );
    }

    #[test]
    fn gateway_listener_specs_reject_public_default_route_source() {
        let primary: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let err = gateway_listener_specs_with_default_route_ip(
            primary,
            &[podman_default_route_listener_requirement()],
            Some("203.0.113.20".parse().unwrap()),
        )
        .unwrap_err();

        assert!(err.to_string().contains("not a private IPv4 address"));
    }

    #[test]
    fn gateway_listener_specs_track_default_route_when_primary_is_ipv4_wildcard() {
        let primary: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let default_route_ip = "192.168.20.20".parse().unwrap();
        let callback = "192.168.20.20:8080".parse().unwrap();

        assert_eq!(
            gateway_listener_specs_with_default_route_ip(
                primary,
                &[podman_default_route_listener_requirement()],
                Some(default_route_ip),
            )
            .unwrap(),
            vec![primary_listener_spec_with_covered(primary, callback)]
        );
    }

    #[test]
    fn gateway_listener_specs_resolve_podman_loopback_separately() {
        let primary: SocketAddr = "192.168.20.20:8080".parse().unwrap();

        assert_eq!(
            gateway_listener_specs(primary, &[podman_loopback_listener_requirement()]).unwrap(),
            vec![
                primary_listener_spec(primary),
                callback_listener_spec(
                    "127.0.0.1:8080".parse().unwrap(),
                    "podman",
                    "Podman machine host forwarder",
                ),
            ]
        );
    }

    #[test]
    fn gateway_listener_specs_track_podman_loopback_when_wildcard_primary_covers_it() {
        let primary = "0.0.0.0:8080".parse().unwrap();
        let loopback = "127.0.0.1:8080".parse().unwrap();

        assert_eq!(
            gateway_listener_specs(primary, &[podman_loopback_listener_requirement()]).unwrap(),
            vec![primary_listener_spec_with_covered(primary, loopback)]
        );
    }

    #[test]
    fn gateway_listener_specs_reject_callback_matching_primary_address() {
        let primary = "127.0.0.1:8080".parse().unwrap();

        let err =
            gateway_listener_specs(primary, &[podman_loopback_listener_requirement()]).unwrap_err();

        assert!(
            err.to_string()
                .contains("same address as the primary listener")
        );
        assert!(err.to_string().contains("callback-only authorization"));
    }

    #[test]
    fn gateway_listener_specs_do_not_use_ipv6_listener_for_ipv4_loopback_requirement() {
        for primary in ["[::1]:8080", "[::]:8080"] {
            let primary = primary.parse().unwrap();
            let specs =
                gateway_listener_specs(primary, &[podman_loopback_listener_requirement()]).unwrap();

            assert_eq!(specs.len(), 2);
            assert_eq!(specs[1].address, SocketAddr::from(([127, 0, 0, 1], 8080)));
        }
    }

    #[test]
    fn gateway_listener_specs_reject_cross_driver_selector_authority() {
        let primary: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let requirement = GatewayListenerRequirement::LoopbackInterface {
            driver_name: "docker".to_string(),
            reason: "wrong selector".to_string(),
        };

        let err = gateway_listener_specs(primary, &[requirement]).unwrap_err();
        assert!(err.to_string().contains("not authorized"));
    }

    #[tokio::test]
    async fn failed_bind_does_not_return_partially_bound_listeners() {
        let occupied_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let occupied_address = occupied_listener.local_addr().unwrap();
        let continuation_reached = AtomicBool::new(false);
        let primary_address: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let result: openshell_core::Result<()> = async {
            let _listeners = bind_gateway_listeners(
                primary_address,
                &[docker_listener_requirement(occupied_address)],
            )
            .await?;
            continuation_reached.store(true, Ordering::SeqCst);
            Ok(())
        }
        .await;

        assert!(
            result.is_err(),
            "binding the occupied extra gateway address should fail"
        );
        assert!(
            !continuation_reached.load(Ordering::SeqCst),
            "binding must fail before returning a partial listener set"
        );
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    #[ignore = "flaky under concurrent test execution"]
    async fn gateway_listeners_bind_ipv6_wildcard_and_ipv4_callback_on_same_port() {
        let probe = TcpListener::bind("[::1]:0")
            .await
            .expect("IPv6 loopback probe should bind");
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let primary = format!("[::]:{port}").parse().unwrap();
        let listeners = bind_gateway_listeners(primary, &[podman_loopback_listener_requirement()])
            .await
            .expect("IPv6 wildcard and IPv4 callback listeners should both bind");

        assert_eq!(listeners.len(), 2);
        assert_eq!(listeners[0].spec.address, primary);
        assert_eq!(
            listeners[1].spec.address,
            SocketAddr::from(([127, 0, 0, 1], port))
        );
    }

    fn docker_listener_requirement(address: SocketAddr) -> GatewayListenerRequirement {
        GatewayListenerRequirement::Exact {
            address,
            driver_name: "docker".to_string(),
            reason: "managed bridge".to_string(),
        }
    }

    fn podman_listener_requirement(address: SocketAddr) -> GatewayListenerRequirement {
        GatewayListenerRequirement::Exact {
            address,
            driver_name: "podman".to_string(),
            reason: "Podman managed bridge".to_string(),
        }
    }

    fn podman_default_route_listener_requirement() -> GatewayListenerRequirement {
        GatewayListenerRequirement::DefaultRouteInterface {
            driver_name: "podman".to_string(),
            reason: "rootless pasta upstream interface".to_string(),
        }
    }

    fn podman_loopback_listener_requirement() -> GatewayListenerRequirement {
        GatewayListenerRequirement::LoopbackInterface {
            driver_name: "podman".to_string(),
            reason: "Podman machine host forwarder".to_string(),
        }
    }

    fn primary_listener_spec(address: SocketAddr) -> GatewayListenerSpec {
        GatewayListenerSpec {
            address,
            scope: GatewayListenerScope::Primary,
            covered_addresses: Vec::new(),
            provenance: None,
        }
    }

    fn primary_listener_spec_with_covered(
        address: SocketAddr,
        covered_address: SocketAddr,
    ) -> GatewayListenerSpec {
        GatewayListenerSpec {
            address,
            scope: GatewayListenerScope::Primary,
            covered_addresses: vec![CoveredGatewayAddress {
                address: covered_address,
                scope: GatewayListenerScope::ComputeDriverCallback,
            }],
            provenance: None,
        }
    }

    fn callback_listener_spec(
        address: SocketAddr,
        driver_name: &str,
        reason: &str,
    ) -> GatewayListenerSpec {
        GatewayListenerSpec {
            address,
            scope: GatewayListenerScope::ComputeDriverCallback,
            covered_addresses: Vec::new(),
            provenance: Some(GatewayListenerProvenance {
                driver_name: driver_name.to_string(),
                reason: reason.to_string(),
            }),
        }
    }
}
