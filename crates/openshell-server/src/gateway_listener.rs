// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::compute::GatewayListenerRequirement;
use openshell_core::{Error, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
#[cfg(target_os = "linux")]
use std::path::Path;
use tokio::net::TcpListener;
use tracing::{info, warn};

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
    allows_nested_container_wildcard_fallback: bool,
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
            allows_nested_container_wildcard_fallback: false,
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
        add_callback_listener_spec(&mut specs, *address, requirement);
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
        add_callback_listener_spec(&mut specs, address, requirement);
    }

    for requirement in requirements {
        let GatewayListenerRequirement::LoopbackInterface { .. } = requirement else {
            continue;
        };
        validate_gateway_listener_requirement(bind_address, requirement)?;
        let address = SocketAddr::from(([127, 0, 0, 1], bind_address.port()));
        validate_resolved_gateway_listener(bind_address, address)?;
        add_callback_listener_spec(&mut specs, address, requirement);
    }

    Ok(specs)
}

fn add_callback_listener_spec(
    specs: &mut Vec<GatewayListenerSpec>,
    address: SocketAddr,
    requirement: &GatewayListenerRequirement,
) {
    let scope = GatewayListenerScope::ComputeDriverCallback;
    if let Some(existing) = specs
        .iter_mut()
        .find(|existing| listener_covers(existing.address, address))
    {
        if existing.scope == GatewayListenerScope::Primary {
            return;
        }
        if existing.address == address {
            return;
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
        return;
    }
    specs.push(callback_listener_spec(address, requirement));
}

fn callback_listener_spec(
    address: SocketAddr,
    requirement: &GatewayListenerRequirement,
) -> GatewayListenerSpec {
    let allows_nested_container_wildcard_fallback = matches!(
        requirement,
        GatewayListenerRequirement::Exact {
            allow_nested_container_wildcard_fallback: true,
            ..
        }
    );
    GatewayListenerSpec {
        address,
        scope: GatewayListenerScope::ComputeDriverCallback,
        covered_addresses: Vec::new(),
        provenance: Some(GatewayListenerProvenance {
            driver_name: requirement.driver_name().to_string(),
            reason: requirement.reason().to_string(),
        }),
        allows_nested_container_wildcard_fallback,
    }
}

fn validate_gateway_listener_requirement(
    primary_listener: SocketAddr,
    requirement: &GatewayListenerRequirement,
) -> Result<()> {
    match requirement {
        GatewayListenerRequirement::Exact { address, .. } => {
            validate_resolved_gateway_listener(primary_listener, *address)
        }
        GatewayListenerRequirement::DefaultRouteInterface { .. }
        | GatewayListenerRequirement::LoopbackInterface { .. } => Ok(()),
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
        let listener = bind_gateway_listener(spec.address, ipv6_only).await;
        let listener = match listener {
            Ok(listener) => listener,
            Err(err) => {
                let Some(fallback_spec) = nested_podman_wildcard_fallback_spec(
                    &specs,
                    spec,
                    err.kind(),
                    running_in_linux_container(),
                ) else {
                    return Err(Error::transport(format!(
                        "failed to bind to {}: {err}",
                        spec.address
                    )));
                };

                // The wildcard cannot coexist with the already-bound loopback
                // socket on the same port. Dropping the partial listener set is
                // safe because none of it has been returned to the server yet.
                drop(listeners);
                let listener = bind_gateway_listener(fallback_spec.address, false)
                    .await
                    .map_err(|fallback_err| {
                        Error::transport(format!(
                            "failed to bind Podman callback address {} ({err}); scoped wildcard fallback {} also failed: {fallback_err}",
                            spec.address, fallback_spec.address
                        ))
                    })?;
                let local_addr = listener.local_addr().unwrap_or(fallback_spec.address);
                let fallback_spec = fallback_spec.bind_to(local_addr);
                warn!(
                    address = %local_addr,
                    unavailable_callback_address = %spec.address,
                    listener_purpose = "nested-podman-callback-fallback",
                    authorization_scope = "primary-on-loopback; sandbox-callable-grpc-only-on-other-ipv4-interfaces",
                    "Podman bridge address is not available yet; gateway callback listener is exposed on all container IPv4 interfaces for this gateway process"
                );
                return Ok(vec![BoundGatewayListener {
                    listener,
                    spec: fallback_spec,
                }]);
            }
        };
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

fn nested_podman_wildcard_fallback_spec(
    specs: &[GatewayListenerSpec],
    failed_spec: &GatewayListenerSpec,
    error_kind: ErrorKind,
    running_in_container: bool,
) -> Option<GatewayListenerSpec> {
    if !running_in_container || error_kind != ErrorKind::AddrNotAvailable || specs.len() != 2 {
        return None;
    }

    let primary = specs
        .iter()
        .find(|spec| spec.scope == GatewayListenerScope::Primary)?;
    let callback = specs.iter().find(|spec| {
        spec.scope == GatewayListenerScope::ComputeDriverCallback && *spec == failed_spec
    })?;
    let callback_provenance = callback.provenance.as_ref()?;
    let (IpAddr::V4(primary_ip), IpAddr::V4(callback_ip)) =
        (primary.address.ip(), callback.address.ip())
    else {
        return None;
    };
    if !primary_ip.is_loopback()
        || !callback_ip.is_private()
        || primary.address.port() == 0
        || primary.address.port() != callback.address.port()
        || !callback.allows_nested_container_wildcard_fallback
        || callback_provenance.driver_name != "podman"
    {
        return None;
    }

    Some(GatewayListenerSpec {
        address: SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, primary.address.port())),
        // The broader socket is callback-only by default. Only connections
        // addressed to the original loopback endpoint retain primary scope.
        scope: GatewayListenerScope::ComputeDriverCallback,
        covered_addresses: vec![CoveredGatewayAddress {
            address: primary.address,
            scope: GatewayListenerScope::Primary,
        }],
        provenance: Some(callback_provenance.clone()),
        allows_nested_container_wildcard_fallback: true,
    })
}

#[cfg(target_os = "linux")]
fn running_in_linux_container() -> bool {
    Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists()
}

#[cfg(not(target_os = "linux"))]
fn running_in_linux_container() -> bool {
    false
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
        GatewayListenerProvenance, GatewayListenerScope, GatewayListenerSpec,
        bind_gateway_listeners, gateway_listener_specs,
        gateway_listener_specs_with_default_route_ip, nested_podman_wildcard_fallback_spec,
    };
    use crate::compute::GatewayListenerRequirement;
    use std::io::ErrorKind;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::net::TcpListener;

    #[test]
    fn gateway_listener_specs_reuse_primary_when_wildcard_covers_driver_address() {
        let primary: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let docker: SocketAddr = "172.18.0.1:8080".parse().unwrap();
        let requirements = [
            docker_listener_requirement(docker),
            docker_listener_requirement(docker),
        ];

        assert_eq!(
            gateway_listener_specs(primary, &requirements).unwrap(),
            vec![primary_listener_spec(primary)]
        );
    }

    #[test]
    fn gateway_listener_scope_for_reused_primary_remains_primary() {
        let primary: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let docker: SocketAddr = "172.18.0.1:8080".parse().unwrap();
        let loopback: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let [spec] = gateway_listener_specs(primary, &[docker_listener_requirement(docker)])
            .unwrap()
            .try_into()
            .unwrap();

        assert_eq!(
            spec.scope_for_local_addr(docker),
            GatewayListenerScope::Primary,
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
                    allows_nested_container_wildcard_fallback: false,
                },
                GatewayListenerSpec {
                    address: docker,
                    scope: GatewayListenerScope::ComputeDriverCallback,
                    covered_addresses: Vec::new(),
                    provenance: Some(GatewayListenerProvenance {
                        driver_name: "docker".to_string(),
                        reason: "managed bridge".to_string(),
                    }),
                    allows_nested_container_wildcard_fallback: false,
                },
            ]
        );
    }

    #[test]
    fn gateway_listener_specs_accept_safe_external_driver_requirement() {
        let primary: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let requirement = GatewayListenerRequirement::Exact {
            address: "172.18.0.1:8080".parse().unwrap(),
            driver_name: "external-test".to_string(),
            reason: "external bridge".to_string(),
            allow_nested_container_wildcard_fallback: false,
        };

        let specs = gateway_listener_specs(primary, &[requirement]).unwrap();
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[1].address, "172.18.0.1:8080".parse().unwrap());
        assert_eq!(specs[1].scope, GatewayListenerScope::ComputeDriverCallback);
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
    fn gateway_listener_specs_reuse_primary_when_it_covers_podman_exact() {
        let primary: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let podman_gateway: SocketAddr = "10.89.1.1:8080".parse().unwrap();

        assert_eq!(
            gateway_listener_specs(primary, &[podman_listener_requirement(podman_gateway)],)
                .unwrap(),
            vec![primary_listener_spec(primary)]
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
    fn gateway_listener_specs_reuse_ipv4_wildcard_for_default_route() {
        let primary: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let default_route_ip = "192.168.20.20".parse().unwrap();
        assert_eq!(
            gateway_listener_specs_with_default_route_ip(
                primary,
                &[podman_default_route_listener_requirement()],
                Some(default_route_ip),
            )
            .unwrap(),
            vec![primary_listener_spec(primary)]
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
    fn gateway_listener_specs_reuse_wildcard_primary_for_podman_loopback() {
        let primary = "0.0.0.0:8080".parse().unwrap();

        assert_eq!(
            gateway_listener_specs(primary, &[podman_loopback_listener_requirement()]).unwrap(),
            vec![primary_listener_spec(primary)]
        );
    }

    #[test]
    fn gateway_listener_specs_reuse_matching_primary_address() {
        let primary = "127.0.0.1:8080".parse().unwrap();

        assert_eq!(
            gateway_listener_specs(primary, &[podman_loopback_listener_requirement()]).unwrap(),
            vec![primary_listener_spec(primary)]
        );
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
    fn gateway_listener_specs_validate_selector_independently_of_driver_name() {
        let primary: SocketAddr = "192.168.20.20:8080".parse().unwrap();
        let requirement = GatewayListenerRequirement::LoopbackInterface {
            driver_name: "docker".to_string(),
            reason: "wrong selector".to_string(),
        };

        let specs = gateway_listener_specs(primary, &[requirement]).unwrap();
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].address, primary);
        assert_eq!(specs[1].address, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(specs[1].scope, GatewayListenerScope::ComputeDriverCallback);
    }

    #[test]
    fn nested_podman_fallback_is_callback_only_off_loopback() {
        let primary: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let podman_gateway: SocketAddr = "10.89.0.1:8080".parse().unwrap();
        let specs = gateway_listener_specs(primary, &[podman_listener_requirement(podman_gateway)])
            .unwrap();

        let fallback = nested_podman_wildcard_fallback_spec(
            &specs,
            &specs[1],
            ErrorKind::AddrNotAvailable,
            true,
        )
        .expect("eligible nested Podman bind failure should use the scoped fallback");

        assert_eq!(fallback.address, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(
            fallback.scope_for_local_addr(primary),
            GatewayListenerScope::Primary
        );
        assert_eq!(
            fallback.scope_for_local_addr(podman_gateway),
            GatewayListenerScope::ComputeDriverCallback
        );
        assert_eq!(
            fallback.scope_for_local_addr("172.17.0.2:8080".parse().unwrap()),
            GatewayListenerScope::ComputeDriverCallback
        );
    }

    #[test]
    fn nested_podman_fallback_rejects_unrelated_bind_failures() {
        let primary: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let podman_gateway: SocketAddr = "10.89.0.1:8080".parse().unwrap();
        let specs = gateway_listener_specs(primary, &[podman_listener_requirement(podman_gateway)])
            .unwrap();

        assert!(
            nested_podman_wildcard_fallback_spec(
                &specs,
                &specs[1],
                ErrorKind::AddrNotAvailable,
                false,
            )
            .is_none(),
            "the gateway must be running in a Linux container"
        );
        assert!(
            nested_podman_wildcard_fallback_spec(&specs, &specs[1], ErrorKind::AddrInUse, true,)
                .is_none(),
            "only a not-yet-present interface is eligible"
        );

        let docker_specs =
            gateway_listener_specs(primary, &[docker_listener_requirement(podman_gateway)])
                .unwrap();
        assert!(
            nested_podman_wildcard_fallback_spec(
                &docker_specs,
                &docker_specs[1],
                ErrorKind::AddrNotAvailable,
                true,
            )
            .is_none(),
            "the fallback must remain specific to Podman"
        );

        let untrusted_podman_requirement = GatewayListenerRequirement::Exact {
            address: podman_gateway,
            driver_name: "podman".to_string(),
            reason: "external or rootless Podman address".to_string(),
            allow_nested_container_wildcard_fallback: false,
        };
        let untrusted_podman_specs =
            gateway_listener_specs(primary, &[untrusted_podman_requirement]).unwrap();
        assert!(
            nested_podman_wildcard_fallback_spec(
                &untrusted_podman_specs,
                &untrusted_podman_specs[1],
                ErrorKind::AddrNotAvailable,
                true,
            )
            .is_none(),
            "the trusted rootful managed-bridge marker is required"
        );
    }

    #[test]
    fn nested_podman_fallback_rejects_non_private_callback_address() {
        let primary: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let public_callback: SocketAddr = "203.0.113.1:8080".parse().unwrap();
        let specs =
            gateway_listener_specs(primary, &[podman_listener_requirement(public_callback)])
                .unwrap();

        assert!(
            nested_podman_wildcard_fallback_spec(
                &specs,
                &specs[1],
                ErrorKind::AddrNotAvailable,
                true,
            )
            .is_none()
        );
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
            allow_nested_container_wildcard_fallback: false,
        }
    }

    fn podman_listener_requirement(address: SocketAddr) -> GatewayListenerRequirement {
        GatewayListenerRequirement::Exact {
            address,
            driver_name: "podman".to_string(),
            reason: "Podman managed bridge".to_string(),
            allow_nested_container_wildcard_fallback: true,
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
            allows_nested_container_wildcard_fallback: false,
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
            allows_nested_container_wildcard_fallback: reason == "Podman managed bridge",
        }
    }
}
