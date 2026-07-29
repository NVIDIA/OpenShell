// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::{Error, Result};
use std::net::SocketAddr;
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
    extra_addresses: &[SocketAddr],
) -> Vec<GatewayListenerSpec> {
    let mut specs = vec![GatewayListenerSpec::new(
        bind_address,
        GatewayListenerScope::Primary,
    )];
    for address in extra_addresses {
        let scope = GatewayListenerScope::ComputeDriverCallback;
        if let Some(existing) = specs
            .iter()
            .position(|existing| listener_covers(existing.address, *address))
        {
            let existing = &mut specs[existing];
            if existing.address != *address
                && !existing
                    .covered_addresses
                    .iter()
                    .any(|covered| covered.address == *address)
            {
                existing.covered_addresses.push(CoveredGatewayAddress {
                    address: *address,
                    scope,
                });
            }
        } else {
            specs.push(GatewayListenerSpec::new(*address, scope));
        }
    }
    specs
}

pub async fn bind_gateway_listeners(
    bind_address: SocketAddr,
    extra_addresses: &[SocketAddr],
) -> Result<Vec<BoundGatewayListener>> {
    let specs = gateway_listener_specs(bind_address, extra_addresses);
    let mut listeners = Vec::with_capacity(specs.len());
    for spec in specs {
        let listener = TcpListener::bind(spec.address)
            .await
            .map_err(|e| Error::transport(format!("failed to bind to {}: {e}", spec.address)))?;
        let local_addr = listener.local_addr().unwrap_or(spec.address);
        info!(address = %local_addr, "Server listening");
        listeners.push(BoundGatewayListener {
            listener,
            spec: spec.bind_to(local_addr),
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

fn listener_covers(existing: SocketAddr, requested: SocketAddr) -> bool {
    if existing == requested {
        return true;
    }
    if existing.port() != requested.port() {
        return false;
    }

    match (existing.ip(), requested.ip()) {
        (std::net::IpAddr::V4(existing), std::net::IpAddr::V4(_)) => existing.is_unspecified(),
        (std::net::IpAddr::V6(existing), std::net::IpAddr::V6(_)) => existing.is_unspecified(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CoveredGatewayAddress, GatewayListenerScope, GatewayListenerSpec, bind_gateway_listeners,
        gateway_listener_specs,
    };
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::net::TcpListener;

    #[test]
    fn gateway_listener_specs_track_driver_address_covered_by_wildcard() {
        let primary: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let docker: SocketAddr = "172.18.0.1:8080".parse().unwrap();

        assert_eq!(
            gateway_listener_specs(primary, &[docker, docker]),
            vec![GatewayListenerSpec {
                address: primary,
                scope: GatewayListenerScope::Primary,
                covered_addresses: vec![CoveredGatewayAddress {
                    address: docker,
                    scope: GatewayListenerScope::ComputeDriverCallback,
                }],
            }]
        );
    }

    #[test]
    fn gateway_listener_scope_for_local_addr_uses_covered_address_scope() {
        let primary: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let docker: SocketAddr = "172.18.0.1:8080".parse().unwrap();
        let loopback: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let [spec] = gateway_listener_specs(primary, &[docker])
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

        assert_eq!(
            gateway_listener_specs(primary, &[docker, docker]),
            vec![
                GatewayListenerSpec {
                    address: primary,
                    scope: GatewayListenerScope::Primary,
                    covered_addresses: Vec::new(),
                },
                GatewayListenerSpec {
                    address: docker,
                    scope: GatewayListenerScope::ComputeDriverCallback,
                    covered_addresses: Vec::new(),
                },
            ]
        );
    }

    #[tokio::test]
    async fn failed_bind_does_not_return_partially_bound_listeners() {
        let occupied_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let occupied_address = occupied_listener.local_addr().unwrap();
        let continuation_reached = AtomicBool::new(false);
        let primary_address: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let result: openshell_core::Result<()> = async {
            let _listeners = bind_gateway_listeners(primary_address, &[occupied_address]).await?;
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
}
