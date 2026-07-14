// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared external destination validation and upstream dial boundary.

use super::{
    implicit_allowed_ips_for_ip_host, is_host_gateway_alias, parse_allowed_ips,
    resolve_and_check_allowed_ips, resolve_and_check_declared_endpoint,
    resolve_and_check_trusted_gateway, resolve_and_reject_internal,
};
use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpStream;

/// Inputs needed to apply the current SSRF and endpoint destination policy.
pub(super) struct DestinationRequest<'a> {
    pub(super) host: &'a str,
    pub(super) normalized_host: &'a str,
    pub(super) port: u16,
    pub(super) sandbox_entrypoint_pid: u32,
    pub(super) trusted_host_gateway: Option<IpAddr>,
    pub(super) raw_allowed_ips: Vec<String>,
    pub(super) exact_declared_endpoint_host: bool,
}

/// Destination-validation branch that rejected an egress request.
///
/// Adapters use this classification to preserve their existing HTTP response
/// and OCSF message shapes while sharing the underlying validation logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DestinationDenialKind {
    TrustedGateway,
    InvalidAllowedIps,
    AllowedIps,
    DeclaredEndpoint,
    InternalAddress,
}

#[derive(Debug)]
pub(super) struct DestinationDenial {
    pub(super) kind: DestinationDenialKind,
    pub(super) reason: String,
}

impl DestinationDenial {
    fn new(kind: DestinationDenialKind, reason: String) -> Self {
        Self { kind, reason }
    }
}

/// Validated, but not yet opened, upstream destination.
///
/// The explicit proxy adapter controls when `connect` is called so CONNECT and
/// forward HTTP retain their current upstream-dial timing during the refactor.
pub(super) struct UpstreamConnector {
    host: String,
    port: u16,
    addrs: Vec<SocketAddr>,
}

impl UpstreamConnector {
    pub(super) fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    pub(super) async fn connect(&self) -> std::io::Result<TcpStream> {
        tracing::debug!(
            host = %self.host,
            port = self.port,
            address_count = self.addrs.len(),
            "Opening validated upstream connection"
        );
        TcpStream::connect(self.addrs.as_slice()).await
    }

    fn new(host: &str, port: u16, addrs: Vec<SocketAddr>) -> Self {
        Self {
            host: host.to_string(),
            port,
            addrs,
        }
    }
}

/// Resolve and validate a destination using the existing proxy security rules.
pub(super) async fn validate_destination(
    request: DestinationRequest<'_>,
) -> Result<UpstreamConnector, DestinationDenial> {
    let DestinationRequest {
        host,
        normalized_host,
        port,
        sandbox_entrypoint_pid,
        trusted_host_gateway,
        mut raw_allowed_ips,
        exact_declared_endpoint_host,
    } = request;

    if raw_allowed_ips.is_empty() {
        raw_allowed_ips = implicit_allowed_ips_for_ip_host(host);
    }

    #[allow(clippy::if_not_else)]
    let addrs = if is_host_gateway_alias(normalized_host)
        && let Some(gateway) = trusted_host_gateway
    {
        resolve_and_check_trusted_gateway(host, port, gateway, sandbox_entrypoint_pid)
            .await
            .map_err(|reason| {
                DestinationDenial::new(DestinationDenialKind::TrustedGateway, reason)
            })?
    } else if !raw_allowed_ips.is_empty() {
        let networks = parse_allowed_ips(&raw_allowed_ips).map_err(|reason| {
            DestinationDenial::new(DestinationDenialKind::InvalidAllowedIps, reason)
        })?;
        resolve_and_check_allowed_ips(host, port, &networks, sandbox_entrypoint_pid)
            .await
            .map_err(|reason| DestinationDenial::new(DestinationDenialKind::AllowedIps, reason))?
    } else if exact_declared_endpoint_host {
        resolve_and_check_declared_endpoint(host, port, sandbox_entrypoint_pid)
            .await
            .map_err(|reason| {
                DestinationDenial::new(DestinationDenialKind::DeclaredEndpoint, reason)
            })?
    } else {
        resolve_and_reject_internal(host, port, sandbox_entrypoint_pid)
            .await
            .map_err(|reason| {
                DestinationDenial::new(DestinationDenialKind::InternalAddress, reason)
            })?
    };

    Ok(UpstreamConnector::new(host, port, addrs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn request(host: &str) -> DestinationRequest<'_> {
        DestinationRequest {
            host,
            normalized_host: host,
            port: 80,
            sandbox_entrypoint_pid: 0,
            trusted_host_gateway: None,
            raw_allowed_ips: vec![],
            exact_declared_endpoint_host: false,
        }
    }

    #[tokio::test]
    async fn default_mode_classifies_loopback_as_internal_address() {
        let denial = validate_destination(request("127.0.0.1"))
            .await
            .err()
            .expect("loopback must be denied");

        assert_eq!(denial.kind, DestinationDenialKind::InternalAddress);
    }

    #[tokio::test]
    async fn invalid_allowed_ips_has_a_distinct_denial_kind() {
        let mut request = request("api.example.test");
        request.raw_allowed_ips = vec!["not-an-ip".to_string()];
        let denial = validate_destination(request)
            .await
            .err()
            .expect("invalid allowed_ips must be denied");

        assert_eq!(denial.kind, DestinationDenialKind::InvalidAllowedIps);
    }

    #[tokio::test]
    async fn declared_endpoint_preserves_its_denial_classification() {
        let mut request = request("127.0.0.1");
        request.exact_declared_endpoint_host = true;
        let denial = validate_destination(request)
            .await
            .err()
            .expect("declared loopback must remain denied");

        assert_eq!(denial.kind, DestinationDenialKind::DeclaredEndpoint);
    }

    #[tokio::test]
    async fn trusted_gateway_preserves_its_denial_classification() {
        let mut request = request("host.openshell.internal");
        request.trusted_host_gateway = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let denial = validate_destination(request)
            .await
            .err()
            .expect("loopback cannot be a trusted gateway");

        assert_eq!(denial.kind, DestinationDenialKind::TrustedGateway);
    }
}
