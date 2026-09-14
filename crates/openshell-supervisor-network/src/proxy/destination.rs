// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::redundant_pub_crate,
    reason = "the destination primitives intentionally remain internal to the proxy crate"
)]

//! Shared external destination validation and upstream dial boundary.

use super::{
    BLOCKED_CONTROL_PLANE_PORTS, implicit_allowed_ips_for_ip_host, is_cloud_metadata_ip,
    is_host_gateway_alias, is_link_local_ip, parse_allowed_ips, resolve_and_check_allowed_ips,
    resolve_and_check_declared_endpoint, resolve_and_check_trusted_gateway,
    resolve_and_reject_internal,
};
use ipnet::IpNet;
use openshell_core::net::{connect_tcp_nodelay_best_effort, is_always_blocked_ip, is_internal_ip};
use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpStream;

/// Address-validation mode selected from the current endpoint configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AddressAuthorization {
    DefaultPublicOnly,
    ExplicitAllowedIps(Vec<IpNet>),
    ExactDeclaredHost,
    ImplicitIpLiteral(IpAddr),
    TrustedGatewayAlias {
        expected_ip: IpAddr,
    },
    /// Addresses already resolved and authorized by policy DNS. This mode must
    /// never resolve `DestinationRequest::host` again before constructing the
    /// unopened connector.
    #[allow(dead_code, reason = "used when the policy DNS adapter lands")]
    PinnedResolved(Vec<IpAddr>),
}

/// Fully materialized input to shared destination validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DestinationValidationPlan {
    pub(crate) address_authorization: AddressAuthorization,
}

/// Inputs needed to apply the current SSRF and endpoint destination policy.
pub(crate) struct DestinationRequest<'a> {
    pub(crate) host: &'a str,
    pub(crate) port: u16,
    pub(crate) sandbox_entrypoint_pid: u32,
    pub(crate) plan: &'a DestinationValidationPlan,
}

/// Destination-validation branch that rejected an egress request.
///
/// Adapters use this classification to preserve their existing HTTP response
/// and OCSF message shapes while sharing the underlying validation logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DestinationDenialKind {
    TrustedGateway,
    InvalidAllowedIps,
    AllowedIps,
    DeclaredEndpoint,
    InternalAddress,
}

#[derive(Debug)]
pub(crate) struct DestinationDenial {
    pub(crate) kind: DestinationDenialKind,
    pub(crate) reason: String,
}

impl DestinationDenial {
    fn new(kind: DestinationDenialKind, reason: String) -> Self {
        Self { kind, reason }
    }
}

/// Select one current destination-validation mode without changing precedence.
pub(crate) fn build_validation_plan(
    host: &str,
    normalized_host: &str,
    trusted_host_gateway: Option<IpAddr>,
    raw_allowed_ips: &[String],
    exact_declared_endpoint_host: bool,
) -> Result<DestinationValidationPlan, DestinationDenial> {
    let address_authorization = if is_host_gateway_alias(normalized_host)
        && let Some(expected_ip) = trusted_host_gateway
    {
        AddressAuthorization::TrustedGatewayAlias { expected_ip }
    } else if !raw_allowed_ips.is_empty() {
        AddressAuthorization::ExplicitAllowedIps(parse_allowed_ips(raw_allowed_ips).map_err(
            |reason| DestinationDenial::new(DestinationDenialKind::InvalidAllowedIps, reason),
        )?)
    } else if let Some(ip) = implicit_allowed_ips_for_ip_host(host)
        .first()
        .and_then(|raw| raw.parse::<IpAddr>().ok())
    {
        AddressAuthorization::ImplicitIpLiteral(ip)
    } else if exact_declared_endpoint_host {
        AddressAuthorization::ExactDeclaredHost
    } else {
        AddressAuthorization::DefaultPublicOnly
    };

    Ok(DestinationValidationPlan {
        address_authorization,
    })
}

/// Build the destination mode used by policy DNS after it has validated and
/// pinned a non-empty answer set for an endpoint.
#[allow(dead_code, reason = "used by the policy DNS adapter")]
pub(crate) fn build_pinned_validation_plan(
    addresses: Vec<IpAddr>,
) -> Result<DestinationValidationPlan, DestinationDenial> {
    if addresses.is_empty() {
        return Err(DestinationDenial::new(
            DestinationDenialKind::InvalidAllowedIps,
            "policy DNS produced an empty pinned address set".to_string(),
        ));
    }

    Ok(DestinationValidationPlan {
        address_authorization: AddressAuthorization::PinnedResolved(addresses),
    })
}

/// Filter resolver-provided addresses through a materialized destination plan.
///
/// This is the address-only policy-DNS boundary: it never reads a hosts file,
/// invokes a system lookup, or otherwise resolves `host`. Unlike CONNECT's
/// all-or-nothing validation, prohibited answers are removed so a trusted DNS
/// response containing both usable and unusable addresses can retain only the
/// usable subset.
#[allow(dead_code, reason = "used by the policy DNS adapter")]
pub(crate) fn filter_resolved_addresses(
    plan: &DestinationValidationPlan,
    host: &str,
    port: u16,
    resolved_ips: &[IpAddr],
) -> Result<Vec<IpAddr>, DestinationDenial> {
    let (kind, control_plane_blocked) = match &plan.address_authorization {
        AddressAuthorization::TrustedGatewayAlias { .. } => {
            (DestinationDenialKind::TrustedGateway, true)
        }
        AddressAuthorization::ExplicitAllowedIps(_)
        | AddressAuthorization::ImplicitIpLiteral(_) => (DestinationDenialKind::AllowedIps, true),
        AddressAuthorization::ExactDeclaredHost => (DestinationDenialKind::DeclaredEndpoint, true),
        AddressAuthorization::DefaultPublicOnly => (DestinationDenialKind::InternalAddress, false),
        AddressAuthorization::PinnedResolved(_) => (DestinationDenialKind::AllowedIps, false),
    };

    if control_plane_blocked && BLOCKED_CONTROL_PLANE_PORTS.contains(&port) {
        return Err(DestinationDenial::new(
            kind,
            format!("port {port} is a blocked control-plane port, connection rejected"),
        ));
    }

    let mut allowed = Vec::new();
    let mut first_rejection = None;
    for &ip in resolved_ips {
        let rejection = match &plan.address_authorization {
            AddressAuthorization::DefaultPublicOnly if is_internal_ip(ip) => Some(format!(
                "{host} resolves to internal address {ip}, connection rejected"
            )),
            AddressAuthorization::ExplicitAllowedIps(networks) => {
                if is_always_blocked_ip(ip) {
                    Some(format!(
                        "{host} resolves to always-blocked address {ip}, connection rejected"
                    ))
                } else if !networks.iter().any(|network| network.contains(&ip)) {
                    Some(format!(
                        "{host} resolves to {ip} which is not in allowed_ips, connection rejected"
                    ))
                } else {
                    None
                }
            }
            AddressAuthorization::ImplicitIpLiteral(expected_ip) => {
                if is_always_blocked_ip(ip) {
                    Some(format!(
                        "{host} resolves to always-blocked address {ip}, connection rejected"
                    ))
                } else if ip != *expected_ip {
                    Some(format!(
                        "{host} resolves to {ip} which is not in allowed_ips, connection rejected"
                    ))
                } else {
                    None
                }
            }
            AddressAuthorization::ExactDeclaredHost if is_always_blocked_ip(ip) => Some(format!(
                "{host} resolves to always-blocked address {ip}, connection rejected"
            )),
            AddressAuthorization::TrustedGatewayAlias { expected_ip } => {
                if is_cloud_metadata_ip(ip) {
                    Some(format!(
                        "{host} resolves to cloud metadata address {ip}, connection rejected"
                    ))
                } else if ip != *expected_ip {
                    Some(format!(
                        "{host} resolves to {ip} which does not match trusted host gateway \
                         {expected_ip}, connection rejected"
                    ))
                } else if !is_link_local_ip(ip) {
                    Some(format!(
                        "{host} resolves to non-link-local address {ip}, connection rejected"
                    ))
                } else {
                    None
                }
            }
            AddressAuthorization::PinnedResolved(pinned) if !pinned.contains(&ip) => Some(format!(
                "{host} resolves to unpinned address {ip}, connection rejected"
            )),
            AddressAuthorization::DefaultPublicOnly
            | AddressAuthorization::ExactDeclaredHost
            | AddressAuthorization::PinnedResolved(_) => None,
        };
        if let Some(reason) = rejection {
            first_rejection.get_or_insert(reason);
        } else if !allowed.contains(&ip) {
            allowed.push(ip);
        }
    }

    if allowed.is_empty() {
        return Err(DestinationDenial::new(
            kind,
            first_rejection.unwrap_or_else(|| {
                format!(
                    "DNS resolution returned no addresses for {}",
                    super::normalize_host_lookup_key(host)
                )
            }),
        ));
    }

    Ok(allowed)
}

/// Validated, but not yet opened, upstream destination.
///
/// The explicit proxy adapter controls when `connect` is called so CONNECT and
/// forward HTTP retain their current upstream-dial timing during the refactor.
pub(crate) struct UpstreamConnector {
    host: String,
    port: u16,
    addrs: Vec<SocketAddr>,
}

impl UpstreamConnector {
    pub(crate) fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// Opens the connection with `TCP_NODELAY` set: this is the upstream dial
    /// boundary for latency-sensitive proxied request/response traffic, where
    /// Nagle would stall sub-MSS writes on delayed ACKs.
    pub(crate) async fn connect(&self) -> std::io::Result<TcpStream> {
        tracing::debug!(
            host = %self.host,
            port = self.port,
            address_count = self.addrs.len(),
            "Opening validated upstream connection"
        );
        connect_tcp_nodelay_best_effort(self.addrs.as_slice()).await
    }

    pub(crate) fn new(host: &str, port: u16, addrs: Vec<SocketAddr>) -> Self {
        Self {
            host: host.to_string(),
            port,
            addrs,
        }
    }
}

/// Resolve and validate a destination using the existing proxy security rules.
pub(crate) async fn validate_destination(
    request: DestinationRequest<'_>,
) -> Result<UpstreamConnector, DestinationDenial> {
    let DestinationRequest {
        host,
        port,
        sandbox_entrypoint_pid,
        plan,
    } = request;

    let addrs = match &plan.address_authorization {
        AddressAuthorization::TrustedGatewayAlias { expected_ip } => {
            resolve_and_check_trusted_gateway(host, port, *expected_ip, sandbox_entrypoint_pid)
                .await
                .map_err(|reason| {
                    DestinationDenial::new(DestinationDenialKind::TrustedGateway, reason)
                })?
        }
        AddressAuthorization::ExplicitAllowedIps(networks) => {
            resolve_and_check_allowed_ips(host, port, networks, sandbox_entrypoint_pid)
                .await
                .map_err(|reason| {
                    DestinationDenial::new(DestinationDenialKind::AllowedIps, reason)
                })?
        }
        AddressAuthorization::ImplicitIpLiteral(ip) => {
            let network = IpNet::from(*ip);
            resolve_and_check_allowed_ips(host, port, &[network], sandbox_entrypoint_pid)
                .await
                .map_err(|reason| {
                    DestinationDenial::new(DestinationDenialKind::AllowedIps, reason)
                })?
        }
        AddressAuthorization::ExactDeclaredHost => {
            resolve_and_check_declared_endpoint(host, port, sandbox_entrypoint_pid)
                .await
                .map_err(|reason| {
                    DestinationDenial::new(DestinationDenialKind::DeclaredEndpoint, reason)
                })?
        }
        AddressAuthorization::DefaultPublicOnly => {
            resolve_and_reject_internal(host, port, sandbox_entrypoint_pid)
                .await
                .map_err(|reason| {
                    DestinationDenial::new(DestinationDenialKind::InternalAddress, reason)
                })?
        }
        AddressAuthorization::PinnedResolved(addresses) => addresses
            .iter()
            .copied()
            .map(|address| SocketAddr::new(address, port))
            .collect(),
    };

    Ok(UpstreamConnector::new(host, port, addrs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn request<'a>(host: &'a str, plan: &'a DestinationValidationPlan) -> DestinationRequest<'a> {
        DestinationRequest {
            host,
            port: 80,
            sandbox_entrypoint_pid: 0,
            plan,
        }
    }

    /// Regression test: the shared upstream dial boundary sets `TCP_NODELAY`.
    #[tokio::test]
    async fn upstream_connector_sets_tcp_nodelay() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        let connector = UpstreamConnector::new("127.0.0.1", addr.port(), vec![addr]);
        let stream = connector.connect().await.expect("connect");
        assert!(stream.nodelay().expect("query TCP_NODELAY"));
    }

    #[tokio::test]
    async fn default_mode_classifies_loopback_as_internal_address() {
        let plan = DestinationValidationPlan {
            address_authorization: AddressAuthorization::DefaultPublicOnly,
        };
        let denial = validate_destination(request("127.0.0.1", &plan))
            .await
            .err()
            .expect("loopback must be denied");

        assert_eq!(denial.kind, DestinationDenialKind::InternalAddress);
    }

    #[tokio::test]
    async fn invalid_allowed_ips_has_a_distinct_denial_kind() {
        let denial = build_validation_plan(
            "api.example.test",
            "api.example.test",
            None,
            &["not-an-ip".to_string()],
            false,
        )
        .expect_err("invalid allowed_ips must be denied");

        assert_eq!(denial.kind, DestinationDenialKind::InvalidAllowedIps);
    }

    #[tokio::test]
    async fn declared_endpoint_preserves_its_denial_classification() {
        let plan = DestinationValidationPlan {
            address_authorization: AddressAuthorization::ExactDeclaredHost,
        };
        let denial = validate_destination(request("127.0.0.1", &plan))
            .await
            .err()
            .expect("declared loopback must remain denied");

        assert_eq!(denial.kind, DestinationDenialKind::DeclaredEndpoint);
    }

    #[tokio::test]
    async fn trusted_gateway_preserves_its_denial_classification() {
        let plan = DestinationValidationPlan {
            address_authorization: AddressAuthorization::TrustedGatewayAlias {
                expected_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            },
        };
        let denial = validate_destination(request("host.openshell.internal", &plan))
            .await
            .err()
            .expect("loopback cannot be a trusted gateway");

        assert_eq!(denial.kind, DestinationDenialKind::TrustedGateway);
    }

    #[tokio::test]
    async fn pinned_addresses_construct_connector_without_resolving_host() {
        let pinned_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let plan = build_pinned_validation_plan(vec![pinned_ip]).unwrap();

        let connector = validate_destination(request("does-not-resolve.invalid", &plan))
            .await
            .expect("pinned mode must not resolve the hostname");

        assert_eq!(connector.addrs(), &[SocketAddr::new(pinned_ip, 80)]);
    }

    #[test]
    fn pinned_addresses_must_not_be_empty() {
        let denial = build_pinned_validation_plan(Vec::new())
            .expect_err("an empty pinned answer set must be rejected");

        assert_eq!(denial.kind, DestinationDenialKind::InvalidAllowedIps);
        assert!(denial.reason.contains("empty pinned address set"));
    }

    #[test]
    fn address_filter_retains_public_answer_from_mixed_set() {
        let plan = DestinationValidationPlan {
            address_authorization: AddressAuthorization::DefaultPublicOnly,
        };
        let public: IpAddr = "8.8.8.8".parse().unwrap();
        let private: IpAddr = "10.1.2.3".parse().unwrap();

        let allowed =
            filter_resolved_addresses(&plan, "mixed.example", 443, &[private, public]).unwrap();

        assert_eq!(allowed, vec![public]);
    }

    #[test]
    fn address_filter_exact_host_allows_private_but_not_always_blocked() {
        let plan = DestinationValidationPlan {
            address_authorization: AddressAuthorization::ExactDeclaredHost,
        };
        let private: IpAddr = "10.1.2.3".parse().unwrap();
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();

        let allowed =
            filter_resolved_addresses(&plan, "private.example", 443, &[loopback, private]).unwrap();

        assert_eq!(allowed, vec![private]);
    }

    #[test]
    fn address_filter_enforces_allowed_ips() {
        let plan = DestinationValidationPlan {
            address_authorization: AddressAuthorization::ExplicitAllowedIps(vec![
                "10.2.0.0/16".parse().unwrap(),
            ]),
        };
        let included: IpAddr = "10.2.3.4".parse().unwrap();
        let excluded: IpAddr = "10.3.4.5".parse().unwrap();

        let allowed =
            filter_resolved_addresses(&plan, "allowlisted.example", 443, &[excluded, included])
                .unwrap();

        assert_eq!(allowed, vec![included]);
    }

    #[test]
    fn address_filter_rejects_always_blocked_only_answer() {
        let plan = DestinationValidationPlan {
            address_authorization: AddressAuthorization::ExactDeclaredHost,
        };

        let denial = filter_resolved_addresses(
            &plan,
            "loopback.example",
            443,
            &["127.0.0.1".parse().unwrap()],
        )
        .expect_err("loopback must not survive filtering");

        assert_eq!(denial.kind, DestinationDenialKind::DeclaredEndpoint);
    }

    #[test]
    fn address_filter_rejects_control_plane_port() {
        let plan = DestinationValidationPlan {
            address_authorization: AddressAuthorization::ExactDeclaredHost,
        };

        let denial =
            filter_resolved_addresses(&plan, "api.example", 6443, &["8.8.8.8".parse().unwrap()])
                .expect_err("control-plane port must remain blocked");

        assert_eq!(denial.kind, DestinationDenialKind::DeclaredEndpoint);
        assert!(denial.reason.contains("blocked control-plane port"));
    }

    #[test]
    fn validation_mode_precedence_is_explicit_and_stable() {
        let trusted_ip = IpAddr::V4(Ipv4Addr::new(169, 254, 1, 2));
        let trusted = build_validation_plan(
            "host.openshell.internal",
            "host.openshell.internal",
            Some(trusted_ip),
            &["10.0.0.0/8".to_string()],
            true,
        )
        .unwrap();
        assert_eq!(
            trusted.address_authorization,
            AddressAuthorization::TrustedGatewayAlias {
                expected_ip: trusted_ip
            }
        );

        let explicit = build_validation_plan(
            "10.2.3.4",
            "10.2.3.4",
            None,
            &["10.0.0.0/8".to_string()],
            true,
        )
        .unwrap();
        assert_eq!(
            explicit.address_authorization,
            AddressAuthorization::ExplicitAllowedIps(vec!["10.0.0.0/8".parse().unwrap()])
        );

        let implicit = build_validation_plan("10.2.3.4", "10.2.3.4", None, &[], true).unwrap();
        assert_eq!(
            implicit.address_authorization,
            AddressAuthorization::ImplicitIpLiteral("10.2.3.4".parse().unwrap())
        );

        let declared =
            build_validation_plan("private.example", "private.example", None, &[], true).unwrap();
        assert_eq!(
            declared.address_authorization,
            AddressAuthorization::ExactDeclaredHost
        );

        let default =
            build_validation_plan("*.example.com", "*.example.com", None, &[], false).unwrap();
        assert_eq!(
            default.address_authorization,
            AddressAuthorization::DefaultPublicOnly
        );
    }
}
