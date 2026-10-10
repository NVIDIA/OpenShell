// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::redundant_pub_crate,
    reason = "the destination primitives intentionally remain internal to the proxy crate"
)]

//! Shared external destination validation and upstream dial boundary.

use super::{
    BLOCKED_CONTROL_PLANE_PORTS, DestinationCheckError, implicit_allowed_ips_for_ip_host,
    is_cloud_metadata_ip, is_host_gateway_alias, is_link_local_ip, normalize_host_lookup_key,
    parse_allowed_ips, resolve_and_check_allowed_ips, resolve_and_check_declared_endpoint,
    resolve_and_check_trusted_gateway, resolve_and_reject_internal, resolve_socket_addrs,
};
use crate::cedar_only::CedarDestination;
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
    /// A backend-provided host-side dial target. The backend is the trusted
    /// authority for this mapping, so the supervisor does not consult its own
    /// resolver before dialing it.
    BackendPinnedGateway(IpAddr),
    /// Addresses already resolved and authorized by policy DNS. This mode must
    /// never resolve `DestinationRequest::host` again before constructing the
    /// unopened connector.
    #[allow(dead_code, reason = "used when the policy DNS adapter lands")]
    PinnedResolved(Vec<IpAddr>),
    /// A Cedar sandbox's connection: each resolved address must pass
    /// [`cedar_address_rejection`].
    Cedar(Box<CedarDestination>),
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
    Resolution,
    TrustedGateway,
    InvalidAllowedIps,
    AllowedIps,
    DeclaredEndpoint,
    InternalAddress,
    /// A Cedar sandbox's destination address rules rejected the address.
    CedarAddress,
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

    fn from_check(error: DestinationCheckError, denied_kind: DestinationDenialKind) -> Self {
        match error {
            DestinationCheckError::Resolution(reason) => {
                Self::new(DestinationDenialKind::Resolution, reason)
            }
            DestinationCheckError::Denied(reason) => Self::new(denied_kind, reason),
        }
    }
}

/// Select one current destination-validation mode without changing precedence.
///
/// A Cedar sandbox passes `cedar`, which replaces the modes below the host
/// gateway aliases. Those aliases keep their pinned address, which Cedar must
/// also allow. As in YAML, provider `allowed_ips` do not apply to an alias's
/// pinned address.
pub(crate) fn build_validation_plan(
    host: &str,
    normalized_host: &str,
    backend_host_gateway: Option<IpAddr>,
    trusted_host_gateway: Option<IpAddr>,
    raw_allowed_ips: &[String],
    exact_declared_endpoint_host: bool,
    cedar: Option<&CedarDestination>,
) -> Result<DestinationValidationPlan, DestinationDenial> {
    let gateway_ip = if is_host_gateway_alias(normalized_host) {
        backend_host_gateway.or(trusted_host_gateway)
    } else {
        None
    };
    if let (Some(ip), Some(cedar)) = (gateway_ip, cedar) {
        let allowed = cedar
            .allows(ip)
            .map_err(|error| DestinationDenial::new(DestinationDenialKind::CedarAddress, error))?;
        if !allowed {
            return Err(DestinationDenial::new(
                DestinationDenialKind::CedarAddress,
                format!(
                    "Cedar policy denies {host} at host gateway address {ip}, connection rejected"
                ),
            ));
        }
    }
    let address_authorization = if is_host_gateway_alias(normalized_host)
        && let Some(expected_ip) = backend_host_gateway
    {
        AddressAuthorization::BackendPinnedGateway(expected_ip)
    } else if is_host_gateway_alias(normalized_host)
        && let Some(expected_ip) = trusted_host_gateway
    {
        AddressAuthorization::TrustedGatewayAlias { expected_ip }
    } else if let Some(cedar) = cedar {
        AddressAuthorization::Cedar(Box::new(cedar.clone()))
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

/// Returns why a Cedar sandbox rejects resolved address `ip` for a
/// connection to `host`, or `None` when it is admitted.
///
/// Reproduces the YAML modes on the connection's allowing permits, never
/// admitting an address that YAML would reject whichever matching endpoint
/// it consulted first:
///
/// - Loopback, link-local (including cloud metadata), and unspecified
///   addresses are always rejected.
/// - Every allowing permit with a `destination_ip` condition must admit the
///   address, as a YAML endpoint's `allowed_ips` restricts every address.
/// - A private address also needs a permit that names the host exactly, or
///   only permits with `destination_ip` conditions; a permit without one is
///   public-only unless it names the host, as a YAML endpoint without
///   `allowed_ips` is.
/// - Every matching provider endpoint with `allowed_ips` must admit the
///   address, as those ranges restrict a YAML provider endpoint's
///   connections. They only narrow: providers grant no access, so they never
///   count toward admitting a private address.
/// - Cedar, with every policy, must allow the connection to the address.
pub(crate) fn cedar_address_rejection(
    cedar: &CedarDestination,
    host: &str,
    ip: IpAddr,
) -> Option<String> {
    if is_always_blocked_ip(ip) {
        return Some(format!(
            "{host} resolves to always-blocked address {ip}, connection rejected"
        ));
    }
    let conditions = cedar.address_conditions();
    if !conditions
        .iter()
        .all(|ranges| ranges.iter().any(|range| range.contains(&ip)))
    {
        return Some(format!(
            "{host} resolves to {ip} which is not in the policy's destination_ip ranges, \
             connection rejected"
        ));
    }
    if let Some(reason) = cedar_provider_rejection(cedar, host, ip) {
        return Some(reason);
    }
    let private_admitted =
        cedar.names_endpoint() || (!conditions.is_empty() && !cedar.unconstrained_permit());
    if is_internal_ip(ip) && !private_admitted {
        return Some(format!(
            "{host} resolves to internal address {ip}, connection rejected"
        ));
    }
    match cedar.allows(ip) {
        Ok(true) => None,
        Ok(false) => Some(format!(
            "Cedar policy denies {host} at address {ip}, connection rejected"
        )),
        Err(error) => Some(format!(
            "Cedar policy evaluation failed for {host} at address {ip}: {error}"
        )),
    }
}

/// Returns why the `allowed_ips` of a provider endpoint matching a Cedar
/// sandbox's connection to `host` reject resolved address `ip`, or `None`
/// when every such endpoint admits it.
fn cedar_provider_rejection(cedar: &CedarDestination, host: &str, ip: IpAddr) -> Option<String> {
    cedar
        .provider_ranges()
        .iter()
        .find_map(|ranges| match ranges {
            Err(reason) => Some(format!("{host}: {reason}, connection rejected")),
            Ok(ranges) if !ranges.iter().any(|range| range.contains(&ip)) => Some(format!(
                "{host} resolves to {ip} which is not in its provider endpoint's allowed_ips, \
             connection rejected"
            )),
            Ok(_) => None,
        })
}

/// Returns whether a Cedar sandbox blocks control-plane ports for a
/// connection to `host`.
///
/// YAML blocks them in every mode that can admit a private address: an
/// endpoint with `allowed_ips`, an IP literal host, or an exactly declared
/// host. Only a public-only connection may use them. A provider endpoint's
/// `allowed_ips` block them too, as they do for a YAML provider endpoint.
pub(crate) fn cedar_blocks_control_plane(cedar: &CedarDestination, host: &str) -> bool {
    !cedar.address_conditions().is_empty()
        || !cedar.provider_ranges().is_empty()
        || cedar.names_endpoint()
        || normalize_host_lookup_key(host).parse::<IpAddr>().is_ok()
}

/// Checks every resolved address of a Cedar sandbox's connection, rejecting
/// the connection if any is rejected, as CONNECT and forward HTTP do.
pub(crate) fn validate_cedar_resolved_addrs(
    cedar: &CedarDestination,
    host: &str,
    port: u16,
    addrs: &[SocketAddr],
) -> Result<(), String> {
    if addrs.is_empty() {
        return Err(format!(
            "DNS resolution returned no addresses for {}",
            normalize_host_lookup_key(host)
        ));
    }
    if BLOCKED_CONTROL_PLANE_PORTS.contains(&port) && cedar_blocks_control_plane(cedar, host) {
        return Err(format!(
            "port {port} is a blocked control-plane port, connection rejected"
        ));
    }
    addrs
        .iter()
        .find_map(|addr| cedar_address_rejection(cedar, host, addr.ip()))
        .map_or(Ok(()), Err)
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
        AddressAuthorization::TrustedGatewayAlias { .. }
        | AddressAuthorization::BackendPinnedGateway(_) => {
            (DestinationDenialKind::TrustedGateway, true)
        }
        AddressAuthorization::ExplicitAllowedIps(_)
        | AddressAuthorization::ImplicitIpLiteral(_) => (DestinationDenialKind::AllowedIps, true),
        AddressAuthorization::ExactDeclaredHost => (DestinationDenialKind::DeclaredEndpoint, true),
        AddressAuthorization::DefaultPublicOnly => (DestinationDenialKind::InternalAddress, false),
        AddressAuthorization::PinnedResolved(_) => (DestinationDenialKind::AllowedIps, false),
        AddressAuthorization::Cedar(cedar) => (
            DestinationDenialKind::CedarAddress,
            cedar_blocks_control_plane(cedar, host),
        ),
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
            AddressAuthorization::BackendPinnedGateway(expected_ip) => {
                if is_cloud_metadata_ip(ip) {
                    Some(format!(
                        "{host} resolves to cloud metadata address {ip}, connection rejected"
                    ))
                } else if ip != *expected_ip {
                    Some(format!(
                        "{host} resolves to {ip} which does not match backend host gateway \
                         {expected_ip}, connection rejected"
                    ))
                } else {
                    None
                }
            }
            AddressAuthorization::PinnedResolved(pinned) if !pinned.contains(&ip) => Some(format!(
                "{host} resolves to unpinned address {ip}, connection rejected"
            )),
            AddressAuthorization::Cedar(cedar) => cedar_address_rejection(cedar, host, ip),
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
                    normalize_host_lookup_key(host)
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
                .map_err(|error| {
                    DestinationDenial::from_check(error, DestinationDenialKind::TrustedGateway)
                })?
        }
        AddressAuthorization::BackendPinnedGateway(ip) => {
            if BLOCKED_CONTROL_PLANE_PORTS.contains(&port) {
                return Err(DestinationDenial::new(
                    DestinationDenialKind::TrustedGateway,
                    format!("port {port} is a blocked control-plane port, connection rejected"),
                ));
            }
            if is_cloud_metadata_ip(*ip) {
                return Err(DestinationDenial::new(
                    DestinationDenialKind::TrustedGateway,
                    format!(
                        "backend host gateway resolves to cloud metadata address {ip}, connection rejected"
                    ),
                ));
            }
            vec![SocketAddr::new(*ip, port)]
        }
        AddressAuthorization::ExplicitAllowedIps(networks) => {
            resolve_and_check_allowed_ips(host, port, networks, sandbox_entrypoint_pid)
                .await
                .map_err(|error| {
                    DestinationDenial::from_check(error, DestinationDenialKind::AllowedIps)
                })?
        }
        AddressAuthorization::ImplicitIpLiteral(ip) => {
            let network = IpNet::from(*ip);
            resolve_and_check_allowed_ips(host, port, &[network], sandbox_entrypoint_pid)
                .await
                .map_err(|error| {
                    DestinationDenial::from_check(error, DestinationDenialKind::AllowedIps)
                })?
        }
        AddressAuthorization::ExactDeclaredHost => {
            resolve_and_check_declared_endpoint(host, port, sandbox_entrypoint_pid)
                .await
                .map_err(|error| {
                    DestinationDenial::from_check(error, DestinationDenialKind::DeclaredEndpoint)
                })?
        }
        AddressAuthorization::DefaultPublicOnly => {
            resolve_and_reject_internal(host, port, sandbox_entrypoint_pid)
                .await
                .map_err(|error| {
                    DestinationDenial::from_check(error, DestinationDenialKind::InternalAddress)
                })?
        }
        AddressAuthorization::PinnedResolved(addresses) => addresses
            .iter()
            .copied()
            .map(|address| SocketAddr::new(address, port))
            .collect(),
        AddressAuthorization::Cedar(cedar) => {
            let addrs = resolve_socket_addrs(host, port, sandbox_entrypoint_pid)
                .await
                .map_err(|reason| {
                    DestinationDenial::new(DestinationDenialKind::Resolution, reason)
                })?;
            validate_cedar_resolved_addrs(cedar, host, port, &addrs).map_err(|reason| {
                DestinationDenial::new(DestinationDenialKind::CedarAddress, reason)
            })?;
            addrs
        }
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
    async fn resolver_failure_has_a_distinct_failure_kind() {
        let plan = DestinationValidationPlan {
            address_authorization: AddressAuthorization::ExactDeclaredHost,
        };
        let denial = validate_destination(request("does-not-resolve.invalid", &plan))
            .await
            .err()
            .expect("reserved invalid TLD must not resolve");

        assert_eq!(denial.kind, DestinationDenialKind::Resolution);
    }

    #[tokio::test]
    async fn invalid_allowed_ips_has_a_distinct_denial_kind() {
        let denial = build_validation_plan(
            "api.example.test",
            "api.example.test",
            None,
            None,
            &["not-an-ip".to_string()],
            false,
            None,
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
        let denial = validate_destination(request("127.0.0.1", &plan))
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

    /// The destination rules of `binary`'s allowed Cedar connection.
    fn cedar_destination(policy: &str, host: &str, port: u16) -> CedarDestination {
        let engine = crate::cedar_only::CedarOnlyEngine::from_policy_str(policy)
            .expect("Cedar policy loads");
        engine
            .authorize_egress(&crate::opa::NetworkInput {
                host: host.to_string(),
                port,
                binary_path: "/usr/bin/curl".into(),
                binary_sha256: String::new(),
                ancestors: Vec::new(),
                cmdline_paths: Vec::new(),
            })
            .expect("request evaluates")
            .cedar_destination
            .expect("the connection is allowed")
    }

    fn addrs(ips: &[&str], port: u16) -> Vec<SocketAddr> {
        ips.iter()
            .map(|ip| SocketAddr::new(ip.parse().unwrap(), port))
            .collect()
    }

    const HOSTLESS_8080: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.port == 8080
    && context has destination_ip
    && context.destination_ip.isInRange(ip("10.0.0.0/8"))
};
"#;

    #[test]
    fn cedar_destination_replaces_the_yaml_modes() {
        let cedar = cedar_destination(HOSTLESS_8080, "svc.example", 8080);
        let plan = build_validation_plan(
            "svc.example",
            "svc.example",
            None,
            None,
            &["192.168.0.0/16".to_string()],
            true,
            Some(&cedar),
        )
        .unwrap();
        assert_eq!(
            plan.address_authorization,
            AddressAuthorization::Cedar(Box::new(cedar))
        );
    }

    #[test]
    fn cedar_must_allow_the_host_gateway_address() {
        let trusted_ip = IpAddr::V4(Ipv4Addr::new(169, 254, 1, 2));
        let alias = "host.openshell.internal";
        let cedar = cedar_destination(HOSTLESS_8080, alias, 8080);
        let denial = build_validation_plan(
            alias,
            alias,
            None,
            Some(trusted_ip),
            &[],
            false,
            Some(&cedar),
        )
        .expect_err("the gateway address is outside the permit's range");
        assert_eq!(denial.kind, DestinationDenialKind::CedarAddress);

        let named = cedar_destination(
            r#"permit (principal, action == Sandbox::Action::"NetworkConnect",
                       resource == Sandbox::NetworkEndpoint::"host.openshell.internal:8080");"#,
            alias,
            8080,
        );
        let plan = build_validation_plan(
            alias,
            alias,
            None,
            Some(trusted_ip),
            &[],
            false,
            Some(&named),
        )
        .unwrap();
        assert_eq!(
            plan.address_authorization,
            AddressAuthorization::TrustedGatewayAlias {
                expected_ip: trusted_ip
            }
        );
    }

    #[test]
    fn cedar_forbids_reading_the_address_reject_resolved_addresses() {
        let policy = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"db.example:443");
forbid (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { context has destination_ip && context.destination_ip.isInRange(ip("10.9.0.0/16")) };
"#;
        let cedar = cedar_destination(policy, "db.example", 443);
        assert!(
            validate_cedar_resolved_addrs(&cedar, "db.example", 443, &addrs(&["10.8.1.1"], 443))
                .is_ok()
        );
        let error = validate_cedar_resolved_addrs(
            &cedar,
            "db.example",
            443,
            &addrs(&["10.8.1.1", "10.9.1.1"], 443),
        )
        .unwrap_err();
        assert!(error.contains("Cedar policy denies"), "{error}");

        let plan = DestinationValidationPlan {
            address_authorization: AddressAuthorization::Cedar(Box::new(cedar)),
        };
        let kept = filter_resolved_addresses(
            &plan,
            "db.example",
            443,
            &["10.9.1.1".parse().unwrap(), "10.8.1.1".parse().unwrap()],
        )
        .unwrap();
        assert_eq!(kept, ["10.8.1.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn cedar_blocks_control_plane_ports_where_yaml_does() {
        let glob = cedar_destination(
            r#"permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
               when { resource.host like("*.example.com", ".") && resource.port == 6443 };"#,
            "api.example.com",
            6443,
        );
        assert!(
            validate_cedar_resolved_addrs(
                &glob,
                "api.example.com",
                6443,
                &addrs(&["8.8.8.8"], 6443)
            )
            .is_ok(),
            "a public-only connection may use a control-plane port, as in YAML"
        );
        let exact = cedar_destination(
            r#"permit (principal, action == Sandbox::Action::"NetworkConnect",
                       resource == Sandbox::NetworkEndpoint::"api.example.com:6443");"#,
            "api.example.com",
            6443,
        );
        let error = validate_cedar_resolved_addrs(
            &exact,
            "api.example.com",
            6443,
            &addrs(&["8.8.8.8"], 6443),
        )
        .unwrap_err();
        assert!(error.contains("control-plane port"), "{error}");
    }

    #[test]
    fn cedar_admits_private_addresses_only_through_ranges_or_exact_hosts() {
        let policy = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { resource.host like("*.corp.example", ".") && resource.port == 443 };
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.port == 443
    && context has destination_ip
    && context.destination_ip.isInRange(ip("10.0.0.0/8"))
};
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"named.corp.example:443");
"#;
        let private = addrs(&["10.1.1.1"], 443);
        // A glob alone is public-only, so a range cannot widen it.
        let glob = cedar_destination(policy, "svc.corp.example", 443);
        assert!(validate_cedar_resolved_addrs(&glob, "svc.corp.example", 443, &private).is_err());
        // Only ranged permits allow this host: their range decides.
        let ranged = cedar_destination(policy, "other.example", 443);
        assert!(validate_cedar_resolved_addrs(&ranged, "other.example", 443, &private).is_ok());
        // An exactly named host may resolve privately, within the range.
        let named = cedar_destination(policy, "named.corp.example", 443);
        assert!(validate_cedar_resolved_addrs(&named, "named.corp.example", 443, &private).is_ok());
        assert!(
            validate_cedar_resolved_addrs(
                &named,
                "named.corp.example",
                443,
                &addrs(&["192.168.1.1"], 443)
            )
            .is_err(),
            "every ranged permit that allows the connection must admit the address"
        );
    }

    /// The destination rules of curl's allowed Cedar connection to
    /// `host:port` on a sandbox with one provider endpoint for `host:port`
    /// whose `allowed_ips` are `ranges`.
    fn cedar_destination_with_provider(
        policy: &str,
        host: &str,
        port: u16,
        ranges: &[&str],
    ) -> CedarDestination {
        let mut proto = openshell_core::proto::SandboxPolicy {
            cedar_policy_source: policy.to_string(),
            ..Default::default()
        };
        proto.provider_credential_rules.insert(
            "_provider_corp".to_string(),
            openshell_core::proto::NetworkPolicyRule {
                name: "_provider_corp".to_string(),
                endpoints: vec![openshell_core::proto::NetworkEndpoint {
                    host: host.to_string(),
                    port: u32::from(port),
                    allowed_ips: ranges.iter().map(ToString::to_string).collect(),
                    provider_credentialed: true,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        crate::cedar_only::CedarOnlyEngine::from_proto(&proto)
            .expect("Cedar policy loads")
            .authorize_egress(&crate::opa::NetworkInput {
                host: host.to_string(),
                port,
                binary_path: "/usr/bin/curl".into(),
                binary_sha256: String::new(),
                ancestors: Vec::new(),
                cmdline_paths: Vec::new(),
            })
            .expect("request evaluates")
            .cedar_destination
            .expect("the connection is allowed")
    }

    const EXACT_CORP: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.corp.example:443");
"#;

    /// Regression test: a credentialed provider endpoint's `allowed_ips`
    /// keep restricting the addresses its connections reach.
    #[test]
    fn provider_ranges_narrow_the_addresses_cedar_admits() {
        let host = "api.corp.example";
        let unranged = cedar_destination(EXACT_CORP, host, 443);
        assert!(
            validate_cedar_resolved_addrs(&unranged, host, 443, &addrs(&["10.6.0.1"], 443)).is_ok(),
            "Cedar alone admits a private address for an exactly named host"
        );

        let ranged = cedar_destination_with_provider(EXACT_CORP, host, 443, &["10.5.0.0/16"]);
        assert!(
            validate_cedar_resolved_addrs(&ranged, host, 443, &addrs(&["10.5.0.1"], 443)).is_ok()
        );
        for outside in [&["10.6.0.1"][..], &["8.8.8.8"], &["10.5.0.1", "10.6.0.1"]] {
            let error = validate_cedar_resolved_addrs(&ranged, host, 443, &addrs(outside, 443))
                .unwrap_err();
            assert!(
                error.contains("provider endpoint's allowed_ips"),
                "{outside:?}: {error}"
            );
        }

        let plan = DestinationValidationPlan {
            address_authorization: AddressAuthorization::Cedar(Box::new(ranged)),
        };
        let kept = filter_resolved_addresses(
            &plan,
            host,
            443,
            &["10.6.0.1".parse().unwrap(), "10.5.0.1".parse().unwrap()],
        )
        .unwrap();
        assert_eq!(kept, ["10.5.0.1".parse::<IpAddr>().unwrap()]);
    }

    /// Provider ranges never admit a private address Cedar's own rules
    /// reject, and block control-plane ports as YAML `allowed_ips` do.
    #[test]
    fn provider_ranges_never_widen_address_admission() {
        let host = "api.corp.example";
        let glob = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { resource.host like("*.corp.example", ".") && (resource.port == 443 || resource.port == 6443) };
"#;
        let ranged = cedar_destination_with_provider(glob, host, 443, &["10.5.0.0/16"]);
        let error = validate_cedar_resolved_addrs(&ranged, host, 443, &addrs(&["10.5.0.1"], 443))
            .unwrap_err();
        assert!(error.contains("internal address"), "{error}");

        let control_plane = cedar_destination_with_provider(glob, host, 6443, &["8.8.8.0/24"]);
        let error =
            validate_cedar_resolved_addrs(&control_plane, host, 6443, &addrs(&["8.8.8.8"], 6443))
                .unwrap_err();
        assert!(error.contains("control-plane port"), "{error}");
    }

    #[test]
    fn invalid_provider_ranges_reject_every_address() {
        let host = "api.corp.example";
        let invalid = cedar_destination_with_provider(EXACT_CORP, host, 443, &["not-an-ip"]);
        let error = validate_cedar_resolved_addrs(&invalid, host, 443, &addrs(&["8.8.8.8"], 443))
            .unwrap_err();
        assert!(error.contains("invalid CIDR/IP"), "{error}");
    }

    #[test]
    fn validation_mode_precedence_is_explicit_and_stable() {
        let backend_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let trusted_ip = IpAddr::V4(Ipv4Addr::new(169, 254, 1, 2));
        let backend = build_validation_plan(
            "host.openshell.internal",
            "host.openshell.internal",
            Some(backend_ip),
            Some(trusted_ip),
            &["10.0.0.0/8".to_string()],
            true,
            None,
        )
        .unwrap();
        assert_eq!(
            backend.address_authorization,
            AddressAuthorization::BackendPinnedGateway(backend_ip)
        );

        let trusted = build_validation_plan(
            "host.openshell.internal",
            "host.openshell.internal",
            None,
            Some(trusted_ip),
            &["10.0.0.0/8".to_string()],
            true,
            None,
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
            None,
            &["10.0.0.0/8".to_string()],
            true,
            None,
        )
        .unwrap();
        assert_eq!(
            explicit.address_authorization,
            AddressAuthorization::ExplicitAllowedIps(vec!["10.0.0.0/8".parse().unwrap()])
        );

        let implicit =
            build_validation_plan("10.2.3.4", "10.2.3.4", None, None, &[], true, None).unwrap();
        assert_eq!(
            implicit.address_authorization,
            AddressAuthorization::ImplicitIpLiteral("10.2.3.4".parse().unwrap())
        );

        let declared = build_validation_plan(
            "private.example",
            "private.example",
            None,
            None,
            &[],
            true,
            None,
        )
        .unwrap();
        assert_eq!(
            declared.address_authorization,
            AddressAuthorization::ExactDeclaredHost
        );

        let default = build_validation_plan(
            "*.example.com",
            "*.example.com",
            None,
            None,
            &[],
            false,
            None,
        )
        .unwrap();
        assert_eq!(
            default.address_authorization,
            AddressAuthorization::DefaultPublicOnly
        );
    }
}
