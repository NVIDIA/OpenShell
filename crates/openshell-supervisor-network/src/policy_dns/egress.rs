// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! IPv6 egress selection and NAT64 prefix setup for the supervisor.
//!
//! Mediated policy DNS answers AAAA queries only when IPv6 egress is enabled.
//! `auto` enables it when the supervisor network namespace is IPv6-only, the
//! case where the IPv4 fallback cannot work (for example NAT64/DNS64 hosts).
//! NAT64 prefixes are registered with [`openshell_core::net::nat64`] so every
//! SSRF check classifies translated addresses by their embedded IPv4 address.

use crate::policy_dns::NormalizedName;
use crate::policy_dns::resolver::{AddressFamily, ResolveError, TrustedResolver};
use openshell_core::PolicyDnsIpv6Egress;
use openshell_core::net::nat64::{self, Nat64Prefix};
use openshell_ocsf::{ConfigStateChangeBuilder, OcsfEvent, SeverityId, StateId, StatusId};
use std::net::IpAddr;

const RTF_UP: u32 = 0x0001;
const RTF_REJECT: u32 = 0x0200;

/// Default-route state of the supervisor network namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteState {
    Ipv6Only,
    DualStack,
    Ipv4Only,
    NoDefaultRoute,
    RouteTableUnavailable,
}

impl RouteState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Ipv6Only => "ipv6_only",
            Self::DualStack => "dual_stack",
            Self::Ipv4Only => "ipv4_only",
            Self::NoDefaultRoute => "no_default_route",
            Self::RouteTableUnavailable => "route_table_unavailable",
        }
    }
}

/// Usable default routes found in the kernel routing tables. `None` means the
/// table could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DefaultRoutes {
    pub(crate) ipv4: Option<bool>,
    pub(crate) ipv6: Option<bool>,
}

impl DefaultRoutes {
    /// Parse `/proc/net/route` and `/proc/net/ipv6_route` contents.
    pub(crate) fn from_tables(ipv4_routes: Option<&str>, ipv6_routes: Option<&str>) -> Self {
        Self {
            ipv4: ipv4_routes.map(has_ipv4_default_route),
            ipv6: ipv6_routes.map(has_ipv6_default_route),
        }
    }

    /// Read the routing tables of the current network namespace.
    pub(crate) fn read() -> Self {
        Self::from_tables(
            std::fs::read_to_string("/proc/net/route").ok().as_deref(),
            std::fs::read_to_string("/proc/net/ipv6_route")
                .ok()
                .as_deref(),
        )
    }

    pub(crate) fn state(self) -> RouteState {
        match (self.ipv4, self.ipv6) {
            (Some(false), Some(true)) => RouteState::Ipv6Only,
            (Some(true), Some(true)) => RouteState::DualStack,
            (Some(true), Some(false)) => RouteState::Ipv4Only,
            (Some(false), Some(false)) => RouteState::NoDefaultRoute,
            _ => RouteState::RouteTableUnavailable,
        }
    }
}

/// The resolved IPv6 egress decision and the evidence behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ipv6EgressDecision {
    pub(crate) requested: PolicyDnsIpv6Egress,
    pub(crate) enabled: bool,
    pub(crate) routes: DefaultRoutes,
}

impl Ipv6EgressDecision {
    /// Resolve `requested` against the detected routes. Explicit modes are
    /// honored as-is; routes are still recorded for the audit event.
    pub(crate) fn resolve(requested: PolicyDnsIpv6Egress, routes: DefaultRoutes) -> Self {
        let enabled = match requested {
            PolicyDnsIpv6Egress::Enabled => true,
            PolicyDnsIpv6Egress::Disabled => false,
            PolicyDnsIpv6Egress::Auto => routes.state() == RouteState::Ipv6Only,
        };
        Self {
            requested,
            enabled,
            routes,
        }
    }

    /// OCSF configuration event describing this decision.
    pub(crate) fn event(self) -> OcsfEvent {
        let state = self.routes.state();
        // Enabling IPv6 answers without an IPv6 route, or keeping them off on
        // an IPv6-only host, breaks allowed destinations: make it visible.
        let mismatch = (self.enabled && self.routes.ipv6 != Some(true))
            || (!self.enabled && state == RouteState::Ipv6Only);
        let unavailable = state == RouteState::RouteTableUnavailable;
        ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
            .severity(if mismatch || unavailable {
                SeverityId::Medium
            } else {
                SeverityId::Informational
            })
            .status(StatusId::Success)
            .state(
                if self.enabled {
                    StateId::Enabled
                } else {
                    StateId::Disabled
                },
                if self.enabled { "enabled" } else { "disabled" },
            )
            .unmapped("requested_mode", self.requested.as_str())
            .unmapped("ipv6_egress", self.enabled)
            .unmapped("ipv4_default_route", route_value(self.routes.ipv4))
            .unmapped("ipv6_default_route", route_value(self.routes.ipv6))
            .unmapped("route_state", state.as_str())
            .message(format!(
                "Policy DNS IPv6 egress {} (requested {}, route state {})",
                if self.enabled { "enabled" } else { "disabled" },
                self.requested.as_str(),
                state.as_str(),
            ))
            .build()
    }
}

fn route_value(value: Option<bool>) -> serde_json::Value {
    value.map_or(serde_json::Value::Null, serde_json::Value::Bool)
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
            && fields[0].len() == 32
            && fields[0].bytes().all(|byte| byte == b'0')
            && fields[1] == "00"
            && fields[9] != "lo"
            && route_flags_usable(fields[8])
    })
}

fn route_flags_usable(flags: &str) -> bool {
    u32::from_str_radix(flags, 16).is_ok_and(|flags| flags & RTF_UP != 0 && flags & RTF_REJECT == 0)
}

/// Where the NAT64 prefixes in effect came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Nat64Setup {
    pub(crate) configured: Vec<Nat64Prefix>,
    pub(crate) discovered: Vec<Nat64Prefix>,
    pub(crate) discovery_error: Option<String>,
}

impl Nat64Setup {
    /// Register operator-configured prefixes, then discover the network's
    /// prefix through `ipv4only.arpa` (RFC 7050) and register it too.
    ///
    /// Registration only ever adds prefixes, so a discovered prefix cannot
    /// weaken an operator-configured one. A failed discovery leaves the
    /// well-known prefix and the configured prefixes in effect.
    pub(crate) async fn apply<R: TrustedResolver>(
        configured: Vec<Nat64Prefix>,
        resolver: &R,
    ) -> Self {
        for prefix in &configured {
            nat64::register_network_prefix(*prefix);
        }
        let name = NormalizedName::parse("ipv4only.arpa").expect("static name is valid");
        let (discovered, discovery_error) = match resolver.resolve(&name, AddressFamily::Ipv6).await
        {
            Ok(answer) => {
                let mut discovered = Vec::new();
                for address in answer.addresses {
                    if let IpAddr::V6(v6) = address
                        && let Some(prefix) = Nat64Prefix::from_ipv4only_arpa_answer(v6)
                        && !discovered.contains(&prefix)
                    {
                        nat64::register_network_prefix(prefix);
                        discovered.push(prefix);
                    }
                }
                (discovered, None)
            }
            // No AAAA for ipv4only.arpa: the resolver does not synthesize, so
            // there is no DNS64 on this network.
            Err(ResolveError::NoData | ResolveError::NxDomain) => (Vec::new(), None),
            Err(error) => (Vec::new(), Some(error.to_string())),
        };
        Self {
            configured,
            discovered,
            discovery_error,
        }
    }

    /// OCSF configuration event describing the prefixes in effect.
    pub(crate) fn event(&self) -> OcsfEvent {
        let list = |prefixes: &[Nat64Prefix]| {
            serde_json::Value::from(prefixes.iter().map(ToString::to_string).collect::<Vec<_>>())
        };
        let mut builder = ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .state(StateId::Enabled, "nat64_prefixes")
            .unmapped(
                "nat64_well_known_prefix",
                nat64::WELL_KNOWN_PREFIX.to_string(),
            )
            .unmapped("nat64_configured_prefixes", list(&self.configured))
            .unmapped("nat64_discovered_prefixes", list(&self.discovered));
        if let Some(error) = &self.discovery_error {
            builder = builder.unmapped("nat64_discovery_error", error.as_str());
        }
        builder
            .message(format!(
                "NAT64 prefixes for SSRF classification: {} configured, {} discovered",
                self.configured.len(),
                self.discovered.len()
            ))
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_dns::TrustedAnswer;
    use std::time::Duration;

    const V4_HEADER: &str =
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT";
    // Entries every Linux network namespace with IPv6 carries on `lo`,
    // including the kernel's unreachable `::/0`, which is not an uplink.
    const V6_LOOPBACK: [&str; 2] = [
        "00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000002 00000000 80200001       lo",
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo",
    ];

    fn v4(rows: &[&str]) -> String {
        std::iter::once(V4_HEADER)
            .chain(rows.iter().copied())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn v6(rows: &[&str]) -> String {
        rows.iter()
            .copied()
            .chain(V6_LOOPBACK)
            .collect::<Vec<_>>()
            .join("\n")
    }

    struct Case {
        backend: &'static str,
        ipv4: Option<String>,
        ipv6: Option<String>,
        expected: RouteState,
    }

    /// Supervisor network namespace layouts per backend, for IPv4-only,
    /// dual-stack and IPv6-only networks. The Blaxel rows are captured
    /// verbatim from a host; the others follow each runtime's default
    /// addressing (`/proc/net/route` gateways are little-endian hex).
    fn backend_cases() -> Vec<Case> {
        // Docker bridge: 172.17.0.0/16 via 172.17.0.1; IPv6 network fd00:1::/64.
        let docker_v4 = [
            "eth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\t0\t0\t0",
            "eth0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0",
        ];
        let docker_v6 = [
            "fd000001000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0",
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fd000001000000000000000000000001 00000400 00000001 00000000 00000003     eth0",
        ];
        // Podman: netavark bridge 10.88.0.0/16; rootless pasta copies the host
        // routes, including an RA-learned IPv6 default (ADDRCONF|DEFAULT|EXPIRES).
        let netavark_v4 = [
            "eth0\t00000000\t0100580A\t0003\t0\t0\t0\t00000000\t0\t0\t0",
            "eth0\t0000580A\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0",
        ];
        let pasta_v4 = [
            "enp1s0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0",
            "enp1s0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0",
        ];
        let pasta_v6 = [
            "20010db8000100000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001   enp1s0",
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00450003   enp1s0",
        ];
        // Kubernetes (Calico): default via 169.254.1.1 and
        // fe80::ecee:eeff:feee:eeee, both on-link host routes.
        let calico_v4 = [
            "eth0\t00000000\t0101FEA9\t0003\t0\t0\t0\t00000000\t0\t0\t0",
            "eth0\t0101FEA9\t00000000\t0005\t0\t0\t0\tFFFFFFFF\t0\t0\t0",
        ];
        let calico_v6 = [
            "fd000000000000000000000000000a2b 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0",
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe80000000000000eceeeefffeeeeeee 00000400 00000001 00000000 00000003     eth0",
        ];
        // VM driver guest (libkrun + gvproxy): 192.168.127.0/24 via .1.
        let vm_v4 = [
            "eth0\t00000000\t017FA8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0",
            "eth0\t007FA8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0",
        ];
        let vm_v6 = [
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00450003     eth0",
        ];
        // Blaxel microVM, captured: IPv6-only behind NAT64 (/128 on eth0,
        // default via fe80::1). With a 464XLAT CLAT the IPv4 default is a
        // gatewayless route on the `clat` tun device.
        let blaxel_v6 = [
            "26056440d00002110a8000040000041a 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0",
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000064 00000003 00000000 00000003     eth0",
            "26056440d00002110a8000040000041a 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000004 00000000 80200001     eth0",
            "ff000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000002 00000000 00000001     eth0",
        ];
        let blaxel_clat_v4 = [
            "clat\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0",
            "clat\t010000C0\t00000000\t0005\t0\t0\t0\tFFFFFFFF\t0\t0\t0",
        ];

        let dual = |a: &[&str], b: &[&str]| (Some(v4(a)), Some(v6(b)));
        let only4 = |a: &[&str]| (Some(v4(a)), Some(v6(&[])));
        let only6 = |b: &[&str]| (Some(v4(&[])), Some(v6(b)));
        [
            ("docker bridge", only4(&docker_v4), RouteState::Ipv4Only),
            (
                "docker dual-stack network",
                dual(&docker_v4, &docker_v6),
                RouteState::DualStack,
            ),
            (
                "docker IPv6-only network",
                only6(&docker_v6),
                RouteState::Ipv6Only,
            ),
            ("podman netavark", only4(&netavark_v4), RouteState::Ipv4Only),
            (
                "podman pasta, dual-stack host",
                dual(&pasta_v4, &pasta_v6),
                RouteState::DualStack,
            ),
            (
                "podman pasta, IPv6-only host",
                only6(&pasta_v6),
                RouteState::Ipv6Only,
            ),
            (
                "kubernetes calico IPv4",
                only4(&calico_v4),
                RouteState::Ipv4Only,
            ),
            (
                "kubernetes calico dual-stack",
                dual(&calico_v4, &calico_v6),
                RouteState::DualStack,
            ),
            (
                "kubernetes calico IPv6 single-stack",
                only6(&calico_v6),
                RouteState::Ipv6Only,
            ),
            ("vm gvproxy", only4(&vm_v4), RouteState::Ipv4Only),
            ("vm dual-stack", dual(&vm_v4, &vm_v6), RouteState::DualStack),
            ("vm IPv6-only", only6(&vm_v6), RouteState::Ipv6Only),
            ("blaxel IPv6-only", only6(&blaxel_v6), RouteState::Ipv6Only),
            (
                "blaxel with CLAT",
                dual(&blaxel_clat_v4, &blaxel_v6),
                RouteState::DualStack,
            ),
            (
                "isolated namespace",
                (Some(v4(&[])), Some(v6(&[]))),
                RouteState::NoDefaultRoute,
            ),
            (
                "kernel without IPv6",
                (Some(v4(&docker_v4)), None),
                RouteState::RouteTableUnavailable,
            ),
            ("no procfs", (None, None), RouteState::RouteTableUnavailable),
        ]
        .into_iter()
        .map(|(backend, (ipv4, ipv6), expected)| Case {
            backend,
            ipv4,
            ipv6,
            expected,
        })
        .collect()
    }

    #[test]
    fn auto_mode_enables_ipv6_egress_only_on_ipv6_only_backends() {
        for case in backend_cases() {
            let routes = DefaultRoutes::from_tables(case.ipv4.as_deref(), case.ipv6.as_deref());
            assert_eq!(routes.state(), case.expected, "{}", case.backend);
            let decision = Ipv6EgressDecision::resolve(PolicyDnsIpv6Egress::Auto, routes);
            assert_eq!(
                decision.enabled,
                case.expected == RouteState::Ipv6Only,
                "{}",
                case.backend
            );
        }
    }

    #[test]
    fn explicit_modes_ignore_routes() {
        for case in backend_cases() {
            let routes = DefaultRoutes::from_tables(case.ipv4.as_deref(), case.ipv6.as_deref());
            assert!(Ipv6EgressDecision::resolve(PolicyDnsIpv6Egress::Enabled, routes).enabled);
            assert!(!Ipv6EgressDecision::resolve(PolicyDnsIpv6Egress::Disabled, routes).enabled);
        }
    }

    #[test]
    fn down_or_reject_default_routes_are_not_uplinks() {
        let down = v4(&["eth0\t00000000\t0100A8C0\t0002\t0\t0\t100\t00000000\t0\t0\t0"]);
        assert!(!has_ipv4_default_route(&down));
        let reject = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000201     eth0";
        assert!(!has_ipv6_default_route(reject));
    }

    fn unmapped(event: &OcsfEvent) -> serde_json::Value {
        serde_json::to_value(event).unwrap()["unmapped"].clone()
    }

    #[test]
    fn decision_event_reports_mode_result_and_route_state() {
        let routes = DefaultRoutes {
            ipv4: Some(false),
            ipv6: Some(true),
        };
        let fields =
            unmapped(&Ipv6EgressDecision::resolve(PolicyDnsIpv6Egress::Auto, routes).event());
        assert_eq!(fields["requested_mode"], "auto");
        assert_eq!(fields["ipv6_egress"], true);
        assert_eq!(fields["ipv4_default_route"], false);
        assert_eq!(fields["ipv6_default_route"], true);
        assert_eq!(fields["route_state"], "ipv6_only");

        let unavailable = DefaultRoutes {
            ipv4: Some(true),
            ipv6: None,
        };
        let event = Ipv6EgressDecision::resolve(PolicyDnsIpv6Egress::Disabled, unavailable).event();
        let fields = unmapped(&event);
        assert_eq!(fields["requested_mode"], "disabled");
        assert_eq!(fields["ipv6_egress"], false);
        assert_eq!(fields["ipv6_default_route"], serde_json::Value::Null);
        assert_eq!(fields["route_state"], "route_table_unavailable");
        assert_eq!(
            serde_json::to_value(&event).unwrap()["severity_id"],
            SeverityId::Medium as u8
        );
    }

    struct FakeResolver(Result<Vec<IpAddr>, fn() -> ResolveError>);

    impl TrustedResolver for FakeResolver {
        async fn resolve(
            &self,
            name: &NormalizedName,
            family: AddressFamily,
        ) -> Result<TrustedAnswer, ResolveError> {
            assert_eq!(name.as_str(), "ipv4only.arpa");
            assert_eq!(family, AddressFamily::Ipv6);
            match &self.0 {
                Ok(addresses) => Ok(TrustedAnswer {
                    addresses: addresses.clone(),
                    ttl: Duration::from_secs(60),
                }),
                Err(error) => Err(error()),
            }
        }
    }

    #[tokio::test]
    async fn nat64_setup_registers_configured_and_discovered_prefixes() {
        let configured: Nat64Prefix = "2001:db8:5001::/48".parse().unwrap();
        let resolver = FakeResolver(Ok(vec![
            "2001:db8:5002:64::c000:aa".parse().unwrap(),
            "2001:db8:5002:64::c000:ab".parse().unwrap(),
        ]));
        let setup = Nat64Setup::apply(vec![configured], &resolver).await;
        let discovered: Nat64Prefix = "2001:db8:5002:64::/96".parse().unwrap();
        assert_eq!(setup.configured, [configured]);
        assert_eq!(setup.discovered, [discovered]);
        assert_eq!(setup.discovery_error, None);
        // Both now classify translated private addresses as internal.
        for internal in ["2001:db8:5001:a00:1::", "2001:db8:5002:64::a00:1"] {
            assert!(
                openshell_core::net::is_internal_ip(internal.parse().unwrap()),
                "{internal}"
            );
        }
        let fields = unmapped(&setup.event());
        assert_eq!(fields["nat64_configured_prefixes"][0], "2001:db8:5001::/48");
        assert_eq!(
            fields["nat64_discovered_prefixes"][0],
            "2001:db8:5002:64::/96"
        );
    }

    #[tokio::test]
    async fn nat64_setup_without_dns64_is_not_an_error() {
        let setup =
            Nat64Setup::apply(Vec::new(), &FakeResolver(Err(|| ResolveError::NoData))).await;
        assert!(setup.discovered.is_empty());
        assert_eq!(setup.discovery_error, None);
        let setup =
            Nat64Setup::apply(Vec::new(), &FakeResolver(Err(|| ResolveError::Timeout))).await;
        assert!(setup.discovery_error.is_some());
        assert_eq!(
            unmapped(&setup.event())["nat64_discovery_error"],
            "trusted DNS exchange timed out"
        );
    }
}
