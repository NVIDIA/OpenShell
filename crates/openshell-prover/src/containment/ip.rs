// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Destination-address predicates for the explicit proxy. DNS answers and the
//! trusted gateway binding are universally quantified, not resolved by the CLI.

use super::{
    ContainmentPolicy, Endpoint, SymbolicAction, binaries_match, bool_or,
    endpoint_matches_connection, str_eq_any,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use z3::ast::{Ast, BV, Bool};
use z3::{Model, Solver};

const HARD_V4: &[&str] = &["127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/32"];
const HARD_V6: &[&str] = &["::/128", "::1/128", "fe80::/10"];
const INTERNAL_V4: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "255.255.255.255/32",
    "100.64.0.0/10",
    "192.0.0.0/24",
    "198.18.0.0/15",
];

pub(super) struct SymbolicIp {
    bits: BV,
    v6: Bool,
}

impl SymbolicIp {
    pub(super) fn new(name: &str) -> Self {
        Self {
            bits: BV::new_const(format!("{name}_destination_ip"), 128),
            v6: Bool::new_const(format!("{name}_ipv6")),
        }
    }

    pub(super) fn concrete(ip: IpAddr) -> Self {
        let net = Network::from_ip(ip);
        Self {
            bits: bits(net.address),
            v6: Bool::from_bool(net.v6),
        }
    }

    pub(super) fn assert_domain(&self, solver: &Solver) {
        solver.assert(
            self.v6
                .not()
                .implies(self.bits.extract(127, 32).eq(BV::from_u64(0, 96))),
        );
    }

    pub(super) fn decode(&self, model: &Model) -> Option<IpAddr> {
        let high = model.eval(&self.bits.extract(127, 64), true)?.as_u64()?;
        let low = model.eval(&self.bits.extract(63, 0), true)?.as_u64()?;
        Some(if model.eval(&self.v6, true)?.as_bool()? {
            IpAddr::V6(Ipv6Addr::from((u128::from(high) << 64) | u128::from(low)))
        } else {
            IpAddr::V4(Ipv4Addr::from(u32::try_from(low).ok()?))
        })
    }

    fn matches(&self, net: Network) -> Bool {
        Bool::and(&[
            self.v6.eq(Bool::from_bool(net.v6)),
            self.bits
                .bvand(bits(net.mask()))
                .eq(bits(net.address & net.mask())),
        ])
    }

    fn ranges(&self, ranges: &[&str]) -> Bool {
        bool_or(
            ranges
                .iter()
                .map(|range| self.matches(Network::parse(range).unwrap())),
        )
    }

    fn mapped_v4_ranges(&self, ranges: &[&str]) -> Bool {
        bool_or(ranges.iter().map(|range| {
            let v4 = Network::parse(range).unwrap();
            self.matches(Network {
                v6: true,
                address: (0xffff_u128 << 32) | v4.address,
                prefix: 96 + v4.prefix,
            })
        }))
    }

    fn hard_blocked(&self) -> Bool {
        Bool::or(&[
            self.ranges(HARD_V4),
            self.ranges(HARD_V6),
            self.mapped_v4_ranges(HARD_V4),
        ])
    }

    fn internal(&self) -> Bool {
        Bool::or(&[
            self.hard_blocked(),
            self.ranges(INTERNAL_V4),
            self.mapped_v4_ranges(INTERNAL_V4),
            self.ranges(&["fc00::/7"]),
        ])
    }
}

fn bits(value: u128) -> BV {
    let high = u64::try_from(value >> 64).expect("high 64 bits");
    let low = u64::try_from(value & u128::from(u64::MAX)).expect("low 64 bits");
    BV::from_u64(high, 64).concat(BV::from_u64(low, 64))
}

#[derive(Clone, Copy)]
struct Network {
    address: u128,
    prefix: u32,
    v6: bool,
}

impl Network {
    fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => Self {
                address: u128::from(u32::from(ip)),
                prefix: 32,
                v6: false,
            },
            IpAddr::V6(ip) => Self {
                address: u128::from(ip),
                prefix: 128,
                v6: true,
            },
        }
    }

    fn parse(value: &str) -> Option<Self> {
        let (address, prefix) = value
            .split_once('/')
            .map_or((value, None), |(a, p)| (a, Some(p)));
        let mut network = Self::from_ip(address.parse().ok()?);
        if let Some(prefix) = prefix {
            let prefix = prefix.parse().ok()?;
            if prefix > network.prefix {
                return None;
            }
            network.prefix = prefix;
        }
        Some(network)
    }

    fn mask(self) -> u128 {
        let width = if self.v6 { 128 } else { 32 };
        if self.prefix == 0 {
            0
        } else {
            u128::MAX << (width - self.prefix)
        }
    }

    fn overlaps(self, other: Self) -> bool {
        self.v6 == other.v6
            && (self.address & self.mask() & other.mask())
                == (other.address & self.mask() & other.mask())
    }
}

pub(super) fn unsupported_endpoint(endpoint: &Endpoint) -> Option<String> {
    // Numeric wildcard hosts can match IP literals, whose implicit allowlist
    // depends on the input string. Keep that unresolved rather than treating
    // them as ordinary DNS names.
    if endpoint.host.contains('*')
        && endpoint
            .host
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'*'))
    {
        return Some(
            "uses an IP-literal wildcard whose address resolution is not modeled".to_owned(),
        );
    }
    for raw in &endpoint.allowed_ips {
        let Some(net) = Network::parse(raw) else {
            return Some(format!("has invalid allowed_ips entry '{raw}'"));
        };
        let blocked = HARD_V4
            .iter()
            .chain(HARD_V6)
            .map(|range| Network::parse(range).unwrap());
        let mut blocked = blocked.chain(HARD_V4.iter().map(|range| {
            let v4 = Network::parse(range).unwrap();
            Network {
                v6: true,
                address: (0xffff_u128 << 32) | v4.address,
                prefix: 96 + v4.prefix,
            }
        }));
        if blocked.any(|blocked| net.overlaps(blocked)) {
            return Some(format!(
                "has allowed_ips entry '{raw}' overlapping a runtime always-blocked range"
            ));
        }
    }
    None
}

pub(super) fn sample_addresses(endpoint: &Endpoint) -> Vec<IpAddr> {
    let mut addresses = vec!["8.8.8.8".parse().unwrap(), "10.0.0.1".parse().unwrap()];
    if let Some(net) = endpoint
        .allowed_ips
        .first()
        .and_then(|raw| Network::parse(raw))
    {
        let address = net.address & net.mask();
        addresses.push(if net.v6 {
            IpAddr::V6(Ipv6Addr::from(address))
        } else {
            IpAddr::V4(Ipv4Addr::from(
                u32::try_from(address).expect("IPv4 network"),
            ))
        });
    }
    addresses
}

pub(super) fn policy_allows(
    policy: &ContainmentPolicy,
    action: &SymbolicAction,
    binary_identity_required: bool,
) -> Bool {
    bool_or(policy.network_policies.values().flat_map(|rule| {
        rule.endpoints.iter().map(move |endpoint| {
            let selected = Bool::and(&[
                binaries_match(rule, action, binary_identity_required),
                endpoint_matches_connection(endpoint, action),
            ]);
            let exact = !endpoint.host.contains('*');
            let control_port =
                bool_or([2379_u64, 2380, 6443, 10250, 10255].map(|port| action.port.eq(port)));
            let ordinary = if endpoint.allowed_ips.is_empty() {
                endpoint.host.parse::<IpAddr>().map_or_else(
                    |_| {
                        if exact {
                            Bool::and(&[!action.ip.hard_blocked(), !control_port.clone()])
                        } else {
                            !action.ip.internal()
                        }
                    },
                    |ip| {
                        Bool::and(&[
                            action.ip.matches(Network::from_ip(ip)),
                            !action.ip.hard_blocked(),
                            !control_port.clone(),
                        ])
                    },
                )
            } else {
                Bool::and(&[
                    bool_or(endpoint.allowed_ips.iter().map(|raw| {
                        action
                            .ip
                            .matches(Network::parse(raw).expect("validated CIDR"))
                    })),
                    !action.ip.hard_blocked(),
                    !control_port.clone(),
                ])
            };
            let alias = str_eq_any(
                &action.host,
                &[
                    "host.openshell.internal",
                    "host.containers.internal",
                    "host.docker.internal",
                ],
            );
            let trusted = Bool::and(&[alias, action.trusted_gateway.clone()]);
            let gateway = Bool::and(&[
                Bool::or(&[
                    action.ip.ranges(&["169.254.0.0/16", "fe80::/10"]),
                    action.ip.mapped_v4_ranges(&["169.254.0.0/16"]),
                ]),
                !action.ip.ranges(&["169.254.169.254/32"]),
                !action.ip.mapped_v4_ranges(&["169.254.169.254/32"]),
                !control_port,
            ]);
            let can_match_gateway = [
                "host.openshell.internal",
                "host.containers.internal",
                "host.docker.internal",
            ]
            .iter()
            .any(|alias| {
                z3::ast::String::from(*alias)
                    .regex_matches(&super::glob_regex(&endpoint.host.to_ascii_lowercase(), "."))
                    .simplify()
                    .as_bool()
                    != Some(false)
            });
            let address = if can_match_gateway {
                trusted.ite(&gateway, &ordinary)
            } else {
                ordinary
            };
            // A literal destination cannot resolve to another address even
            // when the explicit CIDR covers that other address.
            let literal = endpoint.host.parse::<IpAddr>().map_or_else(
                |_| Bool::from_bool(true),
                |ip| action.ip.matches(Network::from_ip(ip)),
            );
            Bool::and(&[selected, address, literal])
        })
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::containment::{
        CheckOptions, CheckResult, Counterexample, check_within_boundary, parse_policy_str,
    };

    fn policy(host: &str, ips: &str) -> ContainmentPolicy {
        parse_policy_str(&format!("version: 1\nnetwork_policies:\n  api:\n    endpoints: [{{host: '{host}', port: 443, allowed_ips: [{ips}]}}]\n    binaries: [{{path: /usr/bin/curl}}]\n")).unwrap()
    }

    fn check(host: &str, boundary: &str, candidate: &str) -> CheckResult {
        check_within_boundary(&policy(host, boundary), &policy(host, candidate), options())
    }

    fn options() -> CheckOptions {
        CheckOptions {
            timeout: std::time::Duration::from_secs(10),
        }
    }

    #[test]
    fn ipv4_ipv6_and_cidr_union_containment() {
        for (maximum, candidate) in [
            ("10.0.0.0/8", "10.2.0.0/16"),
            ("2001:db8::/32", "2001:db8:1234::/48"),
            ("10.0.0.0/9, 10.128.0.0/9", "10.0.0.0/8"),
            ("10.2.3.4", "10.2.3.4/32"),
        ] {
            let result = check("api.example.com", maximum, candidate);
            assert!(
                matches!(result, CheckResult::Within(_)),
                "{maximum} -> {candidate}: {result:?}"
            );
        }
        for (maximum, candidate) in [
            ("10.2.0.0/16", "10.0.0.0/8"),
            ("2001:db8:1234::/48", "2001:db8::/32"),
            ("10.0.0.0/8", "2001:db8::/32"),
        ] {
            let result = check("api.example.com", maximum, candidate);
            assert!(matches!(result, CheckResult::Exceeds(_)), "{result:?}");
            if let CheckResult::Exceeds(evidence) = result {
                assert!(matches!(
                    evidence.counterexample(),
                    Counterexample::Network { .. }
                ));
            }
        }
    }

    #[test]
    fn defaults_and_aliases_use_runtime_modes() {
        assert!(matches!(
            check("api.example.com", "", "10.2.0.0/16"),
            CheckResult::Within(_)
        ));
        assert!(matches!(
            check("api.example.com", "10.2.0.0/16", ""),
            CheckResult::Exceeds(_)
        ));
        let private_expansion = check("*.example.com", "", "10.2.0.0/16");
        assert!(
            matches!(private_expansion, CheckResult::Exceeds(_)),
            "{private_expansion:?}"
        );
        assert!(matches!(
            check("host.openshell.internal", "10.0.0.0/8", "10.2.0.0/16"),
            CheckResult::Within(_)
        ));
        assert!(matches!(
            check("host.openshell.internal", "10.2.0.0/16", "10.0.0.0/8"),
            CheckResult::Exceeds(_)
        ));
        let result = check_within_boundary(
            &policy("*.example.com", ""),
            &policy("api.example.com", ""),
            options(),
        );
        assert!(
            matches!(result, CheckResult::Exceeds(_)),
            "exact declarations permit private addresses unlike wildcard defaults: {result:?}"
        );
    }

    #[test]
    fn malformed_blocked_and_order_dependent_inputs_are_unsupported() {
        for ips in [
            "not-an-ip",
            "10.0.0.1/99",
            "127.0.0.0/8",
            "::ffff:127.0.0.1",
            "0.0.0.0/0",
            "::/0",
        ] {
            assert!(
                matches!(
                    check("api.example.com", ips, ips),
                    CheckResult::Unsupported(_)
                ),
                "{ips}"
            );
        }
        let mut ambiguous = policy("api.example.com", "10.0.0.0/8");
        let mut second = ambiguous.network_policies["api"].endpoints[0].clone();
        second.allowed_ips = vec!["10.1.0.0/16".to_owned()];
        ambiguous
            .network_policies
            .get_mut("api")
            .unwrap()
            .endpoints
            .push(second);
        assert!(matches!(
            check_within_boundary(&ambiguous, &ambiguous, options()),
            CheckResult::Unsupported(_)
        ));
    }

    #[test]
    fn address_classification_matches_runtime() {
        for raw in [
            "8.8.8.8",
            "10.1.2.3",
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "192.0.2.1",
            "100.64.0.1",
            "198.18.0.1",
            "::",
            "::1",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:10.2.3.4",
            "::ffff:8.8.8.8",
        ] {
            let ip: IpAddr = raw.parse().unwrap();
            let symbolic = SymbolicIp::concrete(ip);
            assert_eq!(
                symbolic.hard_blocked().simplify().as_bool(),
                Some(openshell_core::net::is_always_blocked_ip(ip)),
                "{raw}"
            );
            assert_eq!(
                symbolic.internal().simplify().as_bool(),
                Some(openshell_core::net::is_internal_ip(ip)),
                "{raw}"
            );
        }
    }

    #[test]
    fn excessive_ip_ranges_fail_before_constructing_the_model() {
        let mut huge = policy("api.example.com", "10.0.0.0/8");
        huge.network_policies.get_mut("api").unwrap().endpoints[0].allowed_ips =
            vec!["10.0.0.0/8".to_owned(); 4097];
        assert!(
            matches!(check_within_boundary(&huge, &huge, options()), CheckResult::Inconclusive(ref reason) if reason.reason_code() == super::super::ReasonCode::ResourceLimit)
        );
    }
}
