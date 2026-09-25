// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! NAT64 address handling for SSRF classification.
//!
//! A NAT64 translator forwards an IPv6 destination inside its prefix to the
//! IPv4 address embedded in it (RFC 6052). On a DNS64 network an IPv4-only
//! name resolves to such an address, so `10.0.0.5` can be reached as
//! `64:ff9b::a00:5`, or as `<network-specific prefix>::a00:5`. The SSRF
//! predicates in [`super`] classify these addresses by their embedded IPv4
//! address so the IPv4 protections cannot be bypassed through the translator.
//!
//! The well-known prefix `64:ff9b::/96` is always recognized. Network-specific
//! prefixes are learned at runtime (RFC 7050 discovery by the supervisor) and
//! registered with [`register_network_prefix`].

use ipnet::Ipv6Net;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::RwLock;

/// The RFC 6052 well-known prefix, `64:ff9b::/96`.
pub const WELL_KNOWN_PREFIX: Nat64Prefix = Nat64Prefix(Ipv6Net::new_assert(
    Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0),
    96,
));

/// The RFC 8215 local-use IPv4/IPv6 translation range, `64:ff9b:1::/48`.
///
/// The IANA special-purpose registry marks it as not globally reachable, and
/// the embedding length inside it is chosen by the operator. Addresses in it
/// that are not covered by a registered prefix are treated as internal.
pub const LOCAL_USE_NET: Ipv6Net =
    Ipv6Net::new_assert(Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0), 48);

/// The well-known IPv4 addresses behind `ipv4only.arpa` (RFC 7050 §2.2).
const IPV4ONLY_ARPA_ADDRESSES: [Ipv4Addr; 2] =
    [Ipv4Addr::new(192, 0, 0, 170), Ipv4Addr::new(192, 0, 0, 171)];

/// Prefix lengths RFC 6052 §2.2 allows, longest first so discovery prefers
/// the common `/96` layout when an answer matches more than one.
const PREFIX_LENGTHS: [u8; 6] = [96, 64, 56, 48, 40, 32];

/// Index of the RFC 6052 "u" octet (bits 64..71), which never carries IPv4
/// bits.
const U_OCTET: usize = 8;

static NETWORK_PREFIXES: RwLock<Vec<Nat64Prefix>> = RwLock::new(Vec::new());

/// A NAT64 prefix with an RFC 6052 embedding length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nat64Prefix(Ipv6Net);

/// Why a prefix cannot be used as a NAT64 prefix.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("NAT64 prefix {0} must be /32, /40, /48, /56, /64 or /96 (RFC 6052)")]
pub struct InvalidNat64Prefix(Ipv6Net);

impl Nat64Prefix {
    /// Build a prefix, truncating host bits.
    pub fn new(net: Ipv6Net) -> Result<Self, InvalidNat64Prefix> {
        if PREFIX_LENGTHS.contains(&net.prefix_len()) {
            Ok(Self(net.trunc()))
        } else {
            Err(InvalidNat64Prefix(net))
        }
    }

    /// The prefix as a network.
    #[must_use]
    pub const fn net(self) -> Ipv6Net {
        self.0
    }

    /// The IPv4 address a translator using this prefix would forward `addr`
    /// to, or `None` when `addr` is outside the prefix.
    ///
    /// The "u" octet and suffix are ignored rather than validated, so an
    /// address with non-zero reserved bits is still classified by the IPv4
    /// address a lenient translator would reach.
    #[must_use]
    pub fn embedded_ipv4(self, addr: Ipv6Addr) -> Option<Ipv4Addr> {
        if !self.0.contains(&addr) {
            return None;
        }
        let o = addr.octets();
        let v4 = match self.0.prefix_len() {
            32 => [o[4], o[5], o[6], o[7]],
            40 => [o[5], o[6], o[7], o[9]],
            48 => [o[6], o[7], o[9], o[10]],
            56 => [o[7], o[9], o[10], o[11]],
            64 => [o[9], o[10], o[11], o[12]],
            _ => [o[12], o[13], o[14], o[15]],
        };
        Some(Ipv4Addr::from(v4))
    }

    /// Derive the prefix from one AAAA answer for `ipv4only.arpa`
    /// (RFC 7050 §3). Returns `None` when the answer does not embed a
    /// well-known `ipv4only.arpa` address at any RFC 6052 position.
    #[must_use]
    pub fn from_ipv4only_arpa_answer(addr: Ipv6Addr) -> Option<Self> {
        PREFIX_LENGTHS.iter().find_map(|&len| {
            if len < 96 && addr.octets()[U_OCTET] != 0 {
                return None;
            }
            let prefix = Self(Ipv6Net::new(addr, len).ok()?.trunc());
            prefix
                .embedded_ipv4(addr)
                .filter(|v4| IPV4ONLY_ARPA_ADDRESSES.contains(v4))
                .map(|_| prefix)
        })
    }
}

impl std::str::FromStr for Nat64Prefix {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let net = raw
            .trim()
            .parse::<Ipv6Net>()
            .map_err(|_| format!("NAT64 prefix '{raw}' is not an IPv6 CIDR"))?;
        Self::new(net).map_err(|error| error.to_string())
    }
}

impl std::fmt::Display for Nat64Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Register a network-specific prefix for this process.
///
/// Registration is append-only: a prefix can only make more addresses subject
/// to IPv4 classification, never fewer. Returns `false` when the prefix was
/// already known.
pub fn register_network_prefix(prefix: Nat64Prefix) -> bool {
    if prefix == WELL_KNOWN_PREFIX {
        return false;
    }
    let mut prefixes = NETWORK_PREFIXES
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if prefixes.contains(&prefix) {
        return false;
    }
    prefixes.push(prefix);
    true
}

/// Network-specific prefixes registered in this process.
#[must_use]
pub fn network_prefixes() -> Vec<Nat64Prefix> {
    NETWORK_PREFIXES
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// The IPv4 address `addr` translates to under the well-known prefix or any
/// registered network-specific prefix.
#[must_use]
pub fn embedded_ipv4(addr: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = WELL_KNOWN_PREFIX.embedded_ipv4(addr) {
        return Some(v4);
    }
    NETWORK_PREFIXES
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find_map(|prefix| prefix.embedded_ipv4(addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(raw: &str) -> Nat64Prefix {
        Nat64Prefix::new(raw.parse().unwrap()).unwrap()
    }

    #[test]
    fn rejects_non_rfc6052_lengths_and_truncates_host_bits() {
        assert!(Nat64Prefix::new("2001:db8::/80".parse().unwrap()).is_err());
        assert!(Nat64Prefix::new("2001:db8::/128".parse().unwrap()).is_err());
        assert_eq!(
            prefix("2001:db8::1/96").net(),
            "2001:db8::/96".parse::<Ipv6Net>().unwrap()
        );
    }

    #[test]
    fn extracts_ipv4_at_every_rfc6052_length() {
        // RFC 6052 §2.4 examples for 192.0.2.33.
        let expected = Ipv4Addr::new(192, 0, 2, 33);
        for (net, addr) in [
            ("2001:db8::/32", "2001:db8:c000:221::"),
            ("2001:db8:100::/40", "2001:db8:1c0:2:21::"),
            ("2001:db8:122::/48", "2001:db8:122:c000:2:2100::"),
            ("2001:db8:122:300::/56", "2001:db8:122:3c0:0:221::"),
            ("2001:db8:122:344::/64", "2001:db8:122:344:c0:2:2100:0"),
            ("2001:db8:122:344::/96", "2001:db8:122:344::192.0.2.33"),
        ] {
            let addr = addr.parse().unwrap();
            assert_eq!(prefix(net).embedded_ipv4(addr), Some(expected), "{net}");
            assert_eq!(
                Nat64Prefix::from_ipv4only_arpa_answer(addr),
                None,
                "{net}: 192.0.2.33 is not an ipv4only.arpa address"
            );
        }
        assert_eq!(
            WELL_KNOWN_PREFIX.embedded_ipv4("64:ff9b::192.0.2.33".parse().unwrap()),
            Some(expected)
        );
        assert_eq!(
            WELL_KNOWN_PREFIX.embedded_ipv4("64:ff9c::192.0.2.33".parse().unwrap()),
            None
        );
    }

    #[test]
    fn non_zero_u_octet_is_still_classified() {
        let addr = "2001:db8:122:344:ff0a:0:100:0".parse().unwrap();
        assert_eq!(
            prefix("2001:db8:122:344::/64").embedded_ipv4(addr),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    #[test]
    fn discovers_prefix_from_ipv4only_arpa_answers() {
        for (answer, expected) in [
            ("64:ff9b::c000:aa", "64:ff9b::/96"),
            (
                "2600:1f18:4928:5601:d32b::c000:ab",
                "2600:1f18:4928:5601:d32b::/96",
            ),
            ("2001:db8:122:344:c0:0:aa00:0", "2001:db8:122:344::/64"),
            ("2001:db8:c000:aa::", "2001:db8::/32"),
        ] {
            assert_eq!(
                Nat64Prefix::from_ipv4only_arpa_answer(answer.parse().unwrap()),
                Some(prefix(expected)),
                "{answer}"
            );
        }
        assert_eq!(
            Nat64Prefix::from_ipv4only_arpa_answer("2001:4860:4860::8888".parse().unwrap()),
            None
        );
    }

    #[test]
    fn registry_is_append_only_and_ignores_the_well_known_prefix() {
        let nsp = prefix("2001:db8:64:1::/96");
        let addr = "2001:db8:64:1::a00:1".parse().unwrap();
        assert!(!register_network_prefix(WELL_KNOWN_PREFIX));
        register_network_prefix(nsp);
        assert!(!register_network_prefix(nsp));
        assert!(network_prefixes().contains(&nsp));
        assert_eq!(embedded_ipv4(addr), Some(Ipv4Addr::new(10, 0, 0, 1)));
    }
}
