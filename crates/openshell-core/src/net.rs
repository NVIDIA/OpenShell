// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Network IP classification utilities shared across OpenShell crates.
//!
//! These helpers enforce the always-blocked IP invariant (loopback, link-local,
//! unspecified) and the broader internal-IP classification (adds RFC 1918 and
//! ULA).  They are used by:
//! - The sandbox proxy for runtime SSRF enforcement
//! - The mechanistic mapper for proposal filtering
//! - The gateway server for defense-in-depth validation on approval

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Check if an IP address is always blocked regardless of policy.
///
/// Loopback, link-local, and unspecified addresses are never allowed even when
/// an endpoint has `allowed_ips` configured. This prevents proxy bypass
/// (loopback) and cloud metadata SSRF (link-local 169.254.x.x).
pub fn is_always_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return true;
            }
            // fe80::/10 — IPv6 link-local
            if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // Check IPv4-mapped IPv6 (::ffff:x.x.x.x)
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_loopback() || v4.is_link_local() || v4.is_unspecified();
            }
            false
        }
    }
}

/// Check if a CIDR network overlaps any always-blocked range.
///
/// Returns `true` if the network contains or overlaps loopback (`127.0.0.0/8`),
/// link-local (`169.254.0.0/16`), unspecified (`0.0.0.0`), or their IPv6
/// equivalents.  A CIDR like `0.0.0.0/0` is rejected because it contains
/// always-blocked addresses.
///
/// Used at policy load time and server-side approval to reject entries that
/// would be silently blocked at runtime by [`is_always_blocked_ip`].
pub fn is_always_blocked_net(net: ipnet::IpNet) -> bool {
    match net {
        ipnet::IpNet::V4(v4net) => {
            let network = v4net.network();
            let broadcast = v4net.broadcast();

            // Check if the range overlaps 127.0.0.0/8 (loopback)
            if broadcast >= Ipv4Addr::new(127, 0, 0, 0)
                && network <= Ipv4Addr::new(127, 255, 255, 255)
            {
                return true;
            }

            // Check if the range overlaps 169.254.0.0/16 (link-local)
            if broadcast >= Ipv4Addr::new(169, 254, 0, 0)
                && network <= Ipv4Addr::new(169, 254, 255, 255)
            {
                return true;
            }

            // Check if the range contains 0.0.0.0 (unspecified)
            if network == Ipv4Addr::UNSPECIFIED {
                return true;
            }

            false
        }
        ipnet::IpNet::V6(v6net) => {
            // For IPv6, check the network address itself and representative
            // addresses within the range.
            let network = v6net.network();

            // ::1 (loopback)
            if v6net.contains(&Ipv6Addr::LOCALHOST) {
                return true;
            }

            // :: (unspecified)
            if v6net.contains(&Ipv6Addr::UNSPECIFIED) {
                return true;
            }

            // fe80::/10 (link-local) — check overlap
            if (network.segments()[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // Also check if a broad prefix contains fe80::
            if v6net.contains(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)) {
                return true;
            }

            // Check IPv4-mapped IPv6 (::ffff:127.0.0.1, ::ffff:169.254.x.x, etc.)
            if let Some(v4) = network.to_ipv4_mapped() {
                if v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() {
                    return true;
                }
            }

            false
        }
    }
}

/// Check if an IP address is internal (loopback, private RFC 1918, link-local,
/// or unspecified).
///
/// This is a broader check than [`is_always_blocked_ip`] — it includes RFC 1918
/// private ranges (`10/8`, `172.16/12`, `192.168/16`), CGNAT (`100.64.0.0/10`,
/// RFC 6598), other special-use ranges, and IPv6 ULA (`fc00::/7`) which are
/// allowable via `allowed_ips` but blocked by default without one.
///
/// Used by the proxy's default SSRF path and the mechanistic mapper to detect
/// when `allowed_ips` should be populated in proposals.
pub fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_internal_v4(&v4),
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return true;
            }
            // fe80::/10 — IPv6 link-local
            if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // fc00::/7 — IPv6 unique local addresses (ULA)
            if (v6.segments()[0] & 0xfe00) == 0xfc00 {
                return true;
            }
            // Check IPv4-mapped IPv6 (::ffff:x.x.x.x)
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_internal_v4(&v4);
            }
            false
        }
    }
}

/// IPv4 internal address check covering RFC 1918, CGNAT (RFC 6598), and other
/// special-use ranges that should never be reachable from sandbox egress.
fn is_internal_v4(v4: &Ipv4Addr) -> bool {
    if v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified() {
        return true;
    }
    let octets = v4.octets();
    // 100.64.0.0/10 — CGNAT / shared address space (RFC 6598). Commonly used by
    // cloud VPC peering, Tailscale, and similar overlay networks.
    if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
        return true;
    }
    // 192.0.0.0/24 — IETF protocol assignments (RFC 6890)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return true;
    }
    // 198.18.0.0/15 — benchmarking (RFC 2544)
    if octets[0] == 198 && (octets[1] & 0xFE) == 18 {
        return true;
    }
    // 198.51.100.0/24 — TEST-NET-2 (RFC 5737)
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return true;
    }
    // 203.0.113.0/24 — TEST-NET-3 (RFC 5737)
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- is_always_blocked_ip --

    #[test]
    fn test_always_blocked_ip_loopback_v4() {
        assert!(is_always_blocked_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_always_blocked_ip(IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 2
        ))));
    }

    #[test]
    fn test_always_blocked_ip_link_local_v4() {
        assert!(is_always_blocked_ip(IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        ))));
        assert!(is_always_blocked_ip(IpAddr::V4(Ipv4Addr::new(
            169, 254, 0, 1
        ))));
    }

    #[test]
    fn test_always_blocked_ip_loopback_v6() {
        assert!(is_always_blocked_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_always_blocked_ip_link_local_v6() {
        assert!(is_always_blocked_ip(IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn test_always_blocked_ip_unspecified_v4() {
        assert!(is_always_blocked_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    }

    #[test]
    fn test_always_blocked_ip_unspecified_v6() {
        assert!(is_always_blocked_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn test_always_blocked_ip_ipv4_mapped_v6_loopback() {
        let v6 = Ipv4Addr::LOCALHOST.to_ipv6_mapped();
        assert!(is_always_blocked_ip(IpAddr::V6(v6)));
    }

    #[test]
    fn test_always_blocked_ip_ipv4_mapped_v6_link_local() {
        let v6 = Ipv4Addr::new(169, 254, 169, 254).to_ipv6_mapped();
        assert!(is_always_blocked_ip(IpAddr::V6(v6)));
    }

    #[test]
    fn test_always_blocked_ip_allows_rfc1918() {
        assert!(!is_always_blocked_ip(IpAddr::V4(Ipv4Addr::new(
            10, 0, 0, 1
        ))));
        assert!(!is_always_blocked_ip(IpAddr::V4(Ipv4Addr::new(
            172, 16, 0, 1
        ))));
        assert!(!is_always_blocked_ip(IpAddr::V4(Ipv4Addr::new(
            192, 168, 0, 1
        ))));
    }

    #[test]
    fn test_always_blocked_ip_allows_public() {
        assert!(!is_always_blocked_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_always_blocked_ip(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888
        ))));
    }

    // -- is_always_blocked_net --

    #[test]
    fn test_always_blocked_net_loopback_v4() {
        let net: ipnet::IpNet = "127.0.0.0/8".parse().unwrap();
        assert!(is_always_blocked_net(net));
    }

    #[test]
    fn test_always_blocked_net_link_local_v4() {
        let net: ipnet::IpNet = "169.254.0.0/16".parse().unwrap();
        assert!(is_always_blocked_net(net));
    }

    #[test]
    fn test_always_blocked_net_unspecified_v4() {
        let net: ipnet::IpNet = "0.0.0.0/32".parse().unwrap();
        assert!(is_always_blocked_net(net));
    }

    #[test]
    fn test_always_blocked_net_loopback_v6() {
        let net: ipnet::IpNet = "::1/128".parse().unwrap();
        assert!(is_always_blocked_net(net));
    }

    #[test]
    fn test_always_blocked_net_link_local_v6() {
        let net: ipnet::IpNet = "fe80::/10".parse().unwrap();
        assert!(is_always_blocked_net(net));
    }

    #[test]
    fn test_always_blocked_net_ipv4_mapped_v6_loopback() {
        let net: ipnet::IpNet = "::ffff:127.0.0.1/128".parse().unwrap();
        assert!(is_always_blocked_net(net));
    }

    #[test]
    fn test_always_blocked_net_allows_rfc1918() {
        let net10: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let net172: ipnet::IpNet = "172.16.0.0/12".parse().unwrap();
        let net192: ipnet::IpNet = "192.168.0.0/16".parse().unwrap();
        assert!(!is_always_blocked_net(net10));
        assert!(!is_always_blocked_net(net172));
        assert!(!is_always_blocked_net(net192));
    }

    #[test]
    fn test_always_blocked_net_allows_public() {
        let net: ipnet::IpNet = "8.8.8.0/24".parse().unwrap();
        assert!(!is_always_blocked_net(net));
    }

    #[test]
    fn test_always_blocked_net_single_ip_loopback() {
        let net: ipnet::IpNet = "127.0.0.1/32".parse().unwrap();
        assert!(is_always_blocked_net(net));
    }

    #[test]
    fn test_always_blocked_net_single_ip_metadata() {
        let net: ipnet::IpNet = "169.254.169.254/32".parse().unwrap();
        assert!(is_always_blocked_net(net));
    }

    #[test]
    fn test_always_blocked_net_broad_cidr_containing_blocked() {
        // 0.0.0.0/0 contains everything including unspecified, loopback, link-local
        let net: ipnet::IpNet = "0.0.0.0/0".parse().unwrap();
        assert!(is_always_blocked_net(net));
    }

    #[test]
    fn test_always_blocked_net_v6_broad_containing_loopback() {
        let net: ipnet::IpNet = "::/0".parse().unwrap();
        assert!(is_always_blocked_net(net));
    }

    // -- is_internal_ip --

    #[test]
    fn test_internal_ip_rfc1918() {
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
    }

    #[test]
    fn test_internal_ip_loopback() {
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_internal_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_internal_ip_link_local() {
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        ))));
    }

    #[test]
    fn test_internal_ip_unspecified() {
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(is_internal_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn test_internal_ip_v6_ula() {
        assert!(is_internal_ip(IpAddr::V6(Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(is_internal_ip(IpAddr::V6(Ipv6Addr::new(
            0xfd00, 0, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn test_internal_ip_allows_public() {
        assert!(!is_internal_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_internal_ip(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888
        ))));
    }

    #[test]
    fn test_internal_ip_ipv4_mapped_v6() {
        let v6 = Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped();
        assert!(is_internal_ip(IpAddr::V6(v6)));
        let v6_public = Ipv4Addr::new(8, 8, 8, 8).to_ipv6_mapped();
        assert!(!is_internal_ip(IpAddr::V6(v6_public)));
    }

    #[test]
    fn test_internal_ip_cgnat() {
        // 100.64.0.0/10 — CGNAT / shared address space (RFC 6598)
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(100, 100, 50, 3))));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(
            100, 127, 255, 255
        ))));
        // Just outside the /10 boundary
        assert!(!is_internal_ip(IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1))));
        assert!(!is_internal_ip(IpAddr::V4(Ipv4Addr::new(
            100, 63, 255, 255
        ))));
    }

    #[test]
    fn test_internal_ip_special_use_ranges() {
        // 192.0.0.0/24 — IETF protocol assignments
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 0, 1))));
        // 198.18.0.0/15 — benchmarking
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(198, 19, 255, 255))));
        // 198.51.100.0/24 — TEST-NET-2
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
        // 203.0.113.0/24 — TEST-NET-3
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
    }

    #[test]
    fn test_internal_ip_ipv6_mapped_cgnat() {
        let v6 = Ipv4Addr::new(100, 64, 0, 1).to_ipv6_mapped();
        assert!(is_internal_ip(IpAddr::V6(v6)));
    }
}
