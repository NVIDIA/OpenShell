// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! nftables ruleset generation for sandbox network bypass enforcement.
//!
//! This module provides pure functions to generate nftables rulesets that enforce
//! the sandbox network policy: all traffic must go through the proxy, with bypass
//! attempts logged and rejected.

/// Generate a complete nftables ruleset for sandbox network bypass enforcement.
///
/// Creates an `inet` family table (handles both IPv4 and IPv6) with rules that:
/// 1. Accept traffic to the proxy (IPv4 only)
/// 2. Accept loopback traffic
/// 3. Accept established/related connections
/// 4. Reject TCP and UDP bypass attempts (both IPv4 and IPv6)
///
/// If `log_prefix` is provided, log rules are inserted before each reject rule
/// so that bypass attempts are recorded in the kernel ring buffer before being
/// rejected. The `log` expression requires kernel `nft_log` module support;
/// pass `None` for `log_prefix` as a fallback when that module is unavailable.
pub fn generate_bypass_ruleset(host_ip: &str, proxy_port: u16, log_prefix: Option<&str>) -> String {
    let log_tcp = log_prefix
        .map(|p| {
            format!(
                "\n        tcp flags syn limit rate 5/second burst 10 packets log prefix \"{p}\" flags skuid"
            )
        })
        .unwrap_or_default();
    let log_udp = log_prefix
        .map(|p| {
            format!(
                "\n        meta l4proto udp limit rate 5/second burst 10 packets log prefix \"{p}\" flags skuid"
            )
        })
        .unwrap_or_default();

    format!(
        r#"table inet openshell_bypass {{
    chain output {{
        type filter hook output priority 0; policy accept;

        ip daddr {host_ip} tcp dport {proxy_port} accept
        oifname "lo" accept
        ct state established,related accept{log_tcp}
        meta nfproto ipv4 meta l4proto tcp reject with icmp type port-unreachable
        meta nfproto ipv6 meta l4proto tcp reject with icmpv6 type port-unreachable{log_udp}
        meta nfproto ipv4 meta l4proto udp reject with icmp type port-unreachable
        meta nfproto ipv6 meta l4proto udp reject with icmpv6 type port-unreachable
    }}
}}
"#
    )
}

/// Generate a pod-network ruleset for Kubernetes sidecar enforcement.
///
/// The network sidecar and the process supervisor share a pod network
/// namespace. The sidecar runs as `proxy_uid` and owns external egress;
/// sandbox traffic must use loopback services hosted by that sidecar
/// (gateway forward and HTTP CONNECT proxy). The generated fence rejects
/// TCP/UDP bypass attempts from non-proxy UIDs; other L4 protocols are outside
/// the sidecar policy fence.
pub fn generate_sidecar_bypass_ruleset(proxy_uid: u32, log_prefix: Option<&str>) -> String {
    let log_tcp = log_prefix
        .map(|p| {
            format!(
                "\n        tcp flags syn limit rate 5/second burst 10 packets log prefix \"{p}\" flags skuid"
            )
        })
        .unwrap_or_default();
    let log_udp = log_prefix
        .map(|p| {
            format!(
                "\n        meta l4proto udp limit rate 5/second burst 10 packets log prefix \"{p}\" flags skuid"
            )
        })
        .unwrap_or_default();

    format!(
        r#"table inet openshell_sidecar_bypass {{
    chain output {{
        type filter hook output priority 0; policy accept;

        oifname "lo" accept
        ct state established,related accept
        meta skuid {proxy_uid} accept{log_tcp}
        meta nfproto ipv4 meta l4proto tcp reject with icmp type port-unreachable
        meta nfproto ipv6 meta l4proto tcp reject with icmpv6 type port-unreachable{log_udp}
        meta nfproto ipv4 meta l4proto udp reject with icmp type port-unreachable
        meta nfproto ipv6 meta l4proto udp reject with icmpv6 type port-unreachable
    }}
}}
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_bypass_ruleset_with_proxy_rule() {
        let ruleset = generate_bypass_ruleset("10.0.2.2", 8080, None);
        assert!(ruleset.contains("table inet openshell_bypass"));
        assert!(ruleset.contains("chain output"));
        assert!(ruleset.contains("ip daddr 10.0.2.2 tcp dport 8080 accept"));
    }

    #[test]
    fn ruleset_has_inet_family_table_and_output_chain() {
        let ruleset = generate_bypass_ruleset("192.168.1.1", 3128, None);
        assert!(ruleset.contains("table inet openshell_bypass"));
        assert!(ruleset.contains("type filter hook output priority 0; policy accept;"));
    }

    #[test]
    fn proxy_accept_rule_uses_provided_ip_and_port() {
        let ruleset = generate_bypass_ruleset("172.16.0.1", 9999, None);
        assert!(ruleset.contains("ip daddr 172.16.0.1 tcp dport 9999 accept"));
    }

    #[test]
    fn rules_are_ordered_accept_then_reject() {
        let ruleset = generate_bypass_ruleset("10.0.2.2", 8080, None);
        let proxy_pos = ruleset.find("ip daddr").unwrap();
        let lo_pos = ruleset.find("oifname \"lo\"").unwrap();
        let ct_pos = ruleset.find("ct state established,related").unwrap();
        let reject_pos = ruleset.find("reject with icmp type").unwrap();

        assert!(proxy_pos < lo_pos);
        assert!(lo_pos < ct_pos);
        assert!(ct_pos < reject_pos);
    }

    #[test]
    fn both_ipv4_and_ipv6_reject_types_are_present() {
        let ruleset = generate_bypass_ruleset("10.0.2.2", 8080, None);
        let icmp_count = ruleset
            .matches("reject with icmp type port-unreachable")
            .count();
        let icmpv6_count = ruleset
            .matches("reject with icmpv6 type port-unreachable")
            .count();
        assert_eq!(icmp_count, 2, "need IPv4 ICMP rejects for TCP + UDP");
        assert_eq!(icmpv6_count, 2, "need IPv6 ICMPv6 rejects for TCP + UDP");
    }

    #[test]
    fn no_log_ruleset_omits_log_rules() {
        let ruleset = generate_bypass_ruleset("10.0.2.2", 8080, None);
        assert!(
            !ruleset.contains("log prefix"),
            "no-log ruleset must not contain log rules"
        );
    }

    #[test]
    fn log_ruleset_contains_prefix_for_tcp_and_udp() {
        let ruleset = generate_bypass_ruleset("10.0.2.2", 8080, Some("openshell:bypass:test:"));
        let count = ruleset
            .matches("log prefix \"openshell:bypass:test:\"")
            .count();
        assert_eq!(count, 2, "need log rules for both TCP and UDP");
        assert!(ruleset.contains("tcp flags syn limit rate 5/second burst 10 packets"));
        assert!(ruleset.contains("meta l4proto udp limit rate 5/second burst 10 packets"));
    }

    #[test]
    fn log_rules_appear_before_reject_rules() {
        let ruleset = generate_bypass_ruleset("10.0.2.2", 8080, Some("openshell:bypass:test:"));
        let tcp_log_pos = ruleset.find("tcp flags syn").unwrap();
        let tcp_reject_pos = ruleset
            .find("meta nfproto ipv4 meta l4proto tcp reject")
            .unwrap();
        let udp_log_pos = ruleset.find("meta l4proto udp limit rate").unwrap();
        let udp_reject_pos = ruleset
            .find("meta nfproto ipv4 meta l4proto udp reject")
            .unwrap();

        assert!(
            tcp_log_pos < tcp_reject_pos,
            "TCP log rule must come before TCP reject rule"
        );
        assert!(
            udp_log_pos < udp_reject_pos,
            "UDP log rule must come before UDP reject rule"
        );
    }

    #[test]
    fn sidecar_ruleset_allows_supervisor_uid_and_loopback() {
        let ruleset = generate_sidecar_bypass_ruleset(1337, None);
        assert!(ruleset.contains("table inet openshell_sidecar_bypass"));
        assert!(ruleset.contains("oifname \"lo\" accept"));
        assert!(ruleset.contains("meta skuid 1337 accept"));
    }

    #[test]
    fn sidecar_ruleset_rejects_tcp_and_udp_egress() {
        let ruleset = generate_sidecar_bypass_ruleset(0, Some("openshell:sidecar:test:"));
        assert!(ruleset.contains("meta nfproto ipv4 meta l4proto tcp reject"));
        assert!(ruleset.contains("meta nfproto ipv6 meta l4proto tcp reject"));
        assert!(ruleset.contains("meta nfproto ipv4 meta l4proto udp reject"));
        assert!(ruleset.contains("meta nfproto ipv6 meta l4proto udp reject"));
        assert_eq!(
            ruleset
                .matches("log prefix \"openshell:sidecar:test:\"")
                .count(),
            2
        );
    }
}
