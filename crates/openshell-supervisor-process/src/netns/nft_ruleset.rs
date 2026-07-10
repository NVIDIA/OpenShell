// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! nftables ruleset generation for sandbox network bypass enforcement.
//!
//! This module provides pure functions to generate nftables rulesets that enforce
//! the sandbox network policy: all traffic must go through the proxy, with bypass
//! attempts logged and rejected.
//!
//! Rulesets are returned as a sequence of individual nft commands rather than a
//! monolithic file. Running each command as a separate `nft` invocation avoids
//! `nft -f` atomic batch semantics, where a single unsupported expression (e.g.
//! `ct state` without `nf_conntrack`, `log` without `nf_log`) rolls back the
//! entire transaction including table/chain creation.

/// A single nft command with metadata about whether it is required.
pub struct NftCommand {
    /// The nft command arguments (e.g. `["add", "table", "inet", "openshell_bypass"]`).
    pub args: Vec<String>,
    /// When false, failure of this command is non-fatal; the caller should
    /// log a warning and continue with the remaining commands.
    pub required: bool,
}

/// Generate nft commands for sandbox network bypass enforcement.
///
/// Creates an `inet` family table (handles both IPv4 and IPv6) with rules that:
/// 1. Accept traffic to the proxy (IPv4 only)
/// 2. Accept loopback traffic
/// 3. Accept established/related connections (optional; requires `nf_conntrack`)
/// 4. Reject TCP and UDP bypass attempts (both IPv4 and IPv6)
///
/// If `log_prefix` is provided, log rules are inserted before each reject rule
/// so that bypass attempts are recorded in the kernel ring buffer before being
/// rejected. Log rules are always non-required since they need `nf_log` support.
pub fn generate_bypass_commands(
    host_ip: &str,
    proxy_port: u16,
    log_prefix: Option<&str>,
) -> Vec<NftCommand> {
    let table = "openshell_bypass";
    let mut cmds = vec![
        nft_cmd(true, &["add", "table", "inet", table]),
        nft_cmd(true, &["flush", "table", "inet", table]),
        nft_cmd(
            true,
            &[
                "add",
                "chain",
                "inet",
                table,
                "output",
                "{ type filter hook output priority 0; policy accept; }",
            ],
        ),
        nft_cmd(
            true,
            &[
                "add",
                "rule",
                "inet",
                table,
                "output",
                "ip",
                "daddr",
                host_ip,
                "tcp",
                "dport",
                &proxy_port.to_string(),
                "accept",
            ],
        ),
        nft_cmd(
            true,
            &[
                "add", "rule", "inet", table, "output", "oifname", "lo", "accept",
            ],
        ),
        nft_cmd(
            false,
            &[
                "add",
                "rule",
                "inet",
                table,
                "output",
                "ct",
                "state",
                "established,related",
                "accept",
            ],
        ),
    ];

    if let Some(prefix) = log_prefix {
        cmds.push(nft_cmd(
            false,
            &[
                "add", "rule", "inet", table, "output", "tcp", "flags", "syn", "limit", "rate",
                "5/second", "burst", "10", "packets", "log", "prefix", prefix, "flags", "skuid",
            ],
        ));
    }

    cmds.push(nft_cmd(
        true,
        &[
            "add",
            "rule",
            "inet",
            table,
            "output",
            "meta",
            "nfproto",
            "ipv4",
            "meta",
            "l4proto",
            "tcp",
            "reject",
            "with",
            "icmp",
            "type",
            "port-unreachable",
        ],
    ));
    cmds.push(nft_cmd(
        true,
        &[
            "add",
            "rule",
            "inet",
            table,
            "output",
            "meta",
            "nfproto",
            "ipv6",
            "meta",
            "l4proto",
            "tcp",
            "reject",
            "with",
            "icmpv6",
            "type",
            "port-unreachable",
        ],
    ));

    if let Some(prefix) = log_prefix {
        cmds.push(nft_cmd(
            false,
            &[
                "add", "rule", "inet", table, "output", "meta", "l4proto", "udp", "limit", "rate",
                "5/second", "burst", "10", "packets", "log", "prefix", prefix, "flags", "skuid",
            ],
        ));
    }

    cmds.push(nft_cmd(
        true,
        &[
            "add",
            "rule",
            "inet",
            table,
            "output",
            "meta",
            "nfproto",
            "ipv4",
            "meta",
            "l4proto",
            "udp",
            "reject",
            "with",
            "icmp",
            "type",
            "port-unreachable",
        ],
    ));
    cmds.push(nft_cmd(
        true,
        &[
            "add",
            "rule",
            "inet",
            table,
            "output",
            "meta",
            "nfproto",
            "ipv6",
            "meta",
            "l4proto",
            "udp",
            "reject",
            "with",
            "icmpv6",
            "type",
            "port-unreachable",
        ],
    ));

    cmds
}

/// Generate nft commands for Kubernetes sidecar enforcement.
///
/// The network sidecar and the process supervisor share a pod network
/// namespace. The sidecar runs as `proxy_uid` and owns external egress;
/// sandbox traffic must use loopback services hosted by that sidecar
/// (gateway forward and HTTP CONNECT proxy). The generated fence rejects
/// TCP/UDP bypass attempts from non-proxy UIDs; other L4 protocols are outside
/// the sidecar policy fence.
pub fn generate_sidecar_bypass_commands(
    proxy_uid: u32,
    log_prefix: Option<&str>,
) -> Vec<NftCommand> {
    let table = "openshell_sidecar_bypass";
    let uid_str = proxy_uid.to_string();
    let mut cmds = vec![
        nft_cmd(true, &["add", "table", "inet", table]),
        nft_cmd(true, &["flush", "table", "inet", table]),
        nft_cmd(
            true,
            &[
                "add",
                "chain",
                "inet",
                table,
                "output",
                "{ type filter hook output priority 0; policy accept; }",
            ],
        ),
        nft_cmd(
            true,
            &[
                "add", "rule", "inet", table, "output", "oifname", "lo", "accept",
            ],
        ),
        nft_cmd(
            false,
            &[
                "add",
                "rule",
                "inet",
                table,
                "output",
                "ct",
                "state",
                "established,related",
                "accept",
            ],
        ),
        nft_cmd(
            true,
            &[
                "add", "rule", "inet", table, "output", "meta", "skuid", &uid_str, "accept",
            ],
        ),
    ];

    if let Some(prefix) = log_prefix {
        cmds.push(nft_cmd(
            false,
            &[
                "add", "rule", "inet", table, "output", "tcp", "flags", "syn", "limit", "rate",
                "5/second", "burst", "10", "packets", "log", "prefix", prefix, "flags", "skuid",
            ],
        ));
    }

    cmds.push(nft_cmd(
        true,
        &[
            "add",
            "rule",
            "inet",
            table,
            "output",
            "meta",
            "nfproto",
            "ipv4",
            "meta",
            "l4proto",
            "tcp",
            "reject",
            "with",
            "icmp",
            "type",
            "port-unreachable",
        ],
    ));
    cmds.push(nft_cmd(
        true,
        &[
            "add",
            "rule",
            "inet",
            table,
            "output",
            "meta",
            "nfproto",
            "ipv6",
            "meta",
            "l4proto",
            "tcp",
            "reject",
            "with",
            "icmpv6",
            "type",
            "port-unreachable",
        ],
    ));

    if let Some(prefix) = log_prefix {
        cmds.push(nft_cmd(
            false,
            &[
                "add", "rule", "inet", table, "output", "meta", "l4proto", "udp", "limit", "rate",
                "5/second", "burst", "10", "packets", "log", "prefix", prefix, "flags", "skuid",
            ],
        ));
    }

    cmds.push(nft_cmd(
        true,
        &[
            "add",
            "rule",
            "inet",
            table,
            "output",
            "meta",
            "nfproto",
            "ipv4",
            "meta",
            "l4proto",
            "udp",
            "reject",
            "with",
            "icmp",
            "type",
            "port-unreachable",
        ],
    ));
    cmds.push(nft_cmd(
        true,
        &[
            "add",
            "rule",
            "inet",
            table,
            "output",
            "meta",
            "nfproto",
            "ipv6",
            "meta",
            "l4proto",
            "udp",
            "reject",
            "with",
            "icmpv6",
            "type",
            "port-unreachable",
        ],
    ));

    cmds
}

fn nft_cmd(required: bool, args: &[&str]) -> NftCommand {
    NftCommand {
        args: args.iter().map(|s| (*s).to_string()).collect(),
        required,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd_str(cmd: &NftCommand) -> String {
        cmd.args.join(" ")
    }

    fn all_strs(cmds: &[NftCommand]) -> String {
        cmds.iter().map(cmd_str).collect::<Vec<_>>().join("\n")
    }

    #[test]
    fn generates_bypass_commands_with_proxy_rule() {
        let cmds = generate_bypass_commands("10.0.2.2", 8080, None);
        let text = all_strs(&cmds);
        assert!(text.contains("add table inet openshell_bypass"));
        assert!(text.contains("add chain inet openshell_bypass output"));
        assert!(text.contains("ip daddr 10.0.2.2 tcp dport 8080 accept"));
    }

    #[test]
    fn bypass_commands_have_table_and_chain() {
        let cmds = generate_bypass_commands("192.168.1.1", 3128, None);
        let text = all_strs(&cmds);
        assert!(text.contains("add table inet openshell_bypass"));
        assert!(text.contains("type filter hook output priority 0; policy accept;"));
    }

    #[test]
    fn proxy_accept_rule_uses_provided_ip_and_port() {
        let cmds = generate_bypass_commands("172.16.0.1", 9999, None);
        let text = all_strs(&cmds);
        assert!(text.contains("ip daddr 172.16.0.1 tcp dport 9999 accept"));
    }

    #[test]
    fn rules_are_ordered_accept_then_reject() {
        let cmds = generate_bypass_commands("10.0.2.2", 8080, None);
        let text = all_strs(&cmds);
        let proxy_pos = text.find("ip daddr").unwrap();
        let lo_pos = text.find("oifname lo").unwrap();
        let ct_pos = text.find("ct state established,related").unwrap();
        let reject_pos = text.find("reject with icmp type").unwrap();

        assert!(proxy_pos < lo_pos);
        assert!(lo_pos < ct_pos);
        assert!(ct_pos < reject_pos);
    }

    #[test]
    fn both_ipv4_and_ipv6_reject_types_are_present() {
        let cmds = generate_bypass_commands("10.0.2.2", 8080, None);
        let text = all_strs(&cmds);
        let icmp_count = text
            .matches("reject with icmp type port-unreachable")
            .count();
        let icmpv6_count = text
            .matches("reject with icmpv6 type port-unreachable")
            .count();
        assert_eq!(icmp_count, 2, "need IPv4 ICMP rejects for TCP + UDP");
        assert_eq!(icmpv6_count, 2, "need IPv6 ICMPv6 rejects for TCP + UDP");
    }

    #[test]
    fn no_log_commands_omit_log_rules() {
        let cmds = generate_bypass_commands("10.0.2.2", 8080, None);
        let text = all_strs(&cmds);
        assert!(
            !text.contains("log prefix"),
            "no-log commands must not contain log rules"
        );
    }

    #[test]
    fn log_commands_contain_prefix_for_tcp_and_udp() {
        let cmds = generate_bypass_commands("10.0.2.2", 8080, Some("openshell:bypass:test:"));
        let text = all_strs(&cmds);
        let count = text.matches("log prefix openshell:bypass:test:").count();
        assert_eq!(count, 2, "need log rules for both TCP and UDP");
        assert!(text.contains("tcp flags syn limit rate 5/second burst 10 packets"));
        assert!(text.contains("meta l4proto udp limit rate 5/second burst 10 packets"));
    }

    #[test]
    fn log_rules_appear_before_reject_rules() {
        let cmds = generate_bypass_commands("10.0.2.2", 8080, Some("openshell:bypass:test:"));
        let text = all_strs(&cmds);
        let tcp_log_pos = text.find("tcp flags syn").unwrap();
        let tcp_reject_pos = text
            .find("meta nfproto ipv4 meta l4proto tcp reject")
            .unwrap();
        let udp_log_pos = text.find("meta l4proto udp limit rate").unwrap();
        let udp_reject_pos = text
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
    fn ct_state_rule_is_not_required() {
        let cmds = generate_bypass_commands("10.0.2.2", 8080, None);
        let ct_cmd = cmds
            .iter()
            .find(|c| cmd_str(c).contains("ct state"))
            .unwrap();
        assert!(
            !ct_cmd.required,
            "ct state rule should be non-required (needs nf_conntrack)"
        );
    }

    #[test]
    fn log_rules_are_not_required() {
        let cmds = generate_bypass_commands("10.0.2.2", 8080, Some("openshell:bypass:test:"));
        for cmd in &cmds {
            if cmd_str(cmd).contains("log prefix") {
                assert!(
                    !cmd.required,
                    "log rules should be non-required (needs nf_log)"
                );
            }
        }
    }

    #[test]
    fn sidecar_commands_allow_supervisor_uid_and_loopback() {
        let cmds = generate_sidecar_bypass_commands(1337, None);
        let text = all_strs(&cmds);
        assert!(text.contains("add table inet openshell_sidecar_bypass"));
        assert!(text.contains("oifname lo accept"));
        assert!(text.contains("meta skuid 1337 accept"));
    }

    #[test]
    fn sidecar_commands_reject_tcp_and_udp_egress() {
        let cmds = generate_sidecar_bypass_commands(0, Some("openshell:sidecar:test:"));
        let text = all_strs(&cmds);
        assert!(text.contains("meta nfproto ipv4 meta l4proto tcp reject"));
        assert!(text.contains("meta nfproto ipv6 meta l4proto tcp reject"));
        assert!(text.contains("meta nfproto ipv4 meta l4proto udp reject"));
        assert!(text.contains("meta nfproto ipv6 meta l4proto udp reject"));
        assert_eq!(
            text.matches("log prefix openshell:sidecar:test:").count(),
            2
        );
    }
}
