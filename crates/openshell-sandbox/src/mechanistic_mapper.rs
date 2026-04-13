// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Mechanistic policy mapper — deterministically converts denial summaries into
//! draft `NetworkPolicyRule` proposals.
//!
//! This is the "zero-LLM" baseline for policy recommendations. It inspects
//! denial patterns (host, port, binary, frequency) and generates concrete rules
//! that would allow the denied connections, annotated with confidence scores and
//! security notes.
//!
//! The LLM-powered `PolicyAdvisor` (issue #205) wraps and enriches these
//! mechanistic proposals with context-aware rationale and smarter grouping.

use openshell_core::net::{is_always_blocked_ip, is_internal_ip};
use openshell_core::proto::{
    DenialSummary, L7Allow, L7Rule, NetworkBinary, NetworkEndpoint, NetworkPolicyRule, PolicyChunk,
};
use std::collections::HashMap;
use std::net::IpAddr;

/// Well-known ports that get higher confidence scores.
const WELL_KNOWN_PORTS: &[(u16, &str)] = &[
    (80, "HTTP"),
    (443, "HTTPS"),
    (8080, "HTTP-alt"),
    (8443, "HTTPS-alt"),
    (5432, "PostgreSQL"),
    (3306, "MySQL"),
    (6379, "Redis"),
    (27017, "MongoDB"),
    (9200, "Elasticsearch"),
    (9092, "Kafka"),
    (2181, "ZooKeeper"),
    (11211, "Memcached"),
    (5672, "RabbitMQ"),
    (6443, "Kubernetes API"),
    (53, "DNS"),
    (587, "SMTP"),
    (993, "IMAP"),
    (995, "POP3"),
];

/// Generate draft `PolicyChunk` proposals from denial summaries.
///
/// Groups denials by `(host, port, binary)`, then for each group generates a
/// `PolicyChunk` with a `NetworkPolicyRule` allowing that endpoint for that
/// single binary. This produces one proposal per binary so each
/// `(sandbox_id, host, port, binary)` maps to exactly one DB row.
///
/// When a host resolves to a private IP (RFC 1918, loopback, link-local),
/// the proposed endpoint includes `allowed_ips` so the proxy's SSRF override
/// accepts the connection. Public IPs do not need `allowed_ips`.
///
/// Returns an empty vec if there are no actionable denials.
pub async fn generate_proposals(summaries: &[DenialSummary]) -> Vec<PolicyChunk> {
    // Group denials by (host, port, binary).
    let mut groups: HashMap<(String, u32, String), Vec<&DenialSummary>> = HashMap::new();

    for summary in summaries {
        let binary_key = if summary.binary.is_empty() {
            String::new()
        } else {
            summary.binary.clone()
        };
        groups
            .entry((summary.host.clone(), summary.port, binary_key))
            .or_default()
            .push(summary);
    }

    let mut proposals = Vec::new();

    for ((host, port, binary), denials) in &groups {
        let rule_name = generate_rule_name(host, *port);

        let mut total_count: u32 = 0;
        let mut first_seen_ms: i64 = i64::MAX;
        let mut last_seen_ms: i64 = 0;
        let mut is_ssrf = false;

        for denial in denials {
            total_count += denial.count;
            first_seen_ms = first_seen_ms.min(denial.first_seen_ms);
            last_seen_ms = last_seen_ms.max(denial.last_seen_ms);
            if denial.denial_stage == "ssrf" {
                is_ssrf = true;
            }
        }

        // Collect L7 request samples across all denials in this group.
        let mut l7_methods: HashMap<(String, String), u32> = HashMap::new();
        let mut has_l7 = false;
        for denial in denials {
            if denial.l7_inspection_active || !denial.l7_request_samples.is_empty() {
                has_l7 = true;
            }
            for sample in &denial.l7_request_samples {
                *l7_methods
                    .entry((sample.method.clone(), sample.path.clone()))
                    .or_insert(0) += sample.count;
            }
        }

        // Skip proposals for always-blocked destinations (loopback,
        // link-local, unspecified).  These would be denied at runtime by the
        // proxy's is_always_blocked_ip check regardless of policy, producing
        // an infinite proposal loop in the TUI.
        if is_always_blocked_destination(host) {
            tracing::info!(
                host,
                port,
                "Skipped proposal for always-blocked destination \
                 (SSRF hardening — loopback/link-local/unspecified)"
            );
            continue;
        }

        // Resolve the host and check if any IP is private. When a host
        // resolves to private IP space, the proxy requires `allowed_ips` as an
        // explicit SSRF override. Public IPs don't need this.
        let allowed_ips = resolve_allowed_ips_if_private(host, *port).await;

        // Build proposed NetworkPolicyRule.
        let l7_rules = build_l7_rules(&l7_methods);
        let endpoint = if has_l7 && !l7_rules.is_empty() {
            NetworkEndpoint {
                host: host.clone(),
                port: *port,
                ports: vec![*port],
                protocol: "rest".to_string(),
                enforcement: "enforce".to_string(),
                rules: l7_rules,
                allowed_ips: allowed_ips.clone(),
                ..Default::default()
            }
        } else {
            NetworkEndpoint {
                host: host.clone(),
                port: *port,
                ports: vec![*port],
                allowed_ips: allowed_ips.clone(),
                ..Default::default()
            }
        };

        let binaries: Vec<NetworkBinary> = if binary.is_empty() {
            vec![]
        } else {
            vec![NetworkBinary {
                path: binary.clone(),
                ..Default::default()
            }]
        };

        let proposed_rule = NetworkPolicyRule {
            name: rule_name.clone(),
            endpoints: vec![endpoint],
            binaries,
        };

        // Compute confidence.
        #[allow(clippy::cast_possible_truncation)]
        let confidence = compute_confidence(total_count, *port as u16, is_ssrf);

        // Generate rationale.
        let binary_list = if binary.is_empty() {
            "unknown binary".to_string()
        } else {
            short_binary_name(binary)
        };

        #[allow(clippy::cast_possible_truncation)]
        let port_u16 = *port as u16;
        let port_name = WELL_KNOWN_PORTS
            .iter()
            .find(|(p, _)| *p == port_u16)
            .map(|(_, name)| format!(" ({name})"))
            .unwrap_or_default();

        let private_ip_note = if !allowed_ips.is_empty() {
            format!(
                " Host resolves to private IP ({}); allowed_ips included for SSRF override.",
                allowed_ips.join(", ")
            )
        } else {
            String::new()
        };

        // Note: hit_count in the DB accumulates across flush cycles, so we
        // don't bake a denial count into the rationale text (it would go stale).
        let rationale = if has_l7 && !l7_methods.is_empty() {
            let paths: Vec<String> = l7_methods.keys().map(|(m, p)| format!("{m} {p}")).collect();
            format!(
                "Allow {binary_list} to connect to {host}:{port}{port_name} \
                 with L7 inspection. \
                 Allowed paths: {}.{private_ip_note}",
                paths.join(", ")
            )
        } else {
            format!(
                "Allow {binary_list} to connect to \
                 {host}:{port}{port_name}.{private_ip_note}"
            )
        };

        // Generate security notes.
        #[allow(clippy::cast_possible_truncation)]
        let security_notes = generate_security_notes(host, *port as u16, is_ssrf);

        // Determine stage based on denial source.
        let stage = denials
            .first()
            .map_or_else(|| "connect".to_string(), |d| d.denial_stage.clone());

        proposals.push(PolicyChunk {
            id: String::new(), // Assigned by the gateway on persist
            status: "pending".to_string(),
            rule_name,
            proposed_rule: Some(proposed_rule),
            rationale,
            security_notes,
            confidence,
            denial_summary_ids: vec![],
            created_at_ms: 0, // Set by gateway on persist
            decided_at_ms: 0,
            stage,
            supersedes_chunk_id: String::new(),
            hit_count: total_count as i32,
            first_seen_ms,
            last_seen_ms,
            binary: binary.clone(),
        });
    }

    // Sort proposals by confidence (highest first).
    proposals.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    proposals
}

/// Generate a rule name that doesn't conflict with existing rules.
/// Generate a deterministic, idempotent rule name from host and port.
///
/// The same `(host, port)` always produces the same name. DB-level dedup on
/// `(sandbox_id, host, port, binary)` handles collisions — no need to check
/// existing rule names.
fn generate_rule_name(host: &str, port: u32) -> String {
    let sanitized = host
        .replace(['.', '-'], "_")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .collect::<String>();

    format!("allow_{sanitized}_{port}")
}

/// Compute a confidence score (0.0 to 1.0) for a proposed rule.
fn compute_confidence(total_count: u32, port: u16, is_ssrf: bool) -> f32 {
    let mut score: f32 = 0.5;

    // Higher count → higher confidence (the denial is repeatable).
    if total_count >= 10 {
        score += 0.2;
    } else if total_count >= 3 {
        score += 0.1;
    }

    // Well-known port → higher confidence.
    if WELL_KNOWN_PORTS.iter().any(|(p, _)| *p == port) {
        score += 0.15;
    }

    // SSRF denials are lower confidence (may be legitimate blocking).
    if is_ssrf {
        score -= 0.2;
    }

    score.clamp(0.1, 0.95)
}

/// Generate security notes for a proposed rule.
fn generate_security_notes(host: &str, port: u16, is_ssrf: bool) -> String {
    let mut notes = Vec::new();

    if is_ssrf {
        notes.push(
            "This connection was blocked by SSRF protection. \
             Allowing it bypasses internal-IP safety checks."
                .to_string(),
        );
    }

    // Check for private IP patterns in the host.
    if host.starts_with("10.")
        || host.starts_with("172.")
        || host.starts_with("192.168.")
        || host == "localhost"
        || host.starts_with("127.")
    {
        notes.push(format!(
            "Destination '{host}' appears to be an internal/private address."
        ));
    }

    // High port numbers may indicate ephemeral services.
    if port > 49152 {
        notes.push(format!(
            "Port {port} is in the ephemeral range — \
             this may be a temporary service."
        ));
    }

    // Database ports get extra scrutiny.
    let db_ports = [5432, 3306, 6379, 27017, 9200, 11211, 5672];
    if db_ports.contains(&port) {
        notes.push(format!(
            "Port {port} is a well-known database/service port. \
             Consider restricting with L7 rules or read-only access."
        ));
    }

    notes.join(" ")
}

/// Build L7 allow-rules from observed (method, path) samples.
///
/// Groups paths by HTTP method and generalises path patterns where possible:
///   - `/v1/models/abc123` → `/v1/models/**`   (ID-like trailing segments)
///   - `/api/v2/users/42`  → `/api/v2/users/*` (numeric trailing segment)
///
/// Falls back to the exact observed path when no pattern applies.
fn build_l7_rules(samples: &HashMap<(String, String), u32>) -> Vec<L7Rule> {
    // Deduplicate after generalisation.
    let mut seen: HashMap<(String, String), ()> = HashMap::new();
    let mut rules = Vec::new();

    for (method, path) in samples.keys() {
        let generalised = generalise_path(path);
        let key = (method.clone(), generalised.clone());
        if seen.contains_key(&key) {
            continue;
        }
        seen.insert(key, ());

        rules.push(L7Rule {
            allow: Some(L7Allow {
                method: method.clone(),
                path: generalised,
                command: String::new(),
                query: HashMap::new(),
            }),
        });
    }

    // Sort for deterministic output.
    rules.sort_by(|a, b| {
        let a = a.allow.as_ref().unwrap();
        let b = b.allow.as_ref().unwrap();
        (&a.method, &a.path).cmp(&(&b.method, &b.path))
    });

    rules
}

/// Generalise a URL path for policy rules.
///
/// Heuristics:
///   - Strip query strings.
///   - If the last segment looks like an ID (hex, UUID, or numeric), replace
///     with `*`.
///   - Preserve all other segments verbatim.
fn generalise_path(raw: &str) -> String {
    // Strip query string.
    let path = raw.split('?').next().unwrap_or(raw);

    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() <= 1 {
        return path.to_string();
    }

    let last = segments.last().unwrap_or(&"");

    // Replace ID-like trailing segments with a wildcard.
    if looks_like_id(last) {
        let mut out = segments[..segments.len() - 1].join("/");
        out.push_str("/*");
        return out;
    }

    path.to_string()
}

/// Heuristic: does a path segment look like an opaque identifier?
fn looks_like_id(segment: &str) -> bool {
    if segment.is_empty() {
        return false;
    }
    // Pure numeric
    if segment.chars().all(|c| c.is_ascii_digit()) && segment.len() >= 2 {
        return true;
    }
    // UUID-ish (contains dashes, 32+ hex chars)
    let hex_only: String = segment.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex_only.len() >= 24 && segment.contains('-') {
        return true;
    }
    // Long hex string (hash, token)
    if hex_only.len() >= 16 && segment.len() == hex_only.len() {
        return true;
    }
    false
}

/// Extract just the binary name from a full path.
fn short_binary_name(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

/// Check if a destination host is always-blocked.
///
/// For literal IP hosts, checks against [`is_always_blocked_ip`].
/// For hostnames like "localhost", checks well-known loopback names.
/// For other hostnames, returns false (DNS may resolve to anything).
fn is_always_blocked_destination(host: &str) -> bool {
    // Check literal IP addresses
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_always_blocked_ip(ip);
    }
    // Check well-known loopback hostnames
    let host_lc = host.to_lowercase();
    host_lc == "localhost" || host_lc == "localhost."
}

/// Resolve a hostname and return the IPs as `allowed_ips` strings only if any
/// resolved address is in private IP space.
///
/// When a host resolves entirely to public IPs, the proxy doesn't need
/// `allowed_ips` — it passes public traffic through after the OPA check.
/// When any resolved IP is private/internal, the proxy requires `allowed_ips`
/// as an explicit SSRF override, so the mapper includes them.
///
/// Returns an empty vec for public hosts or on DNS resolution failure.
async fn resolve_allowed_ips_if_private(host: &str, port: u32) -> Vec<String> {
    let addr = format!("{host}:{port}");
    let addrs = match tokio::net::lookup_host(&addr).await {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(e) => {
            let event = openshell_ocsf::NetworkActivityBuilder::new(crate::ocsf_ctx())
                .activity(openshell_ocsf::ActivityId::Fail)
                .severity(openshell_ocsf::SeverityId::Low)
                .dst_endpoint(openshell_ocsf::Endpoint::from_domain(host, port as u16))
                .message(format!("DNS resolution failed for allowed_ips check: {e}"))
                .build();
            openshell_ocsf::ocsf_emit!(event);
            return Vec::new();
        }
    };

    if addrs.is_empty() {
        let event = openshell_ocsf::NetworkActivityBuilder::new(crate::ocsf_ctx())
            .activity(openshell_ocsf::ActivityId::Fail)
            .severity(openshell_ocsf::SeverityId::Low)
            .dst_endpoint(openshell_ocsf::Endpoint::from_domain(host, port as u16))
            .message(format!(
                "DNS resolution returned no addresses for {host}:{port}"
            ))
            .build();
        openshell_ocsf::ocsf_emit!(event);
        return Vec::new();
    }

    let has_private = addrs.iter().any(|a| is_internal_ip(a.ip()));
    if !has_private {
        return Vec::new();
    }

    // Host has private IPs — include non-always-blocked resolved IPs in
    // allowed_ips.  Always-blocked addresses (loopback, link-local,
    // unspecified) are filtered out since the proxy will reject them
    // regardless of policy.
    let mut ips: Vec<String> = addrs
        .iter()
        .filter(|a| !is_always_blocked_ip(a.ip()))
        .map(|a| a.ip().to_string())
        .collect();
    ips.sort();
    ips.dedup();

    if ips.is_empty() {
        // All resolved IPs were always-blocked — no viable allowed_ips.
        tracing::debug!(
            host,
            port,
            "All resolved IPs are always-blocked; skipping allowed_ips"
        );
        return Vec::new();
    }

    tracing::debug!(
        host,
        port,
        ?ips,
        "Host resolves to private IP; adding allowed_ips"
    );
    ips
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_rule_name() {
        let name = generate_rule_name("example.com", 443);
        assert_eq!(name, "allow_example_com_443");
    }

    #[test]
    fn test_generate_rule_name_subdomain() {
        let name = generate_rule_name("api.github.com", 443);
        assert_eq!(name, "allow_api_github_com_443");
    }

    #[test]
    fn test_compute_confidence() {
        // Well-known port + high count
        let conf = compute_confidence(10, 443, false);
        assert!(conf > 0.8);

        // SSRF
        let conf = compute_confidence(5, 80, true);
        assert!(conf < 0.6);
    }

    #[test]
    fn test_security_notes_ssrf() {
        let notes = generate_security_notes("169.254.169.254", 80, true);
        assert!(notes.contains("SSRF"));
    }

    #[tokio::test]
    async fn test_generate_proposals_empty() {
        let proposals = generate_proposals(&[]).await;
        assert!(proposals.is_empty());
    }

    #[tokio::test]
    async fn test_generate_proposals_basic() {
        let summaries = vec![DenialSummary {
            sandbox_id: "test".to_string(),
            host: "api.example.com".to_string(),
            port: 443,
            binary: "/usr/bin/curl".to_string(),
            ancestors: vec![],
            deny_reason: "no matching policy".to_string(),
            first_seen_ms: 1000,
            last_seen_ms: 2000,
            count: 5,
            suppressed_count: 0,
            total_count: 5,
            sample_cmdlines: vec![],
            binary_sha256: String::new(),
            persistent: false,
            denial_stage: "connect".to_string(),
            l7_request_samples: vec![],
            l7_inspection_active: false,
        }];

        let proposals = generate_proposals(&summaries).await;
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].rule_name, "allow_api_example_com_443");
        assert!(proposals[0].proposed_rule.is_some());

        let rule = proposals[0].proposed_rule.as_ref().unwrap();
        assert_eq!(rule.endpoints.len(), 1);
        assert_eq!(rule.endpoints[0].host, "api.example.com");
        assert_eq!(rule.endpoints[0].port, 443);
        assert_eq!(rule.binaries.len(), 1);
        assert_eq!(rule.binaries[0].path, "/usr/bin/curl");

        // No L7 fields when no samples provided.
        assert!(rule.endpoints[0].protocol.is_empty());
        assert!(rule.endpoints[0].rules.is_empty());

        // Public host should NOT have allowed_ips.
        assert!(
            rule.endpoints[0].allowed_ips.is_empty(),
            "Public host should not get allowed_ips"
        );
    }

    #[tokio::test]
    async fn test_generate_proposals_with_l7_samples() {
        use openshell_core::proto::L7RequestSample;

        let summaries = vec![DenialSummary {
            sandbox_id: "test".to_string(),
            host: "icanhazdadjoke.com".to_string(),
            port: 443,
            binary: "/usr/bin/python3".to_string(),
            ancestors: vec![],
            deny_reason: "l7 deny".to_string(),
            first_seen_ms: 1000,
            last_seen_ms: 2000,
            count: 3,
            suppressed_count: 0,
            total_count: 3,
            sample_cmdlines: vec![],
            binary_sha256: String::new(),
            persistent: false,
            denial_stage: "l7_deny".to_string(),
            l7_request_samples: vec![
                L7RequestSample {
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    decision: "deny".to_string(),
                    count: 2,
                },
                L7RequestSample {
                    method: "GET".to_string(),
                    path: "/j/abc123def456abcd0099".to_string(),
                    decision: "deny".to_string(),
                    count: 1,
                },
            ],
            l7_inspection_active: true,
        }];

        let proposals = generate_proposals(&summaries).await;
        assert_eq!(proposals.len(), 1);

        let rule = proposals[0].proposed_rule.as_ref().unwrap();
        let ep = &rule.endpoints[0];

        // L7 fields should be set.
        assert_eq!(ep.protocol, "rest");
        // tls field is no longer set (auto-detection handles it).
        assert!(ep.tls.is_empty());
        assert_eq!(ep.enforcement, "enforce");

        // Should have L7 rules.
        assert!(!ep.rules.is_empty());

        let paths: Vec<&str> = ep
            .rules
            .iter()
            .filter_map(|r| r.allow.as_ref())
            .map(|a| a.path.as_str())
            .collect();
        assert!(paths.contains(&"/"));
        // The /j/abc123def456 path should be generalised to /j/*
        assert!(paths.contains(&"/j/*"));

        // Rationale should mention L7.
        assert!(proposals[0].rationale.contains("L7"));
    }

    // -- is_internal_ip tests -------------------------------------------------

    #[test]
    fn test_is_internal_ip_private_v4() {
        use std::net::Ipv4Addr;
        // RFC 1918 ranges
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(10, 110, 50, 3))));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255))));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_is_internal_ip_loopback_and_link_local() {
        use std::net::Ipv4Addr;
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        ))));
    }

    #[test]
    fn test_is_internal_ip_public_v4() {
        use std::net::Ipv4Addr;
        assert!(!is_internal_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_internal_ip(IpAddr::V4(Ipv4Addr::new(208, 95, 112, 1))));
        assert!(!is_internal_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn test_is_internal_ip_cgnat() {
        use std::net::Ipv4Addr;
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(100, 100, 50, 3))));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(
            100, 127, 255, 255
        ))));
        // Just outside the /10 boundary
        assert!(!is_internal_ip(IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1))));
    }

    #[test]
    fn test_is_internal_ip_special_use() {
        use std::net::Ipv4Addr;
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 0, 1))));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
    }

    #[test]
    fn test_is_internal_ip_v6() {
        use std::net::Ipv6Addr;
        // Loopback
        assert!(is_internal_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        // Link-local fe80::1
        assert!(is_internal_ip(IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));
        // ULA fd00::1
        assert!(is_internal_ip(IpAddr::V6(Ipv6Addr::new(
            0xfd00, 0, 0, 0, 0, 0, 0, 1
        ))));
        // Public 2001:db8::1
        assert!(!is_internal_ip(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        ))));
    }

    // -- is_always_blocked_destination tests ------------------------------------

    #[test]
    fn test_always_blocked_destination_loopback_ip() {
        assert!(is_always_blocked_destination("127.0.0.1"));
    }

    #[test]
    fn test_always_blocked_destination_link_local_ip() {
        assert!(is_always_blocked_destination("169.254.169.254"));
    }

    #[test]
    fn test_always_blocked_destination_unspecified_ip() {
        assert!(is_always_blocked_destination("0.0.0.0"));
    }

    #[test]
    fn test_always_blocked_destination_localhost_hostname() {
        assert!(is_always_blocked_destination("localhost"));
        assert!(is_always_blocked_destination("LOCALHOST"));
    }

    #[test]
    fn test_always_blocked_destination_allows_rfc1918() {
        assert!(!is_always_blocked_destination("10.0.5.20"));
        assert!(!is_always_blocked_destination("192.168.1.1"));
    }

    #[test]
    fn test_always_blocked_destination_allows_public_hostname() {
        assert!(!is_always_blocked_destination("api.github.com"));
    }

    // -- generate_proposals: always-blocked filtering tests --------------------

    #[tokio::test]
    async fn test_generate_proposals_skips_loopback_destination() {
        let summaries = vec![DenialSummary {
            host: "127.0.0.1".to_string(),
            port: 80,
            binary: "/usr/bin/curl".to_string(),
            count: 5,
            first_seen_ms: 1000,
            last_seen_ms: 2000,
            denial_stage: "ssrf".to_string(),
            ..Default::default()
        }];

        let proposals = generate_proposals(&summaries).await;
        assert!(
            proposals.is_empty(),
            "should skip proposals for loopback: {proposals:?}"
        );
    }

    #[tokio::test]
    async fn test_generate_proposals_skips_link_local_destination() {
        let summaries = vec![DenialSummary {
            host: "169.254.169.254".to_string(),
            port: 80,
            binary: "/usr/bin/curl".to_string(),
            count: 5,
            first_seen_ms: 1000,
            last_seen_ms: 2000,
            denial_stage: "ssrf".to_string(),
            ..Default::default()
        }];

        let proposals = generate_proposals(&summaries).await;
        assert!(
            proposals.is_empty(),
            "should skip proposals for link-local: {proposals:?}"
        );
    }

    #[tokio::test]
    async fn test_generate_proposals_skips_localhost_hostname() {
        let summaries = vec![DenialSummary {
            host: "localhost".to_string(),
            port: 8080,
            binary: "/usr/bin/curl".to_string(),
            count: 3,
            first_seen_ms: 1000,
            last_seen_ms: 2000,
            denial_stage: "ssrf".to_string(),
            ..Default::default()
        }];

        let proposals = generate_proposals(&summaries).await;
        assert!(
            proposals.is_empty(),
            "should skip proposals for localhost: {proposals:?}"
        );
    }

    #[tokio::test]
    async fn test_generate_proposals_keeps_public_destination() {
        let summaries = vec![DenialSummary {
            host: "api.github.com".to_string(),
            port: 443,
            binary: "/usr/bin/curl".to_string(),
            count: 5,
            first_seen_ms: 1000,
            last_seen_ms: 2000,
            denial_stage: "connect".to_string(),
            ..Default::default()
        }];

        let proposals = generate_proposals(&summaries).await;
        assert_eq!(proposals.len(), 1, "should keep proposals for public host");
    }

    #[test]
    fn test_generalise_path() {
        // Exact path preserved.
        assert_eq!(
            generalise_path("/api/breeds/image/random"),
            "/api/breeds/image/random"
        );

        // Numeric ID replaced.
        assert_eq!(generalise_path("/posts/42"), "/posts/*");

        // UUID-ish replaced.
        assert_eq!(
            generalise_path("/chunks/550e8400-e29b-41d4-a716-446655440000"),
            "/chunks/*"
        );

        // Query string stripped.
        assert_eq!(generalise_path("/json/?fields=status,country"), "/json/");

        // Short path preserved.
        assert_eq!(generalise_path("/"), "/");
    }

    #[test]
    fn test_looks_like_id() {
        assert!(looks_like_id("42"));
        assert!(looks_like_id("550e8400-e29b-41d4-a716-446655440000"));
        assert!(looks_like_id("abc123def456abcd"));
        assert!(!looks_like_id("random"));
        assert!(!looks_like_id("get"));
        assert!(!looks_like_id(""));
        assert!(!looks_like_id("v1"));
    }
}
