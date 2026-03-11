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

use navigator_core::proto::{
    DenialSummary, NetworkBinary, NetworkEndpoint, NetworkPolicyRule, PolicyChunk,
};
use std::collections::HashMap;

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
/// Groups denials by `(host, port)`, then for each group generates a
/// `PolicyChunk` with a `NetworkPolicyRule` allowing that endpoint for the
/// observed binaries.
///
/// Returns an empty vec if there are no actionable denials.
pub fn generate_proposals(
    summaries: &[DenialSummary],
    existing_rule_names: &[String],
) -> Vec<PolicyChunk> {
    // Group denials by (host, port).
    let mut groups: HashMap<(String, u32), Vec<&DenialSummary>> = HashMap::new();
    for summary in summaries {
        groups
            .entry((summary.host.clone(), summary.port))
            .or_default()
            .push(summary);
    }

    let mut proposals = Vec::new();

    for ((host, port), denials) in &groups {
        let rule_name = generate_rule_name(host, *port, existing_rule_names);

        // Collect unique binaries.
        let mut binary_set: HashMap<String, u32> = HashMap::new();
        let mut total_count: u32 = 0;
        let mut first_seen_ms: i64 = i64::MAX;
        let mut last_seen_ms: i64 = 0;
        let mut is_ssrf = false;

        for denial in denials {
            if !denial.binary.is_empty() {
                *binary_set.entry(denial.binary.clone()).or_insert(0) += denial.count;
            }
            total_count += denial.count;
            first_seen_ms = first_seen_ms.min(denial.first_seen_ms);
            last_seen_ms = last_seen_ms.max(denial.last_seen_ms);
            if denial.denial_stage == "ssrf" {
                is_ssrf = true;
            }
        }

        // Build proposed NetworkPolicyRule.
        let endpoint = NetworkEndpoint {
            host: host.clone(),
            port: *port,
            ..Default::default()
        };

        let binaries: Vec<NetworkBinary> = binary_set
            .keys()
            .map(|b| NetworkBinary {
                path: b.clone(),
                ..Default::default()
            })
            .collect();

        let proposed_rule = NetworkPolicyRule {
            name: rule_name.clone(),
            endpoints: vec![endpoint],
            binaries,
        };

        // Compute confidence.
        #[allow(clippy::cast_possible_truncation)]
        let confidence = compute_confidence(total_count, *port as u16, is_ssrf);

        // Generate rationale.
        let binary_list = if binary_set.is_empty() {
            "unknown binary".to_string()
        } else {
            binary_set
                .keys()
                .map(|b| short_binary_name(b))
                .collect::<Vec<_>>()
                .join(", ")
        };

        #[allow(clippy::cast_possible_truncation)]
        let port_u16 = *port as u16;
        let port_name = WELL_KNOWN_PORTS
            .iter()
            .find(|(p, _)| *p == port_u16)
            .map(|(_, name)| format!(" ({name})"))
            .unwrap_or_default();

        let rationale = format!(
            "Allow {binary_list} to connect to {host}:{port}{port_name}. \
             Observed {total_count} denied connection(s)."
        );

        // Generate security notes.
        #[allow(clippy::cast_possible_truncation)]
        let security_notes = generate_security_notes(host, *port as u16, is_ssrf);

        // Determine stage based on denial source.
        let stage = denials
            .first()
            .map_or_else(|| "connect".to_string(), |d| d.denial_stage.clone());

        proposals.push(PolicyChunk {
            id: String::new(), // Assigned by the server on persist
            status: "pending".to_string(),
            rule_name,
            proposed_rule: Some(proposed_rule),
            rationale,
            security_notes,
            confidence,
            denial_summary_ids: vec![], // Linked on persist
            created_at_ms: 0,           // Set on persist
            decided_at_ms: 0,
            stage,
            supersedes_chunk_id: String::new(),
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
fn generate_rule_name(host: &str, port: u32, existing: &[String]) -> String {
    // Sanitize host: replace dots and dashes with underscores.
    let sanitized = host
        .replace(['.', '-'], "_")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .collect::<String>();

    let base = format!("allow_{sanitized}_{port}");

    if !existing.contains(&base) {
        return base;
    }

    // Append a suffix to avoid collisions.
    for i in 2..100 {
        let candidate = format!("{base}_{i}");
        if !existing.contains(&candidate) {
            return candidate;
        }
    }

    // Fallback.
    format!("{base}_{}", uuid::Uuid::new_v4().as_simple())
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

/// Extract just the binary name from a full path.
fn short_binary_name(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_rule_name() {
        let existing = vec!["allow_example_com_443".to_string()];
        let name = generate_rule_name("example.com", 443, &existing);
        assert_eq!(name, "allow_example_com_443_2");
    }

    #[test]
    fn test_generate_rule_name_no_conflict() {
        let existing: Vec<String> = vec![];
        let name = generate_rule_name("api.github.com", 443, &existing);
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

    #[test]
    fn test_generate_proposals_empty() {
        let proposals = generate_proposals(&[], &[]);
        assert!(proposals.is_empty());
    }

    #[test]
    fn test_generate_proposals_basic() {
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

        let proposals = generate_proposals(&summaries, &[]);
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].rule_name, "allow_api_example_com_443");
        assert!(proposals[0].proposed_rule.is_some());

        let rule = proposals[0].proposed_rule.as_ref().unwrap();
        assert_eq!(rule.endpoints.len(), 1);
        assert_eq!(rule.endpoints[0].host, "api.example.com");
        assert_eq!(rule.endpoints[0].port, 443);
        assert_eq!(rule.binaries.len(), 1);
        assert_eq!(rule.binaries[0].path, "/usr/bin/curl");
    }
}
