// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Verification queries.
//!
//! The prover answers four formal questions about a policy and emits one
//! finding category per "yes" answer (see
//! [`crate::finding::category`] for the canonical names). The output is
//! categorical — there is no severity grade. The gateway's
//! `finding_delta` decides which findings are *new* relative to a
//! baseline, and the auto-approval gate triggers when no new findings
//! exist.
//!
//! Categories:
//!
//! 1. **Link-local reach** — any reachable path to a host in
//!    `169.254.0.0/16` or `fe80::/10`. Emitted unconditionally:
//!    cloud-metadata endpoints serve credentials, so reachability alone
//!    is the risk.
//! 2. **L7-bypass + credential** — a binary whose wire protocol the L7
//!    proxy cannot inspect (`git-remote-https`, `ssh`, `nc`) gains reach
//!    to a host where a sandbox credential is in scope.
//! 3. **Credential reach expansion** — a binary gains credentialed reach
//!    to a host:port it could not reach before. The gateway's delta
//!    surfaces only newly-reachable tuples.
//! 4. **Capability expansion** — on a (binary, host, port) that already
//!    had credentialed reach, the policy adds a new HTTP method. The
//!    gateway's delta surfaces only newly-allowed methods.
//!
//! These categories are intended to be (mostly) mutually exclusive per
//! underlying change: at the gateway, `capability_expansion` paths whose
//! `(binary, host, port)` is also in the `credential_reach_expansion`
//! delta are suppressed, so a brand-new credentialed reach surfaces as
//! one `credential_reach_expansion` finding rather than that plus N
//! capability findings. See `crates/openshell-server/src/grpc/policy.rs`.

use std::collections::HashSet;
use std::net::IpAddr;

use z3::SatResult;

use crate::finding::{ExfilPath, Finding, FindingPath, category};
use crate::model::ReachabilityModel;

/// Return true iff the host string parses as an IP in a reserved
/// link-local range (IPv4 `169.254.0.0/16` or IPv6 `fe80::/10`).
///
/// Hostname-only strings (not parseable as IPs) return false. We don't
/// perform DNS resolution at validation time; the model evaluates the
/// policy as written.
pub(crate) fn is_link_local(host: &str) -> bool {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_link_local(),
        Ok(IpAddr::V6(v6)) => v6.is_unicast_link_local(),
        Err(_) => false,
    }
}

/// Return true for static cloud metadata hostnames that should be treated like
/// link-local metadata reach without performing DNS resolution.
pub(crate) fn is_known_metadata_hostname(host: &str) -> bool {
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    matches!(normalized.as_str(), "metadata.google.internal")
}

fn is_link_local_or_metadata_host(host: &str) -> bool {
    is_link_local(host) || is_known_metadata_hostname(host)
}

/// Run all four formal queries against the model and emit one finding
/// per category that has at least one path.
///
/// We deliberately do NOT gate on `filesystem_policy.readable_paths()`
/// being non-empty: the credential itself is the lever for the tracked
/// risks, not anything in `/etc/`.
pub fn check_credential_safety(model: &ReachabilityModel) -> Vec<Finding> {
    let mut reach_paths: Vec<ExfilPath> = Vec::new();
    let mut capability_paths: Vec<ExfilPath> = Vec::new();
    let mut bypass_paths: Vec<ExfilPath> = Vec::new();
    let mut link_local_paths: Vec<ExfilPath> = Vec::new();

    for bpath in &model.binary_paths {
        let cap = model.binary_registry.get_or_unknown(bpath);
        if !cap.can_exfiltrate {
            continue;
        }

        for eid in &model.endpoints {
            let expr = model.can_exfil_via_endpoint(bpath, eid);
            if model.check_sat(&expr) != SatResult::Sat {
                continue;
            }

            let host_is_link_local = is_link_local_or_metadata_host(&eid.host);
            let has_credential = !model.credentials.credentials_for_host(&eid.host).is_empty();

            // Tier 1: link-local/metadata. Unconditional. Other categories
            // are not emitted on these hosts — the metadata signal is the
            // story.
            if host_is_link_local {
                link_local_paths.push(ExfilPath {
                    binary: bpath.clone(),
                    endpoint_host: eid.host.clone(),
                    endpoint_port: eid.port,
                    mechanism: format!(
                        "Link-local endpoint — {bpath} can reach the host's metadata range \
                         (cloud-credential exfiltration territory regardless of declared scopes)"
                    ),
                    policy_name: eid.policy_name.clone(),
                    category: category::LINK_LOCAL_REACH.to_string(),
                    method: String::new(),
                });
                continue;
            }

            // Un-credentialed reach is not a tracked risk.
            if !has_credential {
                continue;
            }

            // Tier 2: bypass-L7 binary on a credentialed host. Wire
            // protocol cannot be inspected; mark and move on.
            if cap.bypasses_l7() {
                bypass_paths.push(ExfilPath {
                    binary: bpath.clone(),
                    endpoint_host: eid.host.clone(),
                    endpoint_port: eid.port,
                    mechanism: format!(
                        "{} — uses non-HTTP protocol, bypasses L7 inspection, and a credential \
                         is in scope for this host",
                        cap.description
                    ),
                    policy_name: eid.policy_name.clone(),
                    category: category::L7_BYPASS_CREDENTIALED.to_string(),
                    method: String::new(),
                });
                continue;
            }

            // Tiers 3 + 4: credentialed L7 reach. We emit both
            // credential_reach_expansion and capability_expansion paths
            // here; the gateway's delta will keep only the relevant
            // category (see `finding_delta` and the suppression rule).
            reach_paths.push(ExfilPath {
                binary: bpath.clone(),
                endpoint_host: eid.host.clone(),
                endpoint_port: eid.port,
                mechanism: format!(
                    "Binary {bpath} has credentialed reach to {host}:{port}",
                    host = eid.host,
                    port = eid.port,
                ),
                policy_name: eid.policy_name.clone(),
                category: category::CREDENTIAL_REACH_EXPANSION.to_string(),
                method: String::new(),
            });

            // One capability_expansion path per allowed method on this
            // (binary, host:port) under this specific rule.
            let methods = endpoint_allowed_methods_in_rule(
                &model.policy,
                &eid.policy_name,
                &eid.host,
                eid.port,
            );
            for method in methods {
                capability_paths.push(ExfilPath {
                    binary: bpath.clone(),
                    endpoint_host: eid.host.clone(),
                    endpoint_port: eid.port,
                    mechanism: format!(
                        "Method {method} allowed for {bpath} on {host}:{port}",
                        host = eid.host,
                        port = eid.port,
                    ),
                    policy_name: eid.policy_name.clone(),
                    category: category::CAPABILITY_EXPANSION.to_string(),
                    method,
                });
            }
        }
    }

    let mut findings = Vec::new();
    if !link_local_paths.is_empty() {
        findings.push(build_finding(
            category::LINK_LOCAL_REACH,
            "Link-Local or Metadata Reach",
            "Reach to a host in a link-local range or known metadata hostname — cloud-metadata territory.",
            link_local_paths,
            vec![
                "Endpoint host is in a link-local range or known metadata hostname \
                 (cloud-metadata territory). Sandboxes should not reach these \
                 endpoints — reaching them can return host credentials the sandbox \
                 should not have."
                    .to_owned(),
            ],
        ));
    }
    if !bypass_paths.is_empty() {
        findings.push(build_finding(
            category::L7_BYPASS_CREDENTIALED,
            "L7-Bypass Binary with Credential in Scope",
            "A binary using a wire protocol the L7 proxy cannot inspect has reach to \
             a host where a sandbox credential is in scope.",
            bypass_paths,
            vec![
                "Binaries using non-HTTP protocols (git, ssh, nc) bypass L7 inspection. \
                 Remove these binaries from the policy if credentialed write access is \
                 not intended."
                    .to_owned(),
            ],
        ));
    }
    if !reach_paths.is_empty() {
        findings.push(build_finding(
            category::CREDENTIAL_REACH_EXPANSION,
            "Credentialed Reach Expansion",
            "A binary gained credentialed reach to a (host, port) it could not reach \
             before.",
            reach_paths,
            vec![
                "Credentialed reach is a privileged action surface. A human reviewer \
                 should confirm the binary should be able to authenticate to this host \
                 at all."
                    .to_owned(),
            ],
        ));
    }
    if !capability_paths.is_empty() {
        findings.push(build_finding(
            category::CAPABILITY_EXPANSION,
            "Capability Expansion on Credentialed Host",
            "New methods were added on a (binary, host, port) that already had \
             credentialed reach. The agent is changing what the sandbox can do with \
             its credentials.",
            capability_paths,
            vec![
                "A capability expansion is a stated intent change. The reviewer should \
                 confirm the new methods (especially mutating methods like PUT, POST, \
                 PATCH, DELETE) are part of the agent's task."
                    .to_owned(),
            ],
        ));
    }
    findings
}

fn build_finding(
    query: &str,
    title: &str,
    description: &str,
    paths: Vec<ExfilPath>,
    remediation: Vec<String>,
) -> Finding {
    let n = paths.len();
    Finding {
        query: query.to_owned(),
        title: title.to_owned(),
        // Per-finding description prefixes the count with the category's
        // canonical sentence so the audit string is self-describing.
        description: format!("{description} ({n} path(s).)"),
        paths: paths.into_iter().map(FindingPath::Exfil).collect(),
        remediation,
        accepted: false,
        accepted_reason: String::new(),
    }
}

/// Run all queries (single entry point for end-to-end callers).
pub fn run_all_queries(model: &ReachabilityModel) -> Vec<Finding> {
    check_credential_safety(model)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Allowed HTTP methods for the endpoint in `policy.network_policies[policy_name]`
/// matching `(host, port)`. Returns empty when the rule or endpoint is not
/// found (e.g. SAT path threaded through a stale model).
fn endpoint_allowed_methods_in_rule(
    policy: &crate::policy::PolicyModel,
    policy_name: &str,
    host: &str,
    port: u16,
) -> HashSet<String> {
    let Some(rule) = policy.network_policies.get(policy_name) else {
        return HashSet::new();
    };
    for ep in &rule.endpoints {
        if ep.host.eq_ignore_ascii_case(host) && ep.effective_ports().contains(&port) {
            return ep.allowed_methods();
        }
    }
    HashSet::new()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_link_local_recognises_ipv4_169_254() {
        assert!(is_link_local("169.254.169.254"));
        assert!(is_link_local("169.254.0.1"));
        assert!(is_link_local("169.254.255.255"));
    }

    #[test]
    fn is_link_local_recognises_ipv6_fe80() {
        assert!(is_link_local("fe80::1"));
        assert!(is_link_local("fe80::abcd:ef01"));
    }

    #[test]
    fn is_link_local_rejects_non_link_local_ips() {
        assert!(!is_link_local("8.8.8.8"));
        assert!(!is_link_local("10.0.0.1"));
        assert!(!is_link_local("192.168.1.1"));
        assert!(!is_link_local("::1"));
        assert!(!is_link_local("2001:db8::1"));
    }

    #[test]
    fn is_link_local_rejects_hostnames() {
        assert!(!is_link_local("api.github.com"));
        assert!(!is_link_local(""));
    }

    #[test]
    fn is_known_metadata_hostname_recognises_gcp_variants() {
        assert!(is_known_metadata_hostname("metadata.google.internal"));
        assert!(is_known_metadata_hostname("METADATA.GOOGLE.INTERNAL"));
        assert!(is_known_metadata_hostname("metadata.google.internal."));
    }

    #[test]
    fn is_known_metadata_hostname_rejects_other_hostnames() {
        assert!(!is_known_metadata_hostname("api.github.com"));
        assert!(!is_known_metadata_hostname(""));
    }
}
