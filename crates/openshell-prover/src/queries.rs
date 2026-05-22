// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Verification queries: `check_data_exfiltration` and `check_write_bypass`.
//!
//! v1 calibration (see `architecture/plans/agentic-policy-approval-loop.md`):
//! the prover emits a finding any time a credential is in scope for the
//! proposed endpoint, plus the categorical link-local floor. The four rows
//! that fire today:
//!
//! 1. **Link-local host** (`169.254.0.0/16`, `fe80::/10`) — emits regardless
//!    of credential context. Cloud metadata endpoints (AWS IMDS, GCP metadata)
//!    serve credentials, so the credential-presence model is fundamentally
//!    wrong for them.
//! 2. **Bypass-L7 binary** (git smart-HTTP, ssh, nc) **with a credential in
//!    scope for the host** — the L7 proxy cannot meaningfully inspect the
//!    wire protocol even when scope looks tight, and an authenticated
//!    privileged action is available.
//! 3. **L4-only endpoint** (no `protocol: rest|graphql`) **with a credential
//!    in scope for the host** — no L7 inspection at all, and authenticated
//!    privileged action is available.
//! 4. **L7-enforced endpoint with a credential in scope for the host** —
//!    even bounded actions can be destructive when authenticated
//!    (e.g., `PUT /repos/.../contents/...` overwrites arbitrary files).
//!    v1 defers to human judgment for any credentialed action because the
//!    prover models *credential exposure surface*, not *action semantics*.
//!    A future calibration may distinguish read methods from mutating ones
//!    once we have real-workload signal; until then, credential in scope =
//!    human review.
//!
//! Severity:
//!
//! - Rows 1–3 (link-local, bypass+credential, L4+credential) emit
//!   `RiskLevel::High`. These are cases the prover cannot bound.
//! - Row 4 (L7-narrow+credential) emits `RiskLevel::Medium`. The reach is
//!   bounded; the *action* (authenticated mutation) is what needs eyes.
//!
//! Severity does not change the auto-approval gate — any finding blocks
//! auto-approval. MEDIUM exists for audit/UI triage signal. The
//! `RiskLevel::Critical` variant is retained for future use; v1 never emits it.

use std::net::IpAddr;

use z3::SatResult;

use crate::finding::{ExfilPath, Finding, FindingPath, RiskLevel};
use crate::model::ReachabilityModel;

/// Return true iff the host string parses as an IP in a reserved link-local
/// range (IPv4 `169.254.0.0/16` or IPv6 `fe80::/10`).
///
/// Hostname-only strings (not parseable as IPs) return false. We don't
/// perform DNS resolution at validation time; the model evaluates the policy
/// as written.
pub(crate) fn is_link_local(host: &str) -> bool {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_link_local(),
        Ok(IpAddr::V6(v6)) => v6.is_unicast_link_local(),
        Err(_) => false,
    }
}

/// Check for data exfiltration / privileged-action paths against the v1
/// calibration table above.
///
/// We deliberately do NOT gate on `filesystem_policy.readable_paths()` being
/// non-empty: most v1 risks (link-local IMDS, L4+credential authenticated
/// writes, bypass-binary + credential) don't require *readable* filesystem
/// content to be dangerous. The credential itself is the lever, not what's
/// in `/etc/`.
pub fn check_data_exfiltration(model: &ReachabilityModel) -> Vec<Finding> {
    let mut exfil_paths: Vec<ExfilPath> = Vec::new();

    for bpath in &model.binary_paths {
        let cap = model.binary_registry.get_or_unknown(bpath);
        if !cap.can_exfiltrate {
            continue;
        }

        for eid in &model.endpoints {
            let expr = model.can_exfil_via_endpoint(bpath, eid);

            if model.check_sat(&expr) == SatResult::Sat {
                let host_is_link_local = is_link_local(&eid.host);
                let has_credential = !model.credentials.credentials_for_host(&eid.host).is_empty();
                // Check the L7 enforcement of THIS specific rule (eid.policy_name),
                // not any rule for the same host:port. Two rules can coexist on
                // the same endpoint — one L7-scoped, one L4-only — and each
                // must be evaluated on its own terms. Otherwise iteration order
                // (HashMap) leaks into the verdict.
                let ep_is_l7 = is_endpoint_in_rule_l7_enforced(
                    &model.policy,
                    &eid.policy_name,
                    &eid.host,
                    eid.port,
                );
                let ep_is_narrow = is_endpoint_in_rule_narrowly_bounded(
                    &model.policy,
                    &eid.policy_name,
                    &eid.host,
                    eid.port,
                );
                let bypass = cap.bypasses_l7();

                // v1 emission table — see module docs.
                let (l7_status, mut mechanism) = if host_is_link_local {
                    (
                        "link_local".to_owned(),
                        format!(
                            "Link-local endpoint — {bpath} can reach the host's metadata range \
                             (cloud-credential exfiltration territory regardless of declared scopes)"
                        ),
                    )
                } else if bypass && has_credential {
                    (
                        "l7_bypassed".to_owned(),
                        format!(
                            "{} — uses non-HTTP protocol, bypasses L7 inspection, and a credential \
                             is in scope for this host",
                            cap.description
                        ),
                    )
                } else if has_credential && (!ep_is_l7 || !ep_is_narrow) {
                    // L4-only OR L7-but-effectively-unbounded (access: full,
                    // wildcard method, wildcard path) — both collapse to
                    // "credentialed reach the prover cannot narrow." HIGH.
                    (
                        "l4_only".to_owned(),
                        format!(
                            "Endpoint with a credential in scope and no effective method/path bound \
                             ({bpath} can send arbitrary authenticated requests)"
                        ),
                    )
                } else if ep_is_l7 && has_credential {
                    // ep_is_l7 && ep_is_narrow — narrow L7 method/path with
                    // a credential in scope. MEDIUM: bounded reach, but
                    // authenticated action that may be destructive.
                    (
                        "l7_credentialed".to_owned(),
                        format!(
                            "L7-enforced endpoint with narrow method/path bounds and a credential in \
                             scope — the bounded action set is authenticated, and {bpath} can execute \
                             potentially destructive mutations against the host's API"
                        ),
                    )
                } else {
                    // v1: any other SAT path has no credential in scope, so
                    // no privileged action is available. Examples that fall
                    // here:
                    //   - L4-only with no credential in scope
                    //   - L7-enforced with no credential in scope
                    //   - bypass-L7 binary with no credential in scope
                    continue;
                };

                if !cap.exfil_mechanism.is_empty() {
                    mechanism = format!("{}. Exfil via: {}", mechanism, cap.exfil_mechanism);
                }

                exfil_paths.push(ExfilPath {
                    binary: bpath.clone(),
                    endpoint_host: eid.host.clone(),
                    endpoint_port: eid.port,
                    mechanism,
                    policy_name: eid.policy_name.clone(),
                    l7_status,
                });
            }
        }
    }

    if exfil_paths.is_empty() {
        return Vec::new();
    }

    let readable = model.policy.filesystem_policy.readable_paths();
    let n_readable = readable.len();
    let has_l4_only = exfil_paths.iter().any(|p| p.l7_status == "l4_only");
    let has_bypass = exfil_paths.iter().any(|p| p.l7_status == "l7_bypassed");
    let has_link_local = exfil_paths.iter().any(|p| p.l7_status == "link_local");
    let has_l7_credentialed = exfil_paths.iter().any(|p| p.l7_status == "l7_credentialed");

    let mut remediation = Vec::new();
    if has_link_local {
        remediation.push(
            "Endpoint host is in a link-local range (cloud-metadata territory). \
             Sandboxes should not reach these endpoints — reaching them can return \
             host credentials the sandbox should not have. If access is truly \
             intended, the policy must be approved by a human operator."
                .to_owned(),
        );
    }
    if has_l4_only {
        remediation.push(
            "Add `protocol: rest` with specific L7 rules to L4-only endpoints \
             to enable HTTP inspection and restrict to safe methods/paths."
                .to_owned(),
        );
    }
    if has_bypass {
        remediation.push(
            "Binaries using non-HTTP protocols (git, ssh, nc) bypass L7 inspection. \
             Remove these binaries from the policy if write access is not intended."
                .to_owned(),
        );
    }
    if has_l7_credentialed {
        remediation.push(
            "Endpoint has a credential in scope. Even with narrow L7 method/path \
             bounds, authenticated actions can be destructive (writes, deletes, \
             config changes). A human reviewer should confirm the intent."
                .to_owned(),
        );
    }
    remediation
        .push("Restrict filesystem read access to only the paths the agent needs.".to_owned());

    // Split paths by severity tier. Two tiers in v1: HIGH for paths the
    // model cannot bound (link-local, L4+credential, bypass-L7+credential),
    // MEDIUM for L7-enforced+credential (bounded but authenticated, deserves
    // human eyes but not the same kind of red flag). Splitting into separate
    // Findings keeps the audit honest — a reviewer sees the worst tier on
    // its own line, can't be misled by a roll-up.
    let (l7_cred_paths, high_paths): (Vec<_>, Vec<_>) = exfil_paths
        .into_iter()
        .partition(|p| p.l7_status == "l7_credentialed");

    let mut findings = Vec::new();

    if !high_paths.is_empty() {
        let paths: Vec<FindingPath> = high_paths.into_iter().map(FindingPath::Exfil).collect();
        let n_paths = paths.len();
        findings.push(Finding {
            query: "data_exfiltration".to_owned(),
            title: "Data Exfiltration Paths Detected".to_owned(),
            description: format!(
                "{n_paths} path(s) flagged by v1 calibration ({n_readable} readable filesystem path(s) in scope)."
            ),
            risk: RiskLevel::High,
            paths,
            remediation: remediation.clone(),
            accepted: false,
            accepted_reason: String::new(),
        });
    }

    if !l7_cred_paths.is_empty() {
        let paths: Vec<FindingPath> = l7_cred_paths.into_iter().map(FindingPath::Exfil).collect();
        let n_paths = paths.len();
        findings.push(Finding {
            query: "data_exfiltration".to_owned(),
            title: "Credentialed L7 Access — Human Review Recommended".to_owned(),
            description: format!(
                "{n_paths} L7-bounded path(s) with a credential in scope. The action set is narrow but authenticated."
            ),
            risk: RiskLevel::Medium,
            paths,
            remediation,
            accepted: false,
            accepted_reason: String::new(),
        });
    }

    findings
}

/// Reserved for future intent-aware write-bypass logic.
///
/// v1 consolidates all emission into `check_data_exfiltration` per the
/// calibration table; this function returns empty so the public API stays
/// stable while we figure out what shape an intent-aware check should take
/// in v2.
pub fn check_write_bypass(_model: &ReachabilityModel) -> Vec<Finding> {
    Vec::new()
}

/// Run both verification queries.
pub fn run_all_queries(model: &ReachabilityModel) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(check_data_exfiltration(model));
    findings.extend(check_write_bypass(model));
    findings
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check whether the specific (`policy_name`, host, port) endpoint is
/// L7-enforced.
///
/// Importantly, this is **per-rule**, not aggregated across the whole policy.
/// Two rules can target the same `host:port` with different enforcement (one
/// L7, one L4); each is evaluated on its own terms so the prover doesn't
/// leak `HashMap` iteration order into the verdict.
fn is_endpoint_in_rule_l7_enforced(
    policy: &crate::policy::PolicyModel,
    policy_name: &str,
    host: &str,
    port: u16,
) -> bool {
    let Some(rule) = policy.network_policies.get(policy_name) else {
        return false;
    };
    for ep in &rule.endpoints {
        if ep.host.eq_ignore_ascii_case(host) && ep.effective_ports().contains(&port) {
            return ep.is_l7_enforced();
        }
    }
    false
}

/// Whether the specific (`policy_name`, host, port) endpoint is L7-enforced
/// AND its allow set is **actually narrow** in both method and path axes.
///
/// L7 enforcement with `access: full` (or rules containing `method: "*"` /
/// `path: "**"`) is L4-equivalent in reachability — the L7 protocol annotation
/// doesn't bound what the binary can do, so a credentialed L7+full proposal
/// should be flagged the same way as L4+credential (HIGH), not as a narrow
/// L7+credential bounded action (MEDIUM). This helper draws that line.
fn is_endpoint_in_rule_narrowly_bounded(
    policy: &crate::policy::PolicyModel,
    policy_name: &str,
    host: &str,
    port: u16,
) -> bool {
    let Some(rule) = policy.network_policies.get(policy_name) else {
        return false;
    };
    for ep in &rule.endpoints {
        if ep.host.eq_ignore_ascii_case(host) && ep.effective_ports().contains(&port) {
            return endpoint_is_narrowly_bounded(ep);
        }
    }
    false
}

fn endpoint_is_narrowly_bounded(ep: &crate::policy::Endpoint) -> bool {
    if !ep.is_l7_enforced() {
        return false;
    }
    match ep.access.as_str() {
        // `access: full` is L4-equivalent reach despite the L7 protocol
        // annotation — not narrow.
        "full" => false,
        // Method-bounded shorthands ("read-only" = GET/HEAD/OPTIONS;
        // "read-write" = adds POST/PUT/PATCH). Path-unrestricted but
        // method-bounded — narrow enough to stay MEDIUM.
        "read-only" | "read-write" => true,
        // Rules-based: need at least one rule, all with bounded method
        // (not `*`) AND bounded path (not empty / `**` / `/**`). Any
        // wildcard in either axis collapses the L7 narrowing.
        _ => {
            !ep.rules.is_empty()
                && ep.rules.iter().all(|r| {
                    let m = r.method.to_uppercase();
                    let p = r.path.as_str();
                    m != "*" && !p.is_empty() && p != "**" && p != "/**"
                })
        }
    }
}

// `collect_credential_actions` removed in v1 along with the original
// `check_write_bypass` logic. When intent-aware write-bypass detection is
// reintroduced, this helper (or its successor) will live here.

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
        // We don't DNS-resolve; hostname strings always return false.
        assert!(!is_link_local("api.github.com"));
        assert!(!is_link_local("metadata.google.internal"));
        assert!(!is_link_local(""));
    }

    // ── narrowness classifier ──

    fn make_endpoint(access: &str, rules: Vec<(&str, &str)>) -> crate::policy::Endpoint {
        crate::policy::Endpoint {
            host: "api.example.com".to_owned(),
            port: 443,
            ports: vec![],
            protocol: "rest".to_owned(),
            tls: String::new(),
            enforcement: "enforce".to_owned(),
            access: access.to_owned(),
            rules: rules
                .into_iter()
                .map(|(m, p)| crate::policy::L7Rule {
                    method: m.to_owned(),
                    path: p.to_owned(),
                    command: String::new(),
                })
                .collect(),
            allowed_ips: vec![],
        }
    }

    #[test]
    fn endpoint_narrow_classifier_access_full_is_not_narrow() {
        let ep = make_endpoint("full", vec![]);
        assert!(
            !endpoint_is_narrowly_bounded(&ep),
            "`access: full` is L4-equivalent and must NOT be considered narrow",
        );
    }

    #[test]
    fn endpoint_narrow_classifier_read_only_and_read_write_are_narrow() {
        // Bounded method set; treated as narrow (MEDIUM under the credential
        // calibration). Reviewer suggested keeping the read-* shorthands in
        // the narrow bucket — they bound destructiveness.
        assert!(endpoint_is_narrowly_bounded(&make_endpoint(
            "read-only",
            vec![]
        )));
        assert!(endpoint_is_narrowly_bounded(&make_endpoint(
            "read-write",
            vec![]
        )));
    }

    #[test]
    fn endpoint_narrow_classifier_wildcard_method_is_not_narrow() {
        let ep = make_endpoint("", vec![("*", "/repos/owner/repo")]);
        assert!(
            !endpoint_is_narrowly_bounded(&ep),
            "rules with `method: \"*\"` are L4-equivalent reach in the method axis",
        );
    }

    #[test]
    fn endpoint_narrow_classifier_wildcard_path_is_not_narrow() {
        for path in ["**", "/**", ""] {
            let ep = make_endpoint("", vec![("PUT", path)]);
            assert!(
                !endpoint_is_narrowly_bounded(&ep),
                "path {path:?} is unbounded; the rule must NOT be considered narrow",
            );
        }
    }

    #[test]
    fn endpoint_narrow_classifier_explicit_method_and_path_is_narrow() {
        let ep = make_endpoint("", vec![("PUT", "/repos/owner/repo/contents/file.md")]);
        assert!(endpoint_is_narrowly_bounded(&ep));
    }

    #[test]
    fn endpoint_narrow_classifier_l4_only_is_not_narrow() {
        let mut ep = make_endpoint("", vec![("GET", "/path")]);
        ep.protocol = String::new(); // L4-only — fails the L7-enforced precondition
        assert!(!endpoint_is_narrowly_bounded(&ep));
    }
}
