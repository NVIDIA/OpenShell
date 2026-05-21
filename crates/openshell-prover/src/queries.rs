// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Verification queries: `check_data_exfiltration` and `check_write_bypass`.
//!
//! v1 calibration (see `architecture/plans/agentic-policy-approval-loop.md`):
//! the prover emits a finding only when the proposal shape is genuinely
//! unbounded for our model. The three rows that fire today:
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
//!
//! All emitted findings carry `RiskLevel::High`. The `Critical` variant is
//! retained in the enum but unused in v1; we'll introduce a tier when a
//! behavioral distinction earns it.

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
                } else if !ep_is_l7 && has_credential {
                    (
                        "l4_only".to_owned(),
                        format!(
                            "L4-only endpoint with a credential in scope — no HTTP inspection, \
                             {bpath} can send arbitrary authenticated requests"
                        ),
                    )
                } else {
                    // v1: any other SAT path is bounded enough that it
                    // doesn't earn a finding. Examples that fall here:
                    //   - L7-enforced with bounded action set (working as intended)
                    //   - L4-only with no credential in scope (no privileged action available)
                    //   - bypass-L7 binary with no credential in scope (no auth to exercise)
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
    remediation
        .push("Restrict filesystem read access to only the paths the agent needs.".to_owned());

    let paths: Vec<FindingPath> = exfil_paths.into_iter().map(FindingPath::Exfil).collect();

    let n_paths = paths.len();
    vec![Finding {
        query: "data_exfiltration".to_owned(),
        title: "Data Exfiltration Paths Detected".to_owned(),
        description: format!(
            "{n_paths} path(s) flagged by v1 calibration ({n_readable} readable filesystem path(s) in scope)."
        ),
        risk: RiskLevel::High,
        paths,
        remediation,
        accepted: false,
        accepted_reason: String::new(),
    }]
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
}
