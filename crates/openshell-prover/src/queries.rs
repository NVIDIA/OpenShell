// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Verification queries: `check_data_exfiltration` and `check_write_bypass`.

use z3::SatResult;

use crate::finding::{ExfilPath, Finding, FindingPath, RiskLevel, WriteBypassPath};
use crate::model::ReachabilityModel;
use crate::policy::PolicyIntent;

/// Check for data exfiltration paths from readable filesystem to writable
/// egress channels.
pub fn check_data_exfiltration(model: &ReachabilityModel) -> Vec<Finding> {
    if model.policy.filesystem_policy.readable_paths().is_empty() {
        return Vec::new();
    }

    let mut exfil_paths: Vec<ExfilPath> = Vec::new();

    for bpath in &model.binary_paths {
        let cap = model.binary_registry.get_or_unknown(bpath);
        if !cap.can_exfiltrate {
            continue;
        }

        for eid in &model.endpoints {
            let expr = model.can_exfil_via_endpoint(bpath, eid);

            if model.check_sat(&expr) == SatResult::Sat {
                // Determine L7 status and mechanism
                let ep_is_l7 = is_endpoint_l7_enforced(&model.policy, &eid.host, eid.port);
                let bypass = cap.bypasses_l7();

                let (l7_status, mut mechanism) = if bypass {
                    (
                        "l7_bypassed".to_owned(),
                        format!(
                            "{} — uses non-HTTP protocol, bypasses L7 inspection",
                            cap.description
                        ),
                    )
                } else if !ep_is_l7 {
                    (
                        "l4_only".to_owned(),
                        format!(
                            "L4-only endpoint — no HTTP inspection, {} can send arbitrary data",
                            bpath
                        ),
                    )
                } else {
                    // L7 is enforced and allows write — policy is
                    // working as intended. Not a finding.
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
    let has_l4_only = exfil_paths.iter().any(|p| p.l7_status == "l4_only");
    let has_bypass = exfil_paths.iter().any(|p| p.l7_status == "l7_bypassed");
    let risk = if has_l4_only || has_bypass {
        RiskLevel::Critical
    } else {
        RiskLevel::High
    };

    let mut remediation = Vec::new();
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
             Remove these binaries from the policy if write access is not intended, \
             or restrict credential scopes to read-only."
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
            "{n_paths} exfiltration path(s) found from {} readable filesystem path(s) to external endpoints.",
            readable.len()
        ),
        risk,
        paths,
        remediation,
        accepted: false,
        accepted_reason: String::new(),
    }]
}

/// Check for write capabilities that bypass read-only policy intent.
pub fn check_write_bypass(model: &ReachabilityModel) -> Vec<Finding> {
    let mut bypass_paths: Vec<WriteBypassPath> = Vec::new();

    for (policy_name, rule) in &model.policy.network_policies {
        for ep in &rule.endpoints {
            // Only check endpoints where the intent is read-only or L4-only
            let intent = ep.intent();
            if !matches!(intent, PolicyIntent::ReadOnly) {
                continue;
            }

            for port in ep.effective_ports() {
                for b in &rule.binaries {
                    let cap = model.binary_registry.get_or_unknown(&b.path);

                    // Check: binary bypasses L7 and can write
                    if cap.bypasses_l7() && cap.can_write() {
                        let cred_actions = collect_credential_actions(model, &ep.host, &cap);
                        if !cred_actions.is_empty()
                            || model.credentials.credentials_for_host(&ep.host).is_empty()
                        {
                            bypass_paths.push(WriteBypassPath {
                                binary: b.path.clone(),
                                endpoint_host: ep.host.clone(),
                                endpoint_port: port,
                                policy_name: policy_name.clone(),
                                policy_intent: intent.to_string(),
                                bypass_reason: "l7_bypass_protocol".to_owned(),
                                credential_actions: cred_actions,
                            });
                        }
                    }

                    // Check: L4-only endpoint + binary can construct HTTP + credential has write
                    if !ep.is_l7_enforced() && cap.can_construct_http {
                        let cred_actions = collect_credential_actions(model, &ep.host, &cap);
                        if !cred_actions.is_empty() {
                            bypass_paths.push(WriteBypassPath {
                                binary: b.path.clone(),
                                endpoint_host: ep.host.clone(),
                                endpoint_port: port,
                                policy_name: policy_name.clone(),
                                policy_intent: intent.to_string(),
                                bypass_reason: "l4_only".to_owned(),
                                credential_actions: cred_actions,
                            });
                        }
                    }
                }
            }
        }
    }

    if bypass_paths.is_empty() {
        return Vec::new();
    }

    let n = bypass_paths.len();
    let paths: Vec<FindingPath> = bypass_paths
        .into_iter()
        .map(FindingPath::WriteBypass)
        .collect();

    vec![Finding {
        query: "write_bypass".to_owned(),
        title: "Write Bypass Detected — Read-Only Intent Violated".to_owned(),
        description: format!("{n} path(s) allow write operations despite read-only policy intent."),
        risk: RiskLevel::High,
        paths,
        remediation: vec![
            "For L4-only endpoints: add `protocol: rest` with `access: read-only` \
             to enable HTTP method filtering."
                .to_owned(),
            "For L7-bypassing binaries (git, ssh, nc): remove them from the policy's \
             binary list if write access is not intended."
                .to_owned(),
            "Restrict credential scopes to read-only where possible.".to_owned(),
        ],
        accepted: false,
        accepted_reason: String::new(),
    }]
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

/// Check whether an endpoint in the policy is L7-enforced.
fn is_endpoint_l7_enforced(policy: &crate::policy::PolicyModel, host: &str, port: u32) -> bool {
    for rule in policy.network_policies.values() {
        for ep in &rule.endpoints {
            if ep.host == host && ep.effective_ports().contains(&port) {
                return ep.is_l7_enforced();
            }
        }
    }
    false
}

/// Collect human-readable credential action descriptions for a host.
fn collect_credential_actions(
    model: &ReachabilityModel,
    host: &str,
    _cap: &crate::registry::BinaryCapability,
) -> Vec<String> {
    let creds = model.credentials.credentials_for_host(host);
    let api = model.credentials.api_for_host(host);
    let mut actions = Vec::new();

    for cred in &creds {
        if let Some(api) = api {
            for wa in api.write_actions_for_scopes(&cred.scopes) {
                actions.push(format!("{} {} ({})", wa.method, wa.path, wa.action));
            }
        } else {
            actions.push(format!(
                "credential '{}' has scopes: {:?}",
                cred.name, cred.scopes
            ));
        }
    }
    actions
}
