// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Verification queries: `check_data_exfiltration` and `check_write_bypass`.

use z3::SatResult;

use crate::finding::{ExfilPath, Finding, FindingPath, RiskLevel, WriteBypassPath};
use crate::model::ReachabilityModel;
use crate::policy::PolicyIntent;

/// Check for data exfiltration paths from readable filesystem to writable
/// egress channels.
///
/// Without binary allowlisting, this flags any L4-only endpoint when the
/// sandbox has readable filesystem paths — the agent can use any tool
/// available in its environment to send data over an uninspected channel.
pub fn check_data_exfiltration(model: &ReachabilityModel) -> Vec<Finding> {
    if model.policy.filesystem_policy.readable_paths().is_empty() {
        return Vec::new();
    }

    let mut exfil_paths: Vec<ExfilPath> = Vec::new();

    for eid in &model.endpoints {
        let ep_is_l7 = is_endpoint_l7_enforced(&model.policy, &eid.host, eid.port);

        // L4-only endpoints allow arbitrary data egress — any process in the
        // sandbox can open a TCP connection and send filesystem contents.
        if !ep_is_l7 {
            exfil_paths.push(ExfilPath {
                binary: String::new(),
                endpoint_host: eid.host.clone(),
                endpoint_port: eid.port,
                mechanism: format!(
                    "L4-only endpoint — no HTTP inspection; any sandbox process can \
                     send arbitrary data to {}:{}",
                    eid.host, eid.port
                ),
                policy_name: eid.policy_name.clone(),
                l7_status: "l4_only".to_owned(),
            });
        }
    }

    if exfil_paths.is_empty() {
        return Vec::new();
    }

    let readable = model.policy.filesystem_policy.readable_paths();
    let n_paths = exfil_paths.len();
    let paths: Vec<FindingPath> = exfil_paths.into_iter().map(FindingPath::Exfil).collect();

    vec![Finding {
        query: "data_exfiltration".to_owned(),
        title: "Data Exfiltration Paths Detected".to_owned(),
        description: format!(
            "{n_paths} exfiltration path(s) found from {} readable filesystem path(s) to \
             L4-only external endpoints.",
            readable.len()
        ),
        risk: RiskLevel::Critical,
        paths,
        remediation: vec![
            "Add `protocol: rest` with specific L7 rules to L4-only endpoints \
             to enable HTTP inspection and restrict to safe methods/paths."
                .to_owned(),
            "Restrict filesystem read access to only the paths the agent needs.".to_owned(),
        ],
        accepted: false,
        accepted_reason: String::new(),
    }]
}

/// Check for write capabilities that bypass read-only policy intent.
///
/// Without binary allowlisting this checks whether:
/// - A read-only-intent endpoint is L4-only (any process can bypass method filtering), or
/// - A read-only-intent endpoint has credentials with write scopes.
pub fn check_write_bypass(model: &ReachabilityModel) -> Vec<Finding> {
    let mut bypass_paths: Vec<WriteBypassPath> = Vec::new();

    for (policy_name, rule) in &model.policy.network_policies {
        for ep in &rule.endpoints {
            let intent = ep.intent();
            if !matches!(intent, PolicyIntent::ReadOnly) {
                continue;
            }

            for port in ep.effective_ports() {
                let eid = crate::model::EndpointId {
                    policy_name: policy_name.clone(),
                    host: ep.host.clone(),
                    port,
                };

                let expr = model.endpoint_allows_write(&eid);
                if model.check_sat(&expr) == SatResult::Sat {
                    if ep.is_l7_enforced() {
                        // L7 enforced but write methods allowed and credential has write scope
                        let cred_actions = collect_credential_actions(model, &ep.host);
                        if !cred_actions.is_empty() {
                            bypass_paths.push(WriteBypassPath {
                                binary: String::new(),
                                endpoint_host: ep.host.clone(),
                                endpoint_port: port,
                                policy_name: policy_name.clone(),
                                policy_intent: intent.to_string(),
                                bypass_reason: "credential_write_scope".to_owned(),
                                credential_actions: cred_actions,
                            });
                        }
                    } else {
                        // L4-only: no HTTP method filtering — any process can send writes
                        bypass_paths.push(WriteBypassPath {
                            binary: String::new(),
                            endpoint_host: ep.host.clone(),
                            endpoint_port: port,
                            policy_name: policy_name.clone(),
                            policy_intent: intent.to_string(),
                            bypass_reason: "l4_only".to_owned(),
                            credential_actions: collect_credential_actions(model, &ep.host),
                        });
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
fn is_endpoint_l7_enforced(policy: &crate::policy::PolicyModel, host: &str, port: u16) -> bool {
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
fn collect_credential_actions(model: &ReachabilityModel, host: &str) -> Vec<String> {
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
