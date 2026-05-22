// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Terminal report rendering (full and compact).

use std::collections::{HashMap, HashSet};
use std::path::Path;

use owo_colors::OwoColorize;

use crate::finding::{Finding, FindingPath, RiskLevel};

// ---------------------------------------------------------------------------
// Compact titles (short labels for each query type)
// ---------------------------------------------------------------------------

fn compact_title(query: &str) -> &str {
    match query {
        "data_exfiltration" => "Data exfiltration possible",
        "write_bypass" => "Write bypass \u{2014} read-only intent violated",
        _ => "Unknown finding",
    }
}

// ---------------------------------------------------------------------------
// Compact detail line
// ---------------------------------------------------------------------------

fn compact_detail(finding: &Finding) -> String {
    match finding.query.as_str() {
        "data_exfiltration" => {
            let mut by_status: HashMap<&str, HashSet<String>> = HashMap::new();
            for path in &finding.paths {
                if let FindingPath::Exfil(p) = path {
                    by_status
                        .entry(&p.l7_status)
                        .or_default()
                        .insert(format!("{}:{}", p.endpoint_host, p.endpoint_port));
                }
            }
            let mut parts = Vec::new();
            if let Some(eps) = by_status.get("link_local") {
                let mut sorted: Vec<&String> = eps.iter().collect();
                sorted.sort();
                parts.push(format!(
                    "link-local (cloud metadata): {}",
                    sorted
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if let Some(eps) = by_status.get("l4_only") {
                let mut sorted: Vec<&String> = eps.iter().collect();
                sorted.sort();
                parts.push(format!(
                    "L4-only: {}",
                    sorted
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if let Some(eps) = by_status.get("l7_bypassed") {
                let mut sorted: Vec<&String> = eps.iter().collect();
                sorted.sort();
                parts.push(format!(
                    "wire protocol bypass: {}",
                    sorted
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if let Some(eps) = by_status.get("l7_allows_write") {
                let mut sorted: Vec<&String> = eps.iter().collect();
                sorted.sort();
                parts.push(format!(
                    "L7 write: {}",
                    sorted
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if let Some(eps) = by_status.get("l7_credentialed") {
                let mut sorted: Vec<&String> = eps.iter().collect();
                sorted.sort();
                parts.push(format!(
                    "L7 + credential in scope: {}",
                    sorted
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            parts.join("; ")
        }
        "write_bypass" => {
            let mut reasons = HashSet::new();
            let mut endpoints = HashSet::new();
            for path in &finding.paths {
                if let FindingPath::WriteBypass(p) = path {
                    reasons.insert(p.bypass_reason.as_str());
                    endpoints.insert(format!("{}:{}", p.endpoint_host, p.endpoint_port));
                }
            }
            let mut sorted_eps: Vec<&String> = endpoints.iter().collect();
            sorted_eps.sort();
            let ep_list = sorted_eps
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            if reasons.contains("l4_only") && reasons.contains("l7_bypass_protocol") {
                format!("L4-only + wire protocol: {ep_list}")
            } else if reasons.contains("l4_only") {
                format!("L4-only (no inspection): {ep_list}")
            } else if reasons.contains("l7_bypass_protocol") {
                format!("wire protocol bypasses L7: {ep_list}")
            } else {
                String::new()
            }
        }
        _ => String::new(),
    }
}

// ---------------------------------------------------------------------------
// One-line shorthand (for embedding findings in other tools' output)
// ---------------------------------------------------------------------------

/// Format a finding as a single uncolored line for embedding in other
/// human-facing surfaces (gateway `validation_result`, demo output, logs).
///
/// Shape: `[<RISK>] <query>: <detail>` — e.g.
/// `[HIGH] data_exfiltration: L4-only: api.github.com:443`. Falls back to
/// `[<RISK>] <query>` when no detail is available.
pub fn finding_shorthand(finding: &Finding) -> String {
    let detail = compact_detail(finding);
    if detail.is_empty() {
        format!("[{}] {}", risk_label(finding.risk), finding.query)
    } else {
        format!("[{}] {}: {detail}", risk_label(finding.risk), finding.query)
    }
}

// ---------------------------------------------------------------------------
// Risk formatting
// ---------------------------------------------------------------------------

fn risk_label(risk: RiskLevel) -> String {
    match risk {
        RiskLevel::Critical => "CRITICAL".to_owned(),
        RiskLevel::High => "HIGH".to_owned(),
        RiskLevel::Medium => "MEDIUM".to_owned(),
    }
}

fn print_risk_label(risk: RiskLevel) {
    match risk {
        RiskLevel::Critical => print!("{}", "CRITICAL".bold().red()),
        RiskLevel::High => print!("{}", "    HIGH".red()),
        RiskLevel::Medium => print!("{}", "  MEDIUM".yellow()),
    }
}

// ---------------------------------------------------------------------------
// Compact output
// ---------------------------------------------------------------------------

/// Render compact output (one-line-per-finding for demos and CI).
/// Returns exit code: 0 = pass, 1 = critical/high found.
pub fn render_compact(findings: &[Finding], _policy_path: &str, _credentials_path: &str) -> i32 {
    let active: Vec<&Finding> = findings.iter().filter(|f| !f.accepted).collect();
    let accepted: Vec<&Finding> = findings.iter().filter(|f| f.accepted).collect();

    for finding in &active {
        print!("  ");
        print_risk_label(finding.risk);
        println!("  {}", compact_title(&finding.query));
        let detail = compact_detail(finding);
        if !detail.is_empty() {
            println!("             {detail}");
        }
        println!();
    }

    for finding in &accepted {
        println!(
            "  {}  {}",
            "ACCEPTED".dimmed(),
            compact_title(&finding.query).dimmed()
        );
    }
    if !accepted.is_empty() {
        println!();
    }

    // Verdict
    let mut counts: HashMap<RiskLevel, usize> = HashMap::new();
    for f in &active {
        *counts.entry(f.risk).or_default() += 1;
    }
    let has_critical = counts.contains_key(&RiskLevel::Critical);
    let has_high = counts.contains_key(&RiskLevel::High);
    let has_medium = counts.contains_key(&RiskLevel::Medium);
    let accepted_note = if accepted.is_empty() {
        String::new()
    } else {
        format!(", {} accepted", accepted.len())
    };

    if has_critical || has_high {
        let n = counts.get(&RiskLevel::Critical).unwrap_or(&0)
            + counts.get(&RiskLevel::High).unwrap_or(&0);
        println!(
            "   {}  {n} critical/high gaps{accepted_note}",
            " FAIL ".white().bold().on_red()
        );
        1
    } else if has_medium {
        let n = counts.get(&RiskLevel::Medium).unwrap_or(&0);
        println!(
            "   {}  {n} medium-risk gap(s){accepted_note}",
            " REVIEW ".black().bold().on_yellow()
        );
        1
    } else if !active.is_empty() {
        println!(
            "   {}  advisories only{accepted_note}",
            " PASS ".black().bold().on_yellow()
        );
        0
    } else {
        println!(
            "   {}  all findings accepted{accepted_note}",
            " PASS ".white().bold().on_green()
        );
        0
    }
}

// ---------------------------------------------------------------------------
// Full terminal report
// ---------------------------------------------------------------------------

/// Render a full terminal report with finding panels.
/// Returns exit code: 0 = pass, 1 = critical/high found.
pub fn render_report(findings: &[Finding], policy_path: &str, credentials_path: &str) -> i32 {
    let policy_name = Path::new(policy_path)
        .file_name()
        .map_or("policy.yaml", |n| n.to_str().unwrap_or("policy.yaml"));
    let creds_name = Path::new(credentials_path)
        .file_name()
        .map_or("credentials.yaml", |n| {
            n.to_str().unwrap_or("credentials.yaml")
        });

    println!();
    println!(
        "{}",
        "\u{250c}\u{2500}\u{2500} OpenShell Policy Prover \u{2500}\u{2500}\u{2510}".blue()
    );
    println!("  Policy:      {policy_name}");
    println!("  Credentials: {creds_name}");
    println!();

    let active: Vec<&Finding> = findings.iter().filter(|f| !f.accepted).collect();
    let accepted: Vec<&Finding> = findings.iter().filter(|f| f.accepted).collect();

    // Summary
    let mut counts: HashMap<RiskLevel, usize> = HashMap::new();
    for f in &active {
        *counts.entry(f.risk).or_default() += 1;
    }

    println!("{}", "Finding Summary".bold().underline());
    for level in [RiskLevel::Critical, RiskLevel::High, RiskLevel::Medium] {
        if let Some(&count) = counts.get(&level) {
            match level {
                RiskLevel::Critical => {
                    println!("  {:>10}  {count}", "CRITICAL".bold().red());
                }
                RiskLevel::High => println!("  {:>10}  {count}", "HIGH".red()),
                RiskLevel::Medium => println!("  {:>10}  {count}", "MEDIUM".yellow()),
            }
        }
    }
    if !accepted.is_empty() {
        println!("  {:>10}  {}", "ACCEPTED".dimmed(), accepted.len());
    }
    println!();

    if active.is_empty() && accepted.is_empty() {
        println!("{}", "No findings. Policy posture is clean.".green().bold());
        return 0;
    }

    // Per-finding details
    for (i, finding) in active.iter().enumerate() {
        let label = risk_label(finding.risk);
        let border = match finding.risk {
            RiskLevel::Critical => format!("{}", format!("[{label}]").bold().red()),
            RiskLevel::High => format!("{}", format!("[{label}]").red()),
            RiskLevel::Medium => format!("{}", format!("[{label}]").yellow()),
        };

        println!("--- Finding #{} {border} ---", i + 1);
        println!("  {}", finding.title.bold());
        println!("  {}", finding.description);
        println!();

        // Render paths
        render_paths(&finding.paths);

        // Remediation
        if !finding.remediation.is_empty() {
            println!("  {}", "Remediation:".bold());
            for r in &finding.remediation {
                println!("    - {r}");
            }
            println!();
        }
    }

    // Accepted findings
    if !accepted.is_empty() {
        println!("{}", "--- Accepted Risks ---".dimmed());
        for finding in &accepted {
            println!(
                "  {}  {}",
                risk_label(finding.risk).dimmed(),
                finding.title.dimmed()
            );
            println!(
                "  {}",
                format!("Reason: {}", finding.accepted_reason).dimmed()
            );
            println!();
        }
    }

    // Verdict
    let has_critical = counts.contains_key(&RiskLevel::Critical);
    let has_high = counts.contains_key(&RiskLevel::High);
    let has_medium = counts.contains_key(&RiskLevel::Medium);
    let accepted_note = if accepted.is_empty() {
        String::new()
    } else {
        format!(" ({} accepted)", accepted.len())
    };

    if has_critical {
        println!(
            "{}{accepted_note}",
            "FAIL \u{2014} Critical gaps found.".bold().red()
        );
        1
    } else if has_high {
        println!(
            "{}{accepted_note}",
            "FAIL \u{2014} High-risk gaps found.".bold().red()
        );
        1
    } else if has_medium {
        println!(
            "{}{accepted_note}",
            "REVIEW \u{2014} Medium-risk gaps require human attention."
                .bold()
                .yellow()
        );
        1
    } else if !active.is_empty() {
        println!(
            "{}{accepted_note}",
            "PASS \u{2014} Advisories only.".bold().yellow()
        );
        0
    } else {
        println!(
            "{}{accepted_note}",
            "PASS \u{2014} All findings accepted.".bold().green()
        );
        0
    }
}

fn render_paths(paths: &[FindingPath]) {
    if paths.is_empty() {
        return;
    }

    match &paths[0] {
        FindingPath::Exfil(_) => render_exfil_paths(paths),
        FindingPath::WriteBypass(_) => render_write_bypass_paths(paths),
    }
}

fn render_exfil_paths(paths: &[FindingPath]) {
    println!(
        "  {:<30} {:<25} {:<15} {}",
        "Binary".bold(),
        "Endpoint".bold(),
        "L7 Status".bold(),
        "Mechanism".bold(),
    );
    for path in paths {
        if let FindingPath::Exfil(p) = path {
            let l7_display = match p.l7_status.as_str() {
                "link_local" => format!("{}", "link-local".bold().red()),
                "l4_only" => format!("{}", "L4-only".red()),
                "l7_bypassed" => format!("{}", "bypassed".red()),
                "l7_allows_write" => format!("{}", "L7 write".yellow()),
                "l7_credentialed" => format!("{}", "L7+cred".yellow()),
                _ => p.l7_status.clone(),
            };
            let ep = format!("{}:{}", p.endpoint_host, p.endpoint_port);
            // Truncate mechanism for display
            let mech = if p.mechanism.len() > 50 {
                format!("{}...", &p.mechanism[..47])
            } else {
                p.mechanism.clone()
            };
            println!("  {:<30} {:<25} {:<15} {}", p.binary, ep, l7_display, mech);
        }
    }
    println!();
}

fn render_write_bypass_paths(paths: &[FindingPath]) {
    println!(
        "  {:<30} {:<25} {:<15} {}",
        "Binary".bold(),
        "Endpoint".bold(),
        "Bypass".bold(),
        "Intent".bold(),
    );
    for path in paths {
        if let FindingPath::WriteBypass(p) = path {
            let ep = format!("{}:{}", p.endpoint_host, p.endpoint_port);
            let bypass_display = match p.bypass_reason.as_str() {
                "l4_only" => format!("{}", "L4-only".red()),
                "l7_bypass_protocol" => format!("{}", "wire proto".red()),
                _ => p.bypass_reason.clone(),
            };
            println!(
                "  {:<30} {:<25} {:<15} {}",
                p.binary, ep, bypass_display, p.policy_intent
            );
        }
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{ExfilPath, WriteBypassPath};

    fn exfil_finding(l7_status: &str, host: &str, port: u16) -> Finding {
        Finding {
            query: "data_exfiltration".to_owned(),
            title: "Data exfiltration possible".to_owned(),
            description: String::new(),
            risk: RiskLevel::High,
            paths: vec![FindingPath::Exfil(ExfilPath {
                binary: "/usr/bin/curl".to_owned(),
                endpoint_host: host.to_owned(),
                endpoint_port: port,
                mechanism: String::new(),
                policy_name: String::new(),
                l7_status: l7_status.to_owned(),
            })],
            remediation: vec![],
            accepted: false,
            accepted_reason: String::new(),
        }
    }

    #[test]
    fn finding_shorthand_renders_exfil_l4_only() {
        let f = exfil_finding("l4_only", "api.github.com", 443);
        assert_eq!(
            finding_shorthand(&f),
            "[HIGH] data_exfiltration: L4-only: api.github.com:443"
        );
    }

    #[test]
    fn finding_shorthand_renders_write_bypass() {
        let f = Finding {
            query: "write_bypass".to_owned(),
            title: String::new(),
            description: String::new(),
            risk: RiskLevel::High,
            paths: vec![FindingPath::WriteBypass(WriteBypassPath {
                binary: "/usr/bin/curl".to_owned(),
                endpoint_host: "api.github.com".to_owned(),
                endpoint_port: 443,
                policy_name: String::new(),
                policy_intent: String::new(),
                bypass_reason: "l4_only".to_owned(),
                credential_actions: vec![],
            })],
            remediation: vec![],
            accepted: false,
            accepted_reason: String::new(),
        };
        assert_eq!(
            finding_shorthand(&f),
            "[HIGH] write_bypass: L4-only (no inspection): api.github.com:443"
        );
    }

    #[test]
    fn finding_shorthand_falls_back_when_detail_empty() {
        let f = Finding {
            query: "unknown_query".to_owned(),
            title: String::new(),
            description: String::new(),
            risk: RiskLevel::Critical,
            paths: vec![],
            remediation: vec![],
            accepted: false,
            accepted_reason: String::new(),
        };
        assert_eq!(finding_shorthand(&f), "[CRITICAL] unknown_query");
    }
}
