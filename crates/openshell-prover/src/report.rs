// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Terminal report rendering (full and compact).
//!
//! The prover output is categorical, not severity-graded. Each finding
//! names *what* the policy change does (e.g., `capability_expansion`);
//! per-path evidence carries the structured detail. There is no HIGH /
//! MEDIUM / CRITICAL grade — the category itself is the signal.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use owo_colors::OwoColorize;

use crate::finding::{Finding, FindingPath, category};

// ---------------------------------------------------------------------------
// Category labels (display strings keyed off `Finding.query`)
// ---------------------------------------------------------------------------

fn category_label(query: &str) -> &str {
    match query {
        category::LINK_LOCAL_REACH => "link-local reach",
        category::L7_BYPASS_CREDENTIALED => "L7-bypass binary with credential",
        category::CREDENTIAL_REACH_EXPANSION => "credentialed reach expansion",
        category::CAPABILITY_EXPANSION => "capability expansion on credentialed host",
        _ => "unknown finding",
    }
}

// ---------------------------------------------------------------------------
// One-line shorthand (used by the gateway's `validation_result`)
// ---------------------------------------------------------------------------

/// Render a finding as one or more single-line strings, suitable for
/// embedding in the gateway `validation_result`, demo output, and logs.
///
/// Shape: `<category>: <per-path detail>` — one line per path. The
/// gateway concatenates these into the chunk's `validation_result` so
/// the reviewer reads what changed without parsing the category enum.
pub fn finding_shorthand(finding: &Finding) -> String {
    let mut lines = Vec::new();
    for path in &finding.paths {
        let FindingPath::Exfil(p) = path;
        lines.push(format_path_line(&finding.query, p));
    }
    lines.join("\n  ")
}

fn format_path_line(query: &str, p: &crate::finding::ExfilPath) -> String {
    let endpoint = format!("{}:{}", p.endpoint_host, p.endpoint_port);
    match query {
        category::LINK_LOCAL_REACH => {
            format!("link_local_reach: {endpoint} via {}", p.binary)
        }
        category::L7_BYPASS_CREDENTIALED => {
            format!("l7_bypass_credentialed: {endpoint} via {}", p.binary)
        }
        category::CREDENTIAL_REACH_EXPANSION => {
            format!("credential_reach_expansion: {endpoint} via {}", p.binary)
        }
        category::CAPABILITY_EXPANSION => {
            format!(
                "capability_expansion: {method} on {endpoint} via {bin}",
                method = p.method,
                bin = p.binary
            )
        }
        _ => format!("{query}: {endpoint} via {}", p.binary),
    }
}

// ---------------------------------------------------------------------------
// Compact output (CLI lint mode)
// ---------------------------------------------------------------------------

/// Render compact output (one-line-per-finding-line for demos and CI).
/// Returns exit code: 0 = pass, 1 = any findings present.
pub fn render_compact(findings: &[Finding], _policy_path: &str, _credentials_path: &str) -> i32 {
    let active: Vec<&Finding> = findings.iter().filter(|f| !f.accepted).collect();
    let accepted: Vec<&Finding> = findings.iter().filter(|f| f.accepted).collect();

    for finding in &active {
        for path in &finding.paths {
            let FindingPath::Exfil(p) = path;
            println!("  {} {}", "•".yellow(), format_path_line(&finding.query, p));
        }
        if !finding.paths.is_empty() {
            println!();
        }
    }

    for finding in &accepted {
        println!(
            "  {} {}",
            "ACCEPTED".dimmed(),
            category_label(&finding.query).dimmed()
        );
    }
    if !accepted.is_empty() {
        println!();
    }

    let accepted_note = if accepted.is_empty() {
        String::new()
    } else {
        format!(", {} accepted", accepted.len())
    };

    let path_count: usize = active.iter().map(|f| f.paths.len()).sum();
    if path_count > 0 {
        println!(
            "   {}  {path_count} finding path(s) require review{accepted_note}",
            " REVIEW ".black().bold().on_yellow()
        );
        1
    } else {
        println!(
            "   {}  no findings{accepted_note}",
            " PASS ".white().bold().on_green()
        );
        0
    }
}

// ---------------------------------------------------------------------------
// Full terminal report
// ---------------------------------------------------------------------------

/// Render a full terminal report with finding panels.
/// Returns exit code: 0 = pass, 1 = any findings present.
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

    // Per-category summary
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for f in &active {
        *counts.entry(f.query.as_str()).or_default() += f.paths.len();
    }

    if active.is_empty() && accepted.is_empty() {
        println!("{}", "No findings. Policy posture is clean.".green().bold());
        return 0;
    }

    println!("{}", "Finding Summary".bold().underline());
    for (query, count) in &counts {
        println!("  {:>40}  {count} path(s)", category_label(query).yellow());
    }
    if !accepted.is_empty() {
        println!("  {:>40}  {}", "ACCEPTED".dimmed(), accepted.len());
    }
    println!();

    for (i, finding) in active.iter().enumerate() {
        println!(
            "--- Finding #{} [{}] ---",
            i + 1,
            category_label(&finding.query)
        );
        println!("  {}", finding.title.bold());
        println!("  {}", finding.description);
        println!();
        render_paths(&finding.paths);
        if !finding.remediation.is_empty() {
            println!("  {}", "Remediation:".bold());
            for r in &finding.remediation {
                println!("    - {r}");
            }
            println!();
        }
    }

    if !accepted.is_empty() {
        println!("{}", "--- Accepted Findings ---".dimmed());
        for finding in &accepted {
            println!(
                "  {}  {}",
                category_label(&finding.query).dimmed(),
                finding.title.dimmed()
            );
            println!(
                "  {}",
                format!("Reason: {}", finding.accepted_reason).dimmed()
            );
            println!();
        }
    }

    let path_count: usize = active.iter().map(|f| f.paths.len()).sum();
    let accepted_note = if accepted.is_empty() {
        String::new()
    } else {
        format!(" ({} accepted)", accepted.len())
    };
    if path_count > 0 {
        println!(
            "{}{accepted_note}",
            "REVIEW \u{2014} prover findings require human attention."
                .bold()
                .yellow()
        );
        1
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
    // Group paths by binary for compact display.
    let mut by_binary: BTreeMap<&str, Vec<&crate::finding::ExfilPath>> = BTreeMap::new();
    for path in paths {
        let FindingPath::Exfil(p) = path;
        by_binary.entry(&p.binary).or_default().push(p);
    }
    for (binary, ps) in &by_binary {
        println!("  Binary: {}", binary.cyan());
        let mut endpoints: BTreeSet<String> = BTreeSet::new();
        let mut methods: BTreeSet<String> = BTreeSet::new();
        for p in ps {
            endpoints.insert(format!("{}:{}", p.endpoint_host, p.endpoint_port));
            if !p.method.is_empty() {
                methods.insert(p.method.clone());
            }
        }
        println!(
            "    Endpoints: {}",
            endpoints.iter().cloned().collect::<Vec<_>>().join(", ")
        );
        if !methods.is_empty() {
            println!(
                "    Methods:   {}",
                methods.iter().cloned().collect::<Vec<_>>().join(", ")
            );
        }
    }
    println!();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::ExfilPath;

    fn exfil_path(category_name: &str, method: &str, host: &str, port: u16) -> ExfilPath {
        ExfilPath {
            binary: "/usr/bin/curl".to_owned(),
            endpoint_host: host.to_owned(),
            endpoint_port: port,
            mechanism: String::new(),
            policy_name: "rule".to_owned(),
            category: category_name.to_owned(),
            method: method.to_owned(),
        }
    }

    fn finding_with(category_name: &str, paths: Vec<ExfilPath>) -> Finding {
        Finding {
            query: category_name.to_owned(),
            title: "test".to_owned(),
            description: String::new(),
            paths: paths.into_iter().map(FindingPath::Exfil).collect(),
            remediation: vec![],
            accepted: false,
            accepted_reason: String::new(),
        }
    }

    #[test]
    fn shorthand_renders_capability_expansion_with_method() {
        let f = finding_with(
            category::CAPABILITY_EXPANSION,
            vec![exfil_path(
                category::CAPABILITY_EXPANSION,
                "PUT",
                "api.github.com",
                443,
            )],
        );
        assert_eq!(
            finding_shorthand(&f),
            "capability_expansion: PUT on api.github.com:443 via /usr/bin/curl"
        );
    }

    #[test]
    fn shorthand_renders_credential_reach_expansion() {
        let f = finding_with(
            category::CREDENTIAL_REACH_EXPANSION,
            vec![exfil_path(
                category::CREDENTIAL_REACH_EXPANSION,
                "",
                "uploads.github.com",
                443,
            )],
        );
        assert_eq!(
            finding_shorthand(&f),
            "credential_reach_expansion: uploads.github.com:443 via /usr/bin/curl"
        );
    }

    #[test]
    fn shorthand_renders_link_local() {
        let f = finding_with(
            category::LINK_LOCAL_REACH,
            vec![exfil_path(
                category::LINK_LOCAL_REACH,
                "",
                "169.254.169.254",
                80,
            )],
        );
        assert_eq!(
            finding_shorthand(&f),
            "link_local_reach: 169.254.169.254:80 via /usr/bin/curl"
        );
    }

    #[test]
    fn shorthand_renders_l7_bypass() {
        let f = finding_with(
            category::L7_BYPASS_CREDENTIALED,
            vec![exfil_path(
                category::L7_BYPASS_CREDENTIALED,
                "",
                "github.com",
                443,
            )],
        );
        assert_eq!(
            finding_shorthand(&f),
            "l7_bypass_credentialed: github.com:443 via /usr/bin/curl"
        );
    }
}
