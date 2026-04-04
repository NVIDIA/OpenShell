// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Load and match accepted risk annotations against findings.

use std::path::Path;

use miette::{IntoDiagnostic, Result, WrapErr};
use serde::Deserialize;

use crate::finding::{Finding, FindingPath};

// ---------------------------------------------------------------------------
// Serde types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct AcceptedRisksFile {
    #[serde(default)]
    accepted_risks: Vec<AcceptedRiskDef>,
}

#[derive(Debug, Deserialize)]
struct AcceptedRiskDef {
    #[serde(default)]
    query: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    accepted_by: String,
    #[serde(default)]
    binary: String,
    #[serde(default)]
    endpoint: String,
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// An explicitly accepted risk annotation.
#[derive(Debug, Clone)]
pub struct AcceptedRisk {
    pub query: String,
    pub reason: String,
    pub accepted_by: String,
    pub binary: String,
    pub endpoint: String,
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Load accepted risks from a YAML file.
pub fn load_accepted_risks(path: &Path) -> Result<Vec<AcceptedRisk>> {
    let contents = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading accepted risks {}", path.display()))?;
    let raw: AcceptedRisksFile = serde_yml::from_str(&contents)
        .into_diagnostic()
        .wrap_err("parsing accepted risks YAML")?;

    Ok(raw
        .accepted_risks
        .into_iter()
        .map(|r| AcceptedRisk {
            query: r.query,
            reason: r.reason,
            accepted_by: r.accepted_by,
            binary: r.binary,
            endpoint: r.endpoint,
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

/// Check if a single finding path matches an accepted risk.
fn path_matches_risk(path: &FindingPath, risk: &AcceptedRisk) -> bool {
    if !risk.binary.is_empty() {
        let path_binary = match path {
            FindingPath::Exfil(p) => &p.binary,
            FindingPath::WriteBypass(p) => &p.binary,
        };
        if path_binary != &risk.binary {
            return false;
        }
    }
    if !risk.endpoint.is_empty() {
        let endpoint_host = match path {
            FindingPath::Exfil(p) => &p.endpoint_host,
            FindingPath::WriteBypass(p) => &p.endpoint_host,
        };
        if endpoint_host != &risk.endpoint {
            return false;
        }
    }
    true
}

/// Mark findings as accepted where they match accepted risk annotations.
///
/// A finding is accepted if **all** of its paths match at least one accepted
/// risk entry for that query. If only some paths match, the finding stays
/// active with the unmatched paths.
pub fn apply_accepted_risks(findings: Vec<Finding>, accepted: &[AcceptedRisk]) -> Vec<Finding> {
    if accepted.is_empty() {
        return findings;
    }

    let mut result = Vec::new();
    for finding in findings {
        let matching_risks: Vec<&AcceptedRisk> = accepted
            .iter()
            .filter(|r| r.query == finding.query)
            .collect();

        if matching_risks.is_empty() {
            result.push(finding);
            continue;
        }

        if finding.paths.is_empty() {
            // Pathless finding — accept if query matches.
            result.push(Finding {
                accepted: true,
                accepted_reason: matching_risks[0].reason.clone(),
                ..finding
            });
            continue;
        }

        let mut unmatched_paths = Vec::new();
        let mut matched_reason = String::new();
        for path in &finding.paths {
            let mut path_accepted = false;
            for risk in &matching_risks {
                if path_matches_risk(path, risk) {
                    path_accepted = true;
                    matched_reason.clone_from(&risk.reason);
                    break;
                }
            }
            if !path_accepted {
                unmatched_paths.push(path.clone());
            }
        }

        if unmatched_paths.is_empty() {
            result.push(Finding {
                accepted: true,
                accepted_reason: matched_reason,
                ..finding
            });
        } else if unmatched_paths.len() < finding.paths.len() {
            result.push(Finding {
                paths: unmatched_paths,
                ..finding
            });
        } else {
            result.push(finding);
        }
    }
    result
}
