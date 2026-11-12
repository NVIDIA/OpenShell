// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    EXTERNAL_FINDING_LABEL, MAX_MIDDLEWARE_FINDING_BYTES, MAX_MIDDLEWARE_FINDINGS_PER_STAGE,
    MAX_MIDDLEWARE_METADATA_BYTES, MAX_MIDDLEWARE_METADATA_ENTRIES, MAX_MIDDLEWARE_REASON_BYTES,
    MAX_MIDDLEWARE_REASON_CODE_BYTES, MiddlewareDiagnosticPolicy, is_stable_reason_code,
};
use openshell_core::proto::MiddlewareDiagnostics;
use prost::Message;

pub fn validate_diagnostics(
    diagnostics: Option<&MiddlewareDiagnostics>,
) -> Result<MiddlewareDiagnostics, &'static str> {
    let diagnostics = diagnostics.cloned().unwrap_or_default();
    if diagnostics.reason.len() > MAX_MIDDLEWARE_REASON_BYTES {
        return Err("diagnostics_reason_over_capacity");
    }
    if !diagnostics.reason_code.is_empty()
        && (diagnostics.reason_code.len() > MAX_MIDDLEWARE_REASON_CODE_BYTES
            || !is_stable_reason_code(&diagnostics.reason_code))
    {
        return Err("diagnostics_reason_code_invalid");
    }
    if diagnostics.findings.len() > MAX_MIDDLEWARE_FINDINGS_PER_STAGE
        || diagnostics
            .findings
            .iter()
            .any(|finding| finding.encoded_len() > MAX_MIDDLEWARE_FINDING_BYTES)
    {
        return Err("diagnostics_findings_over_capacity");
    }
    if diagnostics.metadata.len() > MAX_MIDDLEWARE_METADATA_ENTRIES
        || diagnostics
            .metadata
            .iter()
            .map(|(key, value)| key.len().saturating_add(value.len()))
            .fold(0usize, usize::saturating_add)
            > MAX_MIDDLEWARE_METADATA_BYTES
    {
        return Err("diagnostics_metadata_over_capacity");
    }
    Ok(diagnostics)
}

pub fn normalize_diagnostics(
    implementation: &str,
    policy: MiddlewareDiagnosticPolicy,
    diagnostics: &mut MiddlewareDiagnostics,
) {
    if policy == MiddlewareDiagnosticPolicy::Normalize {
        diagnostics.metadata.clear();
        for finding in &mut diagnostics.findings {
            finding.r#type = format!("{implementation}.finding");
            finding.label = EXTERNAL_FINDING_LABEL.to_string();
            finding.confidence.clear();
            finding.severity = match finding.severity.as_str() {
                "low" => "low",
                "high" => "high",
                _ => "medium",
            }
            .to_string();
        }
    }
}
