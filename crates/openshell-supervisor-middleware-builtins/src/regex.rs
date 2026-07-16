// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Example built-in middleware that applies a fixed set of regular-expression
//! replacements to UTF-8 request bodies.
//!
//! This is intentionally a best-effort text transformation, not a secret
//! scanner or a parser-aware redactor. It provides no guarantee that sensitive
//! values will be detected or fully removed.

use std::collections::HashMap;
use std::sync::LazyLock;

use miette::{Result, miette};
use openshell_core::proto::{
    Decision, Finding, HttpRequestEvaluation, HttpRequestResult, MiddlewareBinding,
    SupervisorMiddlewareOperation, SupervisorMiddlewarePhase,
};
use regex::Regex;
use serde::Deserialize;

pub const NAME: &str = "openshell/regex";
const MAX_BODY_BYTES: u64 = 256 * 1024;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RegexConfig {
    /// Replacement mode. Omitting the field selects [`RegexMode::Redact`].
    pub mode: RegexMode,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegexMode {
    #[default]
    Redact,
}

impl RegexConfig {
    pub fn from_struct(config: &prost_types::Struct) -> Result<Self> {
        serde_json::from_value(openshell_core::proto_struct::struct_to_json_value(config)).map_err(
            |error| {
                miette!("invalid {NAME} config: {error}; this example supports only mode: redact")
            },
        )
    }
}

pub fn describe() -> MiddlewareBinding {
    MiddlewareBinding {
        operation: SupervisorMiddlewareOperation::HttpRequest as i32,
        phase: SupervisorMiddlewarePhase::PreCredentials as i32,
        max_body_bytes: MAX_BODY_BYTES,
        timeout: String::new(),
    }
}

struct ReplacementPattern {
    kind: &'static str,
    regex: Regex,
}

impl ReplacementPattern {
    fn new(kind: &'static str, pattern: &str) -> Self {
        Self {
            kind,
            regex: Regex::new(pattern).expect("valid built-in replacement pattern"),
        }
    }
}

// TODO: Allow policies to supply custom replacement expressions after the
// configuration contract, validation limits, and replacement semantics are
// designed. The initial example deliberately exposes only these fixed patterns.
static REPLACEMENT_PATTERNS: LazyLock<[ReplacementPattern; 1]> =
    LazyLock::new(|| [ReplacementPattern::new("openai", r"sk-[A-Za-z0-9_-]{16,}")]);

pub fn validate_config(config: &prost_types::Struct) -> Result<()> {
    RegexConfig::from_struct(config).map(|_| ())
}

pub fn evaluate_http_request(evaluation: &HttpRequestEvaluation) -> Result<HttpRequestResult> {
    let default_config = prost_types::Struct::default();
    validate_config(evaluation.config.as_ref().unwrap_or(&default_config))?;
    let text = String::from_utf8(evaluation.body.clone())
        .map_err(|_| miette!("{NAME} requires UTF-8 request bodies"))?;
    let (body, matches) = apply_replacements(&text);
    let total: u32 = matches
        .iter()
        .fold(0u32, |acc, (_, count)| acc.saturating_add(*count));
    let mut result = HttpRequestResult {
        decision: Decision::Allow as i32,
        reason: String::new(),
        body: body.into_bytes(),
        has_body: !matches.is_empty(),
        header_mutations: Vec::new(),
        findings: Vec::new(),
        metadata: HashMap::new(),
        reason_code: String::new(),
    };
    for (kind, count) in &matches {
        result.findings.push(Finding {
            r#type: format!("regex.{kind}"),
            label: format!("{kind} regex match"),
            count: *count,
            confidence: "medium".into(),
            severity: "medium".into(),
        });
    }
    if !matches.is_empty() {
        result
            .metadata
            .insert("regex_matches_replaced".into(), total.to_string());
    }
    Ok(result)
}

fn apply_replacements(input: &str) -> (String, Vec<(&'static str, u32)>) {
    let mut output = input.to_string();
    let mut matches = Vec::new();
    for pattern in REPLACEMENT_PATTERNS.iter() {
        let count = u32::try_from(pattern.regex.find_iter(&output).count()).unwrap_or(u32::MAX);
        if count > 0 {
            matches.push((pattern.kind, count));
        }
        output = pattern
            .regex
            .replace_all(&output, "[REDACTED]")
            .into_owned();
    }
    (output, matches)
}
