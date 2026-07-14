// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::LazyLock;

use miette::{Result, miette};
use openshell_core::proto::{
    Decision, Finding, HttpRequestEvaluation, HttpRequestResult, MiddlewareBinding,
    SupervisorMiddlewareOperation, SupervisorMiddlewarePhase,
};
use regex::Regex;
use serde::Deserialize;

pub const BINDING_ID: &str = "openshell/secrets";
const MAX_BODY_BYTES: u64 = 256 * 1024;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecretsConfig {
    /// Redaction mode. Omitting the field selects [`SecretsMode::Redact`].
    pub secrets: SecretsMode,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretsMode {
    #[default]
    Redact,
}

impl SecretsConfig {
    pub fn from_struct(config: &prost_types::Struct) -> Result<Self> {
        serde_json::from_value(openshell_core::proto_struct::struct_to_json_value(config)).map_err(
            |error| {
                miette!(
                    "invalid {BINDING_ID} config: {error}; phase 1 supports only secrets: redact"
                )
            },
        )
    }
}

pub fn describe() -> MiddlewareBinding {
    MiddlewareBinding {
        id: BINDING_ID.into(),
        operation: SupervisorMiddlewareOperation::HttpRequest as i32,
        phase: SupervisorMiddlewarePhase::PreCredentials as i32,
        max_body_bytes: MAX_BODY_BYTES,
        timeout: String::new(),
    }
}

struct SecretPattern {
    kind: &'static str,
    regex: Regex,
}

impl SecretPattern {
    fn new(kind: &'static str, pattern: &str) -> Self {
        Self {
            kind,
            regex: Regex::new(pattern).expect("valid built-in secret redaction pattern"),
        }
    }
}

static SECRET_PATTERNS: LazyLock<[SecretPattern; 2]> = LazyLock::new(|| {
    [
        SecretPattern::new(
            "keyword",
            r#"(?i)(api[_-]?key|access[_-]?token|secret|password)(["']?\s*[:=]\s*["'])[^"',\s}]+(["']?)"#,
        ),
        SecretPattern::new("openai", r"(sk-[A-Za-z0-9_-]{16,})"),
    ]
});

pub fn validate_config(config: &prost_types::Struct) -> Result<()> {
    SecretsConfig::from_struct(config).map(|_| ())
}

pub fn evaluate_http_request(evaluation: &HttpRequestEvaluation) -> Result<HttpRequestResult> {
    let default_config = prost_types::Struct::default();
    validate_config(evaluation.config.as_ref().unwrap_or(&default_config))?;
    let text = String::from_utf8(evaluation.body.clone())
        .map_err(|_| miette!("{} requires UTF-8 request bodies", BINDING_ID))?;
    let (body, matches) = redact_common_secrets(&text);
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
    };
    for (kind, count) in &matches {
        result.findings.push(Finding {
            r#type: format!("secret.{kind}"),
            label: format!("{kind} secret pattern"),
            count: *count,
            confidence: "medium".into(),
            severity: "medium".into(),
        });
    }
    if !matches.is_empty() {
        result
            .metadata
            .insert("secrets_redacted".into(), total.to_string());
    }
    Ok(result)
}

fn redact_common_secrets(input: &str) -> (String, Vec<(&'static str, u32)>) {
    let mut output = input.to_string();
    let mut matches = Vec::new();
    for pattern in SECRET_PATTERNS.iter() {
        let count = u32::try_from(pattern.regex.find_iter(&output).count()).unwrap_or(u32::MAX);
        if count > 0 {
            matches.push((pattern.kind, count));
        }
        output = pattern
            .regex
            .replace_all(&output, |captures: &regex::Captures<'_>| {
                if captures.len() >= 4 {
                    format!("{}{}[REDACTED]{}", &captures[1], &captures[2], &captures[3])
                } else {
                    "[REDACTED]".to_string()
                }
            })
            .into_owned();
    }
    (output, matches)
}
