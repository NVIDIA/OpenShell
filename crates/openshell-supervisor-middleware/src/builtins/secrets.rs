// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::LazyLock;

use miette::{Result, miette};
use openshell_core::proto::{Decision, Finding, HttpRequestEvaluation, HttpRequestResult};
use regex::Regex;

use crate::BUILTIN_SECRETS;

/// A named secret-detection pattern. The `kind` is an audit-safe label that
/// flows into findings so operators can see *what* matched without seeing the
/// raw value.
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

/// Compiled once: recompiling per request would put regex construction on the
/// egress hot path.
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
    let mode = config
        .fields
        .get("secrets")
        .and_then(|value| match value.kind.as_ref() {
            Some(prost_types::value::Kind::StringValue(value)) => Some(value.as_str()),
            _ => None,
        })
        .unwrap_or("redact");
    if mode != "redact" {
        return Err(miette!(
            "{} only supports config.secrets: redact in phase 1",
            BUILTIN_SECRETS
        ));
    }
    Ok(())
}

pub fn evaluate_http_request(evaluation: &HttpRequestEvaluation) -> Result<HttpRequestResult> {
    let default_config = prost_types::Struct::default();
    validate_config(evaluation.config.as_ref().unwrap_or(&default_config))?;
    let text = String::from_utf8(evaluation.body.clone())
        .map_err(|_| miette!("{} requires UTF-8 request bodies", BUILTIN_SECRETS))?;
    let (body, matches) = redact_common_secrets(&text);
    let total: u32 = matches
        .iter()
        .fold(0u32, |acc, (_, count)| acc.saturating_add(*count));
    let mut result = HttpRequestResult {
        decision: Decision::Allow as i32,
        reason: String::new(),
        body: body.into_bytes(),
        has_body: !matches.is_empty(),
        add_headers: HashMap::new(),
        findings: Vec::new(),
        metadata: HashMap::new(),
    };
    if !matches.is_empty() {
        // One finding per matched pattern kind, so audit shows what matched.
        for (kind, count) in &matches {
            result.findings.push(Finding {
                r#type: format!("secret.{kind}"),
                label: format!("{kind} secret pattern"),
                count: *count,
                confidence: "medium".into(),
                severity: "medium".into(),
            });
        }
        result
            .metadata
            .insert("secrets_redacted".into(), total.to_string());
    }
    Ok(result)
}

/// Redact every configured secret pattern, returning the transformed text and
/// the per-kind match counts (only kinds that matched are included).
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
