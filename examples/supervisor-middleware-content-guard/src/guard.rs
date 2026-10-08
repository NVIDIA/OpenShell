// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Protocol-independent configuration and inspection. Every binding and both
//! HTTP protocols call into this module, so they make the same decisions.

use std::collections::{BTreeSet, HashMap};
use std::ops::Range;

use openshell_core::proto::Finding;
use prost_types::Struct;
use prost_types::value::Kind;
use tonic::Status;

pub(crate) const MAX_PAYLOAD_BYTES: u64 = 256 * 1024;
const DEFAULT_REPLACEMENT: &str = "[REDACTED]";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Redact,
    Deny,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct GuardConfig {
    mode: Mode,
    terms: Vec<String>,
    replacement: String,
}

impl GuardConfig {
    pub(crate) fn parse(config: Option<&Struct>) -> Result<Self, String> {
        let config = config.ok_or_else(|| "config is required".to_string())?;
        if let Some(field) = config
            .fields
            .keys()
            .find(|field| !matches!(field.as_str(), "mode" | "terms" | "replacement"))
        {
            return Err(format!("unsupported config field '{field}'"));
        }

        let mode = match optional_string_field(config, "mode")?.unwrap_or("redact") {
            "redact" => Mode::Redact,
            "deny" => Mode::Deny,
            _ => return Err("config.mode must be 'redact' or 'deny'".into()),
        };

        let terms = config
            .fields
            .get("terms")
            .and_then(|value| match value.kind.as_ref() {
                Some(Kind::ListValue(value)) => Some(&value.values),
                _ => None,
            })
            .ok_or_else(|| "config.terms must be a non-empty string list".to_string())?;
        let mut unique_terms = BTreeSet::new();
        for term in terms {
            let Some(Kind::StringValue(term)) = term.kind.as_ref() else {
                return Err("config.terms must contain only strings".into());
            };
            if term.is_empty() {
                return Err("config.terms cannot contain an empty string".into());
            }
            unique_terms.insert(term.clone());
        }
        if unique_terms.is_empty() {
            return Err("config.terms must contain at least one string".into());
        }

        let replacement = optional_string_field(config, "replacement")?
            .unwrap_or(DEFAULT_REPLACEMENT)
            .to_string();
        if mode == Mode::Deny && config.fields.contains_key("replacement") {
            return Err("config.replacement is only valid in redact mode".into());
        }

        Ok(Self {
            mode,
            terms: unique_terms.into_iter().collect(),
            replacement,
        })
    }

    /// Parse the configuration OpenShell sends with an evaluation.
    pub(crate) fn from_evaluation(config: Option<&Struct>) -> Result<Self, Status> {
        Self::parse(config).map_err(Status::invalid_argument)
    }
}

fn optional_string_field<'a>(config: &'a Struct, name: &str) -> Result<Option<&'a str>, String> {
    let Some(value) = config.fields.get(name) else {
        return Ok(None);
    };
    match value.kind.as_ref() {
        Some(Kind::StringValue(value)) => Ok(Some(value.as_str())),
        _ => Err(format!("config.{name} must be a string")),
    }
}

/// One guard decision. A denied outcome has no replacement, and a clean
/// outcome has neither a replacement nor diagnostics.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct GuardOutcome {
    pub(crate) denied: bool,
    pub(crate) replacement: Option<String>,
    pub(crate) reason: String,
    pub(crate) reason_code: String,
    pub(crate) findings: Vec<Finding>,
    pub(crate) metadata: HashMap<String, String>,
}

pub(crate) fn inspect(config: &GuardConfig, body: &str) -> GuardOutcome {
    let (ranges, match_count, matched_term_count) = find_match_ranges(body, &config.terms);

    if match_count == 0 {
        return GuardOutcome::default();
    }

    let finding = Finding {
        r#type: "content_guard.match".into(),
        label: "configured content matched".into(),
        count: match_count,
        confidence: "high".into(),
        severity: "medium".into(),
    };
    let metadata = HashMap::from([
        ("match_count".into(), match_count.to_string()),
        ("matched_term_count".into(), matched_term_count.to_string()),
        (
            "mode".into(),
            match config.mode {
                Mode::Redact => "redact".into(),
                Mode::Deny => "deny".into(),
            },
        ),
    ]);

    GuardOutcome {
        denied: config.mode == Mode::Deny,
        replacement: (config.mode == Mode::Redact)
            .then(|| redact_ranges(body, &ranges, &config.replacement)),
        reason: if config.mode == Mode::Deny {
            "payload matched configured content".into()
        } else {
            String::new()
        },
        reason_code: if config.mode == Mode::Deny {
            "content_match".into()
        } else {
            String::new()
        },
        findings: vec![finding],
        metadata,
    }
}

/// The guard matches text only, so it cannot inspect an HTTP body that is not
/// UTF-8. Each protocol reports this with its own status.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NotUtf8;

impl NotUtf8 {
    pub(crate) const MESSAGE: &str = "content guard requires a UTF-8 body";
}

/// Inspect one complete HTTP body.
pub(crate) fn inspect_http_body(
    config: &GuardConfig,
    body: &[u8],
) -> Result<GuardOutcome, NotUtf8> {
    std::str::from_utf8(body)
        .map(|body| inspect(config, body))
        .map_err(|_| NotUtf8)
}

/// Failure for an HTTP message whose complete body OpenShell does not offer,
/// with `FAILED_PRECONDITION` under both protocols. The guard never passes a
/// body it could not inspect.
pub(crate) fn complete_body_unavailable(body_mode: &str) -> Status {
    Status::failed_precondition(format!("content guard requires {body_mode}"))
}

fn find_match_ranges(body: &str, terms: &[String]) -> (Vec<Range<usize>>, u32, u32) {
    let mut ranges = Vec::new();
    let mut match_count = 0_u32;
    let mut matched_term_count = 0_u32;

    for term in terms {
        let mut term_matched = false;
        for (start, _) in body.char_indices() {
            if body[start..].starts_with(term) {
                ranges.push(start..start + term.len());
                match_count = match_count.saturating_add(1);
                term_matched = true;
            }
        }
        if term_matched {
            matched_term_count = matched_term_count.saturating_add(1);
        }
    }

    ranges.sort_unstable_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| right.end.cmp(&left.end))
    });
    (
        merge_overlapping_ranges(ranges),
        match_count,
        matched_term_count,
    )
}

fn merge_overlapping_ranges(ranges: Vec<Range<usize>>) -> Vec<Range<usize>> {
    let mut merged: Vec<Range<usize>> = Vec::new();
    for range in ranges {
        if let Some(previous) = merged.last_mut()
            && range.start < previous.end
        {
            previous.end = previous.end.max(range.end);
            continue;
        }
        merged.push(range);
    }
    merged
}

fn redact_ranges(body: &str, ranges: &[Range<usize>], replacement: &str) -> String {
    let mut transformed = String::with_capacity(body.len());
    let mut cursor = 0;
    for range in ranges {
        transformed.push_str(&body[cursor..range.start]);
        transformed.push_str(replacement);
        cursor = range.end;
    }
    transformed.push_str(&body[cursor..]);
    transformed
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::collections::BTreeMap;

    use prost_types::value::Kind;
    use prost_types::{ListValue, Struct, Value};

    pub(crate) fn string(value: &str) -> Value {
        Value {
            kind: Some(Kind::StringValue(value.into())),
        }
    }

    pub(crate) fn config(mode: &str, terms: &[&str], replacement: Option<&str>) -> Struct {
        let mut fields = BTreeMap::from([
            ("mode".into(), string(mode)),
            (
                "terms".into(),
                Value {
                    kind: Some(Kind::ListValue(ListValue {
                        values: terms.iter().map(|term| string(term)).collect(),
                    })),
                },
            ),
        ]);
        if let Some(replacement) = replacement {
            fields.insert("replacement".into(), string(replacement));
        }
        Struct { fields }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use prost_types::Value;

    use super::test_support::{config, string};
    use super::*;

    #[test]
    fn redact_replaces_every_configured_match() {
        let config = GuardConfig::parse(Some(&config(
            "redact",
            &["prototype-secret", "internal-only"],
            Some("[FILTERED]"),
        )))
        .expect("valid config");
        let result = inspect(
            &config,
            "prototype-secret then internal-only then prototype-secret",
        );

        assert!(!result.denied);
        assert_eq!(
            result.replacement.as_deref(),
            Some("[FILTERED] then [FILTERED] then [FILTERED]")
        );
        assert_eq!(result.findings[0].count, 3);
    }

    #[test]
    fn redact_merges_partially_overlapping_terms() {
        let config =
            GuardConfig::parse(Some(&config("redact", &["aba", "bab"], Some("[FILTERED]"))))
                .expect("valid config");

        let result = inspect(&config, "abab");

        assert_eq!(result.replacement.as_deref(), Some("[FILTERED]"));
        assert_eq!(result.findings[0].count, 2);
        assert_eq!(result.metadata["matched_term_count"], "2");
    }

    #[test]
    fn redact_merges_self_overlapping_matches() {
        let config = GuardConfig::parse(Some(&config("redact", &["aba"], Some("[FILTERED]"))))
            .expect("valid config");

        let result = inspect(&config, "ababa");

        assert_eq!(result.replacement.as_deref(), Some("[FILTERED]"));
        assert_eq!(result.findings[0].count, 2);
        assert_eq!(result.metadata["matched_term_count"], "1");
    }

    #[test]
    fn redact_keeps_adjacent_matches_separate() {
        let config = GuardConfig::parse(Some(&config("redact", &["abc"], Some("[FILTERED]"))))
            .expect("valid config");

        let result = inspect(&config, "abcabc");

        assert_eq!(result.replacement.as_deref(), Some("[FILTERED][FILTERED]"));
        assert_eq!(result.findings[0].count, 2);
    }

    #[test]
    fn deny_returns_a_generic_reason_without_echoing_the_term() {
        let config = GuardConfig::parse(Some(&config("deny", &["prototype-secret"], None)))
            .expect("valid config");
        let result = inspect(&config, "contains prototype-secret");

        assert!(result.denied);
        assert!(!result.reason.contains("prototype-secret"));
        assert_eq!(result.reason_code, "content_match");
        assert!(result.replacement.is_none());
    }

    #[test]
    fn no_match_allows_without_replacing_the_body() {
        let config =
            GuardConfig::parse(Some(&config("redact", &["blocked"], None))).expect("valid config");
        let result = inspect(&config, "safe content");

        assert_eq!(result, GuardOutcome::default());
    }

    #[test]
    fn http_bodies_must_be_utf8() {
        let config =
            GuardConfig::parse(Some(&config("redact", &["blocked"], None))).expect("valid config");

        assert_eq!(inspect_http_body(&config, &[0xff]), Err(NotUtf8));
    }

    #[test]
    fn validation_rejects_missing_terms_and_deny_replacement() {
        let missing_terms = Struct {
            fields: BTreeMap::from([("mode".into(), string("redact"))]),
        };
        assert!(GuardConfig::parse(Some(&missing_terms)).is_err());
        assert!(
            GuardConfig::parse(Some(&config(
                "deny",
                &["prototype-secret"],
                Some("ignored")
            )))
            .is_err()
        );
    }

    #[test]
    fn validation_rejects_non_string_optional_fields() {
        for field in ["mode", "replacement"] {
            let mut config = config("redact", &["prototype-secret"], None);
            config.fields.insert(
                field.into(),
                Value {
                    kind: Some(Kind::BoolValue(true)),
                },
            );

            assert_eq!(
                GuardConfig::parse(Some(&config)),
                Err(format!("config.{field} must be a string"))
            );
        }
    }

    #[test]
    fn missing_optional_fields_use_defaults() {
        let mut config = config("redact", &["prototype-secret"], None);
        config.fields.remove("mode");

        let parsed = GuardConfig::parse(Some(&config)).expect("valid config");

        assert_eq!(parsed.mode, Mode::Redact);
        assert_eq!(parsed.replacement, DEFAULT_REPLACEMENT);
    }
}
