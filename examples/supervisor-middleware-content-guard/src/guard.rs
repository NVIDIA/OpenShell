// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Content guard configuration and matching, shared by HTTP and WebSocket.

use std::collections::{BTreeSet, HashMap};
use std::ops::Range;

use openshell_core::proto::Finding;
use prost_types::Struct;
use prost_types::value::Kind;

pub(crate) const MAX_PAYLOAD_BYTES: u64 = 256 * 1024;
const DEFAULT_REPLACEMENT: &str = "[REDACTED]";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Redact,
    Deny,
}

/// HTTP body mode the guard selects when OpenShell offers it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BodyMode {
    /// Inspect one complete body, up to 256 KiB.
    Buffered,
    /// Inspect the body as it streams, with no size limit.
    Stream,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct GuardConfig {
    pub(crate) mode: Mode,
    pub(crate) terms: Vec<String>,
    pub(crate) replacement: String,
    pub(crate) body_mode: BodyMode,
    /// Let connections OpenShell cannot inspect, such as `tls: skip`
    /// tunnels, continue. The default denies them.
    pub(crate) allow_uninspectable: bool,
}

impl GuardConfig {
    pub(crate) fn parse(config: Option<&Struct>) -> Result<Self, String> {
        let config = config.ok_or_else(|| "config is required".to_string())?;
        if let Some(field) = config.fields.keys().find(|field| {
            !matches!(
                field.as_str(),
                "mode" | "terms" | "replacement" | "body_mode" | "uninspectable"
            )
        }) {
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
        let body_mode = match optional_string_field(config, "body_mode")?.unwrap_or("buffered") {
            "buffered" => BodyMode::Buffered,
            "stream" => BodyMode::Stream,
            _ => return Err("config.body_mode must be 'buffered' or 'stream'".into()),
        };
        let allow_uninspectable =
            match optional_string_field(config, "uninspectable")?.unwrap_or("deny") {
                "deny" => false,
                "allow" => true,
                _ => return Err("config.uninspectable must be 'deny' or 'allow'".into()),
            };

        Ok(Self {
            mode,
            terms: unique_terms.into_iter().collect(),
            replacement,
            body_mode,
            allow_uninspectable,
        })
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

#[derive(Debug, Default)]
pub(crate) struct GuardOutcome {
    pub(crate) denied: bool,
    pub(crate) replacement: Option<Vec<u8>>,
    pub(crate) reason: String,
    pub(crate) reason_code: String,
    pub(crate) findings: Vec<Finding>,
    pub(crate) metadata: HashMap<String, String>,
}

/// Inspect one complete payload.
pub(crate) fn inspect(config: &GuardConfig, body: &[u8]) -> GuardOutcome {
    let terms: Vec<&[u8]> = config.terms.iter().map(String::as_bytes).collect();
    let (ranges, match_count, matched_term_count) = find_match_ranges(body, &terms);
    if match_count == 0 {
        return GuardOutcome::default();
    }
    GuardOutcome {
        replacement: (config.mode == Mode::Redact)
            .then(|| redact_ranges(body, &ranges, config.replacement.as_bytes())),
        ..outcome(config, match_count, matched_term_count)
    }
}

/// Diagnostics for `match_count` matches. Never echoes the matched content.
pub(crate) fn outcome(
    config: &GuardConfig,
    match_count: u32,
    matched_term_count: u32,
) -> GuardOutcome {
    let denied = config.mode == Mode::Deny;
    GuardOutcome {
        denied,
        replacement: None,
        reason: if denied {
            "payload matched configured content".into()
        } else {
            String::new()
        },
        reason_code: if denied {
            "content_match".into()
        } else {
            String::new()
        },
        findings: vec![Finding {
            r#type: "content_guard.match".into(),
            label: "configured content matched".into(),
            count: match_count,
            confidence: "high".into(),
            severity: "medium".into(),
        }],
        metadata: HashMap::from([
            ("match_count".into(), match_count.to_string()),
            ("matched_term_count".into(), matched_term_count.to_string()),
            (
                "mode".into(),
                match config.mode {
                    Mode::Redact => "redact".into(),
                    Mode::Deny => "deny".into(),
                },
            ),
        ]),
    }
}

/// Redacts or detects configured terms in a body that arrives in chunks.
///
/// Output withholds only the bytes that may begin a term split across
/// chunks. Terms never contain a line break, so every complete line is
/// released at once, which keeps line-oriented streams such as server-sent
/// events flowing.
pub(crate) struct StreamScanner {
    terms: Vec<Vec<u8>>,
    longest_term: usize,
    multiline: bool,
    replacement: Vec<u8>,
    pending: Vec<u8>,
    match_count: u32,
    matched_terms: BTreeSet<usize>,
}

/// A configured term appeared in deny mode.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Denied;

impl StreamScanner {
    pub(crate) fn new(config: &GuardConfig) -> Self {
        let terms: Vec<Vec<u8>> = config
            .terms
            .iter()
            .map(|term| term.as_bytes().to_vec())
            .collect();
        Self {
            longest_term: terms.iter().map(Vec::len).max().unwrap_or(1),
            multiline: terms.iter().any(|term| term.contains(&b'\n')),
            terms,
            replacement: if config.mode == Mode::Redact {
                config.replacement.as_bytes().to_vec()
            } else {
                Vec::new()
            },
            pending: Vec::new(),
            match_count: 0,
            matched_terms: BTreeSet::new(),
        }
    }

    /// Scan `data` and return the output that is now final.
    pub(crate) fn push(&mut self, data: &[u8], deny: bool) -> Result<Vec<u8>, Denied> {
        self.pending.extend_from_slice(data);
        self.release(false, deny)
    }

    /// Release everything still withheld at the end of the body.
    pub(crate) fn finish(&mut self, deny: bool) -> Result<Vec<u8>, Denied> {
        self.release(true, deny)
    }

    /// Match count and distinct matched term count so far.
    pub(crate) fn counts(&self) -> (u32, u32) {
        (
            self.match_count,
            u32::try_from(self.matched_terms.len()).unwrap_or(u32::MAX),
        )
    }

    fn release(&mut self, end: bool, deny: bool) -> Result<Vec<u8>, Denied> {
        let terms: Vec<&[u8]> = self.terms.iter().map(Vec::as_slice).collect();
        let matches = find_matches(&self.pending, &terms);
        if deny && !matches.is_empty() {
            return Err(Denied);
        }
        let mut boundary = if end {
            self.pending.len()
        } else {
            let tail = self
                .pending
                .len()
                .saturating_sub(self.longest_term.saturating_sub(1));
            let complete_lines = if self.multiline {
                0
            } else {
                self.pending
                    .iter()
                    .rposition(|byte| *byte == b'\n')
                    .map_or(0, |position| position + 1)
            };
            tail.max(complete_lines)
        };
        // A complete match that straddles the boundary is released whole.
        for (range, _) in &matches {
            if range.start < boundary && boundary < range.end {
                boundary = range.end;
            }
        }
        let released: Vec<_> = matches
            .into_iter()
            .filter(|(range, _)| range.end <= boundary)
            .collect();
        for (_, term) in &released {
            self.match_count = self.match_count.saturating_add(1);
            self.matched_terms.insert(*term);
        }
        let ranges =
            merge_overlapping_ranges(released.into_iter().map(|(range, _)| range).collect());
        let output = redact_ranges(&self.pending[..boundary], &ranges, &self.replacement);
        self.pending.drain(..boundary);
        Ok(output)
    }
}

/// Every occurrence of every term, sorted by position, with the term index.
fn find_matches(body: &[u8], terms: &[&[u8]]) -> Vec<(Range<usize>, usize)> {
    let mut matches = Vec::new();
    for (index, term) in terms.iter().enumerate() {
        if term.is_empty() || term.len() > body.len() {
            continue;
        }
        for start in 0..=body.len() - term.len() {
            if body[start..].starts_with(term) {
                matches.push((start..start + term.len(), index));
            }
        }
    }
    matches.sort_unstable_by(|(left, _), (right, _)| {
        left.start
            .cmp(&right.start)
            .then_with(|| right.end.cmp(&left.end))
    });
    matches
}

fn find_match_ranges(body: &[u8], terms: &[&[u8]]) -> (Vec<Range<usize>>, u32, u32) {
    let matches = find_matches(body, terms);
    let match_count = u32::try_from(matches.len()).unwrap_or(u32::MAX);
    let matched_terms: BTreeSet<_> = matches.iter().map(|(_, term)| *term).collect();
    let ranges = merge_overlapping_ranges(matches.into_iter().map(|(range, _)| range).collect());
    (
        ranges,
        match_count,
        u32::try_from(matched_terms.len()).unwrap_or(u32::MAX),
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

fn redact_ranges(body: &[u8], ranges: &[Range<usize>], replacement: &[u8]) -> Vec<u8> {
    let mut transformed = Vec::with_capacity(body.len());
    let mut cursor = 0;
    for range in ranges {
        transformed.extend_from_slice(&body[cursor..range.start]);
        transformed.extend_from_slice(replacement);
        cursor = range.end;
    }
    transformed.extend_from_slice(&body[cursor..]);
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

    pub(crate) fn config(mode: &str, terms: &[&str], extra: &[(&str, &str)]) -> Struct {
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
        for (name, value) in extra {
            fields.insert((*name).into(), string(value));
        }
        Struct { fields }
    }
}

#[cfg(test)]
mod tests {
    use prost_types::Value;
    use prost_types::value::Kind;

    use super::test_support::config;
    use super::*;

    fn parse(mode: &str, terms: &[&str], extra: &[(&str, &str)]) -> GuardConfig {
        GuardConfig::parse(Some(&config(mode, terms, extra))).expect("valid config")
    }

    #[test]
    fn redact_replaces_every_configured_match() {
        let config = parse(
            "redact",
            &["prototype-secret", "internal-only"],
            &[("replacement", "[FILTERED]")],
        );
        let result = inspect(
            &config,
            b"prototype-secret then internal-only then prototype-secret",
        );
        assert!(!result.denied);
        assert_eq!(
            result.replacement.unwrap(),
            b"[FILTERED] then [FILTERED] then [FILTERED]"
        );
        assert_eq!(result.findings[0].count, 3);
    }

    #[test]
    fn redact_merges_overlapping_and_keeps_adjacent_matches_separate() {
        let config = parse("redact", &["aba", "bab"], &[("replacement", "[F]")]);
        let result = inspect(&config, b"abab");
        assert_eq!(result.replacement.unwrap(), b"[F]");
        assert_eq!(result.metadata["matched_term_count"], "2");

        let config = parse("redact", &["abc"], &[("replacement", "[F]")]);
        assert_eq!(inspect(&config, b"abcabc").replacement.unwrap(), b"[F][F]");
    }

    #[test]
    fn deny_returns_a_generic_reason_without_echoing_the_term() {
        let config = parse("deny", &["prototype-secret"], &[]);
        let result = inspect(&config, b"contains prototype-secret");
        assert!(result.denied);
        assert!(!result.reason.contains("prototype-secret"));
        assert_eq!(result.reason_code, "content_match");
        assert!(result.replacement.is_none());
    }

    #[test]
    fn no_match_keeps_the_body() {
        let config = parse("redact", &["blocked"], &[]);
        let result = inspect(&config, b"safe content");
        assert!(!result.denied);
        assert!(result.replacement.is_none());
        assert!(result.findings.is_empty());
    }

    #[test]
    fn stream_scanner_redacts_terms_split_across_chunks() {
        let config = parse("redact", &["prototype-secret"], &[("replacement", "[F]")]);
        let input = b"one prototype-secret two prototype-secret three";
        for split in 1..input.len() {
            let mut scanner = StreamScanner::new(&config);
            let mut output = Vec::new();
            for chunk in input.chunks(split) {
                output.extend(scanner.push(chunk, false).unwrap());
            }
            output.extend(scanner.finish(false).unwrap());
            assert_eq!(output, b"one [F] two [F] three", "split={split}");
            assert_eq!(scanner.counts(), (2, 1), "split={split}");
        }
    }

    #[test]
    fn stream_scanner_releases_complete_lines_at_once() {
        let config = parse("redact", &["prototype-secret"], &[]);
        let mut scanner = StreamScanner::new(&config);
        assert_eq!(
            scanner.push(b"data: one\n\n", false).unwrap(),
            b"data: one\n\n"
        );
        // Bytes that may begin a term stay withheld until the line ends.
        assert_eq!(scanner.push(b"data: proto", false).unwrap(), b"");
        assert_eq!(
            scanner.push(b"type-secret\n\n", false).unwrap(),
            b"data: [REDACTED]\n\n"
        );
    }

    #[test]
    fn stream_scanner_denies_a_term_in_deny_mode() {
        let config = parse("deny", &["prototype-secret"], &[]);
        let mut scanner = StreamScanner::new(&config);
        assert_eq!(scanner.push(b"safe prototype-", true).unwrap(), b"");
        assert_eq!(scanner.push(b"secret", true), Err(Denied));
    }

    #[test]
    fn validation_rejects_invalid_configs() {
        let missing_terms = Struct {
            fields: std::collections::BTreeMap::from([(
                "mode".into(),
                test_support::string("redact"),
            )]),
        };
        assert!(GuardConfig::parse(Some(&missing_terms)).is_err());
        for (mode, extra) in [
            ("deny", &[("replacement", "ignored")][..]),
            ("redact", &[("body_mode", "whole")][..]),
            ("redact", &[("uninspectable", "maybe")][..]),
            ("redact", &[("unknown", "x")][..]),
        ] {
            assert!(
                GuardConfig::parse(Some(&config(mode, &["prototype-secret"], extra))).is_err(),
                "{mode} {extra:?}"
            );
        }
        let mut invalid = config("redact", &["prototype-secret"], &[]);
        invalid.fields.insert(
            "mode".into(),
            Value {
                kind: Some(Kind::BoolValue(true)),
            },
        );
        assert_eq!(
            GuardConfig::parse(Some(&invalid)),
            Err("config.mode must be a string".into())
        );
    }

    #[test]
    fn missing_optional_fields_use_defaults() {
        let mut fields = config("redact", &["prototype-secret"], &[]);
        fields.fields.remove("mode");
        let parsed = GuardConfig::parse(Some(&fields)).expect("valid config");
        assert_eq!(parsed.mode, Mode::Redact);
        assert_eq!(parsed.replacement, DEFAULT_REPLACEMENT);
        assert_eq!(parsed.body_mode, BodyMode::Buffered);
        assert!(!parsed.allow_uninspectable);
    }
}
