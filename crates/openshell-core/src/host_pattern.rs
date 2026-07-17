// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! DNS-label-aware host patterns and selectors.

use std::collections::{HashSet, VecDeque};

/// A validated, compiled DNS host pattern.
///
/// Matching is case-insensitive. A `*` wildcard stays within one DNS label,
/// while a label consisting only of `**` consumes one or more labels. These
/// semantics mirror the Rego endpoint glob matching used for network policy
/// admission (`glob.match` with a `.` delimiter), so a pattern copied from a
/// network endpoint selects exactly the hosts that endpoint admits.
#[derive(Clone)]
pub struct HostPattern {
    source: String,
    labels: Vec<HostLabelPattern>,
}

#[derive(Clone)]
enum HostLabelPattern {
    Recursive,
    Label {
        source: String,
        pattern: glob::Pattern,
        literal: bool,
    },
}

/// A validated destination host selector.
///
/// Includes are evaluated first and exclusions take precedence. Constructing
/// the selector compiles every pattern once, so request-time selection cannot
/// fail due to malformed input.
#[derive(Clone)]
pub struct HostSelector {
    includes: Vec<HostPattern>,
    excludes: Vec<HostPattern>,
}

impl HostSelector {
    pub fn new(include: &[String], exclude: &[String]) -> Result<Self, String> {
        if include.is_empty() {
            return Err("endpoint selector must include at least one host pattern".to_string());
        }
        Ok(Self {
            includes: include
                .iter()
                .map(|pattern| HostPattern::new(pattern))
                .collect::<Result<_, _>>()?,
            excludes: exclude
                .iter()
                .map(|pattern| HostPattern::new(pattern))
                .collect::<Result<_, _>>()?,
        })
    }

    #[must_use]
    pub fn matches(&self, host: &str) -> bool {
        self.includes.iter().any(|pattern| pattern.matches(host))
            && !self.excludes.iter().any(|pattern| pattern.matches(host))
    }

    /// Conservatively determine whether this selector can match a concrete
    /// host admitted by `candidate`.
    #[must_use]
    pub fn may_match_pattern(&self, candidate: &HostPattern) -> bool {
        self.includes.iter().any(|include| {
            if !include.overlaps(candidate) {
                return false;
            }

            let concrete_intersection = candidate.literal().or_else(|| include.literal());
            let excluded = concrete_intersection.map_or_else(
                || {
                    self.excludes.iter().any(|excluded| {
                        excluded.is_universal()
                            || excluded.source == include.source
                            || excluded.source == candidate.source
                    })
                },
                |host| self.excludes.iter().any(|excluded| excluded.matches(host)),
            );
            !excluded
        })
    }
}

impl HostPattern {
    pub fn new(pattern: &str) -> Result<Self, String> {
        if pattern.is_empty() {
            return Err("host pattern must not be empty".to_string());
        }
        if pattern.chars().any(char::is_whitespace) {
            return Err("host pattern must not contain whitespace".to_string());
        }
        // The glob crate treats braces as literal characters while endpoint
        // glob matching expands them, so a brace pattern would silently never
        // match a real host. Fail loud instead.
        if pattern.chars().any(|ch| matches!(ch, '{' | '}')) {
            return Err(
                "host pattern must not contain brace alternates; list each host pattern separately"
                    .to_string(),
            );
        }

        let source = pattern.to_ascii_lowercase();
        if source.split('.').any(str::is_empty) {
            return Err("host pattern must not contain empty DNS labels".to_string());
        }
        let labels = source
            .split('.')
            .map(|label| {
                if label == "**" {
                    return Ok(HostLabelPattern::Recursive);
                }
                let pattern = glob::Pattern::new(label)
                    .map_err(|error| format!("invalid host pattern: {error}"))?;
                Ok(HostLabelPattern::Label {
                    source: label.to_string(),
                    pattern,
                    literal: !label.chars().any(|ch| matches!(ch, '*' | '?' | '[')),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self { source, labels })
    }

    #[must_use]
    pub fn matches(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        if host.split('.').any(str::is_empty) {
            return false;
        }
        self.matches_labels(&host.split('.').collect::<Vec<_>>())
    }

    fn matches_labels(&self, host: &[&str]) -> bool {
        let mut pending = vec![(0, 0)];
        let mut visited = HashSet::new();
        while let Some((pattern_idx, host_idx)) = pending.pop() {
            if !visited.insert((pattern_idx, host_idx)) {
                continue;
            }
            if pattern_idx == self.labels.len() && host_idx == host.len() {
                return true;
            }
            match self.labels.get(pattern_idx) {
                Some(HostLabelPattern::Recursive) if host_idx < host.len() => {
                    pending.push((pattern_idx + 1, host_idx + 1));
                    pending.push((pattern_idx, host_idx + 1));
                }
                Some(HostLabelPattern::Label { pattern, .. }) if host_idx < host.len() => {
                    if pattern.matches(host[host_idx]) {
                        pending.push((pattern_idx + 1, host_idx + 1));
                    }
                }
                Some(_) | None => {}
            }
        }
        false
    }

    fn literal(&self) -> Option<&str> {
        self.labels
            .iter()
            .all(|label| matches!(label, HostLabelPattern::Label { literal: true, .. }))
            .then_some(self.source.as_str())
    }

    fn is_universal(&self) -> bool {
        matches!(self.labels.as_slice(), [HostLabelPattern::Recursive])
    }

    fn overlaps(&self, other: &Self) -> bool {
        let mut pending = VecDeque::from([(0, 0)]);
        let mut visited = HashSet::new();
        while let Some((left_idx, right_idx)) = pending.pop_front() {
            if !visited.insert((left_idx, right_idx)) {
                continue;
            }
            if left_idx == self.labels.len() && right_idx == other.labels.len() {
                return true;
            }

            let (Some(left), Some(right)) =
                (self.labels.get(left_idx), other.labels.get(right_idx))
            else {
                continue;
            };

            // Every transition consumes exactly one shared host label, so a
            // `**` on either side must consume at least one label before it
            // can complete — the same minimum the matcher enforces.
            match (left, right) {
                (HostLabelPattern::Recursive, HostLabelPattern::Recursive) => {
                    pending.push_back((left_idx + 1, right_idx + 1));
                    pending.push_back((left_idx, right_idx + 1));
                    pending.push_back((left_idx + 1, right_idx));
                }
                (HostLabelPattern::Recursive, HostLabelPattern::Label { .. }) => {
                    pending.push_back((left_idx + 1, right_idx + 1));
                    pending.push_back((left_idx, right_idx + 1));
                }
                (HostLabelPattern::Label { .. }, HostLabelPattern::Recursive) => {
                    pending.push_back((left_idx + 1, right_idx + 1));
                    pending.push_back((left_idx + 1, right_idx));
                }
                (left, right) if label_patterns_may_overlap(left, right) => {
                    pending.push_back((left_idx + 1, right_idx + 1));
                }
                _ => {}
            }
        }
        false
    }
}

/// Match a host using DNS-label-aware glob semantics.
///
/// Matching is case-insensitive. `*` cannot cross a `.` label boundary, while
/// a label consisting of `**` consumes one or more labels. Invalid or empty
/// patterns return an error instead of silently becoming a non-match.
pub fn host_matches(pattern: &str, host: &str) -> Result<bool, String> {
    Ok(HostPattern::new(pattern)?.matches(host))
}

/// Conservatively determine whether two DNS host patterns can match the same
/// concrete host.
pub fn host_patterns_overlap(left: &str, right: &str) -> Result<bool, String> {
    let left = HostPattern::new(left)?;
    let right = HostPattern::new(right)?;
    Ok(left.overlaps(&right))
}

/// Determine whether a selector can match any concrete host admitted by a host
/// pattern.
///
/// This is conservative for intersections between two non-literal globs:
/// exclusions suppress a conflict only when they cover a known concrete
/// intersection or exactly cover one of the intersecting patterns.
pub fn selector_may_match_pattern(
    include: &[String],
    exclude: &[String],
    candidate: &str,
) -> Result<bool, String> {
    let selector = HostSelector::new(include, exclude)?;
    let candidate = HostPattern::new(candidate)?;
    Ok(selector.may_match_pattern(&candidate))
}

fn label_patterns_may_overlap(left: &HostLabelPattern, right: &HostLabelPattern) -> bool {
    let (
        HostLabelPattern::Label {
            source: left_source,
            pattern: left_pattern,
            literal: left_literal,
        },
        HostLabelPattern::Label {
            source: right_source,
            pattern: right_pattern,
            literal: right_literal,
        },
    ) = (left, right)
    else {
        return true;
    };

    match (*left_literal, *right_literal) {
        (true, true) => left_source == right_source,
        (true, false) => right_pattern.matches(left_source),
        (false, true) => left_pattern.matches(right_source),
        (false, false) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_matching_is_case_insensitive() {
        assert!(host_matches("*.Example.COM", "API.example.com").unwrap());
        assert!(!host_matches("*.example.com", "example.com").unwrap());
        assert!(!host_matches("*.example.com", "deep.api.example.com").unwrap());
        assert!(host_matches("**.example.com", "deep.api.example.com").unwrap());
        assert!(host_matches("*-api.example.com", "tenant-api.example.com").unwrap());
        assert!(!host_matches("*", "deep.api.example.com").unwrap());
    }

    #[test]
    fn host_matching_rejects_invalid_patterns() {
        assert!(host_matches("", "api.example.com").is_err());
        assert!(host_matches("api .example.com", "api.example.com").is_err());
        assert!(host_matches("api[.example.com", "api.example.com").is_err());
        assert!(host_matches("*.{prod,staging}.example.com", "api.prod.example.com").is_err());
        assert!(host_matches("api**.example.com", "apix.example.com").is_err());
    }

    #[test]
    fn recursive_wildcard_requires_at_least_one_label() {
        assert!(host_matches("**.example.com", "api.example.com").unwrap());
        assert!(!host_matches("**.example.com", "example.com").unwrap());
        assert!(host_matches("api.**.com", "api.x.y.com").unwrap());
        assert!(!host_matches("api.**.com", "api.com").unwrap());
    }

    #[test]
    fn universal_wildcard_matches_any_host() {
        for host in [
            "com",
            "localhost",
            "example.com",
            "deep.api.example.com",
            "xn--bcher-kva.example",
            "tenant-api.internal",
            "192.168.1.1",
            "[::1]",
        ] {
            assert!(host_matches("**", host).unwrap(), "** must match {host}");
        }

        // Hosts with empty labels are invalid and never match, even for `**`.
        assert!(!host_matches("**", "").unwrap());
        assert!(!host_matches("**", "api.example.com.").unwrap());
        assert!(!host_matches("**", "api..example.com").unwrap());
    }

    #[test]
    fn host_pattern_overlap_handles_concrete_and_wildcard_hosts() {
        assert!(host_patterns_overlap("*.example.com", "api.example.com").unwrap());
        assert!(host_patterns_overlap("**.example.com", "deep.api.example.com").unwrap());
        assert!(!host_patterns_overlap("*.example.com", "deep.api.example.com").unwrap());
        assert!(!host_patterns_overlap("*.example.com", "*.other.com").unwrap());
        assert!(host_patterns_overlap("**.example.com", "*.api.example.com").unwrap());
        assert!(!host_patterns_overlap("**.example.com", "example.com").unwrap());
    }

    #[test]
    fn selector_pattern_overlap_honors_concrete_exclusions() {
        let include = vec!["*.example.com".to_string()];
        let exclude = vec!["api.example.com".to_string()];

        assert!(!selector_may_match_pattern(&include, &exclude, "api.example.com").unwrap());
        assert!(selector_may_match_pattern(&include, &exclude, "*.example.com").unwrap());
    }
}
