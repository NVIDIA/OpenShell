// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Canonical provider endpoint path matching shared by policy and runtime code.

/// A compiled provider endpoint path pattern.
///
/// Invalid glob syntax retains the existing fail-closed behavior: it matches
/// only when the request path is exactly equal to the configured pattern.
#[derive(Debug, Clone)]
pub struct EndpointPathPattern {
    source: String,
    kind: EndpointPathPatternKind,
}

#[derive(Debug, Clone)]
enum EndpointPathPatternKind {
    Any,
    Subtree(String),
    Glob(glob::Pattern),
    Invalid,
}

impl EndpointPathPattern {
    #[must_use]
    pub fn new(pattern: &str) -> Self {
        let kind = if pattern.is_empty() || pattern == "**" || pattern == "/**" {
            EndpointPathPatternKind::Any
        } else if let Some(prefix) = pattern.strip_suffix("/**") {
            EndpointPathPatternKind::Subtree(prefix.to_string())
        } else {
            glob::Pattern::new(pattern).map_or(
                EndpointPathPatternKind::Invalid,
                EndpointPathPatternKind::Glob,
            )
        };
        Self {
            source: pattern.to_string(),
            kind,
        }
    }

    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        if self.source == path {
            return true;
        }
        match &self.kind {
            EndpointPathPatternKind::Any => true,
            EndpointPathPatternKind::Subtree(prefix) => {
                path == prefix
                    || path
                        .strip_prefix(prefix)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            }
            EndpointPathPatternKind::Glob(pattern) => pattern.matches(path),
            EndpointPathPatternKind::Invalid => false,
        }
    }
}

/// Return whether `path` is selected by a provider endpoint path pattern.
///
/// Empty paths and `**` match every request path. A trailing `/**` matches the
/// named path itself and every descendant. Other patterns use glob semantics.
#[must_use]
pub fn matches(pattern: &str, path: &str) -> bool {
    EndpointPathPattern::new(pattern).matches(path)
}

#[cfg(test)]
mod tests {
    use super::{EndpointPathPattern, matches};

    #[test]
    fn matches_canonical_endpoint_patterns() {
        assert!(matches("", "/v1/messages"));
        assert!(matches("/**", "/v1/messages"));
        assert!(matches("/v1/**", "/v1"));
        assert!(matches("/v1/**", "/v1/messages"));
        assert!(matches("/v*/messages", "/v1/messages"));
        assert!(matches("/v1/*", "/v1/chat/messages"));
        assert!(!matches("/v1/**", "/v2/messages"));
        assert!(!matches("/v1/*/messages", "/v1/chat/completions"));
    }

    #[test]
    fn compiled_patterns_preserve_canonical_matching() {
        let subtree = EndpointPathPattern::new("/v1/**");
        assert!(subtree.matches("/v1"));
        assert!(subtree.matches("/v1/chat/messages"));
        assert!(!subtree.matches("/v2/messages"));

        let glob = EndpointPathPattern::new("/v*/messages");
        assert!(glob.matches("/v1/messages"));
        assert!(!glob.matches("/v1/completions"));

        let invalid = EndpointPathPattern::new("[");
        assert!(invalid.matches("["));
        assert!(!invalid.matches("/v1/messages"));
    }
}
