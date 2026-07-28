// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Canonical provider endpoint path matching shared by policy and runtime code.

/// Return whether `path` is selected by a provider endpoint path pattern.
///
/// Empty paths and `**` match every request path. A trailing `/**` matches the
/// named path itself and every descendant. Other patterns use glob semantics.
#[must_use]
pub fn matches(pattern: &str, path: &str) -> bool {
    if pattern.is_empty() || pattern == "**" || pattern == "/**" {
        return true;
    }
    if pattern == path {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }
    glob::Pattern::new(pattern).is_ok_and(|glob| glob.matches(path))
}

#[cfg(test)]
mod tests {
    use super::matches;

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
}
