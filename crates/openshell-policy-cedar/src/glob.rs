// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Rust guideline compliant 2026-09-30

//! Segment-aware glob classification and matching.
//!
//! Mirrors Rego's `glob.match(pattern, delimiters, string)` semantics
//! closely enough to decide whether a glob pattern is safe to translate
//! into Cedar's `.like()` operator, and to detect requests an unsafe
//! pattern would have matched.
//!
//! Cedar's `*` wildcard always crosses delimiter characters (it matches any
//! sequence, unconditionally). Rego's `glob.match`, as used by
//! `sandbox-policy.rego` for host (`.` delimiter) and binary-path (`/`
//! delimiter) matching, distinguishes a *standalone* `*` (must not cross a
//! delimiter) from `**` (crosses delimiters, the same as Cedar's `*`).
//! Translating a standalone `*` into Cedar's `.like()` would silently make
//! the policy *more permissive* than Rego intended.

/// The result of classifying one glob pattern for Cedar translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobClass<'a> {
    /// No `*` at all: an exact-match string.
    Exact(&'a str),
    /// Every wildcard run in the pattern is `**` (or longer): safe to pass
    /// directly to Cedar's `.like()` unchanged. Cedar's `*` and a run of
    /// two or more `*` both mean "zero or more of anything, crossing
    /// delimiters," so no rewriting is needed.
    SafeGlob(&'a str),
    /// Contains at least one standalone `*` (a run of exactly one `*`),
    /// which Rego treats as delimiter-bounded but Cedar's `.like()` would
    /// not. Not safe to translate to a Cedar clause; use
    /// [`matches_segmented`] to detect which requests it would have
    /// matched, for `Unsupported` reporting.
    Unsafe,
}

/// Classifies `pattern` for Cedar translation safety.
///
/// Classification doesn't depend on the delimiter character itself, only on
/// whether every `*` run has length >= 2 — the delimiter only matters for
/// [`matches_segmented`], which actually evaluates a pattern.
#[must_use]
pub fn classify_glob(pattern: &str) -> GlobClass<'_> {
    if !pattern.contains('*') {
        return GlobClass::Exact(pattern);
    }
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'*' {
            let run_start = i;
            while i < bytes.len() && bytes[i] == b'*' {
                i += 1;
            }
            if i - run_start == 1 {
                return GlobClass::Unsafe;
            }
        } else {
            i += 1;
        }
    }
    GlobClass::SafeGlob(pattern)
}

/// One token of a parsed glob pattern.
enum Token {
    Literal(char),
    /// A wildcard run. `crosses` is true for `**` (or longer) runs, false
    /// for a standalone `*`.
    Star {
        crosses: bool,
    },
}

fn tokenize(pattern: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '*' {
            let start = i;
            while i < chars.len() && chars[i] == '*' {
                i += 1;
            }
            tokens.push(Token::Star {
                crosses: i - start >= 2,
            });
        } else {
            tokens.push(Token::Literal(chars[i]));
            i += 1;
        }
    }
    tokens
}

/// Matches `value` against `pattern`.
///
/// Uses the same delimiter-aware semantics as Rego's
/// `glob.match(pattern, [delimiter], value)`: a standalone `*` matches zero
/// or more characters excluding `delimiter`; a `**` (or longer) run matches
/// zero or more characters including `delimiter`; any other character in
/// `pattern` must match literally.
///
/// Intended for classifying requests against patterns [`classify_glob`]
/// marked [`GlobClass::Unsafe`] — not used for patterns Cedar itself
/// evaluates.
#[must_use]
pub fn matches_segmented(pattern: &str, delimiter: char, value: &str) -> bool {
    let tokens = tokenize(pattern);
    let value: Vec<char> = value.chars().collect();

    // dp[t][v] = tokens[..t] matches value[..v].
    let mut dp = vec![vec![false; value.len() + 1]; tokens.len() + 1];
    dp[0][0] = true;
    for (t, token) in tokens.iter().enumerate() {
        if let Token::Star { .. } = token {
            dp[t + 1][0] = dp[t][0];
        }
    }

    for (t, token) in tokens.iter().enumerate() {
        for v in 1..=value.len() {
            dp[t + 1][v] = match token {
                Token::Literal(c) => dp[t][v - 1] && value[v - 1] == *c,
                Token::Star { crosses } => {
                    dp[t][v] || (dp[t + 1][v - 1] && (*crosses || value[v - 1] != delimiter))
                }
            };
        }
    }

    dp[tokens.len()][value.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_exact_and_glob_patterns() {
        assert_eq!(classify_glob("pypi.org"), GlobClass::Exact("pypi.org"));
        assert_eq!(
            classify_glob("**.example.com"),
            GlobClass::SafeGlob("**.example.com")
        );
        assert_eq!(classify_glob("*"), GlobClass::Unsafe);
        assert_eq!(classify_glob("*.example.com"), GlobClass::Unsafe);
        assert_eq!(
            classify_glob("/sandbox/**/bin/*"),
            GlobClass::Unsafe // the trailing standalone `*` makes the whole pattern unsafe
        );
    }

    #[test]
    fn standalone_star_does_not_cross_dot_delimiter() {
        assert!(matches_segmented("*.example.com", '.', "foo.example.com"));
        assert!(!matches_segmented("*.example.com", '.', "a.b.example.com"));
    }

    #[test]
    fn double_star_crosses_dot_delimiter() {
        assert!(matches_segmented("**.example.com", '.', "a.b.example.com"));
    }

    #[test]
    fn standalone_star_does_not_cross_slash_delimiter() {
        assert!(matches_segmented(
            "/sandbox/*/bin",
            '/',
            "/sandbox/venv/bin"
        ));
        assert!(!matches_segmented(
            "/sandbox/*/bin",
            '/',
            "/sandbox/a/b/bin"
        ));
    }
}
