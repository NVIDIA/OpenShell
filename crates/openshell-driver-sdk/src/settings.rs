// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Setting-value parsing shared by the CLI, the TUI, and the compute drivers.

/// Parse common bool-like string values.
#[must_use]
pub fn parse_bool_like(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::parse_bool_like;

    // ---- parse_bool_like ----

    #[test]
    fn parse_bool_like_accepts_expected_spellings() {
        for raw in ["1", "true", "yes", "on", "Y"] {
            assert_eq!(parse_bool_like(raw), Some(true), "expected true for {raw}");
        }
        for raw in ["0", "false", "no", "off", "N"] {
            assert_eq!(
                parse_bool_like(raw),
                Some(false),
                "expected false for {raw}"
            );
        }
    }

    #[test]
    fn parse_bool_like_case_insensitive() {
        assert_eq!(parse_bool_like("TRUE"), Some(true));
        assert_eq!(parse_bool_like("True"), Some(true));
        assert_eq!(parse_bool_like("FALSE"), Some(false));
        assert_eq!(parse_bool_like("False"), Some(false));
        assert_eq!(parse_bool_like("YES"), Some(true));
        assert_eq!(parse_bool_like("NO"), Some(false));
        assert_eq!(parse_bool_like("On"), Some(true));
        assert_eq!(parse_bool_like("Off"), Some(false));
    }

    #[test]
    fn parse_bool_like_trims_whitespace() {
        assert_eq!(parse_bool_like("  true  "), Some(true));
        assert_eq!(parse_bool_like("\tfalse\t"), Some(false));
        assert_eq!(parse_bool_like(" 1 "), Some(true));
        assert_eq!(parse_bool_like(" 0 "), Some(false));
    }

    #[test]
    fn parse_bool_like_rejects_unrecognized_values() {
        assert_eq!(parse_bool_like("maybe"), None);
        assert_eq!(parse_bool_like(""), None);
        assert_eq!(parse_bool_like("2"), None);
        assert_eq!(parse_bool_like("nope"), None);
        assert_eq!(parse_bool_like("yep"), None);
        assert_eq!(parse_bool_like("enabled"), None);
        assert_eq!(parse_bool_like("disabled"), None);
    }
}
