// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! CLI output parsing utilities.

/// Strip ANSI escape codes (e.g. colors, bold) from a string.
///
/// Handles the common `ESC[<params>m` SGR sequences produced by the CLI's
/// `owo-colors` output.
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Consume the `[` and everything up to the terminating letter.
            if chars.peek() == Some(&'[') {
                chars.next(); // consume '['
                              // Consume parameter bytes (digits, ';') and the final byte.
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            out.push(c);
        }
    }

    out
}

/// Extract a field value from CLI tabular output.
///
/// Given output like:
/// ```text
///   Name:    fuzzy-panda
///   Status:  Running
/// ```
///
/// `extract_field(output, "Name")` returns `Some("fuzzy-panda")`.
///
/// The search is performed on ANSI-stripped text.
pub fn extract_field(output: &str, field: &str) -> Option<String> {
    let clean = strip_ansi(output);
    let prefix = format!("{field}:");

    for line in clean.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(&prefix) {
            let value = rest.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_ansi_removes_color_codes() {
        let colored = "\x1b[1m\x1b[32mName:\x1b[0m  fuzzy-panda";
        assert_eq!(strip_ansi(colored), "Name:  fuzzy-panda");
    }

    #[test]
    fn strip_ansi_passthrough_plain_text() {
        let plain = "no colors here";
        assert_eq!(strip_ansi(plain), plain);
    }

    #[test]
    fn extract_field_finds_value() {
        let output = "  Name:    fuzzy-panda\n  Status:  Running\n";
        assert_eq!(extract_field(output, "Name"), Some("fuzzy-panda".into()));
        assert_eq!(extract_field(output, "Status"), Some("Running".into()));
    }

    #[test]
    fn extract_field_with_ansi() {
        let output = "\x1b[1mName:\x1b[0m  fuzzy-panda\n";
        assert_eq!(extract_field(output, "Name"), Some("fuzzy-panda".into()));
    }

    #[test]
    fn extract_field_missing_returns_none() {
        let output = "  Name:  fuzzy-panda\n";
        assert_eq!(extract_field(output, "Missing"), None);
    }
}
