// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sanitizers for free-form text that lands in OCSF events.

/// Sanitize a free-form reviewer-typed string before it lands in the OCSF
/// audit surface. Callers keep the raw text for their own consumers; this is
/// audit-side defense only.
///
/// Strips control characters (except space) and caps the length, marking
/// truncation with an ellipsis.
#[must_use]
pub fn sanitize_reason_for_audit(raw: &str) -> String {
    const MAX_CHARS: usize = 200;
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(MAX_CHARS)
        .collect();
    if raw.chars().count() > MAX_CHARS {
        format!("{cleaned}…")
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::sanitize_reason_for_audit;

    #[test]
    fn sanitize_reason_for_audit_strips_control_chars_and_caps_length() {
        // Tabs and newlines are stripped; ordinary printable chars survive;
        // multi-byte characters count as one char in the cap.
        let raw = "line one\nline\ttwo\u{0001}\u{0007}";
        let cleaned = sanitize_reason_for_audit(raw);
        assert!(!cleaned.contains('\n'));
        assert!(!cleaned.contains('\t'));
        assert!(!cleaned.contains('\u{0001}'));
        assert!(cleaned.contains("line one"));
        assert!(cleaned.contains("linetwo"));

        // Length cap with ellipsis marker so a downstream reader can tell
        // the audit string is truncated.
        let long: String = "x".repeat(500);
        let capped = sanitize_reason_for_audit(&long);
        assert!(capped.chars().count() <= 201);
        assert!(capped.ends_with('…'));

        // Empty input maps to empty output (caller renders "(no guidance)").
        assert_eq!(sanitize_reason_for_audit(""), "");
    }
}
