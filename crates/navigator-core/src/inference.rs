// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

/// Normalize a list of protocol strings: trim, lowercase, deduplicate, skip empty.
pub fn normalize_protocols(protocols: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();

    for protocol in protocols {
        let candidate = protocol.trim().to_ascii_lowercase();
        if candidate.is_empty() {
            continue;
        }
        if seen.insert(candidate.clone()) {
            normalized.push(candidate);
        }
    }

    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_and_deduplicates() {
        let input = vec![
            "OpenAI_Chat_Completions".to_string(),
            " openai_chat_completions ".to_string(),
            "anthropic_messages".to_string(),
        ];
        let result = normalize_protocols(&input);
        assert_eq!(
            result,
            vec!["openai_chat_completions", "anthropic_messages"]
        );
    }

    #[test]
    fn skips_empty_and_whitespace() {
        let input = vec![String::new(), "  ".to_string(), "valid".to_string()];
        let result = normalize_protocols(&input);
        assert_eq!(result, vec!["valid"]);
    }

    #[test]
    fn empty_input() {
        let result = normalize_protocols(&[]);
        assert!(result.is_empty());
    }
}
