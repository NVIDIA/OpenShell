// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Registry for sandbox runtime settings keys and value kinds.

/// Supported value kinds for registered sandbox settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingValueKind {
    String,
    Int,
    Bool,
}

impl SettingValueKind {
    /// Human-readable value kind used in error messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Int => "int",
            Self::Bool => "bool",
        }
    }
}

/// Static descriptor for one registered sandbox setting key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisteredSetting {
    pub key: &'static str,
    pub kind: SettingValueKind,
}

/// Static registry of currently-supported runtime settings.
///
/// `policy` is intentionally excluded because it is a reserved key handled by
/// dedicated policy commands and payloads.
pub const REGISTERED_SETTINGS: &[RegisteredSetting] = &[
    RegisteredSetting {
        key: "log_level",
        kind: SettingValueKind::String,
    },
    RegisteredSetting {
        key: "dummy_int",
        kind: SettingValueKind::Int,
    },
    RegisteredSetting {
        key: "dummy_bool",
        kind: SettingValueKind::Bool,
    },
];

/// Resolve a setting descriptor from the registry by key.
#[must_use]
pub fn setting_for_key(key: &str) -> Option<&'static RegisteredSetting> {
    REGISTERED_SETTINGS.iter().find(|entry| entry.key == key)
}

/// Return comma-separated registered keys for CLI/API diagnostics.
#[must_use]
pub fn registered_keys_csv() -> String {
    REGISTERED_SETTINGS
        .iter()
        .map(|entry| entry.key)
        .collect::<Vec<_>>()
        .join(", ")
}

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
    use super::{SettingValueKind, parse_bool_like, setting_for_key};

    #[test]
    fn setting_for_key_returns_registered_entry() {
        let setting = setting_for_key("dummy_bool").expect("dummy_bool should be registered");
        assert_eq!(setting.kind, SettingValueKind::Bool);
    }

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
    fn parse_bool_like_rejects_unrecognized_values() {
        assert_eq!(parse_bool_like("maybe"), None);
    }
}
