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
///
/// # Adding a new setting
///
/// 1. Add a [`RegisteredSetting`] entry to this array with the key name and
///    [`SettingValueKind`].
/// 2. Recompile `openshell-server` (gateway) and `openshell-sandbox`
///    (supervisor). No database migration is needed -- new keys are stored in
///    the existing settings JSON blob.
/// 3. Add sandbox-side consumption in `openshell-sandbox` to read and act on
///    the new key from the poll loop's `SettingsPollResult::settings` map.
/// 4. The key will automatically appear in `settings get` (CLI/TUI) and be
///    settable via `settings set`. The server validates that only registered
///    keys are accepted.
/// 5. Add a unit test in this module's `tests` section to cover the new key.
pub const PROVIDERS_V2_ENABLED_KEY: &str = "providers_v2_enabled";

pub const REGISTERED_SETTINGS: &[RegisteredSetting] = &[
    // Gateway-level opt-in for provider profile policy composition. Defaults
    // to false when unset.
    RegisteredSetting {
        key: PROVIDERS_V2_ENABLED_KEY,
        kind: SettingValueKind::Bool,
    },
    // When true the sandbox writes OCSF v1.7.0 JSONL records to
    // `/var/log/openshell-ocsf*.log` (daily rotation, 3 files) in addition
    // to the human-readable shorthand log. Defaults to false (no JSONL written).
    RegisteredSetting {
        key: "ocsf_json_enabled",
        kind: SettingValueKind::Bool,
    },
    // Test-only keys live behind the `dev-settings` feature flag so they
    // don't appear in production builds.
    #[cfg(feature = "dev-settings")]
    RegisteredSetting {
        key: "dummy_int",
        kind: SettingValueKind::Int,
    },
    #[cfg(feature = "dev-settings")]
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
    use super::{
        PROVIDERS_V2_ENABLED_KEY, REGISTERED_SETTINGS, RegisteredSetting, SettingValueKind,
        parse_bool_like, registered_keys_csv, setting_for_key,
    };

    #[cfg(feature = "dev-settings")]
    #[test]
    fn setting_for_key_returns_dev_entries() {
        let setting = setting_for_key("dummy_bool").expect("dummy_bool should be registered");
        assert_eq!(setting.kind, SettingValueKind::Bool);
        let setting = setting_for_key("dummy_int").expect("dummy_int should be registered");
        assert_eq!(setting.kind, SettingValueKind::Int);
    }

    #[test]
    fn setting_for_key_returns_none_for_unknown() {
        assert!(setting_for_key("nonexistent_key").is_none());
    }

    #[test]
    fn setting_for_key_returns_none_for_reserved_policy() {
        // "policy" is intentionally excluded from the registry.
        assert!(setting_for_key("policy").is_none());
    }

    #[test]
    fn setting_for_key_returns_providers_v2_enabled() {
        let setting = setting_for_key(PROVIDERS_V2_ENABLED_KEY)
            .expect("providers_v2_enabled should be registered");
        assert_eq!(setting.kind, SettingValueKind::Bool);
    }

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

    // ---- REGISTERED_SETTINGS entries ----

    #[test]
    fn registered_settings_have_valid_kinds() {
        let valid_kinds = [
            SettingValueKind::String,
            SettingValueKind::Int,
            SettingValueKind::Bool,
        ];
        for entry in REGISTERED_SETTINGS {
            assert!(
                valid_kinds.contains(&entry.kind),
                "registered setting '{}' has unexpected kind {:?}",
                entry.key,
                entry.kind,
            );
        }
    }

    #[test]
    fn registered_settings_keys_are_nonempty_and_unique() {
        let mut seen = std::collections::HashSet::new();
        for entry in REGISTERED_SETTINGS {
            assert!(
                !entry.key.is_empty(),
                "registered setting key must not be empty"
            );
            assert!(
                seen.insert(entry.key),
                "duplicate registered setting key '{}'",
                entry.key,
            );
        }
    }

    #[test]
    fn registered_settings_excludes_policy() {
        assert!(
            !REGISTERED_SETTINGS.iter().any(|e| e.key == "policy"),
            "policy must not appear in REGISTERED_SETTINGS"
        );
    }

    #[test]
    fn registered_keys_csv_contains_all_keys() {
        let csv = registered_keys_csv();
        for entry in REGISTERED_SETTINGS {
            assert!(
                csv.contains(entry.key),
                "registered_keys_csv() missing '{}'",
                entry.key,
            );
        }
    }

    // ---- SettingValueKind::as_str ----

    #[test]
    fn setting_value_kind_as_str_returns_expected_labels() {
        assert_eq!(SettingValueKind::String.as_str(), "string");
        assert_eq!(SettingValueKind::Int.as_str(), "int");
        assert_eq!(SettingValueKind::Bool.as_str(), "bool");
    }

    // ---- RegisteredSetting structural ----

    #[test]
    fn registered_setting_derives_debug_clone_eq() {
        let a = RegisteredSetting {
            key: "test",
            kind: SettingValueKind::Bool,
        };
        let b = a;
        assert_eq!(a, b);
        // Debug is exercised implicitly by format!
        let _ = format!("{a:?}");
    }
}
