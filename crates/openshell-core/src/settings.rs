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
    /// Optional whitelist of allowed string values. When `Some`, values
    /// outside the list are rejected at configure time by every API surface
    /// that goes through [`validate_string_value`] (CLI, TUI, gRPC). `None`
    /// means the value is free-form and any string is accepted. Only
    /// meaningful for [`SettingValueKind::String`] entries.
    pub allowed_string_values: Option<&'static [&'static str]>,
}

impl RegisteredSetting {
    /// Validate a string value against [`allowed_string_values`]. Returns
    /// `Ok(())` when the setting has no constraint or when the value is in
    /// the allowed list. On rejection, returns the allowed slice so callers
    /// can format their own diagnostic.
    ///
    /// [`allowed_string_values`]: Self::allowed_string_values
    ///
    /// # Errors
    ///
    /// Returns the allowed-value slice when the setting has an
    /// `allowed_string_values` whitelist and `value` is not in it.
    pub fn validate_string_value(&self, value: &str) -> Result<(), &'static [&'static str]> {
        match self.allowed_string_values {
            Some(allowed) if !allowed.contains(&value) => Err(allowed),
            _ => Ok(()),
        }
    }
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

/// Sandbox-level opt-in for the agent-driven policy proposal surface.
///
/// When true, the supervisor installs the `policy_advisor` skill, serves
/// the `policy.local` API routes, and includes `next_steps` in L7 deny
/// bodies. See `crates/openshell-sandbox/src/policy_local.rs`. Defaults to
/// false. Independent of the per-proposal developer approval gate, which
/// still applies when this flag is on.
pub const AGENT_POLICY_PROPOSALS_ENABLED_KEY: &str = "agent_policy_proposals_enabled";

/// Approval mode for agent-authored policy proposals.
///
/// `"manual"` (the default when unset): every proposal lands in the draft
/// inbox for human review, regardless of the prover verdict. `"auto"`:
/// proposals whose prover delta is empty are approved automatically;
/// proposals with findings still require human approval. Any other value
/// (typos, future-reserved modes like `"auto_on_low_risk"`) falls back to
/// manual — auto mode is an explicit, exact opt-in.
///
/// Resolution precedence (matches the rest of the settings model): gateway
/// scope wins over sandbox scope. A reviewer can pin manual mode for a
/// fleet by setting it globally; per-sandbox overrides only apply when no
/// global is set.
pub const PROPOSAL_APPROVAL_MODE_KEY: &str = "proposal_approval_mode";

/// Allowed values for [`PROPOSAL_APPROVAL_MODE_KEY`].
///
/// Any other string is rejected at configure time (so operators get immediate
/// feedback on typos like `"autom"`) while the runtime resolver still
/// fail-closes on unknown persisted values for defense in depth.
pub const PROPOSAL_APPROVAL_MODE_VALUES: &[&str] = &["manual", "auto"];

pub const REGISTERED_SETTINGS: &[RegisteredSetting] = &[
    // Gateway-level opt-in for provider profile policy composition. Defaults
    // to false when unset.
    RegisteredSetting {
        key: PROVIDERS_V2_ENABLED_KEY,
        kind: SettingValueKind::Bool,
        allowed_string_values: None,
    },
    // When true the sandbox writes OCSF v1.7.0 JSONL records to
    // `/var/log/openshell-ocsf*.log` (daily rotation, 3 files) in addition
    // to the human-readable shorthand log. Defaults to false (no JSONL written).
    RegisteredSetting {
        key: "ocsf_json_enabled",
        kind: SettingValueKind::Bool,
        allowed_string_values: None,
    },
    // Sandbox-level opt-in for the agent-driven policy proposal surface.
    // See AGENT_POLICY_PROPOSALS_ENABLED_KEY for details. Defaults to false.
    RegisteredSetting {
        key: AGENT_POLICY_PROPOSALS_ENABLED_KEY,
        kind: SettingValueKind::Bool,
        allowed_string_values: None,
    },
    // Approval mode for agent-authored proposals. See
    // PROPOSAL_APPROVAL_MODE_KEY for details. Defaults to manual.
    RegisteredSetting {
        key: PROPOSAL_APPROVAL_MODE_KEY,
        kind: SettingValueKind::String,
        allowed_string_values: Some(PROPOSAL_APPROVAL_MODE_VALUES),
    },
    // Test-only keys live behind the `dev-settings` feature flag so they
    // don't appear in production builds.
    #[cfg(feature = "dev-settings")]
    RegisteredSetting {
        key: "dummy_int",
        kind: SettingValueKind::Int,
        allowed_string_values: None,
    },
    #[cfg(feature = "dev-settings")]
    RegisteredSetting {
        key: "dummy_bool",
        kind: SettingValueKind::Bool,
        allowed_string_values: None,
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
        PROPOSAL_APPROVAL_MODE_KEY, PROPOSAL_APPROVAL_MODE_VALUES, PROVIDERS_V2_ENABLED_KEY,
        REGISTERED_SETTINGS, RegisteredSetting, SettingValueKind, parse_bool_like,
        registered_keys_csv, setting_for_key,
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

    // ---- RegisteredSetting::validate_string_value ----

    #[test]
    fn validate_string_value_accepts_anything_when_unconstrained() {
        let setting = setting_for_key(PROVIDERS_V2_ENABLED_KEY)
            .expect("providers_v2_enabled should be registered");
        // Bool-kind entries currently leave `allowed_string_values = None`;
        // the helper still returns Ok for arbitrary strings.
        assert!(setting.validate_string_value("anything").is_ok());
        assert!(setting.validate_string_value("").is_ok());
    }

    #[test]
    fn proposal_approval_mode_accepts_manual_and_auto() {
        let setting = setting_for_key(PROPOSAL_APPROVAL_MODE_KEY)
            .expect("proposal_approval_mode should be registered");
        assert_eq!(setting.kind, SettingValueKind::String);
        assert_eq!(
            setting.allowed_string_values,
            Some(PROPOSAL_APPROVAL_MODE_VALUES)
        );
        assert!(setting.validate_string_value("manual").is_ok());
        assert!(setting.validate_string_value("auto").is_ok());
    }

    #[test]
    fn proposal_approval_mode_rejects_typos_and_future_modes() {
        let setting = setting_for_key(PROPOSAL_APPROVAL_MODE_KEY)
            .expect("proposal_approval_mode should be registered");
        for bad in [
            "autom",
            "AUTO",
            "Manual",
            "",
            " auto",
            "auto_on_low_risk",
            "yes",
        ] {
            let err = setting
                .validate_string_value(bad)
                .expect_err(&format!("expected '{bad}' to be rejected"));
            // Caller gets the allowed slice back for diagnostics.
            assert_eq!(err, PROPOSAL_APPROVAL_MODE_VALUES);
        }
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
            allowed_string_values: None,
        };
        let b = a;
        assert_eq!(a, b);
        // Debug is exercised implicitly by format!
        let _ = format!("{a:?}");
    }
}
