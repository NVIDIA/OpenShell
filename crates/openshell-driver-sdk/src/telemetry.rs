// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Telemetry state that compute drivers propagate to sandbox supervisors.

/// Whether anonymous telemetry is enabled, as the value drivers hand to sandbox
/// supervisors (`"true"` or `"false"`).
#[cfg(feature = "telemetry")]
pub fn enabled_env_value() -> &'static str {
    enabled_env_value_from(std::env::var("OPENSHELL_TELEMETRY_ENABLED").ok().as_deref())
}

/// Telemetry support is compiled out: report disabled so sandbox supervisors
/// inherit the disabled state and skip activity collection.
#[cfg(not(feature = "telemetry"))]
pub fn enabled_env_value() -> &'static str {
    "false"
}

#[cfg(feature = "telemetry")]
fn enabled_env_value_from(value: Option<&str>) -> &'static str {
    if telemetry_enabled_from(value) {
        "true"
    } else {
        "false"
    }
}

#[cfg(feature = "telemetry")]
fn telemetry_enabled_from(value: Option<&str>) -> bool {
    let value = value.unwrap_or("true");
    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

#[cfg(all(test, feature = "telemetry"))]
mod tests {
    use super::*;

    #[test]
    fn telemetry_enabled_defaults_true() {
        assert!(telemetry_enabled_from(None));
    }

    #[test]
    fn telemetry_enabled_honors_false_values() {
        assert!(!telemetry_enabled_from(Some("off")));
        assert!(!telemetry_enabled_from(Some("false")));
        assert!(telemetry_enabled_from(Some("yes")));
    }

    #[test]
    fn telemetry_enabled_env_value_is_normalized() {
        assert_eq!(enabled_env_value_from(Some("false")), "false");
        assert_eq!(enabled_env_value_from(Some("0")), "false");
        assert_eq!(enabled_env_value_from(None), "true");
        assert_eq!(enabled_env_value_from(Some("yes")), "true");
    }
}
