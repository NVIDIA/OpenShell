// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF schema version downgrade filter.
//!
//! Transforms serialized OCSF JSON events to conform to older schema versions
//! by stripping fields and profiles that don't exist in the target version.

use serde_json::Value;

/// Fields to strip when downgrading to v1.3.0 or earlier.
const STRIP_FOR_V1_3: &[&str] = &["ai_model", "container", "observation_point_id"];

/// Profile names to remove from `metadata.profiles` when downgrading to v1.3.0 or earlier.
const STRIP_PROFILES_V1_3: &[&str] = &["ai_operation", "container"];

/// Downgrade a serialized OCSF event to the target schema version.
///
/// Modifies the JSON in place: strips fields that don't exist in the target
/// version, removes unknown profile names from `metadata.profiles`, and
/// rewrites `metadata.version` to match.
///
/// Returns `true` if the event was modified, `false` if no changes were needed
/// (target is current version or newer).
pub fn downgrade_event(event: &mut Value, target_version: &str) -> bool {
    let target = parse_version(target_version);
    let v1_3 = (1, 3, 0);

    if target >= parse_version(crate::OCSF_VERSION) {
        return false;
    }

    let Some(obj) = event.as_object_mut() else {
        return false;
    };

    let mut modified = false;

    if target <= v1_3 {
        for field in STRIP_FOR_V1_3 {
            if obj.remove(*field).is_some() {
                modified = true;
            }
        }

        if let Some(profiles) = obj
            .get_mut("metadata")
            .and_then(Value::as_object_mut)
            .and_then(|m| m.get_mut("profiles"))
            .and_then(Value::as_array_mut)
        {
            let before = profiles.len();
            profiles.retain(|p| !p.as_str().is_some_and(|s| STRIP_PROFILES_V1_3.contains(&s)));
            if profiles.len() != before {
                modified = true;
            }
        }
    }

    if let Some(metadata) = obj.get_mut("metadata").and_then(Value::as_object_mut) {
        let original_version = metadata
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or(crate::OCSF_VERSION)
            .to_string();
        metadata.insert(
            "version".to_string(),
            Value::String(target_version.to_string()),
        );
        modified = true;

        let unmapped = obj
            .entry("unmapped")
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Some(u) = unmapped.as_object_mut() {
            u.insert(
                "downgraded_from".to_string(),
                Value::String(original_version),
            );
        }
    }

    modified
}

fn parse_version(v: &str) -> (u32, u32, u32) {
    let parts: Vec<u32> = v.split('.').filter_map(|s| s.parse().ok()).collect();
    (
        parts.first().copied().unwrap_or(0),
        parts.get(1).copied().unwrap_or(0),
        parts.get(2).copied().unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_event() -> Value {
        serde_json::json!({
            "class_uid": 4002,
            "class_name": "HTTP Activity",
            "time": 1_234_567_890,
            "severity_id": 1,
            "metadata": {
                "version": crate::OCSF_VERSION,
                "profiles": ["security_control", "network_proxy", "container", "host"]
            },
            "device": {"hostname": "sandbox-1"},
            "container": {"name": "test-sandbox"},
            "observation_point_id": 2,
            "unmapped": {"key": "value"}
        })
    }

    #[test]
    fn test_downgrade_to_v1_3_strips_fields() {
        let mut event = test_event();
        let modified = downgrade_event(&mut event, "1.3.0");

        assert!(modified);
        assert!(event.get("container").is_none());
        assert!(event.get("observation_point_id").is_none());
        assert!(event.get("device").is_some());
        assert!(event.get("unmapped").is_some());
    }

    #[test]
    fn test_downgrade_to_v1_1_strips_fields() {
        let mut event = test_event();
        let modified = downgrade_event(&mut event, "1.1.0");

        assert!(modified);
        assert!(event.get("container").is_none());
        assert!(event.get("observation_point_id").is_none());
    }

    #[test]
    fn test_downgrade_strips_profiles() {
        let mut event = test_event();
        downgrade_event(&mut event, "1.3.0");

        let profiles = event["metadata"]["profiles"].as_array().unwrap();
        assert!(!profiles.iter().any(|p| p == "container"));
        assert!(profiles.iter().any(|p| p == "security_control"));
        assert!(profiles.iter().any(|p| p == "host"));
    }

    #[test]
    fn test_downgrade_rewrites_version() {
        let mut event = test_event();
        downgrade_event(&mut event, "1.1.0");

        assert_eq!(event["metadata"]["version"], "1.1.0");
        assert_eq!(event["unmapped"]["downgraded_from"], crate::OCSF_VERSION);
    }

    #[test]
    fn test_no_downgrade_for_current_version() {
        let mut event = test_event();
        let modified = downgrade_event(&mut event, crate::OCSF_VERSION);

        assert!(!modified);
        assert_eq!(event["metadata"]["version"], crate::OCSF_VERSION);
    }

    #[test]
    fn test_no_downgrade_for_newer_version() {
        let mut event = test_event();
        let modified = downgrade_event(&mut event, "1.9.0");

        assert!(!modified);
    }

    #[test]
    fn test_downgrade_strips_ai_model_when_present() {
        let mut event = serde_json::json!({
            "class_uid": 6003,
            "metadata": {
                "version": "1.8.0",
                "profiles": ["container", "host", "ai_operation"]
            },
            "ai_model": {"name": "claude-3-haiku", "ai_provider": "anthropic"},
            "unmapped": {"latency_ms": 701}
        });
        let modified = downgrade_event(&mut event, "1.3.0");

        assert!(modified);
        assert!(event.get("ai_model").is_none());
        assert!(
            !event["metadata"]["profiles"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p == "ai_operation")
        );
        assert_eq!(event["metadata"]["version"], "1.3.0");
        assert_eq!(event["unmapped"]["downgraded_from"], "1.8.0");
        assert_eq!(event["unmapped"]["latency_ms"], 701);
    }

    #[test]
    fn test_downgrade_creates_unmapped_when_absent() {
        let mut event = serde_json::json!({
            "class_uid": 4001,
            "metadata": {
                "version": crate::OCSF_VERSION,
                "profiles": ["container"]
            },
            "container": {"name": "sandbox-1"}
        });
        let modified = downgrade_event(&mut event, "1.1.0");

        assert!(modified);
        assert_eq!(event["unmapped"]["downgraded_from"], crate::OCSF_VERSION);
    }

    #[test]
    fn test_downgrade_rewrites_version_without_strippable_fields() {
        let mut event = serde_json::json!({
            "class_uid": 0,
            "metadata": {
                "version": crate::OCSF_VERSION,
                "profiles": ["host"]
            }
        });

        let modified = downgrade_event(&mut event, "1.3.0");

        assert!(modified);
        assert_eq!(event["metadata"]["version"], "1.3.0");
        assert_eq!(event["unmapped"]["downgraded_from"], crate::OCSF_VERSION);
    }

    #[test]
    fn test_no_downgrade_omits_breadcrumb() {
        let mut event = test_event();
        downgrade_event(&mut event, crate::OCSF_VERSION);

        assert!(
            event
                .get("unmapped")
                .and_then(Value::as_object)
                .and_then(|u| u.get("downgraded_from"))
                .is_none()
        );
    }
}
