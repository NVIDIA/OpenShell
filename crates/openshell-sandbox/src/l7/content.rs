// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Content scanning configuration parsed from sandbox policy.
//!
//! When `content_policy.enabled` is set on an endpoint, the proxy uses the
//! configured `max_scan_bytes` limit while running the embedded privacy scanner.
//! Endpoints without a content policy still use the default scan cap.

/// Content scanning configuration parsed from policy data.
#[derive(Debug, Clone)]
pub struct ContentScanConfig {
    pub enabled: bool,
    pub max_scan_bytes: u32,
    /// Legacy action field. The embedded scanner always redacts.
    pub action: String,
}

fn get_regorus_str(obj: &regorus::Value, key: &str) -> String {
    let k = regorus::Value::String(key.into());
    match obj {
        regorus::Value::Object(map) => match map.get(&k) {
            Some(regorus::Value::String(s)) => s.to_string(),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

fn get_regorus_bool(obj: &regorus::Value, key: &str) -> bool {
    let k = regorus::Value::String(key.into());
    match obj {
        regorus::Value::Object(map) => match map.get(&k) {
            Some(regorus::Value::Bool(b)) => *b,
            _ => false,
        },
        _ => false,
    }
}

fn get_regorus_u32(obj: &regorus::Value, key: &str, default: u32) -> u32 {
    let k = regorus::Value::String(key.into());
    match obj {
        regorus::Value::Object(map) => match map.get(&k) {
            Some(regorus::Value::Number(n)) => n.as_u64().unwrap_or(default as u64) as u32,
            _ => default,
        },
        _ => default,
    }
}

impl ContentScanConfig {
    /// Parse from a regorus OPA value (the `content_policy` sub-object of an
    /// endpoint in the evaluated Rego policy).
    pub fn from_regorus(val: &regorus::Value) -> Option<Self> {
        let key = regorus::Value::String("content_policy".into());
        let cp = match val {
            regorus::Value::Object(map) => map.get(&key)?,
            _ => return None,
        };

        if !get_regorus_bool(cp, "enabled") {
            return None;
        }

        Some(ContentScanConfig {
            enabled: true,
            max_scan_bytes: get_regorus_u32(cp, "max_scan_bytes", 1_048_576),
            action: get_regorus_str(cp, "action"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_endpoint(json: &str) -> regorus::Value {
        regorus::Value::from_json_str(json).expect("valid JSON")
    }

    #[test]
    fn from_regorus_parses_action_synthesize() {
        let val = make_endpoint(r#"{"content_policy": {"enabled": true, "action": "synthesize"}}"#);
        let cfg = ContentScanConfig::from_regorus(&val).expect("should parse");
        assert_eq!(cfg.action, "synthesize");
        assert_eq!(cfg.max_scan_bytes, 1_048_576);
    }

    #[test]
    fn from_regorus_parses_action_redact() {
        let val = make_endpoint(r#"{"content_policy": {"enabled": true, "action": "redact"}}"#);
        let cfg = ContentScanConfig::from_regorus(&val).expect("should parse");
        assert_eq!(cfg.action, "redact");
    }

    #[test]
    fn from_regorus_action_missing_returns_empty() {
        let val = make_endpoint(r#"{"content_policy": {"enabled": true}}"#);
        let cfg = ContentScanConfig::from_regorus(&val).expect("should parse");
        assert_eq!(cfg.action, "");
    }

    #[test]
    fn from_regorus_disabled_returns_none() {
        let val =
            make_endpoint(r#"{"content_policy": {"enabled": false, "action": "synthesize"}}"#);
        assert!(ContentScanConfig::from_regorus(&val).is_none());
    }

    #[test]
    fn from_regorus_no_content_policy_returns_none() {
        let val = make_endpoint(r#"{"protocol": "rest"}"#);
        assert!(ContentScanConfig::from_regorus(&val).is_none());
    }

    #[test]
    fn from_regorus_max_scan_bytes_respected() {
        let val = make_endpoint(
            r#"{"content_policy": {"enabled": true, "action": "synthesize", "max_scan_bytes": 512}}"#,
        );
        let cfg = ContentScanConfig::from_regorus(&val).expect("should parse");
        assert_eq!(cfg.max_scan_bytes, 512);
    }
}
