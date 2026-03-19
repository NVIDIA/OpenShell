// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `finding_info`, `evidence`, and `remediation` objects.

use serde::{Deserialize, Serialize};

/// OCSF Finding Info object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingInfo {
    /// Unique finding identifier.
    pub uid: String,

    /// Finding title (short human-readable name).
    pub title: String,

    /// Finding description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
}

impl FindingInfo {
    /// Create a new finding info.
    #[must_use]
    pub fn new(uid: &str, title: &str) -> Self {
        Self {
            uid: uid.to_string(),
            title: title.to_string(),
            desc: None,
        }
    }

    /// Set the description.
    #[must_use]
    pub fn with_desc(mut self, desc: &str) -> Self {
        self.desc = Some(desc.to_string());
        self
    }
}

/// OCSF Evidence object — artifacts associated with a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Evidence data as key-value pairs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl Evidence {
    /// Create evidence from a map of key-value pairs.
    #[must_use]
    pub fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        let mut map = serde_json::Map::new();
        for (key, value) in pairs {
            map.insert(
                (*key).to_string(),
                serde_json::Value::String((*value).to_string()),
            );
        }
        Self {
            data: Some(serde_json::Value::Object(map)),
        }
    }
}

/// OCSF Remediation object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Remediation {
    /// Remediation description / guidance.
    pub desc: String,
}

impl Remediation {
    /// Create a new remediation.
    #[must_use]
    pub fn new(desc: &str) -> Self {
        Self {
            desc: desc.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finding_info_creation() {
        let info = FindingInfo::new("nssh1-replay-abc", "NSSH1 Nonce Replay Attack")
            .with_desc("A nonce was replayed.");
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["uid"], "nssh1-replay-abc");
        assert_eq!(json["title"], "NSSH1 Nonce Replay Attack");
        assert_eq!(json["desc"], "A nonce was replayed.");
    }

    #[test]
    fn test_evidence_from_pairs() {
        let evidence = Evidence::from_pairs(&[("nonce", "0xdeadbeef"), ("peer_ip", "10.42.0.1")]);
        let json = serde_json::to_value(&evidence).unwrap();
        assert_eq!(json["data"]["nonce"], "0xdeadbeef");
        assert_eq!(json["data"]["peer_ip"], "10.42.0.1");
    }

    #[test]
    fn test_remediation() {
        let rem = Remediation::new("Set NODE_USE_ENV_PROXY=1");
        let json = serde_json::to_value(&rem).unwrap();
        assert_eq!(json["desc"], "Set NODE_USE_ENV_PROXY=1");
    }
}
