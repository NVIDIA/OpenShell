// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF Device Config State Change [5019] event class.

use serde::{Deserialize, Serialize};

use crate::events::base_event::BaseEventData;

/// OCSF Device Config State Change Event [5019].
///
/// Policy engine and inference routing configuration changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceConfigStateChangeEvent {
    /// Common base event fields.
    #[serde(flatten)]
    pub base: BaseEventData,

    /// State ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_id: Option<u8>,

    /// State label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// Security level ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_level_id: Option<u8>,

    /// Security level label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_level: Option<String>,

    /// Previous security level ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_security_level_id: Option<u8>,

    /// Previous security level label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_security_level: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::{SecurityLevelId, SeverityId, StateId};
    use crate::objects::{Metadata, Product};

    #[test]
    fn test_config_state_change_serialization() {
        let mut base = BaseEventData::new(
            5019,
            "Device Config State Change",
            5,
            "Discovery",
            1,
            "Log",
            SeverityId::Informational,
            Metadata {
                version: "1.7.0".to_string(),
                product: Product::openshell_sandbox("0.1.0"),
                profiles: vec!["security_control".to_string()],
                uid: Some("sandbox-abc123".to_string()),
                log_source: None,
            },
        );
        base.set_message("Policy reloaded successfully");
        base.add_unmapped("policy_version", serde_json::json!("v3"));
        base.add_unmapped("policy_hash", serde_json::json!("sha256:abc123def456"));

        let event = DeviceConfigStateChangeEvent {
            base,
            state_id: Some(StateId::Enabled.as_u8()),
            state: Some("Enabled".to_string()),
            security_level_id: Some(SecurityLevelId::Secure.as_u8()),
            security_level: Some("Secure".to_string()),
            prev_security_level_id: Some(SecurityLevelId::Unknown.as_u8()),
            prev_security_level: Some("Unknown".to_string()),
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["class_uid"], 5019);
        assert_eq!(json["state_id"], 2);
        assert_eq!(json["state"], "Enabled");
        assert_eq!(json["security_level"], "Secure");
        assert_eq!(json["unmapped"]["policy_version"], "v3");
    }
}
