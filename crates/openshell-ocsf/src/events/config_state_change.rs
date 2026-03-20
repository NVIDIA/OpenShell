// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF Device Config State Change [5019] event class.

use serde::{Deserialize, Serialize};

use crate::enums::{SecurityLevelId, StateId};
use crate::events::base_event::BaseEventData;

/// OCSF Device Config State Change Event [5019].
///
/// Policy engine and inference routing configuration changes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DeviceConfigStateChangeEvent {
    /// Common base event fields.
    #[serde(flatten)]
    pub base: BaseEventData,

    #[serde(rename = "state_id", default, skip_serializing_if = "Option::is_none")]
    pub state: Option<StateId>,

    /// Custom state label (used when `state_id` maps to a non-standard label).
    #[serde(rename = "state", default, skip_serializing_if = "Option::is_none")]
    pub state_custom_label: Option<String>,

    #[serde(
        rename = "security_level_id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub security_level: Option<SecurityLevelId>,

    #[serde(
        rename = "prev_security_level_id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub prev_security_level: Option<SecurityLevelId>,
}

impl Serialize for DeviceConfigStateChangeEvent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::events::serde_helpers::{insert_enum_pair, insert_enum_pair_custom};

        let mut base_val = serde_json::to_value(&self.base).map_err(serde::ser::Error::custom)?;
        let obj = base_val
            .as_object_mut()
            .ok_or_else(|| serde::ser::Error::custom("expected object"))?;

        insert_enum_pair_custom!(obj, "state", self.state, self.state_custom_label);
        insert_enum_pair!(obj, "security_level", self.security_level);
        insert_enum_pair!(obj, "prev_security_level", self.prev_security_level);

        base_val.serialize(serializer)
    }
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
            state: Some(StateId::Enabled),
            state_custom_label: None,
            security_level: Some(SecurityLevelId::Secure),
            prev_security_level: Some(SecurityLevelId::Unknown),
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["class_uid"], 5019);
        assert_eq!(json["state_id"], 2);
        assert_eq!(json["state"], "Enabled");
        assert_eq!(json["security_level"], "Secure");
        assert_eq!(json["unmapped"]["policy_version"], "v3");
    }
}
