// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF SSH Activity [4007] event class.

use serde::{Deserialize, Serialize};

use crate::events::base_event::BaseEventData;
use crate::objects::{Actor, Endpoint};

/// OCSF SSH Activity Event [4007].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshActivityEvent {
    /// Common base event fields.
    #[serde(flatten)]
    pub base: BaseEventData,

    /// Source endpoint (connecting peer).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_endpoint: Option<Endpoint>,

    /// Destination endpoint (SSH server).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_endpoint: Option<Endpoint>,

    /// Actor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<Actor>,

    /// Auth type ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_type_id: Option<u8>,

    /// Auth type label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_type: Option<String>,

    /// SSH protocol version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_ver: Option<String>,

    /// Action ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_id: Option<u8>,

    /// Action label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,

    /// Disposition ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition_id: Option<u8>,

    /// Disposition label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::{AuthTypeId, SeverityId};
    use crate::objects::{Metadata, Product};

    #[test]
    fn test_ssh_activity_serialization() {
        let event = SshActivityEvent {
            base: BaseEventData::new(
                4007,
                "SSH Activity",
                4,
                "Network Activity",
                1,
                "Open",
                SeverityId::Informational,
                Metadata {
                    version: "1.7.0".to_string(),
                    product: Product::openshell_sandbox("0.1.0"),
                    profiles: vec!["security_control".to_string()],
                    uid: Some("sandbox-abc123".to_string()),
                    log_source: None,
                },
            ),
            src_endpoint: Some(Endpoint::from_ip_str("10.42.0.1", 48201)),
            dst_endpoint: Some(Endpoint::from_ip_str("10.42.0.2", 2222)),
            actor: None,
            auth_type_id: Some(AuthTypeId::Other.as_u8()),
            auth_type: Some("NSSH1".to_string()),
            protocol_ver: Some("NSSH1".to_string()),
            action_id: Some(1),
            action: Some("Allowed".to_string()),
            disposition_id: Some(1),
            disposition: Some("Allowed".to_string()),
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["class_uid"], 4007);
        assert_eq!(json["auth_type"], "NSSH1");
        assert_eq!(json["auth_type_id"], 99);
        assert_eq!(json["protocol_ver"], "NSSH1");
    }
}
