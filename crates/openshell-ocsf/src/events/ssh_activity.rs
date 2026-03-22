// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF SSH Activity [4007] event class.

use serde::{Deserialize, Serialize};

use crate::enums::{ActionId, AuthTypeId, DispositionId};
use crate::events::base_event::BaseEventData;
use crate::objects::{Actor, Endpoint};

/// OCSF SSH Activity Event [4007].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

    /// Auth type.
    #[serde(
        rename = "auth_type_id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub auth_type: Option<AuthTypeId>,

    /// Custom auth type label (used when `auth_type` is Other).
    #[serde(rename = "auth_type", default, skip_serializing_if = "Option::is_none")]
    pub auth_type_custom_label: Option<String>,

    /// SSH protocol version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_ver: Option<String>,

    /// Action (Security Control profile).
    #[serde(rename = "action_id", default, skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionId>,

    /// Disposition.
    #[serde(
        rename = "disposition_id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub disposition: Option<DispositionId>,
}

impl Serialize for SshActivityEvent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::events::serde_helpers::{
            insert_enum_pair, insert_enum_pair_custom, insert_optional,
        };

        let mut base_val = serde_json::to_value(&self.base).map_err(serde::ser::Error::custom)?;
        let obj = base_val
            .as_object_mut()
            .ok_or_else(|| serde::ser::Error::custom("expected object"))?;

        insert_optional!(obj, "src_endpoint", self.src_endpoint);
        insert_optional!(obj, "dst_endpoint", self.dst_endpoint);
        insert_optional!(obj, "actor", self.actor);
        insert_enum_pair_custom!(
            obj,
            "auth_type",
            self.auth_type,
            self.auth_type_custom_label
        );
        insert_optional!(obj, "protocol_ver", self.protocol_ver);
        insert_enum_pair!(obj, "action", self.action);
        insert_enum_pair!(obj, "disposition", self.disposition);

        base_val.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::{ActionId, AuthTypeId, DispositionId, SeverityId};
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
            auth_type: Some(AuthTypeId::Other),
            auth_type_custom_label: Some("NSSH1".to_string()),
            protocol_ver: Some("NSSH1".to_string()),
            action: Some(ActionId::Allowed),
            disposition: Some(DispositionId::Allowed),
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["class_uid"], 4007);
        assert_eq!(json["auth_type"], "NSSH1");
        assert_eq!(json["auth_type_id"], 99);
        assert_eq!(json["protocol_ver"], "NSSH1");
    }
}
