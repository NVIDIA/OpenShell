// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF Network Activity [4001] event class.

use serde::{Deserialize, Serialize};

use crate::enums::{ActionId, DispositionId};
use crate::events::base_event::BaseEventData;
use crate::objects::{Actor, ConnectionInfo, Endpoint, FirewallRule};

/// OCSF Network Activity Event [4001].
///
/// Proxy CONNECT tunnel events and iptables-level bypass detection.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct NetworkActivityEvent {
    /// Common base event fields.
    #[serde(flatten)]
    pub base: BaseEventData,

    /// Source endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_endpoint: Option<Endpoint>,

    /// Destination endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_endpoint: Option<Endpoint>,

    /// Proxy endpoint (Network Proxy profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_endpoint: Option<Endpoint>,

    /// Actor (process that initiated the connection).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<Actor>,

    /// Firewall / policy rule that applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall_rule: Option<FirewallRule>,

    /// Connection info (protocol name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_info: Option<ConnectionInfo>,

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

    /// Observation point ID (v1.6.0+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation_point_id: Option<u8>,

    /// Whether src/dst assignment is known (v1.6.0+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_src_dst_assignment_known: Option<bool>,
}

impl Serialize for NetworkActivityEvent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::events::serde_helpers::{insert_enum_pair, insert_optional};

        let mut base_val = serde_json::to_value(&self.base).map_err(serde::ser::Error::custom)?;
        let obj = base_val
            .as_object_mut()
            .ok_or_else(|| serde::ser::Error::custom("expected object"))?;

        insert_optional!(obj, "src_endpoint", self.src_endpoint);
        insert_optional!(obj, "dst_endpoint", self.dst_endpoint);
        insert_optional!(obj, "proxy_endpoint", self.proxy_endpoint);
        insert_optional!(obj, "actor", self.actor);
        insert_optional!(obj, "firewall_rule", self.firewall_rule);
        insert_optional!(obj, "connection_info", self.connection_info);
        insert_enum_pair!(obj, "action", self.action);
        insert_enum_pair!(obj, "disposition", self.disposition);
        insert_optional!(obj, "observation_point_id", self.observation_point_id);
        insert_optional!(
            obj,
            "is_src_dst_assignment_known",
            self.is_src_dst_assignment_known
        );

        base_val.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::{ActionId, DispositionId, SeverityId};
    use crate::objects::{Metadata, Product};

    #[test]
    fn test_network_activity_serialization() {
        let event = NetworkActivityEvent {
            base: BaseEventData::new(
                4001,
                "Network Activity",
                4,
                "Network Activity",
                1,
                "Open",
                SeverityId::Informational,
                Metadata {
                    version: "1.7.0".to_string(),
                    product: Product::openshell_sandbox("0.1.0"),
                    profiles: vec!["security_control".to_string(), "network_proxy".to_string()],
                    uid: Some("sandbox-abc123".to_string()),
                    log_source: None,
                },
            ),
            src_endpoint: Some(Endpoint::from_ip_str("10.42.0.2", 54321)),
            dst_endpoint: Some(Endpoint::from_domain("api.example.com", 443)),
            proxy_endpoint: Some(Endpoint::from_ip_str("10.42.0.1", 3128)),
            actor: None,
            firewall_rule: Some(FirewallRule::new("default-egress", "mechanistic")),
            connection_info: None,
            action: Some(ActionId::Allowed),
            disposition: Some(DispositionId::Allowed),
            observation_point_id: Some(2),
            is_src_dst_assignment_known: Some(true),
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["class_uid"], 4001);
        assert_eq!(json["class_name"], "Network Activity");
        assert_eq!(json["type_uid"], 400_101);
        assert_eq!(json["action"], "Allowed");
        assert_eq!(json["disposition"], "Allowed");
        assert_eq!(json["dst_endpoint"]["domain"], "api.example.com");
        assert_eq!(json["firewall_rule"]["type"], "mechanistic");
        assert_eq!(json["observation_point_id"], 2);
        assert_eq!(json["is_src_dst_assignment_known"], true);
    }
}
