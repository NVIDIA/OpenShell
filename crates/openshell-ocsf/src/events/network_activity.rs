// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF Network Activity [4001] event class.

use serde::{Deserialize, Serialize};

use crate::events::base_event::BaseEventData;
use crate::objects::{Actor, ConnectionInfo, Endpoint, FirewallRule};

/// OCSF Network Activity Event [4001].
///
/// Proxy CONNECT tunnel events and iptables-level bypass detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    /// Action ID (Security Control profile).
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

    /// Observation point ID (v1.6.0+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation_point_id: Option<u8>,

    /// Whether src/dst assignment is known (v1.6.0+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_src_dst_assignment_known: Option<bool>,
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
            action_id: Some(ActionId::Allowed.as_u8()),
            action: Some(ActionId::Allowed.label().to_string()),
            disposition_id: Some(DispositionId::Allowed.as_u8()),
            disposition: Some(DispositionId::Allowed.label().to_string()),
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
