// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF HTTP Activity [4002] event class.

use serde::{Deserialize, Serialize};

use crate::events::base_event::BaseEventData;
use crate::objects::{Actor, Endpoint, FirewallRule, HttpRequest, HttpResponse};

/// OCSF HTTP Activity Event [4002].
///
/// HTTP-level events through the forward proxy and L7 relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpActivityEvent {
    /// Common base event fields.
    #[serde(flatten)]
    pub base: BaseEventData,

    /// HTTP request details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_request: Option<HttpRequest>,

    /// HTTP response details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_response: Option<HttpResponse>,

    /// Source endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_endpoint: Option<Endpoint>,

    /// Destination endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_endpoint: Option<Endpoint>,

    /// Proxy endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_endpoint: Option<Endpoint>,

    /// Actor (process that made the request).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<Actor>,

    /// Firewall / policy rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall_rule: Option<FirewallRule>,

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
    use crate::enums::SeverityId;
    use crate::objects::{Metadata, Product, Url};

    #[test]
    fn test_http_activity_serialization() {
        let event = HttpActivityEvent {
            base: BaseEventData::new(
                4002,
                "HTTP Activity",
                4,
                "Network Activity",
                3,
                "Get",
                SeverityId::Informational,
                Metadata {
                    version: "1.7.0".to_string(),
                    product: Product::openshell_sandbox("0.1.0"),
                    profiles: vec!["security_control".to_string()],
                    uid: Some("sandbox-abc123".to_string()),
                    log_source: None,
                },
            ),
            http_request: Some(HttpRequest::new(
                "GET",
                Url::new("https", "api.example.com", "/v1/data", 443),
            )),
            http_response: None,
            src_endpoint: None,
            dst_endpoint: Some(Endpoint::from_domain("api.example.com", 443)),
            proxy_endpoint: None,
            actor: None,
            firewall_rule: None,
            action_id: Some(1),
            action: Some("Allowed".to_string()),
            disposition_id: Some(1),
            disposition: Some("Allowed".to_string()),
            observation_point_id: None,
            is_src_dst_assignment_known: None,
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["class_uid"], 4002);
        assert_eq!(json["type_uid"], 400_203);
        assert_eq!(json["http_request"]["http_method"], "GET");
    }
}
