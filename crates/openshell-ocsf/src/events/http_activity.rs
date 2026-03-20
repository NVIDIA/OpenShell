// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF HTTP Activity [4002] event class.

use serde::{Deserialize, Serialize};

use crate::enums::{ActionId, DispositionId};
use crate::events::base_event::BaseEventData;
use crate::objects::{Actor, Endpoint, FirewallRule, HttpRequest, HttpResponse};

/// OCSF HTTP Activity Event [4002].
///
/// HTTP-level events through the forward proxy and L7 relay.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

    /// Action taken (typed enum serialized as `action_id` + `action` label).
    #[serde(rename = "action_id", default, skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionId>,

    /// Disposition (typed enum serialized as `disposition_id` + `disposition` label).
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

impl Serialize for HttpActivityEvent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::events::serde_helpers::{insert_enum_pair, insert_optional};

        let mut base_val = serde_json::to_value(&self.base).map_err(serde::ser::Error::custom)?;
        let obj = base_val
            .as_object_mut()
            .ok_or_else(|| serde::ser::Error::custom("expected object"))?;

        insert_optional!(obj, "http_request", self.http_request);
        insert_optional!(obj, "http_response", self.http_response);
        insert_optional!(obj, "src_endpoint", self.src_endpoint);
        insert_optional!(obj, "dst_endpoint", self.dst_endpoint);
        insert_optional!(obj, "proxy_endpoint", self.proxy_endpoint);
        insert_optional!(obj, "actor", self.actor);
        insert_optional!(obj, "firewall_rule", self.firewall_rule);
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
            action: Some(ActionId::Allowed),
            disposition: Some(DispositionId::Allowed),
            observation_point_id: None,
            is_src_dst_assignment_known: None,
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["class_uid"], 4002);
        assert_eq!(json["type_uid"], 400_203);
        assert_eq!(json["http_request"]["http_method"], "GET");
    }
}
