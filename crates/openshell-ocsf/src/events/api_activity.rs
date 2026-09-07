// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF API Activity [6003] event class.

use serde::Deserialize;

use super::base_event::BaseEventData;
use crate::enums::{ActionId, DispositionId};
use crate::objects::{Actor, Api, Endpoint, HttpRequest, HttpResponse};

/// API Activity event (`class_uid` 6003).
///
/// Represents an API call, such as an inference request to a model provider.
/// Supports the `ai_operation` profile in OCSF v1.8.0+.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ApiActivityEvent {
    /// Common base event fields.
    #[serde(flatten)]
    pub base: BaseEventData,

    /// The API object (required: contains `operation`).
    pub api: Api,

    /// Actor (process making the API call, required).
    pub actor: Actor,

    /// Source endpoint (caller, required).
    pub src_endpoint: Endpoint,

    /// HTTP request details.
    #[serde(default)]
    pub http_request: Option<HttpRequest>,

    /// HTTP response details.
    #[serde(default)]
    pub http_response: Option<HttpResponse>,

    /// Destination endpoint (API provider).
    #[serde(default)]
    pub dst_endpoint: Option<Endpoint>,

    /// Action taken (allowed, denied, etc.).
    #[serde(default)]
    pub action: Option<ActionId>,

    /// Disposition.
    #[serde(default)]
    pub disposition: Option<DispositionId>,
}

impl serde::Serialize for ApiActivityEvent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::events::serde_helpers::{insert_enum_pair, insert_optional};

        let mut base_val = serde_json::to_value(&self.base).map_err(serde::ser::Error::custom)?;
        let obj = base_val
            .as_object_mut()
            .ok_or_else(|| serde::ser::Error::custom("expected object"))?;

        obj.insert(
            "api".to_string(),
            serde_json::to_value(&self.api).map_err(serde::ser::Error::custom)?,
        );
        obj.insert(
            "actor".to_string(),
            serde_json::to_value(&self.actor).map_err(serde::ser::Error::custom)?,
        );
        obj.insert(
            "src_endpoint".to_string(),
            serde_json::to_value(&self.src_endpoint).map_err(serde::ser::Error::custom)?,
        );
        insert_optional!(obj, "http_request", self.http_request);
        insert_optional!(obj, "http_response", self.http_response);
        insert_optional!(obj, "dst_endpoint", self.dst_endpoint);
        insert_enum_pair!(obj, "action", self.action);
        insert_enum_pair!(obj, "disposition", self.disposition);

        base_val.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::SeverityId;
    use crate::objects::{AiModel, Metadata, Process, Product};

    fn test_api_activity() -> ApiActivityEvent {
        let mut base = BaseEventData::new(
            6003,
            "API Activity",
            6,
            "Application Activity",
            99,
            "Other",
            SeverityId::Informational,
            Metadata {
                version: "1.8.0".to_string(),
                product: Product::openshell_sandbox("0.1.0"),
                profiles: vec!["ai_operation".to_string()],
                uid: None,
                log_source: None,
            },
        );
        base.set_ai_model(AiModel::new("claude-3-haiku", "anthropic"));
        ApiActivityEvent {
            base,
            api: Api::new("POST /v1/messages"),
            actor: Actor {
                process: Process::new("supervisor", 1),
            },
            src_endpoint: Endpoint::from_domain("inference.local", 443),
            http_request: None,
            http_response: None,
            dst_endpoint: None,
            action: None,
            disposition: None,
        }
    }

    #[test]
    fn test_api_activity_serialization() {
        let event = test_api_activity();
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["class_uid"], 6003);
        assert_eq!(json["class_name"], "API Activity");
        assert_eq!(json["activity_id"], 99);
        assert_eq!(json["api"]["operation"], "POST /v1/messages");
        assert_eq!(json["actor"]["process"]["name"], "supervisor");
        assert_eq!(json["src_endpoint"]["domain"], "inference.local");
        assert_eq!(json["ai_model"]["name"], "claude-3-haiku");
    }

    #[test]
    fn test_api_activity_roundtrip() {
        let event = test_api_activity();
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ApiActivityEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.base.class_uid, 6003);
        assert_eq!(deserialized.api.operation, "POST /v1/messages");
        assert!(deserialized.base.ai_model.is_some());
    }
}
