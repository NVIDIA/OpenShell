// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builder for API Activity [6003] events.

use crate::builders::SandboxContext;
use crate::enums::{SeverityId, StatusId};
use crate::events::base_event::BaseEventData;
use crate::events::{ApiActivityEvent, OcsfEvent};
use crate::objects::{Actor, AiModel, Api, Endpoint, HttpRequest, Process};

const MAX_MODEL_LEN: usize = 256;

fn sanitize_model_name(name: &str) -> String {
    let truncated = if name.len() > MAX_MODEL_LEN {
        let mut end = MAX_MODEL_LEN;
        while end > 0 && !name.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &name[..end])
    } else {
        name.to_string()
    };
    truncated.replace(['\n', '\r', '\t'], " ")
}

/// Builder for API Activity [6003] events.
pub struct ApiActivityBuilder<'a> {
    ctx: &'a SandboxContext,
    severity: SeverityId,
    status: Option<StatusId>,
    message: Option<String>,
    api_operation: String,
    http_request: Option<HttpRequest>,
    dst_endpoint: Option<Endpoint>,
    ai_model: Option<AiModel>,
    unmapped: serde_json::Map<String, serde_json::Value>,
}

impl<'a> ApiActivityBuilder<'a> {
    #[must_use]
    pub fn new(ctx: &'a SandboxContext, operation: impl Into<String>) -> Self {
        Self {
            ctx,
            severity: SeverityId::Informational,
            status: None,
            message: None,
            api_operation: operation.into(),
            http_request: None,
            dst_endpoint: None,
            ai_model: None,
            unmapped: serde_json::Map::new(),
        }
    }

    #[must_use]
    pub fn severity(mut self, severity: SeverityId) -> Self {
        self.severity = severity;
        self
    }

    #[must_use]
    pub fn status(mut self, status: StatusId) -> Self {
        self.status = Some(status);
        self
    }

    #[must_use]
    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    #[must_use]
    pub fn http_request(mut self, req: HttpRequest) -> Self {
        self.http_request = Some(req);
        self
    }

    #[must_use]
    pub fn dst_endpoint(mut self, ep: Endpoint) -> Self {
        self.dst_endpoint = Some(ep);
        self
    }

    /// Attach the `ai_operation` profile with model identity.
    /// Model name and provider are sanitized (newlines stripped, length capped).
    #[must_use]
    pub fn ai_model(mut self, model: AiModel) -> Self {
        let sanitized = AiModel {
            name: sanitize_model_name(&model.name),
            ai_provider: sanitize_model_name(&model.ai_provider),
            version: model.version,
            uid: model.uid,
        };
        self.ai_model = Some(sanitized);
        self
    }

    #[must_use]
    pub fn unmapped(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.unmapped.insert(key.to_string(), value.into());
        self
    }

    #[must_use]
    pub fn build(self) -> OcsfEvent {
        let mut profiles: Vec<&str> = vec!["container", "host"];
        if self.ai_model.is_some() {
            profiles.push("ai_operation");
        }
        let mut base = BaseEventData::new(
            6003,
            "API Activity",
            6,
            "Application Activity",
            99,
            "Other",
            self.severity,
            self.ctx.metadata(&profiles),
        );
        if let Some(ai_model) = self.ai_model {
            base.set_ai_model(ai_model);
        }
        if !self.unmapped.is_empty() {
            base.unmapped = Some(serde_json::Value::Object(self.unmapped));
        }
        self.ctx
            .apply_common_fields(&mut base, self.status, self.message);

        OcsfEvent::ApiActivity(ApiActivityEvent {
            base,
            api: Api::new(&self.api_operation),
            actor: Actor {
                process: Process::new("openshell-supervisor", 1),
            },
            src_endpoint: self.ctx.proxy_endpoint(),
            http_request: self.http_request,
            http_response: None,
            dst_endpoint: self.dst_endpoint,
            action: None,
            disposition: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builders::test_sandbox_context;
    use crate::objects::Url;

    #[test]
    fn test_api_activity_builder_with_ai_model() {
        let ctx = test_sandbox_context();
        let event = ApiActivityBuilder::new(&ctx, "POST /v1/messages")
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .ai_model(AiModel::new("claude-3-haiku", "anthropic"))
            .http_request(HttpRequest::new(
                "POST",
                Url::new("https", "inference.local", "/v1/messages", 443),
            ))
            .dst_endpoint(Endpoint::from_domain("inference.local", 443))
            .unmapped("latency_ms", 701_u64)
            .unmapped("input_tokens", 12_u64)
            .message("Model call: claude-3-haiku via anthropic")
            .build();

        let json = event.to_json().unwrap();
        assert_eq!(json["class_uid"], 6003);
        assert_eq!(json["class_name"], "API Activity");
        assert_eq!(json["activity_id"], 99);
        assert_eq!(json["api"]["operation"], "POST /v1/messages");
        assert_eq!(json["actor"]["process"]["name"], "openshell-supervisor");
        assert!(json.get("src_endpoint").is_some());
        assert_eq!(json["ai_model"]["name"], "claude-3-haiku");
        assert_eq!(json["ai_model"]["ai_provider"], "anthropic");
        assert_eq!(json["http_request"]["http_method"], "POST");
        assert_eq!(json["unmapped"]["latency_ms"], 701);
        assert!(
            json["metadata"]["profiles"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p == "ai_operation")
        );
        assert!(json.get("api_operation").is_none());
    }

    #[test]
    fn test_api_activity_builder_without_ai_model() {
        let ctx = test_sandbox_context();
        let event = ApiActivityBuilder::new(&ctx, "GET /v1/models")
            .severity(SeverityId::Informational)
            .build();

        let json = event.to_json().unwrap();
        assert_eq!(json["class_uid"], 6003);
        assert!(json.get("ai_model").is_none());
        assert!(
            !json["metadata"]["profiles"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p == "ai_operation")
        );
    }

    #[test]
    fn test_model_name_sanitized() {
        let ctx = test_sandbox_context();
        let event = ApiActivityBuilder::new(&ctx, "POST /v1/messages")
            .ai_model(AiModel::new("evil\nNET:OPEN [INFO] forged", "provider"))
            .build();

        let json = event.to_json().unwrap();
        let name = json["ai_model"]["name"].as_str().unwrap();
        assert!(!name.contains('\n'));
        assert!(name.contains("evil NET:OPEN [INFO] forged"));
    }

    #[test]
    fn test_model_name_truncated() {
        let ctx = test_sandbox_context();
        let long_name = "x".repeat(500);
        let event = ApiActivityBuilder::new(&ctx, "POST /v1/messages")
            .ai_model(AiModel::new(&long_name, "provider"))
            .build();

        let json = event.to_json().unwrap();
        let name = json["ai_model"]["name"].as_str().unwrap();
        assert!(name.len() <= MAX_MODEL_LEN + 3);
        assert!(name.ends_with("..."));
    }
}
