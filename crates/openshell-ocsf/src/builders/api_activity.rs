// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builder for API Activity [6003] events.

use crate::builders::{EventContext, EventOrigin};
use crate::enums::{ActionId, DispositionId, SeverityId, StatusId};
use crate::events::base_event::BaseEventData;
use crate::events::{ApiActivityEvent, OcsfEvent};
use crate::objects::{
    Actor, AiModel, Api, Endpoint, HttpRequest, Process, ResourceDetails, Service, User,
};

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
    ctx: &'a EventContext,
    severity: SeverityId,
    status: Option<StatusId>,
    message: Option<String>,
    api_operation: String,
    api_service: Option<Service>,
    actor: Option<Actor>,
    src_endpoint: Option<Endpoint>,
    action: Option<ActionId>,
    disposition: Option<DispositionId>,
    status_detail: Option<String>,
    correlation_uid: Option<String>,
    http_request: Option<HttpRequest>,
    dst_endpoint: Option<Endpoint>,
    resources: Vec<ResourceDetails>,
    ai_model: Option<AiModel>,
    unmapped: serde_json::Map<String, serde_json::Value>,
}

impl<'a> ApiActivityBuilder<'a> {
    #[must_use]
    pub fn new(ctx: &'a EventContext, operation: impl Into<String>) -> Self {
        Self {
            ctx,
            severity: SeverityId::Informational,
            status: None,
            message: None,
            api_operation: operation.into(),
            api_service: None,
            actor: None,
            src_endpoint: None,
            action: None,
            disposition: None,
            status_detail: None,
            correlation_uid: None,
            http_request: None,
            dst_endpoint: None,
            resources: Vec::new(),
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

    /// Set the service that exposes the operation.
    #[must_use]
    pub fn api_service(mut self, service: Service) -> Self {
        self.api_service = Some(service);
        self
    }

    /// Set the authenticated principal that made the call. Without one, the
    /// actor is the supervisor process.
    #[must_use]
    pub fn actor_user(mut self, user: User) -> Self {
        self.actor = Some(Actor::user(user));
        self
    }

    /// Set the caller's endpoint. Without one, the source is the proxy
    /// endpoint.
    #[must_use]
    pub fn src_endpoint(mut self, endpoint: Endpoint) -> Self {
        self.src_endpoint = Some(endpoint);
        self
    }

    #[must_use]
    pub fn status_detail(mut self, detail: impl Into<String>) -> Self {
        self.status_detail = Some(detail.into());
        self
    }

    /// Set the identifier shared by events about the same request.
    #[must_use]
    pub fn correlation_uid(mut self, uid: impl Into<String>) -> Self {
        self.correlation_uid = Some(uid.into());
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

    /// Add a resource the call acted on.
    #[must_use]
    pub fn resource(mut self, resource: ResourceDetails) -> Self {
        self.resources.push(resource);
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
        // Gateway events carry a container only when they concern a sandbox.
        let mut profiles: Vec<&str> = match self.ctx.origin {
            EventOrigin::Gateway { .. } if self.ctx.container().is_none() => vec!["host"],
            _ => vec!["container", "host"],
        };
        if self.action.is_some() {
            profiles.push("security_control");
        }
        if self.ai_model.is_some() {
            profiles.push("ai_operation");
        }
        let mut metadata = self.ctx.metadata(&profiles);
        metadata.correlation_uid = self.correlation_uid;
        let mut base = BaseEventData::new(
            6003,
            "API Activity",
            6,
            "Application Activity",
            99,
            "Other",
            self.severity,
            metadata,
        );
        if let Some(detail) = self.status_detail {
            base.set_status_detail(detail);
        }
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
            api: Api {
                service: self.api_service,
                ..Api::new(&self.api_operation)
            },
            actor: self
                .actor
                .unwrap_or_else(|| Actor::process(Process::new("openshell-supervisor", 1))),
            src_endpoint: self
                .src_endpoint
                .unwrap_or_else(|| self.ctx.proxy_endpoint()),
            http_request: self.http_request,
            http_response: None,
            dst_endpoint: self.dst_endpoint,
            resources: (!self.resources.is_empty()).then_some(self.resources),
            action: self.action,
            disposition: self.disposition,
        })
    }
}

impl_action_disposition_setters!(ApiActivityBuilder);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builders::{test_gateway_context, test_sandbox_context};
    use crate::enums::{HttpMethod, UserTypeId};
    use crate::objects::Url;
    use crate::validation::schema::{
        load_class_schema, load_object_schema, validate_enum_value, validate_known_fields,
        validate_required_fields,
    };

    fn gateway_denial() -> serde_json::Value {
        let ctx = test_gateway_context();
        ApiActivityBuilder::new(&ctx, "GetSandbox")
            .api_service(Service::new("openshell.v1.OpenShell"))
            .actor_user(User::other("sb-7f3a", "Sandbox"))
            .src_endpoint(Endpoint::from_ip_str("10.42.0.7", 51234))
            .action(ActionId::Denied)
            .disposition(DispositionId::Blocked)
            .severity(SeverityId::Medium)
            .status(StatusId::Failure)
            .status_detail("cross_sandbox")
            .resource(ResourceDetails::new("sandbox", "sb-9c41"))
            .correlation_uid("6f1c2d3e-4b5a-4c6d-8e7f-9a0b1c2d3e4f")
            .http_request(HttpRequest {
                http_method: HttpMethod::Post,
                url: Some(Url::from_path("/openshell.v1.OpenShell/GetSandbox")),
            })
            .message("authorization denied: cross_sandbox")
            .build()
            .to_json()
            .unwrap()
    }

    #[test]
    fn gateway_denial_matches_vendored_schema() {
        let json = gateway_denial();

        let class = load_class_schema("api_activity");
        validate_required_fields(&json, &class);
        validate_known_fields(&json, &class);
        for field in [
            "activity_id",
            "action_id",
            "disposition_id",
            "severity_id",
            "status_id",
        ] {
            validate_enum_value(&json, field, &class);
        }

        let actor = load_object_schema("actor");
        validate_required_fields(&json["actor"], &actor);
        validate_known_fields(&json["actor"], &actor);
        let user = load_object_schema("user");
        validate_required_fields(&json["actor"]["user"], &user);
        validate_known_fields(&json["actor"]["user"], &user);

        let api = load_object_schema("api");
        validate_required_fields(&json["api"], &api);
        validate_known_fields(&json["api"], &api);
        let service = load_object_schema("service");
        validate_required_fields(&json["api"]["service"], &service);

        let resource = load_object_schema("resource_details");
        validate_required_fields(&json["resources"][0], &resource);
        validate_known_fields(&json["resources"][0], &resource);

        let metadata = load_object_schema("metadata");
        validate_required_fields(&json["metadata"], &metadata);
        validate_known_fields(&json["metadata"], &metadata);
    }

    #[test]
    fn gateway_denial_records_the_principal_and_outcome() {
        let json = gateway_denial();

        assert_eq!(json["class_uid"], 6003);
        assert_eq!(json["activity_id"], 99);
        assert_eq!(
            json["actor"],
            serde_json::json!({"user": {"uid": "sb-7f3a", "type_id": 99, "type": "Sandbox"}})
        );
        assert_eq!(
            json["api"],
            serde_json::json!({
                "operation": "GetSandbox",
                "service": {"name": "openshell.v1.OpenShell"}
            })
        );
        assert_eq!(
            json["resources"],
            serde_json::json!([{"uid": "sb-9c41", "type": "sandbox"}])
        );
        assert_eq!(json["src_endpoint"]["ip"], "10.42.0.7");
        assert_eq!(json["action_id"], 2);
        assert_eq!(json["disposition_id"], 2);
        assert_eq!(json["status_id"], 2);
        assert_eq!(json["status_detail"], "cross_sandbox");
        assert_eq!(
            json["metadata"]["correlation_uid"],
            "6f1c2d3e-4b5a-4c6d-8e7f-9a0b1c2d3e4f"
        );
        assert_eq!(
            json["metadata"]["profiles"],
            serde_json::json!(["host", "security_control"])
        );
        assert!(json.get("container").is_none());
    }

    #[test]
    fn gateway_denial_shorthand_names_principal_operation_and_reason() {
        let ctx = test_gateway_context();
        let event = ApiActivityBuilder::new(&ctx, "GetSandbox")
            .actor_user(User::new("alice@example.com", UserTypeId::User))
            .src_endpoint(Endpoint::from_ip_str("203.0.113.7", 443))
            .action(ActionId::Denied)
            .severity(SeverityId::Medium)
            .status_detail("not_workspace_member")
            .resource(ResourceDetails::named("workspace", "team a]"))
            .http_request(HttpRequest {
                http_method: HttpMethod::Post,
                url: Some(Url::from_path("/openshell.v1.OpenShell/GetSandbox")),
            })
            .build();

        assert_eq!(
            event.format_shorthand(),
            "API:OTHER [MED] DENIED user:alice@example.com from 203.0.113.7:443 \
             [op:/openshell.v1.OpenShell/GetSandbox workspace:team\\u{20}a\\] reason:not_workspace_member]"
        );
    }

    #[test]
    fn test_api_activity_builder_with_ai_model() {
        let ctx = test_sandbox_context();
        let event = ApiActivityBuilder::new(&ctx, "POST /v1/messages")
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .ai_model(AiModel::new("claude-3-haiku", "anthropic"))
            .http_request(HttpRequest::new(
                "POST",
                Url::new("https", "api.anthropic.com", "/v1/messages", 443),
            ))
            .dst_endpoint(Endpoint::from_domain("api.anthropic.com", 443))
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
