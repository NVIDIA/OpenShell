// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builder for Authentication [3002] events.

use crate::builders::EventContext;
use crate::enums::{ActionId, AuthProtocolId, DispositionId, SeverityId, StatusId};
use crate::events::base_event::BaseEventData;
use crate::events::{AuthenticationEvent, OcsfEvent};
use crate::objects::{Endpoint, HttpRequest, Service, User};

/// Builder for Authentication [3002] Logon events.
pub struct AuthenticationBuilder<'a> {
    ctx: &'a EventContext,
    trace: Option<crate::TraceCorrelation>,
    user: User,
    service: Service,
    auth_protocol: Option<AuthProtocolId>,
    auth_protocol_label: Option<String>,
    action: Option<ActionId>,
    disposition: Option<DispositionId>,
    severity: SeverityId,
    status: Option<StatusId>,
    status_detail: Option<String>,
    src_endpoint: Option<Endpoint>,
    http_request: Option<HttpRequest>,
    correlation_uid: Option<String>,
    message: Option<String>,
}

impl<'a> AuthenticationBuilder<'a> {
    /// Set trace correlation explicitly instead of using the active span.
    #[must_use]
    pub fn trace(mut self, trace: crate::TraceCorrelation) -> Self {
        self.trace = Some(trace);
        self
    }

    #[must_use]
    pub fn new(ctx: &'a EventContext, user: User, service: Service) -> Self {
        Self {
            ctx,
            trace: None,
            user,
            service,
            auth_protocol: None,
            auth_protocol_label: None,
            action: None,
            disposition: None,
            severity: SeverityId::Informational,
            status: None,
            status_detail: None,
            src_endpoint: None,
            http_request: None,
            correlation_uid: None,
            message: None,
        }
    }

    /// Set a schema-defined authentication protocol.
    #[must_use]
    pub fn auth_protocol(mut self, id: AuthProtocolId) -> Self {
        self.auth_protocol = Some(id);
        self.auth_protocol_label = None;
        self
    }

    /// Set a protocol with no schema equivalent, recorded as Other.
    #[must_use]
    pub fn auth_protocol_other(mut self, label: impl Into<String>) -> Self {
        self.auth_protocol = Some(AuthProtocolId::Other);
        self.auth_protocol_label = Some(label.into());
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
    pub fn src_endpoint(mut self, endpoint: Endpoint) -> Self {
        self.src_endpoint = Some(endpoint);
        self
    }

    /// Set the request the credential was presented with.
    #[must_use]
    pub fn http_request(mut self, request: HttpRequest) -> Self {
        self.http_request = Some(request);
        self
    }

    #[must_use]
    pub fn build(self) -> OcsfEvent {
        let mut metadata = self.ctx.metadata(&["security_control", "host"]);
        metadata.correlation_uid = self.correlation_uid;
        let mut base = BaseEventData::new(
            3002,
            "Authentication",
            3,
            "Identity & Access Management",
            1,
            "Logon",
            self.severity,
            metadata,
        );
        if let Some(status) = self.status {
            base.set_status(status);
        }
        if let Some(detail) = self.status_detail {
            base.set_status_detail(detail);
        }
        if let Some(message) = self.message {
            base.set_message(message);
        }
        // Not `apply_common_fields`: the container profile defines `container`
        // on endpoints and processes, never at the event top level.
        base.set_device(self.ctx.device());
        if let Some(trace) = self.trace {
            base.set_trace(trace);
        }

        OcsfEvent::Authentication(AuthenticationEvent {
            base,
            user: self.user,
            auth_protocol: self.auth_protocol,
            auth_protocol_label: self.auth_protocol_label,
            service: self.service,
            src_endpoint: self.src_endpoint,
            http_request: self.http_request,
            action: self.action,
            disposition: self.disposition,
        })
    }
}

impl_action_disposition_setters!(AuthenticationBuilder);
impl_builder_setters!(AuthenticationBuilder);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builders::test_sandbox_context;
    use crate::enums::{HttpMethod, UserTypeId};
    use crate::objects::Url;
    use crate::validation::schema::{
        load_class_schema, load_object_schema, validate_enum_value, validate_known_fields,
        validate_required_fields,
    };

    fn gateway_failure() -> serde_json::Value {
        let ctx = test_sandbox_context();
        AuthenticationBuilder::new(
            &ctx,
            User::unidentified(),
            Service::new("openshell-gateway"),
        )
        .auth_protocol(AuthProtocolId::OpenId)
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(SeverityId::Medium)
        .status(StatusId::Failure)
        .status_detail("expired_credential")
        .src_endpoint(Endpoint::from_ip_str("203.0.113.7", 51234))
        .http_request(HttpRequest {
            http_method: HttpMethod::Post,
            url: Some(Url::from_path("/openshell.v1.OpenShell/ListSandboxes")),
        })
        .message("authentication failed")
        .build()
        .to_json()
        .unwrap()
    }

    #[test]
    fn failure_event_matches_vendored_schema() {
        let json = gateway_failure();

        let class = load_class_schema("authentication");
        validate_required_fields(&json, &class);
        validate_known_fields(&json, &class);
        for field in [
            "activity_id",
            "action_id",
            "auth_protocol_id",
            "disposition_id",
            "severity_id",
            "status_id",
        ] {
            validate_enum_value(&json, field, &class);
        }

        let user = load_object_schema("user");
        validate_required_fields(&json["user"], &user);
        validate_known_fields(&json["user"], &user);
        validate_enum_value(&json["user"], "type_id", &user);

        let service = load_object_schema("service");
        validate_required_fields(&json["service"], &service);
        validate_known_fields(&json["service"], &service);

        let endpoint = load_object_schema("network_endpoint");
        validate_required_fields(&json["src_endpoint"], &endpoint);

        let url = load_object_schema("url");
        validate_required_fields(&json["http_request"]["url"], &url);
        validate_known_fields(&json["http_request"]["url"], &url);
    }

    #[test]
    fn failure_event_carries_outcome_fields() {
        let json = gateway_failure();

        assert_eq!(json["class_uid"], 3002);
        assert_eq!(json["class_name"], "Authentication");
        assert_eq!(json["category_uid"], 3);
        assert_eq!(json["category_name"], "Identity & Access Management");
        assert_eq!(json["activity_id"], 1);
        assert_eq!(json["activity_name"], "Logon");
        assert_eq!(json["type_uid"], 300_201);
        assert_eq!(json["auth_protocol_id"], 4);
        assert_eq!(json["auth_protocol"], "OpenID");
        assert_eq!(json["action_id"], 2);
        assert_eq!(json["disposition_id"], 2);
        assert_eq!(json["status_id"], 2);
        assert_eq!(json["status_detail"], "expired_credential");
        assert_eq!(json["service"]["name"], "openshell-gateway");
        assert_eq!(json["src_endpoint"]["ip"], "203.0.113.7");
        assert_eq!(
            json["http_request"],
            serde_json::json!({
                "http_method": "POST",
                "url": {"path": "/openshell.v1.OpenShell/ListSandboxes"}
            })
        );
        assert_eq!(
            json["metadata"]["profiles"],
            serde_json::json!(["security_control", "host"])
        );
        assert!(json.get("container").is_none());
        assert!(json["metadata"].get("correlation_uid").is_none());
    }

    #[test]
    fn correlated_event_from_a_named_source_matches_vendored_schema() {
        let ctx = test_sandbox_context();
        let json = AuthenticationBuilder::new(
            &ctx,
            User::unidentified(),
            Service::new("openshell-gateway"),
        )
        .src_endpoint(Endpoint::from_name("edge-tunnel"))
        .correlation_uid("6f1c2d3e-4b5a-4c6d-8e7f-9a0b1c2d3e4f")
        .build()
        .to_json()
        .unwrap();

        let endpoint = load_object_schema("network_endpoint");
        validate_known_fields(&json["src_endpoint"], &endpoint);
        let metadata = load_object_schema("metadata");
        validate_required_fields(&json["metadata"], &metadata);
        validate_known_fields(&json["metadata"], &metadata);
        assert_eq!(
            json["src_endpoint"],
            serde_json::json!({"name": "edge-tunnel"})
        );
        assert_eq!(
            json["metadata"]["correlation_uid"],
            "6f1c2d3e-4b5a-4c6d-8e7f-9a0b1c2d3e4f"
        );
    }

    #[test]
    fn unidentified_user_is_a_named_placeholder() {
        let json = gateway_failure();

        assert_eq!(
            json["user"],
            serde_json::json!({"name": "unknown", "type_id": 0, "type": "Unknown"})
        );
    }

    #[test]
    fn custom_protocol_uses_other_with_label() {
        let ctx = test_sandbox_context();
        let json = AuthenticationBuilder::new(
            &ctx,
            User::other("sb-7f3a", "Sandbox"),
            Service::new("openshell-gateway"),
        )
        .auth_protocol_other("sandbox_jwt")
        .build()
        .to_json()
        .unwrap();

        assert_eq!(json["auth_protocol_id"], 99);
        assert_eq!(json["auth_protocol"], "sandbox_jwt");
        assert_eq!(
            json["user"],
            serde_json::json!({"uid": "sb-7f3a", "type_id": 99, "type": "Sandbox"})
        );
    }

    #[test]
    fn known_user_type_uses_schema_caption() {
        let ctx = test_sandbox_context();
        let json = AuthenticationBuilder::new(
            &ctx,
            User::new("alice@example.com", UserTypeId::User),
            Service::new("openshell-gateway"),
        )
        .build()
        .to_json()
        .unwrap();

        assert_eq!(
            json["user"],
            serde_json::json!({"uid": "alice@example.com", "type_id": 1, "type": "User"})
        );
        assert!(json.get("auth_protocol_id").is_none());
    }
}
