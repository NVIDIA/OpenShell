// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builder for HTTP Activity [4002] events.

use crate::builders::SandboxContext;
use crate::enums::{ActionId, ActivityId, DispositionId, SeverityId, StatusId};
use crate::events::base_event::BaseEventData;
use crate::events::{HttpActivityEvent, OcsfEvent};
use crate::objects::{Actor, Endpoint, FirewallRule, HttpRequest, HttpResponse, Process};

/// Builder for HTTP Activity [4002] events.
pub struct HttpActivityBuilder<'a> {
    ctx: &'a SandboxContext,
    activity: ActivityId,
    action: Option<ActionId>,
    disposition: Option<DispositionId>,
    severity: SeverityId,
    status: Option<StatusId>,
    http_request: Option<HttpRequest>,
    http_response: Option<HttpResponse>,
    src_endpoint: Option<Endpoint>,
    dst_endpoint: Option<Endpoint>,
    actor: Option<Actor>,
    firewall_rule: Option<FirewallRule>,
    message: Option<String>,
    status_detail: Option<String>,
}

impl<'a> HttpActivityBuilder<'a> {
    #[must_use]
    pub fn new(ctx: &'a SandboxContext) -> Self {
        Self {
            ctx,
            activity: ActivityId::Unknown,
            action: None,
            disposition: None,
            severity: SeverityId::Informational,
            status: None,
            http_request: None,
            http_response: None,
            src_endpoint: None,
            dst_endpoint: None,
            actor: None,
            firewall_rule: None,
            message: None,
            status_detail: None,
        }
    }

    #[must_use]
    pub fn activity(mut self, id: ActivityId) -> Self {
        self.activity = id;
        self
    }
    #[must_use]
    pub fn action(mut self, id: ActionId) -> Self {
        self.action = Some(id);
        self
    }
    #[must_use]
    pub fn disposition(mut self, id: DispositionId) -> Self {
        self.disposition = Some(id);
        self
    }
    #[must_use]
    pub fn severity(mut self, id: SeverityId) -> Self {
        self.severity = id;
        self
    }
    #[must_use]
    pub fn status(mut self, id: StatusId) -> Self {
        self.status = Some(id);
        self
    }
    #[must_use]
    pub fn http_request(mut self, req: HttpRequest) -> Self {
        self.http_request = Some(req);
        self
    }
    #[must_use]
    pub fn http_response(mut self, resp: HttpResponse) -> Self {
        self.http_response = Some(resp);
        self
    }
    #[must_use]
    pub fn src_endpoint(mut self, ep: Endpoint) -> Self {
        self.src_endpoint = Some(ep);
        self
    }
    #[must_use]
    pub fn dst_endpoint(mut self, ep: Endpoint) -> Self {
        self.dst_endpoint = Some(ep);
        self
    }
    #[must_use]
    pub fn actor_process(mut self, process: Process) -> Self {
        self.actor = Some(Actor { process });
        self
    }
    #[must_use]
    pub fn firewall_rule(mut self, name: &str, rule_type: &str) -> Self {
        self.firewall_rule = Some(FirewallRule::new(name, rule_type));
        self
    }
    #[must_use]
    pub fn message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }
    #[must_use]
    pub fn status_detail(mut self, detail: impl Into<String>) -> Self {
        self.status_detail = Some(detail.into());
        self
    }

    #[must_use]
    pub fn build(self) -> OcsfEvent {
        let activity_name = self.activity.http_label().to_string();
        let mut base = BaseEventData::new(
            4002,
            "HTTP Activity",
            4,
            "Network Activity",
            self.activity.as_u8(),
            &activity_name,
            self.severity,
            self.ctx
                .metadata(&["security_control", "network_proxy", "container", "host"]),
        );
        if let Some(status) = self.status {
            base.set_status(status);
        }
        if let Some(msg) = self.message {
            base.set_message(msg);
        }
        if let Some(detail) = self.status_detail {
            base.set_status_detail(detail);
        }
        base.set_device(self.ctx.device());
        base.set_container(self.ctx.container());

        OcsfEvent::HttpActivity(HttpActivityEvent {
            base,
            http_request: self.http_request,
            http_response: self.http_response,
            src_endpoint: self.src_endpoint,
            dst_endpoint: self.dst_endpoint,
            proxy_endpoint: Some(self.ctx.proxy_endpoint()),
            actor: self.actor,
            firewall_rule: self.firewall_rule,
            action: self.action,
            disposition: self.disposition,
            observation_point_id: Some(2),
            is_src_dst_assignment_known: Some(true),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builders::test_sandbox_context;
    use crate::objects::Url;

    #[test]
    fn test_http_activity_builder() {
        let ctx = test_sandbox_context();
        let event = HttpActivityBuilder::new(&ctx)
            .activity(ActivityId::Reset) // Get = 3
            .action(ActionId::Allowed)
            .disposition(DispositionId::Allowed)
            .severity(SeverityId::Informational)
            .http_request(HttpRequest::new(
                "GET",
                Url::new("https", "api.example.com", "/v1/data", 443),
            ))
            .actor_process(Process::new("curl", 88))
            .firewall_rule("default-egress", "mechanistic")
            .build();

        let json = event.to_json().unwrap();
        assert_eq!(json["class_uid"], 4002);
        assert_eq!(json["activity_name"], "Get");
        assert_eq!(json["http_request"]["http_method"], "GET");
        assert_eq!(json["actor"]["process"]["name"], "curl");
    }

    #[test]
    fn test_http_activity_builder_with_status_detail() {
        let ctx = test_sandbox_context();
        let event = HttpActivityBuilder::new(&ctx)
            .activity(ActivityId::Other)
            .action(ActionId::Denied)
            .severity(SeverityId::Medium)
            .status(StatusId::Failure)
            .http_request(HttpRequest::new(
                "PUT",
                Url::new("http", "169.254.169.254", "/latest/api/token", 80),
            ))
            .firewall_rule("aws_iam", "ssrf")
            .message("FORWARD blocked: allowed_ips check failed")
            .status_detail("resolves to always-blocked address")
            .build();

        let json = event.to_json().unwrap();
        assert_eq!(json["class_uid"], 4002);
        assert_eq!(json["status_detail"], "resolves to always-blocked address");
        assert_eq!(json["action_id"], 2); // Denied
    }
}
