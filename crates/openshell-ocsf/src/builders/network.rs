// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builder for Network Activity [4001] events.

use crate::builders::EventContext;
use crate::enums::{ActionId, ActivityId, DispositionId, SeverityId, StatusId};
use crate::events::base_event::BaseEventData;
use crate::events::{NetworkActivityEvent, OcsfEvent};
use crate::objects::{Actor, ConnectionInfo, Endpoint, FirewallRule};

/// Builder for Network Activity [4001] events.
pub struct NetworkActivityBuilder<'a, EndpointState = MissingNetworkEndpoint> {
    ctx: &'a EventContext,
    activity: ActivityId,
    activity_name: Option<String>,
    action: Option<ActionId>,
    disposition: Option<DispositionId>,
    severity: SeverityId,
    status: Option<StatusId>,
    src_endpoint: Option<Endpoint>,
    dst_endpoint: Option<Endpoint>,
    actor: Option<Actor>,
    firewall_rule: Option<FirewallRule>,
    connection_info: Option<ConnectionInfo>,
    observation_point_id: Option<u8>,
    message: Option<String>,
    status_detail: Option<String>,
    unmapped: Option<serde_json::Map<String, serde_json::Value>>,
    log_source: Option<String>,
    endpoint_state: std::marker::PhantomData<EndpointState>,
}

/// Marker for a Network Activity builder without an endpoint.
pub struct MissingNetworkEndpoint;

/// Marker for a Network Activity builder with a source or destination endpoint.
pub struct HasNetworkEndpoint;

impl<'a> NetworkActivityBuilder<'a, MissingNetworkEndpoint> {
    /// Start building a Network Activity event.
    ///
    /// A Network Activity must include a source or destination endpoint before
    /// it can be built.
    ///
    /// ```compile_fail
    /// use openshell_ocsf::{EventContext, NetworkActivityBuilder};
    ///
    /// let ctx = EventContext {
    ///     sandbox_id: String::new(),
    ///     sandbox_name: String::new(),
    ///     container_image: String::new(),
    ///     hostname: String::new(),
    ///     product_version: String::new(),
    ///     proxy_ip: "127.0.0.1".parse().unwrap(),
    ///     proxy_port: 3128,
    /// };
    /// NetworkActivityBuilder::new(&ctx).build();
    /// ```
    #[must_use]
    pub fn new(ctx: &'a EventContext) -> Self {
        Self {
            ctx,
            activity: ActivityId::Unknown,
            activity_name: None,
            action: None,
            disposition: None,
            severity: SeverityId::Informational,
            status: None,
            src_endpoint: None,
            dst_endpoint: None,
            actor: None,
            firewall_rule: None,
            connection_info: None,
            observation_point_id: None,
            message: None,
            status_detail: None,
            unmapped: None,
            log_source: None,
            endpoint_state: std::marker::PhantomData,
        }
    }

    #[must_use]
    pub fn src_endpoint_addr(
        self,
        ip: std::net::IpAddr,
        port: u16,
    ) -> NetworkActivityBuilder<'a, HasNetworkEndpoint> {
        self.with_src_endpoint(Endpoint::from_ip(ip, port))
    }

    #[must_use]
    pub fn dst_endpoint(
        self,
        endpoint: Endpoint,
    ) -> NetworkActivityBuilder<'a, HasNetworkEndpoint> {
        self.with_dst_endpoint(endpoint)
    }
}

impl NetworkActivityBuilder<'_, HasNetworkEndpoint> {
    #[must_use]
    pub fn src_endpoint_addr(mut self, ip: std::net::IpAddr, port: u16) -> Self {
        self.src_endpoint = Some(Endpoint::from_ip(ip, port));
        self
    }

    #[must_use]
    pub fn dst_endpoint(mut self, endpoint: Endpoint) -> Self {
        self.dst_endpoint = Some(endpoint);
        self
    }
}

impl<'a, EndpointState> NetworkActivityBuilder<'a, EndpointState> {
    fn with_src_endpoint(
        self,
        endpoint: Endpoint,
    ) -> NetworkActivityBuilder<'a, HasNetworkEndpoint> {
        NetworkActivityBuilder {
            ctx: self.ctx,
            activity: self.activity,
            activity_name: self.activity_name,
            action: self.action,
            disposition: self.disposition,
            severity: self.severity,
            status: self.status,
            src_endpoint: Some(endpoint),
            dst_endpoint: self.dst_endpoint,
            actor: self.actor,
            firewall_rule: self.firewall_rule,
            connection_info: self.connection_info,
            observation_point_id: self.observation_point_id,
            message: self.message,
            status_detail: self.status_detail,
            unmapped: self.unmapped,
            log_source: self.log_source,
            endpoint_state: std::marker::PhantomData,
        }
    }

    fn with_dst_endpoint(
        self,
        endpoint: Endpoint,
    ) -> NetworkActivityBuilder<'a, HasNetworkEndpoint> {
        NetworkActivityBuilder {
            ctx: self.ctx,
            activity: self.activity,
            activity_name: self.activity_name,
            action: self.action,
            disposition: self.disposition,
            severity: self.severity,
            status: self.status,
            src_endpoint: self.src_endpoint,
            dst_endpoint: Some(endpoint),
            actor: self.actor,
            firewall_rule: self.firewall_rule,
            connection_info: self.connection_info,
            observation_point_id: self.observation_point_id,
            message: self.message,
            status_detail: self.status_detail,
            unmapped: self.unmapped,
            log_source: self.log_source,
            endpoint_state: std::marker::PhantomData,
        }
    }

    #[must_use]
    pub fn activity_name(mut self, name: impl Into<String>) -> Self {
        self.activity_name = Some(name.into());
        self
    }
    #[must_use]
    pub fn connection_info(mut self, info: ConnectionInfo) -> Self {
        self.connection_info = Some(info);
        self
    }
    #[must_use]
    pub fn observation_point(mut self, id: u8) -> Self {
        self.observation_point_id = Some(id);
        self
    }
    #[must_use]
    pub fn status_detail(mut self, detail: impl Into<String>) -> Self {
        self.status_detail = Some(detail.into());
        self
    }
    #[must_use]
    pub fn log_source(mut self, source: impl Into<String>) -> Self {
        self.log_source = Some(source.into());
        self
    }

    /// Add an unmapped field.
    #[must_use]
    pub fn unmapped(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.unmapped
            .get_or_insert_with(serde_json::Map::new)
            .insert(key.to_string(), value.into());
        self
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
    pub fn actor_process(mut self, process: crate::objects::Process) -> Self {
        self.actor = Some(Actor { process });
        self
    }

    #[must_use]
    pub fn firewall_rule(mut self, name: &str, rule_type: &str) -> Self {
        self.firewall_rule = Some(FirewallRule::new(name, rule_type));
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
    pub fn message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }
}

impl NetworkActivityBuilder<'_, HasNetworkEndpoint> {
    /// Finalize and return the `OcsfEvent`.
    #[must_use]
    pub fn build(self) -> OcsfEvent {
        let activity_name = self
            .activity_name
            .unwrap_or_else(|| self.activity.network_label().to_string());
        let mut metadata =
            self.ctx
                .metadata(&["security_control", "network_proxy", "container", "host"]);
        if let Some(source) = self.log_source {
            metadata.log_source = Some(source);
        }

        let mut base = BaseEventData::new(
            4001,
            "Network Activity",
            4,
            "Network Activity",
            self.activity.as_u8(),
            &activity_name,
            self.severity,
            metadata,
        );

        if let Some(detail) = self.status_detail {
            base.set_status_detail(detail);
        }
        if let Some(unmapped) = self.unmapped {
            base.unmapped = Some(serde_json::Value::Object(unmapped));
        }
        self.ctx
            .apply_common_fields(&mut base, self.status, self.message);

        OcsfEvent::NetworkActivity(NetworkActivityEvent {
            base,
            src_endpoint: self.src_endpoint,
            dst_endpoint: self.dst_endpoint,
            proxy_endpoint: Some(self.ctx.proxy_endpoint()),
            actor: self.actor,
            firewall_rule: self.firewall_rule,
            connection_info: self.connection_info,
            action: self.action,
            disposition: self.disposition,
            observation_point_id: self.observation_point_id,
            is_src_dst_assignment_known: Some(true),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builders::test_sandbox_context;
    use crate::objects::Process;

    #[test]
    fn test_network_activity_builder() {
        let ctx = test_sandbox_context();
        let event = NetworkActivityBuilder::new(&ctx)
            .activity(ActivityId::Open)
            .action(ActionId::Allowed)
            .disposition(DispositionId::Allowed)
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .dst_endpoint(Endpoint::from_domain("api.example.com", 443))
            .actor_process(Process::new("python3", 42).with_cmd_line("python3 /app/main.py"))
            .firewall_rule("default-egress", "mechanistic")
            .observation_point(2)
            .message("CONNECT api.example.com:443 allowed")
            .build();

        let json = event.to_json().unwrap();
        assert_eq!(json["class_uid"], 4001);
        assert_eq!(json["activity_name"], "Open");
        assert_eq!(json["action"], "Allowed");
        assert_eq!(json["disposition"], "Allowed");
        assert_eq!(json["dst_endpoint"]["domain"], "api.example.com");
        assert_eq!(json["actor"]["process"]["name"], "python3");
        assert_eq!(json["firewall_rule"]["name"], "default-egress");
        assert_eq!(json["container"]["name"], "my-sandbox");
        assert_eq!(json["device"]["hostname"], "sandbox-abc123");
        assert_eq!(json["is_src_dst_assignment_known"], true);
    }
}
