// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builder for SSH Activity [4007] events.

use crate::builders::EventContext;
use crate::enums::{ActionId, ActivityId, AuthTypeId, DispositionId, SeverityId, StatusId};
use crate::events::base_event::BaseEventData;
use crate::events::{OcsfEvent, SshActivityEvent};
use crate::objects::{Actor, Endpoint};

/// Builder for SSH Activity [4007] events.
pub struct SshActivityBuilder<'a, EndpointState = MissingSshEndpoint> {
    ctx: &'a EventContext,
    activity: ActivityId,
    action: Option<ActionId>,
    disposition: Option<DispositionId>,
    severity: SeverityId,
    status: Option<StatusId>,
    src_endpoint: Option<Endpoint>,
    dst_endpoint: Option<Endpoint>,
    actor: Option<Actor>,
    auth_type_id: Option<AuthTypeId>,
    auth_type_label: Option<String>,
    protocol_ver: Option<String>,
    message: Option<String>,
    endpoint_state: std::marker::PhantomData<EndpointState>,
}

/// Marker for an SSH Activity builder without a source or destination endpoint.
pub struct MissingSshEndpoint;

/// Marker for an SSH Activity builder with a source or destination endpoint.
pub struct HasSshEndpoint;

impl<'a> SshActivityBuilder<'a, MissingSshEndpoint> {
    /// Start building an SSH Activity event.
    ///
    /// An SSH Activity must identify a source or destination endpoint before it
    /// can be built.
    ///
    /// ```compile_fail
    /// use openshell_ocsf::{EventContext, EventOrigin, SshActivityBuilder};
    ///
    /// let ctx = EventContext {
    ///     sandbox_id: String::new(),
    ///     sandbox_name: String::new(),
    ///     container_image: String::new(),
    ///     hostname: String::new(),
    ///     product_version: String::new(),
    ///     proxy_ip: "127.0.0.1".parse().unwrap(),
    ///     proxy_port: 3128,
    ///     origin: EventOrigin::Supervisor,
    /// };
    /// SshActivityBuilder::new(&ctx).build();
    /// ```
    #[must_use]
    pub fn new(ctx: &'a EventContext) -> Self {
        Self {
            ctx,
            activity: ActivityId::Unknown,
            action: None,
            disposition: None,
            severity: SeverityId::Informational,
            status: None,
            src_endpoint: None,
            dst_endpoint: None,
            actor: None,
            auth_type_id: None,
            auth_type_label: None,
            protocol_ver: None,
            message: None,
            endpoint_state: std::marker::PhantomData,
        }
    }
}

impl<'a, EndpointState> SshActivityBuilder<'a, EndpointState> {
    /// Set the source endpoint from an address.
    #[must_use]
    pub fn src_endpoint_addr(
        self,
        ip: std::net::IpAddr,
        port: u16,
    ) -> SshActivityBuilder<'a, HasSshEndpoint> {
        SshActivityBuilder {
            src_endpoint: Some(Endpoint::from_ip(ip, port)),
            dst_endpoint: self.dst_endpoint,
            ctx: self.ctx,
            activity: self.activity,
            action: self.action,
            disposition: self.disposition,
            severity: self.severity,
            status: self.status,
            actor: self.actor,
            auth_type_id: self.auth_type_id,
            auth_type_label: self.auth_type_label,
            protocol_ver: self.protocol_ver,
            message: self.message,
            endpoint_state: std::marker::PhantomData,
        }
    }

    /// Set the destination endpoint.
    #[must_use]
    pub fn dst_endpoint(self, endpoint: Endpoint) -> SshActivityBuilder<'a, HasSshEndpoint> {
        SshActivityBuilder {
            src_endpoint: self.src_endpoint,
            dst_endpoint: Some(endpoint),
            ctx: self.ctx,
            activity: self.activity,
            action: self.action,
            disposition: self.disposition,
            severity: self.severity,
            status: self.status,
            actor: self.actor,
            auth_type_id: self.auth_type_id,
            auth_type_label: self.auth_type_label,
            protocol_ver: self.protocol_ver,
            message: self.message,
            endpoint_state: std::marker::PhantomData,
        }
    }

    /// Set auth type with a custom label (e.g., "NSSH1").
    #[must_use]
    pub fn auth_type(mut self, id: AuthTypeId, label: &str) -> Self {
        self.auth_type_id = Some(id);
        self.auth_type_label = Some(label.to_string());
        self
    }

    #[must_use]
    pub fn protocol_ver(mut self, ver: &str) -> Self {
        self.protocol_ver = Some(ver.to_string());
        self
    }

    /// Set the event activity identifier.
    #[must_use]
    pub fn activity(mut self, id: ActivityId) -> Self {
        self.activity = id;
        self
    }

    /// Set the action taken.
    #[must_use]
    pub fn action(mut self, id: ActionId) -> Self {
        self.action = Some(id);
        self
    }

    /// Set the disposition of the action.
    #[must_use]
    pub fn disposition(mut self, id: DispositionId) -> Self {
        self.disposition = Some(id);
        self
    }

    /// Set the acting process.
    #[must_use]
    pub fn actor_process(mut self, process: crate::objects::Process) -> Self {
        self.actor = Some(Actor { process });
        self
    }

    /// Set the event severity.
    #[must_use]
    pub fn severity(mut self, id: SeverityId) -> Self {
        self.severity = id;
        self
    }

    /// Set the overall event status.
    #[must_use]
    pub fn status(mut self, id: StatusId) -> Self {
        self.status = Some(id);
        self
    }

    /// Set a human-readable event message.
    #[must_use]
    pub fn message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }
}

impl SshActivityBuilder<'_, HasSshEndpoint> {
    #[must_use]
    pub fn build(self) -> OcsfEvent {
        let activity_name = self.activity.network_label().to_string();
        let mut base = BaseEventData::new(
            4007,
            "SSH Activity",
            4,
            "Network Activity",
            self.activity.as_u8(),
            &activity_name,
            self.severity,
            self.ctx
                .metadata(&["security_control", "container", "host"]),
        );
        self.ctx
            .apply_common_fields(&mut base, self.status, self.message);

        OcsfEvent::SshActivity(SshActivityEvent {
            base,
            src_endpoint: self.src_endpoint,
            dst_endpoint: self.dst_endpoint,
            actor: self.actor,
            auth_type: self.auth_type_id,
            auth_type_custom_label: self.auth_type_label,
            protocol_ver: self.protocol_ver,
            action: self.action,
            disposition: self.disposition,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builders::test_sandbox_context;

    #[test]
    fn test_ssh_activity_builder() {
        let ctx = test_sandbox_context();
        let event = SshActivityBuilder::new(&ctx)
            .activity(ActivityId::Open)
            .action(ActionId::Allowed)
            .disposition(DispositionId::Allowed)
            .severity(SeverityId::Informational)
            .src_endpoint_addr("10.42.0.1".parse().unwrap(), 48201)
            .auth_type(AuthTypeId::Other, "NSSH1")
            .protocol_ver("NSSH1")
            .message("SSH handshake accepted via NSSH1")
            .build();

        let json = event.to_json().unwrap();
        assert_eq!(json["class_uid"], 4007);
        assert_eq!(json["auth_type"], "NSSH1");
        assert_eq!(json["auth_type_id"], 99);
    }
}
