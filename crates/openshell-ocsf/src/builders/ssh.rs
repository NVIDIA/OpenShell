// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builder for SSH Activity [4007] events.

use std::net::IpAddr;

use crate::builders::SandboxContext;
use crate::enums::{ActionId, ActivityId, AuthTypeId, DispositionId, SeverityId, StatusId};
use crate::events::base_event::BaseEventData;
use crate::events::{OcsfEvent, SshActivityEvent};
use crate::objects::{Actor, Endpoint, Process};

/// Builder for SSH Activity [4007] events.
pub struct SshActivityBuilder<'a> {
    ctx: &'a SandboxContext,
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
}

impl<'a> SshActivityBuilder<'a> {
    #[must_use]
    pub fn new(ctx: &'a SandboxContext) -> Self {
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
    pub fn src_endpoint_addr(mut self, ip: IpAddr, port: u16) -> Self {
        self.src_endpoint = Some(Endpoint::from_ip(ip, port));
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
    pub fn message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
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
        if let Some(status) = self.status {
            base.set_status(status);
        }
        if let Some(msg) = self.message {
            base.set_message(msg);
        }
        base.set_device(self.ctx.device());
        base.set_container(self.ctx.container());

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
