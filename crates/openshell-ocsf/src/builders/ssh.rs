// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builder for SSH Activity [4007] events.

use crate::builders::SandboxContext;
use crate::enums::{ActionId, ActivityId, AuthTypeId, DispositionId, SeverityId, StatusId};
use crate::events::base_event::BaseEventData;
use crate::events::{OcsfEvent, SshActivityEvent};
use crate::objects::{Actor, Endpoint};

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

impl_activity_setter!(SshActivityBuilder);
impl_action_disposition_setters!(SshActivityBuilder);
impl_actor_process_setter!(SshActivityBuilder);
impl_dst_endpoint_setter!(SshActivityBuilder);
impl_src_endpoint_addr_setter!(SshActivityBuilder);
impl_builder_setters!(SshActivityBuilder);

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
