// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builder for Device Config State Change [5019] events.

use crate::builders::SandboxContext;
use crate::enums::{SecurityLevelId, SeverityId, StateId, StatusId};
use crate::events::base_event::BaseEventData;
use crate::events::{DeviceConfigStateChangeEvent, OcsfEvent};

/// Builder for Device Config State Change [5019] events.
pub struct ConfigStateChangeBuilder<'a> {
    ctx: &'a SandboxContext,
    severity: SeverityId,
    status: Option<StatusId>,
    state_id: Option<StateId>,
    state_label: Option<String>,
    security_level: Option<SecurityLevelId>,
    prev_security_level: Option<SecurityLevelId>,
    message: Option<String>,
    unmapped: serde_json::Map<String, serde_json::Value>,
}

impl<'a> ConfigStateChangeBuilder<'a> {
    #[must_use]
    pub fn new(ctx: &'a SandboxContext) -> Self {
        Self {
            ctx,
            severity: SeverityId::Informational,
            status: None,
            state_id: None,
            state_label: None,
            security_level: None,
            prev_security_level: None,
            message: None,
            unmapped: serde_json::Map::new(),
        }
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

    /// Set state with a custom label (OCSF `state_id` + display label).
    #[must_use]
    pub fn state(mut self, id: StateId, label: &str) -> Self {
        self.state_id = Some(id);
        self.state_label = Some(label.to_string());
        self
    }

    #[must_use]
    pub fn security_level(mut self, id: SecurityLevelId) -> Self {
        self.security_level = Some(id);
        self
    }
    #[must_use]
    pub fn prev_security_level(mut self, id: SecurityLevelId) -> Self {
        self.prev_security_level = Some(id);
        self
    }

    /// Add an unmapped field.
    #[must_use]
    pub fn unmapped(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.unmapped.insert(key.to_string(), value.into());
        self
    }

    #[must_use]
    pub fn build(self) -> OcsfEvent {
        let mut base = BaseEventData::new(
            5019,
            "Device Config State Change",
            5,
            "Discovery",
            1,
            "Log", // activity_id=1 (Log)
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
        if !self.unmapped.is_empty() {
            base.unmapped = Some(serde_json::Value::Object(self.unmapped));
        }

        OcsfEvent::DeviceConfigStateChange(DeviceConfigStateChangeEvent {
            base,
            state: self.state_id,
            state_custom_label: self.state_label,
            security_level: self.security_level,
            prev_security_level: self.prev_security_level,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builders::test_sandbox_context;

    #[test]
    fn test_config_state_change_builder() {
        let ctx = test_sandbox_context();
        let event = ConfigStateChangeBuilder::new(&ctx)
            .state(StateId::Enabled, "loaded")
            .security_level(SecurityLevelId::Secure)
            .prev_security_level(SecurityLevelId::Unknown)
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .unmapped("policy_version", serde_json::json!("v3"))
            .unmapped("policy_hash", serde_json::json!("sha256:abc123"))
            .message("Policy reloaded successfully")
            .build();

        let json = event.to_json().unwrap();
        assert_eq!(json["class_uid"], 5019);
        assert_eq!(json["state_id"], 2);
        assert_eq!(json["security_level"], "Secure");
        assert_eq!(json["unmapped"]["policy_version"], "v3");
    }
}
