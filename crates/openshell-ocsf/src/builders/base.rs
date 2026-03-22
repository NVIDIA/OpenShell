// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builder for Base Event [0].

use crate::builders::SandboxContext;
use crate::enums::{SeverityId, StatusId};
use crate::events::base_event::BaseEventData;
use crate::events::{BaseEvent, OcsfEvent};

/// Builder for Base Event [0] — events without a specific OCSF class.
pub struct BaseEventBuilder<'a> {
    ctx: &'a SandboxContext,
    severity: SeverityId,
    status: Option<StatusId>,
    message: Option<String>,
    activity_name: Option<String>,
    unmapped: serde_json::Map<String, serde_json::Value>,
}

impl<'a> BaseEventBuilder<'a> {
    #[must_use]
    pub fn new(ctx: &'a SandboxContext) -> Self {
        Self {
            ctx,
            severity: SeverityId::Informational,
            status: None,
            message: None,
            activity_name: None,
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
    #[must_use]
    pub fn activity_name(mut self, name: impl Into<String>) -> Self {
        self.activity_name = Some(name.into());
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
        let activity_name = self.activity_name.as_deref().unwrap_or("Other");
        let mut base = BaseEventData::new(
            0,
            "Base Event",
            0,
            "Uncategorized",
            99,
            activity_name,
            self.severity,
            self.ctx.metadata(&["container", "host"]),
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

        OcsfEvent::Base(BaseEvent { base })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builders::test_sandbox_context;

    #[test]
    fn test_base_event_builder() {
        let ctx = test_sandbox_context();
        let event = BaseEventBuilder::new(&ctx)
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .activity_name("Network Namespace Created")
            .message("Network namespace created")
            .unmapped("namespace", serde_json::json!("openshell-sandbox-abc123"))
            .unmapped("host_ip", serde_json::json!("10.42.0.1"))
            .build();

        let json = event.to_json().unwrap();
        assert_eq!(json["class_uid"], 0);
        assert_eq!(json["activity_name"], "Network Namespace Created");
        assert_eq!(json["message"], "Network namespace created");
        assert_eq!(json["unmapped"]["namespace"], "openshell-sandbox-abc123");
    }
}
