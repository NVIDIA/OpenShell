// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builder for Application Lifecycle [6002] events.

use crate::builders::SandboxContext;
use crate::enums::{ActivityId, SeverityId, StatusId};
use crate::events::base_event::BaseEventData;
use crate::events::{ApplicationLifecycleEvent, OcsfEvent};
use crate::objects::Product;

/// Builder for Application Lifecycle [6002] events.
pub struct AppLifecycleBuilder<'a> {
    ctx: &'a SandboxContext,
    activity: ActivityId,
    severity: SeverityId,
    status: Option<StatusId>,
    message: Option<String>,
}

impl<'a> AppLifecycleBuilder<'a> {
    #[must_use]
    pub fn new(ctx: &'a SandboxContext) -> Self {
        Self {
            ctx,
            activity: ActivityId::Unknown,
            severity: SeverityId::Informational,
            status: None,
            message: None,
        }
    }

    #[must_use]
    pub fn activity(mut self, id: ActivityId) -> Self {
        self.activity = id;
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

    #[must_use]
    pub fn build(self) -> OcsfEvent {
        let activity_name = self.activity.lifecycle_label().to_string();
        let mut base = BaseEventData::new(
            6002,
            "Application Lifecycle",
            6,
            "Application Activity",
            self.activity.as_u8(),
            &activity_name,
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

        OcsfEvent::ApplicationLifecycle(ApplicationLifecycleEvent {
            base,
            app: Product::openshell_sandbox(&self.ctx.product_version),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builders::test_sandbox_context;

    #[test]
    fn test_app_lifecycle_builder() {
        let ctx = test_sandbox_context();
        let event = AppLifecycleBuilder::new(&ctx)
            .activity(ActivityId::Reset) // Start
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .message("Starting sandbox")
            .build();

        let json = event.to_json().unwrap();
        assert_eq!(json["class_uid"], 6002);
        assert_eq!(json["activity_name"], "Start");
        assert_eq!(json["app"]["name"], "OpenShell Sandbox Supervisor");
        assert_eq!(json["status"], "Success");
    }
}
