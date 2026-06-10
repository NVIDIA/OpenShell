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
        self.ctx
            .apply_common_fields(&mut base, self.status, self.message);

        OcsfEvent::ApplicationLifecycle(ApplicationLifecycleEvent {
            base,
            app: Product::openshell_sandbox(&self.ctx.product_version),
        })
    }
}

impl_activity_setter!(AppLifecycleBuilder);
impl_builder_setters!(AppLifecycleBuilder);

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
