// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builder for File System Activity [1001] events.

use crate::builders::ContextRef;
use crate::enums::{ActionId, DispositionId, SeverityId, StatusId};
use crate::events::base_event::BaseEventData;
use crate::events::{FileActivityEvent, OcsfEvent};
use crate::objects::{Actor, File, Process};

/// Build a File System Activity for a requested open.
pub struct FileActivityBuilder<'a> {
    ctx: ContextRef<'a>,
    file: File,
    actor: Actor,
    requested_path: String,
    access_type: String,
    action: ActionId,
    disposition: Option<DispositionId>,
    severity: SeverityId,
    status: Option<StatusId>,
}

impl<'a> FileActivityBuilder<'a> {
    /// Start an event for a path as supplied by the workload to open(2).
    #[must_use]
    pub fn new(
        ctx: impl Into<ContextRef<'a>>,
        requested_path: &str,
        actor_process: Process,
        access_type: &str,
    ) -> Self {
        Self {
            ctx: ctx.into(),
            file: File::requested(requested_path),
            actor: Actor::process(actor_process),
            requested_path: requested_path.to_string(),
            access_type: access_type.to_string(),
            action: ActionId::Observed,
            disposition: None,
            severity: SeverityId::Informational,
            status: None,
        }
    }

    /// Set the security-control action when the source knows the decision.
    #[must_use]
    pub fn action(mut self, action: ActionId) -> Self {
        self.action = action;
        self
    }

    /// Set the security-control disposition when the source knows the outcome.
    #[must_use]
    pub fn disposition(mut self, disposition: DispositionId) -> Self {
        self.disposition = Some(disposition);
        self
    }

    /// Set the event severity.
    #[must_use]
    pub fn severity(mut self, severity: SeverityId) -> Self {
        self.severity = severity;
        self
    }

    /// Set the outcome status when the source knows it.
    #[must_use]
    pub fn status(mut self, status: StatusId) -> Self {
        self.status = Some(status);
        self
    }

    /// Finalize the event with an Open activity and explicit path provenance.
    #[must_use]
    pub fn build(self) -> OcsfEvent {
        let mut base = BaseEventData::new(
            1001,
            "File System Activity",
            1,
            "System Activity",
            14,
            "Open",
            self.severity,
            self.ctx
                .metadata(&["container", "host", "security_control"]),
        );
        base.unmapped = Some(serde_json::json!({
            "requested_path": self.requested_path,
            "path_source": "syscall_argument",
            "access_type": self.access_type,
        }));
        self.ctx.apply_common_fields(&mut base, self.status, None);
        OcsfEvent::FileActivity(FileActivityEvent {
            base,
            file: self.file,
            actor: self.actor,
            action: Some(self.action),
            disposition: self.disposition,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builders::test_sandbox_context;

    #[test]
    fn observed_open_is_schema_valid_and_round_trips() {
        let event = FileActivityBuilder::new(
            &test_sandbox_context(),
            "/sandbox/project/.env",
            Process::new("python3", 42).with_path("/usr/bin/python3"),
            "read",
        )
        .build();
        let json = event.to_json().unwrap();
        openshell_ocsf_validate::validate_event(&json).unwrap();
        assert_eq!(json["class_uid"], 1001);
        assert_eq!(json["activity_id"], 14);
        assert_eq!(json["action_id"], 3);
        assert_eq!(json["file"]["path"], "/sandbox/project/.env");
        assert_eq!(json["actor"]["process"]["path"], "/usr/bin/python3");
        assert_eq!(json["unmapped"]["path_source"], "syscall_argument");
        assert!(event.format_shorthand().contains(
            "FILE:OPEN [INFO] OBSERVED python3(42) /sandbox/project/.env [access:read path:requested]"
        ));
        let restored: OcsfEvent = serde_json::from_value(json).unwrap();
        assert_eq!(restored, event);
    }
}
