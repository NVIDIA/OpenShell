// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builder for Process Activity [1007] events.

use crate::builders::EventContext;
use crate::enums::{ActionId, ActivityId, DispositionId, LaunchTypeId, SeverityId, StatusId};
use crate::events::base_event::BaseEventData;
use crate::events::{OcsfEvent, ProcessActivityEvent};
use crate::objects::{Actor, Process};

/// Builder for Process Activity [1007] events.
pub struct ProcessActivityBuilder<'a, ActorState = MissingActor> {
    ctx: &'a EventContext,
    activity: ActivityId,
    severity: SeverityId,
    status: Option<StatusId>,
    action: Option<ActionId>,
    disposition: Option<DispositionId>,
    process: Option<Process>,
    actor: Option<Actor>,
    launch_type: Option<LaunchTypeId>,
    exit_code: Option<i32>,
    message: Option<String>,
    actor_state: std::marker::PhantomData<ActorState>,
}

/// Marker for a Process Activity builder without an acting process.
pub struct MissingActor;

/// Marker for a Process Activity builder with an acting process.
pub struct HasActor;

impl<'a> ProcessActivityBuilder<'a, MissingActor> {
    /// Start building a Process Activity event.
    ///
    /// A Process Activity must name its acting process before it can be built.
    ///
    /// ```compile_fail
    /// use openshell_ocsf::{EventContext, EventOrigin, ProcessActivityBuilder};
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
    /// ProcessActivityBuilder::new(&ctx).build();
    /// ```
    #[must_use]
    pub fn new(ctx: &'a EventContext) -> Self {
        Self {
            ctx,
            activity: ActivityId::Unknown,
            severity: SeverityId::Informational,
            status: None,
            action: None,
            disposition: None,
            process: None,
            actor: None,
            launch_type: None,
            exit_code: None,
            message: None,
            actor_state: std::marker::PhantomData,
        }
    }

    /// Set the acting process. Required by the OCSF schema.
    #[must_use]
    pub fn actor_process(self, process: Process) -> ProcessActivityBuilder<'a, HasActor> {
        ProcessActivityBuilder {
            ctx: self.ctx,
            activity: self.activity,
            severity: self.severity,
            status: self.status,
            action: self.action,
            disposition: self.disposition,
            process: self.process,
            actor: Some(Actor { process }),
            launch_type: self.launch_type,
            exit_code: self.exit_code,
            message: self.message,
            actor_state: std::marker::PhantomData,
        }
    }
}

impl<ActorState> ProcessActivityBuilder<'_, ActorState> {
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
    #[must_use]
    pub fn process(mut self, proc: Process) -> Self {
        self.process = Some(proc);
        self
    }
    #[must_use]
    pub fn launch_type(mut self, lt: LaunchTypeId) -> Self {
        self.launch_type = Some(lt);
        self
    }
    #[must_use]
    pub fn exit_code(mut self, code: i32) -> Self {
        self.exit_code = Some(code);
        self
    }
}

impl ProcessActivityBuilder<'_, HasActor> {
    #[must_use]
    pub fn build(self) -> OcsfEvent {
        let activity_name = self.activity.process_label().to_string();
        let mut base = BaseEventData::new(
            1007,
            "Process Activity",
            1,
            "System Activity",
            self.activity.as_u8(),
            &activity_name,
            self.severity,
            self.ctx
                .metadata(&["security_control", "container", "host"]),
        );
        self.ctx
            .apply_common_fields(&mut base, self.status, self.message);

        OcsfEvent::ProcessActivity(ProcessActivityEvent {
            base,
            process: self.process.unwrap_or_else(|| Process::new("unknown", 0)),
            actor: self.actor,
            launch_type: self.launch_type,
            exit_code: self.exit_code,
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
    fn test_process_activity_builder_launch() {
        let ctx = test_sandbox_context();
        let event = ProcessActivityBuilder::new(&ctx)
            .activity(ActivityId::Open) // Launch
            .action(ActionId::Allowed)
            .disposition(DispositionId::Allowed)
            .severity(SeverityId::Informational)
            .launch_type(LaunchTypeId::Spawn)
            .process(Process::new("python3", 42).with_cmd_line("python3 /app/main.py"))
            .actor_process(Process::new("openshell-sandbox", 1))
            .message("Process started: python3 /app/main.py")
            .build();

        let json = event.to_json().unwrap();
        assert_eq!(json["class_uid"], 1007);
        assert_eq!(json["launch_type"], "Spawn");
        assert_eq!(json["process"]["name"], "python3");
        assert_eq!(json["actor"]["process"]["name"], "openshell-sandbox");
    }

    #[test]
    fn test_process_activity_builder_terminate() {
        let ctx = test_sandbox_context();
        let event = ProcessActivityBuilder::new(&ctx)
            .activity(ActivityId::Close) // Terminate
            .severity(SeverityId::Informational)
            .process(Process::new("python3", 42))
            .actor_process(Process::new("openshell-sandbox", 1))
            .exit_code(0)
            .build();

        let json = event.to_json().unwrap();
        assert_eq!(json["exit_code"], 0);
    }
}
