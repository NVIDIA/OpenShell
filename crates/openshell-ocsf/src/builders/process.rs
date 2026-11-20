// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builder for Process Activity [1007] events.

use crate::builders::ContextRef;
use crate::enums::{ActionId, ActivityId, DispositionId, LaunchTypeId, SeverityId, StatusId};
use crate::events::base_event::BaseEventData;
use crate::events::{OcsfEvent, ProcessActivityEvent};
use crate::objects::{Actor, Process};

/// Builder for Process Activity [1007] events.
pub struct ProcessActivityBuilder<'a, ActorState = MissingActor> {
    ctx: ContextRef<'a>,
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
    unmapped: serde_json::Map<String, serde_json::Value>,
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
    /// use openshell_ocsf::ProcessActivityBuilder;
    ///
    /// ProcessActivityBuilder::new(openshell_ocsf::ctx::ctx()).build();
    /// ```
    #[must_use]
    pub fn new(ctx: impl Into<ContextRef<'a>>) -> Self {
        Self {
            ctx: ctx.into(),
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
            unmapped: serde_json::Map::new(),
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
            actor: Some(Actor::process(process)),
            launch_type: self.launch_type,
            exit_code: self.exit_code,
            message: self.message,
            unmapped: self.unmapped,
            actor_state: std::marker::PhantomData,
        }
    }
}

impl<ActorState> ProcessActivityBuilder<'_, ActorState> {
    /// Set the action taken.
    /// Set the disposition of the action.
    /// Set the event severity.
    /// Set the overall event status.
    /// Set a human-readable event message.
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

    /// Add an unmapped field.
    #[must_use]
    pub fn unmapped(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.unmapped.insert(key.to_string(), value.into());
        self
    }

    /// Mark the event's payload as guest-sourced: the data originated
    /// from the in-guest boundary (untrusted after start in root-workload
    /// mode), not from a supervisor-verified observation.
    #[must_use]
    pub fn guest_sourced(self) -> Self {
        self.unmapped("data_origin", "guest")
    }
}

impl_activity_setter!(ProcessActivityBuilder<ActorState>);
impl_action_disposition_setters!(ProcessActivityBuilder<ActorState>);
impl_builder_setters!(ProcessActivityBuilder<ActorState>);

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
        if !self.unmapped.is_empty() {
            base.unmapped = Some(serde_json::Value::Object(self.unmapped));
        }

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

#[cfg(test)]
mod guest_sourced_tests {
    use super::*;
    use crate::{ActivityId, SeverityId};

    #[test]
    fn guest_sourced_process_exit_carries_the_marker() {
        let event = ProcessActivityBuilder::new(crate::ctx::ctx())
            .activity(ActivityId::Close)
            .severity(SeverityId::Informational)
            .exit_code(137)
            .guest_sourced()
            .message("main process exit reported by the boundary: code 137")
            .actor_process(Process::new("openshell-sandbox", 1))
            .build();
        let json = serde_json::to_value(&event).expect("serialize");
        assert_eq!(
            json.get("unmapped")
                .and_then(|u| u.get("data_origin"))
                .and_then(serde_json::Value::as_str),
            Some("guest")
        );
        let shorthand = event.format_shorthand();
        assert!(
            shorthand.contains("data_origin:guest"),
            "the shorthand must render the marker: {shorthand}"
        );
    }

    #[test]
    fn exec_exit_carries_the_marker_in_root_mode() {
        // The exec exit status is boundary-reported; in root mode the
        // boundary is untrusted after start, so the event is marked.
        use crate::Process;
        let event = ProcessActivityBuilder::new(crate::ctx::ctx())
            .activity(ActivityId::Close)
            .severity(SeverityId::Informational)
            .exit_code(0)
            .process(Process::new("sh", 0))
            .guest_sourced()
            .message("exec exit reported by the boundary: code 0")
            .actor_process(Process::new("openshell-sandbox", 1))
            .build();
        let json = serde_json::to_value(&event).expect("serialize");
        assert_eq!(
            json.get("unmapped")
                .and_then(|u| u.get("data_origin"))
                .and_then(serde_json::Value::as_str),
            Some("guest"),
            "the exec exit event must carry the guest-sourced marking in root mode"
        );
        let shorthand = event.format_shorthand();
        assert!(
            shorthand.contains("data_origin:guest"),
            "the shorthand must render the marker: {shorthand}"
        );
    }

    #[test]
    fn exec_exit_has_no_marker_in_sandboxed_mode() {
        // The exec exit status is boundary-reported but the boundary is
        // supervised in sandboxed mode; the event stays unmarked.
        use crate::Process;
        let event = ProcessActivityBuilder::new(crate::ctx::ctx())
            .activity(ActivityId::Close)
            .severity(SeverityId::Informational)
            .exit_code(0)
            .process(Process::new("sh", 0))
            .message("exec process exited: code 0")
            .actor_process(Process::new("openshell-sandbox", 1))
            .build();
        let json = serde_json::to_value(&event).expect("serialize");
        assert!(
            json.get("unmapped")
                .and_then(|u| u.get("data_origin"))
                .is_none(),
            "the exec exit event must NOT carry the marking in sandboxed mode"
        );
        let shorthand = event.format_shorthand();
        assert!(
            !shorthand.contains("data_origin:guest"),
            "the shorthand must not render the marker: {shorthand}"
        );
    }

    #[test]
    fn adopted_exec_exit_carries_the_marker_in_root_mode() {
        // The adopted-exec exit is boundary-reported; in root mode the
        // event is marked (same lifecycle semantics as the exec exit).
        use crate::Process;
        let event = ProcessActivityBuilder::new(crate::ctx::ctx())
            .activity(ActivityId::Close)
            .severity(SeverityId::Informational)
            .exit_code(137)
            .process(Process::new("python3", 0))
            .guest_sourced()
            .message("adopted exec exit reported by the boundary: code 137")
            .actor_process(Process::new("openshell-sandbox", 1))
            .build();
        let json = serde_json::to_value(&event).expect("serialize");
        assert_eq!(
            json.get("unmapped")
                .and_then(|u| u.get("data_origin"))
                .and_then(serde_json::Value::as_str),
            Some("guest"),
            "the adopted-exec exit must carry the guest-sourced marking in root mode"
        );
    }

    #[test]
    fn forged_process_name_cannot_create_a_marker() {
        // The PROC shorthand escapes guest-controlled fields (process name,
        // command line) with bracket escaping: a name starting with
        // "[data_origin:guest] " renders as "\\[data_origin:guest\\] "
        // (escaped brackets), visually distinct from the real
        // fixed-position marker. The shorthand of an unmarked event must
        // NOT start with the marked prefix.
        use crate::Process;
        let event = ProcessActivityBuilder::new(crate::ctx::ctx())
            .activity(ActivityId::Close)
            .severity(SeverityId::Informational)
            .exit_code(0)
            .process(Process::new("[data_origin:guest] fake-cmd", 0))
            .message("exec process exited: code 0")
            .actor_process(Process::new("openshell-sandbox", 1))
            .build();
        let json = serde_json::to_value(&event).expect("serialize");
        // The event is NOT marked: the forged name is in the process field,
        // not in the unmapped data_origin field.
        assert!(
            json.get("unmapped")
                .and_then(|u| u.get("data_origin"))
                .is_none(),
            "a forged process name must not create a data_origin marking: {json}"
        );
        // The shorthand of an unmarked event must NOT start with the
        // marked prefix. The escaped brackets make the forged name
        // render as \\[data_origin:guest\\], not [data_origin:guest].
        let shorthand = event.format_shorthand();
        assert!(
            !shorthand.starts_with("PROC:TERMINATE [INFO] [data_origin:guest]"),
            "the forged name must not make the shorthand look marked: {shorthand}"
        );
        assert!(
            shorthand.contains("\\[data_origin:guest\\]"),
            "the forged brackets must be escaped: {shorthand}"
        );
    }

    #[test]
    fn newline_in_process_name_cannot_start_a_forged_line() {
        // A newline in a process name would start a new line in the
        // shorthand output, potentially forging a subsequent event. The
        // escape quotes the field, preventing this.
        use crate::Process;
        let event = ProcessActivityBuilder::new(crate::ctx::ctx())
            .activity(ActivityId::Close)
            .severity(SeverityId::Informational)
            .exit_code(0)
            .process(Process::new(
                "cmd\nOCSF NET:OPEN [INFO] [data_origin:guest] fake",
                0,
            ))
            .message("exec process exited: code 0")
            .actor_process(Process::new("openshell-sandbox", 1))
            .build();
        let shorthand = event.format_shorthand();
        // The shorthand must not contain a newline (the escaped name is quoted).
        assert!(
            !shorthand.contains('\n'),
            "a newline in the process name must not create a line break: {shorthand:?}"
        );
    }

    #[test]
    fn unmarked_process_exit_has_no_marker() {
        let event = ProcessActivityBuilder::new(crate::ctx::ctx())
            .activity(ActivityId::Close)
            .severity(SeverityId::Informational)
            .exit_code(0)
            .message("main process exited: code 0")
            .actor_process(Process::new("openshell-sandbox", 1))
            .build();
        let json = serde_json::to_value(&event).expect("serialize");
        assert!(
            json.get("unmapped")
                .and_then(|u| u.get("data_origin"))
                .is_none()
        );
    }
}
