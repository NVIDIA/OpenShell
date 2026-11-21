// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Idle stop: stop a sandbox whose terminal program has waited on the user
//! longer than its `idle_stop_after_seconds` setting.
//!
//! The supervisor reports OSC 7501 program status with relative ages. The
//! replica that holds a sandbox's supervisor session keeps the latest report
//! of that session in memory, with exact input time, and decides idleness
//! from it alone. The stored `ProgramStatus` condition is for display: it is
//! written only on state changes or coarse input progress, can lag, and can
//! outlive the session that reported it, so it never authorizes a stop. A
//! sandbox with no report on its current session is never idle.

use std::time::{Duration, SystemTime};

use openshell_core::metadata::PROGRAM_STATUS_CONDITION;
use openshell_core::proto::{
    Sandbox, SandboxCondition, SandboxPhase, SupervisorWorkloadActivity, WorkloadBlockedKind,
    WorkloadProgramState,
};

pub use openshell_core::metadata::IDLE_STOPPED_REASON;

/// How often each replica looks for idle sandboxes among its sessions.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// Longest delay before the supervisor reports new input: one check interval
/// plus the minimum spacing of input reports. The sweep waits this much past
/// the timeout before asking the supervisor to confirm, which avoids
/// confirmation requests that pushed input would have answered anyway.
pub const INPUT_REPORT_LAG: Duration = Duration::from_secs(15);
/// A confirmation authorizes the `Stopping` write only this long after its
/// reply arrived. A stop that cannot commit by then, such as one waiting on
/// the lifecycle lock, is abandoned and confirmed again on a later sweep.
pub const CONFIRM_FRESHNESS: Duration = Duration::from_secs(2);
/// How long an idle stop waits for the supervisor to confirm. No answer, as
/// from a replaced or dead session, cancels the stop.
#[cfg(not(test))]
pub const CONFIRM_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
pub const CONFIRM_TIMEOUT: Duration = Duration::from_millis(200);
/// Input progress smaller than this does not rewrite the displayed condition.
pub const INPUT_WRITE_GRANULARITY: Duration = Duration::from_mins(1);
/// Durable marker that the in-flight stop was started by the idle sweep. It
/// survives gateway restarts and driver snapshots that rewrite conditions.
pub const IDLE_STOP_ANNOTATION: &str = "internal.openshell.ai/idle-stop";
pub const IDLE_STOPPING_REASON: &str = "IdleStopping";
pub const IDLE_STOPPED_MESSAGE: &str = "Sandbox stopped after its program waited on the user past its idle timeout; connect to start it";
/// Reported app names are bounded by OSC 7501; bound them again here.
const MAX_APP: usize = 32;

fn timestamp(time: SystemTime) -> Option<prost_types::Timestamp> {
    openshell_core::time::timestamp_from_system_time(time).ok()
}

fn system_time(timestamp: Option<&prost_types::Timestamp>) -> Option<SystemTime> {
    openshell_core::time::system_time_from_timestamp(timestamp?).ok()
}

fn before(now: SystemTime, age: Option<&prost_types::Duration>) -> Option<SystemTime> {
    let age = openshell_core::time::duration_to_std(age?).ok()?;
    now.checked_sub(age)
}

fn state_reason(state: WorkloadProgramState) -> Option<&'static str> {
    Some(match state {
        WorkloadProgramState::Unspecified => return None,
        WorkloadProgramState::Idle => "Idle",
        WorkloadProgramState::Working => "Working",
        WorkloadProgramState::Done => "Done",
        WorkloadProgramState::Blocked => "Blocked",
        WorkloadProgramState::Error => "Error",
    })
}

fn condition_message(report: &SupervisorWorkloadActivity, reason: &str) -> String {
    let app: String = report
        .app
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "_.+-".contains(*c))
        .take(MAX_APP)
        .collect();
    let program = if app.is_empty() {
        "program".to_string()
    } else {
        app
    };
    let waits_for = match WorkloadBlockedKind::try_from(report.blocked_kind) {
        Ok(WorkloadBlockedKind::Permission) => " on permission",
        Ok(WorkloadBlockedKind::Question) => " on a question",
        Ok(WorkloadBlockedKind::Auth) => " on authentication",
        _ => "",
    };
    format!("{program} is {}{waits_for}", reason.to_ascii_lowercase())
}

/// The latest report of a supervisor session, in gateway time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveActivity {
    pub session_id: String,
    pub instance_id: String,
    /// The session's supervisor answers activity requests, so it can confirm
    /// idleness before a stop. Sessions that cannot are never idle-stopped.
    pub confirms: bool,
    pub state: WorkloadProgramState,
    /// The later of the state change and the latest client input.
    pub since: SystemTime,
    /// The supervisor's summary sequence; older summaries are dropped.
    pub sequence: u64,
    /// The report itself and when it arrived, for the display condition.
    pub report: SupervisorWorkloadActivity,
    pub received: SystemTime,
}

impl LiveActivity {
    /// Whether `report` from `session_id` is older than this one. A new
    /// session always replaces the entry.
    #[must_use]
    pub fn is_newer_than(&self, session_id: &str, report: &SupervisorWorkloadActivity) -> bool {
        self.session_id == session_id && report.sequence != 0 && report.sequence < self.sequence
    }
}

/// Live activity for a report received at `now` on `session_id`.
pub fn live_from_report(
    report: &SupervisorWorkloadActivity,
    session_id: &str,
    instance_id: &str,
    confirms: bool,
    now: SystemTime,
) -> LiveActivity {
    let state_since = before(now, report.state_age.as_ref()).unwrap_or(now);
    let since =
        before(now, report.input_age.as_ref()).map_or(state_since, |input| input.max(state_since));
    LiveActivity {
        session_id: session_id.to_string(),
        instance_id: instance_id.to_string(),
        confirms,
        state: WorkloadProgramState::try_from(report.state)
            .unwrap_or(WorkloadProgramState::Unspecified),
        since,
        sequence: report.sequence,
        report: report.clone(),
        received: now,
    }
}

/// The `ProgramStatus` condition for a supervisor report received at `now`,
/// or `None` when no program currently reports.
pub fn condition_from_report(
    report: &SupervisorWorkloadActivity,
    now: SystemTime,
) -> Option<SandboxCondition> {
    let state = WorkloadProgramState::try_from(report.state).ok()?;
    let reason = state_reason(state)?;
    let state_since = before(now, report.state_age.as_ref()).unwrap_or(now);
    let since =
        before(now, report.input_age.as_ref()).map_or(state_since, |input| input.max(state_since));
    Some(SandboxCondition {
        r#type: PROGRAM_STATUS_CONDITION.to_string(),
        status: "True".to_string(),
        reason: reason.to_string(),
        message: condition_message(report, reason),
        transition_time: timestamp(since),
    })
}

/// The stored program condition of a sandbox.
pub fn program_condition(sandbox: &Sandbox) -> Option<&SandboxCondition> {
    sandbox
        .status
        .as_ref()?
        .conditions
        .iter()
        .find(|condition| condition.r#type == PROGRAM_STATUS_CONDITION)
}

/// How to update the stored program condition.
#[derive(Debug, PartialEq, Eq)]
pub enum ConditionWrite {
    /// The stored condition is close enough.
    Keep,
    Set(SandboxCondition),
    Remove,
}

/// How to update the stored condition for the next report.
///
/// A repeated state keeps its stored time unless input moved it forward by
/// the write granularity, so frequent reports do not churn the record and a
/// reconnecting supervisor cannot postpone an idle stop.
pub fn merge_condition(
    stored: Option<&SandboxCondition>,
    next: Option<SandboxCondition>,
) -> ConditionWrite {
    match (stored, next) {
        (None, None) => ConditionWrite::Keep,
        (Some(_), None) => ConditionWrite::Remove,
        (None, Some(next)) => ConditionWrite::Set(next),
        (Some(stored), Some(next)) => {
            if stored.reason != next.reason || stored.message != next.message {
                return ConditionWrite::Set(next);
            }
            let advanced = match (
                system_time(stored.transition_time.as_ref()),
                system_time(next.transition_time.as_ref()),
            ) {
                (Some(stored), Some(next)) => next
                    .duration_since(stored)
                    .is_ok_and(|advance| advance >= INPUT_WRITE_GRANULARITY),
                (None, Some(_)) => true,
                (_, None) => false,
            };
            if advanced {
                ConditionWrite::Set(next)
            } else {
                ConditionWrite::Keep
            }
        }
    }
}

/// The effective idle timeout for a raw setting value, or `None` when idle
/// stop is disabled.
pub fn timeout_from_setting(seconds: Option<i64>) -> Option<Duration> {
    let seconds = seconds.filter(|seconds| *seconds > 0)?;
    let seconds = seconds.min(openshell_core::settings::MAX_IDLE_STOP_AFTER_SECONDS);
    Some(Duration::from_secs(u64::try_from(seconds).ok()?))
}

/// When the sandbox began waiting on the user, or `None` while it is not.
///
/// The program waits while the current session last reported idle, done,
/// blocked, or error. The later of that report's time (state change or client
/// input) and the main-process start marks the beginning. A report from
/// another main-process instance does not count.
pub fn idle_since(sandbox: &Sandbox, live: &LiveActivity) -> Option<SystemTime> {
    let status = sandbox.status.as_ref()?;
    if status.phase != SandboxPhase::Ready as i32
        || (!status.main_process_instance_id.is_empty()
            && status.main_process_instance_id != live.instance_id)
    {
        return None;
    }
    if !matches!(
        live.state,
        WorkloadProgramState::Idle
            | WorkloadProgramState::Done
            | WorkloadProgramState::Blocked
            | WorkloadProgramState::Error
    ) {
        return None;
    }
    let started = system_time(status.main_process_started_time.as_ref());
    Some(started.map_or(live.since, |started| started.max(live.since)))
}

/// How long the sandbox has waited, when that reaches `timeout` plus the
/// input report lag.
pub fn idle_stop_due(
    sandbox: &Sandbox,
    live: &LiveActivity,
    timeout: Duration,
    now: SystemTime,
) -> Option<Duration> {
    let idle = now.duration_since(idle_since(sandbox, live)?).ok()?;
    (idle >= timeout + INPUT_REPORT_LAG).then_some(idle)
}

/// The Ready condition of an idle-stopped sandbox. Driver snapshots of the
/// stopped runtime rewrite conditions, so the gateway reapplies it.
pub fn idle_stopped_condition() -> SandboxCondition {
    SandboxCondition {
        r#type: "Ready".to_string(),
        status: "False".to_string(),
        reason: IDLE_STOPPED_REASON.to_string(),
        message: IDLE_STOPPED_MESSAGE.to_string(),
        transition_time: None,
    }
}

/// Whether the stop in flight was started by the idle sweep.
pub fn idle_stop_marked(sandbox: &Sandbox) -> bool {
    sandbox
        .metadata
        .as_ref()
        .is_some_and(|metadata| metadata.annotations.contains_key(IDLE_STOP_ANNOTATION))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::SandboxStatus;

    fn secs(seconds: u64) -> Duration {
        Duration::from_secs(seconds)
    }

    fn proto_secs(seconds: i64) -> prost_types::Duration {
        prost_types::Duration { seconds, nanos: 0 }
    }

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + secs(1_000_000 + seconds)
    }

    fn report(
        state: WorkloadProgramState,
        state_age: i64,
        input_age: Option<i64>,
    ) -> SupervisorWorkloadActivity {
        SupervisorWorkloadActivity {
            state: state.into(),
            blocked_kind: WorkloadBlockedKind::Unspecified.into(),
            app: "claude-code".into(),
            state_age: Some(proto_secs(state_age)),
            input_age: input_age.map(proto_secs),
            reporting_terminals: 1,
            request_id: String::new(),
            sequence: 0,
        }
    }

    fn condition(state: WorkloadProgramState, received: u64) -> SandboxCondition {
        condition_from_report(&report(state, 0, None), at(received)).unwrap()
    }

    fn ready_sandbox(started: u64) -> Sandbox {
        Sandbox {
            status: Some(SandboxStatus {
                phase: SandboxPhase::Ready.into(),
                main_process_instance_id: "instance-1".into(),
                main_process_started_time: timestamp(at(started)),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn live(state: WorkloadProgramState, received: u64, input_age: Option<i64>) -> LiveActivity {
        live_from_report(
            &report(state, 0, input_age),
            "session-1",
            "instance-1",
            true,
            at(received),
        )
    }

    #[test]
    fn report_becomes_condition_at_the_later_of_state_and_input() {
        let done =
            condition_from_report(&report(WorkloadProgramState::Done, 30, Some(90)), at(100))
                .unwrap();
        assert_eq!(done.reason, "Done");
        assert_eq!(done.message, "claude-code is done");
        assert_eq!(system_time(done.transition_time.as_ref()), Some(at(70)));
        let typed =
            condition_from_report(&report(WorkloadProgramState::Done, 30, Some(5)), at(100))
                .unwrap();
        assert_eq!(system_time(typed.transition_time.as_ref()), Some(at(95)));

        let mut blocked = report(WorkloadProgramState::Blocked, 0, None);
        blocked.blocked_kind = WorkloadBlockedKind::Permission.into();
        blocked.app = "bad app\u{1b}".into();
        let blocked = condition_from_report(&blocked, at(0)).unwrap();
        assert_eq!(blocked.message, "badapp is blocked on permission");

        assert!(
            condition_from_report(&report(WorkloadProgramState::Unspecified, 0, None), at(0))
                .is_none()
        );
    }

    #[test]
    fn merge_writes_changes_and_coarse_progress_only() {
        let stored = condition(WorkloadProgramState::Done, 0);
        assert_eq!(
            merge_condition(
                Some(&stored),
                Some(condition(WorkloadProgramState::Done, 20))
            ),
            ConditionWrite::Keep
        );
        let later = condition(WorkloadProgramState::Done, 90);
        assert_eq!(
            merge_condition(Some(&stored), Some(later.clone())),
            ConditionWrite::Set(later)
        );
        let working = condition(WorkloadProgramState::Working, 5);
        assert_eq!(
            merge_condition(Some(&stored), Some(working.clone())),
            ConditionWrite::Set(working)
        );
        assert_eq!(merge_condition(Some(&stored), None), ConditionWrite::Remove);
        assert_eq!(merge_condition(None, None), ConditionWrite::Keep);
    }

    #[test]
    fn setting_values_map_to_timeouts() {
        assert_eq!(timeout_from_setting(None), None);
        assert_eq!(timeout_from_setting(Some(0)), None);
        assert_eq!(timeout_from_setting(Some(-5)), None);
        assert_eq!(timeout_from_setting(Some(600)), Some(secs(600)));
        assert_eq!(
            timeout_from_setting(Some(i64::MAX)),
            Some(secs(30 * 24 * 60 * 60))
        );
    }

    #[test]
    fn waiting_programs_become_due_after_the_timeout_and_report_lag() {
        let sandbox = ready_sandbox(0);
        let done = live(WorkloadProgramState::Done, 100, None);
        assert_eq!(idle_since(&sandbox, &done), Some(at(100)));
        let lag = INPUT_REPORT_LAG.as_secs();
        assert_eq!(
            idle_stop_due(&sandbox, &done, secs(600), at(699 + lag)),
            None
        );
        assert_eq!(
            idle_stop_due(&sandbox, &done, secs(600), at(700 + lag)),
            Some(secs(600 + lag))
        );
        // A later main-process start restarts the wait.
        assert_eq!(idle_since(&ready_sandbox(500), &done), Some(at(500)));
    }

    #[test]
    fn input_moves_the_wait_forward_exactly() {
        // Blocked at 0; input at 45 reported at 50. The timeout counts from 45.
        let sandbox = ready_sandbox(0);
        let blocked = live_from_report(
            &report(WorkloadProgramState::Blocked, 50, Some(5)),
            "session-1",
            "instance-1",
            true,
            at(50),
        );
        assert_eq!(idle_since(&sandbox, &blocked), Some(at(45)));
        assert_eq!(idle_stop_due(&sandbox, &blocked, secs(60), at(60)), None);
    }

    #[test]
    fn working_other_instances_and_non_ready_sandboxes_are_never_idle() {
        let sandbox = ready_sandbox(0);
        assert_eq!(
            idle_since(&sandbox, &live(WorkloadProgramState::Working, 0, None)),
            None
        );
        assert_eq!(
            idle_since(&sandbox, &live(WorkloadProgramState::Unspecified, 0, None)),
            None
        );
        let mut stale = live(WorkloadProgramState::Done, 0, None);
        stale.instance_id = "instance-old".into();
        assert_eq!(idle_since(&sandbox, &stale), None);
        let mut stopping = ready_sandbox(0);
        stopping.status.as_mut().unwrap().phase = SandboxPhase::Stopping.into();
        assert_eq!(
            idle_since(&stopping, &live(WorkloadProgramState::Done, 0, None)),
            None
        );
    }
}
