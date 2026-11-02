// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF lifecycle records for processes directly started by this boundary.

use std::sync::OnceLock;

use openshell_isolation_interface::contract::BoundaryExitStatus;
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, LaunchTypeId, OcsfEvent, Process, ProcessActivityBuilder,
    SeverityId, StatusId,
};

use crate::boundary_io::process_parent_and_start;
use openshell_sandbox_backend::boundary_protocol::ProcessIdentityWire;

/// A captured process instance. Keep this across the wait: `/proc/<pid>` may
/// be gone or the PID may have been reused by the time the exit is emitted.
#[derive(Clone)]
pub struct ProcessAudit {
    process: Process,
}

impl ProcessAudit {
    pub fn capture(program: &str, pid: u32) -> Self {
        let mut process = Process::new(program, i64::from(pid));
        if let Some((parent_pid, start_ticks)) = process_parent_and_start(pid) {
            process = with_identity(process, pid, start_ticks);
            let parent_name = if parent_pid == std::process::id() {
                "openshell-sandbox"
            } else {
                "unknown"
            };
            let mut parent = Process::new(parent_name, i64::from(parent_pid));
            if let Some((_, parent_start_ticks)) = process_parent_and_start(parent_pid) {
                parent = with_identity(parent, parent_pid, parent_start_ticks);
            }
            process = process.with_parent(parent);
        }
        Self { process }
    }

    pub fn identity(&self) -> ProcessIdentityWire {
        let parent = self.process.parent_process.as_deref();
        ProcessIdentityWire {
            name: self.process.name.clone(),
            pid: u32::try_from(self.process.pid).expect("captured PID fits u32"),
            uid: self.process.uid.clone(),
            created_time_ms: self.process.created_time,
            parent_pid: parent.and_then(|process| u32::try_from(process.pid).ok()),
            parent_uid: parent.and_then(|process| process.uid.clone()),
            parent_created_time_ms: parent.and_then(|process| process.created_time),
        }
    }

    pub fn launch_event(&self) -> OcsfEvent {
        ProcessActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .activity(ActivityId::Open)
            .action(ActionId::Allowed)
            .disposition(DispositionId::Allowed)
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .launch_type(LaunchTypeId::Spawn)
            .process(self.process.clone())
            .actor_process(crate::process::ocsf_launcher_process())
            .message(format!("Process started: pid={}", self.process.pid))
            .build()
    }

    pub fn terminate_event(&self, status: BoundaryExitStatus) -> OcsfEvent {
        let mut builder = ProcessActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .activity(ActivityId::Close)
            .severity(SeverityId::Informational)
            .process(self.process.clone())
            .actor_process(crate::process::ocsf_launcher_process());
        if let BoundaryExitStatus::Exited(code) = status {
            builder = builder.exit_code(code);
        }
        let mut event = builder.build();
        if let BoundaryExitStatus::Signaled(signal) = status
            && let OcsfEvent::ProcessActivity(process_event) = &mut event
        {
            process_event.base.unmapped = Some(serde_json::json!({"signal": signal}));
        }
        event
    }
}

fn with_identity(mut process: Process, pid: u32, start_ticks: u64) -> Process {
    // The PID is namespace local; the start tick distinguishes reuse in one
    // sandbox lifetime even when two starts round to the same millisecond.
    process = process.with_uid(format!("{pid}:{start_ticks}"));
    if let Some(time_ms) = process_created_time_ms(start_ticks) {
        process = process.with_created_time(time_ms);
    }
    process
}

#[allow(unsafe_code)]
fn process_created_time_ms(start_ticks: u64) -> Option<i64> {
    static CLOCK: OnceLock<Option<(u64, u64)>> = OnceLock::new();
    let (boot_seconds, ticks_per_second) = (*CLOCK.get_or_init(|| {
        let stat = std::fs::read_to_string("/proc/stat").ok()?;
        let boot_seconds = stat
            .lines()
            .find_map(|line| line.strip_prefix("btime "))?
            .parse::<u64>()
            .ok()?;
        // SAFETY: sysconf reads a process-wide kernel parameter and does not
        // access caller-owned memory.
        let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        let ticks_per_second = u64::try_from(ticks_per_second).ok().filter(|hz| *hz > 0)?;
        Some((boot_seconds, ticks_per_second))
    }))?;
    let milliseconds = boot_seconds
        .checked_mul(1_000)?
        .checked_add(start_ticks.checked_mul(1_000)? / ticks_per_second)?;
    i64::try_from(milliseconds).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_a_stable_process_instance_without_arguments() {
        let pid = std::process::id();
        let audit = ProcessAudit::capture("openshell-sandbox", pid);
        let event = audit.launch_event().to_json().unwrap();
        let (_, ticks) = process_parent_and_start(pid).unwrap();
        assert_eq!(event["process"]["pid"], pid);
        assert_eq!(event["process"]["uid"], format!("{pid}:{ticks}"));
        assert!(event["process"]["created_time"].is_i64());
        assert!(event["process"]["cmd_line"].is_null());
    }

    #[test]
    fn normal_and_signal_exits_keep_the_launch_identity() {
        let audit = ProcessAudit::capture("test", std::process::id());
        let launch = audit.launch_event().to_json().unwrap();
        let normal = audit
            .terminate_event(BoundaryExitStatus::Exited(7))
            .to_json()
            .unwrap();
        assert_eq!(normal["process"], launch["process"]);
        assert_eq!(normal["exit_code"], 7);

        let signal = audit
            .terminate_event(BoundaryExitStatus::Signaled(9))
            .to_json()
            .unwrap();
        assert_eq!(signal["process"], launch["process"]);
        assert_eq!(signal["unmapped"]["signal"], 9);
        assert!(signal.get("exit_code").is_none());
    }

    #[test]
    fn a_short_lived_child_keeps_its_identity_after_reaping() {
        let mut child = std::process::Command::new("/bin/true")
            .spawn()
            .expect("spawn child");
        let pid = child.id();
        let audit = ProcessAudit::capture("/bin/true", pid);
        let launch = audit.launch_event().to_json().unwrap();
        let status = child.wait().expect("reap child");
        assert!(process_parent_and_start(pid).is_none());

        let exit = audit
            .terminate_event(BoundaryExitStatus::Exited(status.code().unwrap()))
            .to_json()
            .unwrap();
        assert_eq!(launch["process"], exit["process"]);
        assert_eq!(
            launch["process"]["parent_process"]["pid"],
            std::process::id()
        );
        assert_eq!(launch["process"]["uid"], exit["process"]["uid"]);
        assert_eq!(exit["exit_code"], 0);
    }
}
