// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF Process Activity for the processes the sandbox runtime starts
//! directly: the entrypoint and exec sessions.

use std::time::Duration;

use openshell_isolation_interface::contract::BackendError;
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, LaunchTypeId, OcsfEvent, Process, ProcessActivityBuilder,
    SeverityId, StatusId, ocsf_emit,
};
use openshell_sandbox_backend::ProcessEventSource;
use openshell_sandbox_backend::boundary_protocol::{
    ExitStatusWire, ProcessEventKindWire, ProcessEventWire,
};

const RETRY_DELAY: Duration = Duration::from_secs(1);

/// Reads process events from `source` and emits them until dropped.
pub struct ProcessActivityRelay(tokio::task::JoinHandle<()>);

impl Drop for ProcessActivityRelay {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub fn start(source: ProcessEventSource) -> ProcessActivityRelay {
    ProcessActivityRelay(tokio::spawn(async move {
        let mut cursor = Cursor::default();
        let mut failing = false;
        loop {
            match source.read(cursor.after).await {
                Ok((events, lost)) => {
                    failing = false;
                    for event in cursor.accept(events, lost) {
                        ocsf_emit!(event);
                    }
                }
                Err(BackendError::Terminated(_)) => return,
                Err(BackendError::Unavailable(error)) => {
                    tracing::warn!(%error, "sandbox process events unavailable; no longer reading them");
                    return;
                }
                Err(error) => {
                    if failing {
                        tracing::debug!(%error, "reading sandbox process events failed; retrying");
                    } else {
                        tracing::warn!(%error, "reading sandbox process events failed; retrying");
                    }
                    failing = true;
                    tokio::time::sleep(RETRY_DELAY).await;
                }
            }
        }
    }))
}

/// Sequence cursor over the runtime's process events.
#[derive(Default)]
struct Cursor {
    after: u64,
}

impl Cursor {
    fn accept(&mut self, events: Vec<ProcessEventWire>, lost: u64) -> Vec<OcsfEvent> {
        if lost > 0 {
            tracing::warn!(
                lost,
                "sandbox runtime dropped process events before they were read"
            );
        }
        events
            .into_iter()
            .map(|event| {
                self.after = self.after.max(event.sequence);
                process_activity(&event)
            })
            .collect()
    }
}

fn process_activity(event: &ProcessEventWire) -> OcsfEvent {
    let instance = event.process;
    let launcher = || Process::new("openshell-sandbox", i64::from(instance.parent_pid));
    let name = if event.executable.is_empty() {
        "-"
    } else {
        event.executable.as_str()
    };
    let process = Process::new(name, i64::from(instance.pid))
        .with_parent(launcher())
        .with_instance(instance.parent_pid, instance.start_time_ms);
    let kind = match event.kind {
        ProcessEventKindWire::Launched => "launch",
        ProcessEventKindWire::Exited(_) => "exit",
    };
    let ctx = openshell_ocsf::ctx::ctx();
    // The process instance and transition identify the activity, so a
    // replacement supervisor that reads it again reports the same uid.
    let uid = format!(
        "{}/{}/{}/{kind}",
        ctx.sandbox_id, instance.pid, instance.start_time_ms
    );
    let builder = ProcessActivityBuilder::new(ctx)
        .action(ActionId::Allowed)
        .disposition(DispositionId::Allowed)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .process(process)
        .time(event.time_ms)
        .uid(uid)
        .actor_process(launcher());
    match event.kind {
        ProcessEventKindWire::Launched => builder
            .activity(ActivityId::Open)
            .launch_type(LaunchTypeId::Spawn)
            .message(format!("Process started: pid={}", instance.pid))
            .build(),
        ProcessEventKindWire::Exited(status) => {
            let (code, detail) = match status {
                ExitStatusWire::Exited(code) => (code, format!("exit={code}")),
                ExitStatusWire::Signaled(signal) => {
                    (128_i32.saturating_add(signal), format!("signal={signal}"))
                }
            };
            builder
                .activity(ActivityId::Close)
                .exit_code(code)
                .message(format!("Process exited: pid={} {detail}", instance.pid))
                .build()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_isolation_interface::contract::ProcessInstance;
    use openshell_sandbox_backend::boundary_protocol::{ExitStatusWire, ProcessEventKindWire};

    fn event(sequence: u64, kind: ProcessEventKindWire) -> ProcessEventWire {
        ProcessEventWire {
            sequence,
            process: ProcessInstance {
                pid: 57,
                parent_pid: 1,
                start_time_ms: 1_793_750_400_123,
            },
            executable: "/usr/bin/sh".to_string(),
            kind,
            time_ms: 1_793_750_400_200 + i64::try_from(sequence).unwrap(),
        }
    }

    #[test]
    fn launch_and_exit_become_process_activity() {
        let mut cursor = Cursor::default();
        let emitted = cursor.accept(
            vec![
                event(1, ProcessEventKindWire::Launched),
                event(2, ProcessEventKindWire::Exited(ExitStatusWire::Exited(3))),
                event(3, ProcessEventKindWire::Exited(ExitStatusWire::Signaled(9))),
            ],
            0,
        );
        assert_eq!(cursor.after, 3);

        let launch = serde_json::to_value(&emitted[0]).unwrap();
        assert_eq!(launch["class_name"], "Process Activity");
        assert_eq!(launch["activity_name"], "Launch");
        assert_eq!(launch["process"]["name"], "/usr/bin/sh");
        assert_eq!(launch["process"]["pid"], 57);
        assert_eq!(launch["process"]["created_time"], 1_793_750_400_123_i64);
        assert_eq!(launch["process"]["parent_process"]["pid"], 1);
        assert_eq!(launch["actor"]["process"]["name"], "openshell-sandbox");
        assert_eq!(launch["actor"]["process"]["pid"], 1);

        let exit = serde_json::to_value(&emitted[1]).unwrap();
        assert_eq!(exit["activity_name"], "Terminate");
        assert_eq!(exit["exit_code"], 3);
        assert_eq!(exit["process"]["created_time"], 1_793_750_400_123_i64);
        assert!(
            emitted[1]
                .format_shorthand()
                .contains("PROC:TERMINATE [INFO] /usr/bin/sh(57) [exit:3]")
        );

        let killed = serde_json::to_value(&emitted[2]).unwrap();
        assert_eq!(killed["exit_code"], 137);
    }

    #[test]
    fn a_replayed_event_keeps_its_time_and_uid() {
        let launch = event(1, ProcessEventKindWire::Launched);
        let first = serde_json::to_value(process_activity(&launch)).unwrap();
        let replayed = serde_json::to_value(process_activity(&launch)).unwrap();
        assert_eq!(first["time"], 1_793_750_400_201_i64);
        assert_eq!(replayed["time"], first["time"]);
        assert_eq!(replayed["metadata"]["uid"], first["metadata"]["uid"]);

        let exit = event(2, ProcessEventKindWire::Exited(ExitStatusWire::Exited(0)));
        let exit = serde_json::to_value(process_activity(&exit)).unwrap();
        assert_ne!(exit["metadata"]["uid"], first["metadata"]["uid"]);
    }

    #[test]
    fn the_cursor_advances_past_events_it_reads() {
        let mut cursor = Cursor::default();
        cursor.accept(vec![event(7, ProcessEventKindWire::Launched)], 6);
        assert_eq!(cursor.after, 7);
        assert!(cursor.accept(Vec::new(), 0).is_empty());
        assert_eq!(cursor.after, 7);
    }
}
