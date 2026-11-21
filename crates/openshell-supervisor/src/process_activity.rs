// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF Process Activity for the processes the sandbox runtime starts
//! directly, the entrypoint and exec sessions, and for each exec in the
//! workload when the `ocsf_process_exec_enabled` setting asks for them.

use std::sync::LazyLock;
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

/// The `ocsf_process_exec_enabled` setting, `None` until it is applied.
static EXEC_EVENTS: LazyLock<tokio::sync::watch::Sender<Option<bool>>> =
    LazyLock::new(|| tokio::sync::watch::Sender::new(None));

/// Ask the runtime to record, or stop recording, each exec in the workload.
pub fn request_exec_events(enabled: bool) {
    if EXEC_EVENTS.send_if_modified(|current| current.replace(enabled) != Some(enabled)) {
        tracing::info!(
            ocsf_process_exec_enabled = enabled,
            "OCSF exec events toggled"
        );
    }
}

#[cfg(test)]
pub fn exec_events_requested() -> bool {
    EXEC_EVENTS.borrow().unwrap_or_default()
}

/// Reads process events from `source` and emits them until dropped.
pub struct ProcessActivityRelay(tokio::task::JoinHandle<()>);

impl Drop for ProcessActivityRelay {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub fn start(source: ProcessEventSource) -> ProcessActivityRelay {
    ProcessActivityRelay(tokio::spawn(relay(
        source,
        EXEC_EVENTS.subscribe(),
        |event| ocsf_emit!(event),
    )))
}

/// The runtime's process event reads the relay makes.
trait ProcessEventReader {
    fn records_executions(&self) -> bool;
    fn read(
        &self,
        after_sequence: u64,
        executions: Option<bool>,
    ) -> impl Future<Output = Result<(Vec<ProcessEventWire>, u64), BackendError>> + Send;
}

impl ProcessEventReader for ProcessEventSource {
    fn records_executions(&self) -> bool {
        Self::records_executions(self)
    }
    fn read(
        &self,
        after_sequence: u64,
        executions: Option<bool>,
    ) -> impl Future<Output = Result<(Vec<ProcessEventWire>, u64), BackendError>> + Send {
        Self::read(self, after_sequence, executions)
    }
}

async fn relay(
    source: impl ProcessEventReader,
    mut exec_events: tokio::sync::watch::Receiver<Option<bool>>,
    emit: impl Fn(OcsfEvent),
) {
    let mut cursor = Cursor::default();
    let mut failing = false;
    let mut executions = None;
    loop {
        let requested = *exec_events.borrow_and_update();
        if requested != executions {
            executions = requested;
            if executions == Some(true) && !source.records_executions() {
                tracing::warn!("the sandbox runtime does not record exec events");
            }
        }
        // A changed setting reissues the read so the runtime applies it.
        let read = tokio::select! {
            read = source.read(cursor.after, executions) => read,
            _ = exec_events.changed() => continue,
        };
        match read {
            Ok((events, lost)) => {
                failing = false;
                for event in cursor.accept(events, lost) {
                    emit(event);
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
}

/// Sequence cursor over the runtime's process events.
#[derive(Default)]
struct Cursor {
    after: u64,
}

impl Cursor {
    fn accept(&mut self, events: Vec<ProcessEventWire>, lost: u64) -> Vec<OcsfEvent> {
        // A first read was never sent what the runtime evicted before it.
        let lost = (lost > 0 && self.after > 0).then(|| lost_events(lost));
        lost.into_iter()
            .chain(events.into_iter().map(|event| {
                self.after = self.after.max(event.sequence);
                process_activity(&event)
            }))
            .collect()
    }
}

/// Events the runtime evicted before this supervisor read them.
fn lost_events(lost: u64) -> OcsfEvent {
    let executable = std::env::current_exe().map_or_else(
        |_| "openshell-supervisor".to_string(),
        |path| path.display().to_string(),
    );
    let supervisor = Process::new(&executable, i64::from(std::process::id()));
    ProcessActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Other)
        .severity(SeverityId::Low)
        .status(StatusId::Failure)
        .count(lost)
        .process(supervisor.clone())
        .actor_process(supervisor)
        .message(format!(
            "Process events lost: lost={lost} evicted before they were read"
        ))
        .build()
}

fn named(executable: &str) -> &str {
    if executable.is_empty() {
        "-"
    } else {
        executable
    }
}

fn process_activity(event: &ProcessEventWire) -> OcsfEvent {
    let instance = event.process;
    let process = |parent: Process| {
        Process::new(named(&event.executable), i64::from(instance.pid))
            .with_parent(parent)
            .with_instance(instance.parent_pid, instance.start_time_ms)
    };
    let launcher = || Process::new("openshell-sandbox", i64::from(instance.parent_pid));
    match &event.kind {
        ProcessEventKindWire::Launched => process_change(event, "launch", launcher())
            .process(process(launcher()))
            .activity(ActivityId::Open)
            .launch_type(LaunchTypeId::Spawn)
            .message(format!("Process started: pid={}", instance.pid))
            .build(),
        ProcessEventKindWire::Executed {
            previous_executable,
            parent_executable,
        } => {
            let before = Process::new(named(previous_executable), i64::from(instance.pid))
                .with_instance(instance.parent_pid, instance.start_time_ms);
            let parent = Process::new(named(parent_executable), i64::from(instance.parent_pid));
            // A process can exec more than once; the runtime's sequence tells
            // those apart.
            process_change(event, &format!("exec/{}", event.sequence), before)
                // Recorded before the kernel runs the exec, which can still fail.
                .action(ActionId::Unknown)
                .disposition(DispositionId::Unknown)
                .status(StatusId::Unknown)
                .process(process(parent))
                .activity(ActivityId::Open)
                .launch_type(LaunchTypeId::Exec)
                .message(format!("Process executed: pid={}", instance.pid))
                .build()
        }
        ProcessEventKindWire::Exited(status) => {
            let (code, detail) = exit_code(*status);
            process_change(event, "exit", launcher())
                .process(process(launcher()))
                .activity(ActivityId::Close)
                .exit_code(code)
                .message(format!("Process exited: pid={} {detail}", instance.pid))
                .build()
        }
        ProcessEventKindWire::Ended(status) => {
            let parent = Process::new("-", i64::from(instance.parent_pid));
            let exited = process_change(event, "exit", process(parent.clone()))
                .process(process(parent))
                .activity(ActivityId::Close);
            match *status {
                Some(status) => {
                    let (code, detail) = exit_code(status);
                    exited
                        .exit_code(code)
                        .message(format!("Process exited: pid={} {detail}", instance.pid))
                }
                // Its parent reaped it before the runtime read its status.
                None => exited
                    .status(StatusId::Unknown)
                    .message(format!("Process exited: pid={}", instance.pid)),
            }
            .build()
        }
        ProcessEventKindWire::Suppressed { count } => {
            let runtime = Process::new(named(&event.executable), i64::from(instance.pid))
                .with_instance(instance.parent_pid, instance.start_time_ms);
            let ctx = openshell_ocsf::ctx::ctx();
            let uid = format!(
                "{}/{}/{}/suppressed/{}",
                ctx.sandbox_id, instance.pid, instance.start_time_ms, event.sequence
            );
            ProcessActivityBuilder::new(ctx)
                .uid(uid)
                .activity(ActivityId::Other)
                .severity(SeverityId::Low)
                .status(StatusId::Failure)
                .count(*count)
                .time(event.time_ms)
                .process(runtime.clone())
                .actor_process(runtime)
                .message(format!(
                    "Process events suppressed: suppressed={count} not recorded"
                ))
                .build()
        }
    }
}

/// The OCSF exit code for `status`, with signals as 128 plus the signal, and
/// the status for a message.
fn exit_code(status: ExitStatusWire) -> (i32, String) {
    match status {
        ExitStatusWire::Exited(code) => (code, format!("exit={code}")),
        ExitStatusWire::Signaled(signal) => {
            (128_i32.saturating_add(signal), format!("signal={signal}"))
        }
    }
}

/// A launch, exec, or exit the workload made, reported once per `transition`
/// of the process instance: a replacement supervisor that reads it again
/// reports the same uid.
fn process_change<'a>(
    event: &ProcessEventWire,
    transition: &str,
    actor: Process,
) -> ProcessActivityBuilder<'a, openshell_ocsf::builders::HasActor> {
    let instance = event.process;
    let ctx = openshell_ocsf::ctx::ctx();
    let uid = format!(
        "{}/{}/{}/{transition}",
        ctx.sandbox_id, instance.pid, instance.start_time_ms
    );
    ProcessActivityBuilder::new(ctx)
        .action(ActionId::Allowed)
        .disposition(DispositionId::Allowed)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .time(event.time_ms)
        .uid(uid)
        .actor_process(actor)
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
    fn an_exec_becomes_a_launch_of_the_new_executable_under_the_same_pid() {
        let exec = ProcessEventWire {
            sequence: 9,
            process: ProcessInstance {
                pid: 58,
                parent_pid: 57,
                start_time_ms: 1_793_750_400_300,
            },
            executable: "/usr/bin/true".to_string(),
            kind: ProcessEventKindWire::Executed {
                previous_executable: "/usr/bin/dash".to_string(),
                parent_executable: "/usr/bin/bash".to_string(),
            },
            time_ms: 1_793_750_400_310,
        };
        let emitted = process_activity(&exec);
        let json = serde_json::to_value(&emitted).unwrap();
        assert_eq!(json["activity_name"], "Launch");
        assert_eq!(json["launch_type"], "Exec");
        assert_eq!(json["process"]["name"], "/usr/bin/true");
        assert_eq!(json["process"]["pid"], 58);
        assert_eq!(json["process"]["created_time"], 1_793_750_400_300_i64);
        assert_eq!(json["process"]["parent_process"]["name"], "/usr/bin/bash");
        assert_eq!(json["process"]["parent_process"]["pid"], 57);
        assert_eq!(json["actor"]["process"]["name"], "/usr/bin/dash");
        assert_eq!(json["actor"]["process"]["pid"], 58);
        assert_eq!(json["time"], 1_793_750_400_310_i64);
        // The exec is recorded before the kernel runs it, so it claims no outcome.
        assert_eq!(json["action_id"], 0);
        assert_eq!(json["disposition_id"], 0);
        assert_eq!(json["status_id"], 0);
        assert!(
            json["metadata"]["uid"]
                .as_str()
                .unwrap()
                .ends_with("/58/1793750400300/exec/9")
        );
        assert!(
            emitted
                .format_shorthand()
                .contains("PROC:LAUNCH [INFO] /usr/bin/true(58)")
        );
    }

    #[test]
    fn a_descendant_exit_becomes_a_terminate_by_the_process_itself() {
        let ended = |status| ProcessEventWire {
            sequence: 11,
            process: ProcessInstance {
                pid: 58,
                parent_pid: 57,
                start_time_ms: 1_793_750_400_300,
            },
            executable: "/usr/bin/true".to_string(),
            kind: ProcessEventKindWire::Ended(status),
            time_ms: 1_793_750_400_500,
        };
        let known = process_activity(&ended(Some(ExitStatusWire::Exited(3))));
        let json = serde_json::to_value(&known).unwrap();
        assert_eq!(json["activity_name"], "Terminate");
        assert_eq!(json["exit_code"], 3);
        assert_eq!(json["status"], "Success");
        assert_eq!(json["process"]["name"], "/usr/bin/true");
        assert_eq!(json["process"]["parent_process"]["pid"], 57);
        assert_eq!(json["actor"]["process"]["name"], "/usr/bin/true");
        assert_eq!(json["actor"]["process"]["pid"], 58);
        assert!(
            json["metadata"]["uid"]
                .as_str()
                .unwrap()
                .ends_with("/58/1793750400300/exit")
        );
        assert!(
            known
                .format_shorthand()
                .contains("PROC:TERMINATE [INFO] /usr/bin/true(58) [exit:3]")
        );

        let unknown = serde_json::to_value(process_activity(&ended(None))).unwrap();
        assert_eq!(unknown["activity_name"], "Terminate");
        assert_eq!(unknown["status_id"], 0);
        assert!(unknown.get("exit_code").is_none());
        assert_eq!(unknown["message"], "Process exited: pid=58");
    }

    #[test]
    fn suppressed_and_lost_events_become_counted_drop_records() {
        let suppressed = ProcessEventWire {
            sequence: 10,
            process: ProcessInstance {
                pid: 1,
                parent_pid: 0,
                start_time_ms: 1_793_750_000_000,
            },
            executable: "/opt/openshell/bin/openshell-sandbox".to_string(),
            kind: ProcessEventKindWire::Suppressed { count: 12 },
            time_ms: 1_793_750_400_400,
        };
        let mut cursor = Cursor { after: 6 };
        let emitted = cursor.accept(vec![suppressed], 3);
        assert_eq!(cursor.after, 10);
        assert_eq!(emitted.len(), 2);

        let lost = serde_json::to_value(&emitted[0]).unwrap();
        assert_eq!(lost["class_name"], "Process Activity");
        assert_eq!(lost["activity_name"], "Other");
        assert_eq!(lost["status"], "Failure");
        assert_eq!(lost["count"], 3);
        assert!(lost["message"].as_str().unwrap().contains("lost=3"));

        let suppressed = serde_json::to_value(&emitted[1]).unwrap();
        assert_eq!(suppressed["activity_name"], "Other");
        assert_eq!(suppressed["count"], 12);
        assert_eq!(suppressed["actor"]["process"]["pid"], 1);
        assert_eq!(
            suppressed["actor"]["process"]["name"],
            "/opt/openshell/bin/openshell-sandbox"
        );
        assert!(
            suppressed["message"]
                .as_str()
                .unwrap()
                .contains("suppressed=12")
        );
        assert!(
            suppressed["metadata"]["uid"]
                .as_str()
                .unwrap()
                .ends_with("/1/1793750000000/suppressed/10")
        );
    }

    /// A supervisor that starts reading from the beginning was never sent
    /// what the runtime evicted, so it reports no loss.
    #[test]
    fn a_first_read_reports_no_lost_events() {
        let mut cursor = Cursor::default();
        let emitted = cursor.accept(vec![event(5, ProcessEventKindWire::Launched)], 4);
        assert_eq!(emitted.len(), 1);
        assert_eq!(
            serde_json::to_value(&emitted[0]).unwrap()["activity_name"],
            "Launch"
        );
        assert_eq!(cursor.after, 5);
    }

    #[test]
    fn process_activity_validates_against_the_ocsf_schema() {
        let mut cursor = Cursor::default();
        let events = cursor.accept(
            vec![
                event(4, ProcessEventKindWire::Launched),
                event(
                    5,
                    ProcessEventKindWire::Executed {
                        previous_executable: "/usr/bin/sh".to_string(),
                        parent_executable: "/usr/bin/bash".to_string(),
                    },
                ),
                event(6, ProcessEventKindWire::Exited(ExitStatusWire::Signaled(9))),
                event(7, ProcessEventKindWire::Suppressed { count: 12 }),
                event(
                    8,
                    ProcessEventKindWire::Ended(Some(ExitStatusWire::Exited(0))),
                ),
                event(9, ProcessEventKindWire::Ended(None)),
            ],
            3,
        );
        let events: Vec<_> = events
            .into_iter()
            .chain(Cursor { after: 7 }.accept(Vec::new(), 2))
            .collect();
        assert_eq!(events.len(), 7);
        for event in events {
            let json = event.to_json().unwrap();
            openshell_ocsf_validate::validate_event(&json).unwrap_or_else(|e| panic!("{e}"));
        }
    }

    /// Each read reports the setting it carried, and the first read waits
    /// like an idle long poll.
    struct IdleReader(std::sync::Mutex<Vec<Option<bool>>>);

    impl ProcessEventReader for &IdleReader {
        fn records_executions(&self) -> bool {
            true
        }
        async fn read(
            &self,
            _after_sequence: u64,
            executions: Option<bool>,
        ) -> Result<(Vec<ProcessEventWire>, u64), BackendError> {
            let first = {
                let mut reads = self.0.lock().unwrap();
                reads.push(executions);
                reads.len() == 1
            };
            if first {
                std::future::pending::<()>().await;
            }
            Err(BackendError::Terminated("done".to_string()))
        }
    }

    /// A read before the setting is known leaves the runtime's choice as it
    /// is, so a replacement supervisor does not turn recording off.
    #[tokio::test]
    async fn a_setting_change_reissues_the_waiting_read() {
        let reader = IdleReader(std::sync::Mutex::default());
        let (setting, exec_events) = tokio::sync::watch::channel(None);
        let relayed = relay(&reader, exec_events, |_| {});
        let toggle = async {
            while reader.0.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
            setting.send(Some(true)).unwrap();
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(relayed, toggle);
        })
        .await
        .expect("relay reissued its read");
        assert_eq!(*reader.0.lock().unwrap(), [None, Some(true)]);
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
