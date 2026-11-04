// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded log of launch and exit events for the workload processes this
//! runtime starts, read by the supervisor with a sequence cursor.

use std::collections::VecDeque;
use std::sync::{Condvar, LazyLock, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openshell_isolation_interface::contract::ProcessInstance;
use openshell_sandbox_backend::boundary_protocol::{
    ExitStatusWire, ProcessEventKindWire, ProcessEventWire,
};

const CAPACITY: usize = 4096;
/// Most events in one response.
pub const MAX_READ: usize = 256;
/// Encoded size one response stays under, half the control message limit.
const MAX_READ_BYTES: usize = 512 * 1024;
/// How long a read with nothing to return waits for an event.
pub const READ_WAIT: Duration = Duration::from_secs(30);

static LOG: LazyLock<ProcessEventLog> = LazyLock::new(|| ProcessEventLog::new(CAPACITY));

/// The runtime's process event log.
pub fn log() -> &'static ProcessEventLog {
    &LOG
}

/// A launch recorded in the log, kept until the runtime reaps the process.
pub struct Launched {
    process: ProcessInstance,
    executable: String,
}

/// Record the launch of a process the runtime just spawned from `program`.
/// `None` when procfs no longer reports it.
pub fn record_launch(pid: u32, program: &str) -> Option<Launched> {
    let Some(process) = openshell_binary_identity::observe_process(pid) else {
        tracing::warn!(
            pid,
            "process not visible in procfs; launch and exit not recorded"
        );
        return None;
    };
    // A process that already exited has no readable executable link.
    let executable = std::fs::read_link(format!("/proc/{pid}/exe"))
        .map_or_else(|_| program.to_string(), |path| path.display().to_string());
    log().record(process, &executable, ProcessEventKindWire::Launched);
    Some(Launched {
        process,
        executable,
    })
}

impl Launched {
    pub fn record_exit(&self, status: ExitStatusWire) {
        log().record(
            self.process,
            &self.executable,
            ProcessEventKindWire::Exited(status),
        );
    }
}

pub struct ProcessEventLog {
    capacity: usize,
    state: Mutex<State>,
    changed: Condvar,
}

struct State {
    events: VecDeque<ProcessEventWire>,
    next_sequence: u64,
}

impl ProcessEventLog {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            state: Mutex::new(State {
                events: VecDeque::new(),
                next_sequence: 1,
            }),
            changed: Condvar::new(),
        }
    }

    pub fn record(&self, process: ProcessInstance, executable: &str, kind: ProcessEventKindWire) {
        let time_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
            .unwrap_or_default();
        let mut state = self.lock();
        let sequence = state.next_sequence;
        state.next_sequence += 1;
        if state.events.len() == self.capacity {
            state.events.pop_front();
        }
        state.events.push_back(ProcessEventWire {
            sequence,
            process,
            executable: executable.to_string(),
            kind,
            time_ms,
        });
        drop(state);
        self.changed.notify_all();
    }

    /// Up to `max` events after `after` that fit the response budget, and how
    /// many events after `after` were evicted. Waits up to `wait` when there
    /// is nothing to return.
    pub fn read(&self, after: u64, max: usize, wait: Duration) -> (Vec<ProcessEventWire>, u64) {
        let state = self.lock();
        let (state, _) = self
            .changed
            .wait_timeout_while(state, wait, |state| {
                state.next_sequence <= after.saturating_add(1)
            })
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let first = state
            .events
            .front()
            .map_or(state.next_sequence, |event| event.sequence);
        let lost = first.saturating_sub(after.saturating_add(1));
        let mut budget = MAX_READ_BYTES;
        let events = state
            .events
            .iter()
            .filter(|event| event.sequence > after)
            .take(max)
            .enumerate()
            .take_while(|(index, event)| {
                let size = encoded_size(event);
                let fits = *index == 0 || size <= budget;
                budget = budget.saturating_sub(size);
                fits
            })
            .map(|(_, event)| event.clone())
            .collect();
        (events, lost)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// An upper bound on one event's encoded size.
fn encoded_size(event: &ProcessEventWire) -> usize {
    event.executable.len() + 128
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Instant;

    fn process(pid: u32) -> ProcessInstance {
        ProcessInstance {
            pid,
            parent_pid: 1,
            start_time_ms: 1_000,
        }
    }

    #[test]
    fn read_returns_events_after_the_cursor_in_order() {
        let log = ProcessEventLog::new(8);
        log.record(process(10), "/bin/sh", ProcessEventKindWire::Launched);
        log.record(
            process(10),
            "/bin/sh",
            ProcessEventKindWire::Exited(ExitStatusWire::Exited(3)),
        );
        log.record(process(11), "/bin/true", ProcessEventKindWire::Launched);

        let (events, lost) = log.read(1, MAX_READ, Duration::ZERO);
        assert_eq!(lost, 0);
        assert_eq!(
            events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            [2, 3]
        );
        assert_eq!(
            events[0].kind,
            ProcessEventKindWire::Exited(ExitStatusWire::Exited(3))
        );
        assert_eq!(events[1].process.pid, 11);

        let (events, _) = log.read(0, 1, Duration::ZERO);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sequence, 1);
    }

    #[test]
    fn evicted_events_after_the_cursor_are_counted_as_lost() {
        let log = ProcessEventLog::new(2);
        for pid in 1..=5 {
            log.record(process(pid), "/bin/true", ProcessEventKindWire::Launched);
        }

        let (events, lost) = log.read(1, MAX_READ, Duration::ZERO);
        assert_eq!(lost, 2);
        assert_eq!(
            events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            [4, 5]
        );
        let (_, lost) = log.read(4, MAX_READ, Duration::ZERO);
        assert_eq!(lost, 0);
    }

    #[test]
    fn a_read_stops_before_the_response_byte_budget() {
        let log = ProcessEventLog::new(MAX_READ);
        let path = format!("/{}", "a".repeat(4095));
        for pid in 1..=u32::try_from(MAX_READ).unwrap() {
            log.record(process(pid), &path, ProcessEventKindWire::Launched);
        }

        let (events, _) = log.read(0, MAX_READ, Duration::ZERO);
        assert!(!events.is_empty());
        assert!(events.len() < MAX_READ);
        let bytes: usize = events.iter().map(encoded_size).sum();
        assert!(bytes <= MAX_READ_BYTES);

        let mut read = events.len();
        let mut after = events.last().unwrap().sequence;
        loop {
            let (events, _) = log.read(after, MAX_READ, Duration::ZERO);
            let Some(last) = events.last() else { break };
            after = last.sequence;
            read += events.len();
        }
        assert_eq!(read, MAX_READ);
    }

    #[test]
    fn an_event_records_when_it_happened() {
        let log = ProcessEventLog::new(8);
        let before = now_ms();
        log.record(process(7), "/bin/sh", ProcessEventKindWire::Launched);
        let (events, _) = log.read(0, MAX_READ, Duration::ZERO);
        assert!(events[0].time_ms >= before);
        assert!(events[0].time_ms <= now_ms());
    }

    fn now_ms() -> i64 {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()
    }

    #[test]
    fn an_empty_read_waits_for_the_next_event() {
        let log = Arc::new(ProcessEventLog::new(8));
        let started = Instant::now();
        let (events, lost) = log.read(0, MAX_READ, Duration::from_millis(50));
        assert!(events.is_empty());
        assert_eq!(lost, 0);
        assert!(started.elapsed() >= Duration::from_millis(50));

        let writer = log.clone();
        let recorder = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            writer.record(process(7), "/bin/sh", ProcessEventKindWire::Launched);
        });
        let (events, _) = log.read(0, MAX_READ, Duration::from_secs(10));
        recorder.join().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].process.pid, 7);
    }
}
