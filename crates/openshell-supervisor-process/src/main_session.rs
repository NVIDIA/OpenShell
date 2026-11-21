// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Retained I/O multiplexer for the canonical sandbox process.

#[cfg(test)]
use openshell_sandbox_backend::test_support as rpc_test;

use openshell_sandbox_backend::{BoundaryProcess, BoundaryTerminal, ProcessAttachment};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::sync::watch;

use openshell_isolation_interface::contract::BoundarySignal;

use crate::terminal_state::TerminalState;

const OUTPUT_BUFFER_BYTES: usize = 1024 * 1024;
/// How long an attachment waits for the program to react to the interim
/// size before restoring the real one.
const REDRAW_SETTLE: std::time::Duration = std::time::Duration::from_millis(200);

#[derive(Clone, Debug)]
pub enum MainOutput {
    Stdout(Bytes),
    Stderr(Bytes),
    Exit(i32),
}

impl MainOutput {
    fn len(&self) -> usize {
        match self {
            Self::Stdout(data) | Self::Stderr(data) => data.len(),
            Self::Exit(_) => 0,
        }
    }
}

#[derive(Clone, Debug)]
struct SequencedOutput {
    sequence: u64,
    event: MainOutput,
}

#[derive(Debug)]
struct OutputLogState {
    events: VecDeque<SequencedOutput>,
    retained_bytes: usize,
    next_sequence: u64,
    /// Terminal state at the oldest retained event, built from evicted
    /// output so a replay can start from a matching terminal.
    evicted_terminal: TerminalState,
}

#[derive(Debug)]
struct OutputLog {
    state: Mutex<OutputLogState>,
    terminal: bool,
    version: watch::Sender<u64>,
    terminal_reported: std::sync::atomic::AtomicBool,
    terminal_reported_notify: Notify,
}

impl OutputLog {
    fn new(terminal: bool) -> Arc<Self> {
        let (version, _) = watch::channel(0);
        Arc::new(Self {
            state: Mutex::new(OutputLogState {
                events: VecDeque::new(),
                retained_bytes: 0,
                next_sequence: 0,
                evicted_terminal: TerminalState::default(),
            }),
            terminal,
            version,
            terminal_reported: std::sync::atomic::AtomicBool::new(false),
            terminal_reported_notify: Notify::new(),
        })
    }

    fn publish(&self, event: MainOutput) {
        let version = {
            let mut state = self.state.lock().expect("main output log lock poisoned");
            let sequence = state.next_sequence;
            state.next_sequence = state
                .next_sequence
                .checked_add(1)
                .expect("main output sequence exhausted");
            state.retained_bytes += event.len();
            state.events.push_back(SequencedOutput { sequence, event });
            while state.retained_bytes > OUTPUT_BUFFER_BYTES {
                let Some(removed) = state.events.pop_front() else {
                    break;
                };
                state.retained_bytes = state.retained_bytes.saturating_sub(removed.event.len());
                if self.terminal
                    && let MainOutput::Stdout(data) = &removed.event
                {
                    state.evicted_terminal.advance(data, None);
                }
            }
            state.next_sequence
        };
        self.version.send_replace(version);
    }

    fn subscribe(self: &Arc<Self>) -> (MainOutputCursor, TerminalReplay) {
        let version = self.version.subscribe();
        let state = self.state.lock().expect("main output log lock poisoned");
        let next_sequence = state
            .events
            .front()
            .map_or(state.next_sequence, |retained| retained.sequence);
        let replay = TerminalReplay {
            start: state.evicted_terminal.clone(),
            end: state.next_sequence,
        };
        drop(state);
        let cursor = MainOutputCursor {
            output: Arc::clone(self),
            next_sequence,
            version,
        };
        (cursor, replay)
    }
}

/// Where a TTY attachment's replay of retained output ends, and the terminal
/// state in effect where it begins.
pub struct TerminalReplay {
    pub start: TerminalState,
    /// First sequence produced after the attachment subscribed.
    pub end: u64,
}

#[derive(Debug)]
struct TerminalAttachmentState {
    active: usize,
    process_finished: bool,
    expectation: AttachmentExpectation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttachmentExpectation {
    None,
    Pending,
    Satisfied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MainOutputLagged {
    pub skipped: u64,
}

pub struct MainOutputCursor {
    output: Arc<OutputLog>,
    next_sequence: u64,
    version: watch::Receiver<u64>,
}

impl MainOutputCursor {
    /// Sequence of the next event `recv` returns.
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.next_sequence
    }

    pub async fn recv(&mut self) -> Result<MainOutput, MainOutputLagged> {
        loop {
            let next = {
                let state = self
                    .output
                    .state
                    .lock()
                    .expect("main output log lock poisoned");
                let oldest = state
                    .events
                    .front()
                    .map_or(state.next_sequence, |event| event.sequence);
                if self.next_sequence < oldest {
                    let skipped = oldest - self.next_sequence;
                    self.next_sequence = oldest;
                    return Err(MainOutputLagged { skipped });
                }
                if self.next_sequence >= state.next_sequence {
                    None
                } else {
                    let offset = usize::try_from(self.next_sequence - oldest)
                        .expect("main output cursor offset exceeds usize");
                    let event = state
                        .events
                        .get(offset)
                        .expect("main output cursor references retained event")
                        .event
                        .clone();
                    self.next_sequence += 1;
                    Some(event)
                }
            };
            if let Some(event) = next {
                return Ok(event);
            }
            // The log owns a sender for the cursor lifetime, so closure is not
            // expected. A changed version means there is another event to read.
            let _ = self.version.changed().await;
        }
    }
}

pub struct MainSession {
    terminal: bool,
    input: tokio::sync::mpsc::Sender<Vec<u8>>,
    output: Arc<OutputLog>,
    input_owner: Mutex<Option<u64>>,
    next_owner: AtomicU64,
    boundary_process: Option<Arc<BoundaryProcess>>,
    boundary_terminal: Option<Arc<BoundaryTerminal>>,
    /// Latest size requested for the boundary terminal.
    terminal_size: Mutex<Option<(u16, u16)>>,
    readers_remaining: AtomicUsize,
    readers_done: Notify,
    finished: std::sync::atomic::AtomicBool,
    terminal_attachments: Mutex<TerminalAttachmentState>,
    terminal_attachments_done: Notify,
}

impl MainSession {
    const REMOTE_OUTPUT_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
    #[cfg(test)]
    pub fn inert() -> Arc<Self> {
        Self::inert_with_input().0
    }

    #[cfg(test)]
    pub fn inert_with_input() -> (Arc<Self>, tokio::sync::mpsc::Receiver<Vec<u8>>) {
        Self::inert_session(false)
    }

    /// An inert session whose main process has a TTY.
    #[cfg(test)]
    pub fn inert_terminal() -> (Arc<Self>, tokio::sync::mpsc::Receiver<Vec<u8>>) {
        Self::inert_session(true)
    }

    #[cfg(test)]
    fn inert_session(terminal: bool) -> (Arc<Self>, tokio::sync::mpsc::Receiver<Vec<u8>>) {
        let (input, input_rx) = tokio::sync::mpsc::channel(64);
        let session = Arc::new(Self {
            terminal,
            input,
            output: OutputLog::new(terminal),
            input_owner: Mutex::new(None),
            next_owner: AtomicU64::new(1),
            boundary_process: None,
            boundary_terminal: None,
            terminal_size: Mutex::new(None),
            readers_remaining: AtomicUsize::new(0),
            readers_done: Notify::new(),
            finished: std::sync::atomic::AtomicBool::new(false),
            terminal_attachments: Mutex::new(TerminalAttachmentState {
                active: 0,
                process_finished: false,
                expectation: AttachmentExpectation::None,
            }),
            terminal_attachments_done: Notify::new(),
        });
        (session, input_rx)
    }

    /// Build the control-side multiplexer around a boundary-owned admitted
    /// process. Process lifecycle and PTY operations remain delegated to the
    /// boundary process handle.
    #[must_use]
    pub fn from_boundary(
        attachment: ProcessAttachment,
        process: Arc<BoundaryProcess>,
    ) -> Arc<Self> {
        let ProcessAttachment {
            stdin,
            stdout,
            stderr,
            terminal,
        } = attachment;
        let terminal_mode = terminal.is_some();
        let (input, mut input_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        let session = Arc::new(Self {
            terminal: terminal_mode,
            input,
            output: OutputLog::new(terminal_mode),
            input_owner: Mutex::new(None),
            next_owner: AtomicU64::new(1),
            boundary_process: Some(process),
            boundary_terminal: terminal,
            terminal_size: Mutex::new(None),
            readers_remaining: AtomicUsize::new(if terminal_mode { 1 } else { 2 }),
            readers_done: Notify::new(),
            finished: std::sync::atomic::AtomicBool::new(false),
            terminal_attachments: Mutex::new(TerminalAttachmentState {
                active: 0,
                process_finished: false,
                expectation: AttachmentExpectation::None,
            }),
            terminal_attachments_done: Notify::new(),
        });
        let stdout_session = Arc::clone(&session);
        tokio::spawn(async move {
            let mut stdout = stdout;
            let mut buffer = [0u8; 4096];
            loop {
                match stdout.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => stdout_session
                        .publish(MainOutput::Stdout(Bytes::copy_from_slice(&buffer[..read]))),
                }
            }
            stdout_session.reader_finished();
        });
        if let Some(mut stderr) = stderr {
            let stderr_session = Arc::clone(&session);
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                loop {
                    match stderr.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(read) => stderr_session
                            .publish(MainOutput::Stderr(Bytes::copy_from_slice(&buffer[..read]))),
                    }
                }
                stderr_session.reader_finished();
            });
        }
        tokio::spawn(async move {
            let mut stdin = stdin;
            while let Some(data) = input_rx.recv().await {
                if stdin.write_all(&data).await.is_err() {
                    break;
                }
                let _ = stdin.flush().await;
            }
        });
        session
    }

    #[cfg(all(test, unix))]
    pub(crate) fn publish_test_output(&self, data: &'static [u8]) {
        self.publish(MainOutput::Stdout(Bytes::from_static(data)));
    }

    fn publish(&self, event: MainOutput) {
        self.output.publish(event);
    }

    fn reader_finished(&self) {
        if self.readers_remaining.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.readers_done.notify_waiters();
        }
    }

    /// Publish the terminal event and retain the transport only when a real
    /// foreground attachment exists or the creating client declared one.
    ///
    /// Returns whether terminal delivery must complete before shutdown.
    pub async fn finish(&self, exit_code: i32, attachment_expected: bool) -> bool {
        self.wait_for_output_readers().await;
        self.complete_finish(exit_code, attachment_expected)
    }

    /// Finish a remotely owned process without allowing descendants that keep
    /// inherited output descriptors open to block terminal publication forever.
    pub async fn finish_remote(&self, exit_code: i32, attachment_expected: bool) -> bool {
        self.finish_remote_with_timeout(
            exit_code,
            attachment_expected,
            Self::REMOTE_OUTPUT_DRAIN_TIMEOUT,
        )
        .await
    }

    async fn finish_remote_with_timeout(
        &self,
        exit_code: i32,
        attachment_expected: bool,
        timeout: std::time::Duration,
    ) -> bool {
        let _ = tokio::time::timeout(timeout, self.wait_for_output_readers()).await;
        self.complete_finish(exit_code, attachment_expected)
    }

    async fn wait_for_output_readers(&self) {
        let notified = self.readers_done.notified();
        if self.readers_remaining.load(Ordering::Acquire) != 0 {
            notified.await;
        }
    }

    fn complete_finish(&self, exit_code: i32, attachment_expected: bool) -> bool {
        let delivery_pending = {
            let mut state = self
                .terminal_attachments
                .lock()
                .expect("terminal attachment lock poisoned");
            state.process_finished = true;
            state.expectation = if attachment_expected {
                if state.active == 0 && state.expectation != AttachmentExpectation::Satisfied {
                    AttachmentExpectation::Pending
                } else {
                    AttachmentExpectation::Satisfied
                }
            } else {
                AttachmentExpectation::None
            };
            attachment_expected || state.active != 0
        };
        self.finished.store(true, Ordering::Release);
        self.publish(MainOutput::Exit(exit_code));
        delivery_pending
    }

    pub fn subscribe(&self) -> MainOutputCursor {
        self.output.subscribe().0
    }

    /// Subscribe a terminal attachment, which needs to know where its replay
    /// of retained output ends and the terminal state where it begins.
    #[must_use]
    pub fn subscribe_terminal(&self) -> (MainOutputCursor, TerminalReplay) {
        self.output.subscribe()
    }

    /// Return the bounded output sequence range currently retained for a
    /// replacement supervisor. A nonzero first sequence is an explicit
    /// truncation watermark rather than silent data loss.
    #[must_use]
    pub fn output_window(&self) -> (u64, u64, bool) {
        let state = self
            .output
            .state
            .lock()
            .expect("main output log lock poisoned");
        let first_sequence = state
            .events
            .front()
            .map_or(state.next_sequence, |event| event.sequence);
        (first_sequence, state.next_sequence, first_sequence != 0)
    }

    /// Wait until the gateway durably acknowledges the main-process result.
    pub async fn wait_for_terminal_reported(&self) {
        let notified = self.output.terminal_reported_notify.notified();
        if self.output.terminal_reported.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }

    /// Release attached clients to receive their SSH exit status after the
    /// durable sandbox phase and exit code have been recorded.
    pub fn mark_terminal_reported(&self) {
        self.output.terminal_reported.store(true, Ordering::Release);
        self.output.terminal_reported_notify.notify_waiters();
    }

    /// Register a foreground main attachment while the process is live.
    pub fn begin_terminal_attachment(&self) -> Result<(), &'static str> {
        let mut state = self
            .terminal_attachments
            .lock()
            .expect("terminal attachment lock poisoned");
        if state.process_finished && state.expectation != AttachmentExpectation::Pending {
            return Err("canonical main process already finished");
        }
        state.active = state
            .active
            .checked_add(1)
            .expect("terminal attachment count exhausted");
        state.expectation = AttachmentExpectation::Satisfied;
        self.terminal_attachments_done.notify_waiters();
        Ok(())
    }

    /// Release a foreground main attachment after its SSH channel closes.
    pub fn end_terminal_attachment(&self) {
        let completed = {
            let mut state = self
                .terminal_attachments
                .lock()
                .expect("terminal attachment lock poisoned");
            debug_assert!(state.active != 0, "terminal attachment count underflow");
            if state.active == 0 {
                return;
            }
            state.active -= 1;
            state.active == 0
        };
        if completed {
            self.terminal_attachments_done.notify_waiters();
        }
    }

    /// Wait for the declared foreground attachment to start, then for every
    /// accepted attachment to close naturally.
    pub async fn wait_for_terminal_attachments(&self) {
        loop {
            let notified = self.terminal_attachments_done.notified();
            let complete = {
                let state = self
                    .terminal_attachments
                    .lock()
                    .expect("terminal attachment lock poisoned");
                state.active == 0 && state.expectation != AttachmentExpectation::Pending
            };
            if complete {
                return;
            }
            notified.await;
        }
    }

    pub fn acquire_input(&self) -> Result<(u64, tokio::sync::mpsc::Sender<Vec<u8>>), &'static str> {
        let mut owner = self.input_owner.lock().expect("main input lock poisoned");
        if owner.is_some() {
            return Err("canonical main process already has an input owner");
        }
        let id = self.next_owner.fetch_add(1, Ordering::Relaxed);
        *owner = Some(id);
        Ok((id, self.input.clone()))
    }

    pub fn release_input(&self, id: u64) {
        let mut owner = self.input_owner.lock().expect("main input lock poisoned");
        if *owner == Some(id) {
            *owner = None;
        }
    }

    pub async fn resize(&self, columns: u32, rows: u32, _pixel_width: u32, _pixel_height: u32) {
        let size = terminal_size(columns, rows);
        *self
            .terminal_size
            .lock()
            .expect("terminal size lock poisoned") = Some(size);
        if let Some(terminal) = self.boundary_terminal.as_ref() {
            let _ = terminal.resize(size.0, size.1).await;
        }
    }

    /// Size the terminal for a new attachment and make the program repaint.
    ///
    /// Linux signals `SIGWINCH` only when the size changes, and programs
    /// that receive it compare against the size they last drew for. Moving
    /// through an interim size, as `kubectl attach` does, forces a full
    /// redraw even when the attachment matches the current size. Call this
    /// after subscribing so the redraw follows the replay.
    pub async fn resize_for_attachment(&self, columns: u32, rows: u32) {
        let (columns, rows) = terminal_size(columns, rows);
        *self
            .terminal_size
            .lock()
            .expect("terminal size lock poisoned") = Some((columns, rows));
        let Some(terminal) = self.boundary_terminal.as_ref() else {
            return;
        };
        let interim = if rows > 1 { rows - 1 } else { rows + 1 };
        let mut version = self.output.version.subscribe();
        let _ = terminal.resize(columns, interim).await;
        // Let the program read the interim size, or it may find the size
        // unchanged by the time it handles the signal.
        let _ = tokio::time::timeout(REDRAW_SETTLE, version.changed()).await;
        // A window change during the wait wins over this attachment's size.
        let latest = *self
            .terminal_size
            .lock()
            .expect("terminal size lock poisoned");
        let (columns, rows) = latest.unwrap_or((columns, rows));
        let _ = terminal.resize(columns, rows).await;
    }

    /// Delegate process-group signaling to the isolation backend.
    pub async fn signal_boundary_group(&self, signal: BoundarySignal) -> Result<(), String> {
        let process = self
            .boundary_process
            .as_ref()
            .ok_or_else(|| "no boundary process is attached".to_string())?;
        process
            .signal(signal)
            .await
            .map_err(|error| error.to_string())
    }

    #[must_use]
    pub const fn terminal(&self) -> bool {
        self.terminal
    }

    #[must_use]
    pub fn finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }
}

fn terminal_size(columns: u32, rows: u32) -> (u16, u16) {
    (
        u16::try_from(columns.max(1)).unwrap_or(u16::MAX),
        u16::try_from(rows.max(1)).unwrap_or(u16::MAX),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_isolation_interface::contract::{
        BackendError, BoundaryExitStatus, BoundaryInput, BoundaryOutput,
    };

    struct TestBoundaryProcess {
        signals: Mutex<Vec<BoundarySignal>>,
    }

    #[async_trait::async_trait]
    impl rpc_test::BoundaryProcess for TestBoundaryProcess {
        async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
            Ok(BoundaryExitStatus::Exited(0))
        }

        async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError> {
            self.signals.lock().unwrap().push(signal);
            Ok(())
        }

        async fn terminate(&self) -> Result<(), BackendError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct TestBoundaryTerminal {
        sizes: Mutex<Vec<(u16, u16)>>,
    }

    #[async_trait::async_trait]
    impl rpc_test::BoundaryTerminal for TestBoundaryTerminal {
        async fn resize(&self, cols: u16, rows: u16) -> Result<(), BackendError> {
            self.sizes.lock().unwrap().push((cols, rows));
            Ok(())
        }
    }

    fn terminal_session(
        terminal: Arc<TestBoundaryTerminal>,
    ) -> (Arc<MainSession>, tokio::io::DuplexStream) {
        let (stdin, _stdin_peer) = tokio::io::duplex(1024);
        let (stdout, stdout_peer) = tokio::io::duplex(1024);
        let stdin: BoundaryInput = Box::new(stdin);
        let stdout: BoundaryOutput = Box::new(stdout);
        let attachment = ProcessAttachment {
            stdin,
            stdout,
            stderr: None,
            terminal: Some(rpc_test::terminal(terminal)),
        };
        let process = Arc::new(TestBoundaryProcess {
            signals: Mutex::new(Vec::new()),
        });
        (
            MainSession::from_boundary(attachment, rpc_test::process(process)),
            stdout_peer,
        )
    }

    #[tokio::test]
    async fn boundary_attachment_drives_main_io_signal_and_terminal() {
        let (stdin, mut stdin_peer) = tokio::io::duplex(1024);
        let (stdout, mut stdout_peer) = tokio::io::duplex(1024);
        let process = Arc::new(TestBoundaryProcess {
            signals: Mutex::new(Vec::new()),
        });
        let terminal = Arc::new(TestBoundaryTerminal::default());
        let stdin: BoundaryInput = Box::new(stdin);
        let stdout: BoundaryOutput = Box::new(stdout);
        let attachment = ProcessAttachment {
            stdin,
            stdout,
            stderr: None,
            terminal: Some(rpc_test::terminal(terminal.clone())),
        };
        let session = MainSession::from_boundary(attachment, rpc_test::process(process.clone()));
        let mut output = session.subscribe();

        stdout_peer.write_all(b"ready\n").await.unwrap();
        assert!(matches!(
            output.recv().await.unwrap(),
            MainOutput::Stdout(data) if data == b"ready\n"[..]
        ));

        let (_owner, input) = session.acquire_input().unwrap();
        input.send(b"hello\n".to_vec()).await.unwrap();
        let mut received = [0_u8; 6];
        stdin_peer.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"hello\n");

        session.resize(120, 40, 0, 0).await;
        assert_eq!(*terminal.sizes.lock().unwrap(), vec![(120, 40)]);
        session
            .signal_boundary_group(BoundarySignal::Int)
            .await
            .unwrap();
        assert_eq!(*process.signals.lock().unwrap(), vec![BoundarySignal::Int]);
    }

    #[tokio::test]
    async fn attachment_resize_moves_through_an_interim_size() {
        let terminal = Arc::new(TestBoundaryTerminal::default());
        let (session, _stdout_peer) = terminal_session(terminal.clone());
        session.resize(80, 24, 0, 0).await;
        session.resize_for_attachment(80, 24).await;
        session.resize_for_attachment(100, 1).await;
        assert_eq!(
            *terminal.sizes.lock().unwrap(),
            vec![(80, 24), (80, 23), (80, 24), (100, 2), (100, 1)]
        );
    }

    #[tokio::test]
    async fn attachment_resize_waits_for_the_program_to_react() {
        let terminal = Arc::new(TestBoundaryTerminal::default());
        let (session, mut stdout_peer) = terminal_session(terminal.clone());
        let resize = tokio::spawn({
            let session = session.clone();
            async move { session.resize_for_attachment(120, 40).await }
        });
        while terminal.sizes.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
        assert_eq!(*terminal.sizes.lock().unwrap(), vec![(120, 39)]);
        // A window change while waiting replaces the attachment's size.
        session.resize(132, 50, 0, 0).await;
        stdout_peer.write_all(b"redraw").await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), resize)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            *terminal.sizes.lock().unwrap(),
            vec![(120, 39), (132, 50), (132, 50)]
        );
    }

    #[tokio::test]
    async fn terminal_replay_starts_from_the_state_of_evicted_output() {
        let (session, _input) = MainSession::inert_terminal();
        session.publish(MainOutput::Stdout(Bytes::from_static(
            b"\x1b[?1049h\x1b[?2004h\x1b[?10",
        )));
        let filler = Bytes::from(vec![b'x'; OUTPUT_BUFFER_BYTES]);
        session.publish(MainOutput::Stdout(filler.clone()));
        let (cursor, replay) = session.subscribe_terminal();
        assert_eq!(cursor.position(), 1);
        assert_eq!(replay.end, 2);
        assert_eq!(replay.start.restore_sequence(), b"\x1b[?1049h\x1b[?2004h");

        // Non-terminal sessions keep no terminal state.
        let (session, _input) = MainSession::inert_with_input();
        session.publish(MainOutput::Stdout(Bytes::from_static(b"\x1b[?1049h")));
        session.publish(MainOutput::Stdout(filler));
        assert_eq!(session.subscribe_terminal().1.start.restore_sequence(), b"");
    }

    #[test]
    fn input_lease_has_one_owner_and_can_be_reacquired() {
        let session = MainSession::inert();
        let (first, _) = session.acquire_input().expect("first owner");
        assert!(session.acquire_input().is_err());

        session.release_input(first);
        let (second, _) = session.acquire_input().expect("replacement owner");
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn subscribers_receive_replay_then_live_output() {
        let session = MainSession::inert();
        session.publish(MainOutput::Stdout(Bytes::from_static(b"before")));

        let mut output = session.subscribe();
        assert!(matches!(
            output.recv().await.expect("replayed output"),
            MainOutput::Stdout(data) if data == b"before"[..]
        ));

        session.publish(MainOutput::Stderr(Bytes::from_static(b"after")));
        assert!(matches!(
            output.recv().await.expect("live output"),
            MainOutput::Stderr(data) if data == b"after"[..]
        ));
    }

    #[tokio::test]
    async fn finish_without_attachment_does_not_defer_shutdown() {
        let session = MainSession::inert();
        assert!(!session.finish(0, false).await);
        assert!(session.finished());
        assert!(session.begin_terminal_attachment().is_err());
    }

    #[tokio::test]
    async fn terminal_report_acknowledgement_is_independent_from_delivery() {
        let session = MainSession::inert();

        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                session.wait_for_terminal_reported(),
            )
            .await
            .is_err(),
            "draining output must not imply durable gateway persistence"
        );

        session.mark_terminal_reported();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            session.wait_for_terminal_reported(),
        )
        .await
        .expect("durable report acknowledgement should wake waiter");
    }

    #[tokio::test]
    async fn finish_waits_for_an_active_attachment_to_close_naturally() {
        let session = MainSession::inert();
        session
            .begin_terminal_attachment()
            .expect("begin terminal attachment");
        assert!(session.finish(0, false).await);

        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                session.wait_for_terminal_attachments(),
            )
            .await
            .is_err(),
            "an active attachment must keep terminal delivery open"
        );

        session.end_terminal_attachment();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            session.wait_for_terminal_attachments(),
        )
        .await
        .expect("closing the attachment should wake the waiter");
    }

    #[tokio::test]
    async fn remote_finish_bounds_output_drain_before_publishing_exit() {
        let mut session = MainSession::inert();
        Arc::get_mut(&mut session)
            .expect("sole test session reference")
            .readers_remaining = AtomicUsize::new(1);
        let mut output = session.subscribe();

        session
            .finish_remote_with_timeout(19, false, std::time::Duration::from_millis(10))
            .await;

        assert!(matches!(
            output
                .recv()
                .await
                .expect("terminal status after bounded drain"),
            MainOutput::Exit(19)
        ));
    }

    #[tokio::test]
    async fn declared_attachment_waits_for_connection_then_natural_close() {
        let session = MainSession::inert();
        assert!(session.finish(0, true).await);

        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                session.wait_for_terminal_attachments(),
            )
            .await
            .is_err(),
            "declared attachment must connect before delivery is complete"
        );

        session
            .begin_terminal_attachment()
            .expect("declared post-exit attachment");
        session.end_terminal_attachment();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            session.wait_for_terminal_attachments(),
        )
        .await
        .expect("natural attachment close should complete delivery");
    }

    #[tokio::test]
    async fn exit_is_retained_in_the_output_log() {
        let session = MainSession::inert();
        let _ = session.finish(0, false).await;

        let mut output = session.subscribe();
        assert!(matches!(
            output.recv().await.expect("replayed exit"),
            MainOutput::Exit(0)
        ));
    }

    #[tokio::test]
    async fn slow_subscriber_reports_evicted_events_then_resumes() {
        let session = MainSession::inert();
        let mut output = session.subscribe();
        let chunk = Bytes::from(vec![0; 4096]);
        for _ in 0..=(OUTPUT_BUFFER_BYTES / chunk.len()) {
            session.publish(MainOutput::Stdout(chunk.clone()));
        }

        let lag = output.recv().await.expect_err("oldest event was evicted");
        assert_eq!(lag.skipped, 1);
        assert!(matches!(
            output.recv().await.expect("resume at oldest retained event"),
            MainOutput::Stdout(data) if data.len() == chunk.len()
        ));
    }

    #[tokio::test]
    async fn signaling_without_boundary_is_rejected() {
        let session = MainSession::inert();
        assert_eq!(
            session
                .signal_boundary_group(BoundarySignal::Term)
                .await
                .unwrap_err(),
            "no boundary process is attached"
        );
    }
}
