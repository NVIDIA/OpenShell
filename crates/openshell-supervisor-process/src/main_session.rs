// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Retained I/O multiplexer for the canonical sandbox process.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::pty::Winsize;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::sync::watch;

use crate::process::ProcessIo;

const OUTPUT_BUFFER_BYTES: usize = 1024 * 1024;

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
}

#[derive(Debug)]
struct OutputLog {
    state: Mutex<OutputLogState>,
    version: watch::Sender<u64>,
    terminal_reported: std::sync::atomic::AtomicBool,
    terminal_reported_notify: Notify,
}

impl OutputLog {
    fn new() -> Arc<Self> {
        let (version, _) = watch::channel(0);
        Arc::new(Self {
            state: Mutex::new(OutputLogState {
                events: VecDeque::new(),
                retained_bytes: 0,
                next_sequence: 0,
            }),
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
            }
            state.next_sequence
        };
        self.version.send_replace(version);
    }

    fn subscribe(self: &Arc<Self>) -> MainOutputCursor {
        let version = self.version.subscribe();
        let state = self.state.lock().expect("main output log lock poisoned");
        let next_sequence = state
            .events
            .front()
            .map_or(state.next_sequence, |retained| retained.sequence);
        drop(state);
        MainOutputCursor {
            output: Arc::clone(self),
            next_sequence,
            version,
        }
    }
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
    pid: u32,
    terminal: bool,
    input: tokio::sync::mpsc::Sender<Vec<u8>>,
    output: Arc<OutputLog>,
    input_owner: Mutex<Option<u64>>,
    next_owner: AtomicU64,
    pty_master: Option<Arc<std::fs::File>>,
    readers_remaining: AtomicUsize,
    readers_done: Notify,
    finished: std::sync::atomic::AtomicBool,
    terminal_attachments: Mutex<TerminalAttachmentState>,
    terminal_attachments_done: Notify,
}

impl MainSession {
    #[cfg(test)]
    pub fn inert() -> Arc<Self> {
        let (input, _input_rx) = tokio::sync::mpsc::channel(64);
        Arc::new(Self {
            pid: 1,
            terminal: false,
            input,
            output: OutputLog::new(),
            input_owner: Mutex::new(None),
            next_owner: AtomicU64::new(1),
            pty_master: None,
            readers_remaining: AtomicUsize::new(0),
            readers_done: Notify::new(),
            finished: std::sync::atomic::AtomicBool::new(false),
            terminal_attachments: Mutex::new(TerminalAttachmentState {
                active: 0,
                process_finished: false,
                expectation: AttachmentExpectation::None,
            }),
            terminal_attachments_done: Notify::new(),
        })
    }

    #[cfg(test)]
    pub fn terminal_for_test() -> (Arc<Self>, std::fs::File) {
        let pty = nix::pty::openpty(None, None).expect("open test PTY");
        let slave = std::fs::File::from(pty.slave);
        (
            Self::new(ProcessIo::Pty(std::fs::File::from(pty.master)), 1),
            slave,
        )
    }

    #[cfg(test)]
    #[allow(unsafe_code)]
    pub fn terminal_size_for_test(&self) -> (u16, u16) {
        let master = self.pty_master.as_ref().expect("terminal PTY master");
        let mut winsize: libc::winsize = unsafe { std::mem::zeroed() };
        let result = unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCGWINSZ, &mut winsize) };
        assert_eq!(result, 0, "read terminal dimensions");
        (winsize.ws_col, winsize.ws_row)
    }

    #[must_use]
    pub fn new(io: ProcessIo, pid: u32) -> Arc<Self> {
        let terminal = matches!(io, ProcessIo::Pty(_));
        let (input, input_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        let pty_master = match &io {
            ProcessIo::Pty(master) => {
                set_nonblocking(master).expect("set canonical PTY master nonblocking");
                master.try_clone().ok().map(Arc::new)
            }
            ProcessIo::Pipes { .. } => None,
        };
        let session = Arc::new(Self {
            pid,
            terminal,
            input,
            output: OutputLog::new(),
            input_owner: Mutex::new(None),
            next_owner: AtomicU64::new(1),
            pty_master,
            readers_remaining: AtomicUsize::new(if terminal { 1 } else { 2 }),
            readers_done: Notify::new(),
            finished: std::sync::atomic::AtomicBool::new(false),
            terminal_attachments: Mutex::new(TerminalAttachmentState {
                active: 0,
                process_finished: false,
                expectation: AttachmentExpectation::None,
            }),
            terminal_attachments_done: Notify::new(),
        });
        Self::start_io(&session, io, input_rx);
        session
    }

    fn start_io(
        this: &Arc<Self>,
        io: ProcessIo,
        mut input_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) {
        match io {
            ProcessIo::Pty(master) => {
                let master = Arc::new(AsyncFd::new(master).expect("register canonical PTY master"));
                let reader = Arc::clone(&master);
                let output = Arc::clone(this);
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    loop {
                        let Ok(mut ready) = reader.readable().await else {
                            break;
                        };
                        match ready.try_io(|inner| {
                            let mut file = inner.get_ref();
                            file.read(&mut buffer)
                        }) {
                            Ok(Ok(0) | Err(_)) => break,
                            Ok(Ok(read)) => output.publish(MainOutput::Stdout(
                                Bytes::copy_from_slice(&buffer[..read]),
                            )),
                            Err(_would_block) => {}
                        }
                    }
                    output.reader_finished();
                });
                tokio::spawn(async move {
                    while let Some(data) = input_rx.recv().await {
                        let mut remaining = data.as_slice();
                        while !remaining.is_empty() {
                            let Ok(mut ready) = master.writable().await else {
                                return;
                            };
                            match ready.try_io(|inner| {
                                let mut file = inner.get_ref();
                                file.write(remaining)
                            }) {
                                Ok(Ok(0) | Err(_)) => return,
                                Ok(Ok(written)) => remaining = &remaining[written..],
                                Err(_would_block) => {}
                            }
                        }
                    }
                });
            }
            ProcessIo::Pipes {
                mut stdin,
                mut stdout,
                mut stderr,
            } => {
                let stdout_session = Arc::clone(this);
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    loop {
                        match stdout.read(&mut buffer).await {
                            Ok(0) | Err(_) => break,
                            Ok(read) => {
                                stdout_session.publish(MainOutput::Stdout(Bytes::copy_from_slice(
                                    &buffer[..read],
                                )));
                            }
                        }
                    }
                    stdout_session.reader_finished();
                });
                let stderr_session = Arc::clone(this);
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    loop {
                        match stderr.read(&mut buffer).await {
                            Ok(0) | Err(_) => break,
                            Ok(read) => {
                                stderr_session.publish(MainOutput::Stderr(Bytes::copy_from_slice(
                                    &buffer[..read],
                                )));
                            }
                        }
                    }
                    stderr_session.reader_finished();
                });
                tokio::spawn(async move {
                    while let Some(data) = input_rx.recv().await {
                        if stdin.write_all(&data).await.is_err() {
                            break;
                        }
                        let _ = stdin.flush().await;
                    }
                });
            }
        }
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
        let notified = self.readers_done.notified();
        if self.readers_remaining.load(Ordering::Acquire) != 0 {
            notified.await;
        }
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
        self.output.subscribe()
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

    pub fn resize(&self, columns: u32, rows: u32, pixel_width: u32, pixel_height: u32) {
        let Some(master) = self.pty_master.as_ref() else {
            return;
        };
        let winsize = Winsize {
            ws_row: u16::try_from(rows.max(1)).unwrap_or(u16::MAX),
            ws_col: u16::try_from(columns.max(1)).unwrap_or(u16::MAX),
            ws_xpixel: u16::try_from(pixel_width).unwrap_or(u16::MAX),
            ws_ypixel: u16::try_from(pixel_height).unwrap_or(u16::MAX),
        };
        #[allow(unsafe_code)]
        unsafe {
            libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &winsize);
        }
    }

    pub fn signal_group(&self, signal: nix::sys::signal::Signal) -> Result<(), nix::errno::Errno> {
        let pid = i32::try_from(self.pid).unwrap_or(i32::MAX);
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(-pid), signal)
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

fn set_nonblocking(file: &std::fs::File) -> Result<(), nix::errno::Errno> {
    let flags = fcntl(file.as_raw_fd(), FcntlArg::F_GETFL)?;
    let flags = OFlag::from_bits_truncate(flags);
    fcntl(
        file.as_raw_fd(),
        FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    async fn terminal_pump_reads_output_and_writes_input() {
        let (session, mut slave) = MainSession::terminal_for_test();
        set_nonblocking(&slave).expect("set test PTY slave nonblocking");
        let mut output = session.subscribe();

        slave
            .write_all(b"process output")
            .expect("write PTY output");
        let event = tokio::time::timeout(std::time::Duration::from_secs(1), output.recv())
            .await
            .expect("PTY output timed out")
            .expect("PTY output was retained");
        assert!(matches!(
            event,
            MainOutput::Stdout(data) if data == b"process output"[..]
        ));

        let (owner, input) = session.acquire_input().expect("acquire PTY input");
        input
            .send(b"client input\n".to_vec())
            .await
            .expect("queue PTY input");
        let mut received = [0; 64];
        let read = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                match slave.read(&mut received) {
                    Ok(read) => break read,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("read PTY input: {error}"),
                }
            }
        })
        .await
        .expect("PTY input timed out");
        assert_eq!(&received[..read], b"client input\n");
        session.release_input(owner);
    }
}
