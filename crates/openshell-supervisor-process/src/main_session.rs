// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Retained I/O multiplexer for the canonical sandbox process.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use nix::pty::Winsize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::sync::broadcast;

use crate::process::ProcessIo;

const OUTPUT_BUFFER_BYTES: usize = 1024 * 1024;
const OUTPUT_CHANNEL_CHUNKS: usize = 512;

#[derive(Clone, Debug)]
pub enum MainOutput {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
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

pub struct MainSession {
    pid: u32,
    terminal: bool,
    input: tokio::sync::mpsc::Sender<Vec<u8>>,
    output: broadcast::Sender<MainOutput>,
    replay: Mutex<(VecDeque<MainOutput>, usize)>,
    input_owner: Mutex<Option<u64>>,
    next_owner: AtomicU64,
    pty_master: Option<Arc<std::fs::File>>,
    readers_remaining: AtomicUsize,
    readers_done: Notify,
}

impl MainSession {
    #[cfg(test)]
    pub fn inert() -> Arc<Self> {
        let (input, _input_rx) = tokio::sync::mpsc::channel(64);
        let (output, _) = broadcast::channel(OUTPUT_CHANNEL_CHUNKS);
        Arc::new(Self {
            pid: 1,
            terminal: false,
            input,
            output,
            replay: Mutex::new((VecDeque::new(), 0)),
            input_owner: Mutex::new(None),
            next_owner: AtomicU64::new(1),
            pty_master: None,
            readers_remaining: AtomicUsize::new(0),
            readers_done: Notify::new(),
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
        let (output, _) = broadcast::channel(OUTPUT_CHANNEL_CHUNKS);
        let pty_master = match &io {
            ProcessIo::Pty(master) => master.try_clone().ok().map(Arc::new),
            ProcessIo::Pipes { .. } => None,
        };
        let session = Arc::new(Self {
            pid,
            terminal,
            input,
            output,
            replay: Mutex::new((VecDeque::new(), 0)),
            input_owner: Mutex::new(None),
            next_owner: AtomicU64::new(1),
            pty_master,
            readers_remaining: AtomicUsize::new(if terminal { 1 } else { 2 }),
            readers_done: Notify::new(),
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
                let mut reader = master.try_clone().expect("PTY master clone");
                let mut writer = master;
                let output = Arc::clone(this);
                std::thread::spawn(move || {
                    let mut buffer = [0u8; 4096];
                    loop {
                        match reader.read(&mut buffer) {
                            Ok(0) | Err(_) => break,
                            Ok(read) => output.publish(MainOutput::Stdout(buffer[..read].to_vec())),
                        }
                    }
                    output.reader_finished();
                });
                std::thread::spawn(move || {
                    while let Some(data) = input_rx.blocking_recv() {
                        if writer.write_all(&data).is_err() {
                            break;
                        }
                        let _ = writer.flush();
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
                                stdout_session.publish(MainOutput::Stdout(buffer[..read].to_vec()));
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
                                stderr_session.publish(MainOutput::Stderr(buffer[..read].to_vec()));
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
        // Keep replay insertion and live publication under one lock. A new
        // subscriber takes this same lock before subscribing, so an event is
        // observed either in the replay snapshot or on the live channel,
        // never both.
        {
            let mut replay = self.replay.lock().expect("main replay lock poisoned");
            replay.1 += event.len();
            replay.0.push_back(event.clone());
            while replay.1 > OUTPUT_BUFFER_BYTES {
                let Some(removed) = replay.0.pop_front() else {
                    break;
                };
                replay.1 = replay.1.saturating_sub(removed.len());
            }
            let _ = self.output.send(event);
        }
    }

    fn reader_finished(&self) {
        if self.readers_remaining.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.readers_done.notify_waiters();
        }
    }

    pub async fn finish(&self, exit_code: i32) {
        let notified = self.readers_done.notified();
        if self.readers_remaining.load(Ordering::Acquire) != 0 {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), notified).await;
        }
        self.publish(MainOutput::Exit(exit_code));
    }

    pub fn subscribe(&self) -> (Vec<MainOutput>, broadcast::Receiver<MainOutput>) {
        let replay = self.replay.lock().expect("main replay lock poisoned");
        let receiver = self.output.subscribe();
        let replay = replay.0.iter().cloned().collect();
        (replay, receiver)
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
        session.publish(MainOutput::Stdout(b"before".to_vec()));

        let (replay, mut live) = session.subscribe();
        assert!(matches!(
            replay.as_slice(),
            [MainOutput::Stdout(data)] if data == b"before"
        ));

        session.publish(MainOutput::Stderr(b"after".to_vec()));
        assert!(matches!(
            live.recv().await.expect("live output"),
            MainOutput::Stderr(data) if data == b"after"
        ));
    }

    #[tokio::test]
    async fn exit_is_replayed_once_to_late_subscribers() {
        let session = MainSession::inert();
        session.finish(0).await;

        let (replay, _live) = session.subscribe();
        assert!(matches!(replay.as_slice(), [MainOutput::Exit(0)]));
    }
}
