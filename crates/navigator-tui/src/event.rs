// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crossterm::event::{self, Event as TermEvent, KeyEvent, MouseEvent};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;

use crate::app::LogLine;

#[derive(Debug)]
pub enum Event {
    Key(KeyEvent),
    Mouse(MouseEvent),
    Tick,
    /// Lightweight redraw trigger (no data refresh). Used for animations.
    Redraw,
    #[allow(dead_code)]
    Resize(u16, u16),
    /// A batch of log lines from the streaming log task.
    LogLines(Vec<LogLine>),
    /// Result of a create sandbox request: `Ok(name)` or `Err(message)`.
    CreateResult(Result<String, String>),
    /// Result of creating a provider on the gateway: `Ok(name)` or `Err(message)`.
    ProviderCreateResult(Result<String, String>),
    /// Provider detail fetched from gateway.
    ProviderDetailFetched(Result<Box<navigator_core::proto::Provider>, String>),
    /// Provider update result: `Ok(name)` or `Err(message)`.
    ProviderUpdateResult(Result<String, String>),
    /// Provider delete result: `Ok(deleted)` or `Err(message)`.
    ProviderDeleteResult(Result<bool, String>),
}

pub struct EventHandler {
    rx: mpsc::UnboundedReceiver<Event>,
    // Kept alive so the spawned task's `tx` doesn't see a closed channel.
    _keepalive: mpsc::UnboundedSender<Event>,
    /// When true, the background reader stops polling stdin.
    paused: Arc<AtomicBool>,
}

impl EventHandler {
    pub fn new(tick_rate: Duration) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let keepalive = tx.clone();
        let paused = Arc::new(AtomicBool::new(false));
        let paused_flag = paused.clone();

        tokio::spawn(async move {
            // Use a short poll interval so we check the paused flag frequently.
            // The tick event fires when the full tick_rate elapses without input.
            let poll_interval = Duration::from_millis(50);
            let mut since_tick = std::time::Instant::now();

            loop {
                // When paused, sleep instead of polling stdin so the child
                // process (e.g. SSH shell) gets uncontested access to stdin.
                if paused_flag.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    since_tick = std::time::Instant::now();
                    continue;
                }

                if event::poll(poll_interval).unwrap_or(false) {
                    match event::read() {
                        Ok(TermEvent::Key(key)) => {
                            if tx.send(Event::Key(key)).is_err() {
                                return;
                            }
                        }
                        Ok(TermEvent::Mouse(mouse)) => {
                            if tx.send(Event::Mouse(mouse)).is_err() {
                                return;
                            }
                        }
                        Ok(TermEvent::Resize(w, h)) => {
                            if tx.send(Event::Resize(w, h)).is_err() {
                                return;
                            }
                        }
                        _ => {}
                    }
                } else if since_tick.elapsed() >= tick_rate {
                    since_tick = std::time::Instant::now();
                    if tx.send(Event::Tick).is_err() {
                        return;
                    }
                }
            }
        });

        Self {
            rx,
            _keepalive: keepalive,
            paused,
        }
    }

    pub async fn next(&mut self) -> Option<Event> {
        self.rx.recv().await
    }

    /// Get a sender handle for dispatching events from background tasks.
    pub fn sender(&self) -> mpsc::UnboundedSender<Event> {
        self._keepalive.clone()
    }

    /// Pause stdin polling (call before suspending TUI for a child process).
    pub fn pause(&self) {
        self.paused.store(true, Ordering::Relaxed);
    }

    /// Resume stdin polling (call after child process exits and TUI resumes).
    pub fn resume(&self) {
        self.paused.store(false, Ordering::Relaxed);
    }
}
