use crossterm::event::{self, Event as TermEvent, KeyEvent, MouseEvent};
use std::time::Duration;
use tokio::sync::mpsc;

use crate::app::LogLine;

/// Per-provider resolution outcome, displayed during create sandbox flow.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ProviderResolution {
    /// Provider already registered on the gateway.
    Exists(String), // provider name
    /// Provider not found on the gateway (user must decide whether to create).
    Missing,
    /// Discovered local credentials, attempting to create on gateway.
    Discovering,
    /// Successfully auto-created on gateway from local credentials.
    Created(String), // provider name
    /// No local credentials found for this type.
    NotFound,
    /// Failed to create on gateway.
    Failed(String), // error message
}

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
    /// Gateway check complete: `(existing: [(type, name)], missing: [type])`.
    GatewayCheckComplete(Vec<(String, String)>, Vec<String>),
    /// Per-provider resolution progress update (during creation phase).
    ProviderStatus(String, ProviderResolution),
    /// Result of a create sandbox request: `Ok(name)` or `Err(message)`.
    CreateResult(Result<String, String>),
}

pub struct EventHandler {
    rx: mpsc::UnboundedReceiver<Event>,
    // Kept alive so the spawned task's `tx` doesn't see a closed channel.
    _keepalive: mpsc::UnboundedSender<Event>,
}

impl EventHandler {
    pub fn new(tick_rate: Duration) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let keepalive = tx.clone();

        tokio::spawn(async move {
            loop {
                if event::poll(tick_rate).unwrap_or(false) {
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
                } else if tx.send(Event::Tick).is_err() {
                    return;
                }
            }
        });

        Self {
            rx,
            _keepalive: keepalive,
        }
    }

    pub async fn next(&mut self) -> Option<Event> {
        self.rx.recv().await
    }

    /// Get a sender handle for dispatching events from background tasks.
    pub fn sender(&self) -> mpsc::UnboundedSender<Event> {
        self._keepalive.clone()
    }
}
