use crossterm::event::{self, Event as TermEvent, KeyEvent};
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Debug)]
pub enum Event {
    Key(KeyEvent),
    Tick,
    #[allow(dead_code)]
    Resize(u16, u16),
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
}
