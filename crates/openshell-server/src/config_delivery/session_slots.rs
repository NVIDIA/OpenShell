// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Latest-wins configuration slots for one supervisor session stream.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use futures::task::AtomicWaker;
use openshell_core::proto::GatewayMessage;
use tokio::sync::mpsc;
use tonic::Status;

use super::ConfigComponentKind;

/// One unsent snapshot per component. A newer snapshot replaces an unsent one,
/// so a slow stream holds at most one message per component.
#[derive(Debug, Default)]
pub struct ConfigSlots {
    pending: Mutex<PendingSlots>,
    waker: AtomicWaker,
}

#[derive(Debug, Default)]
struct PendingSlots {
    next_order: u64,
    sandbox_config: Option<(u64, GatewayMessage)>,
    provider_environment: Option<(u64, GatewayMessage)>,
}

impl ConfigSlots {
    /// Returns true when an unsent snapshot was replaced.
    pub(crate) fn replace(&self, component: ConfigComponentKind, message: GatewayMessage) -> bool {
        let replaced = {
            let mut pending = self.pending.lock().unwrap();
            let order = pending.next_order;
            pending.next_order += 1;
            let slot = match component {
                ConfigComponentKind::SandboxConfig => &mut pending.sandbox_config,
                ConfigComponentKind::ProviderEnvironment => &mut pending.provider_environment,
            };
            slot.replace((order, message)).is_some()
        };
        self.waker.wake();
        replaced
    }

    fn take_oldest(&self) -> Option<GatewayMessage> {
        let mut pending = self.pending.lock().unwrap();
        let sandbox_first = match (&pending.sandbox_config, &pending.provider_environment) {
            (Some((sandbox, _)), Some((provider, _))) => sandbox < provider,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => return None,
        };
        let slot = if sandbox_first {
            pending.sandbox_config.take()
        } else {
            pending.provider_environment.take()
        };
        slot.map(|(_, message)| message)
    }
}

/// Session stream that sends queued control frames before configuration.
///
/// `SessionAccepted` is queued on the control channel before the session can
/// receive configuration, so it always stays first.
pub struct SessionOutbound {
    control: mpsc::Receiver<GatewayMessage>,
    config: Arc<ConfigSlots>,
}

impl SessionOutbound {
    pub(crate) fn new(control: mpsc::Receiver<GatewayMessage>, config: Arc<ConfigSlots>) -> Self {
        Self { control, config }
    }
}

impl tokio_stream::Stream for SessionOutbound {
    type Item = Result<GatewayMessage, Status>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.control.poll_recv(cx) {
            Poll::Ready(Some(message)) => return Poll::Ready(Some(Ok(message))),
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Pending => {}
        }
        this.config.waker.register(cx.waker());
        this.config
            .take_oldest()
            .map_or(Poll::Pending, |message| Poll::Ready(Some(Ok(message))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{ConfigUpdate, RelayOpen, gateway_message};
    use tokio_stream::StreamExt;

    fn config(update_id: &str) -> GatewayMessage {
        GatewayMessage {
            payload: Some(gateway_message::Payload::ConfigUpdate(ConfigUpdate {
                update_id: update_id.into(),
                ..Default::default()
            })),
        }
    }

    fn relay_open() -> GatewayMessage {
        GatewayMessage {
            payload: Some(gateway_message::Payload::RelayOpen(RelayOpen::default())),
        }
    }

    fn update_id(message: GatewayMessage) -> String {
        match message.payload {
            Some(gateway_message::Payload::ConfigUpdate(update)) => update.update_id,
            other => panic!("expected a configuration update, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn control_frames_go_before_queued_configuration() {
        let (tx, rx) = mpsc::channel(4);
        let slots = Arc::new(ConfigSlots::default());
        let mut outbound = SessionOutbound::new(rx, Arc::clone(&slots));
        assert!(!slots.replace(ConfigComponentKind::SandboxConfig, config("config")));
        tx.send(relay_open()).await.unwrap();

        let first = outbound.next().await.unwrap().unwrap();
        assert!(matches!(
            first.payload,
            Some(gateway_message::Payload::RelayOpen(_))
        ));
        assert_eq!(update_id(outbound.next().await.unwrap().unwrap()), "config");
    }

    #[tokio::test]
    async fn newer_snapshot_replaces_an_unsent_one() {
        let (_tx, rx) = mpsc::channel(4);
        let slots = Arc::new(ConfigSlots::default());
        let mut outbound = SessionOutbound::new(rx, Arc::clone(&slots));
        assert!(!slots.replace(ConfigComponentKind::SandboxConfig, config("old")));
        assert!(!slots.replace(ConfigComponentKind::ProviderEnvironment, config("provider")));
        assert!(slots.replace(ConfigComponentKind::SandboxConfig, config("new")));

        assert_eq!(
            update_id(outbound.next().await.unwrap().unwrap()),
            "provider"
        );
        assert_eq!(update_id(outbound.next().await.unwrap().unwrap()), "new");
    }

    #[tokio::test]
    async fn waiting_stream_wakes_for_configuration() {
        let (_tx, rx) = mpsc::channel(4);
        let slots = Arc::new(ConfigSlots::default());
        let mut outbound = SessionOutbound::new(rx, Arc::clone(&slots));
        let next = tokio::spawn(async move { outbound.next().await.unwrap().unwrap() });
        tokio::task::yield_now().await;
        slots.replace(ConfigComponentKind::ProviderEnvironment, config("late"));
        assert_eq!(update_id(next.await.unwrap()), "late");
    }

    #[tokio::test]
    async fn stream_ends_with_the_control_channel() {
        let (tx, rx) = mpsc::channel(4);
        let slots = Arc::new(ConfigSlots::default());
        let mut outbound = SessionOutbound::new(rx, Arc::clone(&slots));
        slots.replace(ConfigComponentKind::SandboxConfig, config("discarded"));
        drop(tx);
        assert!(outbound.next().await.is_none());
    }
}
