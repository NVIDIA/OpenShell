// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SSH session token storage and cleanup.

use openshell_core::ObjectId;
use openshell_core::proto::SshSession;
use prost::Message;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

use crate::persistence::{ObjectType, Store};

impl ObjectType for SshSession {
    fn object_type() -> &'static str {
        "ssh_session"
    }
}

/// Spawn a background task that periodically reaps expired and revoked SSH sessions.
pub fn spawn_session_reaper(store: Arc<Store>, interval: Duration) {
    tokio::spawn(async move {
        tokio::time::sleep(interval).await;

        loop {
            if let Err(e) = reap_expired_sessions(&store).await {
                warn!(error = %e, "SSH session reaper sweep failed");
            }
            tokio::time::sleep(interval).await;
        }
    });
}

async fn reap_expired_sessions(store: &Store) -> Result<(), String> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let records = store
        .list(SshSession::object_type(), 1000, 0)
        .await
        .map_err(|e| e.to_string())?;

    let mut reaped = 0u32;
    for record in records {
        let session: SshSession = match Message::decode(record.payload.as_slice()) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let should_delete =
            (session.expires_at_ms > 0 && now_ms > session.expires_at_ms) || session.revoked;

        if should_delete {
            if let Err(e) = store
                .delete(SshSession::object_type(), session.object_id())
                .await
            {
                warn!(session_id = %session.object_id(), error = %e, "Failed to reap SSH session");
            } else {
                reaped += 1;
            }
        }
    }

    if reaped > 0 {
        info!(count = reaped, "SSH session reaper: cleaned up sessions");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_session(id: &str, sandbox_id: &str, expires_at_ms: i64, revoked: bool) -> SshSession {
        SshSession {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: id.to_string(),
                name: format!("session-{id}"),
                created_at_ms: 1000,
                labels: HashMap::new(),
            }),
            sandbox_id: sandbox_id.to_string(),
            token: id.to_string(),
            expires_at_ms,
            revoked,
        }
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }

    #[tokio::test]
    async fn reaper_deletes_expired_sessions() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        let expired = make_session("expired1", "sbx1", now_ms() - 60_000, false);
        store.put_message(&expired).await.unwrap();

        let valid = make_session("valid1", "sbx1", now_ms() + 3_600_000, false);
        store.put_message(&valid).await.unwrap();

        reap_expired_sessions(&store).await.unwrap();

        assert!(
            store
                .get_message::<SshSession>("expired1")
                .await
                .unwrap()
                .is_none(),
            "expired session should be reaped"
        );
        assert!(
            store
                .get_message::<SshSession>("valid1")
                .await
                .unwrap()
                .is_some(),
            "valid session should be kept"
        );
    }

    #[tokio::test]
    async fn reaper_deletes_revoked_sessions() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        let revoked = make_session("revoked1", "sbx1", 0, true);
        store.put_message(&revoked).await.unwrap();

        let active = make_session("active1", "sbx1", 0, false);
        store.put_message(&active).await.unwrap();

        reap_expired_sessions(&store).await.unwrap();

        assert!(
            store
                .get_message::<SshSession>("revoked1")
                .await
                .unwrap()
                .is_none(),
            "revoked session should be reaped"
        );
        assert!(
            store
                .get_message::<SshSession>("active1")
                .await
                .unwrap()
                .is_some(),
            "active session should be kept"
        );
    }

    #[tokio::test]
    async fn reaper_preserves_zero_expiry_sessions() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        let no_expiry = make_session("noexpiry1", "sbx1", 0, false);
        store.put_message(&no_expiry).await.unwrap();

        reap_expired_sessions(&store).await.unwrap();

        assert!(
            store
                .get_message::<SshSession>("noexpiry1")
                .await
                .unwrap()
                .is_some(),
            "session with no expiry should be preserved"
        );
    }
}
