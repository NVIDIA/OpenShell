// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SSH session token storage and cleanup.

use openshell_core::ObjectId;
use openshell_core::proto::SshSession;
use openshell_core::time::now_ms;
use prost::Message;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

use crate::persistence::{ObjectCursor, ObjectType, Store};

const SESSION_REAPER_PAGE_SIZE: u32 = 1000;

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
    reap_expired_sessions_after_page(store, |_| std::future::ready(())).await
}

async fn reap_expired_sessions_after_page<F, Fut>(
    store: &Store,
    mut after_page: F,
) -> Result<(), String>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = ()>,
{
    let now_ms = now_ms();
    let started = std::time::Instant::now();
    let mut cursor = None;
    let mut page_number = 0_usize;
    let mut scanned = 0_usize;
    let mut decode_failures = 0_usize;
    let mut session_ids = Vec::new();

    loop {
        let records = store
            .list_by_type_after(
                SshSession::object_type(),
                cursor.as_ref(),
                SESSION_REAPER_PAGE_SIZE,
            )
            .await
            .map_err(|e| e.to_string())?;
        let page_len = records.len();
        scanned += page_len;

        cursor = records.last().map(ObjectCursor::from);
        for record in records {
            let Ok(session) = SshSession::decode(record.payload.as_slice()) else {
                decode_failures += 1;
                continue;
            };
            if (session.expires_at_ms > 0 && now_ms > session.expires_at_ms) || session.revoked {
                session_ids.push(session.object_id().to_string());
            }
        }

        if page_len < SESSION_REAPER_PAGE_SIZE as usize {
            break;
        }
        page_number += 1;
        after_page(page_number).await;
    }

    let matched = session_ids.len();
    let deleted = store
        .delete_many(SshSession::object_type(), &session_ids)
        .await
        .map_err(|e| e.to_string())?;
    if matched > 0 || decode_failures > 0 {
        info!(
            scanned,
            matched,
            deleted,
            decode_failures,
            elapsed_ms = started.elapsed().as_millis(),
            "SSH session reaper sweep complete"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    async fn test_store() -> Store {
        crate::persistence::test_store().await
    }

    fn make_session(id: &str, sandbox_id: &str, expires_at_ms: i64, revoked: bool) -> SshSession {
        SshSession {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: id.to_string(),
                name: format!("session-{id}"),
                created_at_ms: 1000,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            sandbox_id: sandbox_id.to_string(),
            token: id.to_string(),
            expires_at_ms,
            revoked,
        }
    }

    #[tokio::test]
    async fn reaper_deletes_expired_sessions() {
        let store = test_store().await;

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
        let store = test_store().await;

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
        let store = test_store().await;

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

    #[tokio::test]
    async fn reaper_batches_expired_and_revoked_sessions() {
        let store = test_store().await;
        let session_count = crate::persistence::DELETE_MANY_BATCH_SIZE + 9;
        for idx in 0..session_count {
            let session = make_session(
                &format!("reap-{idx}"),
                "sbx1",
                if idx % 2 == 0 { now_ms() - 1 } else { 0 },
                idx % 2 != 0,
            );
            store.put_message(&session).await.unwrap();
        }
        let active = make_session("keep", "sbx1", now_ms() + 60_000, false);
        store.put_message(&active).await.unwrap();

        reap_expired_sessions(&store).await.unwrap();

        assert_eq!(
            store
                .count_in_workspace(SshSession::object_type(), "default")
                .await
                .unwrap(),
            1
        );
        assert!(
            store
                .get_message::<SshSession>("keep")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn reaper_removes_every_expired_session_when_an_earlier_page_row_is_deleted() {
        let store = test_store().await;
        for idx in 0..=SESSION_REAPER_PAGE_SIZE {
            let session = make_session(&format!("reap-{idx:04}"), "sbx1", now_ms() - 1, false);
            store.put_message(&session).await.unwrap();
        }

        let delete_store = store.clone();
        reap_expired_sessions_after_page(&store, move |page_number| {
            let delete_store = delete_store.clone();
            async move {
                if page_number == 1 {
                    delete_store
                        .delete(SshSession::object_type(), "reap-0000")
                        .await
                        .unwrap();
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(
            store
                .count_in_workspace(SshSession::object_type(), "default")
                .await
                .unwrap(),
            0,
            "the reaper must not leave an expired session behind"
        );
    }
}
