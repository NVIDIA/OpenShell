// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Durable mutation admission accounting shared by both backends.
//!
//! Each caller bucket has a counter row. Admission increments it under the
//! bucket lock. Deleting admissions marks the counter for recount instead of
//! decrementing it, and admission recounts a full counter only when it is marked
//! or was last written over a minute ago. A rejection at capacity therefore reads
//! one row, and counts left stale by writers that do not maintain counters, such
//! as older gateway versions, correct themselves within a minute.

use super::{PersistenceResult, WriteResult, current_time_ms};

pub const ADMISSION_OBJECT_TYPE: &str = "mutation_admission_v1";
pub(super) const COUNTER_OBJECT_TYPE: &str = "mutation_admission_count_v1";
/// Counter `status` while deleted admissions are not yet reflected in its count.
pub(super) const RECOUNT_STATUS: &str = "recount";
const RECOUNT_INTERVAL_MS: i64 = 60_000;

pub(super) fn counter_id(bucket: &str) -> String {
    format!("mutation-admission-count:{bucket}")
}

/// A completed admission selected for expiry checks.
pub struct CompletedAdmission {
    pub id: String,
    pub payload: Vec<u8>,
}

pub(super) struct Counter {
    pub count: i64,
    pub recount: bool,
    pub updated_at_ms: i64,
}

/// Backend statements run inside one transaction that holds the bucket lock.
pub(super) trait AdmissionTx {
    async fn counter(&mut self, bucket: &str) -> PersistenceResult<Option<Counter>>;
    async fn count(&mut self, bucket: &str) -> PersistenceResult<i64>;
    async fn insert(
        &mut self,
        id: &str,
        name: &str,
        bucket: &str,
        payload: &[u8],
        now_ms: i64,
    ) -> PersistenceResult<()>;
    async fn put_counter(
        &mut self,
        bucket: &str,
        counter: &Counter,
        now_ms: i64,
    ) -> PersistenceResult<()>;
    async fn commit(self) -> PersistenceResult<()>;
}

/// Insert an admission unless its bucket already holds `limit` admissions.
pub(super) async fn admit(
    mut tx: impl AdmissionTx,
    id: &str,
    name: &str,
    bucket: &str,
    payload: &[u8],
    limit: u32,
) -> PersistenceResult<Option<WriteResult>> {
    let now_ms = current_time_ms();
    let limit = i64::from(limit);
    let stale = |counter: &Counter| {
        counter.recount || now_ms.saturating_sub(counter.updated_at_ms) >= RECOUNT_INTERVAL_MS
    };
    let (mut counter, recounted) = match tx.counter(bucket).await? {
        Some(counter) if counter.count < limit || !stale(&counter) => (counter, false),
        _ => (
            Counter {
                count: tx.count(bucket).await?,
                recount: false,
                updated_at_ms: now_ms,
            },
            true,
        ),
    };
    let admitted = counter.count < limit;
    if admitted {
        tx.insert(id, name, bucket, payload, now_ms).await?;
        counter.count += 1;
    }
    if admitted || recounted {
        tx.put_counter(bucket, &counter, now_ms).await?;
    }
    tx.commit().await?;
    Ok(admitted.then_some(WriteResult {
        resource_version: 1,
        created_at_ms: now_ms,
        updated_at_ms: now_ms,
    }))
}
