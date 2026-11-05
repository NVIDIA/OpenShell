// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Explicit maintenance-window activation. The database marker is understood by
//! compatible gateways only; it does not fence an old binary. The operator must
//! retire every incompatible writer before enabling this option.

use std::sync::{Arc, LazyLock};

use serde::{Deserialize, Serialize};
use tonic::Status;

use crate::persistence::{RefreshMutationGuard, Store, WriteCondition};

const OBJECT_TYPE: &str = "credential_issuer_activation";
const OBJECT_ID: &str = "embedded-credential-references-v1";
static LOCAL_MIGRATION: LazyLock<Arc<tokio::sync::Mutex<()>>> =
    LazyLock::new(|| Arc::new(tokio::sync::Mutex::new(())));

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Preparing,
    Converting,
    Active,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    schema: u32,
    phase: Phase,
}

pub struct Activation {
    store: Arc<Store>,
    resource_version: u64,
    phase: Phase,
    _local: tokio::sync::OwnedMutexGuard<()>,
    _lease: RefreshMutationGuard,
}

impl std::fmt::Debug for Activation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Activation")
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

fn encode(phase: Phase) -> Result<Vec<u8>, Status> {
    serde_json::to_vec(&Marker { schema: 1, phase })
        .map_err(|_| Status::internal("encode credential activation marker failed"))
}

fn decode(bytes: &[u8]) -> Result<Phase, Status> {
    let marker: Marker = serde_json::from_slice(bytes)
        .map_err(|_| Status::data_loss("invalid credential activation marker"))?;
    if marker.schema != 1 {
        return Err(Status::failed_precondition(
            "unsupported credential activation schema",
        ));
    }
    Ok(marker.phase)
}

/// Serialize compatible replicas using an owned data-pool lease. Existing
/// configuration/refresh writers must already have been drained by the operator.
pub async fn begin(store: Arc<Store>, enabled: bool) -> Result<Option<Activation>, Status> {
    if !enabled {
        let record = store
            .get(OBJECT_TYPE, OBJECT_ID)
            .await
            .map_err(|_| Status::unavailable("read credential activation marker failed"))?;
        if let Some(record) = record {
            let phase = decode(&record.payload)?;
            if phase != Phase::Preparing {
                return Err(Status::failed_precondition(
                    "versioned credentials were activated or migration is incomplete; enable_versioned_credentials must remain enabled; an old-binary downgrade requires coordinated recovery",
                ));
            }
        }
        return Ok(None);
    }
    let local = Arc::clone(&LOCAL_MIGRATION).lock_owned().await;
    let lease = store
        .acquire_refresh_guard(OBJECT_ID, "migration")
        .await
        .map_err(|_| Status::unavailable("credential migration coordination unavailable"))?;
    let record = store
        .get(OBJECT_TYPE, OBJECT_ID)
        .await
        .map_err(|_| Status::unavailable("read credential activation marker failed"))?;
    let (resource_version, phase) = if let Some(record) = record {
        (record.resource_version, decode(&record.payload)?)
    } else {
        let result = store
            .put_if(
                OBJECT_TYPE,
                OBJECT_ID,
                OBJECT_ID,
                "",
                &encode(Phase::Preparing)?,
                None,
                WriteCondition::MustCreate,
            )
            .await
            .map_err(|_| Status::unavailable("create credential activation marker failed"))?;
        (result.resource_version, Phase::Preparing)
    };
    Ok(Some(Activation {
        store,
        resource_version,
        phase,
        _local: local,
        _lease: lease,
    }))
}

impl Activation {
    pub fn already_active(&self) -> bool {
        self.phase == Phase::Active
    }

    /// Persist BEFORE the first incompatible binding update/inline removal. A
    /// crash must never allow another compatible gateway to reopen legacy mode.
    pub async fn mark_irreversible(&mut self) -> Result<(), Status> {
        if self.phase == Phase::Preparing {
            self.set_phase(Phase::Converting).await?;
        }
        Ok(())
    }

    pub async fn finish(&mut self) -> Result<(), Status> {
        self.set_phase(Phase::Active).await
    }

    async fn set_phase(&mut self, phase: Phase) -> Result<(), Status> {
        let result = self
            .store
            .put_if(
                OBJECT_TYPE,
                OBJECT_ID,
                OBJECT_ID,
                "",
                &encode(phase)?,
                None,
                WriteCondition::MatchResourceVersion(self.resource_version),
            )
            .await
            .map_err(|_| Status::unavailable("persist credential activation progress failed"))?;
        self.resource_version = result.resource_version;
        self.phase = phase;
        Ok(())
    }
}

pub async fn uses_reference_records(store: &Store) -> Result<bool, Status> {
    store
        .get(OBJECT_TYPE, OBJECT_ID)
        .await
        .map_err(|_| Status::unavailable("read credential activation marker failed"))?
        .map(|record| decode(&record.payload).map(|phase| phase != Phase::Preparing))
        .transpose()
        .map(|active| active.unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_activation_is_read_only_and_preparation_can_roll_back() {
        let store = Arc::new(Store::connect("sqlite::memory:").await.unwrap());
        assert!(begin(Arc::clone(&store), false).await.unwrap().is_none());
        assert!(store.get(OBJECT_TYPE, OBJECT_ID).await.unwrap().is_none());
        drop(begin(Arc::clone(&store), true).await.unwrap());
        assert!(begin(store, false).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn first_incompatible_change_fences_compatible_legacy_startup_and_resumes() {
        let store = Arc::new(Store::connect("sqlite::memory:").await.unwrap());
        let mut activation = begin(Arc::clone(&store), true).await.unwrap().unwrap();
        activation.mark_irreversible().await.unwrap();
        drop(activation);
        assert!(
            begin(Arc::clone(&store), false)
                .await
                .unwrap_err()
                .message()
                .contains("must remain enabled")
        );
        let mut resumed = begin(Arc::clone(&store), true).await.unwrap().unwrap();
        assert!(!resumed.already_active());
        resumed.finish().await.unwrap();
        drop(resumed);
        assert!(
            begin(Arc::clone(&store), true)
                .await
                .unwrap()
                .unwrap()
                .already_active()
        );
    }
}
