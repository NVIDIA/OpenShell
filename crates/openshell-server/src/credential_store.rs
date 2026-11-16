// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Adapter from the gateway's existing database pools to issuer persistence.

use crate::persistence::{PersistenceError, Store, WriteCondition};
use async_trait::async_trait;
use openshell_credential_issuer::persistence::{
    CredentialObjectWrite, DbCredstoreObjectStore, DbCredstoreWriteCondition,
    StoredCredentialObject,
};
use std::sync::Arc;
use tonic::Status;

#[derive(Debug, Clone)]
pub struct ServerDbCredstoreObjectStore {
    store: Arc<Store>,
}

impl ServerDbCredstoreObjectStore {
    pub(crate) fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl DbCredstoreObjectStore for ServerDbCredstoreObjectStore {
    async fn get_credential_object(
        &self,
        object_type: &str,
        id: &str,
        operation: &'static str,
    ) -> Result<Option<StoredCredentialObject>, Status> {
        self.store
            .get(object_type, id)
            .await
            .map(|record| {
                record.map(|record| StoredCredentialObject {
                    object_type: record.object_type,
                    id: record.id,
                    payload: record.payload,
                    resource_version: record.resource_version,
                })
            })
            .map_err(|err| default_credential_store_persistence_error_to_status(err, operation))
    }

    async fn put_credential_object(
        &self,
        write: CredentialObjectWrite,
        operation: &'static str,
    ) -> Result<(), Status> {
        let condition = match write.condition {
            DbCredstoreWriteCondition::MustCreate => WriteCondition::MustCreate,
            DbCredstoreWriteCondition::MatchResourceVersion(resource_version) => {
                WriteCondition::MatchResourceVersion(resource_version)
            }
        };
        self.store
            .put_if(
                &write.object_type,
                &write.id,
                &write.name,
                "",
                &write.payload,
                write.labels.as_deref(),
                condition,
            )
            .await
            .map(|_| ())
            .map_err(|err| default_credential_store_persistence_error_to_status(err, operation))
    }

    async fn delete_credential_object(
        &self,
        object_type: &str,
        id: &str,
        expected_resource_version: u64,
        operation: &'static str,
    ) -> Result<(), Status> {
        self.store
            .delete_if(object_type, id, expected_resource_version)
            .await
            .map(|_| ())
            .map_err(|err| default_credential_store_persistence_error_to_status(err, operation))
    }
}

fn default_credential_store_persistence_error_to_status(
    err: PersistenceError,
    operation: &str,
) -> Status {
    match err {
        PersistenceError::UniqueViolation { .. } => {
            Status::already_exists(format!("default credential already exists: {err}"))
        }
        PersistenceError::Conflict {
            current_resource_version,
        } => Status::aborted(format!(
            "default credential was modified concurrently during {operation} (current resource_version: {})",
            current_resource_version.unwrap_or(0)
        )),
        PersistenceError::Decode(err) => Status::data_loss(format!(
            "default credential decode failed during {operation}: {err}"
        )),
        PersistenceError::Encode(err) => Status::internal(format!(
            "default credential encode failed during {operation}: {err}"
        )),
        other => Status::unavailable(format!("default credential {operation} failed: {other}")),
    }
}
