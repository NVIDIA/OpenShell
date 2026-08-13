// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{
    ObjectId, ObjectLabels, ObjectName, ObjectType, ObjectWorkspace, PersistenceError,
    PersistenceResult,
};
use prost::Message;

/// An insert or version-fenced replacement in a multi-object transaction.
/// `None` creates; `Some(version)` replaces exactly that version.
#[derive(Debug, Clone)]
pub struct AtomicObjectWrite {
    pub object_type: String,
    pub id: String,
    pub name: String,
    pub workspace: String,
    pub scope: Option<String>,
    pub payload: Vec<u8>,
    pub labels: Option<String>,
    pub expected_version: Option<u64>,
}

impl AtomicObjectWrite {
    pub fn message<
        T: Message + ObjectType + ObjectId + ObjectName + ObjectWorkspace + ObjectLabels,
    >(
        message: &T,
        expected_version: Option<u64>,
    ) -> PersistenceResult<Self> {
        if T::requires_workspace() && message.object_workspace().is_empty() {
            return Err(PersistenceError::Encode("missing object workspace".into()));
        }
        Ok(Self {
            object_type: T::object_type().into(),
            id: message.object_id().into(),
            name: message.object_name().into(),
            workspace: message.object_workspace().into(),
            scope: None,
            payload: message.encode_to_vec(),
            labels: message
                .object_labels()
                .filter(|labels| !labels.is_empty())
                .map(|labels| serde_json::to_string(&labels))
                .transpose()
                .map_err(|error| PersistenceError::Encode(error.to_string()))?,
            expected_version,
        })
    }
}

pub(super) fn validate(writes: &[AtomicObjectWrite]) -> PersistenceResult<()> {
    let mut ids = std::collections::HashSet::new();
    if writes.is_empty()
        || writes.len() > 16
        || writes.iter().any(|write| {
            write.id.is_empty() || write.expected_version == Some(0) || !ids.insert(&write.id)
        })
    {
        return Err(PersistenceError::Encode(
            "invalid atomic object write batch".into(),
        ));
    }
    Ok(())
}
