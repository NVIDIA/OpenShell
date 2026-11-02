// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF File System Activity [1001] event class.

use serde::{Deserialize, Serialize};

use crate::enums::{ActionId, DispositionId};
use crate::events::base_event::BaseEventData;
use crate::objects::{Actor, File};

/// OCSF File System Activity Event [1001].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FileActivityEvent {
    /// Common base event fields.
    #[serde(flatten)]
    pub base: BaseEventData,
    /// The file named by the activity.
    pub file: File,
    /// The process that requested the operation.
    pub actor: Actor,
    /// Security control action, when known.
    #[serde(rename = "action_id", default, skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionId>,
    /// Security control disposition, when known.
    #[serde(
        rename = "disposition_id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub disposition: Option<DispositionId>,
}

impl Serialize for FileActivityEvent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::events::serde_helpers::{insert_enum_pair, insert_required};

        let mut value = serde_json::to_value(&self.base).map_err(serde::ser::Error::custom)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| serde::ser::Error::custom("expected object"))?;
        insert_required!(object, "file", self.file);
        insert_required!(object, "actor", self.actor);
        insert_enum_pair!(object, "action", self.action);
        insert_enum_pair!(object, "disposition", self.disposition);
        value.serialize(serializer)
    }
}
