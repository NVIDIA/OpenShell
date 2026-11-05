// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `user` object.

use serde::{Deserialize, Serialize};

use crate::enums::UserTypeId;

/// OCSF User object — the principal an event is about.
///
/// The schema requires at least one of `account`, `name`, or `uid`; the
/// constructors always set `name` or `uid`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Stable identifier (subject, sandbox ID, or replica ID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,

    /// User type.
    pub type_id: UserTypeId,

    /// User type label; the schema caption unless `type_id` is Other.
    #[serde(rename = "type")]
    pub type_label: String,
}

impl User {
    /// A principal with a schema-defined user type.
    #[must_use]
    pub fn new(uid: impl Into<String>, type_id: UserTypeId) -> Self {
        Self {
            name: None,
            uid: Some(uid.into()),
            type_id,
            type_label: type_id.label().to_string(),
        }
    }

    /// A principal whose type has no schema equivalent (e.g. "Sandbox").
    #[must_use]
    pub fn other(uid: impl Into<String>, type_label: impl Into<String>) -> Self {
        Self {
            name: None,
            uid: Some(uid.into()),
            type_id: UserTypeId::Other,
            type_label: type_label.into(),
        }
    }

    /// Placeholder for an authentication attempt that established no
    /// verified identity.
    #[must_use]
    pub fn unidentified() -> Self {
        Self {
            name: Some("unknown".to_string()),
            uid: None,
            type_id: UserTypeId::Unknown,
            type_label: UserTypeId::Unknown.label().to_string(),
        }
    }

    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}
