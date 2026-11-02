// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF File object.

use serde::{Deserialize, Serialize};

/// A file named in a filesystem event. Metadata is unknown for an attempted open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct File {
    /// Last component of the requested path.
    pub name: String,
    /// OCSF File type ID. Zero means unknown.
    pub type_id: u8,
    /// Absolute path text, when the caller supplied an absolute path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl File {
    /// Describe a workload-supplied path without resolving or statting it.
    #[must_use]
    pub fn requested(path: &str) -> Self {
        let name = path
            .rsplit('/')
            .find(|component| !component.is_empty())
            .unwrap_or(path);
        Self {
            name: name.to_string(),
            type_id: 0,
            path: path.starts_with('/').then(|| path.to_string()),
        }
    }
}
