// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `os.type_id` enum.

use serde_repr::{Deserialize_repr, Serialize_repr};

/// OCSF OS Type ID.
///
/// Only the values `OpenShell` can produce are modelled; the schema defines a
/// wider set (Android, iOS, Solaris, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u16)]
pub enum OsTypeId {
    /// 99 — Other
    Other = 99,
    /// 100 — Windows
    Windows = 100,
    /// 200 — Linux
    Linux = 200,
    /// 300 — macOS
    MacOs = 300,
}
