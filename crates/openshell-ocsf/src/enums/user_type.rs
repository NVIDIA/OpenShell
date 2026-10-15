// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `user.type_id` enum.

use serde_repr::{Deserialize_repr, Serialize_repr};

/// OCSF User Type ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum UserTypeId {
    /// 0 — Unknown
    Unknown = 0,
    /// 1 — User
    User = 1,
    /// 2 — Admin
    Admin = 2,
    /// 3 — System
    System = 3,
    /// 4 — Service
    Service = 4,
    /// 99 — Other
    Other = 99,
}

impl UserTypeId {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::User => "User",
            Self::Admin => "Admin",
            Self::System => "System",
            Self::Service => "Service",
            Self::Other => "Other",
        }
    }

    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}
