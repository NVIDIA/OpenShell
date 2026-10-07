// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `os.type_id` enum.

use serde_repr::{Deserialize_repr, Serialize_repr};

/// OCSF Operating System Type ID.
///
/// Only the values `OpenShell` can produce are modelled; the schema defines a
/// wider set (Android, iOS, Solaris, ...).
/// Values come from the OCSF os `type_id` enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u16)]
pub enum OsTypeId {
    /// 0 — Unknown
    Unknown = 0,
    /// 99 — Other
    Other = 99,
    /// 100 — Windows
    Windows = 100,
    /// 200 — Linux
    Linux = 200,
    /// 300 — macOS
    MacOs = 300,
}

impl OsTypeId {
    /// OS type for a `std::env::consts::OS` value.
    #[must_use]
    pub fn from_os(os: &str) -> Self {
        match os {
            "linux" => Self::Linux,
            "windows" => Self::Windows,
            "macos" => Self::MacOs,
            _ => Self::Other,
        }
    }

    #[must_use]
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

impl std::fmt::Display for OsTypeId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unknown => "Unknown",
            Self::Other => "Other",
            Self::Windows => "Windows",
            Self::Linux => "Linux",
            Self::MacOs => "macOS",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_type_from_platform_names() {
        for (os, expected) in [
            ("linux", OsTypeId::Linux),
            ("windows", OsTypeId::Windows),
            ("macos", OsTypeId::MacOs),
            ("freebsd", OsTypeId::Other),
            ("", OsTypeId::Other),
        ] {
            assert_eq!(OsTypeId::from_os(os), expected);
        }
    }

    #[test]
    fn os_type_json_roundtrip() {
        for (os_type, expected) in [
            (OsTypeId::Unknown, 0),
            (OsTypeId::Other, 99),
            (OsTypeId::Windows, 100),
            (OsTypeId::Linux, 200),
            (OsTypeId::MacOs, 300),
        ] {
            let json = serde_json::to_value(os_type).unwrap();
            assert_eq!(json, serde_json::json!(expected));
            let decoded: OsTypeId = serde_json::from_value(json).unwrap();
            assert_eq!(decoded, os_type);
        }
    }
}
