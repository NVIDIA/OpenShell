// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Strong identity for one sandbox runtime launch.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;
use uuid::Uuid;

/// Identifies one create or start-from-stopped sandbox launch.
///
/// Retries of the same durable launch reuse this value. A later launch gets a
/// new value even when the compute platform reuses the same sandbox resource.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SandboxSessionId(Uuid);

impl SandboxSessionId {
    /// Generate a fresh launch identity.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Return the underlying UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for SandboxSessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SandboxSessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.hyphenated().fmt(formatter)
    }
}

impl fmt::Debug for SandboxSessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SandboxSessionId")
            .field(&self.to_string())
            .finish()
    }
}

impl FromStr for SandboxSessionId {
    type Err = SandboxSessionIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parsed = Uuid::parse_str(value).map_err(|_| SandboxSessionIdError)?;
        if parsed.is_nil() || parsed.hyphenated().to_string() != value {
            return Err(SandboxSessionIdError);
        }
        Ok(Self(parsed))
    }
}

impl Serialize for SandboxSessionId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SandboxSessionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(|_| {
            de::Error::invalid_value(
                de::Unexpected::Str(&value),
                &"a non-nil canonical lowercase UUID",
            )
        })
    }
}

/// A sandbox session ID was not a non-nil canonical lowercase UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("sandbox session ID must be a non-nil canonical lowercase UUID")]
pub struct SandboxSessionIdError;

#[cfg(test)]
mod tests {
    use crate::sandbox_session::SandboxSessionId;

    #[test]
    fn round_trips_canonical_id() {
        let session = SandboxSessionId::new();
        let encoded = serde_json::to_string(&session).expect("serialize session ID");
        let decoded: SandboxSessionId =
            serde_json::from_str(&encoded).expect("deserialize session ID");
        assert_eq!(decoded, session);
    }

    #[test]
    fn rejects_nil_and_noncanonical_ids() {
        for invalid in [
            "00000000-0000-0000-0000-000000000000",
            "550E8400-E29B-41D4-A716-446655440000",
            "550e8400e29b41d4a716446655440000",
            "not-a-uuid",
        ] {
            assert!(invalid.parse::<SandboxSessionId>().is_err(), "{invalid}");
        }
    }
}
