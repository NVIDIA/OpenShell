// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use serde::{Deserialize, Serialize};

/// Identifies one requested start of a stable sandbox.
///
/// The gateway derives this value from the durable lifecycle transition so a
/// retried driver call carries the same identity after process restart.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SandboxGenerationId(String);

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SandboxGenerationIdError {
    #[error("sandbox generation ID is required")]
    Empty,
    #[error("sandbox generation ID exceeds 64 characters")]
    TooLong,
    #[error("sandbox generation ID contains an unsupported character")]
    InvalidCharacter,
}

impl SandboxGenerationId {
    pub const MAX_LEN: usize = 64;

    /// Construct the stable generation assigned to a gateway start
    /// transition. Resource versions are monotonic within one sandbox record.
    #[must_use]
    pub fn from_start_resource_version(resource_version: u64) -> Self {
        Self(format!("g{resource_version:016x}"))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, SandboxGenerationIdError> {
        let value = value.into();
        if value.is_empty() {
            return Err(SandboxGenerationIdError::Empty);
        }
        if value.len() > Self::MAX_LEN {
            return Err(SandboxGenerationIdError::TooLong);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(SandboxGenerationIdError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for SandboxGenerationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use crate::sandbox_generation::{SandboxGenerationId, SandboxGenerationIdError};

    #[test]
    fn resource_version_generation_is_stable_and_valid() {
        let generation = SandboxGenerationId::from_start_resource_version(42);
        assert_eq!(generation.as_str(), "g000000000000002a");
        assert_eq!(
            SandboxGenerationId::parse(generation.to_string()),
            Ok(generation)
        );
    }

    #[test]
    fn rejects_values_that_are_not_safe_runtime_identifiers() {
        assert_eq!(
            SandboxGenerationId::parse(""),
            Err(SandboxGenerationIdError::Empty)
        );
        assert_eq!(
            SandboxGenerationId::parse("Generation/1"),
            Err(SandboxGenerationIdError::InvalidCharacter)
        );
    }
}
