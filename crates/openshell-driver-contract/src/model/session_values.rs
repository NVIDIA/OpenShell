// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The non-zero counters that appear in the contract documents.

use serde::{Deserialize, Serialize};

/// Why a counter could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SessionValueError {
    #[error("credential epoch must be positive")]
    InvalidCredentialEpoch,
    #[error("session rotation must be positive")]
    InvalidSessionRotation,
    #[error("session rotation overflow")]
    SessionRotationOverflow,
}

/// Monotonic order for authenticated Sandbox Protocol connections.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialEpoch(u64);

impl CredentialEpoch {
    pub fn new(value: u64) -> Result<Self, SessionValueError> {
        if value == 0 {
            return Err(SessionValueError::InvalidCredentialEpoch);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Monotonic identity for Sandbox Protocol attachment state.
///
/// This is a protocol coordination value, not part of JWT authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionRotation(u64);

impl SessionRotation {
    pub fn new(value: u64) -> Result<Self, SessionValueError> {
        if value == 0 {
            return Err(SessionValueError::InvalidSessionRotation);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn successor(self) -> Result<Self, SessionValueError> {
        self.0
            .checked_add(1)
            .ok_or(SessionValueError::SessionRotationOverflow)
            .and_then(Self::new)
    }
}
