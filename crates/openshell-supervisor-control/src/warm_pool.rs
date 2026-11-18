// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Durable creation intents for compute-driver warm pools. These are capacity
//! plans, not a second authority for Sandbox claims or supervisor placement.

use openshell_core::SandboxSessionId;
use openshell_core::jwt::{CredentialEpoch, SessionRotation, SessionVerificationKey};
use serde::{Deserialize, Serialize};

/// Public trust only; no logical Sandbox credentials are minted for a spare.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmRuntimeTrust {
    pub gateway_id: String,
    pub verification_keys: Vec<SessionVerificationKey>,
    pub auth_epoch: CredentialEpoch,
    pub session_rotation: SessionRotation,
}

/// One physical identity selected before any provisioning request is sent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmPoolEntry {
    pub session_id: SandboxSessionId,
    pub created_at_ms: i64,
    pub last_attempt_at_ms: Option<i64>,
    pub last_ready_at_ms: Option<i64>,
    /// First observed physical journal UID; never adopt a replacement CR.
    pub resource_uid: Option<String>,
    /// Persisted before retirement. Never changed back to false.
    pub retiring: bool,
    /// Epoch used by this preparation, retained after its physical CR is gone.
    #[serde(default)]
    pub auth_epoch: Option<CredentialEpoch>,
}

/// Revision-controlled inventory policy, independent of runtime compatibility.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmPoolPolicy {
    pub target_size: u32,
    pub max_size: u32,
    pub max_age_secs: u64,
    pub preparation_timeout_secs: u64,
}

impl WarmPoolPolicy {
    /// Disabling is the only policy change permitted without a new revision.
    #[must_use]
    pub fn is_drain_of(&self, previous: &Self) -> bool {
        self.target_size == 0
            && self.max_size == previous.max_size
            && self.max_age_secs == previous.max_age_secs
            && self.preparation_timeout_secs == previous.preparation_timeout_secs
    }
}

/// Bounded pool journal. Every replica acts on the same physical identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmPoolState {
    /// Operator-incremented revision fences older gateway configurations.
    pub revision: u64,
    /// Effective runtime preparation and public trust digest.
    pub fingerprint: String,
    /// Older journals acquire a policy on their next authorized revision.
    #[serde(default)]
    pub policy: Option<WarmPoolPolicy>,
    pub entries: Vec<WarmPoolEntry>,
}

#[derive(Clone, Debug)]
pub struct WarmPoolSnapshot {
    pub resource_version: u64,
    pub state: WarmPoolState,
}

#[derive(Clone, Debug)]
pub struct WarmPoolUpdate {
    pub workspace: String,
    pub pool_id: String,
    /// None means create only, never overwrite an existing journal.
    pub expected_version: Option<u64>,
    pub state: WarmPoolState,
}

/// Current template intent, or a tombstone for a deleted template. The immutable
/// template ID is the pool identity; names can be deleted and recreated safely.
#[derive(Clone, Debug)]
pub struct WarmPoolTarget {
    pub pool_id: String,
    pub workspace: String,
    pub target: u32,
    pub spec: Option<openshell_core::proto::compute::v1::DriverSandboxSpec>,
}
