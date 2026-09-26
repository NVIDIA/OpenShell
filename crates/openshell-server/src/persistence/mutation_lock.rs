// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Keys, modes, and deadlines of the mutation locks that serialize
//! cross-object mutations across gateway replicas.
//!
//! The locks form a hierarchy of intention locks. Each key is held shared
//! (S) or exclusive (X):
//!
//! | Mutation | Keys |
//! |---|---|
//! | global policy and settings, platform-scope profiles | X(global) |
//! | providers and workspace-scoped profiles | S(global) X(workspace) |
//! | one sandbox, admin or supervisor | S(global) S(workspace) X(sandbox) |
//! | lifecycle, driver watch, reconcile (process-local only) | S(global) X(sandbox) |
//! | provisioning-deadline reconcile (process-local only) | S(global) S(workspace) X(sandbox) |
//!
//! Ordering rules, which make the scheme deadlock-free:
//!
//! 1. A per-sandbox lifecycle gate, where a path uses one, comes first.
//! 2. Process-local keys follow in ascending `i64` order.
//! 3. On `PostgreSQL`, the same keys follow as session-level advisory locks in
//!    ascending order, all on one lock-pool connection.
//! 4. A task never acquires a mutation guard or a local lifecycle lock while
//!    it holds one: no nesting and no upgrade.
//!
//! Within each layer every waiter on a key holds only smaller keys, and the
//! local phase ends before the `PostgreSQL` phase starts, so no wait-for cycle
//! can form.
//!
//! The global key is the legacy cross-object key. Gateways from earlier
//! releases hold it exclusively for every mutation, which conflicts with every
//! scope of this release, so mixed-version fleets stay mutually exclusive
//! during a rolling upgrade.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Duration;

/// Advisory-lock key of the global mutation lock.
///
/// Never change this value: gateways from earlier releases hold it
/// exclusively for every cross-object mutation, and a rolling upgrade relies
/// on old and new replicas excluding each other through it. The bytes spell
/// "OPENSHLL" and stay within `PostgreSQL`'s signed 64-bit key space.
pub const GLOBAL_MUTATION_LOCK_KEY: i64 = 0x4f50_454e_5348_4c4c;

/// Upper bound on acquiring one mutation lock set.
///
/// The holder only validates and writes, so a wait this long means a stuck
/// replica or an overloaded database; failing beats blocking mutations
/// indefinitely. Keep [`MUTATION_LOCK_TIMEOUT_SETTING`] in sync.
pub const MUTATION_LOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// [`MUTATION_LOCK_TIMEOUT`] as a `PostgreSQL` `lock_timeout` value.
pub const MUTATION_LOCK_TIMEOUT_SETTING: &str = "10s";

/// Size of the dedicated `PostgreSQL` lock pool.
///
/// Lock connections come from their own pool so that guard holders can never
/// starve the data pool their critical sections need. Each replica opens at
/// most 10 data plus 4 lock connections, so size `max_connections` for
/// rollouts as the high-availability guide describes
/// (`(2 × replicas + surge) × 14`). Each guard holds
/// one lock connection, so a replica sustains about 4 / c guarded operations
/// per second, where c is how long one guard is held.
pub(super) const MUTATION_LOCK_POOL_MAX_CONNECTIONS: u32 = 4;

/// Domain separator hashed into every derived key.
const KEY_DOMAIN: &[u8] = b"openshell/mutation-lock/v1";

/// Advisory-lock key of the one-time time-payload migration
/// (`PostgresStore::migrate_legacy_time_payloads`). Derived keys never use it.
const TIME_PAYLOAD_MIGRATION_LOCK_KEY: i64 = 3052;

/// Mode in which a mutation lock key is held. `Shared` sorts first, so the
/// maximum of two modes is the stronger one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LockMode {
    Shared,
    Exclusive,
}

/// A mutation lock key.
#[derive(Clone, Copy, Debug)]
pub enum MutationLockKey<'a> {
    /// The fleet-wide key, [`GLOBAL_MUTATION_LOCK_KEY`].
    Global,
    /// One workspace, by name.
    Workspace(&'a str),
    /// One sandbox, by stable id.
    Sandbox(&'a str),
}

impl MutationLockKey<'_> {
    /// The `PostgreSQL` advisory-lock key, also used by the process-local lock
    /// table.
    ///
    /// Derived keys are the first 8 bytes, as a big-endian `i64`, of
    /// `SHA-256(KEY_DOMAIN || 0 || kind || 0 || value)`. They are computed in
    /// Rust so every replica and every `PostgreSQL` version agrees on them. A
    /// hash collision only over-serializes.
    pub fn advisory_key(self) -> i64 {
        match self {
            Self::Global => GLOBAL_MUTATION_LOCK_KEY,
            Self::Workspace(workspace) => derived_key(b"workspace", workspace),
            Self::Sandbox(sandbox_id) => derived_key(b"sandbox", sandbox_id),
        }
    }
}

fn derived_key(kind: &[u8], value: &str) -> i64 {
    let digest = Sha256::new()
        .chain_update(KEY_DOMAIN)
        .chain_update([0])
        .chain_update(kind)
        .chain_update([0])
        .chain_update(value.as_bytes())
        .finalize();
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    avoid_reserved(i64::from_be_bytes(prefix))
}

/// Keep derived keys off the global and migration keys.
const fn avoid_reserved(key: i64) -> i64 {
    if key == GLOBAL_MUTATION_LOCK_KEY || key == TIME_PAYLOAD_MIGRATION_LOCK_KEY {
        key ^ 1
    } else {
        key
    }
}

/// The keys one mutation holds, each in its strongest requested mode.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MutationLockSet {
    entries: BTreeMap<i64, LockMode>,
}

impl MutationLockSet {
    /// Process-local lock set of a lifecycle, driver-watch, or reconcile path:
    /// S(global) X(sandbox).
    pub fn sandbox_lifecycle(sandbox_id: &str) -> Self {
        let mut set = Self::default();
        set.insert(MutationLockKey::Global, LockMode::Shared);
        set.insert(MutationLockKey::Sandbox(sandbox_id), LockMode::Exclusive);
        set
    }

    pub fn insert(&mut self, key: MutationLockKey<'_>, mode: LockMode) {
        self.insert_raw(key.advisory_key(), mode);
    }

    fn insert_raw(&mut self, key: i64, mode: LockMode) {
        self.entries
            .entry(key)
            .and_modify(|held| *held = (*held).max(mode))
            .or_insert(mode);
    }

    /// Keys in ascending order, the only acquisition order.
    pub fn iter(&self) -> impl Iterator<Item = (i64, LockMode)> + '_ {
        self.entries.iter().map(|(key, mode)| (*key, *mode))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_key_is_the_legacy_cross_object_key() {
        assert_eq!(
            MutationLockKey::Global.advisory_key(),
            0x4f50_454e_5348_4c4c
        );
    }

    #[test]
    fn timeout_setting_matches_duration() {
        assert_eq!(
            format!("{}s", MUTATION_LOCK_TIMEOUT.as_secs()),
            MUTATION_LOCK_TIMEOUT_SETTING
        );
    }

    #[test]
    fn lock_set_iterates_in_ascending_key_order() {
        let mut set = MutationLockSet::default();
        set.insert_raw(5, LockMode::Exclusive);
        set.insert_raw(-3, LockMode::Exclusive);

        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            vec![(-3, LockMode::Exclusive), (5, LockMode::Exclusive)]
        );
    }

    #[test]
    fn derived_keys_match_golden_values() {
        // Computed independently from the documented byte layout. Changing
        // any of them breaks mutual exclusion with running replicas.
        assert_eq!(
            MutationLockKey::Workspace("default").advisory_key(),
            4_171_374_605_116_754_083
        );
        assert_eq!(
            MutationLockKey::Workspace("team-a").advisory_key(),
            4_635_337_207_968_654_063
        );
        assert_eq!(
            MutationLockKey::Sandbox("00000000-0000-0000-0000-000000000001").advisory_key(),
            -542_384_872_970_356_635
        );
        assert_eq!(
            MutationLockKey::Sandbox("sb-1").advisory_key(),
            -7_385_842_969_463_770_825
        );
    }

    #[test]
    fn derived_keys_separate_kinds() {
        assert_ne!(
            MutationLockKey::Workspace("x").advisory_key(),
            MutationLockKey::Sandbox("x").advisory_key()
        );
    }

    #[test]
    fn reserved_keys_are_remapped() {
        assert_ne!(
            avoid_reserved(GLOBAL_MUTATION_LOCK_KEY),
            GLOBAL_MUTATION_LOCK_KEY
        );
        assert_eq!(avoid_reserved(TIME_PAYLOAD_MIGRATION_LOCK_KEY), 3053);
        assert_eq!(avoid_reserved(42), 42);
    }

    #[test]
    fn lock_set_keeps_strongest_mode() {
        let mut set = MutationLockSet::default();
        set.insert_raw(5, LockMode::Shared);
        set.insert_raw(-3, LockMode::Exclusive);
        set.insert_raw(5, LockMode::Exclusive);
        set.insert_raw(-3, LockMode::Shared);

        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            vec![(-3, LockMode::Exclusive), (5, LockMode::Exclusive)]
        );
    }

    #[test]
    fn sandbox_lifecycle_set_is_shared_global_exclusive_sandbox() {
        let set = MutationLockSet::sandbox_lifecycle("sb-1");

        let mut expected = vec![
            (GLOBAL_MUTATION_LOCK_KEY, LockMode::Shared),
            (
                MutationLockKey::Sandbox("sb-1").advisory_key(),
                LockMode::Exclusive,
            ),
        ];
        expected.sort_unstable();
        assert_eq!(set.iter().collect::<Vec<_>>(), expected);
    }
}
