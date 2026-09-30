// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Keys, modes, and deadlines of the mutation locks that serialize
//! cross-object mutations across gateway replicas.
//!
//! On `PostgreSQL` a lock set is acquired as session-level advisory locks in
//! ascending key order on one lock-pool connection, so every waiter on a key
//! holds only smaller keys and no wait-for cycle can form.

use std::collections::BTreeMap;
use std::time::Duration;

/// Advisory-lock key of the global mutation lock.
///
/// Never change this value: gateways from earlier releases hold it
/// exclusively for every cross-object mutation, and a rolling upgrade relies
/// on old and new replicas excluding each other through it. The bytes spell
/// "OPENSHLL" and stay within `PostgreSQL`'s signed 64-bit key space.
pub const GLOBAL_MUTATION_LOCK_KEY: i64 = 0x4f50_454e_5348_4c4c;

/// Advisory-lock key that serializes sandbox SSH host identity provisioning
/// and cleanup across replicas.
///
/// Never change this value: every gateway in a fleet must take the same key.
/// It is held on a data-pool connection, not the lock pool, because sandbox
/// creation takes it while holding its mutation guard. The bytes spell
/// "OSSHHOST".
pub const SSH_IDENTITY_LOCK_KEY: i64 = 0x4f53_5348_484f_5354;

/// Upper bound on acquiring one mutation lock set.
///
/// Holders validate and write, and some guarded sections also call the
/// compute driver, credential driver, middleware, or profile sources. A wait
/// this long therefore means a stuck replica, a slow dependency, an
/// overloaded database, or a lock pool exhausted by such holders on this
/// replica; failing beats blocking mutations indefinitely. Keep
/// [`MUTATION_LOCK_TIMEOUT_SETTING`] in sync.
pub const MUTATION_LOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// [`MUTATION_LOCK_TIMEOUT`] as a `PostgreSQL` `lock_timeout` value.
pub const MUTATION_LOCK_TIMEOUT_SETTING: &str = "10s";

/// Opening a lock connection can take this long, so a timeout with less time left is contention.
pub const LOCK_CONNECTION_MIN_BUDGET: Duration = Duration::from_secs(1);

/// Size of the dedicated `PostgreSQL` lock pool.
///
/// Lock connections come from their own pool so that guard holders can never
/// starve the data pool their critical sections need. Each replica opens at
/// most 10 data plus 4 lock connections. A cancelled acquisition frees its
/// slot at once, but its backend can stay until its `lock_timeout` while the
/// pool opens a replacement, so size `max_connections` with headroom for
/// rollouts as the high-availability guide describes
/// (`(2 × replicas + surge) × 14`). Each guard holds
/// one lock connection, so a replica sustains about 4 / c guarded operations
/// per second, where c is how long one guard is held.
pub(super) const MUTATION_LOCK_POOL_MAX_CONNECTIONS: u32 = 4;

/// Mode in which a mutation lock key is held.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LockMode {
    Exclusive,
}

/// A mutation lock key.
#[derive(Clone, Copy, Debug)]
pub enum MutationLockKey {
    /// The fleet-wide key, [`GLOBAL_MUTATION_LOCK_KEY`].
    Global,
}

impl MutationLockKey {
    /// The `PostgreSQL` advisory-lock key.
    pub fn advisory_key(self) -> i64 {
        match self {
            Self::Global => GLOBAL_MUTATION_LOCK_KEY,
        }
    }
}

/// The keys one mutation holds, each in its strongest requested mode.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MutationLockSet {
    #[expect(
        clippy::zero_sized_map_values,
        reason = "LockMode is zero-sized while Exclusive is its only mode"
    )]
    entries: BTreeMap<i64, LockMode>,
}

impl MutationLockSet {
    pub fn insert(&mut self, key: MutationLockKey, mode: LockMode) {
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
}
