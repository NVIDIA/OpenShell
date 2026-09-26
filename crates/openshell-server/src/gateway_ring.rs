// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Consistent hash ring mapping sandboxes to gateway replicas.
//!
//! Every replica builds the same ring from the same membership list, so all
//! replicas agree on which one should own a sandbox without coordinating.
//!
//! The ring answers who *should* own a sandbox. The ownership record in the
//! store stays authoritative for who actually does, because a working session
//! is never moved just because the ring changed. See [`crate::supervisor_owner`].

use sha2::{Digest, Sha256};

/// Points placed on the ring per replica.
///
/// With one point each, arcs come out badly uneven at small replica counts and
/// one replica draws far more sandboxes than the rest. Spreading each replica
/// over many points evens the shares out while keeping the property that
/// removing a replica only redistributes its own share.
const VIRTUAL_NODES_PER_REPLICA: u32 = 128;

/// Immutable snapshot of sandbox-to-replica placement.
#[derive(Debug, Clone, Default)]
pub struct GatewayRing {
    /// `(point, replica_id)` pairs, sorted by point.
    points: Vec<(u64, String)>,
}

impl GatewayRing {
    pub fn new<I, S>(replica_ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut points = Vec::new();
        for replica_id in replica_ids {
            let replica_id = replica_id.as_ref();
            if replica_id.is_empty() {
                continue;
            }
            for vnode in 0..VIRTUAL_NODES_PER_REPLICA {
                points.push((
                    hash_point(&format!("{replica_id}#{vnode}")),
                    replica_id.to_string(),
                ));
            }
        }
        // Sorting by point then replica id keeps the ring identical regardless
        // of the order membership was listed in, which is what lets every
        // replica reach the same answer.
        points.sort_unstable_by(|left, right| {
            left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1))
        });
        points.dedup();
        Self { points }
    }

    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }

    /// Number of distinct replicas on the ring.
    pub fn replica_count(&self) -> usize {
        let mut ids: Vec<&str> = self.points.iter().map(|(_, id)| id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        ids.len()
    }

    /// The replica that should own `sandbox_id`.
    ///
    /// Walks clockwise from the sandbox's point to the first replica point,
    /// wrapping past the end of the ring.
    pub fn owner_for(&self, sandbox_id: &str) -> Option<&str> {
        if self.points.is_empty() {
            return None;
        }
        let point = hash_point(sandbox_id);
        let index = self
            .points
            .partition_point(|(candidate, _)| *candidate < point);
        let index = if index == self.points.len() { 0 } else { index };
        Some(self.points[index].1.as_str())
    }
}

fn hash_point(key: &str) -> u64 {
    let digest = Sha256::digest(key.as_bytes());
    u64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("sha256 digest is longer than 8 bytes"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    fn sandbox_ids(count: usize) -> Vec<String> {
        (0..count).map(|i| format!("sandbox-{i}")).collect()
    }

    #[test]
    fn empty_ring_has_no_owner() {
        let ring = GatewayRing::new::<[&str; 0], &str>([]);
        assert!(ring.is_empty());
        assert_eq!(ring.owner_for("sandbox-1"), None);
    }

    #[test]
    fn blank_replica_ids_are_ignored() {
        let ring = GatewayRing::new(["gw-0", "", "gw-1"]);
        assert_eq!(ring.replica_count(), 2);
    }

    #[test]
    fn single_replica_owns_everything() {
        let ring = GatewayRing::new(["gw-0"]);
        for id in sandbox_ids(50) {
            assert_eq!(ring.owner_for(&id), Some("gw-0"));
        }
    }

    #[test]
    fn owner_is_deterministic() {
        let ring = GatewayRing::new(["gw-0", "gw-1", "gw-2"]);
        let first = ring.owner_for("sandbox-abc").unwrap().to_string();
        for _ in 0..10 {
            assert_eq!(ring.owner_for("sandbox-abc"), Some(first.as_str()));
        }
    }

    #[test]
    fn membership_order_does_not_change_placement() {
        let forward = GatewayRing::new(["gw-0", "gw-1", "gw-2"]);
        let reverse = GatewayRing::new(["gw-2", "gw-1", "gw-0"]);
        for id in sandbox_ids(200) {
            assert_eq!(
                forward.owner_for(&id),
                reverse.owner_for(&id),
                "replicas must agree regardless of listing order for {id}"
            );
        }
    }

    #[test]
    fn every_replica_gets_a_share() {
        let ring = GatewayRing::new(["gw-0", "gw-1", "gw-2"]);
        let mut seen: HashSet<&str> = HashSet::new();
        for id in sandbox_ids(300) {
            seen.insert(ring.owner_for(&id).unwrap());
        }
        assert_eq!(seen.len(), 3, "all replicas should own some sandboxes");
    }

    #[test]
    fn shares_are_roughly_even() {
        let ring = GatewayRing::new(["gw-0", "gw-1", "gw-2", "gw-3"]);
        let total = 4000;
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for id in sandbox_ids(total) {
            *counts.entry(ring.owner_for(&id).unwrap()).or_default() += 1;
        }
        let ideal = total / 4;
        for (replica, count) in counts {
            let drift = count.abs_diff(ideal);
            assert!(
                drift < ideal / 2,
                "{replica} owns {count}, too far from the {ideal} ideal"
            );
        }
    }

    /// The property that makes this worth using: losing a replica must only
    /// move the sandboxes it owned, never anyone else's.
    #[test]
    fn removing_a_replica_only_moves_its_own_sandboxes() {
        let before = GatewayRing::new(["gw-0", "gw-1", "gw-2"]);
        let after = GatewayRing::new(["gw-0", "gw-2"]);

        let mut moved_from_dead = 0;
        for id in sandbox_ids(1000) {
            let old = before.owner_for(&id).unwrap();
            let new = after.owner_for(&id).unwrap();
            if old == "gw-1" {
                moved_from_dead += 1;
                assert_ne!(new, "gw-1", "dead replica must not still own {id}");
            } else {
                assert_eq!(old, new, "{id} moved despite its owner being alive");
            }
        }
        assert!(moved_from_dead > 0, "expected gw-1 to have owned something");
    }

    /// Adding a replica should claim roughly its fair share and disturb
    /// nothing else, so a scale-up does not reshuffle the fleet.
    #[test]
    fn adding_a_replica_moves_only_its_fair_share() {
        let before = GatewayRing::new(["gw-0", "gw-1", "gw-2"]);
        let after = GatewayRing::new(["gw-0", "gw-1", "gw-2", "gw-3"]);

        let total = 1000;
        let mut moved = 0;
        for id in sandbox_ids(total) {
            let old = before.owner_for(&id).unwrap();
            let new = after.owner_for(&id).unwrap();
            if old != new {
                moved += 1;
                assert_eq!(
                    new, "gw-3",
                    "{id} moved to {new} rather than the new replica"
                );
            }
        }
        // A quarter is the ideal; allow generous slack for hash variance.
        assert!(
            moved < total / 2,
            "adding one replica moved {moved} of {total} sandboxes"
        );
    }
}
