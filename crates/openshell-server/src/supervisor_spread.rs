// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Spreads shared supervisors evenly across gateway replicas.
//!
//! A supervisor goes to the first replica clockwise from it on the gateway
//! ring that serves fewer than an even share of supervisors. Counts come from
//! the pool's member records plus the placements this replica made that the
//! records do not show yet, so a burst of arrivals or a replica handing off
//! its supervisors does not pile onto one replica.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use openshell_supervisor_control::pool_timing::MEMBER_TTL;

use crate::gateway_ring::GatewayRing;
use crate::supervisor_pool::LiveMember;

/// A placement counts until the member records show it, or this long.
const PLACEMENT_TTL: Duration = MEMBER_TTL;

#[derive(Debug, Default)]
pub struct SupervisorSpread {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    /// Replica serving each live member that is not leaving, by its record.
    homes: HashMap<String, String>,
    /// Replica each member was placed on here, and when.
    placed: HashMap<String, (String, Instant)>,
}

impl SupervisorSpread {
    /// Take the pool's live member records.
    pub fn observe(&self, members: &[LiveMember]) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Inner { homes, placed } = &mut *inner;
        *homes = members
            .iter()
            .filter(|member| !member.leaving)
            .map(|member| (member.member_id.clone(), member.gateway_replica.clone()))
            .collect();
        placed.retain(|member, (replica, at)| {
            at.elapsed() < PLACEMENT_TTL && homes.get(member) != Some(replica)
        });
    }

    /// The replica on `ring` that should serve `member_id`, counted there
    /// from now on.
    pub fn place(&self, ring: &GatewayRing, member_id: &str) -> Option<String> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Inner { homes, placed } = &mut *inner;
        let mut load = HashMap::<&str, usize>::new();
        let mut supervisors = 1_usize;
        let recorded = homes
            .iter()
            .filter(|(member, _)| !placed.contains_key(*member));
        let pending = placed
            .iter()
            .map(|(member, (replica, _))| (member, replica));
        for (_, replica) in recorded
            .chain(pending)
            .filter(|(member, _)| *member != member_id)
        {
            supervisors += 1;
            *load.entry(replica.as_str()).or_default() += 1;
        }
        let cap = supervisors.div_ceil(ring.replica_count().max(1));
        let home = ring
            .first_below(member_id, cap, |replica| {
                load.get(replica).copied().unwrap_or(0)
            })?
            .to_string();
        placed.insert(member_id.to_string(), (home.clone(), Instant::now()));
        Some(home)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(member_id: &str, gateway_replica: &str) -> LiveMember {
        LiveMember {
            member_id: member_id.to_string(),
            process_id: String::new(),
            runtime_address: String::new(),
            leaving: false,
            gateway_replica: gateway_replica.to_string(),
        }
    }

    fn counts(placements: &[String]) -> HashMap<&str, usize> {
        let mut counts = HashMap::new();
        for replica in placements {
            *counts.entry(replica.as_str()).or_default() += 1;
        }
        counts
    }

    #[test]
    fn simultaneous_arrivals_split_before_the_records_show_them() {
        let spread = SupervisorSpread::default();
        let ring = GatewayRing::new(["gw-a", "gw-b"]);
        let placed = ["sup-1", "sup-2"].map(|member| spread.place(&ring, member).unwrap());
        assert_ne!(placed[0], placed[1]);
    }

    #[test]
    fn a_stopping_replica_hands_off_to_the_emptiest_replicas() {
        let spread = SupervisorSpread::default();
        spread.observe(&[
            member("sup-1", "gw-a"),
            member("sup-2", "gw-a"),
            member("sup-3", "gw-b"),
            member("sup-4", "gw-c"),
        ]);
        let ring = GatewayRing::new(["gw-a", "gw-b", "gw-c"]).without("gw-a");
        let placed = ["sup-1", "sup-2"].map(|member| spread.place(&ring, member).unwrap());
        assert_eq!(counts(&placed), HashMap::from([("gw-b", 1), ("gw-c", 1)]));
    }

    /// In a surge rollout the replacement replica starts empty, and the
    /// stopping replica's whole batch fills it.
    #[test]
    fn a_handoff_batch_fills_the_new_replica() {
        let spread = SupervisorSpread::default();
        let members: Vec<LiveMember> = (0..100)
            .map(|i| member(&format!("sup-{i}"), if i < 50 { "gw-a" } else { "gw-b" }))
            .collect();
        spread.observe(&members);
        let ring = GatewayRing::new(["gw-b", "gw-c"]);
        let placed: Vec<String> = (0..50)
            .map(|i| spread.place(&ring, &format!("sup-{i}")).unwrap())
            .collect();
        assert_eq!(counts(&placed), HashMap::from([("gw-c", 50)]));
    }

    #[test]
    fn a_placement_stops_counting_once_the_records_show_it() {
        let spread = SupervisorSpread::default();
        let ring = GatewayRing::new(["gw-a", "gw-b"]);
        let home = spread.place(&ring, "sup-1").unwrap();
        spread.observe(&[member("sup-1", &home)]);
        assert!(spread.inner.lock().unwrap().placed.is_empty());
        assert_ne!(spread.place(&ring, "sup-2").unwrap(), home);
    }
}
