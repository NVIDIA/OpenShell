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

    /// The replica on `ring` that `member_id` should move to from `here`, or
    /// `None` when `here` keeps it. The member counts on its replica from now
    /// on either way. A host that does not accept a redirect stays `here`.
    pub fn route(
        &self,
        ring: &GatewayRing,
        here: &str,
        member_id: &str,
        accepts_redirect: bool,
    ) -> Option<String> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = accepts_redirect
            .then(|| inner.place(ring, member_id))
            .flatten()
            .unwrap_or_else(|| here.to_string());
        inner
            .placed
            .insert(member_id.to_string(), (home.clone(), Instant::now()));
        (home != here).then_some(home)
    }
}

impl Inner {
    /// The first replica on `ring` below an even share, counting from
    /// `member_id`.
    fn place(&self, ring: &GatewayRing, member_id: &str) -> Option<String> {
        let mut load = HashMap::<&str, usize>::new();
        let mut supervisors = 1_usize;
        let recorded = self
            .homes
            .iter()
            .filter(|(member, _)| !self.placed.contains_key(*member));
        let pending = self
            .placed
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
        ring.first_below(member_id, cap, |replica| {
            load.get(replica).copied().unwrap_or(0)
        })
        .map(str::to_string)
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

    /// Where a host that accepts a redirect is placed by a replica not on
    /// `ring`.
    fn place(spread: &SupervisorSpread, ring: &GatewayRing, member_id: &str) -> String {
        spread.route(ring, "", member_id, true).unwrap()
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
        let placed = ["sup-1", "sup-2"].map(|member| place(&spread, &ring, member));
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
        let placed = ["sup-1", "sup-2"].map(|member| place(&spread, &ring, member));
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
            .map(|i| place(&spread, &ring, &format!("sup-{i}")))
            .collect();
        assert_eq!(counts(&placed), HashMap::from([("gw-c", 50)]));
    }

    #[test]
    fn a_placement_stops_counting_once_the_records_show_it() {
        let spread = SupervisorSpread::default();
        let ring = GatewayRing::new(["gw-a", "gw-b"]);
        let home = place(&spread, &ring, "sup-1");
        spread.observe(&[member("sup-1", &home)]);
        assert!(spread.inner.lock().unwrap().placed.is_empty());
        assert_ne!(place(&spread, &ring, "sup-2"), home);
    }

    /// Each replica has its own placement state. Hosts say hello in this
    /// order, follow at most two redirects, then stay where they land.
    #[test]
    fn replicas_count_every_host_they_keep() {
        let replicas = ["gw-0", "gw-1", "gw-2"];
        let ring = GatewayRing::new(replicas);
        let spreads: HashMap<&str, SupervisorSpread> = replicas
            .into_iter()
            .map(|replica| (replica, SupervisorSpread::default()))
            .collect();
        let mut hosts = HashMap::from([
            ("sup-0", ("gw-0".to_string(), 0, false)),
            ("sup-1", ("gw-1".to_string(), 0, false)),
            ("sup-2", ("gw-2".to_string(), 0, false)),
        ]);
        let order = ["sup-2", "sup-1", "sup-2", "sup-2", "sup-0"];
        for member in order.into_iter().chain(order).chain(order) {
            let (at, hops, kept) = hosts.get_mut(member).unwrap();
            if *kept {
                continue;
            }
            match spreads[at.as_str()].route(&ring, at, member, *hops < 2) {
                Some(next) => {
                    *at = next;
                    *hops += 1;
                }
                None => *kept = true,
            }
        }
        assert!(hosts.values().all(|(_, _, kept)| *kept));
        let homes: Vec<String> = hosts.into_values().map(|(at, _, _)| at).collect();
        assert_eq!(
            counts(&homes),
            HashMap::from([("gw-0", 1), ("gw-1", 1), ("gw-2", 1)])
        );
    }
}
