// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Synthetic-address allocation and resolved endpoint mappings.
//!
//! A synthetic address stands for one normalized name and address family for
//! the life of the store, and is never reused. Its record pins the trusted
//! resolver addresses that passed the destination rules of at least one
//! endpoint eligible for the name when it was published.
//!
//! A record is not bound to the policy generation it was published under.
//! Every connection is authorized by the policy current when it is made, and
//! the pinned addresses are filtered again through that decision's
//! destination rules ([`MappingLookup::pinned_plan`]). A reload can therefore
//! never add a real address to a kept answer, and an unrelated reload, a
//! reordered policy or a new port does not invalidate it. The TTL bounds how
//! long a kept answer stays usable.

use super::name::NormalizedName;
use super::resolver::AddressFamily;
use crate::proxy::destination::{
    DestinationRequest, DestinationValidationPlan, UpstreamConnector, build_pinned_validation_plan,
    filter_resolved_addresses, validate_destination,
};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Unapproved-name observations may hold at most this fraction of each
/// address family's identities; the rest stay available to policy-backed
/// names. Allocations are never reused, even after their TTL expires.
const OBSERVATION_POOL_DIVISOR: usize = 4;

/// Names an endpoint in policy DNS failure events. Mappings do not record
/// endpoints; see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct PolicyEndpointId {
    pub(crate) policy_name: String,
    pub(crate) endpoint_index: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct PublishRequest {
    pub(crate) normalized_name: NormalizedName,
    pub(crate) family: AddressFamily,
    pub(crate) policy_generation: u64,
    pub(crate) ttl: Duration,
    /// Trusted resolver addresses that passed the destination rules of at
    /// least one eligible endpoint, in resolver order.
    pub(crate) pinned_addresses: Vec<IpAddr>,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedEndpointRecord {
    pub(crate) synthetic_address: IpAddr,
    pub(crate) normalized_name: NormalizedName,
    pub(crate) family: AddressFamily,
    /// The generation the record was published under. It orders
    /// republications of the name; it does not limit which policy may use it.
    pub(crate) policy_generation: u64,
    pub(crate) mapping_generation: u64,
    pub(crate) mapping_id: Uuid,
    pub(crate) created_at: Instant,
    pub(crate) expires_at: Instant,
    /// Deduplicated, in resolver order. Empty for an observation.
    pub(crate) pinned_addresses: Vec<IpAddr>,
}

impl ResolvedEndpointRecord {
    /// An observation correlates a name absent from policy with a later TCP
    /// attempt. It pins no address and never authorizes egress.
    pub(crate) fn is_observation(&self) -> bool {
        self.pinned_addresses.is_empty()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MappingLookup {
    pub(crate) record: ResolvedEndpointRecord,
    pub(crate) port: u16,
}

impl MappingLookup {
    /// The pinned destination for a connection the current policy authorized:
    /// the record's addresses that `plan`, the deciding endpoint's destination
    /// rules, permits on this port, in resolver order.
    ///
    /// Filtering through the decision's own rules keeps an address pinned for
    /// another endpoint of the same name (another binary's, or a looser one)
    /// from widening what this connection may reach.
    pub(crate) fn pinned_plan(
        &self,
        plan: &DestinationValidationPlan,
    ) -> Result<DestinationValidationPlan, MappingLookupError> {
        if self.record.is_observation() {
            return Err(MappingLookupError::EndpointMismatch);
        }
        let addresses = filter_resolved_addresses(
            plan,
            self.record.normalized_name.as_str(),
            self.port,
            &self.record.pinned_addresses,
        )
        .map_err(|_| MappingLookupError::InvalidMapping)?;
        build_pinned_validation_plan(addresses).map_err(|_| MappingLookupError::InvalidMapping)
    }

    /// Build the unopened connector for an authorized connection; see
    /// [`Self::pinned_plan`]. The pinned destination mode never resolves
    /// `normalized_name` again.
    pub(crate) async fn connector_for(
        &self,
        plan: &DestinationValidationPlan,
    ) -> Result<UpstreamConnector, MappingLookupError> {
        let plan = self.pinned_plan(plan)?;
        validate_destination(DestinationRequest {
            host: self.record.normalized_name.as_str(),
            port: self.port,
            sandbox_entrypoint_pid: 0,
            plan: &plan,
        })
        .await
        .map_err(|_| MappingLookupError::InvalidMapping)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SyntheticPools {
    ipv4: RangeInclusive<Ipv4Addr>,
    ipv6: RangeInclusive<Ipv6Addr>,
}

impl SyntheticPools {
    /// Construct injectable pools. Production runtime ranges are deliberately
    /// selected only after PR3 checks route collisions in each namespace.
    pub(crate) fn new(
        ipv4: RangeInclusive<Ipv4Addr>,
        ipv6: RangeInclusive<Ipv6Addr>,
    ) -> Result<Self, StoreConfigError> {
        if ipv4.is_empty() || ipv6.is_empty() {
            return Err(StoreConfigError::InvalidPool);
        }
        for address in [IpAddr::V4(*ipv4.start()), IpAddr::V4(*ipv4.end())] {
            if openshell_core::net::is_always_blocked_ip(address) {
                return Err(StoreConfigError::InvalidPool);
            }
        }
        for address in [IpAddr::V6(*ipv6.start()), IpAddr::V6(*ipv6.end())] {
            if openshell_core::net::is_always_blocked_ip(address) {
                return Err(StoreConfigError::InvalidPool);
            }
        }
        Ok(Self { ipv4, ipv6 })
    }

    fn capacity(&self, family: AddressFamily) -> usize {
        let capacity = match family {
            AddressFamily::Ipv4 => {
                u128::from(u32::from(*self.ipv4.end())) - u128::from(u32::from(*self.ipv4.start()))
                    + 1
            }
            AddressFamily::Ipv6 => {
                u128::from(*self.ipv6.end()) - u128::from(*self.ipv6.start()) + 1
            }
        };
        usize::try_from(capacity).unwrap_or(usize::MAX)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct StoreConfig {
    pub(crate) pools: SyntheticPools,
    pub(crate) max_mappings: usize,
}

impl StoreConfig {
    pub(crate) fn new(
        pools: SyntheticPools,
        max_mappings: usize,
    ) -> Result<Self, StoreConfigError> {
        if max_mappings == 0 {
            return Err(StoreConfigError::ZeroCapacity);
        }
        Ok(Self {
            pools,
            max_mappings,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum StoreConfigError {
    #[error("synthetic address pool is empty or contains an always-blocked boundary")]
    InvalidPool,
    #[error("resolved endpoint store capacity must be non-zero")]
    ZeroCapacity,
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublishError {
    #[error("policy generation changed before mapping publication")]
    StalePolicy,
    #[error("resolved endpoint publication was empty or invalid")]
    InvalidMapping,
    #[error("synthetic address pool is exhausted")]
    PoolExhausted,
    #[error("unapproved-name observation budget is exhausted")]
    ObservationBudgetExhausted,
    #[error("resolved endpoint store lock was poisoned")]
    LockPoisoned,
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MappingLookupError {
    #[error("transparent TCP mapping is missing")]
    Missing,
    #[error("transparent TCP mapping is expired")]
    Expired,
    /// Never returned by the store: the transparent TCP path reports a policy
    /// reload that changes the connection's rules while it is set up.
    #[error("policy changed while the transparent TCP connection was authorized")]
    PolicyChanged,
    #[error("transparent TCP mapping pins no address for the authorized endpoint")]
    EndpointMismatch,
    #[error("transparent TCP mapping is internally invalid")]
    InvalidMapping,
    #[error("resolved endpoint store lock was poisoned")]
    LockPoisoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AllocationIdentity {
    /// Contract-free correlation for a name absent from policy.
    Observation,
    /// A name some endpoint allowed, with trusted resolver addresses.
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AllocationKey {
    normalized_name: NormalizedName,
    family: AddressFamily,
    identity: AllocationIdentity,
}

struct Publication {
    key: AllocationKey,
    policy_generation: u64,
    ttl: Duration,
    pinned_addresses: Vec<IpAddr>,
}

struct StoreState {
    records: BTreeMap<IpAddr, ResolvedEndpointRecord>,
    allocations: BTreeMap<AllocationKey, IpAddr>,
    expired_allocations: BTreeMap<IpAddr, ResolvedEndpointRecord>,
    next_ipv4: u32,
    end_ipv4: u32,
    next_ipv6: u128,
    end_ipv6: u128,
    next_mapping_generation: u64,
}

pub(crate) struct ResolvedEndpointStore {
    state: RwLock<StoreState>,
    config: StoreConfig,
    ipv4_pool_high_water_emitted: AtomicBool,
    ipv6_pool_high_water_emitted: AtomicBool,
}

impl ResolvedEndpointStore {
    pub(crate) fn new(config: StoreConfig) -> Self {
        let next_ipv4 = u32::from(*config.pools.ipv4.start());
        let end_ipv4 = u32::from(*config.pools.ipv4.end());
        let next_ipv6 = u128::from(*config.pools.ipv6.start());
        let end_ipv6 = u128::from(*config.pools.ipv6.end());
        Self {
            state: RwLock::new(StoreState {
                records: BTreeMap::new(),
                allocations: BTreeMap::new(),
                expired_allocations: BTreeMap::new(),
                next_ipv4,
                end_ipv4,
                next_ipv6,
                end_ipv6,
                next_mapping_generation: 0,
            }),
            config,
            ipv4_pool_high_water_emitted: AtomicBool::new(false),
            ipv6_pool_high_water_emitted: AtomicBool::new(false),
        }
    }

    /// Recover refresh identity without authorizing expired upstream addresses.
    /// The refresh is judged by the current policy, like any other answer.
    pub(super) fn expired_for_connect(
        &self,
        address: IpAddr,
    ) -> Result<ResolvedEndpointRecord, MappingLookupError> {
        let state = self
            .state
            .read()
            .map_err(|_| MappingLookupError::LockPoisoned)?;
        let record = state
            .records
            .get(&address)
            .or_else(|| state.expired_allocations.get(&address))
            .ok_or(MappingLookupError::Missing)?;
        if record.is_observation() {
            return Err(MappingLookupError::Expired);
        }
        Ok(record.clone())
    }

    pub(crate) fn publish(
        &self,
        request: PublishRequest,
        current_policy_generation: u64,
        now: Instant,
    ) -> Result<ResolvedEndpointRecord, PublishError> {
        if request.policy_generation != current_policy_generation {
            return Err(PublishError::StalePolicy);
        }
        if request.ttl.is_zero()
            || request.pinned_addresses.is_empty()
            || request
                .pinned_addresses
                .iter()
                .any(|address| !request.family.accepts(*address))
        {
            return Err(PublishError::InvalidMapping);
        }
        let mut seen = BTreeSet::new();
        let pinned_addresses = request
            .pinned_addresses
            .into_iter()
            .filter(|address| seen.insert(*address))
            .collect();

        self.publish_checked(
            Publication {
                key: AllocationKey {
                    normalized_name: request.normalized_name,
                    family: request.family,
                    identity: AllocationIdentity::Resolved,
                },
                policy_generation: request.policy_generation,
                ttl: request.ttl,
                pinned_addresses,
            },
            now,
        )
    }

    /// Correlate a denied hostname with a later TCP attempt without resolving
    /// it upstream or granting any port. Only the intent lookup may read this
    /// record; the authorization lookup requires pinned addresses.
    pub(crate) fn publish_observation(
        &self,
        normalized_name: NormalizedName,
        family: AddressFamily,
        policy_generation: u64,
        current_policy_generation: u64,
        now: Instant,
    ) -> Result<ResolvedEndpointRecord, PublishError> {
        if policy_generation != current_policy_generation {
            return Err(PublishError::StalePolicy);
        }
        self.publish_checked(
            Publication {
                key: AllocationKey {
                    normalized_name,
                    family,
                    identity: AllocationIdentity::Observation,
                },
                policy_generation,
                ttl: super::MAX_MAPPING_TTL,
                pinned_addresses: Vec::new(),
            },
            now,
        )
    }

    fn observation_budget(&self, family: AddressFamily) -> usize {
        (self
            .config
            .pools
            .capacity(family)
            .min(self.config.max_mappings)
            / OBSERVATION_POOL_DIVISOR)
            .max(1)
    }

    fn publish_checked(
        &self,
        publication: Publication,
        now: Instant,
    ) -> Result<ResolvedEndpointRecord, PublishError> {
        let Publication {
            key,
            policy_generation,
            ttl,
            pinned_addresses,
        } = publication;
        let family = key.family;
        let mut state = self.state.write().map_err(|_| PublishError::LockPoisoned)?;
        let synthetic_address = if let Some(address) = state.allocations.get(&key) {
            *address
        } else {
            if key.identity == AllocationIdentity::Observation
                && state
                    .allocations
                    .keys()
                    .filter(|allocated| {
                        allocated.identity == AllocationIdentity::Observation
                            && allocated.family == family
                    })
                    .count()
                    >= self.observation_budget(family)
            {
                return Err(PublishError::ObservationBudgetExhausted);
            }
            if state.allocations.len() >= self.config.max_mappings {
                return Err(PublishError::PoolExhausted);
            }
            let address =
                allocate_address(&mut state, family).ok_or(PublishError::PoolExhausted)?;
            state.allocations.insert(key.clone(), address);
            let allocated = state
                .allocations
                .keys()
                .filter(|allocated| allocated.family == family)
                .count();
            let capacity = self
                .config
                .pools
                .capacity(family)
                .min(self.config.max_mappings);
            let emitted = match family {
                AddressFamily::Ipv4 => &self.ipv4_pool_high_water_emitted,
                AddressFamily::Ipv6 => &self.ipv6_pool_high_water_emitted,
            };
            if allocated.saturating_mul(5) >= capacity.saturating_mul(4)
                && !emitted.swap(true, Ordering::Relaxed)
            {
                crate::telemetry::egress_emit!(build_pool_high_water_event(
                    allocated, capacity, family,
                ));
            }
            address
        };

        // Defense in depth for callers outside the OPA generation guard: a
        // delayed publication from an older generation must never replace a
        // newer live correlation for the same name.
        if state
            .records
            .get(&synthetic_address)
            .is_some_and(|record| record.policy_generation > policy_generation)
        {
            return Err(PublishError::StalePolicy);
        }

        state.next_mapping_generation = state.next_mapping_generation.saturating_add(1);
        let record = ResolvedEndpointRecord {
            synthetic_address,
            normalized_name: key.normalized_name,
            family,
            policy_generation,
            mapping_generation: state.next_mapping_generation,
            mapping_id: Uuid::new_v4(),
            created_at: now,
            expires_at: now + ttl,
            pinned_addresses,
        };
        state.expired_allocations.remove(&synthetic_address);
        state.records.insert(synthetic_address, record.clone());
        Ok(record)
    }

    /// The live mapping at `synthetic_address`, without refreshing it; for
    /// tests. Connections pin through `PolicyDnsService::lookup_for_pin`.
    /// Observations pin no address and are refused.
    #[cfg(test)]
    pub(crate) fn lookup(
        &self,
        synthetic_address: IpAddr,
        port: u16,
        now: Instant,
    ) -> Result<MappingLookup, MappingLookupError> {
        let lookup = self.lookup_intent(synthetic_address, port, now)?;
        if lookup.record.is_observation() {
            return Err(MappingLookupError::EndpointMismatch);
        }
        Ok(lookup)
    }

    /// Look up the name behind a synthetic address for a policy decision,
    /// including an observation-only mapping. The caller must never use this
    /// lookup to establish an upstream relay.
    pub(crate) fn lookup_intent(
        &self,
        synthetic_address: IpAddr,
        port: u16,
        now: Instant,
    ) -> Result<MappingLookup, MappingLookupError> {
        let state = self
            .state
            .read()
            .map_err(|_| MappingLookupError::LockPoisoned)?;
        let record = live_record(&state, synthetic_address, now)?;
        Ok(MappingLookup {
            record: record.clone(),
            port,
        })
    }

    /// Remove expired active records without freeing their synthetic identity.
    pub(crate) fn expire(&self, now: Instant) -> Result<usize, MappingLookupError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| MappingLookupError::LockPoisoned)?;
        let expired = state
            .records
            .iter()
            .filter_map(|(address, record)| (now >= record.expires_at).then_some(*address))
            .collect::<Vec<_>>();
        for address in &expired {
            if let Some(record) = state.records.remove(address) {
                state.expired_allocations.insert(*address, record);
            }
        }
        Ok(expired.len())
    }
}

fn live_record(
    state: &StoreState,
    synthetic_address: IpAddr,
    now: Instant,
) -> Result<&ResolvedEndpointRecord, MappingLookupError> {
    let Some(record) = state.records.get(&synthetic_address) else {
        return if state.expired_allocations.contains_key(&synthetic_address) {
            Err(MappingLookupError::Expired)
        } else {
            Err(MappingLookupError::Missing)
        };
    };
    if now >= record.expires_at {
        return Err(MappingLookupError::Expired);
    }
    Ok(record)
}

fn build_pool_high_water_event(
    allocated: usize,
    capacity: usize,
    family: AddressFamily,
) -> openshell_ocsf::OcsfEvent {
    use openshell_ocsf::{ConfigStateChangeBuilder, SeverityId, StateId, StatusId};

    ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
        .severity(SeverityId::Low)
        .status(StatusId::Success)
        .state(StateId::Enabled, "high_water")
        .unmapped("allocated_identities", allocated)
        .unmapped("mapping_capacity", capacity)
        .unmapped("address_family", family.as_str())
        .message(format!(
            "Policy DNS {} synthetic pool reached high water: {allocated}/{capacity} identities allocated",
            family.as_str()
        ))
        .build()
}

fn allocate_address(state: &mut StoreState, family: AddressFamily) -> Option<IpAddr> {
    match family {
        AddressFamily::Ipv4 if state.next_ipv4 <= state.end_ipv4 => {
            let address = IpAddr::V4(Ipv4Addr::from(state.next_ipv4));
            state.next_ipv4 = state.next_ipv4.saturating_add(1);
            Some(address)
        }
        AddressFamily::Ipv6 if state.next_ipv6 <= state.end_ipv6 => {
            let address = IpAddr::V6(Ipv6Addr::from(state.next_ipv6));
            state.next_ipv6 = state.next_ipv6.saturating_add(1);
            Some(address)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::destination::{AddressAuthorization, DestinationValidationPlan};
    use std::sync::{Arc, Barrier};

    fn store(max_mappings: usize) -> ResolvedEndpointStore {
        let pools = SyntheticPools::new(
            Ipv4Addr::new(198, 18, 0, 1)..=Ipv4Addr::new(198, 18, 0, 2),
            "fd00:1::1".parse().unwrap()..="fd00:1::2".parse().unwrap(),
        )
        .unwrap();
        ResolvedEndpointStore::new(StoreConfig::new(pools, max_mappings).unwrap())
    }

    fn request(name: &str, generation: u64, ttl: Duration) -> PublishRequest {
        PublishRequest {
            normalized_name: NormalizedName::parse(name).unwrap(),
            family: AddressFamily::Ipv4,
            policy_generation: generation,
            ttl,
            pinned_addresses: vec!["203.0.113.8".parse().unwrap()],
        }
    }

    fn exact_host() -> DestinationValidationPlan {
        DestinationValidationPlan {
            address_authorization: AddressAuthorization::ExactDeclaredHost,
        }
    }

    fn observation(
        store: &ResolvedEndpointStore,
        name: &str,
        family: AddressFamily,
        now: Instant,
    ) -> Result<ResolvedEndpointRecord, PublishError> {
        store.publish_observation(NormalizedName::parse(name).unwrap(), family, 1, 1, now)
    }

    #[test]
    fn observation_budget_preserves_capacity_for_policy_backed_names() {
        let store = store(8);
        let now = Instant::now();
        let first = observation(&store, "unknown.example", AddressFamily::Ipv4, now).unwrap();
        assert!(first.is_observation());
        assert!(matches!(
            observation(&store, "another.example", AddressFamily::Ipv4, now),
            Err(PublishError::ObservationBudgetExhausted)
        ));
        let refreshed = observation(&store, "unknown.example", AddressFamily::Ipv4, now).unwrap();
        assert_eq!(refreshed.synthetic_address, first.synthetic_address);
        let approved = store
            .publish(request("db.example", 1, Duration::from_secs(10)), 1, now)
            .unwrap();
        assert_ne!(first.synthetic_address, approved.synthetic_address);
    }

    #[test]
    fn observation_budget_is_counted_per_address_family() {
        let store = store(8);
        let now = Instant::now();
        observation(&store, "first.example", AddressFamily::Ipv4, now).unwrap();
        assert!(matches!(
            observation(&store, "second.example", AddressFamily::Ipv4, now),
            Err(PublishError::ObservationBudgetExhausted)
        ));
        let ipv6 = observation(&store, "second.example", AddressFamily::Ipv6, now).unwrap();
        assert!(ipv6.synthetic_address.is_ipv6());
    }

    #[test]
    fn production_observation_budget_is_a_quarter_of_each_family_pool() {
        let pools = SyntheticPools::new(
            Ipv4Addr::new(198, 18, 0, 2)..=Ipv4Addr::new(198, 18, 1, 255),
            "fd23:6f70:656e::".parse().unwrap()..="fd23:6f70:656e::1ff".parse().unwrap(),
        )
        .unwrap();
        let store = ResolvedEndpointStore::new(StoreConfig::new(pools, 1024).unwrap());
        let now = Instant::now();

        for index in 0..127 {
            observation(
                &store,
                &format!("unknown-{index}.example"),
                AddressFamily::Ipv4,
                now,
            )
            .unwrap();
        }
        assert!(matches!(
            observation(&store, "unknown-127.example", AddressFamily::Ipv4, now),
            Err(PublishError::ObservationBudgetExhausted)
        ));
        for index in 0..383 {
            store
                .publish(
                    request(&format!("host-{index}.example"), 1, Duration::from_secs(5)),
                    1,
                    now,
                )
                .unwrap();
        }
        assert!(matches!(
            store.publish(
                request("host-383.example", 1, Duration::from_secs(5)),
                1,
                now
            ),
            Err(PublishError::PoolExhausted)
        ));
    }

    #[test]
    fn only_the_intent_lookup_exposes_an_observation() {
        let store = store(8);
        let now = Instant::now();
        let observed = observation(&store, "unknown.example", AddressFamily::Ipv4, now).unwrap();

        assert!(matches!(
            store.lookup(observed.synthetic_address, 443, now),
            Err(MappingLookupError::EndpointMismatch)
        ));
        let intent = store
            .lookup_intent(observed.synthetic_address, 443, now)
            .unwrap();
        assert_eq!(intent.record.normalized_name.as_str(), "unknown.example");
        assert!(matches!(
            intent.pinned_plan(&exact_host()),
            Err(MappingLookupError::EndpointMismatch)
        ));

        let expired_at = now + crate::policy_dns::MAX_MAPPING_TTL;
        assert_eq!(store.expire(expired_at).unwrap(), 1);
        assert!(matches!(
            store.lookup_intent(observed.synthetic_address, 443, expired_at),
            Err(MappingLookupError::Expired)
        ));
    }

    #[test]
    fn refresh_retains_synthetic_identity_and_changes_mapping_generation() {
        let store = store(2);
        let now = Instant::now();
        let first = store
            .publish(request("db.example", 7, Duration::from_secs(10)), 7, now)
            .unwrap();
        let second = store
            .publish(
                request("DB.EXAMPLE.", 7, Duration::from_secs(20)),
                7,
                now + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(first.synthetic_address, second.synthetic_address);
        assert_ne!(first.mapping_id, second.mapping_id);
        assert!(second.mapping_generation > first.mapping_generation);
        assert_eq!(first.policy_generation, second.policy_generation);
    }

    /// A name keeps its address across policy generations; a republication
    /// replaces the pinned addresses and expiry.
    #[test]
    fn a_name_keeps_its_address_across_policy_generations() {
        let store = store(2);
        let now = Instant::now();
        let first = store
            .publish(request("db.example", 1, Duration::from_secs(5)), 1, now)
            .unwrap();
        let mut republished = request("db.example", 2, Duration::from_secs(10));
        republished.pinned_addresses = vec!["203.0.113.9".parse().unwrap()];
        let second = store.publish(republished, 2, now).unwrap();

        assert_eq!(first.synthetic_address, second.synthetic_address);
        let lookup = store.lookup(first.synthetic_address, 5432, now).unwrap();
        assert_eq!(lookup.record.policy_generation, 2);
        assert_eq!(
            lookup.record.pinned_addresses,
            ["203.0.113.9".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(lookup.record.expires_at, now + Duration::from_secs(10));
    }

    #[test]
    fn an_observed_name_that_is_approved_gets_a_new_address() {
        let store = store(8);
        let now = Instant::now();
        let observed = observation(&store, "db.example", AddressFamily::Ipv4, now).unwrap();
        let approved = store
            .publish(request("db.example", 1, Duration::from_secs(5)), 1, now)
            .unwrap();
        assert_ne!(observed.synthetic_address, approved.synthetic_address);
        assert!(matches!(
            store.lookup(observed.synthetic_address, 5432, now),
            Err(MappingLookupError::EndpointMismatch)
        ));
    }

    #[test]
    fn distinct_names_sharing_real_ip_get_distinct_correlations() {
        let store = store(2);
        let now = Instant::now();
        let left = store
            .publish(request("left.example", 1, Duration::from_secs(10)), 1, now)
            .unwrap();
        let right = store
            .publish(request("right.example", 1, Duration::from_secs(10)), 1, now)
            .unwrap();
        assert_ne!(left.synthetic_address, right.synthetic_address);
        assert_eq!(left.pinned_addresses, right.pinned_addresses);
    }

    /// Ports and policy generations are for the connection's own policy
    /// decision; the mapping only fails closed when it is gone or expired.
    #[test]
    fn lookup_fails_closed_only_for_missing_or_expired_mappings() {
        let store = store(2);
        let now = Instant::now();
        let record = store
            .publish(request("db.example", 4, Duration::from_secs(2)), 4, now)
            .unwrap();
        let lookup = store.lookup(record.synthetic_address, 3306, now).unwrap();
        assert_eq!(lookup.port, 3306);
        assert!(matches!(
            store.lookup(record.synthetic_address, 5432, now + Duration::from_secs(2)),
            Err(MappingLookupError::Expired)
        ));
    }

    #[test]
    fn expiry_never_reassigns_synthetic_address_to_another_name() {
        let store = store(2);
        let now = Instant::now();
        let first = store
            .publish(request("first.example", 1, Duration::from_secs(1)), 1, now)
            .unwrap();
        assert_eq!(store.expire(now + Duration::from_secs(1)).unwrap(), 1);
        let second = store
            .publish(
                request("second.example", 1, Duration::from_secs(10)),
                1,
                now + Duration::from_secs(1),
            )
            .unwrap();
        assert_ne!(first.synthetic_address, second.synthetic_address);
        assert!(matches!(
            store.lookup(first.synthetic_address, 5432, now + Duration::from_secs(1)),
            Err(MappingLookupError::Expired)
        ));
    }

    #[test]
    fn pool_exhaustion_and_stale_publication_publish_nothing() {
        let store = store(1);
        let now = Instant::now();
        assert!(matches!(
            store.publish(request("stale.example", 1, Duration::from_secs(5)), 2, now),
            Err(PublishError::StalePolicy)
        ));
        let first = store
            .publish(request("first.example", 2, Duration::from_secs(5)), 2, now)
            .unwrap();
        assert!(matches!(
            store.publish(request("second.example", 2, Duration::from_secs(5)), 2, now),
            Err(PublishError::PoolExhausted)
        ));
        let preserved = store
            .lookup(first.synthetic_address, 5432, now)
            .expect("pool exhaustion must preserve the existing mapping");
        assert_eq!(preserved.record.mapping_id, first.mapping_id);
        assert!(matches!(
            store.lookup("198.18.0.2".parse().unwrap(), 5432, now),
            Err(MappingLookupError::Missing)
        ));
    }

    #[test]
    fn empty_or_wrong_family_publications_are_invalid() {
        let store = store(2);
        let now = Instant::now();
        let mut empty = request("db.example", 1, Duration::from_secs(5));
        empty.pinned_addresses.clear();
        assert!(matches!(
            store.publish(empty, 1, now),
            Err(PublishError::InvalidMapping)
        ));
        let mut wrong_family = request("db.example", 1, Duration::from_secs(5));
        wrong_family.pinned_addresses = vec!["2001:db8::8".parse().unwrap()];
        assert!(matches!(
            store.publish(wrong_family, 1, now),
            Err(PublishError::InvalidMapping)
        ));
    }

    #[test]
    fn pool_high_water_event_reports_capacity_without_reclaiming_addresses() {
        let event = build_pool_high_water_event(4, 5, AddressFamily::Ipv4);
        let json = serde_json::to_value(event).unwrap();
        assert_eq!(json["unmapped"]["allocated_identities"], 4);
        assert_eq!(json["unmapped"]["mapping_capacity"], 5);
        assert_eq!(json["unmapped"]["address_family"], "ipv4");
        assert_eq!(json["state"], "high_water");
    }

    #[test]
    fn production_sized_ipv4_pool_reaches_its_own_high_water_mark() {
        let pools = SyntheticPools::new(
            Ipv4Addr::new(198, 18, 0, 0)..=Ipv4Addr::new(198, 18, 1, 255),
            "fd23:6f70:656e::".parse().unwrap()..="fd23:6f70:656e::1ff".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(pools.capacity(AddressFamily::Ipv4), 512);
        assert_eq!(pools.capacity(AddressFamily::Ipv6), 512);
        let store = ResolvedEndpointStore::new(StoreConfig::new(pools, 1024).unwrap());
        let now = Instant::now();

        for index in 0..410 {
            store
                .publish(
                    request(&format!("host-{index}.example"), 1, Duration::from_secs(5)),
                    1,
                    now,
                )
                .unwrap();
        }

        assert!(store.ipv4_pool_high_water_emitted.load(Ordering::Relaxed));
        assert!(!store.ipv6_pool_high_water_emitted.load(Ordering::Relaxed));
    }

    #[test]
    fn older_generation_cannot_replace_newer_live_mapping() {
        let store = store(1);
        let now = Instant::now();
        let newer = store
            .publish(request("db.example", 2, Duration::from_secs(10)), 2, now)
            .unwrap();

        assert!(matches!(
            store.publish(
                request("db.example", 1, Duration::from_secs(10)),
                1,
                now + Duration::from_secs(1),
            ),
            Err(PublishError::StalePolicy)
        ));

        let mapping = store.lookup(newer.synthetic_address, 5432, now).unwrap();
        assert_eq!(mapping.record.mapping_id, newer.mapping_id);
        assert_eq!(mapping.record.policy_generation, 2);
    }

    #[test]
    fn real_address_never_inherits_synthetic_mapping() {
        let store = store(1);
        let now = Instant::now();
        store
            .publish(request("db.example", 1, Duration::from_secs(5)), 1, now)
            .unwrap();
        assert!(matches!(
            store.lookup("203.0.113.8".parse().unwrap(), 5432, now),
            Err(MappingLookupError::Missing)
        ));
    }

    #[test]
    fn ipv6_pool_allocates_only_ipv6_synthetic_addresses() {
        let store = store(1);
        let now = Instant::now();
        let mut request = request("db.example", 1, Duration::from_secs(5));
        request.family = AddressFamily::Ipv6;
        request.pinned_addresses = vec!["2001:db8::8".parse().unwrap()];
        let record = store.publish(request, 1, now).unwrap();
        assert!(record.synthetic_address.is_ipv6());
        assert_eq!(record.family, AddressFamily::Ipv6);
    }

    #[test]
    fn concurrent_refreshes_never_publish_partial_records() {
        let store = Arc::new(store(1));
        let barrier = Arc::new(Barrier::new(9));
        let now = Instant::now();
        let mut workers = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                store
                    .publish(request("db.example", 3, Duration::from_secs(5)), 3, now)
                    .unwrap()
            }));
        }
        barrier.wait();
        let records = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert!(
            records
                .iter()
                .all(|record| record.synthetic_address == records[0].synthetic_address)
        );
        let lookup = store
            .lookup(records[0].synthetic_address, 5432, now)
            .unwrap();
        assert!(!lookup.record.pinned_addresses.is_empty());
        assert!(records.iter().all(|record| record.mapping_generation > 0));
    }

    #[tokio::test]
    async fn connector_uses_only_pinned_addresses() {
        let store = store(1);
        let now = Instant::now();
        let record = store
            .publish(
                request("must-not-resolve.invalid", 1, Duration::from_secs(5)),
                1,
                now,
            )
            .unwrap();
        let lookup = store.lookup(record.synthetic_address, 5432, now).unwrap();
        let connector = lookup.connector_for(&exact_host()).await.unwrap();
        assert_eq!(connector.addrs(), &["203.0.113.8:5432".parse().unwrap()]);
    }

    /// The deciding endpoint's destination rules select from the pinned
    /// addresses; an address pinned for a looser endpoint of the same name is
    /// not reachable through a stricter one.
    #[tokio::test]
    async fn connector_keeps_only_addresses_the_deciding_endpoint_permits() {
        let store = store(1);
        let now = Instant::now();
        let mut request = request("must-not-resolve.invalid", 1, Duration::from_secs(5));
        request.pinned_addresses = vec!["10.2.3.4".parse().unwrap(), "8.8.8.8".parse().unwrap()];
        let record = store.publish(request, 1, now).unwrap();
        let lookup = store.lookup(record.synthetic_address, 5432, now).unwrap();
        let public_only = DestinationValidationPlan {
            address_authorization: AddressAuthorization::DefaultPublicOnly,
        };

        let connector = lookup.connector_for(&public_only).await.unwrap();
        assert_eq!(connector.addrs(), &["8.8.8.8:5432".parse().unwrap()]);
        let connector = lookup.connector_for(&exact_host()).await.unwrap();
        assert_eq!(
            connector.addrs(),
            &[
                "10.2.3.4:5432".parse().unwrap(),
                "8.8.8.8:5432".parse().unwrap()
            ]
        );

        let mut private_only = self::request("private.invalid", 1, Duration::from_secs(5));
        private_only.pinned_addresses = vec!["10.2.3.4".parse().unwrap()];
        let store = self::store(1);
        let record = store.publish(private_only, 1, now).unwrap();
        let lookup = store.lookup(record.synthetic_address, 5432, now).unwrap();
        assert!(matches!(
            lookup.connector_for(&public_only).await,
            Err(MappingLookupError::InvalidMapping)
        ));
    }

    #[tokio::test]
    async fn connector_preserves_resolver_address_order_while_deduplicating() {
        let store = store(1);
        let now = Instant::now();
        let mut request = request("must-not-resolve.invalid", 1, Duration::from_secs(5));
        request.pinned_addresses = vec![
            "203.0.113.20".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            "203.0.113.20".parse().unwrap(),
        ];
        let record = store.publish(request, 1, now).unwrap();
        let lookup = store.lookup(record.synthetic_address, 5432, now).unwrap();

        let connector = lookup.connector_for(&exact_host()).await.unwrap();

        assert_eq!(
            connector.addrs(),
            &[
                "203.0.113.20:5432".parse().unwrap(),
                "203.0.113.10:5432".parse().unwrap(),
            ]
        );
    }
}
