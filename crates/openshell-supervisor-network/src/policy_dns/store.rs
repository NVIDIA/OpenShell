// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Synthetic-address allocation and resolved endpoint mappings.

use super::name::NormalizedName;
use super::resolver::AddressFamily;
use crate::proxy::destination::{
    DestinationRequest, DestinationValidationPlan, UpstreamConnector, build_pinned_validation_plan,
    validate_destination,
};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct PolicyEndpointId {
    pub(crate) policy_name: String,
    pub(crate) endpoint_index: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedPortContract {
    pub(crate) endpoint_id: PolicyEndpointId,
    pub(crate) port: u16,
    pub(crate) destination_plan: DestinationValidationPlan,
    pub(crate) pinned_addresses: Vec<IpAddr>,
}

#[derive(Debug, Clone)]
pub(crate) struct PublishRequest {
    pub(crate) normalized_name: NormalizedName,
    pub(crate) family: AddressFamily,
    /// Digest of every compatible endpoint identity and its policy metadata.
    /// A changed endpoint contract receives a new synthetic identity even when
    /// it selects the same normalized name.
    pub(crate) allocation_identity: [u8; 32],
    pub(crate) policy_generation: u64,
    pub(crate) ttl: Duration,
    pub(crate) contracts: Vec<ResolvedPortContract>,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedEndpointRecord {
    pub(crate) synthetic_address: IpAddr,
    pub(crate) normalized_name: NormalizedName,
    pub(crate) family: AddressFamily,
    pub(crate) policy_generation: u64,
    pub(crate) mapping_generation: u64,
    pub(crate) mapping_id: Uuid,
    pub(crate) created_at: Instant,
    pub(crate) expires_at: Instant,
    pub(crate) contracts: Vec<ResolvedPortContract>,
}

impl ResolvedEndpointRecord {
    pub(crate) fn allowed_ports(&self) -> BTreeSet<u16> {
        self.contracts
            .iter()
            .map(|contract| contract.port)
            .collect()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MappingLookup {
    pub(crate) record: ResolvedEndpointRecord,
    pub(crate) port: u16,
}

impl MappingLookup {
    pub(crate) fn endpoint_ids(&self) -> impl Iterator<Item = &PolicyEndpointId> {
        self.record
            .contracts
            .iter()
            .filter(move |contract| contract.port == self.port)
            .map(|contract| &contract.endpoint_id)
    }

    /// Build the unopened connector for a process-authorized endpoint.
    ///
    /// Selecting by endpoint identity prevents a compatible endpoint record
    /// from becoming a new policy precedence rule. The pinned destination mode
    /// never resolves `normalized_name` again.
    pub(crate) async fn connector_for(
        &self,
        endpoint_id: &PolicyEndpointId,
    ) -> Result<UpstreamConnector, MappingLookupError> {
        let mut seen = HashSet::new();
        let addresses = self
            .record
            .contracts
            .iter()
            .filter(|contract| contract.port == self.port && &contract.endpoint_id == endpoint_id)
            .flat_map(|contract| contract.pinned_addresses.iter().copied())
            .filter(|address| seen.insert(*address))
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            return Err(MappingLookupError::EndpointMismatch);
        }
        let plan = build_pinned_validation_plan(addresses)
            .map_err(|_| MappingLookupError::InvalidMapping)?;
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
    #[error("resolved endpoint store lock was poisoned")]
    LockPoisoned,
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MappingLookupError {
    #[error("transparent TCP mapping is missing")]
    Missing,
    #[error("transparent TCP mapping is expired")]
    Expired,
    #[error("transparent TCP mapping belongs to a stale policy generation")]
    StalePolicy,
    #[error("transparent TCP mapping does not authorize the requested port")]
    PortMismatch,
    #[error("transparent TCP mapping does not contain the authorized endpoint")]
    EndpointMismatch,
    #[error("transparent TCP mapping is internally invalid")]
    InvalidMapping,
    #[error("resolved endpoint store lock was poisoned")]
    LockPoisoned,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AllocationKey {
    normalized_name: NormalizedName,
    family: AddressFamily,
    allocation_identity: [u8; 32],
}

struct StoreState {
    records: BTreeMap<IpAddr, ResolvedEndpointRecord>,
    allocations: BTreeMap<AllocationKey, IpAddr>,
    expired_allocations: BTreeSet<IpAddr>,
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
                expired_allocations: BTreeSet::new(),
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
            || request.contracts.is_empty()
            || request.contracts.iter().any(|contract| {
                contract.port == 0
                    || contract.pinned_addresses.is_empty()
                    || contract
                        .pinned_addresses
                        .iter()
                        .any(|address| !request.family.accepts(*address))
            })
        {
            return Err(PublishError::InvalidMapping);
        }

        let key = AllocationKey {
            normalized_name: request.normalized_name.clone(),
            family: request.family,
            allocation_identity: request.allocation_identity,
        };
        let mut state = self.state.write().map_err(|_| PublishError::LockPoisoned)?;
        let synthetic_address = if let Some(address) = state.allocations.get(&key) {
            *address
        } else {
            if state.allocations.len() >= self.config.max_mappings {
                return Err(PublishError::PoolExhausted);
            }
            let address =
                allocate_address(&mut state, request.family).ok_or(PublishError::PoolExhausted)?;
            state.allocations.insert(key, address);
            let allocated = state
                .allocations
                .keys()
                .filter(|key| key.family == request.family)
                .count();
            let capacity = self
                .config
                .pools
                .capacity(request.family)
                .min(self.config.max_mappings);
            let emitted = match request.family {
                AddressFamily::Ipv4 => &self.ipv4_pool_high_water_emitted,
                AddressFamily::Ipv6 => &self.ipv6_pool_high_water_emitted,
            };
            if allocated.saturating_mul(5) >= capacity.saturating_mul(4)
                && !emitted.swap(true, Ordering::Relaxed)
            {
                openshell_ocsf::ocsf_emit!(build_pool_high_water_event(
                    allocated,
                    capacity,
                    request.family,
                ));
            }
            address
        };

        // Defense in depth for callers outside the OPA generation guard: a
        // delayed publication from an older generation must never replace a
        // newer live correlation for the same stable allocation identity.
        if state
            .records
            .get(&synthetic_address)
            .is_some_and(|record| record.policy_generation > request.policy_generation)
        {
            return Err(PublishError::StalePolicy);
        }

        state.next_mapping_generation = state.next_mapping_generation.saturating_add(1);
        let record = ResolvedEndpointRecord {
            synthetic_address,
            normalized_name: request.normalized_name,
            family: request.family,
            policy_generation: request.policy_generation,
            mapping_generation: state.next_mapping_generation,
            mapping_id: Uuid::new_v4(),
            created_at: now,
            expires_at: now + request.ttl,
            contracts: request.contracts,
        };
        state.expired_allocations.remove(&synthetic_address);
        state.records.insert(synthetic_address, record.clone());
        Ok(record)
    }

    pub(crate) fn lookup(
        &self,
        synthetic_address: IpAddr,
        port: u16,
        current_policy_generation: u64,
        now: Instant,
    ) -> Result<MappingLookup, MappingLookupError> {
        let state = self
            .state
            .read()
            .map_err(|_| MappingLookupError::LockPoisoned)?;
        let Some(record) = state.records.get(&synthetic_address) else {
            return if state.expired_allocations.contains(&synthetic_address) {
                Err(MappingLookupError::Expired)
            } else {
                Err(MappingLookupError::Missing)
            };
        };
        if now >= record.expires_at {
            return Err(MappingLookupError::Expired);
        }
        if record.policy_generation != current_policy_generation {
            return Err(MappingLookupError::StalePolicy);
        }
        if !record
            .contracts
            .iter()
            .any(|contract| contract.port == port)
        {
            return Err(MappingLookupError::PortMismatch);
        }
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
            state.records.remove(address);
            state.expired_allocations.insert(*address);
        }
        Ok(expired.len())
    }
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
            allocation_identity: [1; 32],
            policy_generation: generation,
            ttl,
            contracts: vec![ResolvedPortContract {
                endpoint_id: PolicyEndpointId {
                    policy_name: "database".to_string(),
                    endpoint_index: 0,
                },
                port: 5432,
                destination_plan: DestinationValidationPlan {
                    address_authorization: AddressAuthorization::ExactDeclaredHost,
                },
                pinned_addresses: vec!["203.0.113.8".parse().unwrap()],
            }],
        }
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
        assert_eq!(
            left.contracts[0].pinned_addresses,
            right.contracts[0].pinned_addresses
        );
    }

    #[test]
    fn wrong_port_stale_generation_and_expiry_fail_closed() {
        let store = store(2);
        let now = Instant::now();
        let record = store
            .publish(request("db.example", 4, Duration::from_secs(2)), 4, now)
            .unwrap();
        assert!(matches!(
            store.lookup(record.synthetic_address, 3306, 4, now),
            Err(MappingLookupError::PortMismatch)
        ));
        assert!(matches!(
            store.lookup(record.synthetic_address, 5432, 5, now),
            Err(MappingLookupError::StalePolicy)
        ));
        assert!(matches!(
            store.lookup(
                record.synthetic_address,
                5432,
                4,
                now + Duration::from_secs(2)
            ),
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
            store.lookup(
                first.synthetic_address,
                5432,
                1,
                now + Duration::from_secs(1)
            ),
            Err(MappingLookupError::Expired)
        ));
    }

    #[test]
    fn changed_endpoint_contract_never_reuses_synthetic_identity() {
        let store = store(2);
        let now = Instant::now();
        let first = store
            .publish(request("db.example", 1, Duration::from_secs(5)), 1, now)
            .unwrap();
        let mut changed = request("db.example", 2, Duration::from_secs(5));
        changed.allocation_identity = [2; 32];
        let second = store.publish(changed, 2, now).unwrap();
        assert_ne!(first.synthetic_address, second.synthetic_address);
        assert!(matches!(
            store.lookup(first.synthetic_address, 5432, 2, now),
            Err(MappingLookupError::StalePolicy)
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
            .lookup(first.synthetic_address, 5432, 2, now)
            .expect("pool exhaustion must preserve the existing mapping");
        assert_eq!(preserved.record.mapping_id, first.mapping_id);
        assert!(matches!(
            store.lookup("198.18.0.2".parse().unwrap(), 5432, 2, now),
            Err(MappingLookupError::Missing)
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

        let mapping = store.lookup(newer.synthetic_address, 5432, 2, now).unwrap();
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
            store.lookup("203.0.113.8".parse().unwrap(), 5432, 1, now),
            Err(MappingLookupError::Missing)
        ));
    }

    #[test]
    fn ipv6_pool_allocates_only_ipv6_synthetic_addresses() {
        let store = store(1);
        let now = Instant::now();
        let mut request = request("db.example", 1, Duration::from_secs(5));
        request.family = AddressFamily::Ipv6;
        request.contracts[0].pinned_addresses = vec!["2001:db8::8".parse().unwrap()];
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
            .lookup(records[0].synthetic_address, 5432, 3, now)
            .unwrap();
        assert!(!lookup.record.contracts.is_empty());
        assert!(!lookup.record.contracts[0].pinned_addresses.is_empty());
        assert!(records.iter().all(|record| record.mapping_generation > 0));
    }

    #[tokio::test]
    async fn connector_uses_only_pinned_addresses_and_endpoint_identity() {
        let store = store(1);
        let now = Instant::now();
        let record = store
            .publish(
                request("must-not-resolve.invalid", 1, Duration::from_secs(5)),
                1,
                now,
            )
            .unwrap();
        let lookup = store
            .lookup(record.synthetic_address, 5432, 1, now)
            .unwrap();
        let endpoint = lookup.endpoint_ids().next().unwrap().clone();
        let connector = lookup.connector_for(&endpoint).await.unwrap();
        assert_eq!(connector.addrs(), &["203.0.113.8:5432".parse().unwrap()]);
    }

    #[tokio::test]
    async fn connector_preserves_resolver_address_order_while_deduplicating() {
        let store = store(1);
        let now = Instant::now();
        let mut request = request("must-not-resolve.invalid", 1, Duration::from_secs(5));
        request.contracts[0].pinned_addresses = vec![
            "203.0.113.20".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            "203.0.113.20".parse().unwrap(),
        ];
        let record = store.publish(request, 1, now).unwrap();
        let lookup = store
            .lookup(record.synthetic_address, 5432, 1, now)
            .unwrap();
        let endpoint = lookup.endpoint_ids().next().unwrap().clone();

        let connector = lookup.connector_for(&endpoint).await.unwrap();

        assert_eq!(
            connector.addrs(),
            &[
                "203.0.113.20:5432".parse().unwrap(),
                "203.0.113.10:5432".parse().unwrap(),
            ]
        );
    }
}
