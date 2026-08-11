// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::redundant_pub_crate,
    reason = "the crate-private API is consumed by the runtime activation slice"
)]

//! Dormant policy-gated DNS and synthetic resolved-endpoint correlation.
//!
//! This module implements the DNS security boundary and mapping state only.
//! Runtime listener startup, resolver injection, and transparent TCP capture
//! intentionally land in later stack entries.

#![allow(
    dead_code,
    unused_imports,
    reason = "PR2 exposes a dormant library boundary consumed by PR3 runtime wiring"
)]

mod name;
mod resolver;
mod store;
mod wire;

pub(crate) use name::NormalizedName;
pub(crate) use resolver::{AddressFamily, SocketTrustedResolver, TrustedAnswer, TrustedResolver};
pub(crate) use store::{
    MappingLookup, MappingLookupError, PolicyDnsMetricsSnapshot, PolicyEndpointId, PublishError,
    PublishRequest, ResolvedEndpointRecord, ResolvedEndpointStore, ResolvedPortContract,
    StoreConfig, SyntheticPools,
};

use crate::opa::OpaEngine;
use crate::proxy::destination::{build_validation_plan, filter_resolved_addresses};
use openshell_core::host_pattern::HostSelector;
use openshell_ocsf::{
    ActionId, ActivityId, ConfigStateChangeBuilder, DispositionId, Endpoint,
    NetworkActivityBuilder, SeverityId, StateId, StatusId, ocsf_emit,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(crate) const MIN_MAPPING_TTL: Duration = Duration::from_secs(1);
pub(crate) const MAX_MAPPING_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SyntheticAnswer {
    pub(crate) address: std::net::IpAddr,
    pub(crate) ttl: Duration,
    pub(crate) mapping_id: uuid::Uuid,
    pub(crate) mapping_generation: u64,
    pub(crate) policy_generation: u64,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PolicyDnsError {
    #[error("DNS query name is invalid")]
    InvalidName,
    #[error("DNS name is not eligible for policy DNS")]
    Ineligible,
    #[error("trusted resolver failed: {0}")]
    Resolver(#[from] resolver::ResolveError),
    #[error("no trusted resolver address passed endpoint destination policy")]
    NoValidAddress,
    #[error("policy generation changed before DNS mapping publication")]
    StalePolicy,
    #[error("resolved endpoint mapping could not be published: {0}")]
    Publish(#[from] PublishError),
    #[error("policy DNS eligibility snapshot failed: {0}")]
    Policy(String),
}

/// Policy-gated DNS evaluator and synthetic mapping publisher.
///
/// No socket is bound by this type. A later runtime adapter owns listener and
/// namespace lifecycle and calls the bounded wire helpers in this module.
pub(crate) struct PolicyDnsService<R> {
    policy: Arc<OpaEngine>,
    resolver: R,
    store: Arc<ResolvedEndpointStore>,
}

impl<R: TrustedResolver> PolicyDnsService<R> {
    pub(crate) fn new(
        policy: Arc<OpaEngine>,
        resolver: R,
        store: Arc<ResolvedEndpointStore>,
    ) -> Self {
        Self {
            policy,
            resolver,
            store,
        }
    }

    pub(crate) async fn answer_query(
        &self,
        raw_name: &str,
        family: AddressFamily,
        now: Instant,
    ) -> Result<SyntheticAnswer, PolicyDnsError> {
        self.store.note_query();
        let normalized_name =
            NormalizedName::parse(raw_name).map_err(|_| PolicyDnsError::InvalidName)?;
        let snapshot = self
            .policy
            .policy_dns_eligibility_snapshot()
            .map_err(|error| PolicyDnsError::Policy(error.to_string()))?;
        let eligible = eligible_endpoints(&snapshot.endpoints, &normalized_name)?;
        if eligible.is_empty() {
            self.store.note_refused();
            emit_dns_denial(
                &normalized_name,
                "policy_dns_ineligible",
                "Policy DNS refused a name that is not eligible in the active policy",
            );
            return Err(PolicyDnsError::Ineligible);
        }

        // The trusted resolver is invoked only after the immutable snapshot
        // proved policy eligibility. It never consults sandbox resolver state.
        self.store.note_upstream_query();
        let trusted_answer = self.resolver.resolve(&normalized_name, family).await?;
        let ttl = clamp_mapping_ttl(trusted_answer.ttl);
        let allocation_identity = allocation_identity(&eligible);
        let mut contracts = Vec::new();
        for endpoint in eligible {
            for port in endpoint.ports {
                let Ok(pinned_addresses) = filter_resolved_addresses(
                    &endpoint.destination_plan,
                    normalized_name.as_str(),
                    port,
                    &trusted_answer.addresses,
                ) else {
                    continue;
                };
                contracts.push(ResolvedPortContract {
                    endpoint_id: endpoint.endpoint_id.clone(),
                    port,
                    destination_plan: endpoint.destination_plan.clone(),
                    pinned_addresses,
                });
            }
        }
        contracts.sort_by(|left, right| {
            (&left.endpoint_id, left.port).cmp(&(&right.endpoint_id, right.port))
        });
        if contracts.is_empty() {
            self.store.note_no_valid_address();
            emit_dns_denial(
                &normalized_name,
                "policy_dns_no_valid_address",
                "Policy DNS rejected every trusted resolver address",
            );
            return Err(PolicyDnsError::NoValidAddress);
        }

        let current_generation = self.policy.current_generation();
        if current_generation != snapshot.generation {
            return Err(PolicyDnsError::StalePolicy);
        }
        let record = self.store.publish(
            PublishRequest {
                normalized_name: normalized_name.clone(),
                family,
                allocation_identity,
                policy_generation: snapshot.generation,
                ttl,
                contracts,
            },
            current_generation,
            now,
        )?;
        emit_mapping_publication(&record);
        Ok(SyntheticAnswer {
            address: record.synthetic_address,
            ttl,
            mapping_id: record.mapping_id,
            mapping_generation: record.mapping_generation,
            policy_generation: record.policy_generation,
        })
    }

    pub(crate) fn store(&self) -> &Arc<ResolvedEndpointStore> {
        &self.store
    }
}

struct EligibleEndpoint {
    endpoint_id: PolicyEndpointId,
    ports: Vec<u16>,
    destination_plan: crate::proxy::destination::DestinationValidationPlan,
    contract_fingerprint: String,
}

fn eligible_endpoints(
    endpoints: &[crate::opa::MatchedEndpoint],
    name: &NormalizedName,
) -> Result<Vec<EligibleEndpoint>, PolicyDnsError> {
    let mut eligible = Vec::new();
    for endpoint in endpoints {
        let Some(pattern) = value_string(&endpoint.endpoint, "host") else {
            continue;
        };
        let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
        let selector = HostSelector::new(std::slice::from_ref(&pattern), &[])
            .map_err(PolicyDnsError::Policy)?;
        if !selector.matches(name.as_str()) {
            continue;
        }
        let ports = value_ports(&endpoint.endpoint);
        if ports.is_empty() {
            continue;
        }
        let raw_allowed_ips = value_string_array(&endpoint.endpoint, "allowed_ips");
        let exact_declared_host = !pattern.contains('*') && pattern == name.as_str();
        let destination_plan = build_validation_plan(
            name.as_str(),
            name.as_str(),
            None,
            &raw_allowed_ips,
            exact_declared_host,
        )
        .map_err(|error| PolicyDnsError::Policy(error.reason))?;
        eligible.push(EligibleEndpoint {
            endpoint_id: PolicyEndpointId {
                policy_name: endpoint.policy_name.clone(),
                endpoint_index: endpoint.endpoint_index,
            },
            ports,
            destination_plan,
            contract_fingerprint: endpoint.endpoint.to_string(),
        });
    }
    Ok(eligible)
}

fn allocation_identity(endpoints: &[EligibleEndpoint]) -> [u8; 32] {
    let mut contracts = endpoints
        .iter()
        .map(|endpoint| {
            format!(
                "{}\0{}\0{}",
                endpoint.endpoint_id.policy_name,
                endpoint.endpoint_id.endpoint_index,
                endpoint.contract_fingerprint
            )
        })
        .collect::<Vec<_>>();
    contracts.sort();
    let mut hasher = Sha256::new();
    for contract in contracts {
        hasher.update(contract.as_bytes());
        hasher.update([0xff]);
    }
    hasher.finalize().into()
}

fn value_field<'a>(value: &'a regorus::Value, key: &str) -> Option<&'a regorus::Value> {
    let regorus::Value::Object(fields) = value else {
        return None;
    };
    fields.get(&regorus::Value::String(key.into()))
}

fn value_string(value: &regorus::Value, key: &str) -> Option<String> {
    match value_field(value, key) {
        Some(regorus::Value::String(value)) => Some(value.to_string()),
        _ => None,
    }
}

fn value_string_array(value: &regorus::Value, key: &str) -> Vec<String> {
    match value_field(value, key) {
        Some(regorus::Value::Array(values)) => values
            .iter()
            .filter_map(|value| match value {
                regorus::Value::String(value) => Some(value.to_string()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn value_ports(value: &regorus::Value) -> Vec<u16> {
    let mut ports = match value_field(value, "ports") {
        Some(regorus::Value::Array(values)) => values
            .iter()
            .filter_map(|value| match value {
                regorus::Value::Number(number) => number
                    .as_i64()
                    .and_then(|port| u16::try_from(port).ok())
                    .filter(|port| *port != 0),
                _ => None,
            })
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn clamp_mapping_ttl(ttl: Duration) -> Duration {
    ttl.max(MIN_MAPPING_TTL).min(MAX_MAPPING_TTL)
}

fn emit_dns_denial(name: &NormalizedName, detail: &str, message: &str) {
    ocsf_emit!(
        NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .activity(ActivityId::Refuse)
            .action(ActionId::Denied)
            .disposition(DispositionId::Blocked)
            .severity(SeverityId::Medium)
            .status(StatusId::Failure)
            .dst_endpoint(Endpoint::from_domain(name.as_str(), 53))
            .status_detail(detail)
            .message(message)
            .build()
    );
}

fn emit_mapping_publication(record: &ResolvedEndpointRecord) {
    ocsf_emit!(
        ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .state(StateId::Enabled, "published")
            .unmapped("normalized_name", record.normalized_name.as_str())
            .unmapped("address_family", format!("{:?}", record.family))
            .unmapped("allowed_port_count", record.allowed_ports().len() as u64)
            .unmapped("policy_generation", record.policy_generation)
            .unmapped("mapping_generation", record.mapping_generation)
            .unmapped("mapping_id", record.mapping_id.to_string())
            .message("Policy DNS resolved-endpoint mapping published")
            .build()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    struct FakeResolver {
        calls: AtomicUsize,
        answer: TrustedAnswer,
    }

    impl TrustedResolver for FakeResolver {
        async fn resolve(
            &self,
            _name: &NormalizedName,
            _family: AddressFamily,
        ) -> Result<TrustedAnswer, resolver::ResolveError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.answer.clone())
        }
    }

    fn service(policy_yaml: &str, addresses: Vec<IpAddr>) -> PolicyDnsService<FakeResolver> {
        let policy = Arc::new(
            OpaEngine::from_strings(include_str!("../../data/sandbox-policy.rego"), policy_yaml)
                .unwrap(),
        );
        let pools = SyntheticPools::new(
            Ipv4Addr::new(198, 18, 0, 1)..=Ipv4Addr::new(198, 18, 0, 8),
            "fd00:1::1".parse::<Ipv6Addr>().unwrap()..="fd00:1::8".parse::<Ipv6Addr>().unwrap(),
        )
        .unwrap();
        PolicyDnsService::new(
            policy,
            FakeResolver {
                calls: AtomicUsize::new(0),
                answer: TrustedAnswer {
                    addresses,
                    ttl: Duration::from_secs(300),
                },
            },
            Arc::new(ResolvedEndpointStore::new(
                StoreConfig::new(pools, 16).unwrap(),
            )),
        )
    }

    const BASE_POLICY: &str = r"
network_policies:
  database:
    name: database
    endpoints:
      - { host: db.example, port: 5432, protocol: tcp }
    binaries: [{ path: /usr/bin/psql }]
filesystem_policy: { include_workdir: true, read_only: [], read_write: [] }
landlock: { compatibility: best_effort }
process: { run_as_user: sandbox, run_as_group: sandbox }
";

    #[tokio::test]
    async fn refuses_ineligible_name_before_upstream_resolution() {
        let service = service(BASE_POLICY, vec!["8.8.8.8".parse().unwrap()]);
        let result = service
            .answer_query("other.example", AddressFamily::Ipv4, Instant::now())
            .await;
        assert!(matches!(result, Err(PolicyDnsError::Ineligible)));
        assert_eq!(service.resolver.calls.load(Ordering::SeqCst), 0);
        assert_eq!(service.store.metrics(Instant::now()).refused, 1);
    }

    #[tokio::test]
    async fn eligible_name_filters_answers_and_publishes_bounded_mapping() {
        let service = service(
            BASE_POLICY,
            vec!["127.0.0.1".parse().unwrap(), "10.2.3.4".parse().unwrap()],
        );
        let now = Instant::now();
        let answer = service
            .answer_query("DB.EXAMPLE.", AddressFamily::Ipv4, now)
            .await
            .unwrap();
        assert_eq!(answer.ttl, MAX_MAPPING_TTL);
        let mapping = service
            .store
            .lookup(answer.address, 5432, answer.policy_generation, now)
            .unwrap();
        assert_eq!(mapping.record.normalized_name.as_str(), "db.example");
        assert_eq!(
            mapping.record.contracts[0].pinned_addresses,
            ["10.2.3.4".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn wildcard_is_eligible_but_uses_public_only_destination_rules() {
        let yaml = BASE_POLICY.replace("db.example", "'*.example.com'");
        let service = service(&yaml, vec!["10.2.3.4".parse().unwrap()]);
        let result = service
            .answer_query("db.example.com", AddressFamily::Ipv4, Instant::now())
            .await;
        assert!(matches!(result, Err(PolicyDnsError::NoValidAddress)));
    }

    #[tokio::test]
    async fn allowed_ips_filters_each_answer_without_rejecting_usable_addresses() {
        let yaml =
            BASE_POLICY.replace("protocol: tcp", "protocol: tcp, allowed_ips: [10.2.0.0/16]");
        let service = service(
            &yaml,
            vec!["10.3.4.5".parse().unwrap(), "10.2.3.4".parse().unwrap()],
        );
        let now = Instant::now();
        let answer = service
            .answer_query("db.example", AddressFamily::Ipv4, now)
            .await
            .unwrap();
        let mapping = service
            .store
            .lookup(answer.address, 5432, answer.policy_generation, now)
            .unwrap();
        assert_eq!(
            mapping.record.contracts[0].pinned_addresses,
            ["10.2.3.4".parse::<IpAddr>().unwrap()]
        );
    }

    struct BlockingResolver {
        started: Arc<Notify>,
        release: Arc<Notify>,
    }

    impl TrustedResolver for BlockingResolver {
        async fn resolve(
            &self,
            _name: &NormalizedName,
            _family: AddressFamily,
        ) -> Result<TrustedAnswer, resolver::ResolveError> {
            self.started.notify_one();
            self.release.notified().await;
            Ok(TrustedAnswer {
                addresses: vec!["8.8.8.8".parse().unwrap()],
                ttl: Duration::from_secs(10),
            })
        }
    }

    #[tokio::test]
    async fn policy_reload_during_resolution_publishes_nothing() {
        let policy = Arc::new(
            OpaEngine::from_strings(include_str!("../../data/sandbox-policy.rego"), BASE_POLICY)
                .unwrap(),
        );
        let pools = SyntheticPools::new(
            Ipv4Addr::new(198, 18, 0, 1)..=Ipv4Addr::new(198, 18, 0, 2),
            "fd00:1::1".parse::<Ipv6Addr>().unwrap()..="fd00:1::2".parse::<Ipv6Addr>().unwrap(),
        )
        .unwrap();
        let store = Arc::new(ResolvedEndpointStore::new(
            StoreConfig::new(pools, 4).unwrap(),
        ));
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let service = Arc::new(PolicyDnsService::new(
            policy.clone(),
            BlockingResolver {
                started: started.clone(),
                release: release.clone(),
            },
            store.clone(),
        ));
        let query = tokio::spawn(async move {
            service
                .answer_query("db.example", AddressFamily::Ipv4, Instant::now())
                .await
        });
        started.notified().await;
        policy
            .reload(include_str!("../../data/sandbox-policy.rego"), BASE_POLICY)
            .unwrap();
        release.notify_one();
        assert!(matches!(
            query.await.unwrap(),
            Err(PolicyDnsError::StalePolicy)
        ));
        let metrics = store.metrics(Instant::now());
        assert_eq!(metrics.active_mappings, 0);
        assert_eq!(metrics.allocated_identities, 0);
    }

    #[test]
    fn ttl_is_floored_and_capped() {
        assert_eq!(clamp_mapping_ttl(Duration::ZERO), MIN_MAPPING_TTL);
        assert_eq!(
            clamp_mapping_ttl(Duration::from_secs(10)),
            Duration::from_secs(10)
        );
        assert_eq!(clamp_mapping_ttl(Duration::from_secs(300)), MAX_MAPPING_TTL);
    }
}
