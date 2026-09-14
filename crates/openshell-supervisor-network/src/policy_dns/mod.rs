// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::redundant_pub_crate,
    reason = "the crate-private API is consumed by the runtime activation slice"
)]

//! Policy-gated DNS and synthetic resolved-endpoint correlation.
//!
//! The shared supervisor owns DNS eligibility and mapping state. Supported
//! runtimes provide namespace-local DNS and transparent TCP capture sockets.

#![allow(
    dead_code,
    unused_imports,
    reason = "the policy DNS boundary retains metrics and helpers for later runtime integrations"
)]

mod name;
mod resolver;
mod runtime;
mod store;
mod wire;

pub(crate) use name::NormalizedName;
pub(crate) use resolver::{AddressFamily, SocketTrustedResolver, TrustedAnswer, TrustedResolver};
pub(crate) use runtime::{PolicyDnsRuntime, PolicyDnsRuntimeConfig};
pub(crate) use store::{
    MappingLookup, MappingLookupError, PolicyEndpointId, PublishError, PublishRequest,
    ResolvedEndpointRecord, ResolvedEndpointStore, ResolvedPortContract, StoreConfig,
    SyntheticPools,
};

use crate::opa::OpaEngine;
use crate::proxy::destination::{build_validation_plan, filter_resolved_addresses};
use crate::proxy::is_host_gateway_alias;
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
    #[error("trusted host gateway is unavailable for the reserved alias")]
    TrustedGatewayUnavailable,
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
    trusted_host_gateway: Option<std::net::IpAddr>,
}

impl<R: TrustedResolver> PolicyDnsService<R> {
    pub(crate) fn new(
        policy: Arc<OpaEngine>,
        resolver: R,
        store: Arc<ResolvedEndpointStore>,
        trusted_host_gateway: Option<std::net::IpAddr>,
    ) -> Self {
        Self {
            policy,
            resolver,
            store,
            trusted_host_gateway,
        }
    }

    pub(crate) async fn answer_query(
        &self,
        raw_name: &str,
        family: AddressFamily,
        now: Instant,
    ) -> Result<SyntheticAnswer, PolicyDnsError> {
        let normalized_name =
            NormalizedName::parse(raw_name).map_err(|_| PolicyDnsError::InvalidName)?;
        if is_host_gateway_alias(normalized_name.as_str()) && self.trusted_host_gateway.is_none() {
            emit_dns_denial(
                &normalized_name,
                "policy_dns_trusted_gateway_unavailable",
                "Policy DNS refused a reserved host-gateway alias because no trusted gateway is configured",
            );
            return Err(PolicyDnsError::TrustedGatewayUnavailable);
        }
        let snapshot = self
            .policy
            .policy_dns_eligibility_snapshot()
            .map_err(|error| PolicyDnsError::Policy(error.to_string()))?;
        let eligible = eligible_endpoints(
            &snapshot.endpoints,
            &normalized_name,
            self.trusted_host_gateway,
        )?;
        if eligible.is_empty() {
            emit_dns_denial(
                &normalized_name,
                "policy_dns_ineligible",
                "Policy DNS refused a name that is not eligible in the active policy",
            );
            return Err(PolicyDnsError::Ineligible);
        }

        // The trusted resolver is invoked only after the immutable snapshot
        // proved policy eligibility. It never consults sandbox resolver state.
        let endpoint_context = eligible_endpoint_context(&eligible);
        let trusted_answer = match self.resolver.resolve(&normalized_name, family).await {
            Ok(answer) => answer,
            Err(error) => {
                emit_dns_failure(
                    &normalized_name,
                    family,
                    &endpoint_context,
                    snapshot.generation,
                    resolver_failure_detail(&error),
                    "Policy DNS trusted resolver query failed",
                );
                return Err(PolicyDnsError::Resolver(error));
            }
        };
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
            emit_dns_denial(
                &normalized_name,
                "policy_dns_no_valid_address",
                "Policy DNS rejected every trusted resolver address",
            );
            return Err(PolicyDnsError::NoValidAddress);
        }

        let request = PublishRequest {
            normalized_name: normalized_name.clone(),
            family,
            allocation_identity,
            policy_generation: snapshot.generation,
            ttl,
            contracts,
        };
        let record = match self
            .policy
            .with_current_generation(snapshot.generation, |current_generation| {
                self.store.publish(request, current_generation, now)
            }) {
            Ok(Some(Ok(record))) => record,
            Ok(Some(Err(error))) => {
                // InvalidMapping is unreachable for the well-formed request
                // assembled above, and LockPoisoned requires a prior panic
                // while holding the store lock. Keep both defensive outcomes
                // observable because the store API intentionally rejects them.
                emit_dns_failure(
                    &normalized_name,
                    family,
                    &endpoint_context,
                    snapshot.generation,
                    publication_failure_detail(error),
                    "Policy DNS resolved-endpoint mapping publication failed",
                );
                return Err(PolicyDnsError::Publish(error));
            }
            Ok(None) => {
                emit_dns_failure(
                    &normalized_name,
                    family,
                    &endpoint_context,
                    snapshot.generation,
                    "policy_dns_publication_stale_generation",
                    "Policy DNS discarded a stale resolved-endpoint mapping",
                );
                return Err(PolicyDnsError::StalePolicy);
            }
            Err(error) => {
                emit_dns_failure(
                    &normalized_name,
                    family,
                    &endpoint_context,
                    snapshot.generation,
                    "policy_dns_publication_generation_check_failed",
                    "Policy DNS could not validate the active policy generation before publication",
                );
                return Err(PolicyDnsError::Policy(error.to_string()));
            }
        };
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
    trusted_host_gateway: Option<std::net::IpAddr>,
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
            trusted_host_gateway,
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

fn eligible_endpoint_context(endpoints: &[EligibleEndpoint]) -> Vec<PolicyEndpointId> {
    let mut endpoint_ids = endpoints
        .iter()
        .map(|endpoint| endpoint.endpoint_id.clone())
        .collect::<Vec<_>>();
    endpoint_ids.sort();
    endpoint_ids.dedup();
    endpoint_ids
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

fn resolver_failure_detail(error: &resolver::ResolveError) -> &'static str {
    match error {
        resolver::ResolveError::Timeout => "policy_dns_upstream_timeout",
        resolver::ResolveError::Io(_) => "policy_dns_upstream_io_failed",
        resolver::ResolveError::Oversized => "policy_dns_upstream_oversized_response",
        resolver::ResolveError::Malformed => "policy_dns_upstream_malformed_response",
        resolver::ResolveError::NxDomain => "policy_dns_upstream_nxdomain",
        resolver::ResolveError::Response(_) => "policy_dns_upstream_error_response",
        resolver::ResolveError::NoData => "policy_dns_upstream_no_data",
        resolver::ResolveError::CnameLimit => "policy_dns_upstream_cname_limit",
    }
}

fn publication_failure_detail(error: PublishError) -> &'static str {
    match error {
        PublishError::StalePolicy => "policy_dns_publication_stale_generation",
        PublishError::InvalidMapping => "policy_dns_publication_invalid_mapping",
        PublishError::PoolExhausted => "policy_dns_publication_pool_exhausted",
        PublishError::LockPoisoned => "policy_dns_publication_store_unavailable",
    }
}

fn build_dns_failure_event(
    name: &NormalizedName,
    family: AddressFamily,
    eligible_endpoints: &[PolicyEndpointId],
    policy_generation: u64,
    detail: &str,
    message: &str,
) -> openshell_ocsf::OcsfEvent {
    let endpoint_context = eligible_endpoints
        .iter()
        .map(|endpoint| {
            serde_json::json!({
                "policy_name": endpoint.policy_name.as_str(),
                "endpoint_index": endpoint.endpoint_index,
            })
        })
        .collect::<Vec<_>>();
    NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Refuse)
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(SeverityId::Low)
        .status(StatusId::Failure)
        .dst_endpoint(Endpoint::from_domain(name.as_str(), 53))
        .status_detail(detail)
        .unmapped("normalized_name", name.as_str())
        .unmapped("address_family", family.as_str())
        .unmapped(
            "eligible_endpoints",
            serde_json::Value::Array(endpoint_context),
        )
        .unmapped("policy_generation", policy_generation)
        .message(message)
        .build()
}

fn emit_dns_failure(
    name: &NormalizedName,
    family: AddressFamily,
    eligible_endpoints: &[PolicyEndpointId],
    policy_generation: u64,
    detail: &str,
    message: &str,
) {
    ocsf_emit!(build_dns_failure_event(
        name,
        family,
        eligible_endpoints,
        policy_generation,
        detail,
        message,
    ));
}

fn emit_mapping_publication(record: &ResolvedEndpointRecord) {
    ocsf_emit!(build_mapping_publication_event(record));
}

fn build_mapping_publication_event(record: &ResolvedEndpointRecord) -> openshell_ocsf::OcsfEvent {
    let approved_real_ip_candidates = record
        .contracts
        .iter()
        .flat_map(|contract| contract.pinned_addresses.iter().copied())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|address| address.to_string())
        .collect::<Vec<_>>();
    let allowed_ports = record.allowed_ports().into_iter().collect::<Vec<_>>();
    let mapping_id = record.mapping_id.to_string();
    let message = format!(
        "Policy DNS mapped {} resolved={} synthetic={} ports={} mapping_id={mapping_id}",
        record.normalized_name,
        approved_real_ip_candidates.join(","),
        record.synthetic_address,
        allowed_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(","),
    );

    ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .state(StateId::Enabled, "published")
        .unmapped("normalized_domain", record.normalized_name.as_str())
        .unmapped("address_family", format!("{:?}", record.family))
        .unmapped(
            "approved_real_ip_candidates",
            serde_json::json!(approved_real_ip_candidates),
        )
        .unmapped("synthetic_ip", record.synthetic_address.to_string())
        .unmapped("allowed_ports", serde_json::json!(allowed_ports))
        .unmapped("policy_generation", record.policy_generation)
        .unmapped("mapping_generation", record.mapping_generation)
        .unmapped("mapping_id", mapping_id)
        .message(message)
        .build()
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

    struct NxDomainResolver;

    impl TrustedResolver for NxDomainResolver {
        async fn resolve(
            &self,
            _name: &NormalizedName,
            _family: AddressFamily,
        ) -> Result<TrustedAnswer, resolver::ResolveError> {
            Err(resolver::ResolveError::NxDomain)
        }
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
        service_with_gateway(policy_yaml, addresses, None)
    }

    fn service_with_gateway(
        policy_yaml: &str,
        addresses: Vec<IpAddr>,
        trusted_host_gateway: Option<IpAddr>,
    ) -> PolicyDnsService<FakeResolver> {
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
            trusted_host_gateway,
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
    }

    #[tokio::test]
    async fn eligible_nxdomain_fails_without_publishing_a_mapping() {
        let policy = Arc::new(
            OpaEngine::from_strings(include_str!("../../data/sandbox-policy.rego"), BASE_POLICY)
                .unwrap(),
        );
        let pools = SyntheticPools::new(
            Ipv4Addr::new(198, 18, 0, 1)..=Ipv4Addr::new(198, 18, 0, 1),
            "fd00:1::1".parse::<Ipv6Addr>().unwrap()..="fd00:1::1".parse::<Ipv6Addr>().unwrap(),
        )
        .unwrap();
        let store = Arc::new(ResolvedEndpointStore::new(
            StoreConfig::new(pools, 1).unwrap(),
        ));
        let service = PolicyDnsService::new(policy, NxDomainResolver, store.clone(), None);

        let result = service
            .answer_query("DB.EXAMPLE.", AddressFamily::Ipv4, Instant::now())
            .await;

        assert!(matches!(
            result,
            Err(PolicyDnsError::Resolver(resolver::ResolveError::NxDomain))
        ));
        assert!(matches!(
            store.lookup(
                "198.18.0.1".parse().unwrap(),
                5432,
                service.policy.current_generation(),
                Instant::now()
            ),
            Err(MappingLookupError::Missing)
        ));
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
    async fn mapping_publication_ocsf_exposes_correlatable_resolution_chain() {
        let service = service(
            BASE_POLICY,
            vec!["10.2.3.5".parse().unwrap(), "10.2.3.4".parse().unwrap()],
        );
        let now = Instant::now();
        let answer = service
            .answer_query("DB.EXAMPLE.", AddressFamily::Ipv4, now)
            .await
            .unwrap();
        let mapping = service
            .store
            .lookup(answer.address, 5432, answer.policy_generation, now)
            .unwrap();

        let event = build_mapping_publication_event(&mapping.record);
        let json = event.to_json().unwrap();
        let unmapped = &json["unmapped"];
        assert_eq!(unmapped["normalized_domain"], "db.example");
        assert_eq!(unmapped["synthetic_ip"], answer.address.to_string());
        assert_eq!(unmapped["allowed_ports"], serde_json::json!([5432]));
        assert_eq!(
            unmapped["approved_real_ip_candidates"],
            serde_json::json!(["10.2.3.4", "10.2.3.5"])
        );
        assert_eq!(unmapped["mapping_id"], answer.mapping_id.to_string());
        assert_eq!(unmapped["mapping_generation"], answer.mapping_generation);
        assert_eq!(unmapped["policy_generation"], answer.policy_generation);

        let shorthand = event.format_shorthand();
        assert!(shorthand.contains("Policy DNS mapped db.example"));
        assert!(shorthand.contains("resolved=10.2.3.4,10.2.3.5"));
        assert!(shorthand.contains(&format!("synthetic={}", answer.address)));
        assert!(shorthand.contains(&format!("mapping_id={}", answer.mapping_id)));
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

    const HOST_GATEWAY_POLICY: &str = r"
network_policies:
  gateway:
    name: gateway
    endpoints:
      - { host: host.openshell.internal, port: 8080, protocol: tcp }
    binaries: [{ path: /usr/bin/client }]
filesystem_policy: { include_workdir: true, read_only: [], read_write: [] }
landlock: { compatibility: best_effort }
process: { run_as_user: sandbox, run_as_group: sandbox }
";

    fn gateway_service(
        addresses: Vec<IpAddr>,
        trusted_host_gateway: Option<IpAddr>,
    ) -> PolicyDnsService<FakeResolver> {
        service_with_gateway(HOST_GATEWAY_POLICY, addresses, trusted_host_gateway)
    }

    #[tokio::test]
    async fn reserved_gateway_alias_without_trusted_address_never_queries_resolver() {
        for alias in [
            "host.openshell.internal",
            "host.containers.internal",
            "host.docker.internal",
        ] {
            let yaml = HOST_GATEWAY_POLICY.replace("host.openshell.internal", alias);
            let service = service_with_gateway(&yaml, vec!["169.254.1.2".parse().unwrap()], None);

            let result = service
                .answer_query(alias, AddressFamily::Ipv4, Instant::now())
                .await;

            assert!(matches!(
                result,
                Err(PolicyDnsError::TrustedGatewayUnavailable)
            ));
            assert_eq!(service.resolver.calls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn reserved_gateway_alias_pins_only_the_exact_trusted_address() {
        let trusted: IpAddr = "169.254.1.2".parse().unwrap();
        let service = gateway_service(
            vec![
                "169.254.169.254".parse().unwrap(),
                "169.254.1.3".parse().unwrap(),
                "10.2.3.4".parse().unwrap(),
                trusted,
            ],
            Some(trusted),
        );
        let now = Instant::now();

        let answer = service
            .answer_query("host.openshell.internal", AddressFamily::Ipv4, now)
            .await
            .unwrap();
        let mapping = service
            .store
            .lookup(answer.address, 8080, answer.policy_generation, now)
            .unwrap();

        assert_eq!(mapping.record.contracts[0].pinned_addresses, [trusted]);
    }

    #[tokio::test]
    async fn reserved_gateway_alias_rejects_mismatch_metadata_private_and_wrong_family_answers() {
        let trusted: IpAddr = "169.254.1.2".parse().unwrap();
        for (family, address) in [
            (AddressFamily::Ipv4, "169.254.1.3"),
            (AddressFamily::Ipv4, "169.254.169.254"),
            (AddressFamily::Ipv4, "10.2.3.4"),
            (AddressFamily::Ipv6, "fe80::2"),
        ] {
            let service = gateway_service(vec![address.parse().unwrap()], Some(trusted));
            let result = service
                .answer_query("host.openshell.internal", family, Instant::now())
                .await;
            assert!(
                matches!(result, Err(PolicyDnsError::NoValidAddress)),
                "{address} must not satisfy the trusted gateway contract"
            );
        }
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
    async fn delayed_stale_resolution_cannot_replace_newer_generation_mapping() {
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
            None,
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
        let current_service = PolicyDnsService::new(
            policy.clone(),
            FakeResolver {
                calls: AtomicUsize::new(0),
                answer: TrustedAnswer {
                    addresses: vec!["8.8.4.4".parse().unwrap()],
                    ttl: Duration::from_secs(10),
                },
            },
            store.clone(),
            None,
        );
        let now = Instant::now();
        let current = current_service
            .answer_query("db.example", AddressFamily::Ipv4, now)
            .await
            .unwrap();
        release.notify_one();
        assert!(matches!(
            query.await.unwrap(),
            Err(PolicyDnsError::StalePolicy)
        ));
        let mapping = store
            .lookup(current.address, 5432, current.policy_generation, now)
            .unwrap();
        assert_eq!(
            mapping.record.policy_generation,
            policy.current_generation()
        );
        assert_eq!(
            mapping.record.contracts[0].pinned_addresses,
            ["8.8.4.4".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn policy_dns_failure_events_have_stable_actionable_context() {
        let name = NormalizedName::parse("DB.EXAMPLE.").unwrap();
        let endpoints = vec![PolicyEndpointId {
            policy_name: "database".to_string(),
            endpoint_index: 2,
        }];
        let event = build_dns_failure_event(
            &name,
            AddressFamily::Ipv4,
            &endpoints,
            7,
            "policy_dns_upstream_nxdomain",
            "Policy DNS trusted resolver query failed",
        );
        let json = serde_json::to_value(event).unwrap();

        assert_eq!(json["activity_name"], "Refuse");
        assert_eq!(json["action"], "Denied");
        assert_eq!(json["severity"], "Low");
        assert_eq!(json["status"], "Failure");
        assert_eq!(json["status_detail"], "policy_dns_upstream_nxdomain");
        assert_eq!(json["dst_endpoint"]["domain"], "db.example");
        assert_eq!(json["dst_endpoint"]["port"], 53);
        assert_eq!(json["unmapped"]["normalized_name"], "db.example");
        assert_eq!(json["unmapped"]["address_family"], "ipv4");
        assert_eq!(json["unmapped"]["policy_generation"], 7);
        assert_eq!(
            json["unmapped"]["eligible_endpoints"],
            serde_json::json!([{"policy_name": "database", "endpoint_index": 2}])
        );
    }

    #[test]
    fn resolver_and_publication_failures_have_stable_reason_codes() {
        assert_eq!(
            resolver_failure_detail(&resolver::ResolveError::NxDomain),
            "policy_dns_upstream_nxdomain"
        );
        assert_eq!(
            resolver_failure_detail(&resolver::ResolveError::Timeout),
            "policy_dns_upstream_timeout"
        );
        assert_eq!(
            publication_failure_detail(PublishError::StalePolicy),
            "policy_dns_publication_stale_generation"
        );
        assert_eq!(
            publication_failure_detail(PublishError::InvalidMapping),
            "policy_dns_publication_invalid_mapping"
        );
        assert_eq!(
            publication_failure_detail(PublishError::PoolExhausted),
            "policy_dns_publication_pool_exhausted"
        );
        assert_eq!(
            publication_failure_detail(PublishError::LockPoisoned),
            "policy_dns_publication_store_unavailable"
        );
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
