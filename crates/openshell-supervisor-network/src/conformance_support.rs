// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Engine-neutral probes of production networking paths for conformance tests.

use std::{net::IpAddr, sync::Arc};

/// Load Rego without authored-policy validation to test defensive decisions.
pub fn unvalidated_opa(policy: &str, yaml: &str) -> miette::Result<crate::opa::OpaEngine> {
    crate::opa::OpaEngine::from_strings_unvalidated(policy, yaml)
}

/// Exercise the explicit proxy's destination checks with fixed DNS answers.
pub fn connect_destination_outcome(
    engine: &crate::policy_engine::PolicyEngine,
    input: &crate::policy_types::NetworkInput,
    addresses: &[IpAddr],
) -> String {
    crate::proxy::connect_destination_outcome_for_test(engine, input, addresses)
}

/// Select the credential owners admitted by the production relay.
pub fn admitted_token_grant_owners(
    engine: &crate::policy_engine::TunnelPolicyEngine,
    ctx: &crate::l7::relay::L7EvalContext,
    request: &crate::l7::L7RequestInfo,
) -> miette::Result<std::collections::HashSet<String>> {
    crate::l7::relay::admitted_token_grant_owners(engine, ctx, request)
}

/// A trusted resolver that answers every name with the same addresses.
struct FixedResolver(Vec<IpAddr>);

impl crate::policy_dns::TrustedResolver for FixedResolver {
    async fn resolve(
        &self,
        _name: &crate::policy_dns::NormalizedName,
        _family: crate::policy_dns::AddressFamily,
    ) -> Result<crate::policy_dns::TrustedAnswer, crate::policy_dns::TrustedResolveError> {
        Ok(crate::policy_dns::TrustedAnswer {
            addresses: self.0.clone(),
            ttl: std::time::Duration::from_secs(30),
        })
    }
}

/// Resolves `name` through `engine`'s policy DNS, with the trusted resolver
/// answering `answers`, and returns the store holding the mapping.
async fn policy_dns_answer(
    engine: &crate::policy_engine::PolicyEngine,
    name: &str,
    answers: &[IpAddr],
) -> Result<
    (
        crate::policy_dns::SyntheticAnswer,
        Arc<crate::policy_dns::ResolvedEndpointStore>,
    ),
    String,
> {
    use crate::policy_dns::{
        AddressFamily, PolicyDnsService, ResolvedEndpointStore, StoreConfig, SyntheticPools,
    };
    use std::net::{Ipv4Addr, Ipv6Addr};

    // Like the production pools, skip the reserved sandbox-local address.
    let pools = SyntheticPools::new(
        Ipv4Addr::new(198, 18, 0, 2)..=Ipv4Addr::new(198, 18, 0, 9),
        Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 1)..=Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 8),
    )
    .expect("test pools are valid");
    let store = Arc::new(ResolvedEndpointStore::new(
        StoreConfig::new(pools, 16).expect("test store config is valid"),
    ));
    let dns = PolicyDnsService::new(
        engine.clone(),
        FixedResolver(answers.to_vec()),
        Arc::clone(&store),
        None,
    );
    dns.answer_query(name, AddressFamily::Ipv4, std::time::Instant::now())
        .await
        .map(|answer| (answer, store))
        .map_err(|error| format!("dns refused: {error}"))
}

/// Returns the addresses policy DNS pins for `name` on `port`; see
/// the conformance suite.
pub async fn dns_answers_outcome(
    engine: crate::policy_engine::PolicyEngine,
    name: &str,
    port: u16,
    answers: &[IpAddr],
) -> String {
    let (answer, store) = match policy_dns_answer(&engine, name, answers).await {
        Ok(resolved) => resolved,
        Err(refusal) => return refusal,
    };
    let Ok(mapping) = store.lookup(
        answer.address,
        port,
        answer.policy_generation,
        std::time::Instant::now(),
    ) else {
        return "no mapping for port".to_string();
    };
    let mut pinned: Vec<String> = mapping
        .pinned_addresses()
        .iter()
        .map(ToString::to_string)
        .collect();
    pinned.sort();
    pinned.join(",")
}

/// Resolves `name` through `engine`'s policy DNS and stages a transparent
/// open to the answer.
pub async fn transparent_open_outcome(
    engine: crate::policy_engine::PolicyEngine,
    name: &str,
    port: u16,
    binary: &str,
    answers: &[IpAddr],
) -> String {
    let (answer, store) = match policy_dns_answer(&engine, name, answers).await {
        Ok(resolved) => resolved,
        Err(refusal) => return refusal,
    };
    let destination = std::net::SocketAddr::new(answer.address, port);
    let outcome =
        crate::proxy::stage_transparent_open_for_test(&engine, &store, destination, binary).await;
    if outcome.dial_addresses.is_empty() {
        return format!("{:?}", outcome.decision);
    }
    let addresses: Vec<String> = outcome
        .dial_addresses
        .iter()
        .map(ToString::to_string)
        .collect();
    format!(
        "{:?}/{}/{}",
        outcome.decision,
        addresses.join(","),
        if outcome.correlated {
            "correlated"
        } else {
            "uncorrelated"
        }
    )
}

/// Record a result through the production endpoint observer, if applicable.
pub fn observe_endpoint(
    sender: &openshell_core::endpoint_status::EndpointObservationSender,
    config: &crate::l7::L7EndpointConfig,
    result: openshell_core::endpoint_status::EndpointResult,
) -> bool {
    let context = sender.capture();
    let Some(observer) = crate::l7::EndpointObserver::begin_captured(
        Some(sender),
        config,
        context.as_ref(),
        None,
        None,
    ) else {
        return false;
    };
    observer.observe(result);
    true
}

/// Construct an isolated request context without exposing relay internals.
pub fn l7_context(host: &str, port: u16, binary: &str) -> crate::l7::relay::L7EvalContext {
    crate::l7::relay::L7EvalContext {
        host: host.to_string(),
        port,
        binary_path: binary.to_string(),
        ..Default::default()
    }
}

/// Install the placeholder resolver used by a relay credential fixture.
pub fn with_secret_resolver(
    mut ctx: crate::l7::relay::L7EvalContext,
    resolver: Option<Arc<openshell_core::secrets::SecretResolver>>,
) -> crate::l7::relay::L7EvalContext {
    ctx.secret_resolver = resolver;
    ctx
}

/// Capture the matched policy and authority port for a relay fixture.
pub fn relay_context(
    mut ctx: crate::l7::relay::L7EvalContext,
    policy_name: String,
) -> crate::l7::relay::L7EvalContext {
    ctx.policy_name = policy_name;
    ctx.request_default_port = Some(ctx.port);
    ctx
}

/// Parse a request target through the production REST decoder.
pub fn parse_target_query(
    target: &str,
) -> miette::Result<(String, std::collections::HashMap<String, Vec<String>>)> {
    crate::l7::rest::parse_target_query(target)
}

/// Parse query parameters through the production REST decoder.
pub fn parse_query_params(
    query: &str,
) -> miette::Result<std::collections::HashMap<String, Vec<String>>> {
    crate::l7::rest::parse_query_params(query)
}
