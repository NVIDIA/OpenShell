// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared relay primitives for authorized explicit-proxy egress.

use super::{EgressDecision, L7RouteSnapshot, emit_l7_tunnel_close_after_policy_change};
use crate::l7::relay::L7EvalContext;
use crate::opa::{NetworkAction, OpaEngine, PolicyGenerationGuard, TunnelPolicyEngine};
use miette::{IntoDiagnostic, Result};
use openshell_core::activity::ActivitySender;
use openshell_core::proto::ProviderProfileCredential;
use openshell_core::secrets::SecretResolver;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

type DynamicCredentials = Arc<std::sync::RwLock<HashMap<String, ProviderProfileCredential>>>;

enum PreparedHttpPolicy {
    Inspect {
        configs: Vec<crate::l7::L7EndpointConfig>,
        evaluator: Box<TunnelPolicyEngine>,
    },
    Passthrough {
        generation_guard: PolicyGenerationGuard,
    },
}

/// Everything an HTTP relay needs after authorization is complete.
///
/// The relay deliberately owns a generation-pinned policy primitive instead
/// of retaining access to the mutable OPA engine. Policy reloads therefore
/// fail closed through the guard or tunnel evaluator already attached here.
pub(super) struct RelayContext<'a> {
    request: &'a L7EvalContext,
    policy: PreparedHttpPolicy,
    middleware_engine: &'a OpaEngine,
}

/// Build the request-processing context shared by CONNECT and forward HTTP.
pub(super) fn http_context(
    decision: &EgressDecision,
    secret_resolver: Option<Arc<SecretResolver>>,
    activity_tx: Option<ActivitySender>,
    dynamic_credentials: Option<DynamicCredentials>,
    agent_proposals: openshell_core::proposals::AgentProposals,
) -> L7EvalContext {
    let policy_name = match &decision.action {
        NetworkAction::Allow { matched_policy } => matched_policy.clone().unwrap_or_default(),
        NetworkAction::Deny { .. } => String::new(),
    };

    L7EvalContext {
        host: decision.intent.destination.host.clone(),
        port: decision.intent.destination.port,
        policy_name,
        binary_path: decision
            .binary
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default(),
        ancestors: decision
            .ancestors
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
        cmdline_paths: decision
            .cmdline_paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
        secret_resolver,
        activity_tx,
        dynamic_credentials: dynamic_credentials.clone(),
        token_grant_resolver: dynamic_credentials
            .as_ref()
            .map(|_| crate::l7::token_grant_injection::default_resolver()),
        agent_proposals,
    }
}

/// Pin a generation for a relay or the forward HTTP single-request path.
pub(super) fn pin_policy_generation(
    opa_engine: &OpaEngine,
    expected_generation: u64,
) -> Result<PolicyGenerationGuard> {
    opa_engine.generation_guard(expected_generation)
}

/// Clone an L7 evaluator for a relay or the forward HTTP single-request path.
pub(super) fn pin_l7_evaluator(
    opa_engine: &OpaEngine,
    expected_generation: u64,
) -> Result<TunnelPolicyEngine> {
    opa_engine.clone_engine_for_tunnel(expected_generation)
}

/// Prepare a generation-pinned HTTP relay at the adapter boundary.
///
/// A stale generation preserves the established CONNECT behavior: emit the
/// policy-change close event and let the adapter close the live tunnel without
/// attempting to write an HTTP response into it.
pub(super) fn prepare_http_relay<'a>(
    route: Option<&L7RouteSnapshot>,
    opa_engine: &OpaEngine,
    decision: &EgressDecision,
    request: &'a L7EvalContext,
) -> Option<RelayContext<'a>> {
    let policy = if let Some(route) = route.filter(|route| !route.configs.is_empty()) {
        let evaluator = match pin_l7_evaluator(opa_engine, route.l7_policy_generation) {
            Ok(evaluator) => evaluator,
            Err(error) => {
                emit_l7_tunnel_close_after_policy_change(
                    &decision.intent.destination.host,
                    decision.intent.destination.port,
                    error,
                );
                return None;
            }
        };
        let configs = route
            .configs
            .iter()
            .map(|snapshot| snapshot.config.clone())
            .collect();
        PreparedHttpPolicy::Inspect {
            configs,
            evaluator: Box::new(evaluator),
        }
    } else {
        let expected_generation = route.map_or(decision.l4_policy_generation, |route| {
            route.l7_policy_generation
        });
        let generation_guard = match pin_policy_generation(opa_engine, expected_generation) {
            Ok(guard) => guard,
            Err(error) => {
                emit_l7_tunnel_close_after_policy_change(
                    &decision.intent.destination.host,
                    decision.intent.destination.port,
                    error,
                );
                return None;
            }
        };
        PreparedHttpPolicy::Passthrough { generation_guard }
    };

    Some(RelayContext {
        request,
        policy,
        middleware_engine: opa_engine,
    })
}

/// Relay an HTTP/1 stream using an already-authorized, generation-pinned context.
///
/// CONNECT plaintext and TLS-terminated streams both enter through this
/// function. Forward HTTP will provide a buffered first request to the same
/// boundary in the next migration step.
pub(super) async fn relay_http_stream<C, U>(
    client: &mut C,
    upstream: &mut U,
    context: RelayContext<'_>,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    match context.policy {
        PreparedHttpPolicy::Inspect { configs, evaluator } if configs.len() == 1 => {
            crate::l7::relay::relay_with_inspection(
                &configs[0],
                *evaluator,
                client,
                upstream,
                context.request,
            )
            .await
        }
        PreparedHttpPolicy::Inspect { configs, evaluator } => {
            crate::l7::relay::relay_with_route_selection(
                &configs,
                *evaluator,
                client,
                upstream,
                context.request,
            )
            .await
        }
        PreparedHttpPolicy::Passthrough { generation_guard } => {
            crate::l7::relay::relay_passthrough_with_credentials(
                client,
                upstream,
                context.request,
                &generation_guard,
                Some(context.middleware_engine),
            )
            .await
        }
    }
}

/// Relay a policy-authorized raw TCP stream.
pub(super) async fn relay_tcp<C, U>(client: &mut C, upstream: &mut U) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(client, upstream)
        .await
        .into_diagnostic()?;
    Ok(())
}
