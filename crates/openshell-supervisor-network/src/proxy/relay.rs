// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared relay primitives for authorized explicit-proxy egress.

use super::{EgressDecision, L7RouteSnapshot, emit_l7_tunnel_close_after_policy_change};
use crate::l7::relay::L7EvalContext;
use crate::opa::{NetworkAction, OpaEngine};
use miette::{IntoDiagnostic, Result};
use openshell_core::activity::ActivitySender;
use openshell_core::proto::ProviderProfileCredential;
use openshell_core::secrets::SecretResolver;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

type DynamicCredentials = Arc<std::sync::RwLock<HashMap<String, ProviderProfileCredential>>>;

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

/// Relay an HTTP/1 stream using the endpoint's current L7 configuration.
///
/// CONNECT plaintext and TLS-terminated streams both enter through this
/// function. Forward HTTP will provide a buffered first request to the same
/// boundary in the next migration step.
pub(super) async fn relay_http_stream<C, U>(
    route: Option<&L7RouteSnapshot>,
    opa_engine: &Arc<OpaEngine>,
    decision: &EgressDecision,
    client: &mut C,
    upstream: &mut U,
    context: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    if let Some(route) = route.filter(|route| !route.configs.is_empty()) {
        let tunnel_engine = match opa_engine.clone_engine_for_tunnel(route.generation) {
            Ok(engine) => engine,
            Err(error) => {
                emit_l7_tunnel_close_after_policy_change(
                    &decision.intent.destination.host,
                    decision.intent.destination.port,
                    error,
                );
                return Ok(());
            }
        };

        if route.configs.len() == 1 {
            crate::l7::relay::relay_with_inspection(
                &route.configs[0].config,
                tunnel_engine,
                client,
                upstream,
                context,
            )
            .await
        } else {
            let configs = route
                .configs
                .iter()
                .map(|snapshot| snapshot.config.clone())
                .collect::<Vec<_>>();
            crate::l7::relay::relay_with_route_selection(
                &configs,
                tunnel_engine,
                client,
                upstream,
                context,
            )
            .await
        }
    } else {
        let generation = route.map_or(decision.generation, |route| route.generation);
        let generation_guard = match opa_engine.generation_guard(generation) {
            Ok(guard) => guard,
            Err(error) => {
                emit_l7_tunnel_close_after_policy_change(
                    &decision.intent.destination.host,
                    decision.intent.destination.port,
                    error,
                );
                return Ok(());
            }
        };
        crate::l7::relay::relay_passthrough_with_credentials(
            client,
            upstream,
            context,
            &generation_guard,
            Some(opa_engine),
        )
        .await
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
