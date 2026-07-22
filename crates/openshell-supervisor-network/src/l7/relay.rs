// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Protocol-aware bidirectional relay with L7 inspection.
//!
//! Replaces `copy_bidirectional` for endpoints with L7 configuration.
//! Parses each request within the tunnel, evaluates it against OPA policy,
//! and either forwards or denies the request.

use crate::l7::middleware::{
    MiddlewareApplyResult, UninspectableTrafficGate, apply_middleware_chain,
    emit_middleware_uninspectable, middleware_network_input, uninspectable_traffic_gate,
};
#[cfg(test)]
use crate::l7::middleware::{
    middleware_chain_body_limit, middleware_events, middleware_request_input,
    raw_query_from_request_headers, resolve_unbuffered_body,
};
use crate::l7::provider::{L7Provider, RelayOutcome};
use crate::l7::rest::WebSocketExtensionMode;
use crate::l7::{EnforcementMode, L7EndpointConfig, L7Protocol, L7RequestInfo};
use crate::opa::{PolicyGenerationGuard, TunnelPolicyEngine};
use miette::{IntoDiagnostic, Result, miette};
use openshell_core::activity::{ActivitySender, try_record_activity};
use openshell_core::secrets::{self, SecretResolver};
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, Endpoint, HttpActivityBuilder, HttpRequest,
    NetworkActivityBuilder, SeverityId, StatusId, Url as OcsfUrl, ocsf_emit,
};
#[cfg(test)]
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, warn};

/// Context for L7 request policy evaluation.
#[cfg_attr(test, derive(Default))]
pub struct L7EvalContext {
    /// Host from the CONNECT request.
    pub host: String,
    /// Port from the CONNECT request.
    pub port: u16,
    /// Matched policy name from L4 evaluation.
    pub policy_name: String,
    /// Binary path (for cross-layer Rego evaluation).
    pub binary_path: String,
    /// Ancestor paths.
    pub ancestors: Vec<String>,
    /// Cmdline paths.
    pub cmdline_paths: Vec<String>,
    /// Supervisor-only placeholder resolver for outbound headers.
    pub(crate) secret_resolver: Option<Arc<SecretResolver>>,
    /// Anonymous activity counter channel.
    pub(crate) activity_tx: Option<ActivitySender>,
    /// Dynamic credentials (token grants) keyed by endpoint-bound provider metadata.
    pub(crate) dynamic_credentials: Option<
        Arc<
            std::sync::RwLock<
                std::collections::HashMap<String, openshell_core::proto::ProviderProfileCredential>,
            >,
        >,
    >,
    /// Dynamic token grant resolver for endpoint-bound credentials.
    pub(crate) token_grant_resolver:
        Option<Arc<dyn crate::l7::token_grant_injection::TokenGrantResolver>>,
    /// Shared feature state for agent-driven policy proposals.
    pub(crate) agent_proposals: openshell_core::proposals::AgentProposals,
}

#[derive(Default)]
pub(crate) struct UpgradeRelayOptions<'a> {
    pub(crate) websocket_request: bool,
    pub(crate) websocket: WebSocketUpgradeBehavior,
    pub(crate) secret_resolver: Option<Arc<SecretResolver>>,
    pub(crate) engine: Option<&'a TunnelPolicyEngine>,
    pub(crate) ctx: Option<&'a L7EvalContext>,
    pub(crate) enforcement: EnforcementMode,
    pub(crate) target: String,
    pub(crate) query_params: std::collections::HashMap<String, Vec<String>>,
    pub(crate) policy_name: String,
}

#[derive(Default)]
pub(crate) struct WebSocketUpgradeBehavior {
    pub(crate) credential_rewrite: bool,
    pub(crate) message_policy: WebSocketMessagePolicy,
    pub(crate) permessage_deflate: bool,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum WebSocketMessagePolicy {
    #[default]
    None,
    Transport,
    Graphql,
}

impl WebSocketMessagePolicy {
    fn inspects_messages(self) -> bool {
        self != Self::None
    }

    fn is_graphql(self) -> bool {
        self == Self::Graphql
    }
}

#[derive(Debug, Clone, Copy)]
enum ParseRejectionMode {
    L7Endpoint,
    Passthrough,
}

fn parse_rejection_detail(error: &str, mode: ParseRejectionMode) -> String {
    if error.contains("encoded '/' (%2F)") {
        match mode {
            ParseRejectionMode::L7Endpoint => format!(
                "{error}; set allow_encoded_slash: true on this endpoint if the upstream requires encoded slashes"
            ),
            ParseRejectionMode::Passthrough => format!(
                "{error}; passthrough credential relay uses strict path parsing, so configure this endpoint with protocol: rest and allow_encoded_slash: true for encoded-slash APIs, or use tls: skip if HTTP parsing is not needed"
            ),
        }
    } else {
        error.to_string()
    }
}

fn emit_parse_rejection(ctx: &L7EvalContext, detail: &str, engine_type: &str) {
    let policy_name = if ctx.policy_name.is_empty() {
        "-"
    } else {
        &ctx.policy_name
    };
    let event = NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Open)
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(SeverityId::Medium)
        .status(StatusId::Failure)
        .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
        .firewall_rule(policy_name, engine_type)
        .message(format!(
            "HTTP request rejected before policy evaluation for {}:{}",
            ctx.host, ctx.port
        ))
        .status_detail(detail)
        .build();
    ocsf_emit!(event);
    emit_activity(ctx, true, "l7_parse_rejection");
}

fn engine_type_for_protocol(protocol: L7Protocol) -> &'static str {
    match protocol {
        L7Protocol::Graphql => "l7-graphql",
        L7Protocol::JsonRpc => "l7-jsonrpc",
        L7Protocol::Mcp => "l7-mcp",
        L7Protocol::Websocket => "l7-websocket",
        L7Protocol::Rest | L7Protocol::Sql => "l7",
    }
}

async fn deny_h2c_upgrade_if_requested<C>(
    req: &crate::l7::provider::L7Request,
    config: &L7EndpointConfig,
    ctx: &L7EvalContext,
    client: &mut C,
) -> Result<bool>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
{
    if !crate::l7::rest::request_is_h2c_upgrade(&req.raw_header) {
        return Ok(false);
    }

    emit_parse_rejection(
        ctx,
        crate::l7::rest::UNSUPPORTED_H2C_UPGRADE_DETAIL,
        engine_type_for_protocol(config.protocol),
    );
    crate::l7::rest::RestProvider::default()
        .deny_with_redacted_target(
            req,
            &ctx.policy_name,
            crate::l7::rest::UNSUPPORTED_H2C_UPGRADE_DETAIL,
            client,
            None,
            Some(crate::l7::rest::DenyResponseContext::from_l7_context(ctx)),
        )
        .await?;
    Ok(true)
}

/// Run protocol-aware L7 inspection on a tunnel.
///
/// This replaces `copy_bidirectional` for L7-enabled endpoints.
/// Protocol detection (peek) is the caller's responsibility — this function
/// assumes the streams are already proven to carry the expected protocol.
/// For TLS-terminated connections, ALPN proves HTTP; for plaintext, the
/// caller peeks on the raw `TcpStream` before calling this.
pub async fn relay_with_inspection<C, U>(
    config: &L7EndpointConfig,
    engine: TunnelPolicyEngine,
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    match config.protocol {
        L7Protocol::Rest | L7Protocol::Websocket => {
            relay_rest(config, &engine, client, upstream, ctx).await
        }
        L7Protocol::Graphql => relay_graphql(config, &engine, client, upstream, ctx).await,
        L7Protocol::Sql => {
            if close_if_stale(engine.generation_guard(), ctx) {
                return Ok(());
            }
            // The SQL relay is not implemented, so a matching middleware
            // chain can never inspect this stream: gate it like any other
            // uninspectable protocol.
            let chain = engine.query_middleware_chain(&middleware_network_input(ctx))?;
            match uninspectable_traffic_gate(&chain) {
                UninspectableTrafficGate::Deny => {
                    emit_middleware_uninspectable(ctx, "sql passthrough", true);
                    return Ok(());
                }
                UninspectableTrafficGate::BypassWithFinding => {
                    emit_middleware_uninspectable(ctx, "sql passthrough", false);
                }
                UninspectableTrafficGate::Unrestricted => {}
            }
            // SQL provider is Phase 3 — fall through to passthrough with warning
            {
                let event = NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
                    .activity(ActivityId::Other)
                    .severity(SeverityId::Low)
                    .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                    .message("SQL L7 provider not yet implemented, falling back to passthrough")
                    .build();
                ocsf_emit!(event);
            }
            tokio::io::copy_bidirectional(client, upstream)
                .await
                .into_diagnostic()?;
            Ok(())
        }
        L7Protocol::JsonRpc | L7Protocol::Mcp => {
            relay_jsonrpc(config, &engine, client, upstream, ctx).await
        }
    }
}

/// Run HTTP L7 inspection with per-request protocol selection.
///
/// This is used when multiple L7 endpoints share a host:port, for example a
/// REST API under `/repos/**` and a GraphQL API under `/graphql`.
pub async fn relay_with_route_selection<C, U>(
    configs: &[L7EndpointConfig],
    engine: TunnelPolicyEngine,
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let provider =
        crate::l7::rest::RestProvider::with_options(crate::l7::path::CanonicalizeOptions {
            allow_encoded_slash: configs.iter().any(|config| config.allow_encoded_slash),
            ..Default::default()
        });

    loop {
        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        let mut req = match provider.parse_request(client).await {
            Ok(Some(req)) => req,
            Ok(None) => return Ok(()),
            Err(e) => {
                if is_benign_connection_error(&e) {
                    debug!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "L7 route-selected connection closed"
                    );
                } else {
                    let detail =
                        parse_rejection_detail(&e.to_string(), ParseRejectionMode::L7Endpoint);
                    emit_parse_rejection(ctx, &detail, "l7");
                }
                return Ok(());
            }
        };

        let Some(config) = select_l7_config_for_path(configs, &req.target) else {
            crate::l7::rest::RestProvider::default()
                .deny_with_redacted_target(
                    &req,
                    &ctx.policy_name,
                    "no L7 endpoint path matched request",
                    client,
                    None,
                    Some(crate::l7::rest::DenyResponseContext::from_l7_context(ctx)),
                )
                .await?;
            return Ok(());
        };

        if deny_h2c_upgrade_if_requested(&req, config, ctx, client).await? {
            return Ok(());
        }

        let graphql_info = if config.protocol == L7Protocol::Graphql {
            match crate::l7::graphql::inspect_graphql_request(
                client,
                &mut req,
                config.graphql_max_body_bytes,
            )
            .await
            {
                Ok(info) => Some(info),
                Err(e) => {
                    if is_benign_connection_error(&e) {
                        debug!(
                            host = %ctx.host,
                            port = ctx.port,
                            error = %e,
                            "GraphQL L7 connection closed"
                        );
                    } else {
                        let detail =
                            parse_rejection_detail(&e.to_string(), ParseRejectionMode::L7Endpoint);
                        emit_parse_rejection(ctx, &detail, "l7-graphql");
                    }
                    return Ok(());
                }
            }
        } else {
            None
        };
        let jsonrpc_info = if config.protocol.is_jsonrpc_family() {
            if crate::l7::jsonrpc::jsonrpc_receive_stream_request(&req) {
                Some(crate::l7::jsonrpc::JsonRpcRequestInfo::receive_stream())
            } else {
                match crate::l7::http::read_body_for_inspection(
                    client,
                    &mut req,
                    config.json_rpc_max_body_bytes,
                )
                .await
                {
                    Ok(body) => Some(crate::l7::jsonrpc::parse_jsonrpc_body_with_options(
                        &body,
                        crate::l7::jsonrpc::JsonRpcInspectionOptions::for_config(config),
                    )),
                    Err(e) => {
                        if is_benign_connection_error(&e) {
                            debug!(
                                host = %ctx.host,
                                port = ctx.port,
                                error = %e,
                                "JSON-RPC L7 connection closed"
                            );
                        } else {
                            let detail = parse_rejection_detail(
                                &e.to_string(),
                                ParseRejectionMode::L7Endpoint,
                            );
                            emit_parse_rejection(ctx, &detail, "l7-jsonrpc");
                        }
                        return Ok(());
                    }
                }
            }
        } else {
            None
        };

        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        let (eval_target, redacted_target) = if let Some(ref resolver) = ctx.secret_resolver {
            match secrets::rewrite_target_for_eval(&req.target, resolver) {
                Ok(result) => (result.resolved, result.redacted),
                Err(e) => {
                    warn!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "credential resolution failed in request target, rejecting"
                    );
                    let response = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    client.write_all(response).await.into_diagnostic()?;
                    client.flush().await.into_diagnostic()?;
                    return Ok(());
                }
            }
        } else {
            (req.target.clone(), req.target.clone())
        };

        let request_info = L7RequestInfo {
            action: req.action.clone(),
            target: redacted_target.clone(),
            query_params: req.query_params.clone(),
            graphql: graphql_info.clone(),
            jsonrpc: jsonrpc_info.clone(),
        };
        let websocket_request = crate::l7::rest::request_is_websocket_upgrade(&req.raw_header);
        if config.protocol == L7Protocol::Websocket && !websocket_request {
            crate::l7::rest::RestProvider::default()
                .deny_with_redacted_target(
                    &req,
                    &ctx.policy_name,
                    "websocket endpoint requires a valid WebSocket upgrade request",
                    client,
                    Some(&redacted_target),
                    Some(crate::l7::rest::DenyResponseContext::from_l7_context(ctx)),
                )
                .await?;
            return Ok(());
        }

        let hard_deny_reason = l7_request_hard_deny_reason(config.protocol, &request_info);
        let force_deny = hard_deny_reason.is_some();
        let (allowed, reason) = if let Some(reason) = hard_deny_reason {
            (false, reason)
        } else {
            evaluate_l7_request(&engine, ctx, &request_info)?
        };

        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        let decision_str = match (allowed, config.enforcement) {
            (_, _) if force_deny => "deny",
            (true, _) => "allow",
            (false, EnforcementMode::Audit) => "audit",
            (false, EnforcementMode::Enforce) => "deny",
        };
        let engine_type = match config.protocol {
            L7Protocol::Graphql => "l7-graphql",
            L7Protocol::Websocket => "l7-websocket",
            L7Protocol::JsonRpc => "l7-jsonrpc",
            L7Protocol::Mcp => "l7-mcp",
            L7Protocol::Rest | L7Protocol::Sql => "l7",
        };
        let protocol_summary =
            l7_protocol_log_summary(graphql_info.as_ref(), jsonrpc_info.as_ref());
        emit_l7_request_log(
            ctx,
            &request_info,
            &redacted_target,
            decision_str,
            engine_type,
            &reason,
            &protocol_summary,
        );

        let _ = &eval_target;

        if allowed || (config.enforcement == EnforcementMode::Audit && !force_deny) {
            let chain = engine.query_middleware_chain(&middleware_network_input(ctx))?;
            // Route selection resolved `config` per request, so re-check the
            // body against that protocol's policy after every transforming
            // stage (a no-op for REST and websocket, whose policy inputs the
            // chain cannot mutate).
            let validate = transformed_body_validator(config, &engine, ctx, &request_info);
            let req = match apply_middleware_chain(
                req,
                client,
                ctx,
                chain,
                engine.middleware_runner(),
                engine.generation_guard(),
                openshell_supervisor_middleware::TransformedBodyPolicy::Reevaluate(&validate),
            )
            .await?
            {
                MiddlewareApplyResult::Allowed(request) => request,
                MiddlewareApplyResult::Denied { denial, .. } => {
                    let denied_request = crate::l7::provider::L7Request {
                        action: request_info.action.clone(),
                        target: redacted_target.clone(),
                        query_params: request_info.query_params.clone(),
                        raw_header: Vec::new(),
                        body_length: crate::l7::provider::BodyLength::None,
                    };
                    crate::l7::middleware::send_middleware_rejection_response(
                        &denied_request,
                        client,
                        ctx,
                        denial.as_ref(),
                        &redacted_target,
                    )
                    .await?;
                    return Ok(());
                }
            };
            let outcome = crate::l7::rest::relay_http_request_with_options_guarded(
                &req,
                client,
                upstream,
                crate::l7::rest::RelayRequestOptions {
                    resolver: ctx.secret_resolver.as_deref(),
                    generation_guard: Some(engine.generation_guard()),
                    websocket_extensions: websocket_extension_mode(config),
                    request_body_credential_rewrite: config.protocol == L7Protocol::Rest
                        && config.request_body_credential_rewrite,
                    credential_signing: config.credential_signing,
                    signing_service: &config.signing_service,
                    signing_region: &config.signing_region,
                    host: &ctx.host,
                    port: ctx.port,
                },
            )
            .await?;
            match outcome {
                RelayOutcome::Reusable => {}
                RelayOutcome::Consumed => return Ok(()),
                RelayOutcome::Upgraded {
                    overflow,
                    websocket_permessage_deflate,
                } => {
                    let mut options = upgrade_options(
                        config,
                        ctx,
                        websocket_request,
                        &redacted_target,
                        &req.query_params,
                        Some(&engine),
                    );
                    options.websocket.permessage_deflate = websocket_permessage_deflate;
                    return handle_upgrade(
                        client, upstream, overflow, &ctx.host, ctx.port, options,
                    )
                    .await;
                }
            }
        } else {
            crate::l7::rest::RestProvider::default()
                .deny_with_redacted_target(
                    &req,
                    &ctx.policy_name,
                    &reason,
                    client,
                    Some(&redacted_target),
                    Some(crate::l7::rest::DenyResponseContext::from_l7_context(ctx)),
                )
                .await?;
            return Ok(());
        }
    }
}

fn select_l7_config_for_path<'a>(
    configs: &'a [L7EndpointConfig],
    path: &str,
) -> Option<&'a L7EndpointConfig> {
    configs
        .iter()
        .filter(|config| config.matches_path(path))
        .max_by_key(|config| config.path_specificity())
}

fn emit_l7_request_log(
    ctx: &L7EvalContext,
    request_info: &L7RequestInfo,
    redacted_target: &str,
    decision_str: &str,
    engine_type: &str,
    reason: &str,
    protocol_summary: &str,
) {
    let (action_id, disposition_id, severity) = match decision_str {
        "deny" => (ActionId::Denied, DispositionId::Blocked, SeverityId::Medium),
        "allow" | "audit" => (
            ActionId::Allowed,
            DispositionId::Allowed,
            SeverityId::Informational,
        ),
        _ => (
            ActionId::Other,
            DispositionId::Other,
            SeverityId::Informational,
        ),
    };
    let event = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Other)
        .action(action_id)
        .disposition(disposition_id)
        .severity(severity)
        .http_request(HttpRequest::new(
            &request_info.action,
            OcsfUrl::new("http", &ctx.host, redacted_target, ctx.port),
        ))
        .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
        .firewall_rule(&ctx.policy_name, engine_type)
        .message(format!(
            "L7_REQUEST {decision_str} {} {}:{}{}{} reason={}",
            request_info.action, ctx.host, ctx.port, redacted_target, protocol_summary, reason,
        ))
        .build();
    ocsf_emit!(event);
    emit_activity(ctx, decision_str == "deny", "l7_policy");
}

fn l7_protocol_log_summary(
    graphql_info: Option<&crate::l7::graphql::GraphqlRequestInfo>,
    jsonrpc_info: Option<&crate::l7::jsonrpc::JsonRpcRequestInfo>,
) -> String {
    if let Some(info) = graphql_info {
        return format!(" {}", graphql_log_summary(info));
    }

    if let Some(info) = jsonrpc_info {
        return format!(
            " rule_methods={} tools={}",
            rule_method_names_for_log(info),
            tool_names_for_log(info)
        );
    }

    String::new()
}

fn emit_activity(ctx: &L7EvalContext, denied: bool, deny_group: &'static str) {
    if let Some(tx) = &ctx.activity_tx {
        let _ = try_record_activity(tx, denied, deny_group);
    }
}

/// Handle an upgraded connection (101 Switching Protocols).
///
/// Forwards any overflow bytes from the upgrade response to the client, then
/// either switches to a parsed WebSocket relay for opted-in message policy /
/// credential rewriting or to raw bidirectional TCP copy for other upgrades.
pub(crate) async fn handle_upgrade<C, U>(
    client: &mut C,
    upstream: &mut U,
    overflow: Vec<u8>,
    host: &str,
    port: u16,
    options: UpgradeRelayOptions<'_>,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let use_websocket_relay = options.websocket_request
        && (options.websocket.message_policy.inspects_messages()
            || options.websocket.permessage_deflate
            || (options.websocket.credential_rewrite && options.secret_resolver.is_some()));
    let relay_mode = if use_websocket_relay {
        "websocket parsed relay"
    } else {
        "raw bidirectional relay (L7 enforcement no longer active)"
    };
    ocsf_emit!(
        NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .activity(ActivityId::Other)
            .activity_name("Upgrade")
            .severity(SeverityId::Informational)
            .dst_endpoint(Endpoint::from_domain(host, port))
            .message(format!(
                "101 Switching Protocols — {relay_mode} [host:{host} port:{port} overflow_bytes:{}]",
                overflow.len()
            ))
            .build()
    );
    if use_websocket_relay {
        let resolver = if options.websocket.credential_rewrite {
            options.secret_resolver.as_deref()
        } else {
            None
        };
        let inspector = if options.websocket.message_policy.inspects_messages() {
            match (options.engine, options.ctx) {
                (Some(engine), Some(ctx)) => Some(crate::l7::websocket::InspectionOptions {
                    engine,
                    ctx,
                    enforcement: options.enforcement,
                    target: options.target.clone(),
                    query_params: options.query_params.clone(),
                    graphql_policy: options.websocket.message_policy.is_graphql(),
                }),
                _ => {
                    return Err(miette!(
                        "websocket message inspection missing policy context"
                    ));
                }
            }
        } else {
            None
        };
        let compression = if options.websocket.permessage_deflate {
            crate::l7::websocket::WebSocketCompression::PermessageDeflate
        } else {
            crate::l7::websocket::WebSocketCompression::None
        };
        return crate::l7::websocket::relay_with_options(
            client,
            upstream,
            overflow,
            host,
            port,
            crate::l7::websocket::RelayOptions {
                policy_name: &options.policy_name,
                resolver,
                inspector,
                compression,
            },
        )
        .await;
    }
    if !overflow.is_empty() {
        client.write_all(&overflow).await.into_diagnostic()?;
        client.flush().await.into_diagnostic()?;
    }
    tokio::io::copy_bidirectional(client, upstream)
        .await
        .into_diagnostic()?;
    Ok(())
}

pub(crate) fn upgrade_options<'a>(
    config: &L7EndpointConfig,
    ctx: &'a L7EvalContext,
    websocket_request: bool,
    target: &str,
    query_params: &std::collections::HashMap<String, Vec<String>>,
    engine: Option<&'a TunnelPolicyEngine>,
) -> UpgradeRelayOptions<'a> {
    let websocket_credential_rewrite =
        matches!(config.protocol, L7Protocol::Rest | L7Protocol::Websocket)
            && config.websocket_credential_rewrite;
    let websocket_message_policy = if config.protocol == L7Protocol::Websocket {
        if config.websocket_graphql_policy {
            WebSocketMessagePolicy::Graphql
        } else {
            WebSocketMessagePolicy::Transport
        }
    } else {
        WebSocketMessagePolicy::None
    };
    UpgradeRelayOptions {
        websocket_request,
        websocket: WebSocketUpgradeBehavior {
            credential_rewrite: websocket_credential_rewrite,
            message_policy: websocket_message_policy,
            permessage_deflate: false,
        },
        secret_resolver: if websocket_credential_rewrite {
            ctx.secret_resolver.clone()
        } else {
            None
        },
        engine,
        ctx: engine.map(|_| ctx),
        enforcement: config.enforcement,
        target: target.to_string(),
        query_params: query_params.clone(),
        policy_name: ctx.policy_name.clone(),
    }
}

pub(crate) fn websocket_extension_mode(config: &L7EndpointConfig) -> WebSocketExtensionMode {
    if config.protocol == L7Protocol::Websocket
        || (config.protocol == L7Protocol::Rest && config.websocket_credential_rewrite)
    {
        WebSocketExtensionMode::PermessageDeflate
    } else {
        WebSocketExtensionMode::Preserve
    }
}

fn jsonrpc_engine_type(protocol: L7Protocol) -> &'static str {
    match protocol {
        L7Protocol::Mcp => "l7-mcp",
        _ => "l7-jsonrpc",
    }
}

/// REST relay loop: parse request -> evaluate -> allow/deny -> relay response -> repeat.
async fn relay_rest<C, U>(
    config: &L7EndpointConfig,
    engine: &TunnelPolicyEngine,
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Build a provider carrying the per-endpoint canonicalization options so
    // request parsing honors the endpoint's `allow_encoded_slash` setting
    // (e.g. APIs like GitLab that embed `%2F` in path segments).
    let provider =
        crate::l7::rest::RestProvider::with_options(crate::l7::path::CanonicalizeOptions {
            allow_encoded_slash: config.allow_encoded_slash,
            ..Default::default()
        });
    loop {
        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        // Parse one HTTP request from client
        let req = match provider.parse_request(client).await {
            Ok(Some(req)) => req,
            Ok(None) => return Ok(()), // Client closed connection
            Err(e) => {
                if is_benign_connection_error(&e) {
                    debug!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "L7 connection closed"
                    );
                } else {
                    let detail =
                        parse_rejection_detail(&e.to_string(), ParseRejectionMode::L7Endpoint);
                    emit_parse_rejection(ctx, &detail, "l7");
                }
                return Ok(()); // Close connection on parse error
            }
        };

        if deny_h2c_upgrade_if_requested(&req, config, ctx, client).await? {
            return Ok(());
        }

        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        // Rewrite credential placeholders in the request target BEFORE OPA
        // evaluation. OPA sees the redacted path; the resolved path goes only
        // to the upstream write.
        let (eval_target, redacted_target) = if let Some(ref resolver) = ctx.secret_resolver {
            match secrets::rewrite_target_for_eval(&req.target, resolver) {
                Ok(result) => (result.resolved, result.redacted),
                Err(e) => {
                    warn!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "credential resolution failed in request target, rejecting"
                    );
                    let response = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    client.write_all(response).await.into_diagnostic()?;
                    client.flush().await.into_diagnostic()?;
                    return Ok(());
                }
            }
        } else {
            (req.target.clone(), req.target.clone())
        };

        let request_info = L7RequestInfo {
            action: req.action.clone(),
            target: redacted_target.clone(),
            query_params: req.query_params.clone(),
            graphql: None,
            jsonrpc: None,
        };
        let websocket_request = crate::l7::rest::request_is_websocket_upgrade(&req.raw_header);
        if config.protocol == L7Protocol::Websocket && !websocket_request {
            provider
                .deny_with_redacted_target(
                    &req,
                    &ctx.policy_name,
                    "websocket endpoint requires a valid WebSocket upgrade request",
                    client,
                    Some(&redacted_target),
                    Some(crate::l7::rest::DenyResponseContext::from_l7_context(ctx)),
                )
                .await?;
            return Ok(());
        }

        // Evaluate L7 policy via Rego (using redacted target)
        let (allowed, reason) = evaluate_l7_request(engine, ctx, &request_info)?;

        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        // Check if this is an upgrade request for logging purposes.
        let header_end = req
            .raw_header
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map_or(req.raw_header.len(), |p| p + 4);
        let is_upgrade_request = {
            let h = String::from_utf8_lossy(&req.raw_header[..header_end]);
            h.lines()
                .skip(1)
                .any(|l| l.to_ascii_lowercase().starts_with("upgrade:"))
        };

        let decision_str = match (allowed, config.enforcement, is_upgrade_request) {
            (true, _, true) => "allow_upgrade",
            (true, _, false) => "allow",
            (false, EnforcementMode::Audit, _) => "audit",
            (false, EnforcementMode::Enforce, _) => "deny",
        };

        // Log every L7 decision as an OCSF HTTP Activity event.
        // Uses redacted_target (path only, no query params) to avoid logging secrets.
        {
            let (action_id, disposition_id, severity) = match decision_str {
                "deny" => (ActionId::Denied, DispositionId::Blocked, SeverityId::Medium),
                "allow" | "audit" => (
                    ActionId::Allowed,
                    DispositionId::Allowed,
                    SeverityId::Informational,
                ),
                _ => (
                    ActionId::Other,
                    DispositionId::Other,
                    SeverityId::Informational,
                ),
            };
            let event = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(ActivityId::Other)
                .action(action_id)
                .disposition(disposition_id)
                .severity(severity)
                .http_request(HttpRequest::new(
                    &request_info.action,
                    OcsfUrl::new("http", &ctx.host, &redacted_target, ctx.port),
                ))
                .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                .firewall_rule(&ctx.policy_name, "l7")
                .message(format!(
                    "L7_REQUEST {decision_str} {} {}:{}{} reason={}",
                    request_info.action, ctx.host, ctx.port, redacted_target, reason,
                ))
                .build();
            ocsf_emit!(event);
        }

        // Store the resolved target for the deny response redaction
        let _ = &eval_target;

        if allowed || config.enforcement == EnforcementMode::Audit {
            let chain = engine.query_middleware_chain(&middleware_network_input(ctx))?;
            // REST and websocket-upgrade policy evaluates only the method,
            // path, and query, which a middleware result cannot mutate, so no
            // per-stage body re-check is needed.
            let req = match apply_middleware_chain(
                req,
                client,
                ctx,
                chain,
                engine.middleware_runner(),
                engine.generation_guard(),
                openshell_supervisor_middleware::TransformedBodyPolicy::NotPolicyRelevant,
            )
            .await?
            {
                MiddlewareApplyResult::Allowed(request) => request,
                MiddlewareApplyResult::Denied { denial, .. } => {
                    let denied_request = crate::l7::provider::L7Request {
                        action: request_info.action.clone(),
                        target: redacted_target.clone(),
                        query_params: request_info.query_params.clone(),
                        raw_header: Vec::new(),
                        body_length: crate::l7::provider::BodyLength::None,
                    };
                    crate::l7::middleware::send_middleware_rejection_response(
                        &denied_request,
                        client,
                        ctx,
                        denial.as_ref(),
                        &redacted_target,
                    )
                    .await?;
                    return Ok(());
                }
            };
            let req_with_auth =
                match crate::l7::token_grant_injection::inject_if_needed(req, ctx).await {
                    Ok(req) => req,
                    Err(e) => {
                        warn!(
                            host = %ctx.host,
                            port = ctx.port,
                            error = %e,
                            "Token grant failed in L7 relay"
                        );
                        write_bad_gateway_response(client).await?;
                        return Ok(());
                    }
                };

            // Forward request to upstream and relay response
            let outcome = crate::l7::rest::relay_http_request_with_options_guarded(
                &req_with_auth,
                client,
                upstream,
                crate::l7::rest::RelayRequestOptions {
                    resolver: ctx.secret_resolver.as_deref(),
                    generation_guard: Some(engine.generation_guard()),
                    websocket_extensions: websocket_extension_mode(config),
                    request_body_credential_rewrite: config.protocol == L7Protocol::Rest
                        && config.request_body_credential_rewrite,
                    credential_signing: config.credential_signing,
                    signing_service: &config.signing_service,
                    signing_region: &config.signing_region,
                    host: &ctx.host,
                    port: ctx.port,
                },
            )
            .await?;
            match outcome {
                RelayOutcome::Reusable => {} // continue loop
                RelayOutcome::Consumed => {
                    debug!(
                        host = %ctx.host,
                        port = ctx.port,
                        "Upstream connection not reusable, closing L7 relay"
                    );
                    return Ok(());
                }
                RelayOutcome::Upgraded {
                    overflow,
                    websocket_permessage_deflate,
                } => {
                    let mut options = upgrade_options(
                        config,
                        ctx,
                        websocket_request,
                        &redacted_target,
                        &req_with_auth.query_params,
                        Some(engine),
                    );
                    options.websocket.permessage_deflate = websocket_permessage_deflate;
                    return handle_upgrade(
                        client, upstream, overflow, &ctx.host, ctx.port, options,
                    )
                    .await;
                }
            }
        } else {
            // Enforce mode: deny with 403 and close connection (use redacted target)
            provider
                .deny_with_redacted_target(
                    &req,
                    &ctx.policy_name,
                    &reason,
                    client,
                    Some(&redacted_target),
                    Some(crate::l7::rest::DenyResponseContext::from_l7_context(ctx)),
                )
                .await?;
            return Ok(());
        }
    }
}

fn close_if_stale(guard: &PolicyGenerationGuard, ctx: &L7EvalContext) -> bool {
    if !guard.is_stale() {
        return false;
    }

    ocsf_emit!(
        NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .activity(ActivityId::Open)
            .action(ActionId::Denied)
            .disposition(DispositionId::Blocked)
            .severity(SeverityId::Medium)
            .status(StatusId::Failure)
            .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
            .firewall_rule(&ctx.policy_name, "l7")
            .message(format!(
                "L7 tunnel closed after policy reload [host:{} port:{} captured_generation:{} current_generation:{}]",
                ctx.host,
                ctx.port,
                guard.captured_generation(),
                guard.current_generation(),
            ))
            .build()
    );
    true
}

async fn relay_jsonrpc<C, U>(
    config: &L7EndpointConfig,
    engine: &TunnelPolicyEngine,
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    loop {
        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        // Future MCP version-profile request checks should hook here before OPA
        // evaluation. See McpOptions in proto/sandbox.proto for the policy
        // roadmap and source documentation.
        let parsed = match crate::l7::jsonrpc::parse_jsonrpc_http_request(
            client,
            config.json_rpc_max_body_bytes,
            crate::l7::path::CanonicalizeOptions {
                allow_encoded_slash: config.allow_encoded_slash,
                ..Default::default()
            },
            crate::l7::jsonrpc::JsonRpcInspectionOptions::for_config(config),
        )
        .await
        {
            Ok(Some(parsed)) => parsed,
            Ok(None) => return Ok(()),
            Err(e) => {
                if is_benign_connection_error(&e) {
                    debug!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "JSON-RPC L7 connection closed"
                    );
                } else {
                    let detail =
                        parse_rejection_detail(&e.to_string(), ParseRejectionMode::L7Endpoint);
                    emit_parse_rejection(ctx, &detail, jsonrpc_engine_type(config.protocol));
                }
                return Ok(());
            }
        };

        let req = parsed.request;
        let jsonrpc_info = parsed.info;

        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        let redacted_target = req.target.clone();

        let request_info = L7RequestInfo {
            action: req.action.clone(),
            target: redacted_target.clone(),
            query_params: req.query_params.clone(),
            graphql: None,
            jsonrpc: Some(jsonrpc_info.clone()),
        };

        let hard_deny_reason = l7_request_hard_deny_reason(config.protocol, &request_info);
        let force_deny = hard_deny_reason.is_some();
        let (allowed, reason, jsonrpc_log_info) = if let Some(reason) = hard_deny_reason {
            (false, reason, jsonrpc_info.clone())
        } else {
            let evaluation =
                evaluate_jsonrpc_l7_request_for_log(engine, ctx, &request_info, &jsonrpc_info)?;
            (evaluation.allowed, evaluation.reason, evaluation.log_info)
        };

        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        let decision_str = match (allowed, config.enforcement) {
            (_, _) if force_deny => "deny",
            (true, _) => "allow",
            (false, EnforcementMode::Audit) => "audit",
            (false, EnforcementMode::Enforce) => "deny",
        };

        {
            let (action_id, disposition_id, severity) = match decision_str {
                "deny" => (ActionId::Denied, DispositionId::Blocked, SeverityId::Medium),
                _ => (
                    ActionId::Allowed,
                    DispositionId::Allowed,
                    SeverityId::Informational,
                ),
            };
            let endpoint = format!("{}:{}{}", ctx.host, ctx.port, redacted_target);
            let policy_version = engine.captured_generation();
            let event = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(ActivityId::Other)
                .action(action_id)
                .disposition(disposition_id)
                .severity(severity)
                .http_request(HttpRequest::new(
                    &request_info.action,
                    OcsfUrl::new("http", &ctx.host, &redacted_target, ctx.port),
                ))
                .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                .firewall_rule(&ctx.policy_name, jsonrpc_engine_type(config.protocol))
                .message(jsonrpc_log_message(
                    decision_str,
                    &request_info.action,
                    &endpoint,
                    &jsonrpc_log_info,
                    policy_version,
                    &reason,
                ))
                .build();
            ocsf_emit!(event);
        }

        if allowed || (config.enforcement == EnforcementMode::Audit && !force_deny) {
            let chain = engine.query_middleware_chain(&middleware_network_input(ctx))?;
            // Policy admitted the original body above; re-check the body
            // against the same body-aware policy after every transforming
            // stage so a middleware cannot smuggle a denied operation to the
            // upstream or the next stage.
            let validate = transformed_body_validator(config, engine, ctx, &request_info);
            let req = match apply_middleware_chain(
                req,
                client,
                ctx,
                chain,
                engine.middleware_runner(),
                engine.generation_guard(),
                openshell_supervisor_middleware::TransformedBodyPolicy::Reevaluate(&validate),
            )
            .await?
            {
                MiddlewareApplyResult::Allowed(request) => request,
                MiddlewareApplyResult::Denied { denial, .. } => {
                    let denied_request = crate::l7::provider::L7Request {
                        action: request_info.action.clone(),
                        target: redacted_target.clone(),
                        query_params: request_info.query_params.clone(),
                        raw_header: Vec::new(),
                        body_length: crate::l7::provider::BodyLength::None,
                    };
                    crate::l7::middleware::send_middleware_rejection_response(
                        &denied_request,
                        client,
                        ctx,
                        denial.as_ref(),
                        &redacted_target,
                    )
                    .await?;
                    return Ok(());
                }
            };
            // Future MCP response/SSE introspection or rewrite would hook here
            // before returning upstream bytes. The current policy schema has no
            // trusted-annotations or version-profile field, so MCP responses and
            // SSE streams are relayed unchanged; see McpOptions in
            // proto/sandbox.proto for planned policy extensions.
            let outcome = crate::l7::rest::relay_http_request_with_resolver_guarded(
                &req,
                client,
                upstream,
                ctx.secret_resolver.as_deref(),
                Some(engine.generation_guard()),
            )
            .await?;
            match outcome {
                RelayOutcome::Reusable => {}
                RelayOutcome::Consumed => {
                    debug!(
                        host = %ctx.host,
                        port = ctx.port,
                        "Upstream connection not reusable, closing JSON-RPC L7 relay"
                    );
                    return Ok(());
                }
                RelayOutcome::Upgraded { .. } => {
                    return Ok(());
                }
            }
        } else {
            crate::l7::rest::RestProvider::default()
                .deny_with_redacted_target(
                    &req,
                    &ctx.policy_name,
                    &reason,
                    client,
                    Some(&redacted_target),
                    Some(crate::l7::rest::DenyResponseContext::from_l7_context(ctx)),
                )
                .await?;
            return Ok(());
        }
    }
}

async fn relay_graphql<C, U>(
    config: &L7EndpointConfig,
    engine: &TunnelPolicyEngine,
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    loop {
        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        let parsed = match crate::l7::graphql::parse_graphql_http_request(
            client,
            config.graphql_max_body_bytes,
            crate::l7::path::CanonicalizeOptions {
                allow_encoded_slash: config.allow_encoded_slash,
                ..Default::default()
            },
        )
        .await
        {
            Ok(Some(parsed)) => parsed,
            Ok(None) => return Ok(()),
            Err(e) => {
                if is_benign_connection_error(&e) {
                    debug!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "GraphQL L7 connection closed"
                    );
                } else {
                    let detail =
                        parse_rejection_detail(&e.to_string(), ParseRejectionMode::L7Endpoint);
                    emit_parse_rejection(ctx, &detail, "l7-graphql");
                }
                return Ok(());
            }
        };

        let req = parsed.request;
        let graphql_info = parsed.info;

        if deny_h2c_upgrade_if_requested(&req, config, ctx, client).await? {
            return Ok(());
        }

        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        let (eval_target, redacted_target) = if let Some(ref resolver) = ctx.secret_resolver {
            match secrets::rewrite_target_for_eval(&req.target, resolver) {
                Ok(result) => (result.resolved, result.redacted),
                Err(e) => {
                    warn!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "credential resolution failed in GraphQL request target, rejecting"
                    );
                    let response = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    client.write_all(response).await.into_diagnostic()?;
                    client.flush().await.into_diagnostic()?;
                    return Ok(());
                }
            }
        } else {
            (req.target.clone(), req.target.clone())
        };

        let request_info = L7RequestInfo {
            action: req.action.clone(),
            target: redacted_target.clone(),
            query_params: req.query_params.clone(),
            graphql: Some(graphql_info.clone()),
            jsonrpc: None,
        };

        // Malformed or ambiguous GraphQL requests, such as duplicated GET
        // control parameters, are rejected before policy evaluation. This
        // keeps parser-differential cases fail-closed even if the endpoint is
        // otherwise in audit mode.
        let hard_deny_reason = l7_request_hard_deny_reason(config.protocol, &request_info);
        let force_deny = hard_deny_reason.is_some();
        let (allowed, reason) = if let Some(reason) = hard_deny_reason {
            (false, reason)
        } else {
            evaluate_l7_request(engine, ctx, &request_info)?
        };

        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        let decision_str = match (allowed, config.enforcement) {
            (_, _) if force_deny => "deny",
            (true, _) => "allow",
            (false, EnforcementMode::Audit) => "audit",
            (false, EnforcementMode::Enforce) => "deny",
        };

        {
            let (action_id, disposition_id, severity) = match decision_str {
                "deny" => (ActionId::Denied, DispositionId::Blocked, SeverityId::Medium),
                "allow" | "audit" => (
                    ActionId::Allowed,
                    DispositionId::Allowed,
                    SeverityId::Informational,
                ),
                _ => (
                    ActionId::Other,
                    DispositionId::Other,
                    SeverityId::Informational,
                ),
            };
            let gql_summary = graphql_log_summary(&graphql_info);
            let event = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(ActivityId::Other)
                .action(action_id)
                .disposition(disposition_id)
                .severity(severity)
                .http_request(HttpRequest::new(
                    &request_info.action,
                    OcsfUrl::new("http", &ctx.host, &redacted_target, ctx.port),
                ))
                .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                .firewall_rule(&ctx.policy_name, "l7-graphql")
                .message(format!(
                    "GRAPHQL_L7_REQUEST {decision_str} {} {}:{}{} {gql_summary} reason={}",
                    request_info.action, ctx.host, ctx.port, redacted_target, reason,
                ))
                .build();
            ocsf_emit!(event);
        }

        let _ = &eval_target;

        if allowed || (config.enforcement == EnforcementMode::Audit && !force_deny) {
            let chain = engine.query_middleware_chain(&middleware_network_input(ctx))?;
            // Policy admitted the original body above; re-check the body
            // against the same body-aware policy after every transforming
            // stage so a middleware cannot smuggle a denied operation to the
            // upstream or the next stage.
            let validate = transformed_body_validator(config, engine, ctx, &request_info);
            let req = match apply_middleware_chain(
                req,
                client,
                ctx,
                chain,
                engine.middleware_runner(),
                engine.generation_guard(),
                openshell_supervisor_middleware::TransformedBodyPolicy::Reevaluate(&validate),
            )
            .await?
            {
                MiddlewareApplyResult::Allowed(request) => request,
                MiddlewareApplyResult::Denied { denial, .. } => {
                    let denied_request = crate::l7::provider::L7Request {
                        action: request_info.action.clone(),
                        target: redacted_target.clone(),
                        query_params: request_info.query_params.clone(),
                        raw_header: Vec::new(),
                        body_length: crate::l7::provider::BodyLength::None,
                    };
                    crate::l7::middleware::send_middleware_rejection_response(
                        &denied_request,
                        client,
                        ctx,
                        denial.as_ref(),
                        &redacted_target,
                    )
                    .await?;
                    return Ok(());
                }
            };
            let outcome = crate::l7::rest::relay_http_request_with_resolver_guarded(
                &req,
                client,
                upstream,
                ctx.secret_resolver.as_deref(),
                Some(engine.generation_guard()),
            )
            .await?;
            match outcome {
                RelayOutcome::Reusable => {}
                RelayOutcome::Consumed => {
                    debug!(
                        host = %ctx.host,
                        port = ctx.port,
                        "Upstream connection not reusable, closing GraphQL L7 relay"
                    );
                    return Ok(());
                }
                RelayOutcome::Upgraded {
                    overflow,
                    websocket_permessage_deflate,
                } => {
                    let options = UpgradeRelayOptions {
                        websocket: WebSocketUpgradeBehavior {
                            permessage_deflate: websocket_permessage_deflate,
                            ..Default::default()
                        },
                        ..Default::default()
                    };
                    return handle_upgrade(
                        client, upstream, overflow, &ctx.host, ctx.port, options,
                    )
                    .await;
                }
            }
        } else {
            crate::l7::rest::RestProvider::default()
                .deny_with_redacted_target(
                    &req,
                    &ctx.policy_name,
                    &reason,
                    client,
                    Some(&redacted_target),
                    Some(crate::l7::rest::DenyResponseContext::from_l7_context(ctx)),
                )
                .await?;
            return Ok(());
        }
    }
}

fn graphql_log_summary(info: &crate::l7::graphql::GraphqlRequestInfo) -> String {
    if let Some(error) = &info.error {
        return format!("graphql_error={error:?}");
    }
    let ops: Vec<String> = info
        .operations
        .iter()
        .map(|op| {
            let name = op.operation_name.as_deref().unwrap_or("-");
            let fields = if op.fields.is_empty() {
                "-".to_string()
            } else {
                op.fields.join(",")
            };
            let persisted = op
                .persisted_query_hash
                .as_deref()
                .or(op.persisted_query_id.as_deref())
                .unwrap_or("-");
            format!(
                "type={} name={} fields={} persisted={}",
                op.operation_type, name, fields, persisted
            )
        })
        .collect();
    format!("graphql_ops={}", ops.join(";"))
}

pub(crate) fn jsonrpc_log_message(
    decision: &str,
    http_method: &str,
    endpoint: &str,
    info: &crate::l7::jsonrpc::JsonRpcRequestInfo,
    policy_version: u64,
    reason: &str,
) -> String {
    let rule_methods = rule_method_names_for_log(info);
    let tools = tool_names_for_log(info);
    format!(
        "JSONRPC_L7_REQUEST decision={decision} rule_methods={rule_methods} tools={tools} http_method={http_method} endpoint={endpoint} policy_version={policy_version} reason={reason}"
    )
}

pub(crate) fn rule_method_names_for_log(info: &crate::l7::jsonrpc::JsonRpcRequestInfo) -> String {
    if info.calls.is_empty() {
        return "-".to_string();
    }
    info.calls
        .iter()
        .map(|call| sanitize_log_token(&call.method))
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn tool_names_for_log(info: &crate::l7::jsonrpc::JsonRpcRequestInfo) -> String {
    let tools = info
        .calls
        .iter()
        .filter_map(|call| call.tool.as_deref())
        .map(sanitize_log_token)
        .collect::<Vec<_>>();
    if tools.is_empty() {
        "-".to_string()
    } else {
        tools.join(",")
    }
}

fn sanitize_log_token(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_control() { '?' } else { ch })
        .collect()
}

struct JsonRpcEvaluation {
    allowed: bool,
    reason: String,
    log_info: crate::l7::jsonrpc::JsonRpcRequestInfo,
}

pub(crate) const JSONRPC_RESPONSE_FRAME_DENY_REASON: &str =
    "JSON-RPC response frames are not permitted from client to server";

pub(crate) fn jsonrpc_response_frame_hard_deny_reason(
    protocol: L7Protocol,
    jsonrpc: &crate::l7::jsonrpc::JsonRpcRequestInfo,
) -> Option<String> {
    (protocol != L7Protocol::Mcp && jsonrpc.has_response)
        .then(|| JSONRPC_RESPONSE_FRAME_DENY_REASON.to_string())
}

/// Classify malformed or protocol-invalid requests that must be denied even
/// when the selected endpoint is in audit mode.
///
/// All HTTP entry points use this helper so dedicated relays, route-selected
/// relays, forward proxying, and post-middleware re-evaluation cannot drift on
/// hard-deny semantics.
pub(crate) fn l7_request_hard_deny_reason(
    protocol: L7Protocol,
    request: &L7RequestInfo,
) -> Option<String> {
    request
        .graphql
        .as_ref()
        .and_then(|info| info.error.as_deref())
        .map(|error| format!("GraphQL request rejected: {error}"))
        .or_else(|| {
            request.jsonrpc.as_ref().and_then(|info| {
                info.error
                    .as_ref()
                    .map(crate::l7::jsonrpc::JsonRpcInspectionError::rejection_reason)
                    .or_else(|| jsonrpc_response_frame_hard_deny_reason(protocol, info))
            })
        })
}

/// Check if a miette error represents a benign connection close.
///
/// TLS handshake EOF, missing `close_notify`, connection resets, and broken
/// pipes are all normal lifecycle events for proxied connections — not worth
/// a WARN that interrupts the user's terminal.
fn is_benign_connection_error(err: &miette::Report) -> bool {
    const BENIGN: &[&str] = &[
        "close_notify",
        "tls handshake eof",
        "connection reset",
        "broken pipe",
        "unexpected eof",
        "client disconnected mid-request",
    ];
    let msg = err.to_string().to_ascii_lowercase();
    BENIGN.iter().any(|pat| msg.contains(pat))
}

/// Evaluate an L7 request against the OPA engine.
///
/// Returns `(allowed, deny_reason)`.
pub fn evaluate_l7_request(
    engine: &TunnelPolicyEngine,
    ctx: &L7EvalContext,
    request: &L7RequestInfo,
) -> Result<(bool, String)> {
    if let Some(jsonrpc) = &request.jsonrpc
        && jsonrpc.is_batch
        && !jsonrpc.calls.is_empty()
    {
        if jsonrpc.has_response {
            let (allowed, reason) = evaluate_l7_request_once(engine, ctx, request)?;
            if !allowed {
                return Ok((false, reason));
            }
        }
        for call in &jsonrpc.calls {
            let item_request = jsonrpc_request_for_call(request, call);
            let (allowed, reason) = evaluate_l7_request_once(engine, ctx, &item_request)?;
            if !allowed {
                return Ok((false, reason));
            }
        }
        return Ok((true, String::new()));
    }

    evaluate_l7_request_once(engine, ctx, request)
}

fn evaluate_jsonrpc_l7_request_for_log(
    engine: &TunnelPolicyEngine,
    ctx: &L7EvalContext,
    request: &L7RequestInfo,
    jsonrpc: &crate::l7::jsonrpc::JsonRpcRequestInfo,
) -> Result<JsonRpcEvaluation> {
    if jsonrpc.has_response {
        let (allowed, reason) = evaluate_l7_request_once(engine, ctx, request)?;
        if !allowed || !jsonrpc.is_batch || jsonrpc.calls.is_empty() {
            return Ok(JsonRpcEvaluation {
                allowed,
                reason,
                log_info: jsonrpc.clone(),
            });
        }
    }

    if jsonrpc.is_batch && !jsonrpc.calls.is_empty() {
        let mut denied_calls = Vec::new();
        let mut first_denied_reason = None;
        for call in &jsonrpc.calls {
            let item_request = jsonrpc_request_for_call(request, call);
            let (allowed, reason) = evaluate_l7_request_once(engine, ctx, &item_request)?;
            if !allowed {
                if first_denied_reason.is_none() {
                    first_denied_reason = Some(reason);
                }
                denied_calls.push(call.clone());
            }
        }

        if denied_calls.is_empty() {
            return Ok(JsonRpcEvaluation {
                allowed: true,
                reason: String::new(),
                log_info: jsonrpc.clone(),
            });
        }

        return Ok(JsonRpcEvaluation {
            allowed: false,
            reason: first_denied_reason.unwrap_or_else(|| "request denied by policy".to_string()),
            log_info: crate::l7::jsonrpc::JsonRpcRequestInfo {
                calls: denied_calls,
                is_batch: true,
                receive_stream: false,
                has_response: false,
                error: None,
            },
        });
    }

    let (allowed, reason) = evaluate_l7_request_once(engine, ctx, request)?;
    Ok(JsonRpcEvaluation {
        allowed,
        reason,
        log_info: jsonrpc.clone(),
    })
}

fn jsonrpc_request_for_call(
    request: &L7RequestInfo,
    call: &crate::l7::jsonrpc::JsonRpcCallInfo,
) -> L7RequestInfo {
    let mut item_request = request.clone();
    item_request.jsonrpc = Some(crate::l7::jsonrpc::JsonRpcRequestInfo {
        calls: vec![call.clone()],
        is_batch: false,
        receive_stream: false,
        has_response: false,
        error: None,
    });
    item_request
}

/// Re-evaluate body-aware policy against a middleware-transformed body. Policy
/// admits the original body before the chain runs, so each replaced body must
/// be checked again before the next stage or the upstream sees it: a
/// transformation cannot smuggle a denied or unparseable operation past the
/// policy. Returns the deny reason, or `None` when the transformed body is
/// admissible. An unparseable replacement or a response frame denies even
/// under audit, mirroring `force_deny` for the original body; a policy deny
/// respects the endpoint's enforcement mode. Method, path, and query come from
/// `request_info` because a middleware result cannot mutate them.
///
/// The match is exhaustive over `L7Protocol` on purpose: adding a protocol
/// does not compile until its transformed-body re-evaluation is defined here,
/// either by re-deriving the body-dependent policy inputs or by documenting
/// why none exist. Build the per-request validator with
/// [`transformed_body_validator`].
fn reevaluate_transformed_body(
    config: &L7EndpointConfig,
    engine: &TunnelPolicyEngine,
    ctx: &L7EvalContext,
    request_info: &L7RequestInfo,
    body: &[u8],
) -> Result<Option<String>> {
    let (engine_type, transformed_info) = match config.protocol {
        // REST and websocket-upgrade policy evaluates only the method, path,
        // and query, which a middleware result cannot mutate; the body is not
        // a policy input. SQL has no body-aware L7 policy either; the
        // uninspectable-traffic gate keeps required middleware ahead of the
        // unimplemented SQL relay.
        L7Protocol::Rest | L7Protocol::Websocket | L7Protocol::Sql => return Ok(None),
        L7Protocol::JsonRpc | L7Protocol::Mcp => {
            let info = crate::l7::jsonrpc::parse_jsonrpc_body_with_options(
                body,
                crate::l7::jsonrpc::JsonRpcInspectionOptions::for_config(config),
            );
            let mut transformed_info = request_info.clone();
            transformed_info.jsonrpc = Some(info);
            (jsonrpc_engine_type(config.protocol), transformed_info)
        }
        L7Protocol::Graphql => {
            // GraphQL classification needs the request method and query
            // params; only the body was replaced, so rebuild from
            // `request_info` and the new body.
            let request = crate::l7::provider::L7Request {
                action: request_info.action.clone(),
                target: request_info.target.clone(),
                query_params: request_info.query_params.clone(),
                raw_header: Vec::new(),
                body_length: crate::l7::provider::BodyLength::None,
            };
            let info = crate::l7::graphql::classify_request(&request, body);
            let mut transformed_info = request_info.clone();
            transformed_info.graphql = Some(info);
            ("l7-graphql", transformed_info)
        }
    };

    if let Some(reason) = l7_request_hard_deny_reason(config.protocol, &transformed_info) {
        let reason = format!("middleware transformation rejected: {reason}");
        emit_transformed_body_decision(ctx, request_info, engine_type, "deny", &reason);
        return Ok(Some(reason));
    }

    let (allowed, reason) = evaluate_l7_request(engine, ctx, &transformed_info)?;
    if allowed {
        return Ok(None);
    }
    let reason = format!("middleware transformation denied by policy: {reason}");
    if config.enforcement == EnforcementMode::Audit {
        emit_transformed_body_decision(ctx, request_info, engine_type, "audit", &reason);
        return Ok(None);
    }
    emit_transformed_body_decision(ctx, request_info, engine_type, "deny", &reason);
    Ok(Some(reason))
}

/// Build the per-stage transformed-body validator the middleware chain calls
/// after every stage that replaces the body. Borrows the policy inputs, so it
/// lives only as long as this request's evaluation.
pub(crate) fn transformed_body_validator<'a>(
    config: &'a L7EndpointConfig,
    engine: &'a TunnelPolicyEngine,
    ctx: &'a L7EvalContext,
    request_info: &'a L7RequestInfo,
) -> impl Fn(&[u8]) -> Result<Option<String>> + Send + Sync + 'a {
    move |body: &[u8]| reevaluate_transformed_body(config, engine, ctx, request_info, body)
}

/// Log the post-transformation policy decision as an OCSF HTTP Activity
/// event, mirroring the pre-middleware decision logs. `request_info.target`
/// is already redacted by the callers.
fn emit_transformed_body_decision(
    ctx: &L7EvalContext,
    request_info: &L7RequestInfo,
    engine_type: &str,
    decision_str: &str,
    reason: &str,
) {
    let (action_id, disposition_id, severity) = match decision_str {
        "deny" => (ActionId::Denied, DispositionId::Blocked, SeverityId::Medium),
        _ => (
            ActionId::Allowed,
            DispositionId::Allowed,
            SeverityId::Informational,
        ),
    };
    let event = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Other)
        .action(action_id)
        .disposition(disposition_id)
        .severity(severity)
        .http_request(HttpRequest::new(
            &request_info.action,
            OcsfUrl::new("http", &ctx.host, &request_info.target, ctx.port),
        ))
        .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
        .firewall_rule(&ctx.policy_name, engine_type)
        .message(format!(
            "L7_REQUEST_TRANSFORMED {decision_str} {} {}:{}{} reason={}",
            request_info.action, ctx.host, ctx.port, request_info.target, reason
        ))
        .build();
    ocsf_emit!(event);
}

fn jsonrpc_policy_input(info: &crate::l7::jsonrpc::JsonRpcRequestInfo) -> serde_json::Value {
    let call = if info.is_batch {
        None
    } else {
        info.calls.first()
    };
    serde_json::json!({
        "method": call.map(|call| call.method.as_str()),
        "params": call.map(|call| &call.params),
        "tool": call.and_then(|call| call.tool.as_deref()),
        "receive_stream": info.receive_stream,
        "has_response": info.has_response,
        // Rust keeps the inspection failure kind typed. Rego's stable boundary is
        // still the original diagnostic string or null.
        "error": info
            .error
            .as_ref()
            .map(crate::l7::jsonrpc::JsonRpcInspectionError::detail),
    })
}

fn evaluate_l7_request_once(
    engine: &TunnelPolicyEngine,
    ctx: &L7EvalContext,
    request: &L7RequestInfo,
) -> Result<(bool, String)> {
    if engine.is_stale() {
        return Err(miette!(
            "L7 tunnel policy generation is stale [captured_generation:{} current_generation:{}]",
            engine.captured_generation(),
            engine.current_generation(),
        ));
    }

    let input_json = serde_json::json!({
        "network": {
            "host": ctx.host,
            "port": ctx.port,
        },
        "exec": {
            "path": ctx.binary_path,
            "ancestors": ctx.ancestors,
            "cmdline_paths": ctx.cmdline_paths,
        },
        "request": {
            "method": request.action,
            "path": request.target,
            "query_params": request.query_params.clone(),
            "graphql": request.graphql.clone(),
            "jsonrpc": request.jsonrpc.as_ref().map(jsonrpc_policy_input),
        }
    });

    let mut engine = engine
        .engine()
        .lock()
        .map_err(|_| miette!("OPA engine lock poisoned"))?;

    engine
        .set_input_json(&input_json.to_string())
        .map_err(|e| miette!("{e}"))?;

    let allowed = engine
        .eval_rule("data.openshell.sandbox.allow_request".into())
        .map_err(|e| miette!("{e}"))?;
    let allowed = allowed == regorus::Value::from(true);

    let reason = if allowed {
        String::new()
    } else {
        let val = engine
            .eval_rule("data.openshell.sandbox.request_deny_reason".into())
            .map_err(|e| miette!("{e}"))?;
        match val {
            regorus::Value::String(s) => s.to_string(),
            regorus::Value::Undefined => "request denied by policy".to_string(),
            other => other.to_string(),
        }
    };

    Ok((allowed, reason))
}

/// Relay HTTP traffic with credential injection only (no L7 OPA evaluation).
///
/// Used when TLS is auto-terminated but no L7 policy (`protocol` + `access`/`rules`)
/// is configured. Parses HTTP requests minimally to rewrite credential
/// placeholders and log requests for observability, then forwards everything.
pub async fn relay_passthrough_with_credentials<C, U>(
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
    generation_guard: &PolicyGenerationGuard,
    middleware_engine: Option<&crate::opa::OpaEngine>,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Passthrough path: no L7 policy is enforced here, so use default
    // (strict) canonicalization options. Calls to GitLab-style APIs that
    // need `%2F` must be configured as L7 endpoints so the per-endpoint
    // `allow_encoded_slash` opt-in applies.
    let provider = crate::l7::rest::RestProvider::default();
    let mut request_count: u64 = 0;
    let resolver = ctx.secret_resolver.as_deref();

    loop {
        if close_if_stale(generation_guard, ctx) {
            return Ok(());
        }

        // Read next request from client.
        let req = match provider.parse_request(client).await {
            Ok(Some(req)) => req,
            Ok(None) => break, // Client closed connection.
            Err(e) => {
                if is_benign_connection_error(&e) {
                    break;
                }
                let detail =
                    parse_rejection_detail(&e.to_string(), ParseRejectionMode::Passthrough);
                emit_parse_rejection(ctx, &detail, "http-parser");
                return Ok(());
            }
        };

        if close_if_stale(generation_guard, ctx) {
            return Ok(());
        }

        request_count += 1;

        // Resolve and redact the target for logging.
        let redacted_target = if let Some(ref res) = ctx.secret_resolver {
            match secrets::rewrite_target_for_eval(&req.target, res) {
                Ok(result) => result.redacted,
                Err(e) => {
                    warn!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "credential resolution failed in request target, rejecting"
                    );
                    let response = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    client.write_all(response).await.into_diagnostic()?;
                    client.flush().await.into_diagnostic()?;
                    return Ok(());
                }
            }
        } else {
            req.target.clone()
        };

        // Log for observability via OCSF HTTP Activity event.
        // Uses redacted_target (path only, no query params) to avoid logging secrets.
        let has_creds = resolver.is_some();
        {
            let event = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(ActivityId::Other)
                .action(ActionId::Allowed)
                .disposition(DispositionId::Allowed)
                .severity(SeverityId::Informational)
                .http_request(HttpRequest::new(
                    &req.action,
                    OcsfUrl::new("http", &ctx.host, &redacted_target, ctx.port),
                ))
                .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                .message(format!(
                    "HTTP_REQUEST {} {}:{}{} credentials_injected={has_creds} request_num={request_count}",
                    req.action, ctx.host, ctx.port, redacted_target,
                ))
                .build();
            ocsf_emit!(event);
        }

        let req = if let Some(engine) = middleware_engine {
            let input = middleware_network_input(ctx);
            let (chain, generation) = engine.query_middleware_chain_with_generation(&input)?;
            if generation != generation_guard.captured_generation() {
                return Ok(());
            }
            let runner = engine.middleware_runner()?;
            // The passthrough path enforces no L7 policy, so there is no
            // body-aware decision to re-check after a transformation.
            match apply_middleware_chain(
                req,
                client,
                ctx,
                chain,
                &runner,
                generation_guard,
                openshell_supervisor_middleware::TransformedBodyPolicy::NotPolicyRelevant,
            )
            .await?
            {
                MiddlewareApplyResult::Allowed(request) => request,
                MiddlewareApplyResult::Denied { denial, .. } => {
                    let denied_request = crate::l7::provider::L7Request {
                        action: "HTTP".into(),
                        target: redacted_target.clone(),
                        query_params: std::collections::HashMap::new(),
                        raw_header: Vec::new(),
                        body_length: crate::l7::provider::BodyLength::None,
                    };
                    crate::l7::middleware::send_middleware_rejection_response(
                        &denied_request,
                        client,
                        ctx,
                        denial.as_ref(),
                        &redacted_target,
                    )
                    .await?;
                    return Ok(());
                }
            }
        } else {
            req
        };

        let req_with_auth = match crate::l7::token_grant_injection::inject_if_needed(req, ctx).await
        {
            Ok(req) => req,
            Err(e) => {
                warn!(
                    host = %ctx.host,
                    port = ctx.port,
                    error = %e,
                    "Token grant failed in passthrough relay"
                );
                write_bad_gateway_response(client).await?;
                return Ok(());
            }
        };

        // Forward request with credential rewriting and relay the response.
        // relay_http_request_with_resolver handles both directions: it sends
        // the request upstream and reads the response back to the client.
        let outcome = crate::l7::rest::relay_http_request_with_options_guarded(
            &req_with_auth,
            client,
            upstream,
            crate::l7::rest::RelayRequestOptions {
                resolver,
                generation_guard: Some(generation_guard),
                ..Default::default()
            },
        )
        .await?;

        match outcome {
            RelayOutcome::Reusable => {} // continue loop
            RelayOutcome::Consumed => break,
            RelayOutcome::Upgraded { overflow, .. } => {
                return handle_upgrade(
                    client,
                    upstream,
                    overflow,
                    &ctx.host,
                    ctx.port,
                    UpgradeRelayOptions::default(),
                )
                .await;
            }
        }
    }

    debug!(
        host = %ctx.host,
        port = ctx.port,
        total_requests = request_count,
        "Credential injection relay completed"
    );

    Ok(())
}

async fn write_bad_gateway_response<W>(client: &mut W) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let response = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    client.write_all(response).await.into_diagnostic()?;
    client.flush().await.into_diagnostic()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opa::{NetworkInput, OpaEngine};
    use std::path::PathBuf;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

    const TEST_POLICY: &str = include_str!("../../data/sandbox-policy.rego");

    fn install_builtin_middleware(engine: &OpaEngine) {
        engine.set_middleware_runner_for_tests(openshell_supervisor_middleware::ChainRunner::new(
            openshell_supervisor_middleware_builtins::services()
                .into_iter()
                .next()
                .expect("built-in middleware service"),
        ));
    }

    fn assert_middleware_failure_response(response: &str, policy_name: &str) {
        assert!(response.contains("403 Forbidden"), "{response}");
        let (_, body) = response.split_once("\r\n\r\n").expect("HTTP response");
        let body: serde_json::Value = serde_json::from_str(body).expect("JSON response");
        assert_eq!(body["error"], "middleware_failed");
        assert_eq!(
            body["detail"],
            "Request could not be processed by configured middleware"
        );
        assert_eq!(body["policy"], policy_name);
        assert!(body.get("rule").is_none());
        assert!(body.get("rule_missing").is_none());
        assert!(body.get("next_steps").is_none());
        assert!(body.get("agent_guidance").is_none());
    }

    fn rest_token_grant_relay_context(
        resolver_response: std::result::Result<&str, &str>,
    ) -> (
        L7EndpointConfig,
        TunnelPolicyEngine,
        L7EvalContext,
        crate::l7::token_grant_injection::test_support::TokenGrantTestFixture,
    ) {
        let data = r#"
network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: api.example.test
        port: 8080
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/v1/**"
    binaries:
      - { path: /usr/bin/curl }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "api.example.test".into(),
            port: 8080,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let (endpoint_config, generation) = engine
            .query_endpoint_config_with_generation(&input)
            .unwrap();
        let config = crate::l7::parse_l7_config(&endpoint_config.unwrap()).unwrap();
        let tunnel_engine = engine.clone_engine_for_tunnel(generation).unwrap();
        let provider_key = "api.example.test\t8080\t/v1/**\tprovider:access_token";
        let fixture = match resolver_response {
            Ok(token) => {
                crate::l7::token_grant_injection::test_support::TokenGrantTestFixture::success(
                    provider_key,
                    token,
                )
            }
            Err(error) => {
                crate::l7::token_grant_injection::test_support::TokenGrantTestFixture::failure(
                    provider_key,
                    error,
                )
            }
        };
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 8080,
            policy_name: "rest_api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            dynamic_credentials: Some(fixture.dynamic_credentials()),
            token_grant_resolver: Some(fixture.resolver()),
            ..Default::default()
        };

        (config, tunnel_engine, ctx, fixture)
    }

    fn middleware_relay_context(
        middleware_impl: &str,
        on_error: &str,
    ) -> (L7EndpointConfig, TunnelPolicyEngine, L7EvalContext) {
        middleware_relay_context_with_enforcement(middleware_impl, on_error, "enforce")
    }

    fn middleware_relay_context_with_enforcement(
        middleware_impl: &str,
        on_error: &str,
        enforcement: &str,
    ) -> (L7EndpointConfig, TunnelPolicyEngine, L7EvalContext) {
        let data = format!(
            r#"
network_middlewares:
  request-middleware:
    middleware: {middleware_impl}
    on_error: {on_error}
    endpoints:
      include: ["api.example.test"]
network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: api.example.test
        port: 8080
        protocol: rest
        enforcement: {enforcement}
        rules:
          - allow:
              method: POST
              path: "/v1/**"
    binaries:
      - {{ path: /usr/bin/curl }}
"#
        );
        let engine = OpaEngine::from_strings(TEST_POLICY, &data).unwrap();
        install_builtin_middleware(&engine);
        let input = NetworkInput {
            host: "api.example.test".into(),
            port: 8080,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let (endpoint_config, generation) = engine
            .query_endpoint_config_with_generation(&input)
            .unwrap();
        let config = crate::l7::parse_l7_config(&endpoint_config.unwrap()).unwrap();
        let tunnel_engine = engine.clone_engine_for_tunnel(generation).unwrap();
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 8080,
            policy_name: "rest_api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            ..Default::default()
        };

        (config, tunnel_engine, ctx)
    }

    fn passthrough_token_grant_relay_context(
        resolver_response: std::result::Result<&str, &str>,
    ) -> (
        PolicyGenerationGuard,
        L7EvalContext,
        crate::l7::token_grant_injection::test_support::TokenGrantTestFixture,
    ) {
        let policy_data = "network_policies: {}\n";
        let engine = OpaEngine::from_strings(TEST_POLICY, policy_data).unwrap();
        let generation_guard = engine
            .generation_guard(engine.current_generation())
            .unwrap();
        let provider_key = "api.example.test\t8080\t/v1/**\tprovider:access_token";
        let fixture = match resolver_response {
            Ok(token) => {
                crate::l7::token_grant_injection::test_support::TokenGrantTestFixture::success(
                    provider_key,
                    token,
                )
            }
            Err(error) => {
                crate::l7::token_grant_injection::test_support::TokenGrantTestFixture::failure(
                    provider_key,
                    error,
                )
            }
        };
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 8080,
            policy_name: "rest_api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            dynamic_credentials: Some(fixture.dynamic_credentials()),
            token_grant_resolver: Some(fixture.resolver()),
            ..Default::default()
        };

        (generation_guard, ctx, fixture)
    }

    fn jsonrpc_test_relay_context() -> (L7EndpointConfig, TunnelPolicyEngine, L7EvalContext) {
        let data = r"
network_policies:
  jsonrpc_api:
    name: jsonrpc_api
    endpoints:
      - host: jsonrpc.example.test
        port: 8000
        path: /rpc
        protocol: json-rpc
        enforcement: enforce
        rules:
          - allow:
              method: initialize
    binaries:
      - { path: /usr/bin/python3 }
";
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "jsonrpc.example.test".into(),
            port: 8000,
            binary_path: PathBuf::from("/usr/bin/python3"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let (endpoint_config, generation) = engine
            .query_endpoint_config_with_generation(&input)
            .unwrap();
        let config = crate::l7::parse_l7_config(&endpoint_config.unwrap()).unwrap();
        let tunnel_engine = engine.clone_engine_for_tunnel(generation).unwrap();
        let ctx = L7EvalContext {
            host: "jsonrpc.example.test".into(),
            port: 8000,
            policy_name: "jsonrpc_api".into(),
            binary_path: "/usr/bin/python3".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            ..Default::default()
        };
        (config, tunnel_engine, ctx)
    }

    fn mcp_test_relay_context() -> (L7EndpointConfig, TunnelPolicyEngine, L7EvalContext) {
        let data = r"
network_policies:
  mcp_api:
    name: mcp_api
    endpoints:
      - host: mcp.example.test
        port: 8000
        path: /mcp
        protocol: mcp
        enforcement: enforce
        rules:
          - allow:
              method: initialize
    binaries:
      - { path: /usr/bin/python3 }
";
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "mcp.example.test".into(),
            port: 8000,
            binary_path: PathBuf::from("/usr/bin/python3"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let (endpoint_config, generation) = engine
            .query_endpoint_config_with_generation(&input)
            .unwrap();
        let config = crate::l7::parse_l7_config(&endpoint_config.unwrap()).unwrap();
        let tunnel_engine = engine.clone_engine_for_tunnel(generation).unwrap();
        let ctx = L7EvalContext {
            host: "mcp.example.test".into(),
            port: 8000,
            policy_name: "mcp_api".into(),
            binary_path: "/usr/bin/python3".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            ..Default::default()
        };
        (config, tunnel_engine, ctx)
    }

    fn authorization_header_count(headers: &str) -> usize {
        headers
            .lines()
            .filter(|line| {
                line.split_once(':')
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            })
            .count()
    }

    #[test]
    fn parse_rejection_detail_adds_l7_hint_for_encoded_slash() {
        let detail = parse_rejection_detail(
            "HTTP request-target rejected: request-target contains an encoded '/' (%2F) which is not allowed on this endpoint",
            ParseRejectionMode::L7Endpoint,
        );

        assert!(detail.contains("allow_encoded_slash: true"));
        assert!(detail.contains("upstream requires encoded slashes"));
    }

    #[test]
    fn parse_rejection_detail_adds_passthrough_hint_for_encoded_slash() {
        let detail = parse_rejection_detail(
            "HTTP request-target rejected: request-target contains an encoded '/' (%2F) which is not allowed on this endpoint",
            ParseRejectionMode::Passthrough,
        );

        assert!(detail.contains("protocol: rest"));
        assert!(detail.contains("allow_encoded_slash: true"));
        assert!(detail.contains("tls: skip"));
    }

    #[test]
    fn parse_rejection_detail_preserves_other_errors() {
        let error = "HTTP headers contain invalid UTF-8";

        assert_eq!(
            parse_rejection_detail(error, ParseRejectionMode::L7Endpoint),
            error
        );
    }

    #[tokio::test]
    async fn l7_rest_relay_injects_token_grant_authorization_header() {
        let (config, tunnel_engine, ctx, fixture) =
            rest_token_grant_relay_context(Ok("grant-token"));
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        app.write_all(
            b"GET /v1/projects HTTP/1.1\r\nHost: api.example.test\r\nAuthorization: Bearer stale-token\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();

        let mut upstream_request = [0u8; 1024];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut upstream_request),
        )
        .await
        .expect("request should reach upstream")
        .unwrap();
        let upstream_request = String::from_utf8_lossy(&upstream_request[..n]);

        assert!(
            upstream_request.starts_with("GET /v1/projects HTTP/1.1\r\n"),
            "unexpected upstream request: {upstream_request:?}"
        );
        assert!(upstream_request.contains("Authorization: Bearer grant-token\r\n"));
        assert!(!upstream_request.contains("stale-token"));
        assert_eq!(authorization_header_count(&upstream_request), 1);

        upstream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();

        let mut client_response = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.read(&mut client_response),
        )
        .await
        .expect("response should reach client")
        .unwrap();
        assert!(String::from_utf8_lossy(&client_response[..n]).contains("204 No Content"));
        drop(app);

        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should finish")
            .unwrap()
            .unwrap();

        fixture.assert_one_request("api.example.test\t8080\t/v1/**\tprovider:access_token");
    }

    #[tokio::test]
    async fn l7_rest_relay_token_grant_failure_does_not_forward_request() {
        let (config, tunnel_engine, ctx, fixture) =
            rest_token_grant_relay_context(Err("oauth unavailable"));
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        app.write_all(
            b"GET /v1/projects HTTP/1.1\r\nHost: api.example.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should finish")
            .unwrap()
            .unwrap();

        let mut client_response = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.read(&mut client_response),
        )
        .await
        .expect("bad gateway response should reach client")
        .unwrap();
        assert!(String::from_utf8_lossy(&client_response[..n]).contains("502 Bad Gateway"));

        let mut upstream_request = [0u8; 128];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut upstream_request),
        )
        .await
        .expect("upstream should close without forwarded data")
        .unwrap();
        assert_eq!(n, 0, "unauthenticated request must not reach upstream");

        fixture.assert_one_request("api.example.test\t8080\t/v1/**\tprovider:access_token");
    }

    #[tokio::test]
    async fn l7_rest_middleware_redacts_body_before_upstream() {
        let (config, tunnel_engine, ctx) =
            middleware_relay_context("openshell/regex", "fail_closed");
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        let body = br#"{"api_key":"sk-1234567890abcdef"}"#;
        let request = format!(
            "POST /v1/messages HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            std::str::from_utf8(body).unwrap()
        );
        app.write_all(request.as_bytes()).await.unwrap();

        let mut upstream_request = [0u8; 1024];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut upstream_request),
        )
        .await
        .expect("request should reach upstream")
        .unwrap();
        let upstream_request = String::from_utf8_lossy(&upstream_request[..n]);
        assert!(upstream_request.contains(r#""api_key":"[REDACTED]""#));
        assert!(!upstream_request.contains("sk-1234567890abcdef"));

        upstream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut client_response = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.read(&mut client_response),
        )
        .await
        .expect("response should reach client")
        .unwrap();
        assert!(String::from_utf8_lossy(&client_response[..n]).contains("204 No Content"));
        drop(app);
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should finish")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn l7_rest_middleware_acknowledges_expect_continue_before_reading_body() {
        let (config, tunnel_engine, ctx) =
            middleware_relay_context("openshell/regex", "fail_closed");
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        let body = br#"{"api_key":"sk-1234567890abcdef"}"#;
        let headers = format!(
            "POST /v1/messages HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: {}\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
            body.len()
        );
        app.write_all(headers.as_bytes()).await.unwrap();

        let mut interim = [0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), app.read(&mut interim))
            .await
            .expect("middleware buffering should acknowledge Expect before reading the body")
            .unwrap();
        assert_eq!(&interim[..n], b"HTTP/1.1 100 Continue\r\n\r\n");

        app.write_all(body).await.unwrap();

        let mut upstream_request = [0u8; 1024];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut upstream_request),
        )
        .await
        .expect("request should reach upstream after the body is released")
        .unwrap();
        let upstream_request = String::from_utf8_lossy(&upstream_request[..n]);
        assert!(upstream_request.contains(r#""api_key":"[REDACTED]""#));
        assert!(!upstream_request.contains("Expect: 100-continue"));

        upstream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut client_response = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.read(&mut client_response),
        )
        .await
        .expect("response should reach client")
        .unwrap();
        assert!(String::from_utf8_lossy(&client_response[..n]).contains("204 No Content"));
        drop(app);
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should finish")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn l7_rest_middleware_fail_closed_does_not_reach_upstream() {
        let (config, tunnel_engine, ctx) =
            middleware_relay_context("example/unavailable", "fail_closed");
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        app.write_all(
            b"POST /v1/messages HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        )
        .await
        .unwrap();

        let mut response = [0u8; 512];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), app.read(&mut response))
            .await
            .expect("denial should reach client")
            .unwrap();
        let response = String::from_utf8_lossy(&response[..n]);
        assert!(response.contains("403 Forbidden"));
        let (_, body) = response.split_once("\r\n\r\n").expect("HTTP response");
        let body: serde_json::Value = serde_json::from_str(body).expect("JSON response");
        assert_eq!(body["error"], "middleware_failed");
        assert_eq!(
            body["detail"],
            "Request could not be processed by configured middleware"
        );
        assert_eq!(body["policy"], "rest_api");
        assert!(body.get("rule").is_none());
        assert!(body.get("rule_missing").is_none());
        assert!(body.get("next_steps").is_none());
        assert!(body.get("agent_guidance").is_none());

        let mut upstream_request = [0u8; 32];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            upstream.read(&mut upstream_request),
        )
        .await;
        assert!(
            matches!(result, Err(_) | Ok(Ok(0))),
            "upstream should not receive request bytes"
        );

        drop(app);
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should finish")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn audit_endpoint_forwards_policy_denied_request_through_healthy_chain() {
        // Baseline for audit semantics: a request the L7 policy denies is
        // still forwarded on an `enforcement: audit` endpoint when the
        // middleware chain is healthy and allows it.
        let (config, tunnel_engine, ctx) =
            middleware_relay_context_with_enforcement("openshell/regex", "fail_closed", "audit");
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        app.write_all(
            b"GET /other HTTP/1.1\r\nHost: api.example.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();

        let mut upstream_request = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut upstream_request),
        )
        .await
        .expect("audited request should reach upstream")
        .unwrap();
        assert!(String::from_utf8_lossy(&upstream_request[..n]).starts_with("GET /other"));

        upstream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut client_response = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.read(&mut client_response),
        )
        .await
        .expect("response should reach client")
        .unwrap();
        assert!(String::from_utf8_lossy(&client_response[..n]).contains("204 No Content"));
        drop(app);
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should finish")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn audit_endpoint_still_enforces_middleware_deny() {
        // `enforcement: audit` applies to the endpoint's L7 policy rules, not
        // to middleware: a middleware deny (here a fail-closed failure) must
        // block with 403 even though the same request would be forwarded
        // under audit with a healthy chain.
        let (config, tunnel_engine, ctx) = middleware_relay_context_with_enforcement(
            "example/unavailable",
            "fail_closed",
            "audit",
        );
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        app.write_all(
            b"GET /other HTTP/1.1\r\nHost: api.example.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();

        let mut response = [0u8; 512];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), app.read(&mut response))
            .await
            .expect("denial should reach client")
            .unwrap();
        let response = String::from_utf8_lossy(&response[..n]);
        assert!(response.contains("403 Forbidden"));
        assert!(response.contains("middleware_failed"));

        let mut upstream_request = [0u8; 32];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            upstream.read(&mut upstream_request),
        )
        .await;
        assert!(
            matches!(result, Err(_) | Ok(Ok(0))),
            "upstream should not receive request bytes"
        );

        drop(app);
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should finish")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn jsonrpc_middleware_fail_closed_does_not_reach_upstream() {
        let data = r#"
network_middlewares:
  request-middleware:
    middleware: example/unavailable
    on_error: fail_closed
    endpoints:
      include: ["api.example.test"]
network_policies:
  jsonrpc_api:
    name: jsonrpc_api
    endpoints:
      - host: api.example.test
        port: 443
        protocol: json-rpc
        enforcement: enforce
        rules:
          - allow:
              method: reports.list
    binaries:
      - { path: /usr/bin/node }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "api.example.test".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/node"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let (endpoint_config, generation) = engine
            .query_endpoint_config_with_generation(&input)
            .expect("endpoint config");
        let config = crate::l7::parse_l7_config(&endpoint_config.expect("json-rpc config"))
            .expect("parse JSON-RPC config");
        let tunnel_engine = engine.clone_engine_for_tunnel(generation).unwrap();
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 443,
            policy_name: "jsonrpc_api".into(),
            binary_path: "/usr/bin/node".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            ..Default::default()
        };
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_jsonrpc(
                &config,
                &tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        let body = br#"{"jsonrpc":"2.0","id":1,"method":"reports.list"}"#;
        let request = format!(
            "POST /rpc HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            std::str::from_utf8(body).unwrap()
        );
        app.write_all(request.as_bytes()).await.unwrap();

        let mut response = [0u8; 512];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), app.read(&mut response))
            .await
            .expect("denial should reach client")
            .unwrap();
        let response = String::from_utf8_lossy(&response[..n]);
        assert!(response.contains("403 Forbidden"));
        assert!(response.contains("middleware_failed"));

        let mut upstream_request = [0u8; 32];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            upstream.read(&mut upstream_request),
        )
        .await;
        assert!(
            matches!(result, Err(_) | Ok(Ok(0))),
            "upstream should not receive request bytes"
        );

        drop(app);
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should finish")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn l7_rest_middleware_over_capacity_fails_closed() {
        let (config, tunnel_engine, ctx) =
            middleware_relay_context("openshell/regex", "fail_closed");
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        // A declared body far above the 256 KiB inspection cap must be denied
        // (fail-closed) before the body is read or reaches the upstream.
        let request = format!(
            "POST /v1/messages HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            300 * 1024
        );
        app.write_all(request.as_bytes()).await.unwrap();

        let mut response = [0u8; 512];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), app.read(&mut response))
            .await
            .expect("denial should reach client")
            .unwrap();
        let response = String::from_utf8_lossy(&response[..n]);
        assert_middleware_failure_response(&response, "rest_api");

        let mut upstream_request = [0u8; 32];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            upstream.read(&mut upstream_request),
        )
        .await;
        assert!(
            matches!(result, Err(_) | Ok(Ok(0))),
            "upstream should not receive request bytes"
        );

        drop(app);
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should finish")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn over_capacity_resolution_honors_on_error() {
        use openshell_supervisor_middleware::{ChainEntry, OnError};

        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 443,
            policy_name: "p".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            ..Default::default()
        };
        let req = || crate::l7::provider::L7Request {
            action: "POST".into(),
            target: "/v1".into(),
            query_params: std::collections::HashMap::new(),
            raw_header: Vec::new(),
            body_length: crate::l7::provider::BodyLength::None,
        };
        let fail_open = ChainEntry {
            name: "m".into(),
            implementation: "openshell/regex".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailOpen,
        };
        let fail_closed = ChainEntry {
            on_error: OnError::FailClosed,
            ..fail_open.clone()
        };

        let runner = openshell_supervisor_middleware::ChainRunner::default();
        let open_chain = runner
            .describe_chain(std::slice::from_ref(&fail_open))
            .await
            .expect("describe fail-open chain");
        let mixed_chain = runner
            .describe_chain(&[fail_open.clone(), fail_closed])
            .await
            .expect("describe mixed chain");

        // Recoverable (Content-Length over cap, nothing consumed) + all fail-open
        // -> stream through unprocessed.
        assert!(matches!(
            resolve_unbuffered_body(&ctx, req(), &open_chain, true),
            MiddlewareApplyResult::Allowed(_)
        ));
        // Any fail-closed entry -> deny.
        assert!(matches!(
            resolve_unbuffered_body(&ctx, req(), &mixed_chain, true),
            MiddlewareApplyResult::Denied { .. }
        ));
        // Not recoverable (chunked overflow already consumed bytes) -> deny even
        // when every entry is fail-open.
        assert!(matches!(
            resolve_unbuffered_body(&ctx, req(), &open_chain, false),
            MiddlewareApplyResult::Denied { .. }
        ));
    }

    #[tokio::test]
    async fn body_limit_ignores_unresolved_entries() {
        use openshell_supervisor_middleware::{ChainEntry, ChainRunner, OnError};

        let resolved = ChainEntry {
            name: "redact".into(),
            implementation: openshell_supervisor_middleware_builtins::BUILTIN_REGEX.into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        };
        let unresolved = ChainEntry {
            name: "missing".into(),
            implementation: "third-party/missing".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailOpen,
        };

        // A single unresolved (0-limit) entry must not drag the chain limit to
        // zero: the buffer limit reflects only the resolved built-in.
        let mixed = ChainRunner::new(
            openshell_supervisor_middleware_builtins::services()
                .into_iter()
                .next()
                .expect("built-in middleware service"),
        )
        .describe_chain(&[resolved, unresolved.clone()])
        .await
        .expect("describe mixed chain");
        assert_eq!(middleware_chain_body_limit(&mixed), Some(256 * 1024));

        // When nothing resolves, there is no body limit and the caller skips
        // buffering entirely.
        let none = ChainRunner::default()
            .describe_chain(std::slice::from_ref(&unresolved))
            .await
            .expect("describe unresolved chain");
        assert_eq!(middleware_chain_body_limit(&none), None);
    }

    /// A middleware service whose single binding replaces every request body
    /// with a fixed payload, for exercising post-transformation policy
    /// re-evaluation.
    struct BodyReplacingService {
        replacement: &'static [u8],
    }

    #[tonic::async_trait]
    impl openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddleware
        for BodyReplacingService
    {
        async fn describe(
            &self,
            _request: tonic::Request<()>,
        ) -> std::result::Result<
            tonic::Response<openshell_core::proto::MiddlewareManifest>,
            tonic::Status,
        > {
            Ok(tonic::Response::new(
                openshell_core::proto::MiddlewareManifest {
                    name: "test/rewriter".into(),
                    service_version: "test".into(),
                    bindings: vec![openshell_core::proto::MiddlewareBinding {
                        operation: openshell_core::proto::SupervisorMiddlewareOperation::HttpRequest
                            as i32,
                        phase: openshell_core::proto::SupervisorMiddlewarePhase::PreCredentials
                            as i32,
                        max_body_bytes: 8192,
                        timeout: String::new(),
                    }],
                },
            ))
        }

        async fn validate_config(
            &self,
            _request: tonic::Request<openshell_core::proto::ValidateConfigRequest>,
        ) -> std::result::Result<
            tonic::Response<openshell_core::proto::ValidateConfigResponse>,
            tonic::Status,
        > {
            Ok(tonic::Response::new(
                openshell_core::proto::ValidateConfigResponse {
                    valid: true,
                    reason: String::new(),
                },
            ))
        }

        async fn evaluate_http_request(
            &self,
            _request: tonic::Request<openshell_core::proto::HttpRequestEvaluation>,
        ) -> std::result::Result<
            tonic::Response<openshell_core::proto::HttpRequestResult>,
            tonic::Status,
        > {
            Ok(tonic::Response::new(
                openshell_core::proto::HttpRequestResult {
                    decision: openshell_core::proto::Decision::Allow as i32,
                    body: self.replacement.to_vec(),
                    has_body: true,
                    ..Default::default()
                },
            ))
        }
    }

    fn jsonrpc_transforming_relay_parts(
        enforcement: &str,
        replacement: &'static [u8],
    ) -> (L7EndpointConfig, TunnelPolicyEngine, L7EvalContext) {
        let data = format!(
            r#"
network_middlewares:
  rewriter:
    middleware: test/rewriter
    on_error: fail_closed
    endpoints:
      include: ["api.example.test"]
network_policies:
  jsonrpc_api:
    name: jsonrpc_api
    endpoints:
      - host: api.example.test
        port: 443
        protocol: json-rpc
        enforcement: {enforcement}
        rules:
          - allow:
              method: reports.list
    binaries:
      - {{ path: /usr/bin/node }}
"#
        );
        let engine = OpaEngine::from_strings(TEST_POLICY, &data).unwrap();
        engine.set_middleware_runner_for_tests(openshell_supervisor_middleware::ChainRunner::new(
            Arc::new(BodyReplacingService { replacement }),
        ));
        let input = NetworkInput {
            host: "api.example.test".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/node"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let (endpoint_config, generation) = engine
            .query_endpoint_config_with_generation(&input)
            .expect("endpoint config");
        let config = crate::l7::parse_l7_config(&endpoint_config.expect("json-rpc config"))
            .expect("parse JSON-RPC config");
        let tunnel_engine = engine.clone_engine_for_tunnel(generation).unwrap();
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 443,
            policy_name: "jsonrpc_api".into(),
            binary_path: "/usr/bin/node".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            ..Default::default()
        };
        (config, tunnel_engine, ctx)
    }

    async fn run_jsonrpc_transform_case(
        enforcement: &str,
        replacement: &'static [u8],
    ) -> (String, Option<String>) {
        let (config, tunnel_engine, ctx) =
            jsonrpc_transforming_relay_parts(enforcement, replacement);
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_jsonrpc(
                &config,
                &tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        let body = br#"{"jsonrpc":"2.0","id":1,"method":"reports.list"}"#;
        let request = format!(
            "POST /rpc HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            std::str::from_utf8(body).unwrap()
        );
        app.write_all(request.as_bytes()).await.unwrap();

        // Give the relay a moment to either deny (client sees a response) or
        // forward (upstream sees the request).
        let mut upstream_request = [0u8; 1024];
        let upstream_read = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            upstream.read(&mut upstream_request),
        )
        .await;
        let upstream_seen = match upstream_read {
            Ok(Ok(n)) if n > 0 => {
                let seen = String::from_utf8_lossy(&upstream_request[..n]).to_string();
                upstream
                    .write_all(
                        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
                Some(seen)
            }
            _ => None,
        };

        let mut response = [0u8; 1024];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), app.read(&mut response))
            .await
            .expect("client should receive a response")
            .unwrap();
        let response = String::from_utf8_lossy(&response[..n]).to_string();

        drop(app);
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should finish")
            .unwrap()
            .unwrap();
        (response, upstream_seen)
    }

    #[tokio::test]
    async fn transformed_jsonrpc_body_is_reevaluated_and_denied() {
        // Policy allows reports.list; the middleware replaces the body with a
        // method the policy denies. The transformed body must be re-evaluated
        // and the request denied before anything reaches the upstream.
        let (response, upstream_seen) = run_jsonrpc_transform_case(
            "enforce",
            br#"{"jsonrpc":"2.0","id":1,"method":"admin.delete"}"#,
        )
        .await;
        assert_middleware_failure_response(&response, "jsonrpc_api");
        assert!(upstream_seen.is_none(), "upstream must not see the request");
    }

    #[tokio::test]
    async fn transformed_jsonrpc_body_policy_deny_forwards_under_audit() {
        // Under enforcement: audit a policy deny of the transformed body is
        // logged but forwarded, mirroring audit semantics for original
        // bodies.
        let (response, upstream_seen) = run_jsonrpc_transform_case(
            "audit",
            br#"{"jsonrpc":"2.0","id":1,"method":"admin.delete"}"#,
        )
        .await;
        assert!(response.contains("204 No Content"), "{response}");
        let upstream_seen = upstream_seen.expect("audited request reaches upstream");
        assert!(upstream_seen.contains("admin.delete"), "{upstream_seen}");
    }

    #[tokio::test]
    async fn unparseable_transformation_denies_even_under_audit() {
        // An unparseable replacement mirrors force_deny for original parse
        // errors: denied even on an audit endpoint.
        let (response, upstream_seen) = run_jsonrpc_transform_case("audit", b"not json").await;
        assert_middleware_failure_response(&response, "jsonrpc_api");
        assert!(upstream_seen.is_none(), "upstream must not see the request");
    }

    #[tokio::test]
    async fn transformed_graphql_body_is_reevaluated_and_denied() {
        // GraphQL counterpart: policy allows query { viewer }; the middleware
        // rewrites the body into a denied mutation.
        let data = r#"
network_middlewares:
  rewriter:
    middleware: test/rewriter
    on_error: fail_closed
    endpoints:
      include: ["api.example.test"]
network_policies:
  graphql_api:
    name: graphql_api
    endpoints:
      - host: api.example.test
        port: 443
        protocol: graphql
        enforcement: enforce
        rules:
          - allow:
              operation_type: query
              fields: [viewer]
    binaries:
      - { path: /usr/bin/node }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        engine.set_middleware_runner_for_tests(openshell_supervisor_middleware::ChainRunner::new(
            Arc::new(BodyReplacingService {
                replacement: br#"{"query":"mutation { deleteRepository }"}"#,
            }),
        ));
        let input = NetworkInput {
            host: "api.example.test".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/node"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let (endpoint_config, generation) = engine
            .query_endpoint_config_with_generation(&input)
            .expect("endpoint config");
        let config = crate::l7::parse_l7_config(&endpoint_config.expect("graphql config"))
            .expect("parse GraphQL config");
        let tunnel_engine = engine.clone_engine_for_tunnel(generation).unwrap();
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 443,
            policy_name: "graphql_api".into(),
            binary_path: "/usr/bin/node".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            ..Default::default()
        };
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_graphql(
                &config,
                &tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        let body = br#"{"query":"query { viewer }"}"#;
        let request = format!(
            "POST /graphql HTTP/1.1\r\nHost: api.example.test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            std::str::from_utf8(body).unwrap()
        );
        app.write_all(request.as_bytes()).await.unwrap();

        let mut response = [0u8; 1024];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), app.read(&mut response))
            .await
            .expect("denial should reach client")
            .unwrap();
        let response = String::from_utf8_lossy(&response[..n]);
        assert_middleware_failure_response(&response, "graphql_api");

        let mut upstream_request = [0u8; 32];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            upstream.read(&mut upstream_request),
        )
        .await;
        assert!(
            matches!(result, Err(_) | Ok(Ok(0))),
            "upstream should not receive request bytes"
        );

        drop(app);
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should finish")
            .unwrap()
            .unwrap();
    }

    fn sql_middleware_relay_context(
        on_error: &str,
    ) -> (L7EndpointConfig, TunnelPolicyEngine, L7EvalContext) {
        let data = format!(
            r#"
network_middlewares:
  guard:
    middleware: example/unavailable
    on_error: {on_error}
    endpoints:
      include: ["db.example.test"]
network_policies:
  sql_db:
    name: sql_db
    endpoints:
      - host: db.example.test
        port: 5432
        protocol: sql
        enforcement: audit
        rules:
          - allow:
              command: SELECT
    binaries:
      - {{ path: /usr/bin/psql }}
"#
        );
        let engine = OpaEngine::from_strings(TEST_POLICY, &data).unwrap();
        let input = NetworkInput {
            host: "db.example.test".into(),
            port: 5432,
            binary_path: PathBuf::from("/usr/bin/psql"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let (endpoint_config, generation) = engine
            .query_endpoint_config_with_generation(&input)
            .expect("endpoint config");
        let config = crate::l7::parse_l7_config(&endpoint_config.expect("sql config"))
            .expect("parse SQL config");
        let tunnel_engine = engine.clone_engine_for_tunnel(generation).unwrap();
        let ctx = L7EvalContext {
            host: "db.example.test".into(),
            port: 5432,
            policy_name: "sql_db".into(),
            binary_path: "/usr/bin/psql".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            ..Default::default()
        };
        (config, tunnel_engine, ctx)
    }

    #[tokio::test]
    async fn sql_passthrough_denies_with_fail_closed_middleware() {
        // The SQL relay is unimplemented, so a fail-closed chain can never
        // inspect the stream: the connection must be closed instead of
        // silently bypassing the middleware.
        let (config, tunnel_engine, ctx) = sql_middleware_relay_context("fail_closed");
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        app.write_all(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
            .await
            .ok();

        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should close the connection")
            .unwrap()
            .unwrap();

        let mut upstream_bytes = [0u8; 16];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            upstream.read(&mut upstream_bytes),
        )
        .await;
        assert!(
            matches!(result, Err(_) | Ok(Ok(0))),
            "upstream should not receive SQL bytes"
        );
    }

    #[tokio::test]
    async fn sql_passthrough_relays_with_fail_open_middleware() {
        // An all-fail-open chain accepts the bypass (with a detection
        // finding) and the raw stream flows.
        let (config, tunnel_engine, ctx) = sql_middleware_relay_context("fail_open");
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let _relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        app.write_all(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
            .await
            .unwrap();

        let mut upstream_bytes = [0u8; 16];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut upstream_bytes),
        )
        .await
        .expect("fail-open chain must relay SQL bytes")
        .unwrap();
        assert_eq!(&upstream_bytes[..n], b"\x00\x00\x00\x08\x04\xd2\x16\x2f");
    }

    #[test]
    fn uninspectable_gate_reflects_chain_on_error() {
        use openshell_supervisor_middleware::{ChainEntry, OnError};

        let entry = |on_error| ChainEntry {
            name: "m".into(),
            implementation: "example/guard".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error,
        };

        assert_eq!(
            uninspectable_traffic_gate(&[]),
            UninspectableTrafficGate::Unrestricted
        );
        assert_eq!(
            uninspectable_traffic_gate(&[entry(OnError::FailOpen), entry(OnError::FailOpen)]),
            UninspectableTrafficGate::BypassWithFinding
        );
        assert_eq!(
            uninspectable_traffic_gate(&[entry(OnError::FailOpen), entry(OnError::FailClosed)]),
            UninspectableTrafficGate::Deny
        );
    }

    /// One named middleware with one HTTP/pre-credentials binding. Two
    /// instances exercise mixed-limit chain buffering at the relay level.
    struct LimitService {
        name: &'static str,
        max_body_bytes: u64,
        replacement: Option<&'static [u8]>,
    }

    #[tonic::async_trait]
    impl openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddleware
        for LimitService
    {
        async fn describe(
            &self,
            _request: tonic::Request<()>,
        ) -> std::result::Result<
            tonic::Response<openshell_core::proto::MiddlewareManifest>,
            tonic::Status,
        > {
            use openshell_core::proto::{
                MiddlewareBinding, MiddlewareManifest, SupervisorMiddlewareOperation,
                SupervisorMiddlewarePhase,
            };
            Ok(tonic::Response::new(MiddlewareManifest {
                name: self.name.into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_body_bytes: self.max_body_bytes,
                    timeout: String::new(),
                }],
            }))
        }

        async fn validate_config(
            &self,
            _request: tonic::Request<openshell_core::proto::ValidateConfigRequest>,
        ) -> std::result::Result<
            tonic::Response<openshell_core::proto::ValidateConfigResponse>,
            tonic::Status,
        > {
            Ok(tonic::Response::new(
                openshell_core::proto::ValidateConfigResponse {
                    valid: true,
                    reason: String::new(),
                },
            ))
        }

        async fn evaluate_http_request(
            &self,
            request: tonic::Request<openshell_core::proto::HttpRequestEvaluation>,
        ) -> std::result::Result<
            tonic::Response<openshell_core::proto::HttpRequestResult>,
            tonic::Status,
        > {
            let _evaluation = request.into_inner();
            let mut result = openshell_core::proto::HttpRequestResult {
                decision: openshell_core::proto::Decision::Allow as i32,
                ..Default::default()
            };
            if let Some(replacement) = self.replacement {
                result.body = replacement.to_vec();
                result.has_body = true;
            }
            Ok(tonic::Response::new(result))
        }
    }

    #[tokio::test]
    async fn body_over_smallest_stage_limit_is_buffered_and_evaluated() {
        use openshell_supervisor_middleware::{ChainEntry, ChainRunner, OnError};

        // A 64-byte body exceeds the 16-byte guard limit but fits the 8 KiB
        // redactor. The chain must buffer for its largest stage so the
        // redactor runs and replaces the body, while the undersized fail-open
        // guard is skipped through its own on_error, instead of the whole
        // chain taking the unbuffered over-capacity path.
        let (_config, tunnel_engine, ctx) =
            middleware_relay_context("openshell/regex", "fail_closed");
        let registry = openshell_supervisor_middleware::MiddlewareRegistry::connect_services(
            vec![
                Arc::new(LimitService {
                    name: "test/redactor",
                    max_body_bytes: 8192,
                    replacement: Some(b"[SCRUBBED BY TEST REDACTOR]"),
                }),
                Arc::new(LimitService {
                    name: "test/guard",
                    max_body_bytes: 16,
                    replacement: None,
                }),
            ],
            Vec::new(),
        )
        .await
        .expect("connect named middleware services");
        let runner = ChainRunner::from_registry(registry);
        let chain = vec![
            ChainEntry {
                name: "redact".into(),
                implementation: "test/redactor".into(),
                order: 0,
                config: prost_types::Struct::default(),
                on_error: OnError::FailClosed,
            },
            ChainEntry {
                name: "guard".into(),
                implementation: "test/guard".into(),
                order: 10,
                config: prost_types::Struct::default(),
                on_error: OnError::FailOpen,
            },
        ];
        let described = runner.describe_chain(&chain).await.expect("describe chain");
        assert_eq!(middleware_chain_body_limit(&described), Some(8192));

        let body = [b'a'; 64];
        let raw_header = format!(
            "POST /v1/messages HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let req = crate::l7::provider::L7Request {
            action: "POST".into(),
            target: "/v1/messages".into(),
            query_params: std::collections::HashMap::new(),
            raw_header: raw_header.into_bytes(),
            body_length: crate::l7::provider::BodyLength::ContentLength(body.len() as u64),
        };
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        app.write_all(&body).await.unwrap();

        let result = crate::l7::middleware::apply_middleware_chain_for_scheme(
            req,
            &mut relay_client,
            &ctx,
            "https",
            chain,
            &runner,
            tunnel_engine.generation_guard(),
            openshell_supervisor_middleware::TransformedBodyPolicy::NotPolicyRelevant,
        )
        .await
        .expect("apply middleware chain");

        match result {
            MiddlewareApplyResult::Allowed(rebuilt) => {
                let raw = String::from_utf8(rebuilt.raw_header).expect("utf8 request");
                assert!(
                    raw.ends_with("[SCRUBBED BY TEST REDACTOR]"),
                    "redactor must replace the body: {raw}"
                );
            }
            MiddlewareApplyResult::Denied { .. } => {
                panic!("body within the largest stage limit must not fail the chain")
            }
        }
    }

    #[tokio::test]
    async fn all_unresolved_fail_open_forwards_body_unbuffered() {
        // A chain whose only entry is an unregistered binding has no resolvable
        // body limit. Under fail_open the request must pass through with its
        // body intact rather than being denied over a phantom zero-byte cap.
        let (config, tunnel_engine, ctx) =
            middleware_relay_context("third-party/missing", "fail_open");
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        let body = br#"{"api_key":"sk-1234567890abcdef"}"#;
        let request = format!(
            "POST /v1/messages HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            std::str::from_utf8(body).unwrap()
        );
        app.write_all(request.as_bytes()).await.unwrap();

        let mut upstream_request = [0u8; 1024];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut upstream_request),
        )
        .await
        .expect("request should reach upstream")
        .unwrap();
        let upstream_request = String::from_utf8_lossy(&upstream_request[..n]);
        // No middleware ran, so the body is forwarded verbatim.
        assert!(upstream_request.contains(r#""api_key":"sk-1234567890abcdef""#));

        upstream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut client_response = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.read(&mut client_response),
        )
        .await
        .expect("response should reach client")
        .unwrap();
        assert!(String::from_utf8_lossy(&client_response[..n]).contains("204 No Content"));
        drop(app);
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should finish")
            .unwrap()
            .unwrap();
    }

    #[test]
    fn middleware_keeps_the_raw_request_query() {
        let query = raw_query_from_request_headers(
            b"POST /v1/messages?token=a%2Bb&scope=private HTTP/1.1\r\nHost: api.example.test\r\n\r\n",
        )
        .expect("query from request headers");

        assert_eq!(query, "token=a%2Bb&scope=private");
    }

    #[test]
    fn middleware_request_input_preserves_plain_http_scheme() {
        let req = crate::l7::provider::L7Request {
            action: "POST".into(),
            target: "/v1/messages".into(),
            query_params: std::collections::HashMap::new(),
            raw_header: Vec::new(),
            body_length: crate::l7::provider::BodyLength::None,
        };
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 80,
            policy_name: "api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
            secret_resolver: None,
            ..Default::default()
        };

        let input = middleware_request_input(
            "http",
            &req,
            &ctx,
            Vec::new(),
            Vec::new(),
            String::new(),
            Vec::new(),
        );

        assert_eq!(input.scheme, "http");
    }

    #[test]
    fn middleware_ocsf_events_are_audit_safe() {
        use openshell_supervisor_middleware::{
            ChainOutcome, MiddlewareInvocation, NamespacedFinding,
        };

        const RAW_SECRET: &str = "sk-RAWSECRETVALUE0123456789";

        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 443,
            policy_name: "rest_api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            ..Default::default()
        };
        let req = crate::l7::provider::L7Request {
            action: "POST".into(),
            target: "/v1/messages".into(),
            query_params: std::collections::HashMap::new(),
            raw_header: Vec::new(),
            body_length: crate::l7::provider::BodyLength::None,
        };
        let outcome = ChainOutcome {
            allowed: true,
            reason: String::new(),
            // The transformed body still holds the raw secret; emission must never
            // serialize it.
            body: format!(r#"{{"api_key":"{RAW_SECRET}"}}"#).into_bytes(),
            header_mutations: Vec::new(),
            findings: vec![NamespacedFinding {
                middleware: "regex-redactor".into(),
                finding: openshell_core::proto::Finding {
                    r#type: "regex.keyword".into(),
                    label: "keyword regex match".into(),
                    count: 1,
                    confidence: "medium".into(),
                    severity: "medium".into(),
                },
            }],
            metadata: BTreeMap::new(),
            applied: vec![MiddlewareInvocation {
                name: "regex-redactor".into(),
                implementation: "openshell/regex".into(),
                decision: openshell_core::proto::Decision::Allow,
                transformed: true,
                failed: false,
            }],
            denial: None,
        };

        // Build the events directly rather than routing through the global
        // tracing pipeline: its callsite-interest cache is process-global, so a
        // parallel test that emits OCSF with no subscriber installed can cache
        // the callsite as disabled and make captured-event assertions flaky.
        let events = middleware_events(&ctx, &req, &outcome);

        // Per-invocation decisions are HTTP Activity (class 4002).
        assert!(
            events.iter().any(|e| e.class_uid() == 4002),
            "expected an HTTP Activity event for the middleware invocation"
        );
        // Findings are Detection Finding (class 2004) with the finding's severity.
        let finding_event = events
            .iter()
            .find(|e| e.class_uid() == 2004)
            .expect("expected a Detection Finding event");
        assert_eq!(finding_event.base().severity, SeverityId::Medium);

        // No raw payload material may appear in any emitted event.
        let serialized = serde_json::to_string(&events).expect("serialize events");
        assert!(
            !serialized.contains(RAW_SECRET),
            "raw secret leaked into OCSF events: {serialized}"
        );
        // Safe finding metadata is still present.
        assert!(serialized.contains("regex.keyword"));

        let mut bounded_outcome = outcome;
        bounded_outcome.findings = (0
            ..openshell_supervisor_middleware::MAX_MIDDLEWARE_CHAIN_STAGES)
            .flat_map(|stage| {
                (0..openshell_supervisor_middleware::MAX_MIDDLEWARE_FINDINGS_PER_STAGE).map(
                    move |_| NamespacedFinding {
                        middleware: format!("external-guard-{stage}"),
                        finding: openshell_core::proto::Finding {
                            r#type: "example/content-guard.finding".into(),
                            label: "External middleware finding".into(),
                            count: 1,
                            confidence: String::new(),
                            severity: "medium".into(),
                        },
                    },
                )
            })
            .chain(std::iter::once(NamespacedFinding {
                middleware: "over-capacity".into(),
                finding: openshell_core::proto::Finding {
                    r#type: "example/content-guard.finding".into(),
                    label: "External middleware finding".into(),
                    count: 1,
                    confidence: String::new(),
                    severity: "medium".into(),
                },
            }))
            .collect();
        let bounded_events = middleware_events(&ctx, &req, &bounded_outcome);
        assert_eq!(
            bounded_events
                .iter()
                .filter(|event| event.class_uid() == 2004)
                .count(),
            openshell_supervisor_middleware::MAX_MIDDLEWARE_CHAIN_FINDINGS,
            "finding emission must remain bounded even if an invalid outcome bypasses the runner"
        );

        let denied_outcome = ChainOutcome {
            allowed: false,
            reason: "middleware_denied:content-guard:content_match".into(),
            body: Vec::new(),
            header_mutations: Vec::new(),
            findings: Vec::new(),
            metadata: BTreeMap::new(),
            applied: vec![MiddlewareInvocation {
                name: "content-guard".into(),
                implementation: "example/content-guard".into(),
                decision: openshell_core::proto::Decision::Deny,
                transformed: false,
                failed: false,
            }],
            denial: Some(openshell_supervisor_middleware::MiddlewareDenial {
                config_name: "content-guard".into(),
                reason_code: Some("content_match".into()),
            }),
        };
        let denied_events = middleware_events(&ctx, &req, &denied_outcome);
        let denied_http = denied_events
            .iter()
            .find(|event| event.class_uid() == 4002)
            .expect("expected denied HTTP Activity event");
        assert_eq!(
            denied_http.base().status_detail.as_deref(),
            Some("middleware_denied:content-guard:content_match")
        );
        let denied_json = denied_http.to_json().expect("serialize denied event");
        assert_eq!(denied_json["unmapped"]["transformed"], false);
        assert_eq!(denied_json["unmapped"]["failed"], false);
        assert_eq!(
            denied_http.format_shorthand(),
            "HTTP:POST [MED] DENIED POST http://api.example.test:443/v1/messages \
             [policy:rest_api engine:middleware] \
             [failed:false transformed:false \
             reason:middleware_denied:content-guard:content_match]"
        );

        let external_failure_outcome = ChainOutcome {
            reason: "middleware_failed: header_mutation_invalid_name".into(),
            denial: None,
            applied: vec![MiddlewareInvocation {
                failed: true,
                ..denied_outcome.applied[0].clone()
            }],
            ..denied_outcome
        };
        let failure_events = middleware_events(&ctx, &req, &external_failure_outcome);
        let serialized = serde_json::to_string(&failure_events).expect("serialize failure events");
        assert!(serialized.contains("header_mutation_invalid_name"));
        assert!(!serialized.contains(RAW_SECRET));
    }

    #[tokio::test]
    async fn passthrough_relay_runs_middleware_redaction() {
        // A no-protocol endpoint takes the credential-injection passthrough path;
        // host-selected middleware must still inspect and redact its body.
        let data = r#"
network_middlewares:
  request-middleware:
    middleware: openshell/regex
    on_error: fail_closed
    endpoints:
      include: ["api.example.test"]
network_policies:
  passthrough_api:
    name: passthrough_api
    endpoints:
      - host: api.example.test
        port: 8080
    binaries:
      - { path: /usr/bin/curl }
"#;
        let engine = Arc::new(OpaEngine::from_strings(TEST_POLICY, data).unwrap());
        install_builtin_middleware(engine.as_ref());
        let generation_guard = engine
            .generation_guard(engine.current_generation())
            .unwrap();
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 8080,
            policy_name: "passthrough_api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            ..Default::default()
        };

        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let engine_task = Arc::clone(&engine);
        let relay = tokio::spawn(async move {
            relay_passthrough_with_credentials(
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
                &generation_guard,
                Some(engine_task.as_ref()),
            )
            .await
        });

        let body = br#"{"api_key":"sk-1234567890abcdef"}"#;
        let request = format!(
            "POST /v1/messages HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            std::str::from_utf8(body).unwrap()
        );
        app.write_all(request.as_bytes()).await.unwrap();

        let mut upstream_request = [0u8; 1024];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut upstream_request),
        )
        .await
        .expect("request should reach upstream")
        .unwrap();
        let upstream_request = String::from_utf8_lossy(&upstream_request[..n]);
        assert!(
            upstream_request.contains(r#""api_key":"[REDACTED]""#),
            "unexpected upstream request: {upstream_request:?}"
        );
        assert!(!upstream_request.contains("sk-1234567890abcdef"));

        upstream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut client_response = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.read(&mut client_response),
        )
        .await
        .expect("response should reach client")
        .unwrap();
        assert!(String::from_utf8_lossy(&client_response[..n]).contains("204 No Content"));
        drop(app);
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should finish")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn websocket_upgrade_request_is_inspected_and_denied() {
        // The WebSocket upgrade handshake is an HTTP request the hook can inspect
        // and deny: a fail-closed middleware blocks the upgrade before it is
        // forwarded.
        let data = r#"
network_middlewares:
  request-middleware:
    middleware: example/unavailable
    on_error: fail_closed
    endpoints:
      include: ["gateway.example.test"]
network_policies:
  ws_api:
    name: ws_api
    endpoints:
      - host: gateway.example.test
        port: 443
        protocol: websocket
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/ws"
    binaries:
      - { path: /usr/bin/node }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "gateway.example.test".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/node"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let (endpoint_config, generation) = engine
            .query_endpoint_config_with_generation(&input)
            .unwrap();
        let config = crate::l7::parse_l7_config(&endpoint_config.unwrap()).unwrap();
        let tunnel_engine = engine.clone_engine_for_tunnel(generation).unwrap();
        let ctx = L7EvalContext {
            host: "gateway.example.test".into(),
            port: 443,
            policy_name: "ws_api".into(),
            binary_path: "/usr/bin/node".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            ..Default::default()
        };

        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        app.write_all(
            b"GET /ws HTTP/1.1\r\nHost: gateway.example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .await
        .unwrap();

        // Accumulate until the reason marker arrives: the deny response can be
        // delivered in more than one write, so a single read may return only the
        // status line and flake the body assertion.
        let mut response = Vec::new();
        let mut buf = [0u8; 512];
        while !String::from_utf8_lossy(&response).contains("middleware_failed") {
            match tokio::time::timeout(std::time::Duration::from_secs(1), app.read(&mut buf)).await
            {
                Ok(Ok(0)) | Err(_) => break, // clean EOF, or no more data before the deadline
                Ok(Ok(n)) => response.extend_from_slice(&buf[..n]),
                Ok(Err(e)) => panic!("read from relay failed: {e}"),
            }
        }
        let response = String::from_utf8_lossy(&response);
        assert!(response.contains("403 Forbidden"));
        assert!(response.contains("middleware_failed"));

        let mut upstream_request = [0u8; 32];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            upstream.read(&mut upstream_request),
        )
        .await;
        assert!(
            matches!(result, Err(_) | Ok(Ok(0))),
            "upstream should not receive the upgrade request"
        );

        drop(app);
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should finish")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn passthrough_relay_injects_token_grant_authorization_header() {
        let (generation_guard, ctx, fixture) =
            passthrough_token_grant_relay_context(Ok("grant-token"));
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_passthrough_with_credentials(
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
                &generation_guard,
                None,
            )
            .await
        });

        app.write_all(
            b"GET /v1/projects HTTP/1.1\r\nHost: api.example.test\r\nAuthorization: Bearer stale-token\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();

        let mut upstream_request = [0u8; 1024];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut upstream_request),
        )
        .await
        .expect("request should reach upstream")
        .unwrap();
        let upstream_request = String::from_utf8_lossy(&upstream_request[..n]);

        assert!(upstream_request.starts_with("GET /v1/projects HTTP/1.1\r\n"));
        assert!(upstream_request.contains("Authorization: Bearer grant-token\r\n"));
        assert!(!upstream_request.contains("stale-token"));
        assert_eq!(authorization_header_count(&upstream_request), 1);

        upstream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();

        let mut client_response = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.read(&mut client_response),
        )
        .await
        .expect("response should reach client")
        .unwrap();
        assert!(String::from_utf8_lossy(&client_response[..n]).contains("204 No Content"));
        drop(app);

        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should finish")
            .unwrap()
            .unwrap();

        fixture.assert_one_request("api.example.test\t8080\t/v1/**\tprovider:access_token");
    }

    #[tokio::test]
    async fn passthrough_relay_token_grant_failure_returns_bad_gateway_without_forwarding() {
        let (generation_guard, ctx, fixture) =
            passthrough_token_grant_relay_context(Err("oauth unavailable"));
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_passthrough_with_credentials(
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
                &generation_guard,
                None,
            )
            .await
        });

        app.write_all(
            b"GET /v1/projects HTTP/1.1\r\nHost: api.example.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should finish")
            .unwrap()
            .unwrap();

        let mut client_response = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.read(&mut client_response),
        )
        .await
        .expect("bad gateway response should reach client")
        .unwrap();
        assert!(String::from_utf8_lossy(&client_response[..n]).contains("502 Bad Gateway"));

        let mut upstream_request = [0u8; 128];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut upstream_request),
        )
        .await
        .expect("upstream should close without forwarded data")
        .unwrap();
        assert_eq!(n, 0, "unauthenticated request must not reach upstream");

        fixture.assert_one_request("api.example.test\t8080\t/v1/**\tprovider:access_token");
    }

    #[test]
    fn websocket_text_policy_requires_explicit_message_rule() {
        let data = r#"
network_policies:
  ws_api:
    name: ws_api
    endpoints:
      - host: gateway.example.test
        port: 443
        protocol: websocket
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/ws"
    binaries:
      - { path: /usr/bin/node }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "gateway.example.test".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/node"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let generation = engine
            .evaluate_network_action_with_generation(&input)
            .unwrap()
            .1;
        let tunnel_engine = engine.clone_engine_for_tunnel(generation).unwrap();
        let ctx = L7EvalContext {
            host: "gateway.example.test".into(),
            port: 443,
            policy_name: "ws_api".into(),
            binary_path: "/usr/bin/node".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            ..Default::default()
        };
        let request = L7RequestInfo {
            action: "WEBSOCKET_TEXT".into(),
            target: "/ws".into(),
            query_params: std::collections::HashMap::new(),
            graphql: None,
            jsonrpc: None,
        };

        let (allowed, reason) = evaluate_l7_request(&tunnel_engine, &ctx, &request).unwrap();

        assert!(!allowed);
        assert!(reason.contains("WEBSOCKET_TEXT /ws not permitted"));
    }

    #[test]
    fn jsonrpc_inspection_error_opa_projection_remains_string_or_null() {
        let invalid_json = crate::l7::jsonrpc::parse_jsonrpc_body(
            b"{",
            crate::l7::jsonrpc::JsonRpcInspectionMode::JsonRpc,
        );
        let invalid_message = crate::l7::jsonrpc::parse_jsonrpc_body(
            br#"{"id":1,"method":"reports.list"}"#,
            crate::l7::jsonrpc::JsonRpcInspectionMode::JsonRpc,
        );
        let accepted = crate::l7::jsonrpc::parse_jsonrpc_body(
            br#"{"jsonrpc":"2.0","id":1,"method":"reports.list"}"#,
            crate::l7::jsonrpc::JsonRpcInspectionMode::JsonRpc,
        );

        assert_eq!(
            jsonrpc_policy_input(&invalid_json)["error"],
            serde_json::json!("invalid JSON")
        );
        assert_eq!(
            jsonrpc_policy_input(&invalid_message)["error"],
            serde_json::json!("missing or non-string 'jsonrpc' field")
        );
        assert!(jsonrpc_policy_input(&accepted)["error"].is_null());
    }

    #[test]
    fn jsonrpc_batch_evaluates_each_call() {
        let data = r#"
network_policies:
  jsonrpc_api:
    name: jsonrpc_api
    endpoints:
      - host: api.example.test
        port: 443
        protocol: json-rpc
        enforcement: enforce
        rules:
          - allow:
              method: "reports.list"
          - allow:
              method: "reports.search"
        deny_rules:
          - method: "reports.delete"
    binaries:
      - { path: /usr/bin/node }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let tunnel_engine = engine
            .clone_engine_for_tunnel(engine.current_generation())
            .unwrap();
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 443,
            policy_name: "jsonrpc_api".into(),
            binary_path: "/usr/bin/node".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            ..Default::default()
        };
        let mut request = L7RequestInfo {
            action: "POST".into(),
            target: "/rpc".into(),
            query_params: std::collections::HashMap::new(),
            graphql: None,
            jsonrpc: Some(crate::l7::jsonrpc::parse_jsonrpc_body(
                br#"[
                    {"jsonrpc":"2.0","id":1,"method":"reports.list"},
                    {"jsonrpc":"2.0","id":2,"method":"reports.search","params":{"query":"private_query_value"}}
                ]"#,
                crate::l7::jsonrpc::JsonRpcInspectionMode::JsonRpc,
            )),
        };

        let (allowed, reason) = evaluate_l7_request(&tunnel_engine, &ctx, &request).unwrap();
        assert!(allowed, "{reason}");

        request.jsonrpc = Some(crate::l7::jsonrpc::parse_jsonrpc_body(
            br#"[
                {"jsonrpc":"2.0","id":1,"method":"reports.list"},
                {"jsonrpc":"2.0","id":2,"result":{"ok":true}}
            ]"#,
            crate::l7::jsonrpc::JsonRpcInspectionMode::JsonRpc,
        ));
        let (allowed, reason) = evaluate_l7_request(&tunnel_engine, &ctx, &request).unwrap();
        assert!(!allowed);
        assert!(reason.contains("response frames"));

        let jsonrpc = request.jsonrpc.as_ref().expect("jsonrpc request");
        let evaluation =
            evaluate_jsonrpc_l7_request_for_log(&tunnel_engine, &ctx, &request, jsonrpc).unwrap();
        assert!(!evaluation.allowed);
        assert!(evaluation.log_info.has_response);
        assert_eq!(
            rule_method_names_for_log(&evaluation.log_info),
            "reports.list"
        );

        request.jsonrpc = Some(crate::l7::jsonrpc::parse_jsonrpc_body(
            br#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#,
            crate::l7::jsonrpc::JsonRpcInspectionMode::JsonRpc,
        ));
        let (allowed, reason) = evaluate_l7_request(&tunnel_engine, &ctx, &request).unwrap();
        assert!(!allowed);
        assert!(reason.contains("response frames"));

        let jsonrpc = request.jsonrpc.as_ref().expect("jsonrpc response");
        let evaluation =
            evaluate_jsonrpc_l7_request_for_log(&tunnel_engine, &ctx, &request, jsonrpc).unwrap();
        assert!(!evaluation.allowed);
        assert!(evaluation.log_info.has_response);
        assert_eq!(rule_method_names_for_log(&evaluation.log_info), "-");

        request.jsonrpc = Some(crate::l7::jsonrpc::parse_jsonrpc_body(
            br#"[
                {"jsonrpc":"2.0","id":1,"method":"reports.list"},
                {"jsonrpc":"2.0","id":2,"method":"reports.search","params":{"query":"private_query_value"}},
                {"jsonrpc":"2.0","id":3,"method":"reports.delete","params":{"id":"purge_cache"}}
            ]"#,
            crate::l7::jsonrpc::JsonRpcInspectionMode::JsonRpc,
        ));
        let (allowed, _) = evaluate_l7_request(&tunnel_engine, &ctx, &request).unwrap();
        assert!(!allowed);

        let jsonrpc = request.jsonrpc.as_ref().expect("jsonrpc request");
        let evaluation =
            evaluate_jsonrpc_l7_request_for_log(&tunnel_engine, &ctx, &request, jsonrpc).unwrap();
        assert!(!evaluation.allowed);
        assert!(evaluation.log_info.is_batch);
        assert_eq!(
            rule_method_names_for_log(&evaluation.log_info),
            "reports.delete"
        );

        let message = jsonrpc_log_message(
            "deny",
            "POST",
            "api.example.test:443/rpc",
            &evaluation.log_info,
            42,
            &evaluation.reason,
        );
        assert!(message.contains("rule_methods=reports.delete"));
        assert!(message.contains("policy_version=42"));
        assert!(!message.contains("reports.list"));
        assert!(!message.contains("reports.search"));
        assert!(!message.contains("private_query_value"));
        assert!(!message.contains("purge_cache"));
    }

    #[test]
    fn jsonrpc_request_params_do_not_affect_method_policy() {
        let data = r#"
network_policies:
  jsonrpc_api:
    name: jsonrpc_api
    endpoints:
      - host: api.example.test
        port: 443
        protocol: json-rpc
        enforcement: enforce
        rules:
          - allow:
              method: "reports.search"
    binaries:
      - { path: /usr/bin/node }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let tunnel_engine = engine
            .clone_engine_for_tunnel(engine.current_generation())
            .unwrap();
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 443,
            policy_name: "jsonrpc_api".into(),
            binary_path: "/usr/bin/node".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            ..Default::default()
        };
        let mut request = L7RequestInfo {
            action: "POST".into(),
            target: "/rpc".into(),
            query_params: std::collections::HashMap::new(),
            graphql: None,
            jsonrpc: Some(crate::l7::jsonrpc::parse_jsonrpc_body(
                br#"{"jsonrpc":"2.0","id":1,"method":"reports.search","params":{"query":"delete_resource","filters":{"scope":"workspace/secret"}}}"#,
                crate::l7::jsonrpc::JsonRpcInspectionMode::JsonRpc,
            )),
        };

        let (allowed, reason) = evaluate_l7_request(&tunnel_engine, &ctx, &request).unwrap();
        assert!(allowed, "{reason}");
        request.jsonrpc = Some(crate::l7::jsonrpc::parse_jsonrpc_body(
            br#"{"jsonrpc":"2.0","id":1,"method":"reports.search","params":["ignored",{"nested":true}]}"#,
            crate::l7::jsonrpc::JsonRpcInspectionMode::JsonRpc,
        ));
        let (allowed, reason) = evaluate_l7_request(&tunnel_engine, &ctx, &request).unwrap();
        assert!(allowed, "{reason}");
    }

    #[test]
    fn mcp_tool_deny_rule_blocks_tools_call() {
        let data = r#"
network_policies:
  mcp_api:
    name: mcp_api
    endpoints:
      - host: api.example.test
        port: 443
        path: "/mcp"
        protocol: mcp
        enforcement: enforce
        mcp:
          max_body_bytes: 131072
        rules:
          - allow:
              method: initialize
          - allow:
              method: tools/list
          - allow:
              method: tools/call
              tool: read_status
        deny_rules:
          - method: tools/call
            tool: delete_resource
    binaries:
      - { path: /usr/bin/node }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let tunnel_engine = engine
            .clone_engine_for_tunnel(engine.current_generation())
            .unwrap();
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 443,
            policy_name: "mcp_api".into(),
            binary_path: "/usr/bin/node".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            ..Default::default()
        };
        let mut request = L7RequestInfo {
            action: "POST".into(),
            target: "/mcp".into(),
            query_params: std::collections::HashMap::new(),
            graphql: None,
            jsonrpc: Some(crate::l7::jsonrpc::parse_jsonrpc_body(
                br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_status","arguments":{}}}"#,
                crate::l7::jsonrpc::JsonRpcInspectionMode::Mcp,
            )),
        };

        let (allowed, reason) = evaluate_l7_request(&tunnel_engine, &ctx, &request).unwrap();
        assert!(allowed, "{reason}");
        let allowed_info = request.jsonrpc.as_ref().expect("parsed MCP request");
        let allowed_message = jsonrpc_log_message(
            "allow",
            "POST",
            "api.example.test:443/mcp",
            allowed_info,
            42,
            &reason,
        );
        assert!(allowed_message.contains("rule_methods=tools/call"));
        assert!(allowed_message.contains("tools=read_status"));

        request.jsonrpc = Some(crate::l7::jsonrpc::parse_jsonrpc_body(
            br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_resource","arguments":{"scope":"workspace/main"}}}"#,
            crate::l7::jsonrpc::JsonRpcInspectionMode::Mcp,
        ));
        let parsed = request.jsonrpc.as_ref().expect("parsed MCP request");
        assert!(
            parsed.error.is_none(),
            "MCP request should parse: {parsed:?}"
        );
        assert_eq!(
            parsed.calls.first().and_then(|call| call.tool.as_deref()),
            Some("delete_resource")
        );

        let (allowed, reason) = evaluate_l7_request(&tunnel_engine, &ctx, &request).unwrap();
        assert!(!allowed, "delete_resource must match the MCP deny rule");
        assert!(
            reason.contains("deny rule"),
            "deny reason should identify policy denial: {reason}"
        );
        let denied_message = jsonrpc_log_message(
            "deny",
            "POST",
            "api.example.test:443/mcp",
            parsed,
            42,
            &reason,
        );
        assert!(denied_message.contains("rule_methods=tools/call"));
        assert!(denied_message.contains("tools=delete_resource"));
        assert!(!denied_message.contains("workspace/main"));
    }

    #[test]
    fn jsonrpc_log_records_method_names_not_params() {
        let info = crate::l7::jsonrpc::parse_jsonrpc_body(
            br#"{"jsonrpc":"2.0","id":1,"method":"reports.archive","params":{"id":"delete_resource","filters":{"scope":"secret-scope"}}}"#,
            crate::l7::jsonrpc::JsonRpcInspectionMode::JsonRpc,
        );
        let message = jsonrpc_log_message(
            "deny",
            "POST",
            "jsonrpc.example.com:443/rpc",
            &info,
            42,
            "request denied by policy",
        );

        assert!(message.contains("endpoint=jsonrpc.example.com:443/rpc"));
        assert!(message.contains("rule_methods=reports.archive"));
        assert!(message.contains("tools=-"));
        assert!(message.contains("policy_version=42"));
        assert!(!message.contains("delete_resource"));
        assert!(!message.contains("secret-scope"));

        let batch = crate::l7::jsonrpc::parse_jsonrpc_body(
            br#"[
                {"jsonrpc":"2.0","id":1,"method":"reports.list"},
                {"jsonrpc":"2.0","id":2,"method":"reports.archive","params":{"id":"delete_resource"}}
            ]"#,
            crate::l7::jsonrpc::JsonRpcInspectionMode::JsonRpc,
        );
        let batch_message = jsonrpc_log_message(
            "allow",
            "POST",
            "jsonrpc.example.com:443/rpc",
            &batch,
            43,
            "",
        );

        assert!(batch_message.starts_with("JSONRPC_L7_REQUEST "));
        assert!(batch_message.contains("rule_methods=reports.list,reports.archive"));
        assert!(batch_message.contains("policy_version=43"));
        assert!(!batch_message.contains("delete_resource"));

        let no_params = crate::l7::jsonrpc::parse_jsonrpc_body(
            br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
            crate::l7::jsonrpc::JsonRpcInspectionMode::JsonRpc,
        );
        let no_params_message = jsonrpc_log_message(
            "allow",
            "POST",
            "jsonrpc.example.com:443/rpc",
            &no_params,
            44,
            "",
        );
        assert!(no_params_message.contains("rule_methods=initialize"));
    }

    #[tokio::test]
    async fn route_selected_jsonrpc_response_frame_hard_denies_under_audit() {
        let data = r"
network_policies:
  route_api:
    name: route_api
    endpoints:
      - host: gateway.example.test
        port: 443
        path: /rpc
        protocol: json-rpc
        enforcement: audit
        rules:
          - allow:
              method: initialize
    binaries:
      - { path: /usr/bin/node }
";
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "gateway.example.test".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/node"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let (endpoint, generation) = engine
            .query_endpoint_config_with_generation(&input)
            .expect("endpoint config");
        let configs = vec![
            crate::l7::parse_l7_config(&endpoint.expect("JSON-RPC endpoint"))
                .expect("parse JSON-RPC config"),
        ];
        let tunnel_engine = engine.clone_engine_for_tunnel(generation).unwrap();
        let ctx = L7EvalContext {
            host: "gateway.example.test".into(),
            port: 443,
            policy_name: "route_api".into(),
            binary_path: "/usr/bin/node".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            ..Default::default()
        };
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_route_selection(
                &configs,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        let body = br#"{"jsonrpc":"2.0","id":7,"result":{"ok":true}}"#;
        let request = format!(
            "POST /rpc HTTP/1.1\r\nHost: gateway.example.test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        app.write_all(request.as_bytes()).await.unwrap();
        app.write_all(body).await.unwrap();

        let mut response = [0u8; 1024];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), app.read(&mut response))
            .await
            .expect("hard denial should reach client")
            .unwrap();
        let response = String::from_utf8_lossy(&response[..n]);
        assert!(response.contains("403 Forbidden"), "{response}");
        assert!(response.contains("response frames"), "{response}");

        let mut upstream_bytes = [0u8; 16];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            upstream.read(&mut upstream_bytes),
        )
        .await;
        assert!(
            matches!(result, Err(_) | Ok(Ok(0))),
            "hard-denied response frame must not reach upstream"
        );

        drop(app);
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should finish")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn route_selected_websocket_upgrade_rejects_invalid_accept_without_forwarding_101() {
        let data = r#"
network_policies:
  route_api:
    name: route_api
    endpoints:
      - host: gateway.example.test
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/ws"
    binaries:
      - { path: /usr/bin/node }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let tunnel_engine = engine
            .clone_engine_for_tunnel(engine.current_generation())
            .unwrap();
        let configs = vec![L7EndpointConfig {
            protocol: L7Protocol::Rest,
            path: "/ws".into(),
            tls: crate::l7::TlsMode::Auto,
            enforcement: EnforcementMode::Enforce,
            graphql_max_body_bytes: 0,
            json_rpc_max_body_bytes: crate::l7::jsonrpc::DEFAULT_MAX_BODY_BYTES,
            mcp_strict_tool_names: true,
            allow_encoded_slash: false,
            websocket_credential_rewrite: true,
            request_body_credential_rewrite: false,
            websocket_graphql_policy: false,
            credential_signing: crate::l7::CredentialSigning::None,
            signing_service: String::new(),
            signing_region: String::new(),
        }];
        let ctx = L7EvalContext {
            host: "gateway.example.test".into(),
            port: 443,
            policy_name: "route_api".into(),
            binary_path: "/usr/bin/node".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            ..Default::default()
        };

        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_route_selection(
                &configs,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        app.write_all(
            b"GET /ws HTTP/1.1\r\nHost: gateway.example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .await
        .unwrap();

        let mut forwarded = [0u8; 1024];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut forwarded),
        )
        .await
        .expect("upgrade request should reach upstream")
        .unwrap();
        let forwarded = String::from_utf8_lossy(&forwarded[..n]);
        assert!(forwarded.contains("Upgrade: websocket\r\n"));
        assert!(forwarded.contains("Connection: Upgrade\r\n"));

        upstream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: invalid\r\n\r\n",
            )
            .await
            .unwrap();

        let err = tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should fail closed on invalid accept")
            .unwrap()
            .expect_err("invalid accept must fail the route-selected relay");
        assert!(err.to_string().contains("Sec-WebSocket-Accept"));

        let mut response = [0u8; 1];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), app.read(&mut response))
            .await
            .expect("client side should close without 101")
            .unwrap();
        assert_eq!(n, 0, "invalid response must not forward 101 headers");
    }

    #[tokio::test]
    async fn route_selected_websocket_rewrites_text_credentials_after_upgrade() {
        let data = r#"
network_policies:
  route_api:
    name: route_api
    endpoints:
      - host: gateway.example.test
        port: 443
        protocol: websocket
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/ws"
          - allow:
              method: WEBSOCKET_TEXT
              path: "/ws"
        websocket_credential_rewrite: true
    binaries:
      - { path: /usr/bin/node }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let tunnel_engine = engine
            .clone_engine_for_tunnel(engine.current_generation())
            .unwrap();
        let configs = vec![L7EndpointConfig {
            protocol: L7Protocol::Websocket,
            path: "/ws".into(),
            tls: crate::l7::TlsMode::Auto,
            enforcement: EnforcementMode::Enforce,
            graphql_max_body_bytes: 0,
            json_rpc_max_body_bytes: crate::l7::jsonrpc::DEFAULT_MAX_BODY_BYTES,
            mcp_strict_tool_names: true,
            allow_encoded_slash: false,
            websocket_credential_rewrite: true,
            request_body_credential_rewrite: false,
            websocket_graphql_policy: false,
            credential_signing: crate::l7::CredentialSigning::None,
            signing_service: String::new(),
            signing_region: String::new(),
        }];
        let (child_env, resolver) = SecretResolver::from_provider_env(
            std::iter::once(("DISCORD_BOT_TOKEN".to_string(), "real-token".to_string())).collect(),
        );
        let placeholder = child_env.get("DISCORD_BOT_TOKEN").expect("placeholder env");
        let ctx = L7EvalContext {
            host: "gateway.example.test".into(),
            port: 443,
            policy_name: "route_api".into(),
            binary_path: "/usr/bin/node".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: resolver.map(Arc::new),
            ..Default::default()
        };

        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_route_selection(
                &configs,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        app.write_all(
            b"GET /ws HTTP/1.1\r\nHost: gateway.example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .await
        .unwrap();

        let mut forwarded = [0u8; 1024];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut forwarded),
        )
        .await
        .expect("upgrade request should reach upstream")
        .unwrap();
        let forwarded = String::from_utf8_lossy(&forwarded[..n]);
        assert!(forwarded.contains("Upgrade: websocket\r\n"));

        upstream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            )
            .await
            .unwrap();

        let mut response = [0u8; 1024];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), app.read(&mut response))
            .await
            .expect("client should receive upgrade response")
            .unwrap();
        assert!(String::from_utf8_lossy(&response[..n]).contains("101 Switching Protocols"));

        let payload = format!(r#"{{"op":2,"d":{{"token":"{placeholder}"}}}}"#);
        app.write_all(&masked_text_frame(payload.as_bytes()))
            .await
            .unwrap();

        let (masked, rewritten) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            read_text_frame(&mut upstream),
        )
        .await
        .expect("rewritten websocket text should reach upstream")
        .unwrap();
        assert!(masked, "client-to-server frame must remain masked");
        assert_eq!(rewritten, r#"{"op":2,"d":{"token":"real-token"}}"#);
        assert!(!rewritten.contains(placeholder));

        drop(app);
        drop(upstream);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), relay).await;
    }

    #[tokio::test]
    async fn route_selected_graphql_websocket_rewrites_connection_init_credentials_after_upgrade() {
        let data = r#"
network_policies:
  route_api:
    name: route_api
    endpoints:
      - host: gateway.example.test
        port: 443
        path: "/graphql"
        protocol: websocket
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/graphql"
          - allow:
              operation_type: query
              fields: [viewer]
        websocket_credential_rewrite: true
    binaries:
      - { path: /usr/bin/node }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let tunnel_engine = engine
            .clone_engine_for_tunnel(engine.current_generation())
            .unwrap();
        let configs = vec![L7EndpointConfig {
            protocol: L7Protocol::Websocket,
            path: "/graphql".into(),
            tls: crate::l7::TlsMode::Auto,
            enforcement: EnforcementMode::Enforce,
            graphql_max_body_bytes: 0,
            json_rpc_max_body_bytes: crate::l7::jsonrpc::DEFAULT_MAX_BODY_BYTES,
            mcp_strict_tool_names: true,
            allow_encoded_slash: false,
            websocket_credential_rewrite: true,
            request_body_credential_rewrite: false,
            websocket_graphql_policy: true,
            credential_signing: crate::l7::CredentialSigning::None,
            signing_service: String::new(),
            signing_region: String::new(),
        }];
        let (child_env, resolver) = SecretResolver::from_provider_env(
            std::iter::once(("T".to_string(), "real-token".to_string())).collect(),
        );
        let placeholder = child_env.get("T").expect("placeholder env");
        let ctx = L7EvalContext {
            host: "gateway.example.test".into(),
            port: 443,
            policy_name: "route_api".into(),
            binary_path: "/usr/bin/node".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: resolver.map(Arc::new),
            ..Default::default()
        };

        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_route_selection(
                &configs,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        app.write_all(
            b"GET /graphql HTTP/1.1\r\nHost: gateway.example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .await
        .unwrap();

        let mut forwarded = [0u8; 1024];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut forwarded),
        )
        .await
        .expect("upgrade request should reach upstream")
        .unwrap();
        let forwarded = String::from_utf8_lossy(&forwarded[..n]);
        assert!(forwarded.contains("GET /graphql HTTP/1.1"));
        assert!(forwarded.contains("Upgrade: websocket\r\n"));

        upstream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            )
            .await
            .unwrap();

        let mut response = [0u8; 1024];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), app.read(&mut response))
            .await
            .expect("client should receive upgrade response")
            .unwrap();
        assert!(String::from_utf8_lossy(&response[..n]).contains("101 Switching Protocols"));

        let payload = format!(
            r#"{{"type":"connection_init","payload":{{"authorization":"{placeholder}"}}}}"#
        );
        app.write_all(&masked_text_frame(payload.as_bytes()))
            .await
            .unwrap();

        let (masked, rewritten) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            read_text_frame(&mut upstream),
        )
        .await
        .expect("rewritten GraphQL WebSocket control message should reach upstream")
        .unwrap();
        assert!(masked, "client-to-server frame must remain masked");
        assert_eq!(
            rewritten,
            r#"{"type":"connection_init","payload":{"authorization":"real-token"}}"#
        );
        assert!(!rewritten.contains(placeholder));

        drop(app);
        drop(upstream);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), relay).await;
    }

    fn masked_text_frame(payload: &[u8]) -> Vec<u8> {
        let mask = [0x11, 0x22, 0x33, 0x44];
        assert!(
            payload.len() <= 125,
            "test helper only supports small frames"
        );
        let payload_len = u8::try_from(payload.len()).expect("small frame length");
        let mut frame = vec![0x81, 0x80 | payload_len];
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(idx, byte)| byte ^ mask[idx % 4]),
        );
        frame
    }

    async fn read_text_frame<R: AsyncRead + Unpin>(
        reader: &mut R,
    ) -> std::io::Result<(bool, String)> {
        let mut header = [0u8; 2];
        reader.read_exact(&mut header).await?;
        assert_eq!(header[0] & 0x0f, 0x1, "expected text frame");
        let masked = header[1] & 0x80 != 0;
        let payload_len = usize::from(header[1] & 0x7f);
        assert!(payload_len <= 125, "test helper only supports small frames");
        let mut mask = [0u8; 4];
        if masked {
            reader.read_exact(&mut mask).await?;
        }
        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload).await?;
        if masked {
            for (idx, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[idx % 4];
            }
        }
        Ok((masked, String::from_utf8(payload).expect("text payload")))
    }

    #[tokio::test]
    async fn l7_relay_closes_keep_alive_tunnel_after_policy_generation_change() {
        let initial_data = r#"
network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: api.example.test
        port: 8080
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: POST
              path: "/write"
    binaries:
      - { path: /usr/bin/curl }
"#;
        let reloaded_data = r#"
network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: api.example.test
        port: 8080
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/write"
    binaries:
      - { path: /usr/bin/curl }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, initial_data).unwrap();
        let input = NetworkInput {
            host: "api.example.test".into(),
            port: 8080,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let (endpoint_config, generation) = engine
            .query_endpoint_config_with_generation(&input)
            .unwrap();
        let config = crate::l7::parse_l7_config(&endpoint_config.unwrap()).unwrap();
        let tunnel_engine = engine.clone_engine_for_tunnel(generation).unwrap();
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 8080,
            policy_name: "rest_api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            ..Default::default()
        };

        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        app.write_all(
            b"POST /write HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
        )
        .await
        .unwrap();

        let mut first_upstream = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut first_upstream),
        )
        .await
        .expect("first request should reach upstream")
        .unwrap();
        let first_upstream = String::from_utf8_lossy(&first_upstream[..n]);
        assert!(
            first_upstream.starts_with("POST /write HTTP/1.1"),
            "unexpected upstream request: {first_upstream:?}"
        );

        upstream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")
            .await
            .unwrap();

        let mut first_response = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.read(&mut first_response),
        )
        .await
        .expect("first response should reach client")
        .unwrap();
        let first_response = String::from_utf8_lossy(&first_response[..n]);
        assert!(first_response.contains("200 OK"));

        engine.reload(TEST_POLICY, reloaded_data).unwrap();
        app.write_all(
            b"POST /write HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
        )
        .await
        .unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should close stale tunnel")
            .unwrap()
            .unwrap();

        let mut second_upstream = [0u8; 128];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut second_upstream),
        )
        .await
        .expect("upstream side should close")
        .unwrap();
        assert_eq!(n, 0, "stale request must not be forwarded upstream");
    }

    #[tokio::test]
    async fn passthrough_relay_closes_keep_alive_tunnel_after_policy_generation_change() {
        let policy_data = "network_policies: {}\n";
        let engine = OpaEngine::from_strings(TEST_POLICY, policy_data).unwrap();
        let generation_guard = engine
            .generation_guard(engine.current_generation())
            .unwrap();
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 8080,
            policy_name: "rest_api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            ..Default::default()
        };

        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_passthrough_with_credentials(
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
                &generation_guard,
                None,
            )
            .await
        });

        app.write_all(
            b"GET /first HTTP/1.1\r\nHost: api.example.test\r\nConnection: keep-alive\r\n\r\n",
        )
        .await
        .unwrap();

        let mut first_upstream = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut first_upstream),
        )
        .await
        .expect("first passthrough request should reach upstream")
        .unwrap();
        let first_upstream = String::from_utf8_lossy(&first_upstream[..n]);
        assert!(first_upstream.starts_with("GET /first HTTP/1.1"));

        upstream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")
            .await
            .unwrap();

        let mut first_response = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.read(&mut first_response),
        )
        .await
        .expect("first passthrough response should reach client")
        .unwrap();
        let first_response = String::from_utf8_lossy(&first_response[..n]);
        assert!(first_response.contains("200 OK"));

        engine.reload(TEST_POLICY, policy_data).unwrap();
        app.write_all(
            b"GET /second HTTP/1.1\r\nHost: api.example.test\r\nConnection: keep-alive\r\n\r\n",
        )
        .await
        .unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("passthrough relay should close stale tunnel")
            .unwrap()
            .unwrap();

        let mut second_upstream = [0u8; 128];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut second_upstream),
        )
        .await
        .expect("upstream side should close")
        .unwrap();
        assert_eq!(
            n, 0,
            "stale passthrough request must not be forwarded upstream"
        );
    }

    #[tokio::test]
    async fn jsonrpc_relay_forwards_allowed_method() {
        let (config, tunnel_engine, ctx) = jsonrpc_test_relay_context();
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        let body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
        let request = format!(
            "POST /rpc HTTP/1.1\r\nHost: jsonrpc.example.test:8000\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        app.write_all(request.as_bytes()).await.unwrap();
        app.write_all(body).await.unwrap();

        let mut upstream_bytes = Vec::new();
        let mut upstream_buf = [0u8; 1024];
        loop {
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                upstream.read(&mut upstream_buf),
            )
            .await
            .expect("allowed JSON-RPC request should reach upstream")
            .unwrap();
            assert_ne!(n, 0, "upstream closed before JSON-RPC body arrived");
            upstream_bytes.extend_from_slice(&upstream_buf[..n]);
            if String::from_utf8_lossy(&upstream_bytes).contains(r#""method":"initialize""#) {
                break;
            }
        }
        let upstream_request = String::from_utf8_lossy(&upstream_bytes);
        assert!(upstream_request.starts_with("POST /rpc HTTP/1.1"));
        assert!(upstream_request.contains(r#""method":"initialize""#));

        upstream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 36\r\nConnection: close\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}",
            )
            .await
            .unwrap();

        let mut response = [0u8; 512];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), app.read(&mut response))
            .await
            .expect("upstream response should reach client")
            .unwrap();
        assert!(String::from_utf8_lossy(&response[..n]).contains("200 OK"));

        drop(app);
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should complete")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn mcp_relay_forwards_jsonrpc_response_frame() {
        let (config, tunnel_engine, ctx) = mcp_test_relay_context();
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        let body = br#"{"jsonrpc":"2.0","id":7,"result":{"action":"accept","content":{}}}"#;
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        app.write_all(request.as_bytes()).await.unwrap();
        app.write_all(body).await.unwrap();

        let mut upstream_buf = [0u8; 1024];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut upstream_buf),
        )
        .await
        .expect("MCP response frame should reach upstream")
        .unwrap();
        let upstream_request = String::from_utf8_lossy(&upstream_buf[..n]);
        assert!(upstream_request.starts_with("POST /mcp HTTP/1.1"));
        assert!(upstream_request.contains(r#""result":{"action":"accept""#));

        upstream
            .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();

        let mut response = [0u8; 512];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), app.read(&mut response))
            .await
            .expect("upstream response should reach client")
            .unwrap();
        assert!(String::from_utf8_lossy(&response[..n]).contains("202 Accepted"));

        drop(app);
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should complete")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn jsonrpc_relay_denies_method_not_in_allow_list() {
        let (config, tunnel_engine, ctx) = jsonrpc_test_relay_context();
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        let body =
            br#"{"jsonrpc":"2.0","id":1,"method":"reports.search","params":{"query":"list_repos"}}"#;
        let request = format!(
            "POST /rpc HTTP/1.1\r\nHost: jsonrpc.example.test:8000\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        app.write_all(request.as_bytes()).await.unwrap();
        app.write_all(body).await.unwrap();

        let mut response = [0u8; 512];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), app.read(&mut response))
            .await
            .expect("relay should respond without reaching upstream")
            .unwrap();
        let response = String::from_utf8_lossy(&response[..n]);
        assert!(
            response.contains("403"),
            "reports.search not in allow list must be denied with 403, got: {response:?}"
        );

        let mut upstream_buf = [0u8; 128];
        let n = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            upstream.read(&mut upstream_buf),
        )
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0);
        assert_eq!(n, 0, "denied request must not be forwarded to upstream");

        drop(app);
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should complete")
            .unwrap()
            .unwrap();
    }
}
