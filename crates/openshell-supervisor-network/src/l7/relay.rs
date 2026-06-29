// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Protocol-aware bidirectional relay with L7 inspection.
//!
//! Replaces `copy_bidirectional` for endpoints with L7 configuration.
//! Parses each request within the tunnel, evaluates it against OPA policy,
//! and either forwards or denies the request.

use crate::l7::provider::{L7Provider, RelayOutcome};
use crate::l7::rest::WebSocketExtensionMode;
use crate::l7::{EnforcementMode, L7EndpointConfig, L7Protocol, L7RequestInfo};
use crate::opa::{PolicyGenerationGuard, TunnelPolicyEngine};
use miette::{IntoDiagnostic, Result, miette};
use openshell_core::activity::{ActivitySender, try_record_activity};
use openshell_core::secrets::{self, SecretResolver};
use openshell_ocsf::{
    ActionId, ActivityId, DetectionFindingBuilder, DispositionId, Endpoint, FindingInfo,
    HttpActivityBuilder, HttpRequest, NetworkActivityBuilder, SeverityId, StatusId, Url as OcsfUrl,
    ocsf_emit,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, warn};

/// Context for L7 request policy evaluation.
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
        .deny(
            req,
            &ctx.policy_name,
            crate::l7::rest::UNSUPPORTED_H2C_UPGRADE_DETAIL,
            client,
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
                .deny(
                    &req,
                    &ctx.policy_name,
                    "no L7 endpoint path matched request",
                    client,
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
                    Some(crate::l7::rest::DenyResponseContext {
                        host: Some(&ctx.host),
                        port: Some(ctx.port),
                        binary: Some(&ctx.binary_path),
                    }),
                )
                .await?;
            return Ok(());
        }

        let parse_error_reason = graphql_info
            .as_ref()
            .and_then(|info| info.error.as_deref())
            .map(|error| format!("GraphQL request rejected: {error}"))
            .or_else(|| {
                jsonrpc_info
                    .as_ref()
                    .and_then(|info| info.error.as_deref())
                    .map(|error| format!("JSON-RPC request rejected: {error}"))
            });
        let force_deny = parse_error_reason.is_some();
        let (allowed, reason) = if let Some(reason) = parse_error_reason {
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
            let req =
                match apply_middleware_chain(req, client, ctx, chain, engine.generation_guard())
                    .await?
                {
                    MiddlewareApplyResult::Allowed(req) => req,
                    MiddlewareApplyResult::Denied(reason) => {
                        crate::l7::rest::RestProvider::default()
                            .deny_with_redacted_target(
                                &crate::l7::provider::L7Request {
                                    action: request_info.action.clone(),
                                    target: redacted_target.clone(),
                                    query_params: request_info.query_params.clone(),
                                    raw_header: Vec::new(),
                                    body_length: crate::l7::provider::BodyLength::None,
                                },
                                &ctx.policy_name,
                                &reason,
                                client,
                                Some(&redacted_target),
                                Some(crate::l7::rest::DenyResponseContext {
                                    host: Some(&ctx.host),
                                    port: Some(ctx.port),
                                    binary: Some(&ctx.binary_path),
                                }),
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
                    Some(crate::l7::rest::DenyResponseContext {
                        host: Some(&ctx.host),
                        port: Some(ctx.port),
                        binary: Some(&ctx.binary_path),
                    }),
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
        return format!(" rule_methods={}", rule_method_names_for_log(info));
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

pub(crate) enum MiddlewareApplyResult {
    Allowed(crate::l7::provider::L7Request),
    Denied(String),
}

fn middleware_chain_body_limit(
    chain: &[openshell_supervisor_middleware::DescribedChainEntry],
) -> Option<usize> {
    chain
        .iter()
        .map(openshell_supervisor_middleware::DescribedChainEntry::max_body_bytes)
        .min()
}

pub(crate) async fn apply_middleware_chain<C: AsyncRead + AsyncWrite + Unpin + Send>(
    req: crate::l7::provider::L7Request,
    client: &mut C,
    ctx: &L7EvalContext,
    chain: Vec<openshell_supervisor_middleware::ChainEntry>,
    generation_guard: &PolicyGenerationGuard,
) -> Result<MiddlewareApplyResult> {
    apply_middleware_chain_for_scheme(req, client, ctx, "https", chain, generation_guard).await
}

pub(crate) async fn apply_middleware_chain_for_scheme<C: AsyncRead + AsyncWrite + Unpin + Send>(
    req: crate::l7::provider::L7Request,
    client: &mut C,
    ctx: &L7EvalContext,
    scheme: &str,
    chain: Vec<openshell_supervisor_middleware::ChainEntry>,
    generation_guard: &PolicyGenerationGuard,
) -> Result<MiddlewareApplyResult> {
    if chain.is_empty() {
        return Ok(MiddlewareApplyResult::Allowed(req));
    }
    let runner = openshell_supervisor_middleware::ChainRunner::default();
    let chain = runner.describe_chain(&chain).await?;
    let max_body_bytes =
        middleware_chain_body_limit(&chain).expect("non-empty middleware chain has a body limit");
    let buffered = match crate::l7::rest::buffer_request_body_for_middleware(
        &req,
        client,
        Some(generation_guard),
        max_body_bytes,
    )
    .await?
    {
        crate::l7::rest::BufferResult::Buffered(buffered) => buffered,
        crate::l7::rest::BufferResult::OverCapacity { recoverable } => {
            return Ok(resolve_unbuffered_body(ctx, req, &chain, recoverable));
        }
    };
    let headers = safe_middleware_headers(&buffered.headers)?;
    let query = raw_query_from_request_headers(&buffered.headers)?;
    let input = middleware_request_input(scheme, &req, ctx, headers, query, buffered.body);
    let outcome = runner.evaluate_described(&chain, input).await?;
    emit_middleware_events(ctx, &req, &outcome);
    let rebuilt = crate::l7::rest::rebuild_request_with_buffered_body(
        &req,
        &buffered.headers,
        &outcome.body,
        &outcome.added_headers,
    )?;
    if outcome.allowed {
        Ok(MiddlewareApplyResult::Allowed(rebuilt))
    } else {
        Ok(MiddlewareApplyResult::Denied(outcome.reason))
    }
}

fn middleware_request_input(
    scheme: &str,
    req: &crate::l7::provider::L7Request,
    ctx: &L7EvalContext,
    headers: BTreeMap<String, String>,
    query: String,
    body: Vec<u8>,
) -> openshell_supervisor_middleware::HttpRequestInput {
    openshell_supervisor_middleware::HttpRequestInput {
        request_id: uuid::Uuid::new_v4().to_string(),
        sandbox_id: openshell_ocsf::ctx::ctx().sandbox_id.clone(),
        scheme: scheme.into(),
        host: ctx.host.clone(),
        port: ctx.port,
        method: req.action.clone(),
        path: req.target.clone(),
        query,
        headers,
        body,
    }
}

fn raw_query_from_request_headers(headers: &[u8]) -> Result<String> {
    let header_str =
        std::str::from_utf8(headers).map_err(|_| miette!("HTTP headers contain invalid UTF-8"))?;
    let target = header_str
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| miette!("HTTP request line is missing a target"))?;
    Ok(target
        .split_once('?')
        .map_or_else(String::new, |(_, query)| query.to_string()))
}

/// Apply the chain's `on_error` policy when the request body cannot be buffered
/// for inspection because it exceeds the size cap. The RFC treats an unbufferable
/// body as an `on_error` event: it is denied unless every attached middleware is
/// `fail_open`, and passing it through is only safe when no bytes were consumed.
fn resolve_unbuffered_body(
    ctx: &L7EvalContext,
    req: crate::l7::provider::L7Request,
    chain: &[openshell_supervisor_middleware::DescribedChainEntry],
    recoverable: bool,
) -> MiddlewareApplyResult {
    let all_fail_open = chain
        .iter()
        .all(|entry| entry.on_error() == openshell_supervisor_middleware::OnError::FailOpen);
    if recoverable && all_fail_open {
        emit_middleware_body_unavailable(ctx, false);
        return MiddlewareApplyResult::Allowed(req);
    }
    emit_middleware_body_unavailable(ctx, true);
    MiddlewareApplyResult::Denied("middleware_failed: request_body_over_capacity".into())
}

fn emit_middleware_body_unavailable(ctx: &L7EvalContext, denied: bool) {
    let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
        .severity(if denied {
            SeverityId::High
        } else {
            SeverityId::Medium
        })
        .finding_info(FindingInfo::new(
            "openshell.middleware.body_unavailable",
            "Supervisor middleware could not inspect request body",
        ))
        .evidence_pairs(&[
            ("policy", ctx.policy_name.as_str()),
            ("host", ctx.host.as_str()),
            ("disposition", if denied { "denied" } else { "fail_open" }),
        ])
        .message(if denied {
            "Request body exceeded middleware inspection cap; denied"
        } else {
            "Request body exceeded middleware inspection cap; passed through (fail_open)"
        })
        .build();
    ocsf_emit!(event);
}

fn safe_middleware_headers(headers: &[u8]) -> Result<BTreeMap<String, String>> {
    let header_str =
        std::str::from_utf8(headers).map_err(|_| miette!("HTTP headers contain invalid UTF-8"))?;
    let mut out = BTreeMap::new();
    for line in header_str.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty()
            || matches!(
                name.as_str(),
                "authorization" | "cookie" | "host" | "content-length" | "transfer-encoding"
            )
            || name.starts_with("x-amz-")
            || name.starts_with("x-openshell-credential")
        {
            continue;
        }
        out.insert(name, value.trim().to_string());
    }
    Ok(out)
}

fn middleware_network_input(ctx: &L7EvalContext) -> crate::opa::NetworkInput {
    crate::opa::NetworkInput {
        host: ctx.host.clone(),
        port: ctx.port,
        binary_path: PathBuf::from(&ctx.binary_path),
        binary_sha256: String::new(),
        ancestors: ctx.ancestors.iter().map(PathBuf::from).collect(),
        cmdline_paths: ctx.cmdline_paths.iter().map(PathBuf::from).collect(),
    }
}

fn emit_middleware_events(
    ctx: &L7EvalContext,
    req: &crate::l7::provider::L7Request,
    outcome: &openshell_supervisor_middleware::ChainOutcome,
) {
    for invocation in &outcome.applied {
        let allowed = invocation.decision == openshell_core::proto::Decision::Allow;
        let event = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .activity(ActivityId::Other)
            .action(if allowed {
                ActionId::Allowed
            } else {
                ActionId::Denied
            })
            .disposition(if allowed {
                DispositionId::Allowed
            } else {
                DispositionId::Blocked
            })
            .severity(if allowed {
                SeverityId::Informational
            } else {
                SeverityId::Medium
            })
            .http_request(HttpRequest::new(
                &req.action,
                OcsfUrl::new("http", &ctx.host, &req.target, ctx.port),
            ))
            .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
            .firewall_rule(&ctx.policy_name, "middleware")
            .message(format!(
                "MIDDLEWARE {} {} decision={:?} transformed={} failed={}",
                invocation.name,
                invocation.implementation,
                invocation.decision,
                invocation.transformed,
                invocation.failed
            ))
            .build();
        ocsf_emit!(event);

        // A middleware that failed but was bypassed under `fail_open` is an
        // enforcement failure operators must be able to alert on, even though the
        // request proceeded.
        if invocation.failed && allowed {
            let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(SeverityId::Medium)
                .finding_info(FindingInfo::new(
                    "openshell.middleware.failure",
                    "Supervisor middleware failed open",
                ))
                .evidence_pairs(&[
                    ("middleware", invocation.name.as_str()),
                    ("implementation", invocation.implementation.as_str()),
                ])
                .message(format!(
                    "Middleware {} failed and was bypassed (fail_open)",
                    invocation.name
                ))
                .build();
            ocsf_emit!(event);
        }
    }
    if !outcome.allowed && outcome.reason.starts_with("middleware_failed:") {
        let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
            .severity(SeverityId::High)
            .finding_info(FindingInfo::new(
                "openshell.middleware.failure",
                "Supervisor middleware failure",
            ))
            .message("Required supervisor middleware failed closed")
            .build();
        ocsf_emit!(event);
    }
    for finding in &outcome.findings {
        let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
            .severity(match finding.finding.severity.as_str() {
                "high" => SeverityId::High,
                "low" => SeverityId::Low,
                _ => SeverityId::Medium,
            })
            .finding_info(FindingInfo::new(
                &finding.finding.r#type,
                &finding.finding.label,
            ))
            .evidence_pairs(&[
                ("middleware", &finding.middleware),
                ("count", &finding.finding.count.to_string()),
            ])
            .message(format!(
                "Middleware finding {} count={}",
                finding.finding.r#type, finding.finding.count
            ))
            .build();
        ocsf_emit!(event);
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
                    Some(crate::l7::rest::DenyResponseContext {
                        host: Some(&ctx.host),
                        port: Some(ctx.port),
                        binary: Some(&ctx.binary_path),
                    }),
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
            let req =
                match apply_middleware_chain(req, client, ctx, chain, engine.generation_guard())
                    .await?
                {
                    MiddlewareApplyResult::Allowed(req) => req,
                    MiddlewareApplyResult::Denied(reason) => {
                        provider
                            .deny_with_redacted_target(
                                &crate::l7::provider::L7Request {
                                    action: request_info.action.clone(),
                                    target: redacted_target.clone(),
                                    query_params: request_info.query_params.clone(),
                                    raw_header: Vec::new(),
                                    body_length: crate::l7::provider::BodyLength::None,
                                },
                                &ctx.policy_name,
                                &reason,
                                client,
                                Some(&redacted_target),
                                Some(crate::l7::rest::DenyResponseContext {
                                    host: Some(&ctx.host),
                                    port: Some(ctx.port),
                                    binary: Some(&ctx.binary_path),
                                }),
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
                    Some(crate::l7::rest::DenyResponseContext {
                        host: Some(&ctx.host),
                        port: Some(ctx.port),
                        binary: Some(&ctx.binary_path),
                    }),
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

        let parse_error_reason = jsonrpc_info
            .error
            .as_deref()
            .map(|e| format!("JSON-RPC request rejected: {e}"));
        let response_frame_reason =
            jsonrpc_response_frame_hard_deny_reason(config.protocol, &jsonrpc_info);
        let force_deny = parse_error_reason.is_some() || response_frame_reason.is_some();
        let (allowed, reason, jsonrpc_log_info) = if let Some(reason) = parse_error_reason {
            (false, reason, jsonrpc_info.clone())
        } else if let Some(reason) = response_frame_reason {
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
            let req =
                match apply_middleware_chain(req, client, ctx, chain, engine.generation_guard())
                    .await?
                {
                    MiddlewareApplyResult::Allowed(req) => req,
                    MiddlewareApplyResult::Denied(reason) => {
                        crate::l7::rest::RestProvider::default()
                            .deny_with_redacted_target(
                                &crate::l7::provider::L7Request {
                                    action: request_info.action.clone(),
                                    target: redacted_target.clone(),
                                    query_params: request_info.query_params.clone(),
                                    raw_header: Vec::new(),
                                    body_length: crate::l7::provider::BodyLength::None,
                                },
                                &ctx.policy_name,
                                &reason,
                                client,
                                Some(&redacted_target),
                                Some(crate::l7::rest::DenyResponseContext {
                                    host: Some(&ctx.host),
                                    port: Some(ctx.port),
                                    binary: Some(&ctx.binary_path),
                                }),
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
                    Some(crate::l7::rest::DenyResponseContext {
                        host: Some(&ctx.host),
                        port: Some(ctx.port),
                        binary: Some(&ctx.binary_path),
                    }),
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
        let parse_error_reason = graphql_info
            .error
            .as_deref()
            .map(|error| format!("GraphQL request rejected: {error}"));
        let force_deny = parse_error_reason.is_some();
        let (allowed, reason) = if let Some(reason) = parse_error_reason {
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
            let req =
                match apply_middleware_chain(req, client, ctx, chain, engine.generation_guard())
                    .await?
                {
                    MiddlewareApplyResult::Allowed(req) => req,
                    MiddlewareApplyResult::Denied(reason) => {
                        crate::l7::rest::RestProvider::default()
                            .deny_with_redacted_target(
                                &crate::l7::provider::L7Request {
                                    action: request_info.action.clone(),
                                    target: redacted_target.clone(),
                                    query_params: request_info.query_params.clone(),
                                    raw_header: Vec::new(),
                                    body_length: crate::l7::provider::BodyLength::None,
                                },
                                &ctx.policy_name,
                                &reason,
                                client,
                                Some(&redacted_target),
                                Some(crate::l7::rest::DenyResponseContext {
                                    host: Some(&ctx.host),
                                    port: Some(ctx.port),
                                    binary: Some(&ctx.binary_path),
                                }),
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
                    Some(crate::l7::rest::DenyResponseContext {
                        host: Some(&ctx.host),
                        port: Some(ctx.port),
                        binary: Some(&ctx.binary_path),
                    }),
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
    format!(
        "JSONRPC_L7_REQUEST decision={decision} http_method={http_method} endpoint={endpoint} rule_methods={rule_methods} policy_version={policy_version} reason={reason}"
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
            "jsonrpc": request.jsonrpc.as_ref().map(|j| {
                let call = if j.is_batch { None } else { j.calls.first() };
                serde_json::json!({
                    "method": call.map(|call| call.method.as_str()),
                    "params": call.map(|call| &call.params),
                    "tool": call.and_then(|call| call.tool.as_deref()),
                    "receive_stream": j.receive_stream,
                    "has_response": j.has_response,
                    "error": j.error,
                })
            }),
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
            match apply_middleware_chain(req, client, ctx, chain, generation_guard).await? {
                MiddlewareApplyResult::Allowed(req) => req,
                MiddlewareApplyResult::Denied(reason) => {
                    crate::l7::rest::RestProvider::default()
                        .deny_with_redacted_target(
                            &crate::l7::provider::L7Request {
                                action: "HTTP".into(),
                                target: redacted_target.clone(),
                                query_params: std::collections::HashMap::new(),
                                raw_header: Vec::new(),
                                body_length: crate::l7::provider::BodyLength::None,
                            },
                            &ctx.policy_name,
                            &reason,
                            client,
                            Some(&redacted_target),
                            Some(crate::l7::rest::DenyResponseContext {
                                host: Some(&ctx.host),
                                port: Some(ctx.port),
                                binary: Some(&ctx.binary_path),
                            }),
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
            activity_tx: None,
            dynamic_credentials: Some(fixture.dynamic_credentials()),
            token_grant_resolver: Some(fixture.resolver()),
        };

        (config, tunnel_engine, ctx, fixture)
    }

    fn middleware_relay_context(
        middleware_impl: &str,
        on_error: &str,
    ) -> (L7EndpointConfig, TunnelPolicyEngine, L7EvalContext) {
        let data = format!(
            r#"
network_middlewares:
  - name: request-middleware
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
        enforcement: enforce
        rules:
          - allow:
              method: POST
              path: "/v1/**"
    binaries:
      - {{ path: /usr/bin/curl }}
"#
        );
        let engine = OpaEngine::from_strings(TEST_POLICY, &data).unwrap();
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
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
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
            activity_tx: None,
            dynamic_credentials: Some(fixture.dynamic_credentials()),
            token_grant_resolver: Some(fixture.resolver()),
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
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
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
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
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
            middleware_relay_context("openshell/secrets", "fail_closed");
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
  - name: request-middleware
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
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
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
            middleware_relay_context("openshell/secrets", "fail_closed");
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
        assert!(response.contains("403 Forbidden"));
        assert!(response.contains("request_body_over_capacity"));

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
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
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
            implementation: "openshell/secrets".into(),
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
            MiddlewareApplyResult::Denied(_)
        ));
        // Not recoverable (chunked overflow already consumed bytes) -> deny even
        // when every entry is fail-open.
        assert!(matches!(
            resolve_unbuffered_body(&ctx, req(), &open_chain, false),
            MiddlewareApplyResult::Denied(_)
        ));
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
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
        };

        let input = middleware_request_input(
            "http",
            &req,
            &ctx,
            BTreeMap::new(),
            String::new(),
            Vec::new(),
        );

        assert_eq!(input.scheme, "http");
    }

    /// Tracing layer that captures emitted `OcsfEvent`s for assertions.
    struct OcsfCaptureLayer(Arc<std::sync::Mutex<Vec<openshell_ocsf::OcsfEvent>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for OcsfCaptureLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if event.metadata().target() == openshell_ocsf::OCSF_TARGET
                && let Some(ocsf_event) = openshell_ocsf::clone_current_event()
            {
                self.0.lock().unwrap().push(ocsf_event);
            }
        }
    }

    #[test]
    fn middleware_ocsf_events_are_audit_safe() {
        use openshell_supervisor_middleware::{
            ChainOutcome, MiddlewareInvocation, NamespacedFinding,
        };
        use tracing_subscriber::layer::SubscriberExt;

        const RAW_SECRET: &str = "sk-RAWSECRETVALUE0123456789";

        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(OcsfCaptureLayer(Arc::clone(&events)));
        let _guard = tracing::subscriber::set_default(subscriber);

        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 443,
            policy_name: "rest_api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
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
            added_headers: BTreeMap::new(),
            findings: vec![NamespacedFinding {
                middleware: "redact-secrets".into(),
                finding: openshell_core::proto::Finding {
                    r#type: "secret.common".into(),
                    label: "common secret pattern".into(),
                    count: 1,
                    confidence: "medium".into(),
                    severity: "medium".into(),
                },
            }],
            metadata: BTreeMap::new(),
            applied: vec![MiddlewareInvocation {
                name: "redact-secrets".into(),
                implementation: "openshell/secrets".into(),
                decision: openshell_core::proto::Decision::Allow,
                transformed: true,
                failed: false,
            }],
        };

        emit_middleware_events(&ctx, &req, &outcome);

        let captured = events.lock().unwrap();
        // Per-invocation decisions are HTTP Activity (class 4002).
        assert!(
            captured.iter().any(|e| e.class_uid() == 4002),
            "expected an HTTP Activity event for the middleware invocation"
        );
        // Findings are Detection Finding (class 2004) with the finding's severity.
        let finding_event = captured
            .iter()
            .find(|e| e.class_uid() == 2004)
            .expect("expected a Detection Finding event");
        assert_eq!(finding_event.base().severity, SeverityId::Medium);

        // No raw payload material may appear in any emitted event.
        let serialized = serde_json::to_string(&*captured).expect("serialize events");
        assert!(
            !serialized.contains(RAW_SECRET),
            "raw secret leaked into OCSF events: {serialized}"
        );
        // Safe finding metadata is still present.
        assert!(serialized.contains("secret.common"));
    }

    #[tokio::test]
    async fn passthrough_relay_runs_middleware_redaction() {
        // A no-protocol endpoint takes the credential-injection passthrough path;
        // host-selected middleware must still inspect and redact its body.
        let data = r#"
network_middlewares:
  - name: request-middleware
    middleware: openshell/secrets
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
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
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
  - name: request-middleware
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
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
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
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
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
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
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
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
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
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
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
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
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
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
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
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
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
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
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
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
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
