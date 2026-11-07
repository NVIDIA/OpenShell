// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared relay primitives for authorized explicit-proxy egress.

use super::{EgressDecision, L7RouteSnapshot, emit_l7_tunnel_close_after_policy_change};
use crate::l7::relay::L7EvalContext;
use crate::opa::{
    AuthorizedConnection, NetworkAction, OpaEngine, PolicyGenerationGuard, PolicyRevalidator,
    TunnelPolicyEngine,
};
use miette::{IntoDiagnostic, Result};
use openshell_core::activity::ActivitySender;
use openshell_core::endpoint_status::EndpointObservationSender;
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_core::secrets::SecretResolver;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

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

/// Non-blocking observation channels attached to an authorized HTTP relay.
pub(super) struct RelaySignals {
    /// Receives general sandbox network activity.
    pub(super) activity: Option<ActivitySender>,
    /// Receives terminal tool server results for endpoint status reporting.
    pub(super) endpoint_observation: Option<EndpointObservationSender>,
}

/// Build the request-processing context shared by CONNECT and forward HTTP.
pub(super) fn http_context(
    decision: &EgressDecision,
    provider_credentials: Option<ProviderCredentialState>,
    secret_resolver: Option<Arc<SecretResolver>>,
    policy_local: Option<&crate::policy_local::PolicyLocalContext>,
    agent_proposals: openshell_core::proposals::AgentProposals,
    signals: RelaySignals,
) -> L7EvalContext {
    // Provider-backed credentials must be acquired from the live state for
    // each request after middleware/token-grant awaits. Keep only the legacy
    // resolver fallback when no live provider state exists.
    let secret_resolver = provider_credentials
        .is_none()
        .then_some(secret_resolver)
        .flatten();
    // Grants use the owning sandbox instance's resolver; without one they fail closed.
    let token_grant_resolver = provider_credentials
        .as_ref()
        .and(policy_local)
        .and_then(crate::policy_local::PolicyLocalContext::token_grant_resolver);
    let workspace = policy_local
        .map(crate::policy_local::PolicyLocalContext::workspace)
        .unwrap_or_default();
    let policy_name = match &decision.action {
        NetworkAction::Allow { matched_policy } => matched_policy.clone().unwrap_or_default(),
        NetworkAction::Deny { .. } => String::new(),
    };

    L7EvalContext {
        host: decision.intent.destination.host.clone(),
        port: decision.intent.destination.port,
        request_default_port: None,
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
        provider_credentials,
        provider_credential_revision: None,
        provider_credential_installation_id: None,
        body_classifier: None,
        activity_tx: signals.activity,
        token_grant_resolver,
        agent_proposals,
        workspace,
        endpoint_observation_tx: signals.endpoint_observation,
    }
}

/// Capture the contract that authorized `decision` so its relay can re-pin
/// through policy changes that do not affect it.
///
/// Returns `None` for denials and when the policy already moved on; the guard
/// then closes on any change, which was the only behavior before
/// revalidation. Pass `credentials` for relays that can inject provider
/// credentials so a credential change still closes them. See
/// [`crate::opa::PolicyRevalidator`].
fn connection_revalidator(
    opa_engine: &Arc<OpaEngine>,
    decision: &EgressDecision,
    credentials: Option<&ProviderCredentialState>,
) -> Option<Arc<PolicyRevalidator>> {
    PolicyRevalidator::capture(
        opa_engine,
        decision.policy_input(),
        &AuthorizedConnection {
            action: &decision.action,
            endpoint_configs: &decision.endpoint.policy_configs,
            matched_endpoints: &decision.endpoint.matched_endpoints,
            exact_declared_endpoint_host: decision.endpoint.exact_declared_host,
        },
        decision.policy_generation,
        credentials,
    )
}

/// Pin the generation that authorized `decision` for a relay, CONNECT setup,
/// or the forward HTTP single-request path.
///
/// The pin fails if the policy changed after authorization. Once pinned, the
/// guard follows later changes that leave the connection's contract intact.
/// `credentials` is the provider state the guarded path may inject from, or
/// `None` when it never injects credentials.
pub(super) fn pin_policy_generation(
    opa_engine: &Arc<OpaEngine>,
    decision: &EgressDecision,
    credentials: Option<&ProviderCredentialState>,
) -> Result<PolicyGenerationGuard> {
    let guard = opa_engine.generation_guard(decision.policy_generation)?;
    let revalidator = connection_revalidator(opa_engine, decision, credentials);
    Ok(guard.with_revalidator(revalidator))
}

/// Clone an L7 evaluator for a relay or the forward HTTP single-request path.
pub(super) fn pin_l7_evaluator(
    opa_engine: &Arc<OpaEngine>,
    decision: &EgressDecision,
    expected_generation: u64,
    credentials: Option<&ProviderCredentialState>,
) -> Result<TunnelPolicyEngine> {
    let evaluator = opa_engine.clone_engine_for_tunnel(expected_generation)?;
    let revalidator = connection_revalidator(opa_engine, decision, credentials);
    Ok(evaluator.with_revalidator(revalidator))
}

pub(super) fn validate_route_generation(
    route: Option<&L7RouteSnapshot>,
    expected_generation: u64,
) -> Result<()> {
    if let Some(route) = route
        && route.l7_policy_generation != expected_generation
    {
        return Err(miette::miette!(
            "policy changed before CONNECT route hydration \
             [l4_generation:{} l7_generation:{}]",
            expected_generation,
            route.l7_policy_generation,
        ));
    }
    Ok(())
}

/// Prepare a generation-pinned HTTP relay at the adapter boundary.
///
/// A stale generation preserves the established CONNECT behavior: emit the
/// policy-change close event and let the adapter close the live tunnel without
/// attempting to write an HTTP response into it.
pub(super) fn prepare_http_relay<'a>(
    route: Option<&L7RouteSnapshot>,
    opa_engine: &'a Arc<OpaEngine>,
    decision: &EgressDecision,
    request: &'a L7EvalContext,
) -> Option<RelayContext<'a>> {
    if let Err(error) = validate_route_generation(route, decision.policy_generation) {
        emit_l7_tunnel_close_after_policy_change(
            &decision.intent.destination.host,
            decision.intent.destination.port,
            error,
        );
        return None;
    }

    // HTTP relays can inject provider credentials, so they also pin them.
    let credentials = request.provider_credentials.as_ref();
    let policy = if let Some(route) = route.filter(|route| !route.configs.is_empty()) {
        let generation = decision.policy_generation;
        let evaluator = match pin_l7_evaluator(opa_engine, decision, generation, credentials) {
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
        let generation_guard = match pin_policy_generation(opa_engine, decision, credentials) {
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
        middleware_engine: opa_engine.as_ref(),
    })
}

/// Pin the generation used by a raw relay so a policy change that affects the
/// connection, or any quarantine, closes streams that otherwise have no
/// request boundary at which to notice a stale decision.
///
/// Raw relays never inject provider credentials, so they do not pin them.
pub(super) fn prepare_raw_relay(
    route: Option<&L7RouteSnapshot>,
    opa_engine: &Arc<OpaEngine>,
    decision: &EgressDecision,
) -> Option<PolicyGenerationGuard> {
    if let Err(error) = validate_route_generation(route, decision.policy_generation) {
        emit_l7_tunnel_close_after_policy_change(
            &decision.intent.destination.host,
            decision.intent.destination.port,
            error,
        );
        return None;
    }

    match pin_policy_generation(opa_engine, decision, None) {
        Ok(guard) => Some(guard),
        Err(error) => {
            emit_l7_tunnel_close_after_policy_change(
                &decision.intent.destination.host,
                decision.intent.destination.port,
                error,
            );
            None
        }
    }
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
            let generation_guard = evaluator.generation_guard().clone();
            tokio::select! {
                result = crate::l7::relay::relay_with_inspection(
                    &configs[0],
                    *evaluator,
                    client,
                    upstream,
                    context.request,
                ) => result,
                () = generation_guard.wait_until_stale() => {
                    emit_stale_relay_close(context.request, &generation_guard);
                    Ok(())
                }
            }
        }
        PreparedHttpPolicy::Inspect { configs, evaluator } => {
            let generation_guard = evaluator.generation_guard().clone();
            tokio::select! {
                result = crate::l7::relay::relay_with_route_selection(
                    &configs,
                    *evaluator,
                    client,
                    upstream,
                    context.request,
                ) => result,
                () = generation_guard.wait_until_stale() => {
                    emit_stale_relay_close(context.request, &generation_guard);
                    Ok(())
                }
            }
        }
        PreparedHttpPolicy::Passthrough { generation_guard } => {
            tokio::select! {
                result = crate::l7::relay::relay_passthrough_with_credentials(
                    client,
                    upstream,
                    context.request,
                    &generation_guard,
                    Some(context.middleware_engine),
                ) => result,
                () = generation_guard.wait_until_stale() => {
                    emit_stale_relay_close(context.request, &generation_guard);
                    Ok(())
                }
            }
        }
    }
}

// Exercise the production single/multiple-route dispatch from L7 fixtures.
#[cfg(test)]
pub async fn relay_inspected_http_stream_for_test<C, U>(
    client: &mut C,
    upstream: &mut U,
    configs: Vec<crate::l7::L7EndpointConfig>,
    evaluator: TunnelPolicyEngine,
    middleware_engine: &OpaEngine,
    request: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    relay_http_stream(
        client,
        upstream,
        RelayContext {
            request,
            policy: PreparedHttpPolicy::Inspect {
                configs,
                evaluator: Box::new(evaluator),
            },
            middleware_engine,
        },
    )
    .await
}

/// Relay a policy-authorized raw TCP stream.
pub(super) async fn relay_tcp<C, U>(
    client: &mut C,
    upstream: &mut U,
    generation_guard: &PolicyGenerationGuard,
    request: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    tokio::select! {
        result = tokio::io::copy_bidirectional(client, upstream) => {
            result.into_diagnostic()?;
        }
        () = generation_guard.wait_until_stale() => {
            emit_stale_relay_close(request, generation_guard);
        }
    }
    Ok(())
}

fn emit_stale_relay_close(request: &L7EvalContext, guard: &PolicyGenerationGuard) {
    emit_l7_tunnel_close_after_policy_change(
        &request.host,
        request.port,
        miette::miette!(
            "policy generation is stale [captured_generation:{} current_generation:{}]",
            guard.captured_generation(),
            guard.current_generation(),
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::super::{EgressIntent, EndpointDecision, ProcessIdentityEvidence};
    use super::*;

    const POLICY_REGO: &str = include_str!("../../data/sandbox-policy.rego");
    const EMPTY_POLICY_DATA: &str = "network_policies: {}\n";

    fn decision(policy_generation: u64) -> EgressDecision {
        EgressDecision {
            intent: EgressIntent::connect("example.com".to_string(), 80),
            action: NetworkAction::Allow {
                matched_policy: Some("test".to_string()),
            },
            policy_generation,
            identity: ProcessIdentityEvidence::Available,
            endpoint: EndpointDecision::default(),
            binary: None,
            binary_pid: None,
            ancestors: vec![],
            cmdline_paths: vec![],
        }
    }

    fn request_context() -> L7EvalContext {
        L7EvalContext {
            host: "example.com".to_string(),
            port: 80,
            request_default_port: Some(80),
            policy_name: "test".to_string(),
            binary_path: String::new(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            provider_credentials: None,
            provider_credential_revision: None,
            provider_credential_installation_id: None,
            body_classifier: None,
            activity_tx: None,
            token_grant_resolver: None,
            agent_proposals: openshell_core::proposals::AgentProposals::default(),
            workspace: String::new(),
            endpoint_observation_tx: None,
        }
    }

    async fn assert_response_lifecycle<C, P>(mut caller: C, mut client: P)
    where
        C: AsyncRead + AsyncWrite + Unpin,
        P: AsyncRead + AsyncWrite + Unpin + Send,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut upstream, mut server) = tokio::io::duplex(1024);
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap());
        let decision = decision(engine.current_generation());
        let request = request_context();
        let context = prepare_http_relay(None, &engine, &decision, &request).unwrap();
        let persistent = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        // Larger than either transport buffer: closing must drain the body.
        let body = vec![b'x'; 64 * 1024];
        let mut closing = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        closing.extend_from_slice(&body);
        let relay = Box::pin(relay_http_stream(&mut client, &mut upstream, context));
        let serve = async {
            for response in [persistent.as_slice(), closing.as_slice()] {
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(server.read_u8().await.unwrap());
                    assert!(request.len() < 4096);
                }
                assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
                server.write_all(response).await.unwrap();
                server.flush().await.unwrap();
            }
            // Retain the upstream socket: response headers decide persistence.
        };
        let receive = async {
            let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
            caller.write_all(request).await.unwrap();
            caller.flush().await.unwrap();
            let mut first = vec![0; persistent.len()];
            caller.read_exact(&mut first).await.unwrap();
            assert_eq!(first, persistent);
            // A real second exchange verifies reuse, without a timing assertion.
            caller.write_all(request).await.unwrap();
            caller.flush().await.unwrap();
            let mut second = Vec::new();
            // TLS must return clean EOF, not UnexpectedEof from a dropped socket.
            caller.read_to_end(&mut second).await.unwrap();
            assert_eq!(second, closing);
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (result, (), ()) = tokio::join!(relay, serve, receive);
            result.unwrap();
        })
        .await
        .expect("response delivery and EOF must not await another request");
    }

    #[tokio::test]
    async fn http_relay_reuses_then_closes_after_complete_response() {
        let (caller, client) = tokio::io::duplex(1024);
        assert_response_lifecycle(caller, client).await;
    }

    #[tokio::test]
    async fn tls_http_relay_reuses_then_sends_close_notify_after_complete_response() {
        use crate::l7::tls::{CertCache, ProxyTlsState, SandboxCa, tls_terminate_client};
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        let ca = SandboxCa::generate().unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_reader_iter(&mut ca.cert_pem().as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let config = Arc::new(
            openshell_crypto::tls::client_builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let state = ProxyTlsState::new(CertCache::new(ca), config.clone());
        let connector = tokio_rustls::TlsConnector::from(config);
        let (caller, client) = tokio::io::duplex(1024);
        let (caller, client) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                connector.connect(
                    rustls::pki_types::ServerName::try_from("example.com").unwrap(),
                    caller
                ),
                tls_terminate_client(client, &state, "example.com"),
            )
        })
        .await
        .expect("TLS handshake must complete");
        assert_response_lifecycle(caller.unwrap(), client.unwrap()).await;
    }

    #[test]
    fn relay_without_route_pins_l4_decision_generation() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap());
        let decision = decision(engine.current_generation());
        let request = request_context();

        let context = prepare_http_relay(None, &engine, &decision, &request)
            .expect("current L4 generation should prepare a relay");
        let PreparedHttpPolicy::Passthrough { generation_guard } = context.policy else {
            panic!("route-less relay should use a generation guard");
        };

        assert_eq!(
            generation_guard.captured_generation(),
            decision.policy_generation
        );
    }

    #[test]
    fn empty_hydrated_route_cannot_replace_stale_l4_generation() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap());
        let decision = decision(u64::MAX);
        let route = L7RouteSnapshot {
            configs: vec![],
            l7_policy_generation: engine.current_generation(),
        };
        let request = request_context();

        assert!(
            prepare_http_relay(Some(&route), &engine, &decision, &request).is_none(),
            "a current L7 lookup must not freshen a stale L4 allow"
        );
    }

    #[test]
    fn inspected_route_cannot_replace_stale_l4_generation() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap());
        let decision = decision(u64::MAX);
        let route = L7RouteSnapshot {
            configs: vec![super::super::L7ConfigSnapshot {
                config: crate::l7::L7EndpointConfig {
                    protocol: crate::l7::L7Protocol::Rest,
                    endpoint_id: String::new(),
                    policy_hash: String::new(),
                    path: "/**".to_string(),
                    tls: crate::l7::TlsMode::Auto,
                    enforcement: crate::l7::EnforcementMode::Enforce,
                    graphql_max_body_bytes: crate::l7::graphql::DEFAULT_MAX_BODY_BYTES,
                    json_rpc_max_body_bytes: crate::l7::jsonrpc::DEFAULT_MAX_BODY_BYTES,
                    mcp_strict_tool_names: true,
                    mcp_versions: Vec::new(),
                    allow_encoded_slash: false,
                    websocket_credential_rewrite: false,
                    request_body_credential_rewrite: false,
                    allow_uninspected_credentials: false,
                    provider_credentialed: false,
                    websocket_graphql_policy: false,
                    credential_signing: crate::l7::CredentialSigning::None,
                    signing_service: String::new(),
                    signing_region: String::new(),
                },
            }],
            l7_policy_generation: engine.current_generation(),
        };
        let request = request_context();

        assert!(
            prepare_http_relay(Some(&route), &engine, &decision, &request).is_none(),
            "an inspected route must use the generation that authorized CONNECT"
        );
    }

    #[test]
    fn raw_route_cannot_replace_stale_l4_generation() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap());
        let decision = decision(u64::MAX);
        let route = L7RouteSnapshot {
            configs: vec![],
            l7_policy_generation: engine.current_generation(),
        };

        assert!(
            prepare_raw_relay(Some(&route), &engine, &decision).is_none(),
            "a raw relay must not freshen a stale L4 allow"
        );
    }

    #[test]
    fn stale_generation_fails_before_relay_context_is_created() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap());
        let decision = decision(engine.current_generation());
        let request = request_context();
        engine.reload(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();

        assert!(
            prepare_http_relay(None, &engine, &decision, &request).is_none(),
            "policy reload must prevent a stale relay from starting"
        );
    }

    #[tokio::test]
    async fn raw_relay_closes_immediately_when_fail_closed_generation_is_published() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap());
        let guard = engine
            .generation_guard(engine.current_generation())
            .unwrap();
        let request = request_context();
        let (_client_peer, mut proxy_client) = tokio::io::duplex(64);
        let (_upstream_peer, mut proxy_upstream) = tokio::io::duplex(64);

        let relay = tokio::spawn(async move {
            relay_tcp(&mut proxy_client, &mut proxy_upstream, &guard, &request).await
        });
        tokio::task::yield_now().await;

        engine
            .enter_fail_closed("candidate policy validation failed")
            .unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("raw relay should close when its generation becomes stale")
            .expect("relay task should not panic")
            .expect("stale relay closure should be clean");
    }

    const CURL_EXAMPLE_POLICY: &str = r"
network_policies:
  web:
    name: web
    endpoints:
      - { host: example.com, port: 80 }
    binaries:
      - { path: /usr/bin/curl }
";

    const CURL_EXAMPLE_AND_OTHER_POLICY: &str = r"
network_policies:
  web:
    name: web
    endpoints:
      - { host: example.com, port: 80 }
    binaries:
      - { path: /usr/bin/curl }
  other:
    name: other
    endpoints:
      - { host: other.example.net, port: 443 }
    binaries:
      - { path: /usr/bin/curl }
";

    /// Authorize `example.com:80` for curl the way the CONNECT adapter does.
    fn authorized_decision(engine: &OpaEngine) -> EgressDecision {
        let intent = EgressIntent::connect("example.com".to_string(), 80);
        let mut decision = EgressDecision {
            intent,
            action: NetworkAction::Deny {
                reason: String::new(),
            },
            policy_generation: 0,
            identity: ProcessIdentityEvidence::Available,
            endpoint: EndpointDecision::default(),
            binary: Some(std::path::PathBuf::from("/usr/bin/curl")),
            binary_pid: None,
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let authorization = engine.authorize_egress(&decision.policy_input()).unwrap();
        decision.action = authorization.action.clone();
        decision.policy_generation = authorization.generation;
        decision.endpoint = EndpointDecision::from_authorization(&authorization);
        assert!(matches!(decision.action, NetworkAction::Allow { .. }));
        decision
    }

    #[tokio::test]
    async fn raw_relay_survives_reload_that_does_not_affect_it_and_closes_on_one_that_does() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let guard = prepare_raw_relay(None, &engine, &decision).expect("current decision pins");
        let request = request_context();
        let (mut client_peer, mut proxy_client) = tokio::io::duplex(64);
        let (mut upstream_peer, mut proxy_upstream) = tokio::io::duplex(64);
        let relay = tokio::spawn(async move {
            relay_tcp(&mut proxy_client, &mut proxy_upstream, &guard, &request).await
        });

        // Approve an endpoint for a different host.
        engine
            .reload(POLICY_REGO, CURL_EXAMPLE_AND_OTHER_POLICY)
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!relay.is_finished(), "unrelated approval must not close the relay");

        client_peer.write_all(b"ping").await.unwrap();
        let mut received = [0u8; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream_peer.read_exact(&mut received),
        )
        .await
        .expect("bytes must keep flowing after the reload")
        .unwrap();
        assert_eq!(&received, b"ping");

        // Revoke the endpoint this connection uses.
        engine.reload(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("revoking this endpoint must close the relay")
            .expect("relay task should not panic")
            .expect("stale relay closure should be clean");
    }

    #[test]
    fn http_relay_survives_unrelated_reload_but_not_a_credential_change() {
        use std::collections::HashMap;

        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let credentials = ProviderCredentialState::from_child_env_snapshot(1, HashMap::new());
        let mut request = request_context();
        request.provider_credentials = Some(credentials.clone());
        let context = prepare_http_relay(None, &engine, &decision, &request).unwrap();
        let PreparedHttpPolicy::Passthrough { generation_guard } = context.policy else {
            panic!("route-less relay should use a generation guard");
        };

        engine
            .reload(POLICY_REGO, CURL_EXAMPLE_AND_OTHER_POLICY)
            .unwrap();
        assert!(!generation_guard.is_stale(), "unchanged credentials and contract");

        // Provider credentials change together with a runtime reload.
        credentials.install_child_env_snapshot(2, HashMap::new());
        engine.reload(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap();
        assert!(
            generation_guard.is_stale(),
            "an upstream session may hold the previous credential"
        );
    }

    #[test]
    fn reload_between_authorization_and_pin_still_refuses_the_relay() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        engine
            .reload(POLICY_REGO, CURL_EXAMPLE_AND_OTHER_POLICY)
            .unwrap();

        assert!(
            prepare_raw_relay(None, &engine, &decision).is_none(),
            "revalidation applies to established relays, not to setup"
        );
    }
}
