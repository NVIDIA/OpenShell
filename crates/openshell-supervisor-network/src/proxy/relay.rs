// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared relay primitives for authorized explicit-proxy egress.

use super::{EgressDecision, L7RouteSnapshot, emit_l7_tunnel_close_after_policy_change};
use crate::l7::relay::L7EvalContext;
use crate::opa::{
    NetworkAction, OpaEngine, PolicyGenerationGuard, PolicyRevalidator, TunnelPolicyEngine,
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
    // One use record per connection: every resolver and grant derived from
    // this context reports to it, and the relay's credential pin reads it.
    // Idempotent, so an adapter that already tracked the handle keeps it.
    let provider_credentials = provider_credentials
        .as_ref()
        .map(ProviderCredentialState::with_use_tracking);
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

/// Pin the generation that authorized `decision` for a relay, CONNECT setup,
/// or the forward HTTP single-request path.
///
/// The pin fails if the policy changed after authorization. Once pinned, the
/// guard follows later changes that leave the connection's contract intact;
/// see [`crate::opa::PolicyRevalidator`]. `credentials` is the connection's
/// tracked provider handle when the guarded path may inject credentials, or
/// `None` when it never does.
pub(super) fn pin_policy_generation(
    opa_engine: &Arc<OpaEngine>,
    decision: &EgressDecision,
    credentials: Option<&ProviderCredentialState>,
) -> Result<PolicyGenerationGuard> {
    opa_engine.revalidating_generation_guard(
        decision.policy_input(),
        decision.policy_generation,
        credentials,
    )
}

/// Clone an L7 evaluator for a relay or the forward HTTP single-request path.
pub(super) fn pin_l7_evaluator(
    opa_engine: &Arc<OpaEngine>,
    decision: &EgressDecision,
    expected_generation: u64,
    credentials: Option<&ProviderCredentialState>,
) -> Result<TunnelPolicyEngine> {
    let evaluator = opa_engine.clone_engine_for_tunnel(expected_generation)?;
    // The baseline must come from the generation the evaluator is pinned to,
    // so that every later generation is checked.
    let revalidator = PolicyRevalidator::capture(
        opa_engine,
        decision.policy_input(),
        expected_generation,
        credentials,
    );
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
    use openshell_core::provider_credentials::ProviderCredentialState;

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

    // --- Established relays across policy reloads ---
    //
    // A reload advances one sandbox-wide policy generation. These tests pin
    // down which reloads close an established relay. Reloads that change the
    // connection's own rules, credentials, or middleware must close it.

    /// Policy allowing curl to reach example.com:80 at L4.
    const CURL_EXAMPLE_POLICY: &str = r"
network_policies:
  web:
    name: web
    endpoints:
      - { host: example.com, port: 80 }
    binaries:
      - { path: /usr/bin/curl }
";

    /// [`CURL_EXAMPLE_POLICY`] after approving an endpoint for another host.
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

    /// example.com:80 inspected as REST.
    const CURL_EXAMPLE_REST_POLICY: &str = r#"
network_policies:
  web:
    name: web
    endpoints:
      - host: example.com
        port: 80
        protocol: rest
        enforcement: enforce
        rules:
          - allow: { method: GET, path: "/**" }
    binaries:
      - { path: /usr/bin/curl }
"#;

    /// [`CURL_EXAMPLE_REST_POLICY`] after approving an endpoint for another host.
    const CURL_EXAMPLE_REST_AND_OTHER_POLICY: &str = r#"
network_policies:
  web:
    name: web
    endpoints:
      - host: example.com
        port: 80
        protocol: rest
        enforcement: enforce
        rules:
          - allow: { method: GET, path: "/**" }
    binaries:
      - { path: /usr/bin/curl }
  other:
    name: other
    endpoints:
      - { host: other.example.net, port: 443 }
    binaries:
      - { path: /usr/bin/curl }
"#;

    /// [`CURL_EXAMPLE_REST_POLICY`] with narrower rules for example.com.
    const CURL_EXAMPLE_REST_NARROWED_POLICY: &str = r#"
network_policies:
  web:
    name: web
    endpoints:
      - host: example.com
        port: 80
        protocol: rest
        enforcement: enforce
        rules:
          - allow: { method: GET, path: "/public/**" }
    binaries:
      - { path: /usr/bin/curl }
"#;

    /// example.com:80 with a fail-open middleware, then the same chain made
    /// fail-closed. Raw relays decide the uninspectable-traffic gate at setup.
    const CURL_EXAMPLE_FAIL_OPEN_MIDDLEWARE_POLICY: &str = r#"
network_middlewares:
  scan:
    middleware: test/scan
    on_error: fail_open
    endpoints:
      include: ["example.com"]
network_policies:
  web:
    name: web
    endpoints:
      - { host: example.com, port: 80 }
    binaries:
      - { path: /usr/bin/curl }
"#;

    const CURL_EXAMPLE_FAIL_CLOSED_MIDDLEWARE_POLICY: &str = r#"
network_middlewares:
  scan:
    middleware: test/scan
    on_error: fail_closed
    endpoints:
      include: ["example.com"]
network_policies:
  web:
    name: web
    endpoints:
      - { host: example.com, port: 80 }
    binaries:
      - { path: /usr/bin/curl }
"#;

    /// Authorize curl to example.com:80 the way the CONNECT adapter does.
    fn authorized_decision(engine: &OpaEngine) -> EgressDecision {
        let input = crate::opa::NetworkInput {
            host: "example.com".to_string(),
            port: 80,
            binary_path: std::path::PathBuf::from("/usr/bin/curl"),
            binary_sha256: String::new(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let authorization = engine.authorize_egress(&input).unwrap();
        assert!(
            matches!(authorization.action, NetworkAction::Allow { .. }),
            "fixture must authorize example.com:80"
        );
        EgressDecision {
            intent: EgressIntent::connect("example.com".to_string(), 80),
            action: authorization.action.clone(),
            policy_generation: authorization.generation,
            identity: ProcessIdentityEvidence::Available,
            endpoint: EndpointDecision::from_authorization(&authorization),
            binary: Some(input.binary_path),
            binary_pid: None,
            ancestors: vec![],
            cmdline_paths: vec![],
        }
    }

    /// The L7 route the CONNECT adapter hydrates from `decision`.
    fn inspected_route(decision: &EgressDecision) -> L7RouteSnapshot {
        let configs: Vec<_> = decision
            .endpoint
            .policy_configs
            .iter()
            .filter_map(crate::l7::parse_l7_config)
            .map(|config| super::super::L7ConfigSnapshot { config })
            .collect();
        assert!(!configs.is_empty(), "fixture must select an L7 config");
        L7RouteSnapshot {
            configs,
            l7_policy_generation: decision.policy_generation,
        }
    }

    /// Run a raw relay for `decision` and report whether it closed after
    /// `reload` (within `wait`).
    async fn raw_relay_closes_after(
        engine: &Arc<OpaEngine>,
        decision: &EgressDecision,
        reload: impl FnOnce(&OpaEngine),
        wait: std::time::Duration,
    ) -> bool {
        let guard = prepare_raw_relay(None, engine, decision).expect("current decision pins");
        let request = request_context();
        let (_client_peer, mut proxy_client) = tokio::io::duplex(64);
        let (_upstream_peer, mut proxy_upstream) = tokio::io::duplex(64);
        let relay = tokio::spawn(async move {
            relay_tcp(&mut proxy_client, &mut proxy_upstream, &guard, &request).await
        });
        tokio::task::yield_now().await;

        reload(engine.as_ref());

        let Ok(joined) = tokio::time::timeout(wait, relay).await else {
            return false;
        };
        joined
            .expect("relay task should not panic")
            .expect("closure should be clean");
        true
    }

    /// Changed: approving an endpoint for another host leaves a raw relay open.
    /// Today it closes.
    #[tokio::test]
    async fn raw_relay_survives_when_an_unrelated_endpoint_is_approved() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);

        let closed = raw_relay_closes_after(
            &engine,
            &decision,
            |engine| {
                engine
                    .reload(POLICY_REGO, CURL_EXAMPLE_AND_OTHER_POLICY)
                    .unwrap();
            },
            std::time::Duration::from_millis(200),
        )
        .await;

        assert!(!closed, "approving another host must not close this relay");
    }

    /// Changed: a raw relay keeps moving bytes after an unrelated reload, and
    /// still closes when its own endpoint is revoked. Today the reload closes it.
    #[tokio::test]
    async fn raw_relay_keeps_relaying_bytes_after_an_unrelated_reload() {
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

        engine
            .reload(POLICY_REGO, CURL_EXAMPLE_AND_OTHER_POLICY)
            .unwrap();
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

        // The same relay still closes once its own endpoint is revoked.
        engine.reload(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("revoking this endpoint must close the relay")
            .expect("relay task should not panic")
            .expect("stale relay closure should be clean");
    }

    /// Unchanged: revoking the connection's endpoint closes a raw relay.
    #[tokio::test]
    async fn raw_relay_closes_when_its_endpoint_is_revoked() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);

        let closed = raw_relay_closes_after(
            &engine,
            &decision,
            |engine| engine.reload(POLICY_REGO, EMPTY_POLICY_DATA).unwrap(),
            std::time::Duration::from_secs(1),
        )
        .await;

        assert!(closed, "revoking the endpoint must close the relay");
    }

    /// Unchanged: a raw relay that was let through a fail-open chain closes
    /// when the chain becomes fail-closed, which would now refuse it.
    #[tokio::test]
    async fn raw_relay_closes_when_its_middleware_becomes_fail_closed() {
        let engine = Arc::new(
            OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_FAIL_OPEN_MIDDLEWARE_POLICY).unwrap(),
        );
        let decision = authorized_decision(&engine);

        let closed = raw_relay_closes_after(
            &engine,
            &decision,
            |engine| {
                engine
                    .reload(POLICY_REGO, CURL_EXAMPLE_FAIL_CLOSED_MIDDLEWARE_POLICY)
                    .unwrap();
            },
            std::time::Duration::from_secs(1),
        )
        .await;

        assert!(
            closed,
            "a fail-closed chain would now refuse this uninspectable stream"
        );
    }

    /// Changed: approving an endpoint for another host leaves an HTTP
    /// passthrough relay current, re-pinned to the new generation. Today it goes stale.
    #[test]
    fn http_passthrough_relay_stays_current_when_an_unrelated_endpoint_is_approved() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let request = connection_context(&decision, &empty_provider_credentials());
        let generation_guard = http_relay_guard(&engine, &decision, &request);

        engine
            .reload(POLICY_REGO, CURL_EXAMPLE_AND_OTHER_POLICY)
            .unwrap();

        assert!(!generation_guard.is_stale(), "approving another host must not close this relay");
        assert_eq!(generation_guard.captured_generation(), engine.current_generation());
    }

    /// Changed: approving an endpoint for another host leaves an inspected (L7)
    /// tunnel current. Today it goes stale.
    #[test]
    fn inspected_relay_stays_current_when_an_unrelated_endpoint_is_approved() {
        let engine =
            Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_REST_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let route = inspected_route(&decision);
        let request = request_context();
        let context = prepare_http_relay(Some(&route), &engine, &decision, &request).unwrap();
        let PreparedHttpPolicy::Inspect { evaluator, .. } = context.policy else {
            panic!("an L7 route should use a tunnel evaluator");
        };

        engine
            .reload(POLICY_REGO, CURL_EXAMPLE_REST_AND_OTHER_POLICY)
            .unwrap();

        assert!(
            !evaluator.is_stale(),
            "approving another host must not close this tunnel"
        );
    }

    /// Unchanged: narrowing the L7 rules of the connection's endpoint makes its
    /// tunnel stale.
    #[test]
    fn inspected_relay_goes_stale_when_its_rules_change() {
        let engine =
            Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_REST_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let route = inspected_route(&decision);
        let request = request_context();
        let context = prepare_http_relay(Some(&route), &engine, &decision, &request).unwrap();
        let PreparedHttpPolicy::Inspect { evaluator, .. } = context.policy else {
            panic!("an L7 route should use a tunnel evaluator");
        };

        engine
            .reload(POLICY_REGO, CURL_EXAMPLE_REST_NARROWED_POLICY)
            .unwrap();

        assert!(evaluator.is_stale(), "narrowed rules must close the tunnel");
    }

    /// Unchanged: a relay whose credential handle cannot report use goes stale
    /// when provider credentials change.
    #[test]
    fn http_relay_goes_stale_when_provider_credentials_change() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let credentials = empty_provider_credentials();
        let mut request = request_context();
        request.provider_credentials = Some(credentials.clone());
        let context = prepare_http_relay(None, &engine, &decision, &request).unwrap();
        let PreparedHttpPolicy::Passthrough { generation_guard } = context.policy else {
            panic!("route-less relay should use a generation guard");
        };

        // Provider credentials change together with a runtime reload; the
        // policy itself is identical. An upstream session (for example an
        // upgraded WebSocket) may hold the previous credential. This handle
        // does not track use, so it cannot show which credentials it carried
        // and the relay closes on the next reload.
        credentials.install_child_env_snapshot(2, std::collections::HashMap::new());
        engine.reload(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap();

        assert!(generation_guard.is_stale());
    }

    /// The request context the CONNECT adapter builds for `decision`, with
    /// the sandbox's provider credentials.
    fn connection_context(
        decision: &EgressDecision,
        credentials: &ProviderCredentialState,
    ) -> L7EvalContext {
        let mut context = http_context(
            decision,
            Some(credentials.clone()),
            None,
            None,
            openshell_core::proposals::AgentProposals::default(),
            RelaySignals {
                activity: None,
                endpoint_observation: None,
            },
        );
        context.request_default_port = Some(80);
        context
    }

    /// The HTTP relay guard the CONNECT adapter pins for `request`.
    fn http_relay_guard(
        engine: &Arc<OpaEngine>,
        decision: &EgressDecision,
        request: &L7EvalContext,
    ) -> PolicyGenerationGuard {
        let context = prepare_http_relay(None, engine, decision, request).unwrap();
        let PreparedHttpPolicy::Passthrough { generation_guard } = context.policy else {
            panic!("route-less relay should use a generation guard");
        };
        generation_guard
    }

    fn token_credentials(revision: u64, tokens: &[(&str, &str)]) -> ProviderCredentialState {
        ProviderCredentialState::from_environment(
            revision,
            tokens
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        )
    }

    /// Change provider credentials the way a runtime reload does: install the
    /// new material, then publish a policy generation.
    fn change_provider_credentials(
        engine: &OpaEngine,
        credentials: &ProviderCredentialState,
        revision: u64,
        tokens: &[(&str, &str)],
    ) {
        credentials.install_environment(
            revision,
            tokens
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        engine.reload(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap();
    }

    /// Inject `env_key` on the connection with context `request`, the way a
    /// request rewrite does: through a resolver built from its credentials.
    fn inject_static_credential(request: &L7EvalContext, env_key: &str) {
        let credentials = request.provider_credentials.as_ref().unwrap();
        let placeholder = credentials.snapshot().child_env[env_key].clone();
        let resolver = credentials
            .resolver_for_endpoint("example.com", 80, "/")
            .expect("unbound credentials resolve on any endpoint");
        assert!(resolver.resolve_placeholder(&placeholder).is_some());
    }

    /// Changed: a connection that never had a credential injected cannot hold
    /// a stale one, so it survives credential changes. Today it closes.
    #[test]
    fn http_relay_that_never_injected_survives_a_credential_change() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let credentials = token_credentials(1, &[("API_TOKEN", "a")]);
        let request = connection_context(&decision, &credentials);
        let guard = http_relay_guard(&engine, &decision, &request);

        change_provider_credentials(&engine, &credentials, 2, &[("API_TOKEN", "a2")]);

        assert!(
            !guard.is_stale(),
            "a connection that never carried credentials cannot hold a stale one"
        );
    }

    /// Unchanged: rotating a credential the connection sent closes it; an
    /// upstream session may hold the old credential.
    #[test]
    fn http_relay_closes_when_a_credential_it_injected_rotates() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let credentials = token_credentials(1, &[("API_TOKEN", "a")]);
        let request = connection_context(&decision, &credentials);
        let guard = http_relay_guard(&engine, &decision, &request);

        inject_static_credential(&request, "API_TOKEN");
        change_provider_credentials(&engine, &credentials, 2, &[("API_TOKEN", "a2")]);

        assert!(guard.is_stale(), "the upstream session may hold the old credential");
    }

    /// Changed: rotating another provider's credential, or attaching a new
    /// provider, leaves open a connection that never sent them. Today it closes.
    #[test]
    fn http_relay_survives_changes_to_credentials_it_did_not_inject() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let credentials = token_credentials(1, &[("API_TOKEN", "a"), ("OTHER_TOKEN", "b")]);
        let request = connection_context(&decision, &credentials);
        let guard = http_relay_guard(&engine, &decision, &request);
        inject_static_credential(&request, "API_TOKEN");

        // Another provider rotates, then a third provider is attached.
        change_provider_credentials(
            &engine,
            &credentials,
            2,
            &[("API_TOKEN", "a"), ("OTHER_TOKEN", "b2")],
        );
        assert!(!guard.is_stale(), "OTHER_TOKEN was never sent on this connection");
        change_provider_credentials(
            &engine,
            &credentials,
            3,
            &[("API_TOKEN", "a"), ("OTHER_TOKEN", "b2"), ("NEW_TOKEN", "c")],
        );
        assert!(!guard.is_stale());
    }

    /// Changed: a connection that first injects a credential after its provider
    /// was attached survives unrelated reloads, and closes when that credential
    /// rotates. Today the attach closes it.
    #[test]
    fn http_relay_pins_credentials_it_first_injects_after_an_attach() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let credentials = token_credentials(1, &[]);
        let request = connection_context(&decision, &credentials);
        let guard = http_relay_guard(&engine, &decision, &request);

        // A provider is attached while the connection is open, and the
        // connection then injects its credential.
        change_provider_credentials(&engine, &credentials, 2, &[("API_TOKEN", "a")]);
        assert!(!guard.is_stale());
        inject_static_credential(&request, "API_TOKEN");

        // Unrelated reloads keep it open: it holds the current credential.
        engine
            .reload(POLICY_REGO, CURL_EXAMPLE_AND_OTHER_POLICY)
            .unwrap();
        assert!(!guard.is_stale());

        // Rotating that credential closes it.
        change_provider_credentials(&engine, &credentials, 3, &[("API_TOKEN", "a2")]);
        assert!(guard.is_stale());
    }

    /// Unchanged: a reload between authorization and relay setup refuses the
    /// relay, whatever the reload changed.
    #[test]
    fn reload_between_authorization_and_pin_refuses_the_relay() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        engine
            .reload(POLICY_REGO, CURL_EXAMPLE_AND_OTHER_POLICY)
            .unwrap();

        assert!(prepare_raw_relay(None, &engine, &decision).is_none());
        let request = request_context();
        assert!(prepare_http_relay(None, &engine, &decision, &request).is_none());
    }

    // --- HTTP passthrough with middleware across reloads ---

    /// Policy data for example.com:80 with the built-in regex middleware on
    /// the host (`on_error` as given), plus `extra` policies.
    fn regex_middleware_policy(on_error: &str, extra: &str) -> String {
        format!(
            r#"
network_middlewares:
  redact:
    middleware: openshell/regex
    on_error: {on_error}
    endpoints:
      include: ["example.com"]
network_policies:
  web:
    name: web
    endpoints:
      - {{ host: example.com, port: 80 }}
    binaries:
      - {{ path: /usr/bin/curl }}
{extra}"#
        )
    }

    const OTHER_POLICY: &str = r"  other:
    name: other
    endpoints:
      - { host: other.example.net, port: 443 }
    binaries:
      - { path: /usr/bin/curl }
";

    async fn read_http_head<R: AsyncRead + Unpin>(reader: &mut R) -> Vec<u8> {
        use tokio::io::AsyncReadExt;

        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            let n = reader.read(&mut byte).await.unwrap();
            assert!(n > 0, "peer closed before a complete HTTP head");
            head.push(byte[0]);
        }
        head
    }

    /// Send one request on a kept-alive HTTP passthrough connection that runs
    /// middleware, reload the policy to `reload_data`, and send a second.
    /// Returns whether the second request reached upstream.
    async fn second_passthrough_request_reaches_upstream(reload_data: &str) -> bool {
        use openshell_supervisor_middleware::{ChainRunner, MiddlewareRegistry};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let initial = regex_middleware_policy("fail_closed", "");
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, &initial).unwrap());
        let registry = MiddlewareRegistry::connect_services(
            openshell_supervisor_middleware_builtins::services(),
            Vec::new(),
        )
        .await
        .expect("built-in registry");
        engine.set_middleware_runner_for_tests(ChainRunner::from_registry(registry));
        let decision = authorized_decision(&engine);
        let request = connection_context(&decision, &empty_provider_credentials());
        let guard = http_relay_guard(&engine, &decision, &request);

        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay_engine = Arc::clone(&engine);
        let relay = tokio::spawn(async move {
            crate::l7::relay::relay_passthrough_with_credentials(
                &mut relay_client,
                &mut relay_upstream,
                &request,
                &guard,
                Some(relay_engine.as_ref()),
            )
            .await
        });
        let timeout = std::time::Duration::from_secs(1);
        let request_bytes = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

        app.write_all(request_bytes).await.unwrap();
        tokio::time::timeout(timeout, read_http_head(&mut upstream))
            .await
            .expect("first request should reach upstream");
        upstream
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await
            .unwrap();
        tokio::time::timeout(timeout, read_http_head(&mut app))
            .await
            .expect("first response should reach the client");

        engine.reload(POLICY_REGO, reload_data).unwrap();

        app.write_all(request_bytes).await.unwrap();
        let mut second = [0u8; 1024];
        let forwarded = matches!(
            tokio::time::timeout(std::time::Duration::from_millis(500), upstream.read(&mut second))
                .await,
            Ok(Ok(n)) if n > 0
        );

        drop(app);
        drop(upstream);
        let _ = tokio::time::timeout(timeout, relay).await;
        forwarded
    }

    /// Changed: a kept-alive passthrough connection that runs middleware
    /// serves its next request after an unrelated reload. Today it drops it.
    #[tokio::test]
    async fn passthrough_middleware_connection_serves_next_request_after_unrelated_reload() {
        let reload = regex_middleware_policy("fail_closed", OTHER_POLICY);

        assert!(
            second_passthrough_request_reaches_upstream(&reload).await,
            "approving another host must not end the connection"
        );
    }

    /// Unchanged: a changed middleware chain does not apply to a kept-alive
    /// connection; its next request is dropped.
    #[tokio::test]
    async fn passthrough_middleware_connection_drops_next_request_after_its_chain_changes() {
        let reload = regex_middleware_policy("fail_open", "");

        assert!(
            !second_passthrough_request_reaches_upstream(&reload).await,
            "a changed chain must not apply to the old connection"
        );
    }

    fn empty_provider_credentials() -> ProviderCredentialState {
        ProviderCredentialState::from_child_env_snapshot(1, std::collections::HashMap::new())
    }

    // --- Policy reloads: endpoints, proto policies, middleware, coalescing ---

    /// [`CURL_EXAMPLE_POLICY`] with an endpoint inserted before example.com in
    /// the same policy, which shifts example.com's endpoint index.
    const CURL_EXAMPLE_AFTER_EARLIER_ENDPOINT_POLICY: &str = r"
network_policies:
  web:
    name: web
    endpoints:
      - { host: earlier.example.com, port: 80 }
      - { host: example.com, port: 80 }
    binaries:
      - { path: /usr/bin/curl }
";

    /// [`CURL_EXAMPLE_POLICY`] plus an endpoint for another host, numbered so
    /// consecutive reloads differ.
    fn curl_example_and_other_policy(n: usize) -> String {
        format!(
            r"
network_policies:
  web:
    name: web
    endpoints:
      - {{ host: example.com, port: 80 }}
    binaries:
      - {{ path: /usr/bin/curl }}
  other:
    name: other
    endpoints:
      - {{ host: other-{n}.example.net, port: 443 }}
    binaries:
      - {{ path: /usr/bin/curl }}
"
        )
    }

    /// Middleware selecting `host`, for [`CURL_EXAMPLE_POLICY`]'s connection.
    fn curl_example_with_middleware_for(host: &str) -> String {
        format!(
            r#"
network_middlewares:
  scan:
    middleware: test/scan
    on_error: fail_closed
    endpoints:
      include: ["{host}"]
network_policies:
  web:
    name: web
    endpoints:
      - {{ host: example.com, port: 80 }}
    binaries:
      - {{ path: /usr/bin/curl }}
"#
        )
    }

    /// The tunnel evaluator the CONNECT adapter pins for an inspected route.
    fn inspected_relay_evaluator(
        engine: &Arc<OpaEngine>,
        decision: &EgressDecision,
        request: &L7EvalContext,
    ) -> Box<TunnelPolicyEngine> {
        let route = inspected_route(decision);
        let context = prepare_http_relay(Some(&route), engine, decision, request).unwrap();
        let PreparedHttpPolicy::Inspect { evaluator, .. } = context.policy else {
            panic!("an L7 route should use a tunnel evaluator");
        };
        evaluator
    }

    /// A gateway-delivered policy: `endpoint` (example.com:80) for curl, plus
    /// `other_hosts` in a second policy. Proto conversion stamps the hash of
    /// the complete policy into every endpoint.
    fn proto_policy_with(
        endpoint: openshell_core::proto::NetworkEndpoint,
        other_hosts: &[&str],
    ) -> openshell_core::proto::SandboxPolicy {
        use openshell_core::proto::{
            FilesystemPolicy, LandlockPolicy, NetworkBinary, NetworkEndpoint, NetworkPolicyRule,
            ProcessPolicy, SandboxPolicy,
        };

        let curl = || NetworkBinary {
            path: "/usr/bin/curl".to_string(),
        };
        let mut network_policies = std::collections::HashMap::new();
        network_policies.insert(
            "web".to_string(),
            NetworkPolicyRule {
                name: "web".to_string(),
                endpoints: vec![endpoint],
                binaries: vec![curl()],
            },
        );
        if !other_hosts.is_empty() {
            network_policies.insert(
                "other".to_string(),
                NetworkPolicyRule {
                    name: "other".to_string(),
                    endpoints: other_hosts
                        .iter()
                        .map(|host| NetworkEndpoint {
                            host: (*host).to_string(),
                            port: 443,
                            ..Default::default()
                        })
                        .collect(),
                    binaries: vec![curl()],
                },
            );
        }
        SandboxPolicy {
            version: 1,
            filesystem: Some(FilesystemPolicy {
                include_workdir: true,
                read_only: vec!["/usr".to_string(), "/lib".to_string()],
                read_write: vec!["/sandbox".to_string(), "/tmp".to_string()],
            }),
            landlock: Some(LandlockPolicy {
                compatibility: "best_effort".to_string(),
            }),
            process: Some(ProcessPolicy {
                run_as_user: "sandbox".to_string(),
                run_as_group: "sandbox".to_string(),
            }),
            network_policies,
            network_middlewares: std::collections::HashMap::default(),
        }
    }

    /// example.com:80, at `path` (empty for any path), inspected as `protocol`
    /// with one `allow` rule.
    fn inspected_proto_endpoint(
        protocol: &str,
        path: &str,
        allow: openshell_core::proto::L7Allow,
    ) -> openshell_core::proto::NetworkEndpoint {
        openshell_core::proto::NetworkEndpoint {
            host: "example.com".to_string(),
            port: 80,
            path: path.to_string(),
            protocol: protocol.to_string(),
            enforcement: openshell_core::proto::NetworkEnforcementMode::Enforce as i32,
            rules: vec![openshell_core::proto::L7Rule { allow: Some(allow) }],
            ..Default::default()
        }
    }

    /// example.com:80 inspected as REST, allowing GET on `path`.
    fn example_proto_policy(
        path: &str,
        other_hosts: &[&str],
    ) -> openshell_core::proto::SandboxPolicy {
        let allow = openshell_core::proto::L7Allow {
            method: "GET".to_string(),
            path: path.to_string(),
            ..Default::default()
        };
        proto_policy_with(inspected_proto_endpoint("rest", "", allow), other_hosts)
    }

    /// example.com:80/mcp inspected as MCP, allowing the JSON-RPC `method`.
    fn example_mcp_proto_policy(
        method: &str,
        other_hosts: &[&str],
    ) -> openshell_core::proto::SandboxPolicy {
        let allow = openshell_core::proto::L7Allow {
            method: method.to_string(),
            ..Default::default()
        };
        proto_policy_with(inspected_proto_endpoint("mcp", "/mcp", allow), other_hosts)
    }

    /// Changed: an endpoint inserted before the connection's own, in the same
    /// policy, shifts its index but not its rules. Today the relay closes.
    #[tokio::test]
    async fn raw_relay_survives_an_endpoint_inserted_before_its_own() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);

        let closed = raw_relay_closes_after(
            &engine,
            &decision,
            |engine| {
                engine
                    .reload(POLICY_REGO, CURL_EXAMPLE_AFTER_EARLIER_ENDPOINT_POLICY)
                    .unwrap();
            },
            std::time::Duration::from_millis(200),
        )
        .await;

        assert!(!closed);
    }

    /// Changed: in a gateway-delivered policy every reload restamps every
    /// endpoint with the new policy hash. That stamp alone must not close an
    /// inspected tunnel. Today it closes.
    #[test]
    fn inspected_relay_from_a_proto_policy_stays_current_when_another_policy_changes() {
        let engine = Arc::new(OpaEngine::from_proto(&example_proto_policy("/**", &[])).unwrap());
        let decision = authorized_decision(&engine);
        let request = request_context();
        let evaluator = inspected_relay_evaluator(&engine, &decision, &request);

        engine
            .reload_from_proto(&example_proto_policy("/**", &["other.example.net"]))
            .unwrap();

        assert!(!evaluator.is_stale());
    }

    /// Unchanged: narrowing the rules of a gateway-delivered endpoint closes
    /// its inspected tunnel.
    #[test]
    fn inspected_relay_from_a_proto_policy_goes_stale_when_its_rules_change() {
        let engine = Arc::new(OpaEngine::from_proto(&example_proto_policy("/**", &[])).unwrap());
        let decision = authorized_decision(&engine);
        let request = request_context();
        let evaluator = inspected_relay_evaluator(&engine, &decision, &request);

        engine
            .reload_from_proto(&example_proto_policy("/public/**", &[]))
            .unwrap();

        assert!(evaluator.is_stale());
    }

    /// Changed: middleware selected for another host does not affect this
    /// connection. Today the relay closes.
    #[tokio::test]
    async fn raw_relay_survives_middleware_added_for_another_host() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let data = curl_example_with_middleware_for("other.example.net");

        let closed = raw_relay_closes_after(
            &engine,
            &decision,
            |engine| engine.reload(POLICY_REGO, &data).unwrap(),
            std::time::Duration::from_millis(200),
        )
        .await;

        assert!(!closed);
    }

    /// Unchanged: middleware newly selected for this host closes the relay,
    /// which cannot be inspected retroactively.
    #[tokio::test]
    async fn raw_relay_closes_when_middleware_is_added_for_its_host() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let data = curl_example_with_middleware_for("example.com");

        let closed = raw_relay_closes_after(
            &engine,
            &decision,
            |engine| engine.reload(POLICY_REGO, &data).unwrap(),
            std::time::Duration::from_secs(1),
        )
        .await;

        assert!(closed);
    }

    /// Changed: replacing the middleware registry cannot affect a connection
    /// that runs no middleware. Today the relay closes.
    #[tokio::test]
    async fn raw_relay_without_middleware_survives_a_registry_replacement() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);

        let closed = raw_relay_closes_after(
            &engine,
            &decision,
            |engine| {
                engine
                    .replace_middleware_registry(
                        openshell_supervisor_middleware::MiddlewareRegistry::default(),
                    )
                    .unwrap();
            },
            std::time::Duration::from_millis(200),
        )
        .await;

        assert!(!closed);
    }

    /// Unchanged: replacing the middleware registry closes a connection that
    /// runs middleware, because its tunnel holds the old runner. A reload
    /// lands before the connection checks, as reloads often coalesce.
    #[test]
    fn http_relay_with_middleware_goes_stale_when_the_registry_is_replaced() {
        let data = curl_example_with_middleware_for("example.com");
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, &data).unwrap());
        let decision = authorized_decision(&engine);
        let request = connection_context(&decision, &empty_provider_credentials());
        let guard = http_relay_guard(&engine, &decision, &request);

        engine
            .replace_middleware_registry(
                openshell_supervisor_middleware::MiddlewareRegistry::default(),
            )
            .unwrap();
        engine.reload(POLICY_REGO, &data).unwrap();

        assert!(guard.is_stale());
    }

    /// Changed: several unrelated reloads can land before a connection next
    /// checks. It re-pins through all of them. Today it goes stale.
    #[test]
    fn http_relay_stays_current_through_several_unchecked_unrelated_reloads() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let request = connection_context(&decision, &empty_provider_credentials());
        let guard = http_relay_guard(&engine, &decision, &request);

        for n in 0..3 {
            engine
                .reload(POLICY_REGO, &curl_example_and_other_policy(n))
                .unwrap();
        }

        assert!(!guard.is_stale());
        assert_eq!(guard.captured_generation(), engine.current_generation());
    }

    /// Changed: a connection checked between reloads stays open however many
    /// unrelated reloads there are. Today it goes stale at the first.
    #[test]
    fn http_relay_checked_between_unrelated_reloads_stays_current_indefinitely() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let request = connection_context(&decision, &empty_provider_credentials());
        let guard = http_relay_guard(&engine, &decision, &request);

        for n in 0..40 {
            engine
                .reload(POLICY_REGO, &curl_example_and_other_policy(n))
                .unwrap();
            assert!(!guard.is_stale(), "reload {n}");
        }
    }

    /// Unchanged: a connection that sleeps through a very long run of reloads
    /// closes, because it can no longer be checked against each of them.
    #[test]
    fn http_relay_goes_stale_after_a_long_run_of_unchecked_reloads() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let request = connection_context(&decision, &empty_provider_credentials());
        let guard = http_relay_guard(&engine, &decision, &request);

        for n in 0..40 {
            engine
                .reload(POLICY_REGO, &curl_example_and_other_policy(n))
                .unwrap();
        }

        assert!(guard.is_stale());
    }

    /// Unchanged: a reload that revoked the connection closes it even if the
    /// next reload restored access before the connection checked.
    #[test]
    fn http_relay_goes_stale_when_a_coalesced_reload_revoked_it() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let request = connection_context(&decision, &empty_provider_credentials());
        let guard = http_relay_guard(&engine, &decision, &request);

        engine.reload(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();
        engine.reload(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap();

        assert!(guard.is_stale());
    }

    /// Unchanged: a reload that changed the connection's rules closes it even
    /// if an unrelated reload followed before the connection checked.
    #[test]
    fn inspected_relay_goes_stale_when_a_coalesced_reload_changed_its_rules() {
        let engine =
            Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_REST_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let request = request_context();
        let evaluator = inspected_relay_evaluator(&engine, &decision, &request);

        engine
            .reload(POLICY_REGO, CURL_EXAMPLE_REST_NARROWED_POLICY)
            .unwrap();
        engine
            .reload(POLICY_REGO, CURL_EXAMPLE_REST_AND_OTHER_POLICY)
            .unwrap();

        assert!(evaluator.is_stale());
    }

    /// Unchanged: once a connection has been found stale it stays stale, even
    /// after its policy is restored.
    #[test]
    fn inspected_relay_stays_stale_after_its_policy_is_restored() {
        let engine =
            Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_REST_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let request = request_context();
        let evaluator = inspected_relay_evaluator(&engine, &decision, &request);

        engine
            .reload(POLICY_REGO, CURL_EXAMPLE_REST_NARROWED_POLICY)
            .unwrap();
        assert!(evaluator.is_stale());
        engine.reload(POLICY_REGO, CURL_EXAMPLE_REST_POLICY).unwrap();

        assert!(evaluator.is_stale());
    }

    // --- Credential changes: install paths and placeholder generations ---

    /// Changed: `install_prepared`, the path runtime reloads use, rotates a
    /// credential this connection never sent. Today the relay closes.
    #[test]
    fn http_relay_survives_install_prepared_rotating_a_credential_it_did_not_inject() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let credentials = token_credentials(1, &[("API_TOKEN", "a"), ("OTHER_TOKEN", "b")]);
        let request = connection_context(&decision, &credentials);
        let guard = http_relay_guard(&engine, &decision, &request);
        inject_static_credential(&request, "API_TOKEN");

        credentials.install_prepared(&token_credentials(
            2,
            &[("API_TOKEN", "a"), ("OTHER_TOKEN", "b2")],
        ));
        engine.reload(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap();

        assert!(!guard.is_stale());
    }

    /// Unchanged: `install_prepared` rotating a credential this connection
    /// sent closes the relay.
    #[test]
    fn http_relay_closes_when_install_prepared_rotates_a_credential_it_injected() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let credentials = token_credentials(1, &[("API_TOKEN", "a")]);
        let request = connection_context(&decision, &credentials);
        let guard = http_relay_guard(&engine, &decision, &request);
        inject_static_credential(&request, "API_TOKEN");

        credentials.install_prepared(&token_credentials(2, &[("API_TOKEN", "a2")]));
        engine.reload(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap();

        assert!(guard.is_stale());
    }

    /// Changed: reinstalling identical credentials changes nothing a
    /// connection holds. Today the relay closes.
    #[test]
    fn http_relay_survives_a_reinstall_of_identical_credentials() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let credentials = token_credentials(1, &[("API_TOKEN", "a")]);
        let request = connection_context(&decision, &credentials);
        let guard = http_relay_guard(&engine, &decision, &request);
        inject_static_credential(&request, "API_TOKEN");

        change_provider_credentials(&engine, &credentials, 2, &[("API_TOKEN", "a")]);

        assert!(!guard.is_stale());
    }

    /// Changed: hiding a credential from future child processes does not
    /// revoke it; the proxy still resolves it. Today the relay closes.
    #[test]
    fn http_relay_survives_suppression_of_a_credential_it_injected() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let credentials = token_credentials(1, &[("API_TOKEN", "a")]);
        let request = connection_context(&decision, &credentials);
        let guard = http_relay_guard(&engine, &decision, &request);
        inject_static_credential(&request, "API_TOKEN");

        credentials.remove_env_key("API_TOKEN");
        engine.reload(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap();

        assert!(!guard.is_stale());
    }

    /// Changed: a long-running process may still hold a placeholder from a
    /// generation that has aged out; it falls back to the current value, so
    /// the connection holds the current credential. Today the relay closes.
    #[test]
    fn http_relay_survives_after_an_aged_out_placeholder_falls_back_to_the_current_value() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let credentials = token_credentials(1, &[("API_TOKEN", "a")]);
        let first_placeholder = credentials.snapshot().child_env["API_TOKEN"].clone();
        let request = connection_context(&decision, &credentials);
        let guard = http_relay_guard(&engine, &decision, &request);

        // More identical reinstalls than the retained generations.
        for revision in 2..=10 {
            change_provider_credentials(&engine, &credentials, revision, &[("API_TOKEN", "a")]);
            assert!(!guard.is_stale());
        }
        let resolver = request
            .provider_credentials
            .as_ref()
            .unwrap()
            .resolver_for_endpoint("example.com", 80, "/")
            .unwrap();
        assert_eq!(resolver.resolve_placeholder(&first_placeholder), Some("a"));
        engine
            .reload(POLICY_REGO, CURL_EXAMPLE_AND_OTHER_POLICY)
            .unwrap();

        assert!(!guard.is_stale());
    }

    /// Unchanged: a connection that sent a credential closes when it rotates,
    /// even if it rotated twice before the connection checked.
    #[test]
    fn http_relay_closes_after_coalesced_rotations_of_a_credential_it_injected() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let credentials = token_credentials(1, &[("API_TOKEN", "a")]);
        let request = connection_context(&decision, &credentials);
        let guard = http_relay_guard(&engine, &decision, &request);
        inject_static_credential(&request, "API_TOKEN");

        change_provider_credentials(&engine, &credentials, 2, &[("API_TOKEN", "b")]);
        change_provider_credentials(&engine, &credentials, 3, &[("API_TOKEN", "c")]);

        assert!(guard.is_stale());
    }

    /// Unchanged: detaching the provider of a credential this connection sent
    /// closes the relay.
    #[test]
    fn http_relay_closes_when_the_provider_of_a_credential_it_injected_is_detached() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let credentials = token_credentials(1, &[("API_TOKEN", "a"), ("OTHER_TOKEN", "b")]);
        let request = connection_context(&decision, &credentials);
        let guard = http_relay_guard(&engine, &decision, &request);
        inject_static_credential(&request, "API_TOKEN");

        change_provider_credentials(&engine, &credentials, 2, &[("OTHER_TOKEN", "b")]);

        assert!(guard.is_stale());
    }

    // --- Endpoint status of a kept-alive MCP tunnel across reloads ---

    /// The endpoint config a connection to example.com:80/mcp selects under
    /// `policy`, carrying the policy's stamped hash and the endpoint's id.
    fn mcp_endpoint_config(
        policy: &openshell_core::proto::SandboxPolicy,
    ) -> crate::l7::L7EndpointConfig {
        let engine = OpaEngine::from_proto(policy).unwrap();
        let decision = authorized_decision(&engine);
        inspected_route(&decision).configs.remove(0).config
    }

    /// Publish the endpoint-status inventory of the policy `config` came from,
    /// as the supervisor does after installing a configuration.
    async fn publish_mcp_inventory(
        sender: &openshell_core::endpoint_status::EndpointObservationSender,
        receiver: &mut openshell_core::endpoint_status::EndpointStatusReceiver,
        config: &crate::l7::L7EndpointConfig,
    ) {
        use openshell_core::endpoint_status::{
            EndpointConfigVersion, EndpointInventoryEntry, EndpointStatusCommand,
        };

        sender
            .reset(
                EndpointConfigVersion {
                    policy_hash: config.policy_hash.clone(),
                    provider_env_revision: 1,
                },
                vec![EndpointInventoryEntry {
                    endpoint_id: config.endpoint_id.clone(),
                    uses_provider_credentials: false,
                }],
            )
            .await
            .expect("publish endpoint inventory");
        assert!(matches!(
            receiver.recv().await,
            Some(EndpointStatusCommand::Reset { .. })
        ));
    }

    /// Send one MCP `initialize` on the connection; returns whether it reached
    /// upstream, answering it there if so.
    async fn mcp_exchange<A, S>(app: &mut A, server: &mut S) -> bool
    where
        A: AsyncRead + AsyncWrite + Unpin,
        S: AsyncRead + AsyncWrite + Unpin,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;
        let head = format!(
            "POST /mcp HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        app.write_all(head.as_bytes()).await.unwrap();
        app.write_all(body).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_millis(500), async {
            let mut forwarded = Vec::new();
            while !forwarded.ends_with(body) {
                let mut buffer = [0u8; 1024];
                let n = server.read(&mut buffer).await.ok()?;
                if n == 0 {
                    return None;
                }
                forwarded.extend_from_slice(&buffer[..n]);
            }
            Some(())
        })
        .await;
        if !matches!(received, Ok(Some(()))) {
            return false;
        }
        server
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), read_http_head(app))
            .await
            .expect("the response should reach the client");
        true
    }

    /// The policy hash of the next MCP result reported, if one is reported.
    async fn next_mcp_report(
        receiver: &mut openshell_core::endpoint_status::EndpointStatusReceiver,
    ) -> Option<String> {
        use openshell_core::endpoint_status::{EndpointResult, EndpointStatusCommand};

        match tokio::time::timeout(std::time::Duration::from_millis(500), receiver.recv()).await {
            Ok(Some(EndpointStatusCommand::Observe {
                config_version,
                result: EndpointResult::HttpResponseReceived,
                ..
            })) => Some(config_version.policy_hash),
            _ => None,
        }
    }

    /// What a kept-alive MCP tunnel reported across a policy change.
    struct McpStatusAcrossReload {
        /// The policy hash the exchange before the change was reported against.
        first_reported: Option<String>,
        /// Whether the exchange after the change reached upstream.
        second_forwarded: bool,
        /// The policy hash the exchange after the change was reported against.
        second_reported: Option<String>,
    }

    /// Open an MCP tunnel under [`example_mcp_proto_policy`] with its endpoint
    /// inventory published, complete one exchange, then reload the runtime to
    /// `reload_to` (if any), publish the inventory of `publish_for` (if any),
    /// and attempt a second exchange on the same connection.
    async fn mcp_status_across_reload(
        reload_to: Option<openshell_core::proto::SandboxPolicy>,
        publish_for: Option<openshell_core::proto::SandboxPolicy>,
    ) -> McpStatusAcrossReload {
        let initial = example_mcp_proto_policy("initialize", &[]);
        let engine = Arc::new(OpaEngine::from_proto(&initial).unwrap());
        let decision = authorized_decision(&engine);
        let route = inspected_route(&decision);
        let (sender, mut receiver) = openshell_core::endpoint_status::endpoint_status_channel();
        publish_mcp_inventory(&sender, &mut receiver, &route.configs[0].config).await;
        let mut request = http_context(
            &decision,
            None,
            None,
            None,
            openshell_core::proposals::AgentProposals::default(),
            RelaySignals {
                activity: None,
                endpoint_observation: Some(sender.clone()),
            },
        );
        request.request_default_port = Some(80);
        let context = prepare_http_relay(Some(&route), &engine, &decision, &request).unwrap();

        let (mut app, mut client) = tokio::io::duplex(8192);
        let (mut upstream, mut server) = tokio::io::duplex(8192);
        let relay = relay_http_stream(&mut client, &mut upstream, context);
        let drive = async {
            assert!(mcp_exchange(&mut app, &mut server).await, "first exchange");
            let first_reported = next_mcp_report(&mut receiver).await;

            if let Some(policy) = &reload_to {
                engine.reload_from_proto(policy).unwrap();
            }
            if let Some(policy) = &publish_for {
                publish_mcp_inventory(&sender, &mut receiver, &mcp_endpoint_config(policy)).await;
            }

            let second_forwarded = mcp_exchange(&mut app, &mut server).await;
            let second_reported = next_mcp_report(&mut receiver).await;
            drop(app);
            drop(server);
            McpStatusAcrossReload {
                first_reported,
                second_forwarded,
                second_reported,
            }
        };
        let (_, outcome) = tokio::join!(relay, drive);
        assert_eq!(
            outcome.first_reported.as_deref(),
            Some(route.configs[0].config.policy_hash.as_str()),
            "the exchange before any change is reported against the policy in force"
        );
        outcome
    }

    /// Changed: after an unrelated reload, and once the supervisor publishes
    /// the new policy's endpoint inventory, a kept-alive MCP tunnel keeps
    /// reporting its exchanges, against the new policy. Today the reload
    /// closes the tunnel, so nothing more is exchanged or reported.
    #[tokio::test]
    async fn mcp_tunnel_keeps_reporting_endpoint_status_after_an_unrelated_reload() {
        let reloaded = example_mcp_proto_policy("initialize", &["other.example.net"]);
        let reloaded_hash = mcp_endpoint_config(&reloaded).policy_hash;

        let outcome = mcp_status_across_reload(Some(reloaded.clone()), Some(reloaded)).await;

        assert!(outcome.second_forwarded, "the tunnel must stay open");
        assert_eq!(
            outcome.second_reported,
            Some(reloaded_hash),
            "the exchange must be reported against the policy now in force"
        );
    }

    /// Unchanged: until the supervisor publishes the reloaded policy's
    /// inventory, results cannot be attributed to the inventory of the policy
    /// that was replaced, so the exchange after the reload is not reported.
    #[tokio::test]
    async fn mcp_tunnel_reports_nothing_until_the_reloaded_policy_inventory_is_published() {
        let reloaded = example_mcp_proto_policy("initialize", &["other.example.net"]);

        let outcome = mcp_status_across_reload(Some(reloaded), None).await;

        assert_eq!(outcome.second_reported, None);
    }

    /// Unchanged: an inventory published ahead of the runtime, for a policy
    /// the tunnel is not running under, receives none of its results.
    #[tokio::test]
    async fn mcp_tunnel_reports_nothing_against_an_inventory_published_ahead_of_its_policy() {
        let upcoming = example_mcp_proto_policy("initialize", &["other.example.net"]);

        let outcome = mcp_status_across_reload(None, Some(upcoming)).await;

        assert!(outcome.second_forwarded, "nothing changed for the running tunnel");
        assert_eq!(outcome.second_reported, None);
    }

    /// Unchanged: a reload that changes the MCP endpoint's rules closes the
    /// tunnel, so nothing more is exchanged or reported on it.
    #[tokio::test]
    async fn mcp_tunnel_closes_and_reports_nothing_when_its_rules_change() {
        let reloaded = example_mcp_proto_policy("tools/list", &[]);

        let outcome = mcp_status_across_reload(Some(reloaded.clone()), Some(reloaded)).await;

        assert!(!outcome.second_forwarded);
        assert_eq!(outcome.second_reported, None);
    }

    // --- Credentials injected through a stable-handle placeholder ---

    /// `API_KEY` bound to example.com:80 with a stable workload handle, so its
    /// placeholder survives rotations, plus an unbound `OTHER_TOKEN`.
    fn stable_handle_bindings()
    -> std::collections::HashMap<String, openshell_core::proto::StaticCredentialBinding> {
        std::collections::HashMap::from([(
            "API_KEY".to_string(),
            openshell_core::proto::StaticCredentialBinding {
                endpoints: vec![openshell_core::proto::StaticCredentialEndpointBinding {
                    host: "example.com".to_string(),
                    port: 80,
                    path: "/**".to_string(),
                }],
                credential_identity: "provider:API_KEY".to_string(),
                workload_credential_handle: "a".repeat(64),
            },
        )])
    }

    fn stable_handle_tokens(
        api_key: &str,
        other: &str,
    ) -> std::collections::HashMap<String, String> {
        std::collections::HashMap::from([
            ("API_KEY".to_string(), api_key.to_string()),
            ("OTHER_TOKEN".to_string(), other.to_string()),
        ])
    }

    fn stable_handle_credentials(api_key: &str, other: &str) -> ProviderCredentialState {
        ProviderCredentialState::from_bound_environment_with_stable_placeholders(
            1,
            stable_handle_tokens(api_key, other),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            stable_handle_bindings(),
            vec![],
            vec!["API_KEY".to_string()],
        )
        .expect("valid stable-handle binding")
    }

    /// Install new values the way a runtime reload does, keeping the handle.
    fn reinstall_stable_handle_credentials(
        engine: &OpaEngine,
        credentials: &ProviderCredentialState,
        revision: u64,
        api_key: &str,
        other: &str,
    ) {
        credentials
            .install_bound_environment_with_stable_placeholders(
                revision,
                stable_handle_tokens(api_key, other),
                std::collections::HashMap::new(),
                std::collections::HashMap::new(),
                stable_handle_bindings(),
                vec![],
                vec!["API_KEY".to_string()],
            )
            .expect("valid stable-handle binding");
        engine.reload(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap();
    }

    /// Send `API_KEY` on the connection with context `request` through its
    /// stable-handle placeholder, as an Authorization header rewrite does.
    fn inject_through_stable_handle(request: &L7EvalContext) {
        let credentials = request.provider_credentials.as_ref().unwrap();
        let placeholder = credentials.snapshot().child_env["API_KEY"].clone();
        assert!(
            placeholder.starts_with("openshell:resolve:env:s"),
            "fixture must issue a stable-handle placeholder, got {placeholder}"
        );
        let resolver = credentials
            .resolver_for_endpoint("example.com", 80, "/")
            .expect("bound credential resolves on its endpoint");
        let rewritten = resolver
            .rewrite_header_value_for_name("Authorization", &placeholder)
            .expect("stable-handle placeholder resolves");
        assert!(rewritten.is_some());
    }

    /// Changed: a connection that sent a credential through its stable-handle
    /// placeholder survives a rotation of another credential, and keeps its
    /// placeholder. Today the relay closes.
    #[test]
    fn http_relay_that_injected_through_a_stable_handle_survives_an_unrelated_rotation() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let credentials = stable_handle_credentials("key-1", "other-1");
        let placeholder = credentials.snapshot().child_env["API_KEY"].clone();
        let request = connection_context(&decision, &credentials);
        let guard = http_relay_guard(&engine, &decision, &request);
        inject_through_stable_handle(&request);

        reinstall_stable_handle_credentials(&engine, &credentials, 2, "key-1", "other-2");

        assert_eq!(credentials.snapshot().child_env["API_KEY"], placeholder);
        assert!(!guard.is_stale());
    }

    /// Unchanged: a connection that sent a credential through its stable-handle
    /// placeholder closes when the value behind the handle rotates, even
    /// though the placeholder itself is unchanged.
    #[test]
    fn http_relay_closes_when_the_credential_behind_its_stable_handle_rotates() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let credentials = stable_handle_credentials("key-1", "other-1");
        let placeholder = credentials.snapshot().child_env["API_KEY"].clone();
        let request = connection_context(&decision, &credentials);
        let guard = http_relay_guard(&engine, &decision, &request);
        inject_through_stable_handle(&request);

        reinstall_stable_handle_credentials(&engine, &credentials, 2, "key-2", "other-1");

        assert_eq!(credentials.snapshot().child_env["API_KEY"], placeholder);
        assert!(guard.is_stale());
    }

    // --- Credentials injected through other placeholder forms ---

    /// Changed: a connection that sent a credential through its canonical
    /// placeholder (`openshell:resolve:env:KEY`, the documented form) sent the
    /// current value, so it survives a rotation of another credential. Today
    /// the relay closes.
    #[test]
    fn http_relay_that_injected_through_a_canonical_placeholder_survives_an_unrelated_rotation() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let decision = authorized_decision(&engine);
        let credentials = token_credentials(1, &[("API_TOKEN", "a"), ("OTHER_TOKEN", "b")]);
        let request = connection_context(&decision, &credentials);
        let guard = http_relay_guard(&engine, &decision, &request);
        let resolver = request
            .provider_credentials
            .as_ref()
            .unwrap()
            .resolver_for_endpoint("example.com", 80, "/")
            .expect("unbound credentials resolve on any endpoint");
        assert_eq!(
            resolver.resolve_placeholder(&openshell_core::secrets::placeholder_for_env_key(
                "API_TOKEN"
            )),
            Some("a")
        );

        change_provider_credentials(
            &engine,
            &credentials,
            2,
            &[("API_TOKEN", "a"), ("OTHER_TOKEN", "b2")],
        );

        assert!(!guard.is_stale());
    }

    /// Unchanged: a connection that sent a credential through a placeholder
    /// from an older, still-retained revision sent a value that is no longer
    /// current, so it closes on the next reload.
    #[test]
    fn http_relay_closes_after_injecting_through_an_older_retained_revision() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let credentials = token_credentials(1, &[("API_TOKEN", "a")]);
        let old_placeholder = credentials.snapshot().child_env["API_TOKEN"].clone();
        change_provider_credentials(&engine, &credentials, 2, &[("API_TOKEN", "a2")]);
        let decision = authorized_decision(&engine);
        let request = connection_context(&decision, &credentials);
        let guard = http_relay_guard(&engine, &decision, &request);
        let resolver = request
            .provider_credentials
            .as_ref()
            .unwrap()
            .resolver_for_endpoint("example.com", 80, "/")
            .expect("unbound credentials resolve on any endpoint");
        assert_eq!(resolver.resolve_placeholder(&old_placeholder), Some("a"));

        engine.reload(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap();

        assert!(guard.is_stale());
    }

    /// Changed: provider revisions are sandbox-wide, so rotating another
    /// credential reissues every placeholder at the new revision. A process
    /// still holding the previous revision's placeholder for an unchanged
    /// credential sends the current value, so its connection survives the next
    /// reload. Today the relay closes.
    #[test]
    fn http_relay_survives_after_injecting_an_unchanged_credential_through_an_older_revision() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap());
        let credentials = token_credentials(1, &[("API_TOKEN", "a"), ("OTHER_TOKEN", "b")]);
        let old_placeholder = credentials.snapshot().child_env["API_TOKEN"].clone();
        change_provider_credentials(
            &engine,
            &credentials,
            2,
            &[("API_TOKEN", "a"), ("OTHER_TOKEN", "b2")],
        );
        assert_ne!(credentials.snapshot().child_env["API_TOKEN"], old_placeholder);
        let decision = authorized_decision(&engine);
        let request = connection_context(&decision, &credentials);
        let guard = http_relay_guard(&engine, &decision, &request);
        let resolver = request
            .provider_credentials
            .as_ref()
            .unwrap()
            .resolver_for_endpoint("example.com", 80, "/")
            .expect("unbound credentials resolve on any endpoint");
        assert_eq!(resolver.resolve_placeholder(&old_placeholder), Some("a"));

        engine.reload(POLICY_REGO, CURL_EXAMPLE_POLICY).unwrap();

        assert!(!guard.is_stale());
    }
}
