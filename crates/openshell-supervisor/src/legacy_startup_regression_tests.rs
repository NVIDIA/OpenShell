// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use backend_setup::{BackendServices, BackendSetup, BuiltBackend, LaunchIdentity, PreparedBackend};
use openshell_core::proto::{
    GatewayMessage, GetSandboxConfigRequest, GetSandboxConfigResponse,
    GetSandboxProviderEnvironmentRequest, GetSandboxProviderEnvironmentResponse,
    ReportPolicyStatusRequest, ReportPolicyStatusResponse, ReportSandboxConfigurationRequest,
    ReportSandboxConfigurationResponse, SessionAccepted, SupervisorMessage, UpdateConfigRequest,
    UpdateConfigResponse, gateway_message, supervisor_message,
};
use openshell_isolation_interface::contract::{BackendError, ResolvedWorkloadIdentity};
use std::sync::atomic::Ordering;
use tonic::codegen::tokio_stream::{StreamExt as _, wrappers::TcpListenerStream};
use tonic::codegen::{Body, BoxFuture, BoxStream, Bytes, Service, StdError, http};

#[derive(Clone, Default)]
struct LegacyReadyProbe {
    ready_event: Arc<tokio::sync::Notify>,
    premature_ready: Arc<AtomicBool>,
    discovered: Arc<AtomicBool>,
}

#[derive(Clone)]
struct LegacyGateway {
    probe: LegacyReadyProbe,
}

impl tonic::server::NamedService for LegacyGateway {
    const NAME: &'static str = "openshell.v1.OpenShell";
}

struct LegacyConnect(LegacyReadyProbe);

impl tonic::server::StreamingService<SupervisorMessage> for LegacyConnect {
    type Response = GatewayMessage;
    type ResponseStream = BoxStream<GatewayMessage>;
    type Future = BoxFuture<tonic::Response<Self::ResponseStream>, tonic::Status>;

    fn call(
        &mut self,
        request: tonic::Request<tonic::Streaming<SupervisorMessage>>,
    ) -> Self::Future {
        let probe = self.0.clone();
        Box::pin(async move {
            let message = request
                .into_inner()
                .message()
                .await?
                .expect("supervisor hello");
            assert!(matches!(
                message.payload,
                Some(supervisor_message::Payload::Hello(_))
            ));

            // A pre-push gateway ignores workload_pending and records Ready
            // on connection. The restart's existing admission is accepted.
            probe.premature_ready.store(true, Ordering::SeqCst);
            probe.ready_event.notify_one();
            let accepted = GatewayMessage {
                payload: Some(gateway_message::Payload::SessionAccepted(SessionAccepted {
                    session_id: "legacy-session".into(),
                    ..Default::default()
                })),
            };
            let stream = futures::stream::once(async move { Ok(accepted) })
                .chain(futures::stream::pending());
            let stream: Self::ResponseStream = Box::pin(stream);
            Ok(tonic::Response::new(stream))
        })
    }
}

struct FixedUnary<R>(R);

impl<Q, R> tonic::server::UnaryService<Q> for FixedUnary<R>
where
    Q: Send + 'static,
    R: Clone + Send + 'static,
{
    type Response = R;
    type Future = BoxFuture<tonic::Response<R>, tonic::Status>;

    fn call(&mut self, _request: tonic::Request<Q>) -> Self::Future {
        let response = self.0.clone();
        Box::pin(async move { Ok(tonic::Response::new(response)) })
    }
}

async fn legacy_unary<B, Q, R>(
    request: http::Request<B>,
    response: R,
) -> http::Response<tonic::body::Body>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<StdError> + Send,
    Q: prost::Message + Default + Send + 'static,
    R: prost::Message + Default + Clone + Send + 'static,
{
    tonic::server::Grpc::new(tonic_prost::ProstCodec::<R, Q>::default())
        .unary(FixedUnary(response), request)
        .await
}

impl<B> Service<http::Request<B>> for LegacyGateway
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let probe = self.probe.clone();
        Box::pin(async move {
            let response = match request.uri().path() {
                "/openshell.v1.OpenShell/ConnectSupervisor" => {
                    tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                        GatewayMessage,
                        SupervisorMessage,
                    >::default())
                    .streaming(LegacyConnect(probe), request)
                    .await
                }
                "/openshell.v1.OpenShell/GetSandboxConfig" => {
                    let mut policy = openshell_policy::restrictive_default_policy();
                    enrich_proto_baseline_paths(&mut policy);
                    legacy_unary::<B, GetSandboxConfigRequest, _>(
                        request,
                        GetSandboxConfigResponse {
                            policy: Some(policy),
                            version: 1,
                            policy_hash: "legacy-policy".into(),
                            config_revision: 7,
                            workspace: "default".into(),
                            configuration_admitted: true,
                            configuration_instance_id: "configuration-1".into(),
                            policy_source: openshell_core::proto::PolicySource::Sandbox.into(),
                            policy_validation_failure_mode: "fail_closed".into(),
                            ..Default::default()
                        },
                    )
                    .await
                }
                "/openshell.v1.OpenShell/GetSandboxProviderEnvironment" => {
                    legacy_unary::<B, GetSandboxProviderEnvironmentRequest, _>(
                        request,
                        GetSandboxProviderEnvironmentResponse::default(),
                    )
                    .await
                }
                "/openshell.v1.OpenShell/ReportSandboxConfiguration" => {
                    legacy_unary::<B, ReportSandboxConfigurationRequest, _>(
                        request,
                        ReportSandboxConfigurationResponse::default(),
                    )
                    .await
                }
                "/openshell.v1.OpenShell/ReportPolicyStatus" => {
                    legacy_unary::<B, ReportPolicyStatusRequest, _>(
                        request,
                        ReportPolicyStatusResponse::default(),
                    )
                    .await
                }
                "/openshell.v1.OpenShell/UpdateConfig" => {
                    legacy_unary::<B, UpdateConfigRequest, _>(
                        request,
                        UpdateConfigResponse {
                            version: 1,
                            policy_hash: "legacy-policy".into(),
                            ..Default::default()
                        },
                    )
                    .await
                }
                _ => http::Response::builder()
                    .status(200)
                    .header("grpc-status", "12")
                    .header("content-type", "application/grpc")
                    .body(tonic::body::Body::empty())
                    .unwrap(),
            };
            Ok(response)
        })
    }
}

struct HeldBackendSetup {
    session_id: openshell_core::SandboxSessionId,
    probe: LegacyReadyProbe,
}

impl BackendSetup for HeldBackendSetup {
    fn backend_name(&self) -> &'static str {
        "test-held"
    }

    fn decode(
        &self,
        _payload: &[u8],
    ) -> Result<(LaunchIdentity, Box<dyn PreparedBackend>), BackendError> {
        Ok((
            LaunchIdentity {
                sandbox_id: "sb-legacy-restart".into(),
                generation: "generation-1".into(),
                session_id: self.session_id,
                workload_identity: ResolvedWorkloadIdentity::new(
                    1000,
                    1000,
                    Vec::new(),
                    "test".into(),
                    "test-image".into(),
                )?,
                vm_policy_identity: None,
            },
            Box::new(HeldPreparedBackend(self.probe.clone())),
        ))
    }
}

struct HeldPreparedBackend(LegacyReadyProbe);

#[tonic::async_trait]
impl PreparedBackend for HeldPreparedBackend {
    async fn discover_policy(
        &self,
        _bearer: openshell_core::jwt::SessionBearerTokenSlot,
    ) -> Result<(Option<String>, bool), BackendError> {
        self.0.discovered.store(true, Ordering::SeqCst);
        Ok((None, false))
    }

    fn build(self: Box<Self>, _services: BackendServices) -> Result<BuiltBackend, BackendError> {
        Err(BackendError::Attach("test boundary remains held".into()))
    }
}

#[tokio::test]
async fn config_push_regression_legacy_gateway_never_observes_ready_before_workload() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let probe = LegacyReadyProbe::default();
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(LegacyGateway {
                probe: probe.clone(),
            })
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    let session_id = openshell_core::SandboxSessionId::new();
    let auth_bundle = openshell_core::jwt::SupervisorAuthBundle {
        session_id,
        runtime_generation: openshell_core::sandbox_generation::SandboxGenerationId::parse(
            "generation-1",
        )
        .unwrap(),
        session_rotation: openshell_core::jwt::SessionRotation::new(1).unwrap(),
        auth_epoch: openshell_core::jwt::CredentialEpoch::new(1).unwrap(),
        gateway_token: openshell_core::jwt::SecretJwt::parse("test-gateway-token").unwrap(),
        gateway_expires_at: 0,
        sandbox_token: openshell_core::jwt::SecretJwt::parse("test-sandbox-token").unwrap(),
        sandbox_expires_at: 0,
        ssh_host_private_key: None,
        ocsf_otlp_headers: None,
    };
    let setup = HeldBackendSetup {
        session_id,
        probe: probe.clone(),
    };
    let config = SandboxInstanceConfig {
        command: vec!["true".into()],
        workdir: None,
        timeout_secs: 0,
        interactive: false,
        await_main_process_attachment: false,
        sandbox_id: Some("sb-legacy-restart".into()),
        sandbox: Some("legacy-restart".into()),
        container_image: String::new(),
        openshell_endpoint: Some(endpoint),
        policy_rules: None,
        policy_data: None,
        ssh_socket_path: None,
        shared_ssh_socket: false,
        upstream_proxy_args:
            openshell_supervisor_network::upstream_proxy::UpstreamProxyArgs::default(),
        additional_ca_bundle: None,
        backend_descriptor: openshell_isolation_interface::contract::BackendDescriptor {
            backend_name: "test-held".into(),
            payload: Vec::new(),
        },
        auth_bundle,
        admitted_isolation_backend: Some("test-held".into()),
        main_exit_marker: None,
        trace_context: None,
        provider_workload_api_socket: None,
        proxy_tls: openshell_supervisor_network::run::ProxyTlsFiles::default(),
    };
    let bindings = SandboxInstanceBindings::dedicated(
        &config,
        openshell_core::grpc_client::GatewayCredentials::from_auth_bundle(&config.auth_bundle)
            .unwrap(),
        openshell_ocsf::OcsfJsonSettings::default(),
    );
    let startup = run_sandbox_with_backend(&setup, config, bindings, None, None);
    tokio::pin!(startup);
    let result = tokio::select! {
        () = probe.ready_event.notified() => None,
        result = &mut startup => Some(result),
        () = tokio::time::sleep(Duration::from_secs(5)) => panic!("startup must reach the held boundary or the legacy readiness event"),
    };
    server.abort();
    let _ = server.await;
    assert!(
        probe.discovered.load(Ordering::SeqCst),
        "fixture reaches authenticated image discovery"
    );
    assert!(
        !probe.premature_ready.load(Ordering::SeqCst),
        "a legacy gateway must not observe a Ready event while the workload is still unstarted"
    );
    let error = result
        .expect("startup reaches the deliberately held backend")
        .unwrap_err();
    assert!(error.to_string().contains("test boundary remains held"));
}
