// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Backward-compatibility rules for the two HTTP middleware protocols.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures::StreamExt as _;
use openshell_core::extension_protocol::{
    extension_metadata, extension_metadata_with_requirements, peer_supports,
};
use openshell_core::proto::middleware::v1::http_request_pre_credentials_server::{
    HttpRequestPreCredentials, HttpRequestPreCredentialsServer,
};
use openshell_core::proto::middleware::v1::http_response_pre_return_server::{
    HttpResponsePreReturn, HttpResponsePreReturnServer,
};
use openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddlewareServer;
use openshell_core::proto::{
    HttpContinue, HttpPreflight, HttpPreflightResult, HttpRequestPreflightHead, HttpRequestResult,
    HttpResponseBodyMode, HttpResponseEvent, HttpResponseEventResult, HttpResponsePreflightInspect,
    HttpResponsePreflightResult, HttpResponsePreflightSkip, HttpResult, WebSocketSessionEvent,
    http_event, http_preflight, http_preflight_result, http_response_event,
    http_response_event_result, http_response_preflight_result, http_result,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};

use super::*;
use crate::compat_tests::harness::{
    RequestChains, RequestInput, ResponseCase, preflight_response, run_response,
};

const MAX_PAYLOAD_BYTES: u64 = 4096;

/// What a test service advertises at Describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Build {
    /// A 0.1.x service: legacy HTTP bindings and no capability requirements.
    Legacy,
    /// A version 2-only service that requires `http-v2`.
    V2Only,
    /// Version 2 bindings for peers that advertise `http-v2`, legacy otherwise.
    Dual,
}

/// gRPC middleware service that serves both HTTP protocols. A version 2-only
/// build answers the legacy RPCs with `UNIMPLEMENTED`.
#[derive(Clone)]
struct CompatService {
    build: Arc<Mutex<Build>>,
    describe_capabilities: Arc<Mutex<Vec<Vec<String>>>>,
    legacy_calls: Arc<AtomicUsize>,
}

impl CompatService {
    fn new(build: Build) -> Self {
        Self {
            build: Arc::new(Mutex::new(build)),
            describe_capabilities: Arc::default(),
            legacy_calls: Arc::default(),
        }
    }

    fn build(&self) -> Build {
        *self.build.lock().expect("build")
    }

    /// Replace the build behind the same endpoint, as an operator upgrading
    /// the service would. Registries keep their cached manifests.
    fn switch_to(&self, build: Build) {
        *self.build.lock().expect("build") = build;
    }

    fn caller_advertised_http_v2(&self) -> Vec<bool> {
        self.describe_capabilities
            .lock()
            .expect("describe capabilities")
            .iter()
            .map(|capabilities| {
                capabilities
                    .iter()
                    .any(|capability| capability == SUPERVISOR_MIDDLEWARE_HTTP_V2)
            })
            .collect()
    }

    fn legacy_calls(&self) -> usize {
        self.legacy_calls.load(Ordering::SeqCst)
    }

    fn manifest(&self, caller_supports_http_v2: bool) -> MiddlewareManifest {
        let v2 = match self.build() {
            Build::Legacy => false,
            Build::V2Only => true,
            Build::Dual => caller_supports_http_v2,
        };
        let http_binding = |operation: SupervisorMiddlewareOperation, phase| MiddlewareBinding {
            operation: operation as i32,
            phase: phase as i32,
            max_payload_bytes: MAX_PAYLOAD_BYTES,
            request_timeout: None,
            http_protocol_version: if v2 { 2 } else { 0 },
            supported_http_body_modes: if v2 {
                vec![HttpBodyMode::Buffered as i32, HttpBodyMode::Stream as i32]
            } else {
                Vec::new()
            },
        };
        let bindings = vec![
            http_binding(
                SupervisorMiddlewareOperation::HttpRequest,
                SupervisorMiddlewarePhase::PreCredentials,
            ),
            http_binding(
                SupervisorMiddlewareOperation::HttpResponse,
                SupervisorMiddlewarePhase::PreReturn,
            ),
        ];
        let extension = match self.build() {
            Build::Legacy => extension_metadata(
                ExtensionFamily::SupervisorMiddleware,
                "example/guard",
                "0.1.2",
                [],
            ),
            Build::V2Only => extension_metadata_with_requirements(
                ExtensionFamily::SupervisorMiddleware,
                "example/guard",
                "1.0.0",
                [],
                [SUPERVISOR_MIDDLEWARE_HTTP_V2.to_string()],
            ),
            Build::Dual => extension_metadata(
                ExtensionFamily::SupervisorMiddleware,
                "example/guard",
                "0.9.0",
                [SUPERVISOR_MIDDLEWARE_HTTP_V2.to_string()],
            ),
        };
        MiddlewareManifest {
            name: "example/guard".into(),
            service_version: String::new(),
            bindings,
            expected_audience: String::new(),
            extension: Some(extension),
        }
    }
}

#[tonic::async_trait]
impl SupervisorMiddleware for CompatService {
    type EvaluateWebSocketSessionStream = WebSocketResponseStream;

    async fn describe(
        &self,
        request: Request<MiddlewareDescribeRequest>,
    ) -> std::result::Result<TonicResponse<MiddlewareManifest>, TonicStatus> {
        let gateway = request.into_inner().gateway.unwrap_or_default();
        let caller_supports_http_v2 = peer_supports(&gateway, SUPERVISOR_MIDDLEWARE_HTTP_V2);
        self.describe_capabilities
            .lock()
            .expect("describe capabilities")
            .push(gateway.supported_capabilities);
        Ok(TonicResponse::new(self.manifest(caller_supports_http_v2)))
    }

    async fn validate_config(
        &self,
        _request: Request<ValidateConfigRequest>,
    ) -> std::result::Result<TonicResponse<ValidateConfigResponse>, TonicStatus> {
        Ok(TonicResponse::new(ValidateConfigResponse {
            valid: true,
            reason: String::new(),
        }))
    }

    async fn evaluate_http_request(
        &self,
        _request: Request<HttpRequestEvaluation>,
    ) -> std::result::Result<TonicResponse<HttpRequestResult>, TonicStatus> {
        if self.build() == Build::V2Only {
            return Err(TonicStatus::unimplemented("version 2-only build"));
        }
        self.legacy_calls.fetch_add(1, Ordering::SeqCst);
        Ok(TonicResponse::new(HttpRequestResult {
            decision: Decision::Allow as i32,
            ..Default::default()
        }))
    }

    async fn evaluate_web_socket_session(
        &self,
        _request: Request<tonic::Streaming<WebSocketSessionEvent>>,
    ) -> std::result::Result<TonicResponse<Self::EvaluateWebSocketSessionStream>, TonicStatus> {
        Err(TonicStatus::unimplemented("HTTP-only test middleware"))
    }
}

/// Answer every version 2 preflight with Continue.
fn continue_stream(mut events: tonic::Streaming<HttpEvent>) -> HttpResultStream {
    let (sender, receiver) = mpsc::channel(4);
    tokio::spawn(async move {
        while let Some(Ok(event)) = events.next().await {
            if matches!(event.event, Some(http_event::Event::Preflight(_))) {
                let result = HttpResult {
                    result: Some(http_result::Result::PreflightResult(HttpPreflightResult {
                        decision: Some(http_preflight_result::Decision::ContinueWithoutBody(
                            HttpContinue {},
                        )),
                        ..Default::default()
                    })),
                };
                if sender.send(Ok(result)).await.is_err() {
                    return;
                }
            }
        }
    });
    Box::pin(ReceiverStream::new(receiver))
}

#[tonic::async_trait]
impl HttpRequestPreCredentials for CompatService {
    type EvaluateHttpStream = HttpResultStream;

    async fn evaluate_http(
        &self,
        request: Request<tonic::Streaming<HttpEvent>>,
    ) -> std::result::Result<TonicResponse<Self::EvaluateHttpStream>, TonicStatus> {
        Ok(TonicResponse::new(continue_stream(request.into_inner())))
    }
}

#[tonic::async_trait]
impl HttpResponsePreReturn for CompatService {
    type EvaluateStream = HttpResponseResultStream;
    type EvaluateHttpStream = HttpResultStream;

    async fn evaluate(
        &self,
        request: Request<tonic::Streaming<HttpResponseEvent>>,
    ) -> std::result::Result<TonicResponse<Self::EvaluateStream>, TonicStatus> {
        if self.build() == Build::V2Only {
            return Err(TonicStatus::unimplemented("version 2-only build"));
        }
        self.legacy_calls.fetch_add(1, Ordering::SeqCst);
        let mut events = request.into_inner();
        let (sender, receiver) = mpsc::channel(4);
        tokio::spawn(async move {
            while let Some(Ok(event)) = events.next().await {
                if matches!(event.event, Some(http_response_event::Event::Preflight(_))) {
                    let result = HttpResponseEventResult {
                        result: Some(http_response_event_result::Result::PreflightResult(
                            HttpResponsePreflightResult {
                                action: Some(http_response_preflight_result::Action::Skip(
                                    HttpResponsePreflightSkip {},
                                )),
                                ..Default::default()
                            },
                        )),
                    };
                    if sender.send(Ok(result)).await.is_err() {
                        return;
                    }
                }
            }
        });
        Ok(TonicResponse::new(Box::pin(ReceiverStream::new(receiver))))
    }

    async fn evaluate_http(
        &self,
        request: Request<tonic::Streaming<HttpEvent>>,
    ) -> std::result::Result<TonicResponse<Self::EvaluateHttpStream>, TonicStatus> {
        Ok(TonicResponse::new(continue_stream(request.into_inner())))
    }
}

/// Serve `service` until the returned sender is dropped.
async fn serve(service: CompatService) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test middleware");
    let address = listener.local_addr().expect("test middleware address");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tonic::transport::Server::builder()
        .add_service(SupervisorMiddlewareServer::new(service.clone()))
        .add_service(HttpRequestPreCredentialsServer::new(service.clone()))
        .add_service(HttpResponsePreReturnServer::new(service))
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
            let _ = shutdown_rx.await;
        });
    tokio::spawn(server);
    (address, shutdown_tx)
}

fn registration(name: &str, address: SocketAddr) -> SupervisorMiddlewareService {
    SupervisorMiddlewareService {
        name: name.into(),
        grpc_endpoint: format!("http://{address}"),
        max_payload_bytes: MAX_PAYLOAD_BYTES,
        ..Default::default()
    }
}

fn entry(name: &str, implementation: &str, on_error: OnError) -> ChainEntry {
    ChainEntry {
        name: name.into(),
        implementation: implementation.into(),
        order: 0,
        config: prost_types::Struct::default(),
        on_error,
    }
}

fn request_input() -> RequestInput {
    RequestInput {
        request_id: "req".into(),
        sandbox_id: "sbx-id".into(),
        sandbox_name: "sbx".into(),
        workspace: "default".into(),
        scheme: "https".into(),
        host: "api.example.com".into(),
        port: 443,
        method: "POST".into(),
        path: "/v1".into(),
        query: String::new(),
        headers: Vec::new(),
        connection_nominated_headers: Vec::new(),
        body: b"hello".to_vec(),
    }
}

fn binding(operation: SupervisorMiddlewareOperation, version: u32) -> MiddlewareBinding {
    let phase = if operation == SupervisorMiddlewareOperation::HttpResponse {
        SupervisorMiddlewarePhase::PreReturn
    } else {
        SupervisorMiddlewarePhase::PreCredentials
    };
    MiddlewareBinding {
        operation: operation as i32,
        phase: phase as i32,
        max_payload_bytes: MAX_PAYLOAD_BYTES,
        http_protocol_version: version,
        ..Default::default()
    }
}

fn manifest_with(bindings: Vec<MiddlewareBinding>, extension: PeerMetadata) -> MiddlewareManifest {
    MiddlewareManifest {
        name: "example/guard".into(),
        service_version: String::new(),
        bindings,
        expected_audience: String::new(),
        extension: Some(extension),
    }
}

fn legacy_extension() -> PeerMetadata {
    extension_metadata(
        ExtensionFamily::SupervisorMiddleware,
        "example/guard",
        "test",
        [],
    )
}

#[derive(Default)]
struct RecordingObserver {
    contract_failures: Mutex<Vec<ContractFailure>>,
    fail_open_not_applied: Mutex<Vec<FailOpenNotApplied>>,
}

impl RecordingObserver {
    fn contract_failures(&self) -> Vec<ContractFailure> {
        self.contract_failures
            .lock()
            .expect("contract failures")
            .clone()
    }

    fn fail_open_not_applied(&self) -> Vec<FailOpenNotApplied> {
        self.fail_open_not_applied
            .lock()
            .expect("fail_open reports")
            .clone()
    }
}

impl MiddlewareRuntimeObserver for RecordingObserver {
    fn contract_failure(&self, failure: &ContractFailure) {
        self.contract_failures
            .lock()
            .expect("contract failures")
            .push(failure.clone());
    }

    fn fail_open_not_applied(&self, entry: &FailOpenNotApplied) {
        self.fail_open_not_applied
            .lock()
            .expect("fail_open reports")
            .push(entry.clone());
    }
}

/// Legacy response service that inspects with `STREAM_BYTES`, then fails the
/// first body unit with `status`.
struct FailingStreamService {
    status: TonicStatus,
}

#[tonic::async_trait]
impl InProcessMiddleware for FailingStreamService {
    async fn describe(&self) -> MiddlewareManifest {
        manifest_with(
            vec![binding(SupervisorMiddlewareOperation::HttpResponse, 0)],
            legacy_extension(),
        )
    }

    async fn validate_config(&self, _name: &str, _config: &prost_types::Struct) -> Result<()> {
        Ok(())
    }

    async fn evaluate_http_request(
        &self,
        _request: HttpRequestView<'_>,
    ) -> Result<HttpRequestResult> {
        Err(miette!("response-only test middleware"))
    }

    async fn open_http_response_pre_return(
        &self,
        mut events: mpsc::Receiver<HttpResponseEvent>,
    ) -> std::result::Result<HttpResponseResultStream, TonicStatus> {
        let (sender, receiver) = mpsc::channel(4);
        let status = self.status.clone();
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                let result = match event.event {
                    Some(http_response_event::Event::Preflight(_)) => Ok(HttpResponseEventResult {
                        result: Some(http_response_event_result::Result::PreflightResult(
                            HttpResponsePreflightResult {
                                action: Some(http_response_preflight_result::Action::Inspect(
                                    HttpResponsePreflightInspect {
                                        body_mode: HttpResponseBodyMode::StreamBytes as i32,
                                        header_mutations: Vec::new(),
                                    },
                                )),
                                ..Default::default()
                            },
                        )),
                    }),
                    Some(http_response_event::Event::Body(_)) => Err(status.clone()),
                    _ => continue,
                };
                if sender.send(result).await.is_err() {
                    return;
                }
            }
        });
        Ok(Box::pin(ReceiverStream::new(receiver)))
    }
}

/// In-process service with a fixed manifest.
struct ManifestService(MiddlewareManifest);

#[tonic::async_trait]
impl InProcessMiddleware for ManifestService {
    async fn describe(&self) -> MiddlewareManifest {
        self.0.clone()
    }

    async fn validate_config(&self, _name: &str, _config: &prost_types::Struct) -> Result<()> {
        Ok(())
    }

    async fn evaluate_http_request(
        &self,
        _request: HttpRequestView<'_>,
    ) -> Result<HttpRequestResult> {
        Ok(HttpRequestResult {
            decision: Decision::Allow as i32,
            ..Default::default()
        })
    }
}

/// Register `registrations` as a 0.1.x supervisor or gateway would, without
/// advertising `http-v2`.
async fn connect_as_0_1_peer(
    registrations: Vec<SupervisorMiddlewareService>,
) -> Result<MiddlewareRegistry> {
    MiddlewareRegistry::connect_services_inner(Vec::new(), registrations, None, HttpV2Support::NONE)
        .await
}

#[tokio::test]
async fn legacy_service_still_registers_and_evaluates_through_the_legacy_rpc() {
    let service = CompatService::new(Build::Legacy);
    let (address, _shutdown) = serve(service.clone()).await;
    let registry = MiddlewareRegistry::connect_services(
        Vec::new(),
        vec![registration("guard-service", address)],
    )
    .await
    .expect("a 0.1.x service registers unchanged");
    // This build advertises http-v2, which a 0.1.x service ignores.
    assert_eq!(service.caller_advertised_http_v2(), [true]);

    let runner = ChainRunner::from_registry(registry);
    let chain = runner
        .describe_chain(&[entry("guard", "guard-service", OnError::FailOpen)])
        .await
        .expect("describe chain");
    assert_eq!(chain[0].http_protocol(), Some(HttpProtocol::Legacy));
    assert_eq!(chain[0].on_error(), OnError::FailOpen);
    assert!(chain[0].http_stage_transport().is_none());

    let outcome = runner
        .run_described(&chain, request_input())
        .await
        .expect("evaluate");
    assert!(outcome.allowed);
    assert_eq!(service.legacy_calls(), 1);
}

#[tokio::test]
async fn version_2_only_service_requires_http_v2() {
    let service = CompatService::new(Build::V2Only);
    let (address, _shutdown) = serve(service.clone()).await;
    let error = connect_as_0_1_peer(vec![registration("guard-service", address)])
        .await
        .expect_err("a peer without http-v2 refuses a version 2-only service at Describe");
    assert!(
        error
            .to_string()
            .contains("missing capabilities required by supervisor-middleware extension")
    );
    assert!(error.to_string().contains(SUPERVISOR_MIDDLEWARE_HTTP_V2));

    let registry = MiddlewareRegistry::connect_services(
        Vec::new(),
        vec![registration("guard-service", address)],
    )
    .await
    .expect("this build executes version 2 and accepts the service");
    let chain = ChainRunner::from_registry(registry)
        .describe_chain(&[entry("guard", "guard-service", OnError::FailOpen)])
        .await
        .expect("describe chain");
    assert_eq!(chain[0].http_protocol(), Some(HttpProtocol::V2));
    assert_eq!(
        chain[0].on_error(),
        OnError::FailClosed,
        "version 2 HTTP bindings never fail open"
    );
    assert!(chain[0].supports_http_body_mode(HttpBodyMode::Stream));
}

#[tokio::test]
async fn dual_protocol_service_gets_version_2_bindings_only_when_the_caller_advertises_http_v2() {
    let service = CompatService::new(Build::Dual);
    let (address, _shutdown) = serve(service.clone()).await;

    let legacy_peer = connect_as_0_1_peer(vec![registration("guard-service", address)])
        .await
        .expect("dual-protocol service registers with legacy bindings");
    let runner = ChainRunner::from_registry(legacy_peer);
    let chain = runner
        .describe_chain(&[entry("guard", "guard-service", OnError::FailClosed)])
        .await
        .expect("describe chain");
    assert_eq!(chain[0].http_protocol(), Some(HttpProtocol::Legacy));
    assert!(
        runner
            .run_described(&chain, request_input())
            .await
            .expect("evaluate")
            .allowed
    );
    assert_eq!(service.legacy_calls(), 1);

    let v2_peer = MiddlewareRegistry::connect_services(
        Vec::new(),
        vec![registration("guard-service", address)],
    )
    .await
    .expect("dual-protocol service registers with version 2 bindings");
    let chain = ChainRunner::from_registry(v2_peer)
        .describe_http_response_chain(&[entry("guard", "guard-service", OnError::FailClosed)])
        .await
        .expect("describe chain");
    assert_eq!(chain[0].http_protocol(), Some(HttpProtocol::V2));
    assert_eq!(service.caller_advertised_http_v2(), [false, true]);
}

#[tokio::test]
async fn version_2_stage_transport_opens_the_services_evaluate_http_streams() {
    let service = CompatService::new(Build::V2Only);
    let (address, _shutdown) = serve(service.clone()).await;
    let runner = ChainRunner::from_registry(
        MiddlewareRegistry::connect_services_with_http_v2(
            Vec::new(),
            vec![registration("guard-service", address)],
        )
        .await
        .expect("registry"),
    );
    let entries = [entry("guard", "guard-service", OnError::FailClosed)];
    for chain in [
        runner
            .describe_chain(&entries)
            .await
            .expect("request chain"),
        runner
            .describe_http_response_chain(&entries)
            .await
            .expect("response chain"),
    ] {
        let transport = chain[0]
            .http_stage_transport()
            .expect("version 2 entries have a stage transport");
        let (events, receiver) = mpsc::channel(4);
        events
            .send(HttpEvent {
                event: Some(http_event::Event::Preflight(HttpPreflight {
                    head: Some(http_preflight::Head::Request(
                        HttpRequestPreflightHead::default(),
                    )),
                    ..Default::default()
                })),
            })
            .await
            .expect("send preflight");
        let mut results = transport.open(receiver).await.expect("open stage");
        let result = results
            .next()
            .await
            .expect("preflight result")
            .expect("valid result");
        assert!(matches!(
            result.result,
            Some(http_result::Result::PreflightResult(HttpPreflightResult {
                decision: Some(http_preflight_result::Decision::ContinueWithoutBody(_)),
                ..
            }))
        ));
    }
    assert_eq!(service.legacy_calls(), 0);
}

#[tokio::test]
async fn version_2_stages_never_reach_legacy_rpcs() {
    let service = CompatService::new(Build::Dual);
    let (address, _shutdown) = serve(service.clone()).await;
    let runner = ChainRunner::from_registry(
        MiddlewareRegistry::connect_services_with_http_v2(
            Vec::new(),
            vec![registration("guard-service", address)],
        )
        .await
        .expect("registry"),
    );
    let entries = [entry("guard", "guard-service", OnError::FailOpen)];

    // The request pipeline runs the stage over EvaluateHttp.
    let outcome = runner
        .run_chain(&entries, request_input())
        .await
        .expect("evaluate");
    assert!(outcome.allowed, "{}", outcome.reason);
    assert!(!outcome.applied[0].failed);

    // The response pipeline runs it over EvaluateHttp too.
    let (observed, held) = preflight_response(
        &runner,
        &entries,
        &ResponseCase::ok("application/json", &[]),
    )
    .await;
    assert!(observed.preflight_allowed(), "{:?}", observed.failure);
    held.end().await;
    assert_eq!(service.legacy_calls(), 0);
}

/// Unset or 0 selects HTTP protocol 1 and 2 selects HTTP protocol 2. An
/// explicit 1 is not an alias for the legacy protocol.
#[test]
fn unsupported_http_protocol_version_fails_registration() {
    for version in [1, 3] {
        let manifest = manifest_with(
            vec![binding(SupervisorMiddlewareOperation::HttpRequest, version)],
            legacy_extension(),
        );
        let error = validate_manifest_bindings("test service", &manifest, None)
            .expect_err("only unset, 0, and 2 select a protocol");
        assert!(
            error.to_string().contains(&format!(
                "unsupported HTTP middleware protocol version {version}"
            )),
            "{version}: {error}"
        );
    }
}

#[test]
fn body_modes_require_http_protocol_version_2() {
    let mut legacy = binding(SupervisorMiddlewareOperation::HttpRequest, 0);
    legacy.supported_http_body_modes = vec![HttpBodyMode::Buffered as i32];
    let error = validate_manifest_bindings(
        "test service",
        &manifest_with(vec![legacy], legacy_extension()),
        None,
    )
    .expect_err("legacy bindings cannot select body modes");
    assert!(
        error
            .to_string()
            .contains("require http_protocol_version 2")
    );

    for modes in [
        vec![HttpBodyMode::Buffered, HttpBodyMode::Buffered],
        vec![HttpBodyMode::Unspecified],
    ] {
        let mut candidate = binding(SupervisorMiddlewareOperation::HttpResponse, 2);
        candidate.supported_http_body_modes = modes.into_iter().map(i32::from).collect();
        assert!(
            validate_manifest_bindings(
                "test service",
                &manifest_with(vec![candidate], legacy_extension()),
                None,
            )
            .expect_err("invalid modes")
            .to_string()
            .contains("invalid or duplicate HTTP body mode")
        );
    }
}

#[test]
fn websocket_bindings_cannot_set_http_protocol_fields() {
    let mut websocket = binding(SupervisorMiddlewareOperation::WebsocketMessage, 0);
    validate_manifest_bindings(
        "test service",
        &manifest_with(vec![websocket.clone()], legacy_extension()),
        None,
    )
    .expect("plain WebSocket binding");

    websocket.http_protocol_version = 2;
    assert!(
        validate_manifest_bindings(
            "test service",
            &manifest_with(vec![websocket], legacy_extension()),
            None,
        )
        .expect_err("WebSocket bindings leave HTTP protocol fields unset")
        .to_string()
        .contains("not an HTTP binding")
    );
}

#[test]
fn preflight_only_version_2_binding_needs_no_payload_limit() {
    let mut preflight_only = binding(SupervisorMiddlewareOperation::HttpRequest, 2);
    preflight_only.max_payload_bytes = 0;
    for operator_limit in [None, Some(0), Some(4096)] {
        validate_manifest_bindings(
            "test service",
            &manifest_with(vec![preflight_only.clone()], legacy_extension()),
            operator_limit,
        )
        .expect("a preflight-only binding can only Continue or Reject");
    }

    let mut legacy = binding(SupervisorMiddlewareOperation::HttpRequest, 0);
    legacy.max_payload_bytes = 0;
    assert!(
        validate_manifest_bindings(
            "test service",
            &manifest_with(vec![legacy], legacy_extension()),
            None,
        )
        .expect_err("legacy bindings keep the payload limit requirement")
        .to_string()
        .contains("non-zero payload limit")
    );
}

#[test]
fn service_requiring_http_v2_cannot_advertise_legacy_http_bindings() {
    let requires_http_v2 = extension_metadata_with_requirements(
        ExtensionFamily::SupervisorMiddleware,
        "example/guard",
        "1.0.0",
        [],
        [SUPERVISOR_MIDDLEWARE_HTTP_V2.to_string()],
    );
    let error = validate_manifest_bindings(
        "test service",
        &manifest_with(
            vec![
                binding(SupervisorMiddlewareOperation::HttpRequest, 2),
                binding(SupervisorMiddlewareOperation::HttpResponse, 0),
            ],
            requires_http_v2.clone(),
        ),
        None,
    )
    .expect_err("a version 2-only service cannot serve the legacy protocol");
    assert!(
        error
            .to_string()
            .contains("advertises a legacy HTTP binding")
    );

    validate_manifest_bindings(
        "test service",
        &manifest_with(
            vec![
                binding(SupervisorMiddlewareOperation::HttpRequest, 2),
                binding(SupervisorMiddlewareOperation::WebsocketMessage, 0),
            ],
            requires_http_v2,
        ),
        None,
    )
    .expect("WebSocket bindings are unaffected by http-v2");
}

#[test]
fn this_build_runs_and_advertises_version_2_in_both_directions() {
    let response = manifest_with(
        vec![binding(SupervisorMiddlewareOperation::HttpResponse, 2)],
        legacy_extension(),
    );
    let request = manifest_with(
        vec![binding(SupervisorMiddlewareOperation::HttpRequest, 2)],
        legacy_extension(),
    );
    for manifest in [&request, &response] {
        ensure_http_v2_supported("test service", manifest, HttpV2Support::BUILD)
            .expect("this build runs version 2 stages in both directions");
    }
    let partial = HttpV2Support {
        request: true,
        response: false,
    };
    let error = ensure_http_v2_supported("test service", &response, partial)
        .expect_err("a direction without version 2 support rejects its bindings");
    assert!(error.to_string().contains("does not support yet"));

    let advertised = |support: HttpV2Support| {
        support
            .describe_metadata()
            .supported_capabilities
            .contains(&SUPERVISOR_MIDDLEWARE_HTTP_V2.to_string())
    };
    assert!(advertised(HttpV2Support::BUILD));
    assert!(!advertised(partial));
    assert!(!advertised(HttpV2Support::NONE));
}

#[tokio::test]
async fn mixed_legacy_and_version_2_chain_resolves_every_http_binding_to_a_stage() {
    let legacy = CompatService::new(Build::Legacy);
    let v2 = CompatService::new(Build::V2Only);
    let (legacy_address, _legacy_shutdown) = serve(legacy).await;
    let (v2_address, _v2_shutdown) = serve(v2).await;
    let runner = ChainRunner::from_registry(
        MiddlewareRegistry::connect_services_with_http_v2(
            Vec::new(),
            vec![
                registration("legacy-service", legacy_address),
                registration("v2-service", v2_address),
            ],
        )
        .await
        .expect("registry"),
    );
    let mut entries = vec![
        entry("legacy", "legacy-service", OnError::FailOpen),
        entry("v2", "v2-service", OnError::FailClosed),
    ];
    entries[1].order = 1;
    for direction in [HttpDirection::Request, HttpDirection::Response] {
        let chain = runner
            .describe_chain_for(&entries, direction.operation(), direction.phase())
            .await
            .expect("describe chain");
        assert!(chain.unbound.is_empty(), "no HTTP binding may be unbound");
        assert_eq!(
            chain
                .entries
                .iter()
                .map(DescribedChainEntry::http_protocol)
                .collect::<Vec<_>>(),
            [Some(HttpProtocol::Legacy), Some(HttpProtocol::V2)]
        );
    }
}

#[tokio::test]
async fn websocket_only_middleware_stays_unbound_for_http() {
    let runner = ChainRunner::from_registry(
        MiddlewareRegistry::connect_services(
            vec![Arc::new(ManifestService(manifest_with(
                vec![binding(SupervisorMiddlewareOperation::WebsocketMessage, 0)],
                legacy_extension(),
            )))],
            Vec::new(),
        )
        .await
        .expect("registry"),
    );
    let chain = runner
        .describe_chain_for(
            &[entry("ws", "example/guard", OnError::FailClosed)],
            SupervisorMiddlewareOperation::HttpRequest,
            SupervisorMiddlewarePhase::PreCredentials,
        )
        .await
        .expect("describe chain");
    assert!(chain.entries.is_empty());
    assert_eq!(chain.unbound.len(), 1);
}

#[tokio::test]
async fn unsupported_version_in_a_lazily_described_manifest_is_an_error_not_an_unbound_entry() {
    let runner = ChainRunner::new(Arc::new(ManifestService(manifest_with(
        vec![binding(SupervisorMiddlewareOperation::HttpRequest, 3)],
        legacy_extension(),
    ))));
    let error = runner
        .describe_chain(&[entry("guard", "example/guard", OnError::FailOpen)])
        .await
        .err()
        .expect("an unknown protocol version must not drop the entry");
    assert!(
        error
            .to_string()
            .contains("unsupported HTTP middleware protocol version 3")
    );
}

#[tokio::test]
async fn unimplemented_legacy_request_rpc_fails_closed_under_fail_open_and_requests_reconciliation()
{
    let service = CompatService::new(Build::Legacy);
    let (address, _shutdown) = serve(service.clone()).await;
    let observer = Arc::new(RecordingObserver::default());
    let runner = ChainRunner::default().with_runtime_observer(observer.clone());
    let runner = runner.with_replacement_registry(
        MiddlewareRegistry::connect_services(
            Vec::new(),
            vec![registration("guard-service", address)],
        )
        .await
        .expect("registry"),
    );
    // A version 2-only build swapped in behind the cached legacy manifest.
    service.switch_to(Build::V2Only);

    let outcome = runner
        .run_chain(
            &[entry("guard", "guard-service", OnError::FailOpen)],
            request_input(),
        )
        .await
        .expect("evaluate");
    assert!(
        !outcome.allowed,
        "fail_open must not skip a contract failure"
    );
    assert_eq!(
        outcome.reason,
        "middleware_failed: middleware_contract_failure_unimplemented"
    );
    assert!(outcome.applied[0].failed);
    assert_eq!(
        observer.contract_failures(),
        [ContractFailure {
            config_name: "guard".into(),
            implementation: "guard-service".into(),
            direction: HttpDirection::Request,
            protocol: HttpProtocol::Legacy,
            kind: ContractFailureKind::Unimplemented,
        }]
    );

    // The request survives a registry swap and is taken once.
    let replaced = runner.with_replacement_registry(MiddlewareRegistry::default());
    assert!(replaced.take_reconciliation_request());
    assert!(!runner.take_reconciliation_request());
}

#[tokio::test]
async fn unimplemented_legacy_response_rpc_fails_closed_under_fail_open() {
    let service = CompatService::new(Build::Legacy);
    let (address, _shutdown) = serve(service.clone()).await;
    let observer = Arc::new(RecordingObserver::default());
    let runner = ChainRunner::default()
        .with_runtime_observer(observer.clone())
        .with_replacement_registry(
            MiddlewareRegistry::connect_services(
                Vec::new(),
                vec![registration("guard-service", address)],
            )
            .await
            .expect("registry"),
        );
    service.switch_to(Build::V2Only);

    let (response, _held) = preflight_response(
        &runner,
        &[entry("guard", "guard-service", OnError::FailOpen)],
        &ResponseCase::ok("application/json", &[]),
    )
    .await;
    assert_eq!(
        response
            .failure
            .expect("a contract failure fails closed")
            .reason,
        "middleware_failed: middleware_contract_failure_unimplemented"
    );
    assert_eq!(
        response.records[0].outcome,
        HttpResponseInvocationOutcome::FailClosed
    );
    assert_eq!(
        response.records[0].failure_category.as_deref(),
        Some("contract_failure")
    );
    assert_eq!(
        observer.contract_failures()[0].direction,
        HttpDirection::Response
    );
    assert!(runner.take_reconciliation_request());
}

/// The supervisor answers a reconciliation request by connecting the delivered
/// services again. A peer without version 2 support refuses the swapped
/// service and keeps its last-known-good registry; a peer that executes
/// version 2 installs the new bindings.
#[tokio::test]
async fn re_describe_after_a_contract_failure_installs_the_swapped_services_bindings() {
    // A 0.1.x service is swapped to a version 2-only build behind the
    // cached legacy manifest.
    let service = CompatService::new(Build::Legacy);
    let (address, _shutdown) = serve(service.clone()).await;
    let registrations = vec![registration("guard-service", address)];
    let entries = [entry("guard", "guard-service", OnError::FailOpen)];
    let runner = ChainRunner::default().with_replacement_registry(
        MiddlewareRegistry::connect_services(Vec::new(), registrations.clone())
            .await
            .expect("registry"),
    );
    assert_eq!(
        runner.describe_chain(&entries).await.expect("chain")[0].http_protocol(),
        Some(HttpProtocol::Legacy)
    );

    service.switch_to(Build::V2Only);
    assert!(
        !runner
            .run_chain(&entries, request_input())
            .await
            .expect("evaluate")
            .allowed,
        "UNIMPLEMENTED fails closed despite fail_open"
    );
    assert!(runner.take_reconciliation_request());

    let error = connect_as_0_1_peer(registrations.clone())
        .await
        .expect_err("a peer without http-v2 refuses the version 2-only build");
    assert!(error.to_string().contains(SUPERVISOR_MIDDLEWARE_HTTP_V2));

    let runner = runner.with_replacement_registry(
        MiddlewareRegistry::connect_services(Vec::new(), registrations)
            .await
            .expect("re-describing installs the new bindings"),
    );
    assert_eq!(
        runner.describe_chain(&entries).await.expect("chain")[0].http_protocol(),
        Some(HttpProtocol::V2)
    );
}

/// Codec that sends and receives raw message bytes, so a test service can put
/// bytes on the wire that do not decode as the method's message type.
struct RawCodec;

impl tonic::codec::Codec for RawCodec {
    type Encode = Vec<u8>;
    type Decode = Vec<u8>;
    type Encoder = Self;
    type Decoder = Self;

    fn encoder(&mut self) -> Self {
        Self
    }

    fn decoder(&mut self) -> Self {
        Self
    }
}

impl tonic::codec::Encoder for RawCodec {
    type Item = Vec<u8>;
    type Error = TonicStatus;

    fn encode(
        &mut self,
        item: Vec<u8>,
        dst: &mut tonic::codec::EncodeBuf<'_>,
    ) -> std::result::Result<(), TonicStatus> {
        use prost::bytes::BufMut as _;
        dst.put_slice(&item);
        Ok(())
    }
}

impl tonic::codec::Decoder for RawCodec {
    type Item = Vec<u8>;
    type Error = TonicStatus;

    fn decode(
        &mut self,
        src: &mut tonic::codec::DecodeBuf<'_>,
    ) -> std::result::Result<Option<Vec<u8>>, TonicStatus> {
        use prost::bytes::Buf as _;
        Ok(Some(src.copy_to_bytes(src.remaining()).to_vec()))
    }
}

/// Fully qualified name of the gRPC service a [`RawReplies`] serves.
trait RawServiceName: Clone + Send + Sync + 'static {
    const NAME: &'static str;
}

#[derive(Clone)]
struct RequestStageService;

impl RawServiceName for RequestStageService {
    const NAME: &'static str =
        openshell_core::proto::middleware::v1::http_request_pre_credentials_server::SERVICE_NAME;
}

#[derive(Clone)]
struct ResponseStageService;

impl RawServiceName for ResponseStageService {
    const NAME: &'static str =
        openshell_core::proto::middleware::v1::http_response_pre_return_server::SERVICE_NAME;
}

/// gRPC service that answers every method of `S` with one message holding
/// `reply`, whatever the method's response type, and then ends the call.
#[derive(Clone)]
struct RawReplies<S> {
    reply: Vec<u8>,
    service: std::marker::PhantomData<S>,
}

impl<S> RawReplies<S> {
    fn new(reply: &[u8]) -> Self {
        Self {
            reply: reply.to_vec(),
            service: std::marker::PhantomData,
        }
    }
}

impl<S: RawServiceName> tonic::server::NamedService for RawReplies<S> {
    const NAME: &'static str = S::NAME;
}

impl<S: RawServiceName> tonic::codegen::Service<tonic::codegen::http::Request<tonic::body::Body>>
    for RawReplies<S>
{
    type Response = tonic::codegen::http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = tonic::codegen::BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: tonic::codegen::http::Request<tonic::body::Body>) -> Self::Future {
        let reply = OneReply(self.reply.clone());
        Box::pin(async move {
            Ok(tonic::server::Grpc::new(RawCodec)
                .streaming(reply, request)
                .await)
        })
    }
}

/// Ignores a call's messages and answers with one raw message.
struct OneReply(Vec<u8>);

impl tonic::server::StreamingService<Vec<u8>> for OneReply {
    type Response = Vec<u8>;
    type ResponseStream =
        futures::stream::Once<std::future::Ready<std::result::Result<Vec<u8>, TonicStatus>>>;
    type Future =
        std::future::Ready<std::result::Result<TonicResponse<Self::ResponseStream>, TonicStatus>>;

    fn call(&mut self, _request: Request<tonic::Streaming<Vec<u8>>>) -> Self::Future {
        let reply = std::mem::take(&mut self.0);
        std::future::ready(Ok(TonicResponse::new(futures::stream::once(
            std::future::ready(Ok(reply)),
        ))))
    }
}

/// A result whose first field, a length-delimited message, declares more
/// bytes than follow.
const UNDECODABLE_RESULT: &[u8] = b"\x0a\x05\x01";

/// Serve Describe from `describe` and answer every request and response stage
/// RPC with [`UNDECODABLE_RESULT`], until the returned sender is dropped.
async fn serve_undecodable_stage_results(
    describe: CompatService,
) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test middleware");
    let address = listener.local_addr().expect("test middleware address");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tonic::transport::Server::builder()
        .add_service(SupervisorMiddlewareServer::new(describe))
        .add_service(RawReplies::<RequestStageService>::new(UNDECODABLE_RESULT))
        .add_service(RawReplies::<ResponseStageService>::new(UNDECODABLE_RESULT))
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
            let _ = shutdown_rx.await;
        });
    tokio::spawn(server);
    (address, shutdown_tx)
}

/// Decode failures are classified from the status `tonic-prost` reports for
/// a message that does not decode. A real gRPC stream carries such a message
/// here, so a change in that status fails this test.
#[tokio::test]
async fn version_2_results_that_do_not_decode_on_the_wire_are_decode_contract_failures() {
    let (address, _shutdown) =
        serve_undecodable_stage_results(CompatService::new(Build::V2Only)).await;
    let runner = ChainRunner::from_registry(
        MiddlewareRegistry::connect_services_with_http_v2(
            Vec::new(),
            vec![registration("guard-service", address)],
        )
        .await
        .expect("registry"),
    );
    let entries = [entry("guard", "guard-service", OnError::FailOpen)];
    for chain in [
        runner
            .describe_chain(&entries)
            .await
            .expect("request chain"),
        runner
            .describe_http_response_chain(&entries)
            .await
            .expect("response chain"),
    ] {
        let transport = chain[0]
            .http_stage_transport()
            .expect("version 2 entries have a stage transport");
        let (events, receiver) = mpsc::channel(4);
        events
            .send(HttpEvent {
                event: Some(http_event::Event::Preflight(HttpPreflight::default())),
            })
            .await
            .expect("send preflight");
        let mut results = transport.open(receiver).await.expect("open stage");
        let status = results
            .next()
            .await
            .expect("a result")
            .expect_err("the result does not decode");
        assert_eq!(status.code(), tonic::Code::Internal, "{status:?}");
        assert_eq!(
            ContractFailureKind::from_status(&status),
            Some(ContractFailureKind::Decode),
            "{status:?}"
        );
    }
}

#[tokio::test]
async fn legacy_response_result_that_does_not_decode_on_the_wire_fails_closed_under_fail_open() {
    let (address, _shutdown) =
        serve_undecodable_stage_results(CompatService::new(Build::Legacy)).await;
    let observer = Arc::new(RecordingObserver::default());
    let runner = ChainRunner::default()
        .with_runtime_observer(observer.clone())
        .with_replacement_registry(
            MiddlewareRegistry::connect_services(
                Vec::new(),
                vec![registration("guard-service", address)],
            )
            .await
            .expect("registry"),
        );

    let (response, _held) = preflight_response(
        &runner,
        &[entry("guard", "guard-service", OnError::FailOpen)],
        &ResponseCase::ok("application/json", &[]),
    )
    .await;
    assert_eq!(
        response
            .failure
            .expect("a decode failure fails closed")
            .reason,
        "middleware_failed: middleware_contract_failure_decode_failure"
    );
    assert_eq!(
        response.records[0].outcome,
        HttpResponseInvocationOutcome::FailClosed
    );
    assert_eq!(
        observer.contract_failures()[0].kind,
        ContractFailureKind::Decode
    );
    assert!(runner.take_reconciliation_request());
}

#[tokio::test]
async fn legacy_response_stream_decode_failure_fails_closed_under_fail_open() {
    let decode_error = HttpResponseEventResult::decode(&b"\x0a\x05\x01"[..])
        .expect_err("truncated message must not decode");
    let observer = Arc::new(RecordingObserver::default());
    let runner = ChainRunner::new(Arc::new(FailingStreamService {
        status: TonicStatus::internal(decode_error.to_string()),
    }))
    .with_runtime_observer(observer.clone());

    let response = run_response(
        &runner,
        &[entry("guard", "example/guard", OnError::FailOpen)],
        ResponseCase::ok("application/json", &[b"body"]),
    )
    .await;
    assert!(response.inspected, "STREAM_BYTES session");
    assert!(response.body().is_empty());
    let failure = response
        .failure
        .expect("a decode failure must not pass the body through");
    assert_eq!(
        failure.reason,
        "middleware_failed: middleware_contract_failure_decode_failure"
    );
    assert_eq!(
        observer.contract_failures()[0].kind,
        ContractFailureKind::Decode
    );
    assert!(runner.take_reconciliation_request());
}

#[tokio::test]
async fn ordinary_legacy_response_stream_failure_keeps_fail_open() {
    let runner = ChainRunner::new(Arc::new(FailingStreamService {
        status: TonicStatus::internal("service error"),
    }));
    let observed = run_response(
        &runner,
        &[entry("guard", "example/guard", OnError::FailOpen)],
        ResponseCase::ok("application/json", &[b"body"]),
    )
    .await;
    assert!(observed.inspected, "STREAM_BYTES session");
    assert!(observed.failure.is_none(), "{:?}", observed.failure);
    assert_eq!(
        observed.released,
        [b"body".to_vec()],
        "fail_open passes the unit on"
    );
    assert!(!runner.take_reconciliation_request());
}

/// In-process services covering every combination `on_error` scope cares
/// about, keyed by manifest name.
async fn scope_registry() -> MiddlewareRegistry {
    let named = |name: &str, bindings| -> Arc<dyn InProcessMiddleware> {
        let mut manifest = manifest_with(bindings, legacy_extension());
        manifest.name = name.into();
        Arc::new(ManifestService(manifest))
    };
    MiddlewareRegistry::connect_services_with_http_v2(
        vec![
            named(
                "example/v2-http",
                vec![
                    binding(SupervisorMiddlewareOperation::HttpRequest, 2),
                    binding(SupervisorMiddlewareOperation::HttpResponse, 2),
                ],
            ),
            named(
                "example/v2-http-and-websocket",
                vec![
                    binding(SupervisorMiddlewareOperation::HttpRequest, 2),
                    binding(SupervisorMiddlewareOperation::WebsocketMessage, 0),
                ],
            ),
            named(
                "example/legacy-http",
                vec![binding(SupervisorMiddlewareOperation::HttpRequest, 0)],
            ),
            named(
                "example/websocket",
                vec![binding(SupervisorMiddlewareOperation::WebsocketMessage, 0)],
            ),
        ],
        Vec::new(),
    )
    .await
    .expect("registry")
}

fn policy_with(middleware: &str, on_error: &str, on_uninspectable: &str) -> SandboxPolicy {
    SandboxPolicy {
        network_middlewares: HashMap::from([(
            "guard".to_string(),
            NetworkMiddlewareConfig {
                middleware: middleware.into(),
                on_error: on_error.into(),
                on_uninspectable: on_uninspectable.into(),
                ..Default::default()
            },
        )]),
        ..Default::default()
    }
}

#[tokio::test]
async fn on_error_scope_rejects_fail_open_only_where_it_has_no_effect() {
    let registry = scope_registry().await;
    let error = registry
        .validate_on_error_scope(&policy_with("example/v2-http", "fail_open", "deny"))
        .await
        .expect_err("fail_open affects neither version 2 HTTP nor denied uninspectable traffic");
    assert_eq!(
        error.to_string(),
        "middleware config 'guard' cannot use on_error: fail_open with 'example/v2-http': on_error applies only to WebSocket bindings and, until 0.2.0, legacy HTTP bindings; version 2 HTTP middleware is fail-closed, and on_uninspectable: deny overrides fail_open for uninspectable traffic"
    );

    for (middleware, on_error, on_uninspectable) in [
        ("example/v2-http", "fail_closed", "deny"),
        ("example/v2-http", "", "deny"),
        // fail_open is the deprecated fallback for an unset on_uninspectable,
        // and 0.1.x supervisors gate uninspectable traffic on on_error alone.
        ("example/v2-http", "fail_open", ""),
        ("example/v2-http", "fail_open", "allow"),
        ("example/v2-http-and-websocket", "fail_open", "deny"),
        ("example/legacy-http", "fail_open", "deny"),
        ("example/websocket", "fail_open", "deny"),
        ("example/unregistered", "fail_open", "deny"),
    ] {
        registry
            .validate_on_error_scope(&policy_with(middleware, on_error, on_uninspectable))
            .await
            .unwrap_or_else(|error| {
                panic!("{middleware} with {on_error:?}/{on_uninspectable:?}: {error}")
            });
    }
}

#[tokio::test]
async fn stale_fail_open_on_version_2_binding_runs_fail_closed_with_a_report() {
    let observer = Arc::new(RecordingObserver::default());
    let runner = ChainRunner::default()
        .with_runtime_observer(observer.clone())
        .with_replacement_registry(scope_registry().await);
    let mut entries = vec![
        entry("stale", "example/v2-http", OnError::FailOpen),
        entry("mixed", "example/v2-http-and-websocket", OnError::FailOpen),
        entry("legacy", "example/legacy-http", OnError::FailOpen),
    ];
    for (order, entry) in entries.iter_mut().enumerate() {
        entry.order = i32::try_from(order).expect("order");
    }

    let chain = runner
        .describe_chain(&entries)
        .await
        .expect("describe chain");
    assert_eq!(
        chain
            .iter()
            .map(DescribedChainEntry::on_error)
            .collect::<Vec<_>>(),
        [OnError::FailClosed, OnError::FailClosed, OnError::FailOpen],
        "only the legacy entry keeps fail_open; the policy is not rejected"
    );
    assert_eq!(
        observer.fail_open_not_applied(),
        [
            FailOpenNotApplied {
                config_name: "stale".into(),
                implementation: "example/v2-http".into(),
                direction: HttpDirection::Request,
                applies_elsewhere: false,
            },
            FailOpenNotApplied {
                config_name: "mixed".into(),
                implementation: "example/v2-http-and-websocket".into(),
                direction: HttpDirection::Request,
                applies_elsewhere: true,
            },
        ]
    );

    let websocket = runner
        .describe_websocket_chain(&entries)
        .await
        .expect("describe WebSocket chain");
    assert_eq!(websocket.len(), 1);
    assert_eq!(websocket[0].on_error(), OnError::FailOpen);
    assert_eq!(observer.fail_open_not_applied().len(), 2);
}

#[tokio::test]
async fn delivered_registrations_carry_the_http_protocols_the_gateway_described() {
    let mut servers = Vec::new();
    for build in [Build::Legacy, Build::V2Only, Build::Dual] {
        servers.push(serve(CompatService::new(build)).await);
    }
    let names = ["legacy-guard", "v2-guard", "dual-guard"];
    let gateway = MiddlewareRegistry::connect_services_with_http_v2(
        Vec::new(),
        names
            .iter()
            .zip(&servers)
            .map(|(name, (address, _shutdown))| registration(name, *address))
            .collect(),
    )
    .await
    .expect("gateway registry");
    let policy = SandboxPolicy {
        network_middlewares: names
            .iter()
            .map(|name| {
                (
                    (*name).to_string(),
                    NetworkMiddlewareConfig {
                        middleware: (*name).to_string(),
                        ..Default::default()
                    },
                )
            })
            .collect(),
        ..Default::default()
    };

    let mut delivered = gateway.required_services(Some(&policy));
    delivered.sort_by(|left, right| left.name.cmp(&right.name));
    assert_eq!(
        delivered
            .iter()
            .map(|service| (
                service.name.as_str(),
                service.http_request_protocol_version,
                service.http_response_protocol_version,
            ))
            .collect::<Vec<_>>(),
        [
            ("dual-guard", 2, 2),
            ("legacy-guard", 0, 0),
            ("v2-guard", 2, 2)
        ]
    );
}

#[tokio::test]
async fn undescribed_service_fails_closed_where_the_gateway_described_version_2() {
    let delivered = [
        SupervisorMiddlewareService {
            name: "v2-request-guard".into(),
            http_request_protocol_version: 2,
            ..Default::default()
        },
        SupervisorMiddlewareService {
            name: "legacy-guard".into(),
            ..Default::default()
        },
    ];
    let runner = ChainRunner::from_registry(
        MiddlewareRegistry::connect_services(Vec::new(), Vec::new())
            .await
            .expect("built-in registry")
            .with_undescribed_services(&delivered),
    );
    let mut entries = vec![
        entry("v2", "v2-request-guard", OnError::FailOpen),
        entry("legacy", "legacy-guard", OnError::FailOpen),
        entry("unknown", "unknown-guard", OnError::FailOpen),
    ];
    for (order, entry) in entries.iter_mut().enumerate() {
        entry.order = i32::try_from(order).expect("order");
    }
    let on_error = |chain: Vec<DescribedChainEntry>| {
        assert!(chain.iter().all(|entry| !entry.is_resolved()));
        chain
            .iter()
            .map(DescribedChainEntry::on_error)
            .collect::<Vec<_>>()
    };

    assert_eq!(
        on_error(runner.describe_chain(&entries).await.expect("requests")),
        [OnError::FailClosed, OnError::FailOpen, OnError::FailOpen],
        "only the direction the gateway described as version 2 fails closed"
    );
    assert_eq!(
        on_error(
            runner
                .describe_http_response_chain(&entries)
                .await
                .expect("responses")
        ),
        [OnError::FailOpen; 3]
    );
    assert_eq!(
        on_error(
            runner
                .describe_websocket_chain(&entries)
                .await
                .expect("WebSocket")
        ),
        [OnError::FailOpen; 3]
    );
}

#[tokio::test]
async fn described_services_ignore_the_gateways_protocol_report() {
    let (address, _shutdown) = serve(CompatService::new(Build::Legacy)).await;
    let reported_v2 = SupervisorMiddlewareService {
        http_request_protocol_version: 2,
        ..registration("guard-service", address)
    };
    let registry =
        MiddlewareRegistry::connect_services_with_http_v2(Vec::new(), vec![reported_v2.clone()])
            .await
            .expect("registry")
            .with_undescribed_services(&[reported_v2]);
    let chain = ChainRunner::from_registry(registry)
        .describe_chain(&[entry("guard", "guard-service", OnError::FailOpen)])
        .await
        .expect("describe chain");
    assert_eq!(chain[0].http_protocol(), Some(HttpProtocol::Legacy));
    assert_eq!(
        chain[0].on_error(),
        OnError::FailOpen,
        "the supervisor's own Describe decides once it succeeds"
    );
}

/// Supervisors that predate version 2 refuse a service that requires it, and
/// then skip every entry that uses it under `fail_open`, for HTTP and
/// WebSocket traffic alike. Until 0.2.0 the gateway rejects `fail_open` on
/// such middleware whatever its bindings and `on_uninspectable` say. A
/// service that serves both protocols does not require version 2, so its
/// WebSocket binding keeps `fail_open`.
#[tokio::test]
async fn on_error_scope_rejects_fail_open_on_middleware_that_requires_version_2() {
    let named = |name: &str, required: bool| -> Arc<dyn InProcessMiddleware> {
        let capability = [SUPERVISOR_MIDDLEWARE_HTTP_V2.to_string()];
        let extension = if required {
            extension_metadata_with_requirements(
                ExtensionFamily::SupervisorMiddleware,
                name,
                "1.0.0",
                [],
                capability,
            )
        } else {
            extension_metadata(
                ExtensionFamily::SupervisorMiddleware,
                name,
                "1.0.0",
                capability,
            )
        };
        let bindings = if name.ends_with("-and-websocket") {
            vec![
                binding(SupervisorMiddlewareOperation::HttpRequest, 2),
                binding(SupervisorMiddlewareOperation::WebsocketMessage, 0),
            ]
        } else {
            vec![binding(SupervisorMiddlewareOperation::HttpRequest, 2)]
        };
        let mut manifest = manifest_with(bindings, extension);
        manifest.name = name.into();
        Arc::new(ManifestService(manifest))
    };
    let registry = MiddlewareRegistry::connect_services_with_http_v2(
        vec![
            named("example/v2-only-http", true),
            named("example/v2-only-http-and-websocket", true),
            named("example/dual-http-and-websocket", false),
        ],
        Vec::new(),
    )
    .await
    .expect("registry");

    for on_uninspectable in ["", "allow", "deny"] {
        for (middleware, remedy) in [
            ("example/v2-only-http", "use fail_closed"),
            (
                "example/v2-only-http-and-websocket",
                "use fail_closed, or ship a build of the service that serves both HTTP protocols to keep WebSocket fail_open",
            ),
        ] {
            let error = registry
                .validate_on_error_scope(&policy_with(middleware, "fail_open", on_uninspectable))
                .await
                .expect_err("an older supervisor would skip the service");
            assert_eq!(
                error.to_string(),
                format!(
                    "middleware config 'guard' cannot use on_error: fail_open with '{middleware}': until 0.2.0, fail_open is not supported on middleware that requires HTTP protocol version 2, because supervisors that predate version 2 cannot run it and would skip it; {remedy}"
                ),
                "{on_uninspectable:?}"
            );
            registry
                .validate_on_error_scope(&policy_with(middleware, "fail_closed", on_uninspectable))
                .await
                .expect("fail_closed is always valid");
        }
        registry
            .validate_on_error_scope(&policy_with(
                "example/dual-http-and-websocket",
                "fail_open",
                on_uninspectable,
            ))
            .await
            .expect("fail_open still governs the WebSocket binding of a dual-protocol service");
    }
}
