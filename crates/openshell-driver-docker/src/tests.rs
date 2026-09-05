// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use openshell_core::config::DEFAULT_SERVER_PORT;
use openshell_core::driver_utils::{
    LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE, LABEL_SANDBOX_ID, LABEL_SANDBOX_NAME,
    LABEL_SANDBOX_NAMESPACE,
};
use openshell_core::progress::{
    PROGRESS_ACTIVE_DETAIL_KEY, PROGRESS_ACTIVE_STEP_KEY, PROGRESS_COMPLETE_LABEL_KEY,
    PROGRESS_COMPLETE_STEP_KEY, PROGRESS_STEP_PULLING_IMAGE, PROGRESS_STEP_REQUESTING_SANDBOX,
    PROGRESS_STEP_STARTING_SANDBOX,
};
use openshell_core::proto::compute::v1::{
    DriverResourceRequirements, DriverSandboxSpec, DriverSandboxTemplate,
    GetGatewayListenerRequirementsRequest, GpuResourceRequirements, ResourceRequirements,
    WorkloadIdentityRequest, gateway_listener_requirement::Selector,
};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tempfile::TempDir;

fn test_sandbox() -> DriverSandbox {
    // Mirrors the gateway-supplied request: the public `Sandbox` API no
    // longer carries `namespace`, so the gateway elides the field and the
    // driver must source it from its own runtime config.
    DriverSandbox {
        id: "sbx-123".to_string(),
        name: "demo".to_string(),
        namespace: String::new(),
        spec: Some(DriverSandboxSpec {
            log_level: "debug".to_string(),
            environment: HashMap::from([("SPEC_ENV".to_string(), "spec".to_string())]),
            template: Some(DriverSandboxTemplate {
                image: "ghcr.io/nvidia/openshell-community/sandboxes/base:latest".to_string(),
                agent_socket_path: String::new(),
                labels: HashMap::new(),
                environment: HashMap::from([("TEMPLATE_ENV".to_string(), "template".to_string())]),
                ..Default::default()
            }),
            policy: None,
            resource_requirements: None,
            sandbox_token: String::new(),
            command: Vec::new(),
            tty: false,
            await_main_process_attachment: false,
            workload_identity: None,
        }),
        status: None,
        workspace: String::new(),
    }
}

fn cdi_devices_config(device_ids: &[&str]) -> prost_types::Struct {
    list_string_driver_config("cdi_devices", device_ids)
}

fn cdi_device_typo_config(device_ids: &[&str]) -> prost_types::Struct {
    list_string_driver_config("cdi_device", device_ids)
}

fn list_string_driver_config(field: &str, values: &[&str]) -> prost_types::Struct {
    prost_types::Struct {
        fields: std::iter::once((
            field.to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::ListValue(
                    prost_types::ListValue {
                        values: values
                            .iter()
                            .map(|device_id| prost_types::Value {
                                kind: Some(prost_types::value::Kind::StringValue(
                                    (*device_id).to_string(),
                                )),
                            })
                            .collect(),
                    },
                )),
            },
        ))
        .collect(),
    }
}

fn gpu_resources(count: Option<u32>) -> ResourceRequirements {
    ResourceRequirements {
        gpu: Some(GpuResourceRequirements { count }),
    }
}

fn runtime_config() -> DockerDriverRuntimeConfig {
    DockerDriverRuntimeConfig {
        default_image: "image:latest".to_string(),
        image_pull_policy: String::new(),
        sandbox_namespace: "default".to_string(),
        gateway_route: DockerGatewayRoute::Bridge {
            bind_address: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(172, 18, 0, 1)),
                DEFAULT_SERVER_PORT,
            ),
        },
        gateway_callback_bind_address: Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(172, 18, 0, 1)),
            DEFAULT_SERVER_PORT,
        )),
        stop_timeout_secs: DEFAULT_STOP_TIMEOUT_SECS,
        log_level: "info".to_string(),
        sandbox_binary: Arc::new(b"\x7fELFtest".to_vec()),
        supervisor_image_id: "sha256:supervisor-test".to_string(),
        network_name: "openshell-test".to_string(),
        supervisor_grpc_endpoint: "https://host.openshell.internal:8443".to_string(),
        gateway_tls_server_name: None,
        guest_tls: Some(DockerGuestTlsPaths {
            ca: PathBuf::from("/tmp/ca.crt"),
            cert: PathBuf::from("/tmp/tls.crt"),
            key: PathBuf::from("/tmp/tls.key"),
        }),
        daemon_version: "28.0.0".to_string(),
        supports_gpu: false,
        allow_all_default_gpu: false,
        sandbox_pids_limit: DEFAULT_SANDBOX_PIDS_LIMIT,
        enable_bind_mounts: false,
    }
}

fn test_workload_identity() -> ResolvedWorkloadIdentity {
    ResolvedWorkloadIdentity::new(
        1234,
        1235,
        vec![1236],
        "test".to_string(),
        "sha256:immutable".to_string(),
    )
    .unwrap()
}

fn json_struct(value: serde_json::Value) -> prost_types::Struct {
    let serde_json::Value::Object(object) = value else {
        panic!("expected JSON object");
    };
    openshell_core::proto_struct::json_object_to_struct(object)
        .expect("test JSON must convert to a protobuf Struct")
}

fn inspected_volume(driver: &str, options: HashMap<String, String>) -> bollard::models::Volume {
    bollard::models::Volume {
        name: "openshell-test-volume".to_string(),
        driver: driver.to_string(),
        mountpoint: "/var/lib/docker/volumes/openshell-test-volume/_data".to_string(),
        created_at: None,
        status: None,
        labels: HashMap::new(),
        scope: None,
        cluster_volume: None,
        options,
        usage_data: None,
    }
}

fn test_driver_with_config(config: DockerDriverRuntimeConfig) -> DockerComputeDriver {
    let allow_all_default_gpu = config.allow_all_default_gpu;
    DockerComputeDriver {
        docker: Arc::new(
            Docker::connect_with_http("http://127.0.0.1:2375", 1, bollard::API_DEFAULT_VERSION)
                .expect("construct test Docker client"),
        ),
        config,
        events: broadcast::channel(WATCH_BUFFER).0,
        pending: Arc::new(Mutex::new(HashMap::new())),
        gpu_selector: Arc::new(CdiGpuDefaultSelector::new(
            CdiGpuInventory::default(),
            allow_all_default_gpu,
        )),
        lifecycle_event_fences: DockerLifecycleEventFences::default(),
        control_processes: Arc::new(Mutex::new(HashMap::new())),
        runtime_failures: Arc::new(Mutex::new(HashMap::new())),
    }
}

type TestDriverClient =
    openshell_core::proto::compute::v1::compute_driver_client::ComputeDriverClient<
        tonic::transport::Channel,
    >;

fn request_with_traceparent<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.metadata_mut().insert(
        "traceparent",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
            .parse()
            .unwrap(),
    );
    request
}

async fn standalone_traced_client() -> (
    TestDriverClient,
    oneshot::Sender<()>,
    JoinHandle<Result<(), tonic::transport::Error>>,
) {
    use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriverServer;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, shutdown_rx) = oneshot::channel();
    let service = ComputeDriverService::new(test_driver_with_config(runtime_config()));
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .layer(openshell_otel::compute_driver_rpc_layer())
            .add_service(ComputeDriverServer::new(service))
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await
    });
    let client = TestDriverClient::connect(format!("http://{address}"))
        .await
        .unwrap();
    (client, shutdown, server)
}

#[tokio::test]
async fn tracing_standalone_rpc_layer_propagates_context_and_records_errors() {
    use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
    use tracing_subscriber::layer::SubscriberExt as _;

    let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
    let exporter = InMemorySpanExporterBuilder::new().build();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let dispatch = tracing::Dispatch::new(
        tracing_subscriber::registry().with(otel_tracing::TRACING.layer(&provider)),
    );
    let _dispatch = tracing::dispatcher::set_default(&dispatch);
    let (mut client, shutdown, server) = standalone_traced_client().await;

    client
        .get_capabilities(request_with_traceparent(GetCapabilitiesRequest {}))
        .await
        .expect("capabilities should succeed");
    client
        .validate_sandbox_create(request_with_traceparent(ValidateSandboxCreateRequest {
            sandbox: None,
        }))
        .await
        .expect_err("missing sandbox should fail");
    drop(client);
    shutdown.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("standalone test server should stop")
        .expect("standalone test server should not panic")
        .expect("standalone test server should stop cleanly");
    provider.force_flush().unwrap();

    let spans = exporter.get_finished_spans().unwrap();
    let capabilities = spans
        .iter()
        .find(|span| span.name == "openshell.compute.v1.ComputeDriver/GetCapabilities")
        .expect("capabilities RPC span");
    assert_eq!(
        capabilities.span_context.trace_id().to_string(),
        "4bf92f3577b34da6a3ce929d0e0e4736"
    );
    assert_eq!(capabilities.parent_span_id.to_string(), "00f067aa0ba902b7");
    assert!(capabilities.attributes.iter().any(|attribute| {
        attribute.key.as_str() == "rpc.method"
            && attribute.value.to_string() == "openshell.compute.v1.ComputeDriver/GetCapabilities"
    }));
    assert!(
        capabilities
            .attributes
            .iter()
            .all(|attribute| attribute.key.as_str() != "rpc.service"),
        "the current RPC semantic conventions integrate the service into rpc.method"
    );
    let failed = spans
        .iter()
        .find(|span| span.name == "openshell.compute.v1.ComputeDriver/ValidateSandboxCreate")
        .expect("failed RPC span");
    assert!(matches!(
        failed.status,
        opentelemetry::trace::Status::Error { .. }
    ));
    provider.shutdown().unwrap();
}

#[tokio::test]
async fn control_failure_overrides_running_container_readiness() {
    let driver = test_driver_with_config(runtime_config());
    driver.runtime_failures.lock().await.insert(
        "sbx-123".to_string(),
        DockerRuntimeFailure {
            reason: "ControlSupervisorExited",
            message: "control exited unexpectedly".to_string(),
        },
    );
    let mut sandbox = pending_sandbox_snapshot(
        &test_sandbox(),
        "default",
        DriverCondition {
            r#type: "Ready".to_string(),
            status: "True".to_string(),
            reason: "BackendReady".to_string(),
            message: "Container is running".to_string(),
            last_transition_time: String::new(),
        },
        false,
    );

    driver.apply_runtime_failure(&mut sandbox).await;

    let ready = sandbox
        .status
        .unwrap()
        .conditions
        .into_iter()
        .find(|condition| condition.r#type == "Ready")
        .expect("ready condition");
    assert_eq!(ready.status, "False");
    assert_eq!(ready.reason, "ControlSupervisorExited");
    assert!(ready.message.contains("control exited unexpectedly"));
}

#[tokio::test]
async fn control_failure_does_not_hide_a_terminal_container_exit() {
    let driver = test_driver_with_config(runtime_config());
    driver.runtime_failures.lock().await.insert(
        "sbx-123".to_string(),
        DockerRuntimeFailure {
            reason: "ControlSupervisorExited",
            message: "control exited unexpectedly".to_string(),
        },
    );
    let mut sandbox = pending_sandbox_snapshot(
        &test_sandbox(),
        "default",
        DriverCondition {
            r#type: "Ready".to_string(),
            status: "False".to_string(),
            reason: CONDITION_EXITED.to_string(),
            message: "Container exited".to_string(),
            last_transition_time: String::new(),
        },
        false,
    );

    driver.apply_runtime_failure(&mut sandbox).await;

    let ready = sandbox
        .status
        .unwrap()
        .conditions
        .into_iter()
        .find(|condition| condition.r#type == "Ready")
        .expect("ready condition");
    assert_eq!(ready.reason, CONDITION_EXITED);
}

#[tokio::test]
async fn tracing_in_process_service_preserves_the_driver_rpc_server_boundary() {
    use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
    use tracing::{Instrument as _, instrument::WithSubscriber as _};
    use tracing_subscriber::layer::SubscriberExt as _;

    let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
    let gateway_exporter = InMemorySpanExporterBuilder::new().build();
    let gateway_provider = SdkTracerProvider::builder()
        .with_simple_exporter(gateway_exporter.clone())
        .build();
    let driver_exporter = InMemorySpanExporterBuilder::new().build();
    let driver_provider = SdkTracerProvider::builder()
        .with_simple_exporter(driver_exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry()
        .with(openshell_otel::layer_excluding_target_prefixes(
            &gateway_provider,
            "gateway-test",
            otel_tracing::TRACING.in_process_targets(),
        ))
        .with(otel_tracing::TRACING.in_process_layer(&driver_provider));
    let service = ComputeDriverService::new_in_process(test_driver_with_config(runtime_config()));

    async {
        let gateway_span = tracing::info_span!(
            target: "openshell_server::compute",
            "driver",
            otel.name = "openshell.compute.v1.ComputeDriver/GetCapabilities",
            otel.kind = "client"
        );
        ComputeDriver::get_capabilities(&service, Request::new(GetCapabilitiesRequest {}))
            .instrument(gateway_span)
            .await?;

        let unrelated = tracing::info_span!(
            target: "openshell_driver_kubernetes::compute",
            "kubernetes.operation"
        );
        drop(unrelated.enter());
        drop(unrelated);
        let selected_backend = tracing::info_span!(
            target: "openshell_driver_docker::compute",
            "docker.operation"
        );
        drop(selected_backend.enter());
        drop(selected_backend);
        Ok::<_, Status>(())
    }
    .with_subscriber(subscriber)
    .await
    .expect("capabilities should succeed");
    async {
        let gateway_span = tracing::info_span!(
            target: "openshell_server::compute",
            "driver",
            otel.name = "openshell.compute.v1.ComputeDriver/ValidateSandboxCreate",
            otel.kind = "client"
        );
        ComputeDriver::validate_sandbox_create(
            &service,
            Request::new(ValidateSandboxCreateRequest { sandbox: None }),
        )
        .instrument(gateway_span)
        .await
    }
    .with_subscriber(
        tracing_subscriber::registry()
            .with(openshell_otel::layer_excluding_target_prefixes(
                &gateway_provider,
                "gateway-test",
                otel_tracing::TRACING.in_process_targets(),
            ))
            .with(otel_tracing::TRACING.in_process_layer(&driver_provider)),
    )
    .await
    .expect_err("missing sandbox should fail");
    gateway_provider.force_flush().unwrap();
    driver_provider.force_flush().unwrap();

    let gateway_spans = gateway_exporter.get_finished_spans().unwrap();
    let driver_spans = driver_exporter.get_finished_spans().unwrap();
    let client = gateway_spans
        .iter()
        .find(|span| span.name == "openshell.compute.v1.ComputeDriver/GetCapabilities")
        .unwrap();
    let server = driver_spans
        .iter()
        .find(|span| span.name == "openshell.compute.v1.ComputeDriver/GetCapabilities")
        .expect("in-process server span");
    assert_eq!(
        server.span_context.trace_id(),
        client.span_context.trace_id()
    );
    assert_eq!(server.parent_span_id, client.span_context.span_id());
    assert_eq!(server.span_kind, opentelemetry::trace::SpanKind::Server);
    assert!(server.attributes.iter().any(|attribute| {
        attribute.key.as_str() == "rpc.method"
            && attribute.value.to_string() == "openshell.compute.v1.ComputeDriver/GetCapabilities"
    }));
    assert!(
        server
            .attributes
            .iter()
            .all(|attribute| attribute.key.as_str() != "rpc.service"),
        "the current RPC semantic conventions integrate the service into rpc.method"
    );
    assert!(server.attributes.iter().any(|attribute| {
        attribute.key.as_str() == "rpc.response.status_code" && attribute.value.to_string() == "OK"
    }));
    assert!(
        gateway_spans
            .iter()
            .any(|span| span.name == "kubernetes.operation"),
        "unrelated driver targets must remain gateway spans"
    );
    assert!(
        driver_spans
            .iter()
            .all(|span| span.name != "kubernetes.operation"),
        "the Docker provider must not claim unrelated driver spans"
    );
    assert!(
        gateway_spans
            .iter()
            .all(|span| span.name != "docker.operation"),
        "the gateway provider must not claim the selected driver's backend spans"
    );
    assert!(
        driver_spans
            .iter()
            .any(|span| span.name == "docker.operation"),
        "the Docker provider must export backend spans from the selected driver"
    );
    let failed = driver_spans
        .iter()
        .find(|span| span.name == "openshell.compute.v1.ComputeDriver/ValidateSandboxCreate")
        .expect("failed in-process server span");
    assert!(matches!(
        failed.status,
        opentelemetry::trace::Status::Error { .. }
    ));
    assert!(failed.attributes.iter().any(|attribute| {
        attribute.key.as_str() == "rpc.response.status_code"
            && attribute.value.to_string() == "INVALID_ARGUMENT"
    }));
    gateway_provider.shutdown().unwrap();
    driver_provider.shutdown().unwrap();
}

#[tokio::test]
async fn tracing_lifecycle_rpc_failures_export_docker_operation_spans() {
    use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
    use tracing::instrument::WithSubscriber as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
    let exporter = InMemorySpanExporterBuilder::new().build();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry().with(otel_tracing::TRACING.layer(&provider));
    let driver = test_driver_with_config(runtime_config());

    async {
        ComputeDriver::create_sandbox(
            &driver,
            Request::new(CreateSandboxRequest { sandbox: None }),
        )
        .await
        .expect_err("missing sandbox should fail");
        ComputeDriver::start_sandbox(&driver, Request::new(StartSandboxRequest::default()))
            .await
            .expect_err("missing start identifier should fail");
        ComputeDriver::stop_sandbox(&driver, Request::new(StopSandboxRequest::default()))
            .await
            .expect_err("missing stop identifier should fail");
        ComputeDriver::delete_sandbox(&driver, Request::new(DeleteSandboxRequest::default()))
            .await
            .expect_err("missing delete identifier should fail");
    }
    .with_subscriber(subscriber)
    .await;
    provider.force_flush().unwrap();

    let spans = exporter.get_finished_spans().unwrap();
    for name in [
        "docker.schedule_sandbox",
        "docker.start_sandbox",
        "docker.stop_sandbox",
        "docker.delete_sandbox",
    ] {
        let span = spans
            .iter()
            .find(|span| span.name == name)
            .unwrap_or_else(|| panic!("{name} should be exported"));
        assert!(
            matches!(span.status, opentelemetry::trace::Status::Error { .. }),
            "{name} should record the failed operation"
        );
    }
    provider.shutdown().unwrap();
}

#[tokio::test]
async fn tracing_direct_start_exports_a_docker_start_span() {
    use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
    use tracing::instrument::WithSubscriber as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
    let exporter = InMemorySpanExporterBuilder::new().build();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry().with(otel_tracing::TRACING.layer(&provider));
    let driver = test_driver_with_config(runtime_config());

    Box::pin(DockerComputeDriver::start_sandbox(&driver, "", "").with_subscriber(subscriber))
        .await
        .expect_err("missing identifier should fail");
    provider.force_flush().unwrap();

    let spans = exporter.get_finished_spans().unwrap();
    let span = spans
        .iter()
        .find(|span| span.name == "docker.start_sandbox")
        .expect("direct startup operation should export docker.start_sandbox");
    assert!(matches!(
        span.status,
        opentelemetry::trace::Status::Error { .. }
    ));
    provider.shutdown().unwrap();
}

#[tokio::test]
async fn tracing_image_preparation_failure_exports_nested_failed_spans() {
    use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
    use tracing::{Instrument as _, instrument::WithSubscriber as _};
    use tracing_subscriber::layer::SubscriberExt as _;

    let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
    let exporter = InMemorySpanExporterBuilder::new().build();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry().with(otel_tracing::TRACING.layer(&provider));
    let mut config = runtime_config();
    config.image_pull_policy = "unsupported".to_string();
    let driver = test_driver_with_config(config);

    async {
        Box::pin(
            driver
                .provision_sandbox_inner(&test_sandbox())
                .instrument(tracing::info_span!(
                    "docker.provision",
                    otel.status_code = tracing::field::Empty
                )),
        )
        .await
    }
    .with_subscriber(subscriber)
    .await
    .expect_err("unsupported image pull policy should fail provisioning");
    provider.force_flush().unwrap();

    let spans = exporter.get_finished_spans().unwrap();
    let provision = spans
        .iter()
        .find(|span| span.name == "docker.provision")
        .expect("provisioning span should be exported");
    assert!(matches!(
        provision.status,
        opentelemetry::trace::Status::Error { .. }
    ));
    let prepare_image = spans
        .iter()
        .find(|span| span.name == "docker.prepare_image")
        .expect("image preparation span should be exported");
    assert_eq!(
        prepare_image.parent_span_id,
        provision.span_context.span_id()
    );
    assert!(matches!(
        prepare_image.status,
        opentelemetry::trace::Status::Error { .. }
    ));
    provider.shutdown().unwrap();
}

#[tokio::test]
async fn background_provisioning_does_not_extend_the_scheduling_span_lifetime() {
    use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
    use tracing::Instrument as _;
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
    let exporter = InMemorySpanExporterBuilder::new().build();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry().with(otel_tracing::TRACING.layer(&provider));
    let dispatch = tracing::Dispatch::new(subscriber);
    let _dispatch = tracing::dispatcher::set_default(&dispatch);

    let scheduling = tracing::info_span!("docker.schedule_sandbox");
    let entered = scheduling.enter();
    let sandbox = test_sandbox();
    let provisioning = provisioning_span(&scheduling.context(), &sandbox, "test-image");
    let task = tokio::spawn(futures::future::pending::<()>().instrument(provisioning));
    drop(entered);
    drop(scheduling);
    provider.force_flush().unwrap();

    let spans = exporter.get_finished_spans().unwrap();
    assert!(
        spans
            .iter()
            .any(|span| span.name == "docker.schedule_sandbox"),
        "the scheduling span should finish while background provisioning is pending"
    );
    assert!(
        spans.iter().all(|span| span.name != "docker.provision"),
        "the provisioning span should remain open with the background task"
    );

    task.abort();
    task.await
        .expect_err("the pending task should be cancelled");
    provider.shutdown().unwrap();
}

#[tokio::test]
async fn tracing_in_process_stream_span_lives_until_stream_failure() {
    use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
    use tracing::instrument::WithSubscriber as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
    let exporter = InMemorySpanExporterBuilder::new().build();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber =
        tracing_subscriber::registry().with(otel_tracing::TRACING.in_process_layer(&provider));

    async {
        let span = tracing::info_span!(
            target: otel_tracing::TRACING.in_process_target(),
            "driver_rpc",
            otel.name = "openshell.compute.v1.ComputeDriver/WatchSandboxes",
            otel.kind = "server",
            otel.status_code = tracing::field::Empty,
            rpc.response.status_code = tracing::field::Empty,
        );
        let inner: WatchStream = Box::pin(futures::stream::iter([Err(Status::internal(
            "watch failed",
        ))]));
        let mut stream = TracedWatchStream::new(inner, span);

        provider.force_flush().unwrap();
        assert!(
            exporter.get_finished_spans().unwrap().is_empty(),
            "server span must remain open while the response stream is alive"
        );
        stream
            .next()
            .await
            .expect("stream item")
            .expect_err("stream should fail");
        drop(stream);
    }
    .with_subscriber(subscriber)
    .await;
    provider.force_flush().unwrap();

    let spans = exporter.get_finished_spans().unwrap();
    let span = spans
        .iter()
        .find(|span| span.name == "openshell.compute.v1.ComputeDriver/WatchSandboxes")
        .expect("watch server span should be exported when the stream ends");
    assert!(matches!(
        span.status,
        opentelemetry::trace::Status::Error { .. }
    ));
    provider.shutdown().unwrap();
}

#[tokio::test]
async fn tracing_in_process_stream_records_ok_when_stream_completes() {
    use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
    use tracing::instrument::WithSubscriber as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
    let exporter = InMemorySpanExporterBuilder::new().build();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber =
        tracing_subscriber::registry().with(otel_tracing::TRACING.in_process_layer(&provider));

    async {
        let span = tracing::info_span!(
            target: otel_tracing::TRACING.in_process_target(),
            "driver_rpc",
            otel.name = "openshell.compute.v1.ComputeDriver/WatchSandboxes",
            otel.kind = "server",
            otel.status_code = tracing::field::Empty,
            rpc.response.status_code = tracing::field::Empty,
        );
        let inner: WatchStream = Box::pin(futures::stream::empty());
        let mut stream = TracedWatchStream::new(inner, span);

        assert!(stream.next().await.is_none());
        drop(stream);
    }
    .with_subscriber(subscriber)
    .await;
    provider.force_flush().unwrap();

    let spans = exporter.get_finished_spans().unwrap();
    let span = spans
        .iter()
        .find(|span| span.name == "openshell.compute.v1.ComputeDriver/WatchSandboxes")
        .expect("watch server span should be exported when the stream completes");
    assert!(span.attributes.iter().any(|attribute| {
        attribute.key.as_str() == "rpc.response.status_code" && attribute.value.to_string() == "OK"
    }));
    provider.shutdown().unwrap();
}

#[tokio::test]
async fn tracing_in_process_stream_leaves_status_unset_when_dropped() {
    use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
    use tracing::instrument::WithSubscriber as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
    let exporter = InMemorySpanExporterBuilder::new().build();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber =
        tracing_subscriber::registry().with(otel_tracing::TRACING.in_process_layer(&provider));

    async {
        let span = tracing::info_span!(
            target: otel_tracing::TRACING.in_process_target(),
            "driver_rpc",
            otel.name = "openshell.compute.v1.ComputeDriver/WatchSandboxes",
            otel.kind = "server",
            otel.status_code = tracing::field::Empty,
            rpc.response.status_code = tracing::field::Empty,
        );
        let inner: WatchStream = Box::pin(futures::stream::pending());
        let stream = TracedWatchStream::new(inner, span);

        drop(stream);
    }
    .with_subscriber(subscriber)
    .await;
    provider.force_flush().unwrap();

    let spans = exporter.get_finished_spans().unwrap();
    let span = spans
        .iter()
        .find(|span| span.name == "openshell.compute.v1.ComputeDriver/WatchSandboxes")
        .expect("watch server span should be exported when the stream is dropped");
    assert!(matches!(span.status, opentelemetry::trace::Status::Unset));
    assert!(
        span.attributes
            .iter()
            .all(|attribute| attribute.key.as_str() != "rpc.response.status_code")
    );
    provider.shutdown().unwrap();
}

#[tokio::test]
async fn gateway_listener_requirements_report_managed_bridge_address() {
    let config = runtime_config();
    let expected_address = match config.gateway_route {
        DockerGatewayRoute::Bridge { bind_address, .. } => bind_address,
        DockerGatewayRoute::HostGateway => panic!("test config must use a managed bridge"),
    };
    let driver = test_driver_with_config(config);

    let response = driver
        .get_gateway_listener_requirements(Request::new(GetGatewayListenerRequirementsRequest {}))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(response.requirements.len(), 1);
    assert_eq!(
        response.requirements[0].selector,
        Some(Selector::ExactBindAddress(expected_address.to_string()))
    );
}

#[tokio::test]
async fn gateway_listener_requirements_are_empty_for_host_gateway_route() {
    let mut config = runtime_config();
    config.gateway_route = DockerGatewayRoute::HostGateway;
    config.gateway_callback_bind_address = None;
    let driver = test_driver_with_config(config);

    let response = driver
        .get_gateway_listener_requirements(Request::new(GetGatewayListenerRequirementsRequest {}))
        .await
        .unwrap()
        .into_inner();

    assert!(response.requirements.is_empty());
}

#[tokio::test]
async fn host_gateway_route_reports_ipv4_loopback_callback_listener() {
    let mut config = runtime_config();
    config.gateway_route = DockerGatewayRoute::HostGateway;
    config.gateway_callback_bind_address = Some("127.0.0.1:17670".parse().unwrap());
    let driver = test_driver_with_config(config);

    let response = driver
        .get_gateway_listener_requirements(Request::new(GetGatewayListenerRequirementsRequest {}))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(response.requirements.len(), 1);
    assert_eq!(
        response.requirements[0].selector,
        Some(Selector::ExactBindAddress("127.0.0.1:17670".to_string()))
    );
}

#[test]
fn docker_bridge_gateway_ip_requires_ipv4_gateway() {
    let network = bollard::models::NetworkInspect {
        driver: Some(DOCKER_NETWORK_DRIVER.to_string()),
        ipam: Some(bollard::models::Ipam {
            config: Some(vec![
                bollard::models::IpamConfig {
                    gateway: Some("fd00::1".to_string()),
                    ..Default::default()
                },
                bollard::models::IpamConfig {
                    gateway: Some("172.18.0.1".to_string()),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        }),
        ..Default::default()
    };

    assert_eq!(
        docker_bridge_gateway_ip(DEFAULT_DOCKER_NETWORK_NAME, &network).unwrap(),
        IpAddr::V4(Ipv4Addr::new(172, 18, 0, 1))
    );

    let ipv6_only_network = bollard::models::NetworkInspect {
        driver: Some(DOCKER_NETWORK_DRIVER.to_string()),
        ipam: Some(bollard::models::Ipam {
            config: Some(vec![bollard::models::IpamConfig {
                gateway: Some("fd00::1".to_string()),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    };

    assert!(
        docker_bridge_gateway_ip(DEFAULT_DOCKER_NETWORK_NAME, &ipv6_only_network)
            .unwrap_err()
            .to_string()
            .contains("IPv4 IPAM gateway")
    );
}

#[test]
fn docker_gateway_route_uses_host_gateway_for_docker_desktop() {
    let info = SystemInfo {
        operating_system: Some("Docker Desktop".to_string()),
        labels: Some(vec![
            "com.docker.desktop.address=unix:///tmp/docker.sock".to_string(),
        ]),
        ..Default::default()
    };

    assert_eq!(
        docker_gateway_route(
            &info,
            IpAddr::V4(Ipv4Addr::new(172, 18, 0, 1)),
            DEFAULT_SERVER_PORT,
            None,
        ),
        DockerGatewayRoute::HostGateway
    );
}

#[test]
fn vm_backed_docker_daemon_uses_daemon_local_companion_transport() {
    let desktop = SystemInfo {
        operating_system: Some("Docker Desktop".to_string()),
        ..Default::default()
    };
    let native = SystemInfo {
        operating_system: Some("Ubuntu 24.04".to_string()),
        ..Default::default()
    };

    assert!(uses_host_gateway_alias(&desktop));
    assert!(!uses_host_gateway_alias(&native));
}

#[test]
fn host_gateway_route_requests_ipv4_loopback_for_ipv6_primary() {
    assert_eq!(
        docker_gateway_callback_bind_address(
            &DockerGatewayRoute::HostGateway,
            "[::1]:17670".parse().unwrap(),
        ),
        Some("127.0.0.1:17670".parse().unwrap())
    );
}

#[test]
fn host_gateway_route_reuses_ipv4_primary_when_it_covers_loopback() {
    for primary in ["127.0.0.1:17670", "0.0.0.0:17670"] {
        assert_eq!(
            docker_gateway_callback_bind_address(
                &DockerGatewayRoute::HostGateway,
                primary.parse().unwrap(),
            ),
            None,
            "{primary} already covers the IPv4 loopback callback"
        );
    }
}

#[test]
fn docker_gateway_route_uses_host_gateway_for_colima() {
    let info = SystemInfo {
        name: Some("colima".to_string()),
        operating_system: Some("Ubuntu 24.04.4 LTS".to_string()),
        ..Default::default()
    };

    assert_eq!(
        docker_gateway_route(
            &info,
            IpAddr::V4(Ipv4Addr::new(172, 20, 0, 1)),
            DEFAULT_SERVER_PORT,
            None,
        ),
        DockerGatewayRoute::HostGateway
    );
}

#[test]
fn docker_gateway_route_uses_host_gateway_for_colima_named_profile() {
    let info = SystemInfo {
        operating_system: Some("Ubuntu 24.04 LTS".to_string()),
        // `colima start --profile <name>` sets the daemon hostname to
        // `colima-<name>`; the prefix match still catches it.
        name: Some("colima-default".to_string()),
        ..Default::default()
    };

    assert_eq!(
        docker_gateway_route(
            &info,
            IpAddr::V4(Ipv4Addr::new(172, 18, 0, 1)),
            DEFAULT_SERVER_PORT,
            None,
        ),
        DockerGatewayRoute::HostGateway
    );
}

#[test]
fn docker_gateway_route_uses_host_gateway_for_rancher_desktop() {
    let info = SystemInfo {
        operating_system: Some("Alpine Linux v3.20".to_string()),
        name: Some("lima-rancher-desktop".to_string()),
        labels: Some(vec![
            "dev.rancherdesktop.profile=Rancher Desktop".to_string(),
        ]),
        ..Default::default()
    };

    assert_eq!(
        docker_gateway_route(
            &info,
            IpAddr::V4(Ipv4Addr::new(172, 18, 0, 1)),
            DEFAULT_SERVER_PORT,
            None,
        ),
        DockerGatewayRoute::HostGateway
    );
}

#[test]
fn docker_gateway_route_uses_host_gateway_for_orbstack() {
    let info = SystemInfo {
        operating_system: Some("OrbStack".to_string()),
        name: Some("orbstack".to_string()),
        labels: Some(vec!["dev.orbstack.machine_type=docker".to_string()]),
        ..Default::default()
    };

    assert_eq!(
        docker_gateway_route(
            &info,
            IpAddr::V4(Ipv4Addr::new(172, 18, 0, 1)),
            DEFAULT_SERVER_PORT,
            None,
        ),
        DockerGatewayRoute::HostGateway
    );
}

#[test]
fn docker_gateway_route_uses_bridge_gateway_for_linux_docker() {
    let info = SystemInfo {
        operating_system: Some("Ubuntu 24.04 LTS".to_string()),
        ..Default::default()
    };

    let route = docker_gateway_route_for_host(
        &info,
        IpAddr::V4(Ipv4Addr::new(172, 18, 0, 1)),
        DEFAULT_SERVER_PORT,
        None,
        false,
    );

    assert_eq!(
        route,
        DockerGatewayRoute::Bridge {
            bind_address: "172.18.0.1:17670".parse().unwrap(),
        }
    );
}

#[test]
fn docker_gateway_route_uses_host_gateway_when_host_runtime_requires_it() {
    let info = SystemInfo {
        operating_system: Some("Ubuntu 24.04 LTS".to_string()),
        ..Default::default()
    };

    assert_eq!(
        docker_gateway_route_for_host(
            &info,
            IpAddr::V4(Ipv4Addr::new(10, 89, 10, 1)),
            DEFAULT_SERVER_PORT,
            None,
            true,
        ),
        DockerGatewayRoute::HostGateway
    );
}

#[test]
fn docker_gateway_route_prefers_configured_host_gateway_ip() {
    let info = SystemInfo {
        operating_system: Some("Ubuntu 24.04 LTS".to_string()),
        ..Default::default()
    };

    let route = docker_gateway_route(
        &info,
        IpAddr::V4(Ipv4Addr::new(172, 18, 0, 1)),
        DEFAULT_SERVER_PORT,
        Some(IpAddr::V4(Ipv4Addr::new(172, 20, 0, 4))),
    );

    assert_eq!(
        route,
        DockerGatewayRoute::Bridge {
            bind_address: "172.20.0.4:17670".parse().unwrap(),
        }
    );
}

#[test]
fn docker_supervisor_alias_matches_the_trusted_gateway_route() {
    assert_eq!(
        docker_supervisor_host_alias(&DockerGatewayRoute::Bridge {
            bind_address: "172.20.0.4:17670".parse().unwrap(),
        }),
        "172.20.0.4"
    );
    assert_eq!(
        docker_supervisor_host_alias(&DockerGatewayRoute::HostGateway),
        "host-gateway"
    );
}

#[test]
fn parse_optional_host_gateway_ip_rejects_invalid_values() {
    assert_eq!(parse_optional_host_gateway_ip("").unwrap(), None);
    assert_eq!(
        parse_optional_host_gateway_ip("172.20.0.4").unwrap(),
        Some(IpAddr::V4(Ipv4Addr::new(172, 20, 0, 4)))
    );
    assert!(
        parse_optional_host_gateway_ip("not-an-ip")
            .unwrap_err()
            .to_string()
            .contains("host_gateway_ip")
    );
}

#[test]
fn parse_cpu_limit_supports_cores_and_millicores() {
    assert_eq!(parse_cpu_limit("250m").unwrap(), Some(250_000_000));
    assert_eq!(parse_cpu_limit("2").unwrap(), Some(2_000_000_000));
    assert!(parse_cpu_limit("0").is_err());
}

#[test]
fn parse_memory_limit_supports_binary_quantities() {
    assert_eq!(parse_memory_limit("512Mi").unwrap(), Some(536_870_912));
    assert_eq!(parse_memory_limit("1G").unwrap(), Some(1_000_000_000));
    assert!(parse_memory_limit("12XB").is_err());
}

#[test]
fn docker_resource_limits_rejects_requests() {
    let template = DriverSandboxTemplate {
        image: "img".to_string(),
        agent_socket_path: String::new(),
        labels: HashMap::new(),
        environment: HashMap::new(),
        resources: Some(DriverResourceRequirements {
            cpu_request: "250m".to_string(),
            cpu_limit: String::new(),
            memory_request: String::new(),
            memory_limit: String::new(),
        }),
        ..Default::default()
    };

    let err = docker_resource_limits(&template).unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("resources.requests.cpu"));
}

#[test]
fn docker_resource_limits_applies_cpu_and_memory_limits() {
    let template = DriverSandboxTemplate {
        image: "img".to_string(),
        agent_socket_path: String::new(),
        labels: HashMap::new(),
        environment: HashMap::new(),
        resources: Some(DriverResourceRequirements {
            cpu_limit: "500m".to_string(),
            memory_limit: "2Gi".to_string(),
            ..Default::default()
        }),
        ..Default::default()
    };

    let limits = docker_resource_limits(&template).unwrap();
    assert_eq!(limits.nano_cpus, Some(500_000_000));
    assert_eq!(limits.memory_bytes, Some(2_147_483_648));
}

#[test]
fn docker_pids_limit_uses_driver_default_and_allows_runtime_inherit() {
    assert_eq!(
        docker_pids_limit(DEFAULT_SANDBOX_PIDS_LIMIT).unwrap(),
        Some(DEFAULT_SANDBOX_PIDS_LIMIT)
    );
    assert_eq!(docker_pids_limit(0).unwrap(), None);
    assert!(docker_pids_limit(-1).is_err());
}

#[test]
fn docker_compute_config_disables_bind_mounts_by_default() {
    let cfg = DockerComputeConfig::default();
    assert!(!cfg.enable_bind_mounts);
}

#[test]
fn container_create_body_sets_driver_owned_pids_limit() {
    let body = build_container_create_body(&test_sandbox(), &runtime_config()).unwrap();
    let host_config = body.host_config.expect("host config");
    assert_eq!(host_config.pids_limit, Some(DEFAULT_SANDBOX_PIDS_LIMIT));
}

#[test]
fn docker_child_environment_strips_supervisor_control_keys() {
    let mut sandbox = test_sandbox();
    let spec = sandbox.spec.as_mut().unwrap();
    for key in [
        openshell_core::sandbox_env::ENDPOINT,
        openshell_core::sandbox_env::GATEWAY_TLS_SERVER_NAME,
        openshell_core::sandbox_env::NETWORK_RUNTIME_CAPABILITIES,
        openshell_core::sandbox_env::OCI_IMAGE_USER,
        openshell_core::sandbox_env::SANDBOX_TOKEN,
        openshell_core::sandbox_env::SANDBOX_TOKEN_FILE,
    ] {
        spec.environment
            .insert(key.to_string(), "spoofed".to_string());
    }
    spec.environment
        .insert("PATH".to_string(), "/agent/bin".to_string());

    let env = docker_child_environment(&sandbox);

    assert_eq!(env.get("PATH").map(String::as_str), Some("/agent/bin"));
    assert!(env.contains_key("TEMPLATE_ENV"));
    assert!(env.contains_key("SPEC_ENV"));
    assert!(!env.values().any(|value| value == "spoofed"));
}

#[test]
fn boundary_environment_contains_only_driver_owned_values() {
    let env = build_boundary_environment(&test_sandbox(), &runtime_config());

    assert_eq!(env.len(), 2);
    assert!(
        env.iter()
            .any(|entry| entry.starts_with("OPENSHELL_LOG_LEVEL="))
    );
    assert!(env.iter().any(|entry| entry.starts_with(&format!(
        "{}=",
        openshell_core::sandbox_env::TELEMETRY_ENABLED
    ))));
}

#[test]
fn container_creation_uses_inspected_immutable_image() {
    let sandbox = test_sandbox();
    let metadata = DockerImageMetadata {
        id: "sha256:immutable".to_string(),
        user: "1234:1235".to_string(),
        working_dir: "/workspace/project".to_string(),
        volumes: Vec::new(),
    };
    let body = build_container_create_body_for_image(
        &sandbox,
        &runtime_config(),
        &DockerSandboxDriverConfig::default(),
        None,
        &metadata,
        &test_workload_identity(),
    )
    .unwrap();

    assert_eq!(body.image.as_deref(), Some("sha256:immutable"));
    assert_eq!(body.user.as_deref(), Some("1234:1235"));
    assert_eq!(body.working_dir.as_deref(), Some("/"));
    assert_eq!(
        body.labels
            .as_ref()
            .and_then(|labels| labels.get(LABEL_ISOLATION_TOPOLOGY))
            .map(String::as_str),
        Some(LABEL_ISOLATION_TOPOLOGY_CAPABILITY_FREE)
    );
    assert_eq!(
        body.labels
            .as_ref()
            .and_then(|labels| labels.get(LABEL_ISOLATION_ROLE))
            .map(String::as_str),
        Some(LABEL_ISOLATION_ROLE_SANDBOX)
    );
    assert_eq!(
        body.cmd.as_deref(),
        Some(
            &[
                "--bootstrap".to_string(),
                BOUNDARY_CONFIG_MOUNT_PATH.to_string(),
            ][..]
        )
    );
    assert!(body.env.unwrap().iter().all(|entry| {
        !entry.starts_with(&format!("{}=", openshell_core::sandbox_env::OCI_IMAGE_USER))
    }));
    let host = body.host_config.unwrap();
    assert_eq!(host.cap_add, None);
    assert_eq!(host.cap_drop, Some(vec!["ALL".to_string()]));
    assert_eq!(host.group_add, Some(vec!["1236".to_string()]));
    assert_eq!(
        host.security_opt,
        Some(vec!["no-new-privileges:true".to_string()])
    );
    assert_eq!(host.network_mode.as_deref(), Some("none"));
    assert_eq!(host.dns, Some(vec!["127.0.0.53".to_string()]));
}

#[test]
fn docker_outer_fence_accepts_network_none_without_attachments() {
    let inspected = bollard::models::ContainerInspectResponse {
        host_config: Some(HostConfig {
            network_mode: Some("none".to_string()),
            ..Default::default()
        }),
        network_settings: Some(bollard::models::NetworkSettings {
            networks: Some(HashMap::from([(
                "none".to_string(),
                bollard::models::EndpointSettings::default(),
            )])),
            ..Default::default()
        }),
        ..Default::default()
    };

    assert!(validate_docker_outer_fence(&inspected).is_ok());
}

#[test]
fn docker_outer_fence_rejects_network_mode_or_attached_network_drift() {
    let bridge_mode = bollard::models::ContainerInspectResponse {
        host_config: Some(HostConfig {
            network_mode: Some("bridge".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let attached_network = bollard::models::ContainerInspectResponse {
        host_config: Some(HostConfig {
            network_mode: Some("none".to_string()),
            ..Default::default()
        }),
        network_settings: Some(bollard::models::NetworkSettings {
            networks: Some(HashMap::from([(
                "unexpected".to_string(),
                bollard::models::EndpointSettings::default(),
            )])),
            ..Default::default()
        }),
        ..Default::default()
    };

    assert!(validate_docker_outer_fence(&bridge_mode).is_err());
    assert!(validate_docker_outer_fence(&attached_network).is_err());
}

#[test]
fn sandbox_bundle_prepares_only_the_driver_managed_workspace() {
    let identity = test_workload_identity();
    let default_archive = docker_sandbox_bundle_archive(
        b"sandbox-binary",
        b"{}",
        DockerSandboxTls {
            certificate: b"server-cert",
            private_key: b"server-key",
            client_ca: b"client-ca",
        },
        &identity,
        driver_mounts::DEFAULT_WORKSPACE_ROOT,
    )
    .unwrap();
    let mut archive = tar::Archive::new(default_archive.as_slice());
    let sandbox_entry = archive
        .entries()
        .unwrap()
        .map(Result::unwrap)
        .find(|entry| entry.path().unwrap().as_ref() == Path::new("sandbox"))
        .expect("managed /sandbox entry");
    assert!(sandbox_entry.header().entry_type().is_dir());
    assert_eq!(sandbox_entry.header().mode().unwrap(), 0o700);
    assert_eq!(
        sandbox_entry.header().uid().unwrap(),
        u64::from(identity.uid)
    );
    assert_eq!(
        sandbox_entry.header().gid().unwrap(),
        u64::from(identity.gid)
    );

    let image_archive = docker_sandbox_bundle_archive(
        b"sandbox-binary",
        b"{}",
        DockerSandboxTls {
            certificate: b"server-cert",
            private_key: b"server-key",
            client_ca: b"client-ca",
        },
        &identity,
        "/workspace/project",
    )
    .unwrap();
    let mut archive = tar::Archive::new(image_archive.as_slice());
    assert!(
        archive
            .entries()
            .unwrap()
            .map(Result::unwrap)
            .all(|entry| { entry.path().unwrap().as_ref() != Path::new("workspace/project") })
    );
}

#[test]
fn sandbox_bundle_stages_private_mutual_tls_material() {
    let identity = test_workload_identity();
    let archive = docker_sandbox_bundle_archive(
        b"sandbox-binary",
        b"{}",
        DockerSandboxTls {
            certificate: b"server-cert",
            private_key: b"server-key",
            client_ca: b"client-ca",
        },
        &identity,
        driver_mounts::DEFAULT_WORKSPACE_ROOT,
    )
    .unwrap();
    let mut archive = tar::Archive::new(archive.as_slice());
    let entries = archive
        .entries()
        .unwrap()
        .map(Result::unwrap)
        .filter_map(|entry| {
            let path = entry.path().ok()?.into_owned();
            Some((
                path,
                (
                    entry.header().mode().ok()?,
                    entry.header().uid().ok()?,
                    entry.header().gid().ok()?,
                ),
            ))
        })
        .collect::<HashMap<_, _>>();
    for path in [
        ".openshell/channel/sandbox/server.crt",
        ".openshell/channel/sandbox/server.key",
        ".openshell/channel/sandbox/client-ca.crt",
    ] {
        assert_eq!(
            entries.get(Path::new(path)),
            Some(&(0o600, u64::from(identity.uid), u64::from(identity.gid)))
        );
    }
    assert_eq!(
        entries.get(Path::new(".openshell/runtime/openshell-sandbox")),
        Some(&(0o555, 0, 0)),
        "the trusted sandbox executable must not be writable by the workload"
    );
    assert_eq!(
        entries.get(Path::new(".openshell/channel")),
        Some(&(0o755, 0, 0)),
        "the workload must not be able to replace the supervisor secret directory"
    );
    assert_eq!(
        entries.get(Path::new(".openshell/channel/sandbox")),
        Some(&(0o711, u64::from(identity.uid), u64::from(identity.gid))),
        "the supervisor must be able to traverse to the authenticated socket without reading sandbox secrets"
    );
}

#[test]
fn docker_identity_resolution_uses_pinned_image_accounts_and_exact_groups() {
    let sandbox = test_sandbox();
    let image = DockerImageMetadata {
        id: "sha256:image".to_string(),
        user: "agent".to_string(),
        working_dir: "/sandbox".to_string(),
        volumes: Vec::new(),
    };
    let resolved = resolve_docker_identity_from_accounts(
        &sandbox,
        &image,
        b"root:x:0:0:root:/root:/bin/sh\nagent:x:10001:10002::/sandbox:/bin/sh\n",
        b"root:x:0:\nagent:x:10002:\nrender:x:10003:agent\n",
    )
    .unwrap();

    assert_eq!(resolved.uid, 10001);
    assert_eq!(resolved.gid, 10002);
    assert_eq!(resolved.supplementary_gids, vec![10003]);
    assert_eq!(resolved.source, "image");
    assert_eq!(resolved.resource_digest, "sha256:image");
}

#[test]
fn docker_identity_resolution_honors_policy_selectors_and_rejects_root() {
    let mut sandbox = test_sandbox();
    sandbox.spec.as_mut().unwrap().workload_identity = Some(WorkloadIdentityRequest {
        user: "10001".to_string(),
        group: "workers".to_string(),
    });
    let image = DockerImageMetadata {
        id: "sha256:image".to_string(),
        user: String::new(),
        working_dir: "/sandbox".to_string(),
        volumes: Vec::new(),
    };
    let resolved = resolve_docker_identity_from_accounts(
        &sandbox,
        &image,
        b"agent:x:10001:10002::/sandbox:/bin/sh\n",
        b"workers:x:10004:agent\n",
    )
    .unwrap();
    assert_eq!((resolved.uid, resolved.gid), (10001, 10004));
    assert_eq!(resolved.source, "policy");

    sandbox.spec.as_mut().unwrap().workload_identity = Some(WorkloadIdentityRequest {
        user: "root".to_string(),
        group: "root".to_string(),
    });
    let error = resolve_docker_identity_from_accounts(
        &sandbox,
        &image,
        b"root:x:0:0:root:/root:/bin/sh\n",
        b"root:x:0:\n",
    )
    .unwrap_err();
    assert!(error.message().contains("UID or GID zero"));
}

#[test]
fn container_creation_rejects_invalid_oci_working_dir() {
    let metadata = DockerImageMetadata {
        id: "sha256:immutable".to_string(),
        user: "1234:1235".to_string(),
        working_dir: "relative/workspace".to_string(),
        volumes: Vec::new(),
    };
    let err = build_container_create_body_for_image(
        &test_sandbox(),
        &runtime_config(),
        &DockerSandboxDriverConfig::default(),
        None,
        &metadata,
        &test_workload_identity(),
    )
    .unwrap_err();

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("must be an absolute container path"));
}

#[test]
fn container_creation_rejects_openshell_control_path_working_dir() {
    let metadata = DockerImageMetadata {
        id: "sha256:immutable".to_string(),
        user: "1234:1235".to_string(),
        working_dir: "/opt/openshell/bin/project".to_string(),
        volumes: Vec::new(),
    };
    let err = build_container_create_body_for_image(
        &test_sandbox(),
        &runtime_config(),
        &DockerSandboxDriverConfig::default(),
        None,
        &metadata,
        &test_workload_identity(),
    )
    .unwrap_err();

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("OpenShell control path"));
}

#[test]
fn container_creation_rejects_image_volume_that_masks_working_dir() {
    let sandbox = test_sandbox();
    let metadata = DockerImageMetadata {
        id: "sha256:immutable".to_string(),
        user: "1234:1235".to_string(),
        working_dir: "/workspace/project".to_string(),
        volumes: vec!["/workspace".to_string()],
    };

    let error = build_container_create_body_for_image(
        &sandbox,
        &runtime_config(),
        &DockerSandboxDriverConfig::default(),
        None,
        &metadata,
        &test_workload_identity(),
    )
    .unwrap_err();

    assert!(
        error
            .message()
            .contains("masks OCI WorkingDir '/workspace/project'")
    );
}

#[test]
fn container_creation_reserves_resolved_workspace_root_but_allows_nested_mounts() {
    let metadata = DockerImageMetadata {
        id: "sha256:immutable".to_string(),
        user: "1234:1235".to_string(),
        working_dir: "/workspace".to_string(),
        volumes: Vec::new(),
    };
    let root_mount: DockerSandboxDriverConfig = serde_json::from_value(serde_json::json!({
        "mounts": [{"type": "tmpfs", "target": "/workspace"}]
    }))
    .unwrap();
    let err = build_container_create_body_for_image(
        &test_sandbox(),
        &runtime_config(),
        &root_mount,
        None,
        &metadata,
        &test_workload_identity(),
    )
    .unwrap_err();
    assert!(
        err.message()
            .contains("reserved for the OpenShell workspace")
    );

    let ancestor_mount: DockerSandboxDriverConfig = serde_json::from_value(serde_json::json!({
        "mounts": [{"type": "tmpfs", "target": "/workspace"}]
    }))
    .unwrap();
    let nested_metadata = DockerImageMetadata {
        working_dir: "/workspace/project".to_string(),
        volumes: Vec::new(),
        ..metadata.clone()
    };
    let err = build_container_create_body_for_image(
        &test_sandbox(),
        &runtime_config(),
        &ancestor_mount,
        None,
        &nested_metadata,
        &test_workload_identity(),
    )
    .unwrap_err();
    assert!(
        err.message()
            .contains("reserved for the OpenShell workspace")
    );

    let nested_mount: DockerSandboxDriverConfig = serde_json::from_value(serde_json::json!({
        "mounts": [{"type": "tmpfs", "target": "/workspace/cache"}]
    }))
    .unwrap();
    build_container_create_body_for_image(
        &test_sandbox(),
        &runtime_config(),
        &nested_mount,
        None,
        &metadata,
        &test_workload_identity(),
    )
    .expect("nested workspace mounts remain supported");

    let compatibility_path_mount: DockerSandboxDriverConfig =
        serde_json::from_value(serde_json::json!({
            "mounts": [{"type": "tmpfs", "target": "/sandbox"}]
        }))
        .unwrap();
    build_container_create_body_for_image(
        &test_sandbox(),
        &runtime_config(),
        &compatibility_path_mount,
        None,
        &metadata,
        &test_workload_identity(),
    )
    .expect("/sandbox remains mountable when the inspected workspace is elsewhere");
}

#[test]
fn build_binds_does_not_expose_host_runtime_material() {
    let binds = build_binds(&test_sandbox(), &runtime_config());
    assert!(binds.is_empty());
}

#[test]
fn build_container_create_body_includes_driver_config_mounts() {
    let mut sandbox = test_sandbox();
    let template = sandbox.spec.as_mut().unwrap().template.as_mut().unwrap();
    template.driver_config = Some(json_struct(serde_json::json!({
        "mounts": [
            {
                "type": "volume",
                "source": "work-nfs",
                "target": "/sandbox/work",
                "read_only": true,
                "subpath": "project-a"
            },
            {
                "type": "tmpfs",
                "target": "/sandbox/cache",
                "options": ["nosuid", "size=1048576"],
                "size_bytes": 1_048_576,
                "mode": 511
            }
        ]
    })));

    let body = build_container_create_body(&sandbox, &runtime_config()).unwrap();
    let mounts = body
        .host_config
        .unwrap()
        .mounts
        .expect("driver config mounts should be set");

    assert_eq!(mounts.len(), 3);
    assert_eq!(mounts[0].typ, Some(MountTypeEnum::VOLUME));
    assert_eq!(mounts[0].source.as_deref(), Some("work-nfs"));
    assert_eq!(mounts[0].target.as_deref(), Some("/sandbox/work"));
    assert_eq!(mounts[0].read_only, Some(true));
    assert_eq!(
        mounts[0]
            .volume_options
            .as_ref()
            .and_then(|options| options.subpath.as_deref()),
        Some("project-a")
    );
    assert_eq!(mounts[1].typ, Some(MountTypeEnum::TMPFS));
    assert_eq!(mounts[1].target.as_deref(), Some("/sandbox/cache"));
    assert_eq!(mounts[2].typ, Some(MountTypeEnum::VOLUME));
    assert_eq!(mounts[2].target.as_deref(), Some(BOUNDARY_MOUNT_PATH));
    assert_eq!(mounts[2].read_only, Some(false));
    assert_eq!(
        mounts[1]
            .tmpfs_options
            .as_ref()
            .and_then(|options| options.size_bytes),
        Some(1_048_576)
    );
}

#[test]
fn driver_config_defaults_volume_mounts_to_read_only() {
    let mut sandbox = test_sandbox();
    sandbox
        .spec
        .as_mut()
        .unwrap()
        .template
        .as_mut()
        .unwrap()
        .driver_config = Some(json_struct(serde_json::json!({
        "mounts": [{
            "type": "volume",
            "source": "work-nfs",
            "target": "/sandbox/work"
        }]
    })));

    let body = build_container_create_body(&sandbox, &runtime_config()).unwrap();
    let mounts = body
        .host_config
        .unwrap()
        .mounts
        .expect("driver config mounts should be set");

    assert_eq!(mounts[0].read_only, Some(true));
}

#[test]
fn driver_config_allows_explicit_writable_volume_mounts() {
    let mut sandbox = test_sandbox();
    sandbox
        .spec
        .as_mut()
        .unwrap()
        .template
        .as_mut()
        .unwrap()
        .driver_config = Some(json_struct(serde_json::json!({
        "mounts": [{
            "type": "volume",
            "source": "work-nfs",
            "target": "/sandbox/work",
            "read_only": false
        }]
    })));

    let body = build_container_create_body(&sandbox, &runtime_config()).unwrap();
    let mounts = body
        .host_config
        .unwrap()
        .mounts
        .expect("driver config mounts should be set");

    assert_eq!(mounts[0].read_only, Some(false));
}

#[test]
fn driver_config_rejects_duplicate_mount_targets() {
    let mut sandbox = test_sandbox();
    sandbox
        .spec
        .as_mut()
        .unwrap()
        .template
        .as_mut()
        .unwrap()
        .driver_config = Some(json_struct(serde_json::json!({
        "mounts": [
            {
                "type": "volume",
                "source": "work-nfs",
                "target": "/sandbox/work"
            },
            {
                "type": "tmpfs",
                "target": "/sandbox/work"
            }
        ]
    })));

    let err = build_container_create_body(&sandbox, &runtime_config()).unwrap_err();

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(
        err.message()
            .contains("duplicate docker driver_config mount target")
    );
}

#[test]
fn driver_config_rejects_bind_mounts_unless_enabled() {
    let mut sandbox = test_sandbox();
    sandbox
        .spec
        .as_mut()
        .unwrap()
        .template
        .as_mut()
        .unwrap()
        .driver_config = Some(json_struct(serde_json::json!({
        "mounts": [{
            "type": "bind",
            "source": "/host/path",
            "target": "/sandbox/host"
        }]
    })));

    let err = build_container_create_body(&sandbox, &runtime_config()).unwrap_err();

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("enable_bind_mounts = true"));
}

#[test]
fn build_container_create_body_includes_bind_mounts_when_enabled() {
    let bind_src = TempDir::new().unwrap();
    let src_path = bind_src.path().to_str().unwrap();
    let mut sandbox = test_sandbox();
    sandbox
        .spec
        .as_mut()
        .unwrap()
        .template
        .as_mut()
        .unwrap()
        .driver_config = Some(json_struct(serde_json::json!({
        "mounts": [{
            "type": "bind",
            "source": src_path,
            "target": "/sandbox/host",
            "read_only": true
        }]
    })));
    let mut config = runtime_config();
    config.enable_bind_mounts = true;

    let body = build_container_create_body(&sandbox, &config).unwrap();
    let binds = body
        .host_config
        .as_ref()
        .unwrap()
        .binds
        .as_ref()
        .expect("binds should be set");

    // User bind mount appears after the system binds.
    let expected = format!("{src_path}:/sandbox/host:ro");
    assert!(
        binds.iter().any(|b| b == &expected),
        "expected bind entry '{expected}', got {binds:?}"
    );
    // Bind mounts must not appear in the structured mounts vec.
    let mounts = body.host_config.unwrap().mounts.unwrap_or_default();
    assert!(
        mounts.iter().all(|m| m.typ != Some(MountTypeEnum::BIND)),
        "bind mounts should not appear in structured mounts"
    );
}

#[test]
fn driver_config_defaults_enabled_bind_mounts_to_read_only() {
    let bind_src = TempDir::new().unwrap();
    let src_path = bind_src.path().to_str().unwrap();
    let mut sandbox = test_sandbox();
    sandbox
        .spec
        .as_mut()
        .unwrap()
        .template
        .as_mut()
        .unwrap()
        .driver_config = Some(json_struct(serde_json::json!({
        "mounts": [{
            "type": "bind",
            "source": src_path,
            "target": "/sandbox/host"
        }]
    })));
    let mut config = runtime_config();
    config.enable_bind_mounts = true;

    let body = build_container_create_body(&sandbox, &config).unwrap();
    let binds = body
        .host_config
        .unwrap()
        .binds
        .expect("binds should be set");

    let expected = format!("{src_path}:/sandbox/host:ro");
    assert!(
        binds.iter().any(|b| b == &expected),
        "default bind mount should be read-only, got {binds:?}"
    );
}

#[test]
fn bind_mount_selinux_shared_label() {
    let bind_src = TempDir::new().unwrap();
    let src_path = bind_src.path().to_str().unwrap();
    let mut sandbox = test_sandbox();
    sandbox
        .spec
        .as_mut()
        .unwrap()
        .template
        .as_mut()
        .unwrap()
        .driver_config = Some(json_struct(serde_json::json!({
        "mounts": [{
            "type": "bind",
            "source": src_path,
            "target": "/sandbox/data",
            "read_only": true,
            "selinux_label": "shared"
        }]
    })));
    let mut config = runtime_config();
    config.enable_bind_mounts = true;

    let body = build_container_create_body(&sandbox, &config).unwrap();
    let binds = body
        .host_config
        .unwrap()
        .binds
        .expect("binds should be set");

    let expected = format!("{src_path}:/sandbox/data:ro,z");
    assert!(
        binds.iter().any(|b| b == &expected),
        "expected ':ro,z' label, got {binds:?}"
    );
}

#[test]
fn bind_mount_selinux_private_label() {
    let bind_src = TempDir::new().unwrap();
    let src_path = bind_src.path().to_str().unwrap();
    let mut sandbox = test_sandbox();
    sandbox
        .spec
        .as_mut()
        .unwrap()
        .template
        .as_mut()
        .unwrap()
        .driver_config = Some(json_struct(serde_json::json!({
        "mounts": [{
            "type": "bind",
            "source": src_path,
            "target": "/sandbox/data",
            "read_only": false,
            "selinux_label": "private"
        }]
    })));
    let mut config = runtime_config();
    config.enable_bind_mounts = true;

    let body = build_container_create_body(&sandbox, &config).unwrap();
    let binds = body
        .host_config
        .unwrap()
        .binds
        .expect("binds should be set");

    let expected = format!("{src_path}:/sandbox/data:Z");
    assert!(
        binds.iter().any(|b| b == &expected),
        "expected ':Z' label, got {binds:?}"
    );
}

#[test]
fn bind_mount_without_selinux_label() {
    let bind_src = TempDir::new().unwrap();
    let src_path = bind_src.path().to_str().unwrap();
    let mut sandbox = test_sandbox();
    sandbox
        .spec
        .as_mut()
        .unwrap()
        .template
        .as_mut()
        .unwrap()
        .driver_config = Some(json_struct(serde_json::json!({
        "mounts": [{
            "type": "bind",
            "source": src_path,
            "target": "/sandbox/host",
            "read_only": false
        }]
    })));
    let mut config = runtime_config();
    config.enable_bind_mounts = true;

    let body = build_container_create_body(&sandbox, &config).unwrap();
    let binds = body
        .host_config
        .unwrap()
        .binds
        .expect("binds should be set");

    let expected = format!("{src_path}:/sandbox/host");
    assert!(
        binds.iter().any(|b| b == &expected),
        "expected no options suffix, got {binds:?}"
    );
}

#[test]
fn driver_config_rejects_missing_bind_source() {
    let mut sandbox = test_sandbox();
    sandbox
        .spec
        .as_mut()
        .unwrap()
        .template
        .as_mut()
        .unwrap()
        .driver_config = Some(json_struct(serde_json::json!({
        "mounts": [{
            "type": "bind",
            "source": "/no/such/path",
            "target": "/sandbox/data"
        }]
    })));
    let mut config = runtime_config();
    config.enable_bind_mounts = true;

    let err = build_container_create_body(&sandbox, &config).unwrap_err();

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(
        err.message().contains("bind source path does not exist"),
        "expected missing-source error, got: {}",
        err.message()
    );
}

#[test]
fn driver_config_rejects_relative_bind_sources_when_enabled() {
    let mut sandbox = test_sandbox();
    sandbox
        .spec
        .as_mut()
        .unwrap()
        .template
        .as_mut()
        .unwrap()
        .driver_config = Some(json_struct(serde_json::json!({
        "mounts": [{
            "type": "bind",
            "source": "relative/path",
            "target": "/sandbox/host"
        }]
    })));
    let mut config = runtime_config();
    config.enable_bind_mounts = true;

    let err = build_container_create_body(&sandbox, &config).unwrap_err();

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(
        err.message()
            .contains("bind source must be an absolute host path")
    );
}

#[test]
fn driver_config_rejects_image_mounts() {
    let mut sandbox = test_sandbox();
    sandbox
        .spec
        .as_mut()
        .unwrap()
        .template
        .as_mut()
        .unwrap()
        .driver_config = Some(json_struct(serde_json::json!({
        "mounts": [{
            "type": "image",
            "source": "ghcr.io/acme/tools:latest",
            "target": "/opt/tools"
        }]
    })));

    let err = build_container_create_body(&sandbox, &runtime_config()).unwrap_err();

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("invalid docker driver_config"));
}

#[test]
fn driver_config_rejects_reserved_mount_targets() {
    let mut sandbox = test_sandbox();
    sandbox
        .spec
        .as_mut()
        .unwrap()
        .template
        .as_mut()
        .unwrap()
        .driver_config = Some(json_struct(serde_json::json!({
        "mounts": [{
            "type": "volume",
            "source": "work-nfs",
            "target": "/etc/openshell/auth"
        }]
    })));

    let err = build_container_create_body(&sandbox, &runtime_config()).unwrap_err();

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("reserved OpenShell path"));
}

#[test]
fn docker_local_volume_with_bind_option_is_bind_backed() {
    let volume = inspected_volume(
        "local",
        HashMap::from([
            ("type".to_string(), "none".to_string()),
            ("o".to_string(), "rw,bind".to_string()),
            ("device".to_string(), "/tmp/openshell".to_string()),
        ]),
    );

    assert!(docker_volume_is_bind_backed(&volume));
}

#[test]
fn docker_local_volume_with_rbind_option_is_bind_backed() {
    let volume = inspected_volume(
        "local",
        HashMap::from([
            ("type".to_string(), "none".to_string()),
            ("o".to_string(), "rw,rbind".to_string()),
            ("device".to_string(), "/tmp/openshell".to_string()),
        ]),
    );

    assert!(docker_volume_is_bind_backed(&volume));
}

#[test]
fn docker_local_volume_without_bind_option_is_not_bind_backed() {
    let volume = inspected_volume(
        "local",
        HashMap::from([
            ("type".to_string(), "nfs".to_string()),
            ("o".to_string(), "addr=127.0.0.1,rw".to_string()),
            ("device".to_string(), ":/exports/openshell".to_string()),
        ]),
    );

    assert!(!docker_volume_is_bind_backed(&volume));
}

#[test]
fn docker_nonlocal_volume_with_bind_option_is_not_bind_backed() {
    let volume = inspected_volume(
        "custom",
        HashMap::from([("o".to_string(), "bind".to_string())]),
    );

    assert!(!docker_volume_is_bind_backed(&volume));
}

#[test]
fn managed_container_label_filters_include_gateway_namespace() {
    let filters =
        managed_container_label_filters("tenant-a", [format!("{LABEL_SANDBOX_ID}=sbx-123")]);
    let labels = filters.get("label").unwrap();

    assert!(labels.contains(&format!("{LABEL_MANAGED_BY}={LABEL_MANAGED_BY_VALUE}")));
    assert!(labels.contains(&format!("{LABEL_SANDBOX_NAMESPACE}=tenant-a")));
    assert!(labels.contains(&format!(
        "{LABEL_ISOLATION_ROLE}={LABEL_ISOLATION_ROLE_SANDBOX}"
    )));
    assert!(labels.contains(&format!("{LABEL_SANDBOX_ID}=sbx-123")));
}

#[test]
fn build_container_create_body_replaces_inherited_cmd_with_sandbox_bootstrap() {
    let create_body = build_container_create_body(&test_sandbox(), &runtime_config()).unwrap();

    assert_eq!(
        create_body.entrypoint,
        Some(vec![SANDBOX_BINARY_PATH.to_string()])
    );
    assert_eq!(
        create_body.cmd,
        Some(vec![
            "--bootstrap".to_string(),
            BOUNDARY_CONFIG_MOUNT_PATH.to_string(),
        ])
    );
    assert_eq!(
        create_body
            .labels
            .as_ref()
            .and_then(|labels| labels.get(LABEL_SANDBOX_NAMESPACE)),
        Some(&"default".to_string())
    );
    let host_config = create_body.host_config.as_ref().unwrap();
    assert!(
        host_config.device_requests.as_ref().is_none(),
        "non-GPU containers should not request Docker devices"
    );
    assert_eq!(
        host_config.security_opt.as_ref(),
        Some(&vec!["no-new-privileges:true".to_string()])
    );
    assert_eq!(host_config.network_mode.as_deref(), Some("none"));
    assert_eq!(host_config.extra_hosts, None);
    assert!(create_body.networking_config.is_none());
}

#[test]
fn validate_sandbox_rejects_gpu_when_cdi_unavailable() {
    let config = runtime_config();
    let mut sandbox = test_sandbox();
    sandbox.spec.as_mut().unwrap().resource_requirements = Some(gpu_resources(None));

    let err = DockerComputeDriver::validate_sandbox(&sandbox, &config).unwrap_err();

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("Docker CDI"));
}

#[test]
fn validate_sandbox_rejects_missing_gpu_support_before_request_shape() {
    let config = runtime_config();
    let mut sandbox = test_sandbox();
    let spec = sandbox.spec.as_mut().unwrap();
    spec.resource_requirements = Some(gpu_resources(Some(2)));
    spec.template.as_mut().unwrap().driver_config = Some(cdi_devices_config(&["nvidia.com/gpu=0"]));

    let err = DockerComputeDriver::validate_sandbox(&sandbox, &config).unwrap_err();

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("Docker CDI"));
}

#[test]
fn validate_sandbox_rejects_invalid_cdi_devices_before_gpu_capability() {
    let config = runtime_config();
    let mut sandbox = test_sandbox();
    let spec = sandbox.spec.as_mut().unwrap();
    spec.resource_requirements = Some(gpu_resources(None));
    spec.template.as_mut().unwrap().driver_config = Some(cdi_devices_config(&[]));

    let err = DockerComputeDriver::validate_sandbox(&sandbox, &config).unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("invalid docker driver_config"));
    assert!(err.message().contains("non-empty list"));
}

#[test]
fn validate_sandbox_rejects_unknown_driver_config_fields() {
    let config = runtime_config();
    let mut sandbox = test_sandbox();
    let spec = sandbox.spec.as_mut().unwrap();
    spec.resource_requirements = Some(gpu_resources(None));
    spec.template.as_mut().unwrap().driver_config =
        Some(cdi_device_typo_config(&["nvidia.com/gpu=0"]));

    let err = DockerComputeDriver::validate_sandbox(&sandbox, &config).unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("unknown field"));
}

#[test]
fn validate_sandbox_accepts_gpu_count_request_shape() {
    let mut config = runtime_config();
    config.supports_gpu = true;
    let mut sandbox = test_sandbox();
    sandbox.spec.as_mut().unwrap().resource_requirements = Some(gpu_resources(Some(2)));

    DockerComputeDriver::validate_sandbox(&sandbox, &config)
        .expect("default GPU count shape should be accepted before inventory selection");
}

#[test]
fn validate_sandbox_accepts_gpu_count_matching_cdi_devices() {
    let mut config = runtime_config();
    config.supports_gpu = true;
    let mut sandbox = test_sandbox();
    let spec = sandbox.spec.as_mut().unwrap();
    spec.resource_requirements = Some(gpu_resources(Some(2)));
    spec.template.as_mut().unwrap().driver_config = Some(cdi_devices_config(&[
        "nvidia.com/gpu=0",
        "nvidia.com/gpu=1",
    ]));

    DockerComputeDriver::validate_sandbox(&sandbox, &config)
        .expect("matching explicit CDI device count should be accepted");
}

#[test]
fn validate_sandbox_accepts_single_cdi_device_without_gpu_count() {
    let mut config = runtime_config();
    config.supports_gpu = true;
    let mut sandbox = test_sandbox();
    let spec = sandbox.spec.as_mut().unwrap();
    spec.resource_requirements = Some(gpu_resources(None));
    spec.template.as_mut().unwrap().driver_config = Some(cdi_devices_config(&["nvidia.com/gpu=0"]));

    DockerComputeDriver::validate_sandbox(&sandbox, &config)
        .expect("single exact CDI device should be compatible with a default GPU request");
}

#[test]
fn validate_sandbox_rejects_multiple_cdi_devices_without_gpu_count() {
    let mut config = runtime_config();
    config.supports_gpu = true;
    let mut sandbox = test_sandbox();
    let spec = sandbox.spec.as_mut().unwrap();
    spec.resource_requirements = Some(gpu_resources(None));
    spec.template.as_mut().unwrap().driver_config = Some(cdi_devices_config(&[
        "nvidia.com/gpu=0",
        "nvidia.com/gpu=1",
    ]));

    let err = DockerComputeDriver::validate_sandbox(&sandbox, &config).unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(
        err.message()
            .contains("gpu count (1) must match driver_config.cdi_devices length (2)")
    );
}

#[test]
fn validate_sandbox_rejects_cdi_devices_without_gpu_request() {
    let mut config = runtime_config();
    config.supports_gpu = true;
    let mut sandbox = test_sandbox();
    sandbox
        .spec
        .as_mut()
        .unwrap()
        .template
        .as_mut()
        .unwrap()
        .driver_config = Some(cdi_devices_config(&["nvidia.com/gpu=0"]));

    let err = DockerComputeDriver::validate_sandbox(&sandbox, &config).unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("requires a gpu request"));
}

#[test]
fn validate_sandbox_rejects_gpu_count_mismatched_cdi_devices() {
    let mut config = runtime_config();
    config.supports_gpu = true;
    let mut sandbox = test_sandbox();
    let spec = sandbox.spec.as_mut().unwrap();
    spec.resource_requirements = Some(gpu_resources(Some(2)));
    spec.template.as_mut().unwrap().driver_config = Some(cdi_devices_config(&["nvidia.com/gpu=0"]));

    let err = DockerComputeDriver::validate_sandbox(&sandbox, &config).unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(
        err.message()
            .contains("gpu count (2) must match driver_config.cdi_devices length (1)")
    );
}

#[test]
fn validate_sandbox_rejects_template_errors_before_device_config() {
    let config = runtime_config();
    let mut sandbox = test_sandbox();
    let spec = sandbox.spec.as_mut().unwrap();
    spec.resource_requirements = Some(gpu_resources(None));
    let template = spec.template.as_mut().unwrap();
    template.agent_socket_path = "/tmp/agent.sock".to_string();
    template.driver_config = Some(cdi_devices_config(&[]));

    let err = DockerComputeDriver::validate_sandbox(&sandbox, &config).unwrap_err();

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("agent_socket_path"));
}

#[test]
fn validate_sandbox_auth_requires_gateway_token() {
    let mut sandbox = test_sandbox();
    sandbox.spec.as_mut().unwrap().sandbox_token.clear();

    let err = DockerComputeDriver::validate_sandbox_auth(&sandbox).unwrap_err();

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        err.message(),
        "docker sandboxes require gateway JWT auth; configure [openshell.gateway.gateway_jwt]"
    );
}

#[test]
fn validate_sandbox_auth_accepts_gateway_token() {
    let mut sandbox = test_sandbox();
    sandbox.spec.as_mut().unwrap().sandbox_token = "secret.jwt.value".to_string();

    DockerComputeDriver::validate_sandbox_auth(&sandbox).unwrap();
}

#[test]
fn build_container_create_body_maps_default_gpu_to_selected_cdi_device() {
    let mut config = runtime_config();
    config.supports_gpu = true;
    let mut sandbox = test_sandbox();
    sandbox.spec.as_mut().unwrap().resource_requirements = Some(gpu_resources(None));

    let driver_config = DockerSandboxDriverConfig::default();
    let gpu_devices = vec!["nvidia.com/gpu=1".to_string()];
    let create_body = build_container_create_body_with_gpu_devices(
        &sandbox,
        &config,
        &driver_config,
        Some(&gpu_devices),
    )
    .unwrap();
    let request = create_body
        .host_config
        .as_ref()
        .and_then(|host_config| host_config.device_requests.as_ref())
        .and_then(|requests| requests.first())
        .expect("GPU request should add a Docker device request");

    assert_eq!(request.driver.as_deref(), Some("cdi"));
    assert_eq!(
        request.device_ids.as_ref().unwrap(),
        &vec!["nvidia.com/gpu=1".to_string()]
    );
}

#[test]
fn build_container_create_body_omits_devices_without_resolved_default_cdi_devices() {
    let mut config = runtime_config();
    config.supports_gpu = true;
    let mut sandbox = test_sandbox();
    sandbox.spec.as_mut().unwrap().resource_requirements = Some(gpu_resources(None));

    let create_body = build_container_create_body(&sandbox, &config).unwrap();

    assert!(
        create_body
            .host_config
            .as_ref()
            .and_then(|host_config| host_config.device_requests.as_ref())
            .is_none()
    );
}

#[test]
fn build_container_create_body_passes_explicit_cdi_device_id_through() {
    let mut config = runtime_config();
    config.supports_gpu = true;
    let mut sandbox = test_sandbox();
    let spec = sandbox.spec.as_mut().unwrap();
    spec.resource_requirements = Some(gpu_resources(None));
    spec.template.as_mut().unwrap().driver_config = Some(cdi_devices_config(&["nvidia.com/gpu=0"]));

    let create_body = build_container_create_body(&sandbox, &config).unwrap();
    let request = create_body
        .host_config
        .as_ref()
        .and_then(|host_config| host_config.device_requests.as_ref())
        .and_then(|requests| requests.first())
        .expect("GPU request should add a Docker device request");

    assert_eq!(request.driver.as_deref(), Some("cdi"));
    assert_eq!(
        request.device_ids.as_ref().unwrap(),
        &vec!["nvidia.com/gpu=0".to_string()]
    );
}

#[test]
fn build_container_create_body_rejects_gpu_count_mismatched_cdi_devices() {
    let mut config = runtime_config();
    config.supports_gpu = true;
    let mut sandbox = test_sandbox();
    let spec = sandbox.spec.as_mut().unwrap();
    spec.resource_requirements = Some(gpu_resources(Some(2)));
    spec.template.as_mut().unwrap().driver_config = Some(cdi_devices_config(&["nvidia.com/gpu=0"]));

    let err = build_container_create_body(&sandbox, &config).unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(
        err.message()
            .contains("gpu count (2) must match driver_config.cdi_devices length (1)")
    );
}

#[test]
fn build_container_create_body_rejects_cdi_devices_without_gpu_request() {
    let mut sandbox = test_sandbox();
    sandbox
        .spec
        .as_mut()
        .unwrap()
        .template
        .as_mut()
        .unwrap()
        .driver_config = Some(cdi_devices_config(&["nvidia.com/gpu=0"]));

    let err = build_container_create_body(&sandbox, &runtime_config()).unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("requires a gpu request"));
}

#[test]
fn build_container_create_body_rejects_empty_cdi_devices() {
    let mut sandbox = test_sandbox();
    let spec = sandbox.spec.as_mut().unwrap();
    spec.resource_requirements = Some(gpu_resources(None));
    spec.template.as_mut().unwrap().driver_config = Some(cdi_devices_config(&[]));

    let err = build_container_create_body(&sandbox, &runtime_config()).unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("non-empty list"));
}

#[test]
fn driver_default_gpu_selection_consumes_distinct_devices_for_creates() {
    let mut config = runtime_config();
    config.supports_gpu = true;
    let driver = test_driver_with_config(config);
    driver.gpu_selector.refresh(
        CdiGpuInventory::new(["nvidia.com/gpu=0", "nvidia.com/gpu=1"]),
        false,
    );
    let mut first_sandbox = test_sandbox();
    first_sandbox.id = "sbx-first".to_string();
    first_sandbox.name = "first".to_string();
    first_sandbox.spec.as_mut().unwrap().resource_requirements = Some(gpu_resources(None));
    let mut second_sandbox = test_sandbox();
    second_sandbox.id = "sbx-second".to_string();
    second_sandbox.name = "second".to_string();
    second_sandbox.spec.as_mut().unwrap().resource_requirements = Some(gpu_resources(None));

    DockerComputeDriver::validate_sandbox(&first_sandbox, &driver.config).unwrap();
    assert_eq!(
        driver.gpu_selector.peek_device_ids(1).unwrap(),
        vec!["nvidia.com/gpu=0".to_string()]
    );
    let first_devices = driver.gpu_selector.next_device_ids(1).unwrap();
    let driver_config = DockerSandboxDriverConfig::default();
    let first_create_body = build_container_create_body_with_gpu_devices(
        &first_sandbox,
        &driver.config,
        &driver_config,
        Some(&first_devices),
    )
    .unwrap();

    DockerComputeDriver::validate_sandbox(&second_sandbox, &driver.config).unwrap();
    assert_eq!(
        driver.gpu_selector.peek_device_ids(1).unwrap(),
        vec!["nvidia.com/gpu=1".to_string()]
    );
    let second_devices = driver.gpu_selector.next_device_ids(1).unwrap();
    let second_create_body = build_container_create_body_with_gpu_devices(
        &second_sandbox,
        &driver.config,
        &driver_config,
        Some(&second_devices),
    )
    .unwrap();

    let first_request = first_create_body
        .host_config
        .as_ref()
        .and_then(|host_config| host_config.device_requests.as_ref())
        .and_then(|requests| requests.first())
        .expect("first default GPU request should add a Docker device request");
    let second_request = second_create_body
        .host_config
        .as_ref()
        .and_then(|host_config| host_config.device_requests.as_ref())
        .and_then(|requests| requests.first())
        .expect("second default GPU request should add a Docker device request");

    assert_eq!(
        first_request.device_ids.as_ref().unwrap(),
        &vec!["nvidia.com/gpu=0".to_string()]
    );
    assert_eq!(
        second_request.device_ids.as_ref().unwrap(),
        &vec!["nvidia.com/gpu=1".to_string()]
    );
}

#[test]
fn docker_info_reports_wsl2_from_kernel_version() {
    let info = SystemInfo {
        kernel_version: Some("5.15.153.1-microsoft-standard-WSL2".to_string()),
        operating_system: Some("Docker Desktop".to_string()),
        ..Default::default()
    };

    assert!(docker_info_reports_wsl2(&info));
}

#[test]
fn docker_info_reports_wsl2_from_operating_system() {
    let info = SystemInfo {
        operating_system: Some("Ubuntu 24.04.4 LTS on WSL2".to_string()),
        ..Default::default()
    };

    assert!(docker_info_reports_wsl2(&info));
}

#[test]
fn docker_info_reports_wsl2_ignores_daemon_name_and_labels() {
    let info = SystemInfo {
        kernel_version: Some("6.8.0-60-generic".to_string()),
        operating_system: Some("Ubuntu 24.04.4 LTS".to_string()),
        name: Some("wsl-docker-daemon".to_string()),
        labels: Some(vec!["com.example.platform=wsl2".to_string()]),
        ..Default::default()
    };

    assert!(!docker_info_reports_wsl2(&info));
}

#[test]
fn docker_info_reports_wsl2_rejects_plain_linux() {
    let info = SystemInfo {
        kernel_version: Some("6.8.0-60-generic".to_string()),
        operating_system: Some("Ubuntu 24.04.4 LTS".to_string()),
        os_type: Some("linux".to_string()),
        architecture: Some("x86_64".to_string()),
        ..Default::default()
    };

    assert!(!docker_info_reports_wsl2(&info));
}

#[test]
fn require_sandbox_identifier_rejects_when_id_and_name_are_empty() {
    // Regression test: `delete_sandbox` (and the other identifier-keyed
    // RPCs) must refuse requests where both the id and the name are
    // empty. Otherwise the empty filters fed to
    // `find_managed_container_summary` match the first managed container
    // in the namespace, allowing an arbitrary sandbox to be deleted.
    let err = require_sandbox_identifier("", "").unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("sandbox_id or sandbox_name"));

    require_sandbox_identifier("sbx-1", "").expect("id-only is accepted");
    require_sandbox_identifier("", "demo").expect("name-only is accepted");
    require_sandbox_identifier("sbx-1", "demo").expect("id and name is accepted");
}

#[test]
fn build_container_create_body_disables_docker_networking() {
    let create_body = build_container_create_body(&test_sandbox(), &runtime_config()).unwrap();
    let host_config = create_body.host_config.expect("host_config is populated");

    assert_eq!(
        host_config.network_mode,
        Some("none".to_string()),
        "the sandbox must not receive direct Docker networking"
    );
    assert_eq!(host_config.extra_hosts, None);
    assert_eq!(host_config.dns, Some(vec!["127.0.0.53".to_string()]));
}

#[test]
fn build_container_create_body_uses_runtime_namespace_label() {
    // Regression test: the namespace label must come from the driver's
    // runtime config, not from `DriverSandbox.namespace`. The gateway
    // does not populate `DriverSandbox.namespace`, so a container created
    // with that empty value would not match subsequent list/get/find
    // queries (which filter on `config.sandbox_namespace`), leaking
    // sandboxes that the driver itself cannot observe.
    let mut config = runtime_config();
    config.sandbox_namespace = "tenant-a".to_string();
    let mut sandbox = test_sandbox();
    sandbox.namespace = "ignored-by-driver".to_string();

    let create_body = build_container_create_body(&sandbox, &config).unwrap();
    let labels = create_body.labels.expect("labels are populated");

    assert_eq!(
        labels.get(LABEL_SANDBOX_NAMESPACE),
        Some(&"tenant-a".to_string()),
        "namespace label must reflect the driver's runtime config"
    );
}

#[test]
fn driver_status_keeps_running_sandboxes_provisioning_with_stable_message() {
    let running = ContainerSummary {
        id: Some("cid".to_string()),
        names: Some(vec!["/openshell-demo".to_string()]),
        labels: Some(HashMap::from([
            (LABEL_SANDBOX_ID.to_string(), "sbx-1".to_string()),
            (LABEL_SANDBOX_NAME.to_string(), "demo".to_string()),
            (LABEL_SANDBOX_NAMESPACE.to_string(), "default".to_string()),
        ])),
        state: Some(ContainerSummaryStateEnum::RUNNING),
        status: Some("Up 2 seconds".to_string()),
        ..Default::default()
    };
    let exited = ContainerSummary {
        state: Some(ContainerSummaryStateEnum::EXITED),
        status: Some("Exited (1) 3 seconds ago".to_string()),
        ..running.clone()
    };
    let running_later = ContainerSummary {
        status: Some("Up 4 seconds".to_string()),
        ..running.clone()
    };

    // A running container always emits Ready=True with BackendReady. The gateway
    // composes this with supervisor-session presence to decide public SandboxPhase.
    let running_status = driver_status_from_summary(&running, "demo");
    let running_later_status = driver_status_from_summary(&running_later, "demo");
    assert_eq!(running_status.conditions[0].status, "True");
    assert_eq!(running_status.conditions[0].reason, "BackendReady");
    assert_eq!(running_status.conditions[0].message, "Container is running");
    assert_eq!(running_status.conditions, running_later_status.conditions);

    let exited_status = driver_status_from_summary(&exited, "demo");
    assert_eq!(exited_status.conditions[0].status, "False");
    assert_eq!(exited_status.conditions[0].reason, "ContainerExited");
    assert_eq!(exited_status.conditions[0].message, "Container exited");
}

#[test]
fn driver_status_marks_restarting_sandboxes_as_error() {
    let restarting = ContainerSummary {
        id: Some("cid".to_string()),
        names: Some(vec!["/openshell-demo".to_string()]),
        labels: Some(HashMap::from([
            (LABEL_SANDBOX_ID.to_string(), "sbx-1".to_string()),
            (LABEL_SANDBOX_NAME.to_string(), "demo".to_string()),
            (LABEL_SANDBOX_NAMESPACE.to_string(), "default".to_string()),
        ])),
        state: Some(ContainerSummaryStateEnum::RESTARTING),
        status: Some("Restarting (1) 2 seconds ago".to_string()),
        ..Default::default()
    };

    let status = driver_status_from_summary(&restarting, "demo");
    assert_eq!(status.conditions[0].status, "False");
    assert_eq!(status.conditions[0].reason, "ContainerRestarting");
    assert_eq!(
        status.conditions[0].message,
        "Container is restarting after a failure"
    );
}

#[test]
fn docker_scheduled_event_adds_progress_metadata() {
    let mut metadata = HashMap::from([(
        "image_ref".to_string(),
        "ghcr.io/acme/sandbox:latest".to_string(),
    )]);

    attach_docker_progress_metadata(
        &mut metadata,
        "Scheduled",
        "Docker sandbox accepted for image \"ghcr.io/acme/sandbox:latest\"",
    );

    assert_eq!(
        metadata.get(PROGRESS_COMPLETE_STEP_KEY).map(String::as_str),
        Some(PROGRESS_STEP_REQUESTING_SANDBOX)
    );
    assert_eq!(
        metadata
            .get(PROGRESS_COMPLETE_LABEL_KEY)
            .map(String::as_str),
        Some("Sandbox allocated")
    );
    assert_eq!(
        metadata.get(PROGRESS_ACTIVE_STEP_KEY).map(String::as_str),
        Some(PROGRESS_STEP_PULLING_IMAGE)
    );
    assert_eq!(
        metadata.get(PROGRESS_ACTIVE_DETAIL_KEY).map(String::as_str),
        Some("ghcr.io/acme/sandbox:latest")
    );
}

#[test]
fn docker_pulled_event_advances_to_starting_progress() {
    let mut metadata = HashMap::new();

    attach_docker_progress_metadata(
        &mut metadata,
        "Pulled",
        "Pulled Docker image \"ghcr.io/acme/sandbox:latest\"",
    );

    assert_eq!(
        metadata.get(PROGRESS_COMPLETE_STEP_KEY).map(String::as_str),
        Some(PROGRESS_STEP_PULLING_IMAGE)
    );
    assert_eq!(
        metadata
            .get(PROGRESS_COMPLETE_LABEL_KEY)
            .map(String::as_str),
        Some("Image pulled")
    );
    assert_eq!(
        metadata.get(PROGRESS_ACTIVE_STEP_KEY).map(String::as_str),
        Some(PROGRESS_STEP_STARTING_SANDBOX)
    );
}

#[test]
fn docker_pull_progress_event_adds_layer_detail_metadata() {
    let event = docker_pull_progress_event(
        "ghcr.io/acme/sandbox:latest",
        &CreateImageInfo {
            id: Some("layer-1".to_string()),
            status: Some("Downloading".to_string()),
            progress_detail: Some(ProgressDetail {
                current: Some(42 * 1024 * 1024),
                total: Some(84 * 1024 * 1024),
            }),
            ..Default::default()
        },
    )
    .expect("pull progress event");

    assert_eq!(event.source, "docker");
    assert_eq!(event.reason, "PullingLayer");
    assert_eq!(
        event
            .metadata
            .get(PROGRESS_ACTIVE_STEP_KEY)
            .map(String::as_str),
        Some(PROGRESS_STEP_PULLING_IMAGE)
    );
    assert_eq!(
        event
            .metadata
            .get(PROGRESS_ACTIVE_DETAIL_KEY)
            .map(String::as_str),
        Some("Downloading layer-1 (42 MB/84 MB)")
    );
}

#[test]
fn pending_sandbox_snapshot_uses_docker_namespace_and_starting_condition() {
    let sandbox = test_sandbox();

    let snapshot =
        pending_sandbox_snapshot(&sandbox, "docker-dev", provisioning_condition(), false);

    assert_eq!(snapshot.id, "sbx-123");
    assert_eq!(snapshot.name, "demo");
    assert_eq!(snapshot.namespace, "docker-dev");
    assert!(snapshot.spec.is_none());
    assert!(pending_sandbox_matches(&snapshot, "sbx-123", ""));
    assert!(pending_sandbox_matches(&snapshot, "", "demo"));

    let status = snapshot.status.expect("status");
    assert!(!status.deleting);
    assert_eq!(status.sandbox_name, "demo");
    assert_eq!(status.conditions.len(), 1);
    assert_eq!(status.conditions[0].r#type, "Ready");
    assert_eq!(status.conditions[0].status, "False");
    assert_eq!(status.conditions[0].reason, "Starting");
    assert_eq!(status.conditions[0].message, "Docker container is starting");
}

#[test]
fn docker_guest_tls_paths_require_all_files_for_https() {
    let tempdir = TempDir::new().unwrap();
    let ca = tempdir.path().join("ca.crt");
    fs::write(&ca, b"ca").unwrap();

    let err = docker_guest_tls_paths(&DockerComputeConfig {
        grpc_endpoint: "https://localhost:8443".to_string(),
        guest_tls_ca: Some(ca),
        ..Default::default()
    })
    .unwrap_err();
    assert!(err.to_string().contains("guest_tls_cert"));
}

#[test]
fn container_name_preserves_id_suffix_for_long_names() {
    // Names up to 253 chars are permitted by the gRPC layer. The id
    // suffix is what makes the container name unique between sandboxes
    // sharing a prefix, so it must always appear in the final name.
    let long_name = "a".repeat(253);
    let first = DriverSandbox {
        id: "sbx-first-1234567890".to_string(),
        name: long_name,
        namespace: "default".to_string(),
        spec: None,
        status: None,
        workspace: "default".to_string(),
    };
    let second = DriverSandbox {
        id: "sbx-second-0987654321".to_string(),
        ..first.clone()
    };

    let first_container = container_name_for_sandbox(&first);
    let second_container = container_name_for_sandbox(&second);

    assert!(
        first_container.len() <= MAX_CONTAINER_NAME_LEN,
        "container name {} exceeded {MAX_CONTAINER_NAME_LEN} chars: {first_container}",
        first_container.len(),
    );
    assert!(
        first_container.ends_with(&first.id),
        "container name should end with sandbox id: {first_container}",
    );
    assert_ne!(
        first_container, second_container,
        "container names must differ for sandboxes with distinct ids",
    );
}

#[test]
fn container_name_empty_sandbox_name_uses_workspace_and_id() {
    let sandbox = DriverSandbox {
        id: "sbx-abc".to_string(),
        name: String::new(),
        namespace: "default".to_string(),
        spec: None,
        status: None,
        workspace: "default".to_string(),
    };
    assert_eq!(
        container_name_for_sandbox(&sandbox),
        "openshell-default---sbx-abc",
    );
}

#[test]
fn trim_container_name_tail_strips_separators() {
    assert_eq!(trim_container_name_tail("foo-".to_string()), "foo");
    assert_eq!(trim_container_name_tail("foo-.".to_string()), "foo");
    assert_eq!(trim_container_name_tail("foo_-.".to_string()), "foo");
    assert_eq!(trim_container_name_tail("foo".to_string()), "foo");
}

#[test]
fn docker_guest_tls_paths_rejects_tls_flags_without_https() {
    let tempdir = TempDir::new().unwrap();
    let ca = tempdir.path().join("ca.crt");
    fs::write(&ca, b"ca").unwrap();

    let err = docker_guest_tls_paths(&DockerComputeConfig {
        grpc_endpoint: "http://localhost:8080".to_string(),
        guest_tls_ca: Some(ca),
        ..Default::default()
    })
    .unwrap_err();
    assert!(err.to_string().contains("https://"));
}

#[test]
fn docker_guest_tls_paths_allows_plain_http_without_tls_flags() {
    let result = docker_guest_tls_paths(&DockerComputeConfig {
        grpc_endpoint: "http://localhost:8080".to_string(),
        ..Default::default()
    })
    .unwrap();
    assert!(result.is_none());
}

#[test]
fn default_docker_supervisor_image_uses_nvidia_ghcr_repo() {
    let image = openshell_core::config::default_supervisor_image();
    assert!(
        image.starts_with("ghcr.io/nvidia/openshell/supervisor:"),
        "unexpected default image reference: {image}",
    );
}

#[test]
fn docker_supervisor_image_tag_prefers_explicit_build_tags() {
    use openshell_core::config::resolve_supervisor_image_tag;
    assert_eq!(
        resolve_supervisor_image_tag(&["1.2.3", "sha", "0.0.0"]),
        "1.2.3"
    );
    assert_eq!(resolve_supervisor_image_tag(&["", "sha", "0.0.0"]), "sha");
    assert_eq!(resolve_supervisor_image_tag(&["", "", "1.2.3"]), "1.2.3");
    assert_eq!(resolve_supervisor_image_tag(&["", "", "0.0.0"]), "dev");
}

#[test]
fn docker_supervisor_image_tag_sanitizes_build_metadata_for_docker() {
    use openshell_core::config::resolve_supervisor_image_tag;
    assert_eq!(
        resolve_supervisor_image_tag(&["", "", "0.0.37-dev.156+g1d3b741ee"]),
        "0.0.37-dev.156-g1d3b741ee",
    );
    assert_eq!(
        resolve_supervisor_image_tag(&["0.0.37-dev.156+g1d3b741ee", "", "0.0.0"]),
        "0.0.37-dev.156-g1d3b741ee",
    );
}

#[test]
fn docker_supervisor_image_refreshes_mutable_tags_only() {
    assert!(supervisor_image_should_refresh(
        "ghcr.io/nvidia/openshell/supervisor:dev"
    ));
    assert!(supervisor_image_should_refresh(
        "ghcr.io/nvidia/openshell/supervisor:latest"
    ));
    assert!(supervisor_image_should_refresh(
        "ghcr.io/nvidia/openshell/supervisor"
    ));
    assert!(!supervisor_image_should_refresh(
        "ghcr.io/nvidia/openshell/supervisor:0.0.47-dev.13-g57b71c68f"
    ));
    assert!(!supervisor_image_should_refresh(
        "ghcr.io/nvidia/openshell/supervisor@sha256:abc123"
    ));
}

#[test]
fn temp_extract_container_names_are_unique_per_call() {
    let first = temp_extract_container_name();
    let second = temp_extract_container_name();
    assert_ne!(first, second);
    assert!(first.starts_with("openshell-supervisor-extract-"));
}

#[test]
fn extract_first_tar_entry_returns_payload_of_single_file_archive() {
    // Build a tar archive with the same shape Docker returns from
    // `/containers/<id>/archive` for a single file.
    let payload = b"\x7fELFtest-binary-bytes";
    let mut tar_buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);
        let mut header = tar::Header::new_gnu();
        header.set_path("openshell-sandbox").unwrap();
        header.set_size(payload.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder.append(&header, payload.as_slice()).unwrap();
        builder.finish().unwrap();
    }

    let extracted = extract_first_tar_entry(&tar_buf).unwrap();
    assert_eq!(extracted, payload);
}

#[test]
fn extract_first_tar_entry_rejects_empty_archive() {
    let mut tar_buf = Vec::new();
    tar::Builder::new(&mut tar_buf).finish().unwrap();
    let err = extract_first_tar_entry(&tar_buf).unwrap_err();
    assert!(err.contains("empty"), "unexpected error message: {err}");
}

#[test]
fn container_state_needs_start_matches_startable_states() {
    for state in [
        ContainerSummaryStateEnum::EXITED,
        ContainerSummaryStateEnum::CREATED,
    ] {
        assert!(
            container_state_needs_start(state),
            "{state:?} should be started with Docker start",
        );
    }

    for state in [
        ContainerSummaryStateEnum::RUNNING,
        ContainerSummaryStateEnum::RESTARTING,
        ContainerSummaryStateEnum::PAUSED,
        ContainerSummaryStateEnum::DEAD,
        ContainerSummaryStateEnum::REMOVING,
        ContainerSummaryStateEnum::EMPTY,
    ] {
        assert!(
            !container_state_needs_start(state),
            "{state:?} should not be started with Docker start",
        );
    }
}

#[test]
fn lifecycle_fence_rejects_polled_exit_from_before_restart() {
    let fences = DockerLifecycleEventFences::default();
    fences.begin_start("sandbox-1");
    assert!(fences.start_in_progress("sandbox-1"));
    fences.finish_start("sandbox-1");
    assert!(!fences.start_in_progress("sandbox-1"));

    fences.record_previous_exit("sandbox-1", Some("2026-08-12T16:39:13Z"));
    assert_eq!(
        fences.previous_exit("sandbox-1").as_deref(),
        Some("2026-08-12T16:39:13Z")
    );

    let previous_exit = ContainerState {
        status: Some(ContainerStateStatusEnum::EXITED),
        finished_at: Some("2026-08-12T16:39:13Z".to_string()),
        ..Default::default()
    };
    assert!(docker_polled_exit_is_stale(
        "2026-08-12T16:39:13Z",
        Some(&previous_exit),
    ));

    let running = ContainerState {
        status: Some(ContainerStateStatusEnum::RUNNING),
        ..previous_exit.clone()
    };
    assert!(docker_polled_exit_is_stale(
        "2026-08-12T16:39:13Z",
        Some(&running),
    ));

    let new_exit = ContainerState {
        finished_at: Some("2026-08-12T16:40:00Z".to_string()),
        ..previous_exit
    };
    assert!(!docker_polled_exit_is_stale(
        "2026-08-12T16:39:13Z",
        Some(&new_exit),
    ));

    fences.remove("sandbox-1");
    assert!(fences.previous_exit("sandbox-1").is_none());
}

fn exited_sandbox_with_ready_reason(reason: &str) -> DriverSandbox {
    DriverSandbox {
        id: "sbx-exit".to_string(),
        name: "demo".to_string(),
        namespace: String::new(),
        spec: None,
        status: Some(DriverSandboxStatus {
            sandbox_name: "demo".to_string(),
            instance_id: "container-1".to_string(),
            agent_fd: String::new(),
            sandbox_fd: String::new(),
            conditions: vec![DriverCondition {
                r#type: "Ready".to_string(),
                status: "False".to_string(),
                reason: reason.to_string(),
                message: "Container exited".to_string(),
                last_transition_time: String::new(),
            }],
            deleting: false,
            ..Default::default()
        }),
        workspace: String::new(),
    }
}

fn ready_reason(sandbox: &DriverSandbox) -> &str {
    sandbox
        .status
        .as_ref()
        .and_then(|status| status.conditions.iter().find(|c| c.r#type == "Ready"))
        .map(|c| c.reason.as_str())
        .expect("Ready condition present")
}

#[test]
fn docker_signal_kill_reclassified_as_runtime_restart() {
    // 137 (128+SIGKILL) and 143 (128+SIGTERM) mark an external termination —
    // the signature of a machine/daemon restart — and become recoverable
    // `ContainerRuntimeRestart`.
    for exit_code in [137, 143] {
        let mut sandbox = exited_sandbox_with_ready_reason(CONDITION_EXITED);
        let state = ContainerState {
            status: Some(ContainerStateStatusEnum::EXITED),
            oom_killed: Some(false),
            exit_code: Some(exit_code),
            ..Default::default()
        };
        apply_docker_exit_classification(&mut sandbox, &state);
        assert_eq!(
            ready_reason(&sandbox),
            CONDITION_RUNTIME_RESTART,
            "exit code {exit_code} should reclassify as runtime restart"
        );
    }
}

#[test]
fn docker_ordinary_exit_stays_terminal() {
    // An application exit (non-zero error code) stays `ContainerExited` so its
    // failure signal survives instead of being relaunched on startup.
    let mut sandbox = exited_sandbox_with_ready_reason(CONDITION_EXITED);
    let state = ContainerState {
        status: Some(ContainerStateStatusEnum::EXITED),
        oom_killed: Some(false),
        exit_code: Some(1),
        ..Default::default()
    };
    apply_docker_exit_classification(&mut sandbox, &state);
    assert_eq!(ready_reason(&sandbox), CONDITION_EXITED);
}

#[test]
fn docker_oom_kill_stays_terminal_despite_137() {
    // An OOM kill reports exit 137 but must NOT be treated as a recoverable
    // restart — it is a genuine failure and stays terminal.
    let mut sandbox = exited_sandbox_with_ready_reason(CONDITION_EXITED);
    let state = ContainerState {
        status: Some(ContainerStateStatusEnum::EXITED),
        oom_killed: Some(true),
        exit_code: Some(137),
        ..Default::default()
    };
    apply_docker_exit_classification(&mut sandbox, &state);
    assert_eq!(ready_reason(&sandbox), CONDITION_EXITED);
}
