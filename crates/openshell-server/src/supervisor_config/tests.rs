// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    grpc::{
        OpenShellService,
        test_support::{authed_request, test_server_state},
    },
    policy_store::PolicyStoreExt,
};
use openshell_core::proto::{
    DeleteInferenceRouteRequest, GatewayMessage, GetSandboxConfigRequest,
    GetSandboxProviderEnvironmentRequest, ObjectMeta, Provider, ProviderEnvironmentSnapshot,
    SandboxConfigSnapshot, SandboxSpec, SetInferenceRouteRequest, SettingValue,
    UpdateConfigRequest, UpdateProviderRequest, gateway_message, inference_server::Inference,
    open_shell_server::OpenShell, setting_value,
};
use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule, SandboxPolicy};
use openshell_core::proto::{
    SupervisorHello, SupervisorMessage, open_shell_client::OpenShellClient,
    open_shell_server::OpenShellServer, supervisor_message,
};
use tokio::sync::oneshot;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};

#[derive(Clone, PartialEq, Message)]
struct LegacyAccepted {
    #[prost(string, tag = "1")]
    session_id: String,
    #[prost(uint32, tag = "2")]
    heartbeat_interval_secs: u32,
}

#[derive(Clone, PartialEq, Message)]
struct LegacyGatewayMessage {
    #[prost(message, optional, tag = "1")]
    accepted: Option<LegacyAccepted>,
    #[prost(message, optional, tag = "3")]
    heartbeat: Option<openshell_core::proto::GatewayHeartbeat>,
}

fn register(
    sessions: &SupervisorSessionRegistry,
    session: &str,
    capacity: usize,
) -> (mpsc::Receiver<GatewayMessage>, oneshot::Receiver<()>) {
    let (tx, rx) = mpsc::channel(capacity);
    let (shutdown, closed) = oneshot::channel();
    sessions.register("sandbox".into(), session.into(), tx, shutdown);
    (rx, closed)
}

fn update() -> SupervisorConfigMessage {
    SupervisorConfigMessage::Update(Box::new(ConfigUpdate {
        component: Some(config_update::Component::SandboxConfig(
            SandboxConfigSnapshot {
                config_revision: 7,
                ..Default::default()
            },
        )),
        ..Default::default()
    }))
}

async fn receive(rx: &mut mpsc::Receiver<GatewayMessage>) -> ConfigUpdate {
    let message = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap();
    let Some(gateway_message::Payload::ConfigUpdate(update)) = message.payload else {
        panic!("expected config update");
    };
    assert!(!update.update_id.is_empty());
    assert!(update.component_sequence > 0);
    update
}

async fn fixture() -> (
    Arc<ServerState>,
    OpenShellService,
    mpsc::Receiver<GatewayMessage>,
) {
    let state = test_server_state().await;
    state
        .store
        .put_message(&Sandbox {
            metadata: Some(ObjectMeta {
                id: "sandbox".into(),
                name: "sandbox".into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            spec: Some(SandboxSpec::default()),
            ..Default::default()
        })
        .await
        .unwrap();
    let (rx, _) = register(&state.supervisor_sessions, "session", 64);
    let service = OpenShellService::new(state.clone());
    (state, service, rx)
}

fn setting(value: &str) -> UpdateConfigRequest {
    UpdateConfigRequest {
        name: "sandbox".into(),
        workspace: "default".into(),
        setting_key: "proposal_approval_mode".into(),
        setting_value: Some(SettingValue {
            value: Some(setting_value::Value::StringValue(value.into())),
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn stream_acceptance_precedes_updates_and_survives_missing_bootstrap() {
    let (state, service, _) = fixture().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(OpenShellServer::new(OpenShellService::new(state.clone())))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    let mut client = OpenShellClient::connect(format!("http://{address}"))
        .await
        .unwrap();
    for expect_bootstrap in [true, false] {
        if !expect_bootstrap {
            state
                .store
                .update_message_cas::<Sandbox, _>("sandbox", 0, |sandbox| {
                    sandbox
                        .spec
                        .as_mut()
                        .unwrap()
                        .providers
                        .push("missing-provider".into());
                })
                .await
                .unwrap();
        }
        let (tx, rx) = mpsc::channel(4);
        tx.send(SupervisorMessage {
            payload: Some(supervisor_message::Payload::Hello(SupervisorHello {
                sandbox_id: "sandbox".into(),
                instance_id: "instance".into(),
            })),
        })
        .await
        .unwrap();
        let mut stream = client
            .connect_supervisor(ReceiverStream::new(rx))
            .await
            .unwrap()
            .into_inner();
        let first = tokio::time::timeout(Duration::from_secs(5), stream.message())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let Some(gateway_message::Payload::SessionAccepted(accepted)) = first.payload else {
            panic!("acceptance must be first");
        };
        assert_eq!(accepted.bootstrap.is_some(), expect_bootstrap);
        assert!(!accepted.session_id.is_empty());
        if expect_bootstrap {
            service
                .update_config(authed_request(setting("auto")))
                .await
                .unwrap();
        } else {
            state.config_publisher.publish(
                &state,
                ConfigChange::Sandbox("sandbox".into(), Components::Inference),
            );
        }
        let update = tokio::time::timeout(Duration::from_secs(5), stream.message())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(
            update.payload,
            Some(gateway_message::Payload::ConfigUpdate(_))
        ));
        drop(tx);
    }
    server.abort();
}

#[tokio::test]
async fn legacy_stream_decoder_ignores_updates_and_keeps_receiving_heartbeats() {
    let (state, service, _) = fixture().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(OpenShellServer::new(OpenShellService::new(state.clone())))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = tonic::client::Grpc::new(channel);
    client.ready().await.unwrap();
    let (tx, rx) = mpsc::channel(4);
    tx.send(SupervisorMessage {
        payload: Some(supervisor_message::Payload::Hello(SupervisorHello {
            sandbox_id: "sandbox".into(),
            instance_id: "legacy".into(),
        })),
    })
    .await
    .unwrap();
    let response = client
        .streaming(
            tonic::Request::new(ReceiverStream::new(rx)),
            http::uri::PathAndQuery::from_static("/openshell.v1.OpenShell/ConnectSupervisor"),
            tonic_prost::ProstCodec::<SupervisorMessage, LegacyGatewayMessage>::default(),
        )
        .await
        .unwrap();
    let mut stream = response.into_inner();
    let first = stream.message().await.unwrap().unwrap();
    let accepted = first.accepted.unwrap();
    service
        .update_config(authed_request(setting("auto")))
        .await
        .unwrap();
    for _ in 0..2 {
        let unknown = tokio::time::timeout(Duration::from_secs(5), stream.message())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(unknown.accepted.is_none());
        assert!(unknown.heartbeat.is_none());
    }
    let heartbeat = tokio::time::timeout(Duration::from_secs(30), stream.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(heartbeat.heartbeat.is_some());
    assert!(
        state
            .supervisor_sessions
            .is_current_session("sandbox", &accepted.session_id)
    );
    drop(tx);
    server.abort();
}

#[tokio::test]
async fn policy_delivery_does_not_mark_committed_revision_applied_and_cas_failure_does_not_publish()
{
    let (state, service, mut rx) = fixture().await;
    let policy = SandboxPolicy {
        network_policies: [(
            "example".into(),
            NetworkPolicyRule {
                name: "example".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "example.com".into(),
                    port: 443,
                    ..Default::default()
                }],
                ..Default::default()
            },
        )]
        .into(),
        ..Default::default()
    };
    let mut request = UpdateConfigRequest {
        name: "sandbox".into(),
        workspace: "default".into(),
        policy: Some(policy),
        expected_resource_version: u64::MAX,
        ..Default::default()
    };
    assert_eq!(
        service
            .update_config(authed_request(request.clone()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
    assert!(state.config_publisher.sender.get().is_none());
    assert!(
        state
            .store
            .get_latest_policy("sandbox")
            .await
            .unwrap()
            .is_none()
    );
    request.expected_resource_version = 0;
    let committed = service
        .update_config(authed_request(request))
        .await
        .unwrap()
        .into_inner();
    let config_update::Component::SandboxConfig(snapshot) =
        receive(&mut rx).await.component.unwrap()
    else {
        panic!("expected sandbox config");
    };
    assert_eq!(snapshot.version, committed.version);
    let revision = state
        .store
        .get_latest_policy("sandbox")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(revision.version, i64::from(snapshot.version));
    assert_eq!(revision.status, "pending");
    assert!(revision.loaded_at_ms.is_none());
}

#[tokio::test]
async fn workspace_and_platform_profile_fanout_have_distinct_scopes() {
    let (state, _, mut rx) = fixture().await;
    publish_change(
        &state,
        ConfigChange::ProviderProfile("other-workspace".into()),
    )
    .await
    .unwrap();
    assert!(rx.try_recv().is_err());
    publish_change(&state, ConfigChange::ProviderProfile(String::new()))
        .await
        .unwrap();
    assert!(matches!(
        receive(&mut rx).await.component,
        Some(config_update::Component::SandboxConfig(_))
    ));
    assert!(matches!(
        receive(&mut rx).await.component,
        Some(config_update::Component::ProviderEnvironment(_))
    ));
    assert!(matches!(
        receive(&mut rx).await.component,
        Some(config_update::Component::InferenceBundle(_))
    ));
}

#[tokio::test]
async fn publication_queue_is_bounded_without_blocking_mutation_callers() {
    let (state, _, _) = fixture().await;
    for _ in 0..=PUBLISH_QUEUE_CAPACITY {
        state.config_publisher.publish(
            &state,
            ConfigChange::Sandbox("sandbox".into(), Components::Inference),
        );
    }
    let sender = state.config_publisher.sender.get().unwrap();
    assert_eq!(sender.max_capacity(), PUBLISH_QUEUE_CAPACITY);
    assert_eq!(sender.capacity(), 0);
}

#[tokio::test]
async fn local_router_bounds_queues_and_fences_replacement_sessions() {
    let sessions = Arc::new(SupervisorSessionRegistry::new());
    let router = LocalSupervisorConfigRouter::new(sessions.clone());
    assert_eq!(
        router.deliver("sandbox", update()).await,
        DeliveryDisposition::NoActiveSession
    );
    let (mut old_rx, old_closed) = register(&sessions, "old", 1);
    assert_eq!(
        router.deliver("sandbox", update()).await,
        DeliveryDisposition::Delivered
    );
    assert_eq!(
        router.deliver("sandbox", update()).await,
        DeliveryDisposition::QueueUnavailable
    );
    assert_eq!(receive(&mut old_rx).await.component_sequence, 1);
    assert_eq!(
        router.deliver("sandbox", update()).await,
        DeliveryDisposition::Delivered
    );
    assert_eq!(receive(&mut old_rx).await.component_sequence, 3);
    let (mut new_rx, _) = register(&sessions, "new", 2);
    old_closed.await.unwrap();
    assert_eq!(
        router.deliver("sandbox", update()).await,
        DeliveryDisposition::Delivered
    );
    assert_eq!(receive(&mut new_rx).await.component_sequence, 1);
    assert!(old_rx.recv().await.is_none());
    drop(new_rx);
    assert_eq!(
        router.deliver("sandbox", update()).await,
        DeliveryDisposition::QueueUnavailable
    );
    sessions.disconnect("sandbox");
    assert_eq!(
        router.deliver("sandbox", update()).await,
        DeliveryDisposition::NoActiveSession
    );
}

#[tokio::test]
async fn local_router_keeps_component_sequences_independent_and_redacts_payloads() {
    let sessions = Arc::new(SupervisorSessionRegistry::new());
    let router = LocalSupervisorConfigRouter::new(sessions.clone());
    let (mut rx, _) = register(&sessions, "session", 4);
    router.deliver("sandbox", update()).await;
    let first = receive(&mut rx).await;
    let provider = SupervisorConfigMessage::Update(Box::new(ConfigUpdate {
        component: Some(config_update::Component::ProviderEnvironment(
            ProviderEnvironmentSnapshot {
                environment: [("API_KEY".into(), "secret-marker".into())].into(),
                ..Default::default()
            },
        )),
        ..Default::default()
    }));
    assert!(!format!("{provider:?}").contains("secret-marker"));
    assert_eq!(
        router.deliver("sandbox", provider).await,
        DeliveryDisposition::Delivered
    );
    let second = receive(&mut rx).await;
    assert_eq!(second.component_sequence, first.component_sequence);
    assert_ne!(first.update_id, second.update_id);
    let oversized = SupervisorConfigMessage::Update(Box::new(ConfigUpdate {
        component: Some(config_update::Component::ProviderEnvironment(
            ProviderEnvironmentSnapshot {
                environment: [("API_KEY".into(), "x".repeat(MAX_CONFIG_BYTES))].into(),
                ..Default::default()
            },
        )),
        ..Default::default()
    }));
    assert_eq!(
        router.deliver("sandbox", oversized).await,
        DeliveryDisposition::PayloadTooLarge
    );
    assert_eq!(
        router
            .deliver("sandbox", SupervisorConfigMessage::Update(Box::default()))
            .await,
        DeliveryDisposition::InvalidComponent
    );
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn committed_settings_deliver_polling_equivalent_snapshots_without_history_writes() {
    let (state, service, mut rx) = fixture().await;
    let bootstrap = build_bootstrap(&state, "sandbox").await.unwrap();
    let config = service
        .get_sandbox_config(authed_request(GetSandboxConfigRequest {
            sandbox_id: "sandbox".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(bootstrap.sandbox_config.unwrap(), config.into());
    let environment = service
        .get_sandbox_provider_environment(authed_request(GetSandboxProviderEnvironmentRequest {
            sandbox_id: "sandbox".into(),
            supports_static_credential_bindings: true,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(bootstrap.provider_environment.unwrap(), environment.into());
    let inference = inference::resolve_inference_bundle_with_credentials(
        &state.store,
        "default",
        Some(&state.credentials),
    )
    .await
    .unwrap();
    assert_eq!(
        bootstrap.inference_bundle.unwrap().revision,
        inference.revision
    );

    service
        .update_config(authed_request(setting("auto")))
        .await
        .unwrap();
    let pushed = receive(&mut rx).await;
    let config_update::Component::SandboxConfig(pushed) = pushed.component.unwrap() else {
        panic!("expected sandbox config");
    };
    let polled = service
        .get_sandbox_config(authed_request(GetSandboxConfigRequest {
            sandbox_id: "sandbox".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(pushed, polled.into());
    assert!(matches!(
        receive(&mut rx).await.component,
        Some(config_update::Component::ProviderEnvironment(_))
    ));
    assert!(
        state
            .store
            .get_latest_policy("sandbox")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn rejected_mutation_does_not_start_publication() {
    let (state, service, mut rx) = fixture().await;
    let mut rejected = setting("auto");
    rejected.setting_key = "not_a_registered_setting".into();
    assert!(
        service
            .update_config(authed_request(rejected))
            .await
            .is_err()
    );
    assert!(state.config_publisher.sender.get().is_none());
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn snapshot_failure_does_not_fail_committed_mutation() {
    let (state, service, mut rx) = fixture().await;
    state
        .store
        .update_message_cas::<Sandbox, _>("sandbox", 0, |sandbox| {
            sandbox
                .spec
                .as_mut()
                .unwrap()
                .providers
                .push("missing-provider".into());
        })
        .await
        .unwrap();
    service
        .update_config(authed_request(setting("auto")))
        .await
        .unwrap();
    assert!(build_bootstrap(&state, "sandbox").await.is_none());
    // A barrier after the failed builds proves the worker continues processing.
    state.config_publisher.publish(
        &state,
        ConfigChange::Sandbox("sandbox".into(), Components::Inference),
    );
    assert!(matches!(
        receive(&mut rx).await.component,
        Some(config_update::Component::InferenceBundle(_))
    ));
    assert!(
        state
            .store
            .get_by_name(policy::SANDBOX_SETTINGS_OBJECT_TYPE, "default", "sandbox")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn provider_rotation_and_inference_mutations_publish_complete_bundles() {
    let (state, service, mut rx) = fixture().await;
    state
        .store
        .put_message(&Provider {
            metadata: Some(ObjectMeta {
                id: "provider".into(),
                name: "provider".into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            r#type: "openai".into(),
            credentials: [("OPENAI_API_KEY".into(), "before".into())].into(),
            ..Default::default()
        })
        .await
        .unwrap();
    state
        .store
        .update_message_cas::<Sandbox, _>("sandbox", 0, |sandbox| {
            sandbox
                .spec
                .as_mut()
                .unwrap()
                .providers
                .push("provider".into());
        })
        .await
        .unwrap();
    let inference = inference::InferenceService::new(state.clone());
    inference
        .set_inference_route(authed_request(SetInferenceRouteRequest {
            workspace: "default".into(),
            provider_name: "provider".into(),
            model_id: "test-model".into(),
            no_verify: true,
            ..Default::default()
        }))
        .await
        .unwrap();
    assert!(matches!(
        receive(&mut rx).await.component,
        Some(config_update::Component::InferenceBundle(_))
    ));
    service
        .update_provider(authed_request(UpdateProviderRequest {
            workspace: "default".into(),
            provider: Some(Provider {
                metadata: Some(ObjectMeta {
                    name: "provider".into(),
                    ..Default::default()
                }),
                credentials: [("OPENAI_API_KEY".into(), "after".into())].into(),
                ..Default::default()
            }),
            ..Default::default()
        }))
        .await
        .unwrap();
    assert!(matches!(
        receive(&mut rx).await.component,
        Some(config_update::Component::SandboxConfig(_))
    ));
    let config_update::Component::ProviderEnvironment(environment) =
        receive(&mut rx).await.component.unwrap()
    else {
        panic!("expected provider snapshot");
    };
    assert_eq!(
        environment
            .environment
            .get("OPENAI_API_KEY")
            .map(String::as_str),
        Some("after")
    );
    let config_update::Component::InferenceBundle(bundle) =
        receive(&mut rx).await.component.unwrap()
    else {
        panic!("expected inference snapshot");
    };
    assert_eq!(bundle.routes[0].api_key, "after");
    inference
        .delete_inference_route(authed_request(DeleteInferenceRouteRequest {
            workspace: "default".into(),
            ..Default::default()
        }))
        .await
        .unwrap();
    let config_update::Component::InferenceBundle(bundle) =
        receive(&mut rx).await.component.unwrap()
    else {
        panic!("expected inference snapshot");
    };
    assert!(bundle.routes.is_empty());
}
