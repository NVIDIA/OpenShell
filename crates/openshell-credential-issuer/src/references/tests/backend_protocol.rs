// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Real issuer/driver adapters against local HTTP and UDS protocol fixtures.
//! The manifest CAS remains the deterministic test store; this is backend-wire
//! evidence, not a claim that Vault/Kubernetes deployment or database lanes ran.

use super::{MemoryStore, now, owner};
use crate::references::{ReferenceProjection, ReferenceRuntime, StoreReferenceSecrets};
use crate::{CredentialIssuer, EmbeddedCredentialIssuer, Handles, IssuerConfig, StoreSecrets};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use tonic::Code;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const LEGACY: &str = "legacy-value";
const ROTATION_ONE: &str = "rotation-one-value";
const ROTATION_TWO: &str = "rotation-two-value";
const KEY: &str = "API_KEY";

#[derive(Clone, Copy)]
enum Protocol {
    Vault,
    Kubernetes,
}

#[derive(Default)]
struct ProtocolState {
    objects: BTreeMap<String, Value>,
    writes: Vec<String>,
    fail_next_write_after_persist: bool,
    fail_reads: bool,
}

#[derive(Clone)]
struct ProtocolFixture {
    protocol: Protocol,
    state: Arc<Mutex<ProtocolState>>,
}

fn api_error(code: u16) -> ResponseTemplate {
    ResponseTemplate::new(code).set_body_json(json!({
        "kind": "Status", "apiVersion": "v1", "status": "Failure",
        "reason": if code == 404 { "NotFound" } else { "ServiceUnavailable" },
        "message": "injected protocol fixture failure", "code": code,
    }))
}

// The HTTP fixture is intentionally limited to the three fixed test values;
// no new encoding implementation or application dependency is introduced.
fn fixture_base64(value: &str) -> &'static str {
    match value {
        LEGACY => "bGVnYWN5LXZhbHVl",
        ROTATION_ONE => "cm90YXRpb24tb25lLXZhbHVl",
        ROTATION_TWO => "cm90YXRpb24tdHdvLXZhbHVl",
        _ => panic!("unexpected fixed fixture value"),
    }
}

impl Respond for ProtocolFixture {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let path = request.url.path();
        let mut state = self.state.lock().unwrap();
        if path == "/__fixture/control" {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            match body["mode"].as_str().unwrap() {
                "uncertain-write" => state.fail_next_write_after_persist = true,
                "outage" => state.fail_reads = true,
                "healthy" => state.fail_reads = false,
                "reset" => *state = ProtocolState::default(),
                "remove-latest" => {
                    let latest = state.writes.last().unwrap().clone();
                    state.objects.remove(&latest);
                }
                "tamper-latest-owner" => {
                    let latest = state.writes.last().unwrap().clone();
                    state.objects.get_mut(&latest).unwrap()["metadata"]["annotations"]["openshell.nvidia.com/provider-credential-id"] =
                        json!("foreign-owner");
                }
                _ => panic!("invalid fixture control"),
            }
            return ResponseTemplate::new(200).set_body_json(json!({}));
        }
        if path == "/__fixture/stats" {
            return ResponseTemplate::new(200).set_body_json(json!({
                "writes": state.writes, "objects": state.objects.keys().collect::<Vec<_>>(),
            }));
        }
        if request.method.as_str() == "POST" {
            let mut body: Value = serde_json::from_slice(&request.body).unwrap();
            let (object_path, response) = match self.protocol {
                Protocol::Vault => {
                    assert!(path.starts_with("/v1/secret/data/openshell/"));
                    assert_eq!(
                        request.headers.get("x-vault-token").unwrap(),
                        "fixture-vault-token"
                    );
                    (path.to_owned(), json!({ "data": body }))
                }
                Protocol::Kubernetes => {
                    assert_eq!(path, "/api/v1/namespaces/ref-tests/secrets");
                    let name = body["metadata"]["name"].as_str().unwrap().to_owned();
                    let object_path = format!("{path}/{name}");
                    if state.objects.contains_key(&object_path) {
                        return api_error(409);
                    }
                    body["apiVersion"] = json!("v1");
                    body["kind"] = json!("Secret");
                    body["metadata"]["uid"] = json!(format!("fixture-uid-{name}"));
                    body["metadata"]["resourceVersion"] = json!("1");
                    let raw = body.as_object_mut().unwrap().remove("stringData").unwrap();
                    let encoded: serde_json::Map<String, Value> = raw
                        .as_object()
                        .unwrap()
                        .iter()
                        .map(|(key, value)| {
                            (key.clone(), json!(fixture_base64(value.as_str().unwrap())))
                        })
                        .collect();
                    body["data"] = Value::Object(encoded);
                    (object_path, body)
                }
            };
            state.writes.push(object_path.clone());
            state.objects.insert(object_path, response.clone());
            if std::mem::take(&mut state.fail_next_write_after_persist) {
                return api_error(503);
            }
            return ResponseTemplate::new(200).set_body_json(response);
        }
        if request.method.as_str() == "GET" {
            if state.fail_reads {
                return api_error(503);
            }
            return state.objects.get(path).map_or_else(
                || api_error(404),
                |value| ResponseTemplate::new(200).set_body_json(value),
            );
        }
        // A staging write must never turn into a Kubernetes patch of an active
        // object or a delete of a value whose ownership is still uncertain.
        panic!("unexpected backend method: {}", request.method);
    }
}

async fn protocol_server(protocol: Protocol) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ProtocolFixture {
            protocol,
            state: Arc::new(Mutex::new(ProtocolState::default())),
        })
        .mount(&server)
        .await;
    server
}

async fn control(uri: &str, mode: &str) {
    reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("{uri}/__fixture/control"))
        .json(&json!({ "mode": mode }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
}

async fn writes(uri: &str) -> Vec<String> {
    let response: Value = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("{uri}/__fixture/stats"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    response["writes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect()
}

fn config(driver: &str, table: toml::Table) -> IssuerConfig {
    IssuerConfig {
        credential_drivers: vec![driver.to_owned()],
        default_credential_driver: Some(driver.to_owned()),
        driver_configs: BTreeMap::from([(driver.to_owned(), toml::Value::Table(table))]),
        ..IssuerConfig::default()
    }
}

fn vault_config(uri: &str, token_file: &std::path::Path) -> toml::Table {
    toml::Table::from_iter([
        ("address".to_owned(), toml::Value::String(uri.to_owned())),
        (
            "auth_method".to_owned(),
            toml::Value::String("token_file".to_owned()),
        ),
        (
            "token_path".to_owned(),
            toml::Value::String(token_file.display().to_string()),
        ),
    ])
}

async fn backend_scenario(backend: Arc<dyn CredentialIssuer>, uri: &str, driver: &str) {
    let empty = Handles::new();
    let legacy_values = HashMap::from([(KEY.to_owned(), LEGACY.to_owned())]);
    let legacy = backend
        .store(StoreSecrets {
            owner: owner(),
            object_id: Some("legacy-object"),
            values: &legacy_values,
            existing_handles: &empty,
        })
        .await
        .unwrap();
    assert_eq!(legacy[KEY].driver, driver);
    assert_eq!(
        legacy[KEY].metadata["openshell.storage_object_id"],
        "legacy-object"
    );
    if driver == "vault" {
        assert!(legacy[KEY].handle.starts_with("v1:openshell/"));
    } else {
        assert!(legacy[KEY].handle.starts_with("v1:ref-tests:"));
    }
    let state_store = Arc::new(MemoryStore::default());
    let runtime = ReferenceRuntime::new(
        "protocol-fixture-issuer",
        backend.clone(),
        state_store.clone(),
    )
    .unwrap();
    let references = runtime
        .adopt_with_expiration(owner(), "static", &legacy, None, "adoption")
        .await
        .unwrap();
    assert_eq!(
        writes(uri).await.len(),
        1,
        "adoption must not write the backend"
    );
    assert_eq!(references[KEY].driver, legacy[KEY].driver);
    assert_eq!(references[KEY].handle, legacy[KEY].handle);
    for (key, value) in &legacy[KEY].metadata {
        assert_eq!(references[KEY].metadata.get(key), Some(value));
    }
    assert!(
        ReferenceProjection::from_handle(&references[KEY])
            .unwrap()
            .is_some()
    );
    let resolved = runtime
        .resolve_at(owner(), &references, now())
        .await
        .unwrap();
    assert_eq!(resolved[0].version, 1);
    assert!(resolved[0].value == LEGACY);

    let values = HashMap::from([(KEY.to_owned(), ROTATION_ONE.to_owned())]);
    let store_one = || StoreReferenceSecrets {
        owner: owner(),
        epoch: "static",
        write_id: "rotation-one",
        protected_intent: b"protected-fixture-intent-one",
        values: &values,
        existing_handles: &references,
        expiration_time: None,
    };
    let rotated = runtime.store(store_one()).await.unwrap();
    assert_eq!(rotated, references);
    runtime.store(store_one()).await.unwrap();
    assert_eq!(
        writes(uri).await.len(),
        2,
        "idempotent replay must not repeat a physical write"
    );
    let resolved = runtime
        .resolve_at(owner(), &references, now())
        .await
        .unwrap();
    assert_eq!(resolved[0].version, 2);
    assert!(resolved[0].value == ROTATION_ONE);
    assert!(
        backend.resolve(owner(), &legacy).await.unwrap()[0].value == LEGACY,
        "staging must not overwrite the original physical path"
    );

    let values = HashMap::from([(KEY.to_owned(), ROTATION_TWO.to_owned())]);
    let store_uncertain = || StoreReferenceSecrets {
        owner: owner(),
        epoch: "static",
        write_id: "uncertain-rotation",
        protected_intent: b"protected-fixture-intent-two",
        values: &values,
        existing_handles: &references,
        expiration_time: None,
    };
    control(uri, "uncertain-write").await;
    assert_eq!(
        runtime.store(store_uncertain()).await.err().unwrap().code(),
        Code::Unavailable
    );
    assert_eq!(
        writes(uri).await.len(),
        3,
        "failed response follows a committed backend write"
    );
    let resolved = runtime
        .resolve_at(owner(), &references, now())
        .await
        .unwrap();
    assert_eq!(resolved[0].version, 2);
    assert!(resolved[0].value == ROTATION_ONE);
    let recovery = runtime.write_recovery(owner()).await.unwrap();
    let unknown = recovery
        .iter()
        .find(|record| record.write_id == "uncertain-rotation")
        .unwrap();
    assert_eq!(unknown.attempt_object_ids.len(), 1);
    assert!(!unknown.committed && unknown.staged_keys.is_empty());
    let first_attempt = unknown.attempt_object_ids[0].clone();
    runtime.store(store_uncertain()).await.unwrap();
    let recovery = runtime.write_recovery(owner()).await.unwrap();
    let recovered = recovery
        .iter()
        .find(|record| record.write_id == "uncertain-rotation")
        .unwrap();
    assert!(recovered.committed);
    assert_eq!(recovered.attempt_object_ids.len(), 2);
    assert_eq!(recovered.attempt_object_ids[0], first_attempt);
    assert_ne!(
        recovered.attempt_object_ids[0],
        recovered.attempt_object_ids[1]
    );
    let paths = writes(uri).await;
    assert_eq!(paths.len(), 4);
    assert_eq!(
        paths
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        4,
        "every physical execution needs a distinct path"
    );
    let restarted =
        ReferenceRuntime::new("protocol-fixture-issuer", backend.clone(), state_store).unwrap();
    let resolved = restarted
        .resolve_at(owner(), &references, now())
        .await
        .unwrap();
    assert_eq!(resolved[0].version, 3);
    assert!(resolved[0].value == ROTATION_TWO);

    control(uri, "outage").await;
    assert_eq!(
        restarted
            .resolve_at(owner(), &references, now())
            .await
            .err()
            .unwrap()
            .code(),
        Code::Unavailable
    );
    control(uri, "healthy").await;
    assert_eq!(
        restarted
            .resolve_at(owner(), &references, now())
            .await
            .unwrap()[0]
            .version,
        3
    );
    control(uri, "remove-latest").await;
    assert_eq!(
        restarted
            .resolve_at(owner(), &references, now())
            .await
            .err()
            .unwrap()
            .code(),
        Code::NotFound
    );
    assert!(backend.resolve(owner(), &legacy).await.unwrap()[0].value == LEGACY);
}

#[tokio::test]
async fn vault_adapter_adopts_stages_and_retains_uncertain_write_evidence() {
    let server = protocol_server(Protocol::Vault).await;
    let directory = tempfile::tempdir().unwrap();
    let token_file = directory.path().join("token");
    std::fs::write(&token_file, "fixture-vault-token\n").unwrap();
    let issuer = EmbeddedCredentialIssuer::from_options(
        &config("vault", vault_config(&server.uri(), &token_file)),
        None,
    )
    .await
    .unwrap();
    let issuer: Arc<dyn CredentialIssuer> = Arc::new(issuer);
    backend_scenario(issuer.clone(), &server.uri(), "vault").await;
    verify_vault_migration_retry_identity(issuer, &server.uri()).await;
}

#[cfg(unix)]
#[tokio::test]
async fn uds_transport_with_real_vault_service_preserves_staging_and_uncertain_results() {
    use openshell_core::proto::credentials::v1::credential_driver_server::CredentialDriverServer;
    use openshell_driver_vault::{CredentialDriverService, VaultCredentialDriver};
    let server = protocol_server(Protocol::Vault).await;
    let directory = tempfile::tempdir().unwrap();
    let token_file = directory.path().join("token");
    std::fs::write(&token_file, "fixture-vault-token\n").unwrap();
    let vault =
        VaultCredentialDriver::from_config(&vault_config(&server.uri(), &token_file)).unwrap();
    let socket = directory.path().join("driver.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let incoming = futures::stream::unfold(listener, |listener| async move {
        Some((listener.accept().await.map(|(stream, _)| stream), listener))
    });
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(CredentialDriverServer::new(CredentialDriverService::new(
                vault,
            )))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = stop_rx.await;
            })
            .await
    });
    let table = toml::Table::from_iter([
        (
            "transport".to_owned(),
            toml::Value::String("uds".to_owned()),
        ),
        (
            "socket_path".to_owned(),
            toml::Value::String(socket.display().to_string()),
        ),
    ]);
    let options = config("vault", table);
    let issuer = EmbeddedCredentialIssuer::from_options(&options, None)
        .await
        .unwrap();
    assert_eq!(issuer.negotiated_extensions().len(), 1);
    // Transport correctness alone is not a recovery capability. This older
    // Vault service contract cannot authorize automatic UDS conversion.
    assert_eq!(
        crate::references::backend_recovery::validate_activation(
            &options,
            issuer.negotiated_extensions()
        )
        .unwrap_err()
        .code(),
        Code::FailedPrecondition
    );
    backend_scenario(Arc::new(issuer), &server.uri(), "vault").await;
    stop_tx.send(()).unwrap();
    task.await.unwrap().unwrap();
}

// kube::Client::try_default reads KUBECONFIG. Use the existing isolated-child
// fixture pattern rather than racing global environment mutation in this test
// process or adding a production-only dependency injection hook.
#[tokio::test]
async fn kubernetes_adapter_adopts_stages_and_retains_uncertain_write_evidence() {
    let server = protocol_server(Protocol::Kubernetes).await;
    let directory = tempfile::tempdir().unwrap();
    let kubeconfig = directory.path().join("kubeconfig");
    std::fs::write(&kubeconfig, serde_json::to_vec(&json!({
        "apiVersion": "v1", "kind": "Config", "current-context": "fixture",
        "clusters": [{ "name": "fixture", "cluster": { "server": server.uri(), "insecure-skip-tls-verify": true } }],
        "contexts": [{ "name": "fixture", "context": { "cluster": "fixture", "user": "fixture", "namespace": "ref-tests" } }],
        "users": [{ "name": "fixture", "user": { "token": "fixture-kube-token" } }],
    })).unwrap()).unwrap();
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(90),
        tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "references::tests::backend_protocol::kubernetes_protocol_child",
                "--ignored",
                "--nocapture",
            ])
            .env("KUBECONFIG", &kubeconfig)
            .env("OPENSHELL_REFERENCE_KUBE_CHILD", server.uri())
            .env_remove("KUBERNETES_SERVICE_HOST")
            .env_remove("KUBERNETES_SERVICE_PORT")
            .env_remove("HTTP_PROXY")
            .env_remove("HTTPS_PROXY")
            .env_remove("ALL_PROXY")
            .env_remove("http_proxy")
            .env_remove("https_proxy")
            .env_remove("all_proxy")
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "isolated Kubernetes protocol test failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
#[ignore = "run by the Kubernetes adapter test in an isolated KUBECONFIG process"]
async fn kubernetes_protocol_child() {
    let Ok(uri) = std::env::var("OPENSHELL_REFERENCE_KUBE_CHILD") else {
        return;
    };
    let table = toml::Table::from_iter([(
        "namespace".to_owned(),
        toml::Value::String("ref-tests".to_owned()),
    )]);
    let issuer = EmbeddedCredentialIssuer::from_options(&config("kubernetes-secrets", table), None)
        .await
        .unwrap();
    let issuer: Arc<dyn CredentialIssuer> = Arc::new(issuer);
    backend_scenario(issuer.clone(), &uri, "kubernetes-secrets").await;
    recover_lost_migration_response(issuer, &uri).await;
    #[cfg(unix)]
    kubernetes_uds_recovery_scenario(&uri).await;
}

async fn recover_lost_migration_response(backend: Arc<dyn CredentialIssuer>, uri: &str) {
    let values = HashMap::from([(KEY.to_owned(), LEGACY.to_owned())]);
    let empty = Handles::new();
    let write = || StoreSecrets {
        owner: owner(),
        object_id: Some("durable-migration-attempt"),
        values: &values,
        existing_handles: &empty,
    };
    control(uri, "uncertain-write").await;
    assert_eq!(
        backend.store(write()).await.err().unwrap().code(),
        Code::Unavailable
    );
    let before = writes(uri).await;
    let recovered = backend.store(write()).await.unwrap();
    assert_eq!(
        writes(uri).await,
        before,
        "verified recovery must not rewrite an attempt-owned Secret"
    );
    assert_eq!(
        recovered[KEY].metadata["openshell.storage_object_id"],
        "durable-migration-attempt"
    );
    assert_eq!(backend.store(write()).await.unwrap(), recovered);
    let changed_values = HashMap::from([(KEY.to_owned(), ROTATION_ONE.to_owned())]);
    assert_eq!(
        backend
            .store(StoreSecrets {
                owner: owner(),
                object_id: Some("durable-migration-attempt"),
                values: &changed_values,
                existing_handles: &empty
            })
            .await
            .err()
            .unwrap()
            .code(),
        Code::AlreadyExists
    );
    assert!(backend.resolve(owner(), &recovered).await.unwrap()[0].value == LEGACY);
    control(uri, "tamper-latest-owner").await;
    assert_eq!(
        backend.store(write()).await.err().unwrap().code(),
        Code::FailedPrecondition
    );
}

#[cfg(unix)]
async fn kubernetes_uds_recovery_scenario(uri: &str) {
    use openshell_core::proto::credentials::v1::credential_driver_server::CredentialDriverServer;
    use openshell_driver_kubernetes_secrets::{
        CredentialDriverService, KubernetesSecretsCredentialDriver,
        RECOVERABLE_IMMUTABLE_WRITE_CAPABILITY,
    };
    control(uri, "reset").await;
    let namespace = toml::Table::from_iter([(
        "namespace".to_owned(),
        toml::Value::String("ref-tests".to_owned()),
    )]);
    let driver = KubernetesSecretsCredentialDriver::from_config(&namespace)
        .await
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("kube-driver.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let incoming = futures::stream::unfold(listener, |listener| async move {
        Some((listener.accept().await.map(|(stream, _)| stream), listener))
    });
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(CredentialDriverServer::new(CredentialDriverService::new(
                driver,
            )))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = stop_rx.await;
            })
            .await
    });
    let transport = toml::Table::from_iter([
        (
            "transport".to_owned(),
            toml::Value::String("uds".to_owned()),
        ),
        (
            "socket_path".to_owned(),
            toml::Value::String(socket.display().to_string()),
        ),
    ]);
    let options = config("kubernetes-secrets", transport);
    let issuer = EmbeddedCredentialIssuer::from_options(&options, None)
        .await
        .unwrap();
    crate::references::backend_recovery::validate_activation(
        &options,
        issuer.negotiated_extensions(),
    )
    .unwrap();
    assert!(
        issuer.negotiated_extensions()[0]
            .supported_capabilities
            .iter()
            .any(|capability| capability == RECOVERABLE_IMMUTABLE_WRITE_CAPABILITY)
    );
    let issuer: Arc<dyn CredentialIssuer> = Arc::new(issuer);
    backend_scenario(issuer.clone(), uri, "kubernetes-secrets").await;
    recover_lost_migration_response(issuer, uri).await;
    stop_tx.send(()).unwrap();
    task.await.unwrap().unwrap();
}

async fn verify_vault_migration_retry_identity(backend: Arc<dyn CredentialIssuer>, uri: &str) {
    let values = HashMap::from([(KEY.to_owned(), LEGACY.to_owned())]);
    let empty = Handles::new();
    let write = || StoreSecrets {
        owner: owner(),
        object_id: Some("vault-migration-attempt"),
        values: &values,
        existing_handles: &empty,
    };
    control(uri, "uncertain-write").await;
    assert_eq!(
        backend.store(write()).await.err().unwrap().code(),
        Code::Unavailable
    );
    let unknown = writes(uri).await.last().unwrap().clone();
    let recovered = backend.store(write()).await.unwrap();
    let retry_paths = writes(uri).await;
    assert_eq!(retry_paths[retry_paths.len() - 2], unknown);
    assert_eq!(retry_paths[retry_paths.len() - 1], unknown);
    assert_eq!(backend.store(write()).await.unwrap(), recovered);
    assert_eq!(writes(uri).await.last(), Some(&unknown));
    assert_eq!(
        recovered[KEY].metadata["openshell.storage_object_id"],
        "vault-migration-attempt"
    );
    assert!(backend.resolve(owner(), &recovered).await.unwrap()[0].value == LEGACY);
    // Vault's legacy contract can append another KV version on retry. It
    // preserves the attempt path under the caller's immutable protected intent;
    // this is NOT exactly-once physical writes or generic UDS CAS support.
}
