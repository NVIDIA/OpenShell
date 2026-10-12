// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Continuous HTTP observations through the existing sandbox service relay.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use futures::{StreamExt, stream};
use http::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use openshell_core::proto::{
    HttpReadinessCheck, RelayOpen, Sandbox, SandboxPhase, ServiceEndpoint, ServiceHealth,
    ServiceHealthState, TcpRelayTarget, relay_open,
};
use openshell_core::{GetResourceVersion, ObjectId};
use prost::Message;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tonic::Status;

use crate::ServerState;
use crate::persistence::ObjectListQuery;

const INTERVAL: Duration = Duration::from_secs(5);
const TIMEOUT: Duration = Duration::from_secs(1);
const STALE_AFTER: Duration = Duration::from_secs(15);
const FAILURE_THRESHOLD: u32 = 3;
const PAGE_SIZE: u32 = 100;
const MAX_CONCURRENT_CHECKS: usize = 16;

#[derive(Default, Debug)]
pub struct ServiceHealthCache {
    entries: Mutex<HashMap<String, Observation>>,
}

#[derive(Debug)]
struct Observation {
    generation: Vec<u8>,
    observed_at: Instant,
    failures: u32,
    health: ServiceHealth,
}

enum ProbeResult {
    Http(StatusCode),
    Failed(&'static str),
    Unknown(&'static str),
}

pub fn validate_readiness_check(check: Option<&HttpReadinessCheck>) -> Result<(), Status> {
    let Some(check) = check else { return Ok(()) };
    if check.path.is_empty() {
        return Ok(());
    }
    let path = &check.path;
    if path.len() > 1024
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.contains(['?', '#'])
        || !path.bytes().all(|byte| byte.is_ascii_graphic())
        || path.parse::<http::uri::PathAndQuery>().is_err()
    {
        return Err(Status::invalid_argument(
            "readiness_check.path must be an HTTP path beginning with /, without a query or fragment, at most 1024 bytes",
        ));
    }
    Ok(())
}

fn probe_path(endpoint: &ServiceEndpoint) -> &str {
    endpoint.readiness_check.as_ref().map_or("/", |check| {
        if check.path.is_empty() {
            "/"
        } else {
            &check.path
        }
    })
}

fn unknown(message: &str) -> ServiceHealth {
    ServiceHealth {
        state: ServiceHealthState::Unknown as i32,
        message: message.to_string(),
        ..Default::default()
    }
}

// Include the runtime identity and endpoint revision so an old response can
// never certify a replacement runtime or a newly configured port/path.
fn generation(state: &ServerState, endpoint: &ServiceEndpoint, sandbox: &Sandbox) -> Vec<u8> {
    let mut bytes = endpoint.get_resource_version().to_le_bytes().to_vec();
    bytes.extend_from_slice(endpoint.sandbox_id.as_bytes());
    if let Some(status) = &sandbox.status {
        bytes.extend_from_slice(status.main_process_instance_id.as_bytes());
        bytes.extend_from_slice(&status.restart_count.to_le_bytes());
        if let Some(started) = &status.main_process_started_time {
            bytes.extend_from_slice(&started.encode_to_vec());
        }
    }
    if let Some(session) = state
        .supervisor_sessions
        .current_session_id(&endpoint.sandbox_id)
    {
        bytes.extend_from_slice(session.as_bytes());
    }
    bytes
}

impl ServiceHealthCache {
    fn read(&self, endpoint: &ServiceEndpoint, generation: &[u8]) -> ServiceHealth {
        let entries = self.entries.lock().unwrap();
        let Some(entry) = entries.get(endpoint.object_id()) else {
            return unknown("Awaiting first HTTP check");
        };
        if entry.generation != generation {
            return unknown("Awaiting HTTP check for current runtime and configuration");
        }
        if entry.observed_at.elapsed() >= STALE_AFTER {
            return unknown("HTTP observation is stale");
        }
        entry.health.clone()
    }

    fn record(&self, endpoint: &ServiceEndpoint, generation: Vec<u8>, result: ProbeResult) {
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap();
        let entry = entries
            .entry(endpoint.object_id().to_string())
            .or_insert_with(|| Observation {
                generation: generation.clone(),
                observed_at: now,
                failures: 0,
                health: unknown("Awaiting first HTTP check"),
            });
        if entry.generation != generation {
            entry.generation = generation;
            entry.failures = 0;
            entry.health = unknown("Awaiting first HTTP check");
        } else if now.duration_since(entry.observed_at) >= STALE_AFTER {
            // A delayed scan invalidates readiness, but consecutive failed
            // attempts still count when the runtime/configuration is unchanged.
            entry.health = unknown("HTTP observation is stale");
        }
        entry.observed_at = now;
        entry.health.last_checked_time =
            openshell_core::time::timestamp_from_millis(crate::persistence::current_time_ms()).ok();
        entry.health.http_status_code = None;
        let successful = match result {
            ProbeResult::Http(status) => {
                entry.health.http_status_code = Some(u32::from(status.as_u16()));
                entry.health.message = format!("HTTP check returned {}", status.as_u16());
                endpoint.readiness_check.is_none() || status.is_success()
            }
            ProbeResult::Failed(message) => {
                entry.health.message = message.to_string();
                false
            }
            ProbeResult::Unknown(message) => {
                entry.failures = 0;
                entry.health.state = ServiceHealthState::Unknown as i32;
                entry.health.message = message.to_string();
                return;
            }
        };
        if successful {
            entry.failures = 0;
            entry.health.state = ServiceHealthState::Healthy as i32;
        } else {
            entry.failures = entry.failures.saturating_add(1);
            if entry.failures >= FAILURE_THRESHOLD {
                entry.health.state = ServiceHealthState::Unhealthy as i32;
            }
        }
    }
}

/// Reads cached health after validating that the owning runtime is still ready.
/// This performs no network probe and never writes the persisted service.
pub async fn endpoint_health(state: &ServerState, endpoint: &ServiceEndpoint) -> ServiceHealth {
    match state
        .store
        .get_message::<Sandbox>(&endpoint.sandbox_id)
        .await
    {
        Ok(Some(sandbox)) if sandbox.phase() == SandboxPhase::Ready as i32 => state
            .service_health
            .read(endpoint, &generation(state, endpoint, &sandbox)),
        Ok(_) => unknown("Sandbox is not ready for HTTP checks"),
        Err(_) => unknown("Sandbox observation is unavailable"),
    }
}

async fn http_check<T>(stream: T, port: u32, path: &str) -> ProbeResult
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Ok((mut sender, connection)) = hyper::client::conn::http1::Builder::new()
        .max_buf_size(16 * 1024)
        .handshake::<_, Body>(TokioIo::new(stream))
        .await
    else {
        return ProbeResult::Failed("HTTP connection failed");
    };
    let request = Request::builder()
        .uri(path)
        .header(http::header::HOST, format!("127.0.0.1:{port}"))
        .header(http::header::CONNECTION, "close")
        .body(Body::empty())
        .expect("validated readiness path and loopback host");
    // Drive the connection in this task so timeout/cancellation drops both
    // halves. Only response headers are needed; never buffer application bodies.
    let response = sender.send_request(request);
    tokio::pin!(response);
    let result = tokio::select! {
        result = &mut response => result,
        // The connection can finish in the same poll that delivers headers.
        // Consume the response channel before classifying the close as failure.
        _ = connection => response.await,
    };
    result.map_or(ProbeResult::Failed("HTTP response failed"), |response| {
        ProbeResult::Http(response.status())
    })
}

async fn probe(state: &Arc<ServerState>, endpoint: &ServiceEndpoint) -> ProbeResult {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    let relay = tokio::time::timeout_at(
        deadline,
        crate::supervisor_session::open_routed_relay_with_message(
            state,
            &endpoint.sandbox_id,
            RelayOpen {
                channel_id: uuid::Uuid::new_v4().to_string(),
                target: Some(relay_open::Target::Tcp(TcpRelayTarget {
                    host: "127.0.0.1".to_string(),
                    port: endpoint.target_port,
                })),
                service_id: endpoint.object_id().to_string(),
                health_check: true,
            },
            TIMEOUT,
        ),
    )
    .await;
    let (channel_id, receiver) = match relay {
        Ok(Ok(relay)) => relay,
        Ok(Err(status)) => return relay_failure(&status),
        _ => return ProbeResult::Unknown("Supervisor relay unavailable"),
    };
    let stream = match tokio::time::timeout_at(deadline, receiver).await {
        Ok(Ok(Ok(stream))) => stream,
        Ok(Ok(Err(_))) => return ProbeResult::Failed("Service connection failed"),
        Ok(Err(_)) => return ProbeResult::Unknown("Supervisor relay disconnected"),
        Err(_) => {
            state
                .supervisor_sessions
                .fail_pending_relay(&channel_id, "HTTP check timed out".to_string());
            return ProbeResult::Unknown("Supervisor relay setup timed out");
        }
    };
    tokio::time::timeout_at(
        deadline,
        http_check(stream, endpoint.target_port, probe_path(endpoint)),
    )
    .await
    .unwrap_or(ProbeResult::Failed("HTTP response timed out"))
}

fn relay_failure(status: &Status) -> ProbeResult {
    if crate::supervisor_session::is_relay_target_failure(status) {
        ProbeResult::Failed("Service connection failed")
    } else {
        ProbeResult::Unknown("Supervisor relay unavailable")
    }
}

async fn check_endpoint(state: &Arc<ServerState>, endpoint: ServiceEndpoint) {
    let Ok(Some(sandbox)) = state
        .store
        .get_message::<Sandbox>(&endpoint.sandbox_id)
        .await
    else {
        state
            .service_health
            .entries
            .lock()
            .unwrap()
            .remove(endpoint.object_id());
        return;
    };
    if sandbox.phase() != SandboxPhase::Ready as i32 {
        state
            .service_health
            .entries
            .lock()
            .unwrap()
            .remove(endpoint.object_id());
        return;
    }
    // Legacy or corrupt stored checks must not panic the monitor.
    if validate_readiness_check(endpoint.readiness_check.as_ref()).is_err() {
        return;
    }
    let observed_generation = generation(state, &endpoint, &sandbox);
    let result = probe(state, &endpoint).await;
    state
        .service_health
        .record(&endpoint, observed_generation, result);
}

async fn scan(state: &Arc<ServerState>) {
    let mut cursor = None;
    let mut seen = HashSet::new();
    loop {
        let page = match state
            .store
            .list_message_page::<ServiceEndpoint>(
                ObjectListQuery::AllWorkspaces,
                cursor.as_ref(),
                PAGE_SIZE,
            )
            .await
        {
            Ok(page) => page,
            Err(error) => {
                tracing::warn!(%error, "service health scan failed");
                return;
            }
        };
        seen.extend(
            page.messages
                .iter()
                .map(|endpoint| endpoint.object_id().to_string()),
        );
        stream::iter(page.messages)
            .for_each_concurrent(MAX_CONCURRENT_CHECKS, |endpoint| {
                check_endpoint(state, endpoint)
            })
            .await;
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    // Collect deleted endpoints. Retain live stale entries so a slow scan does
    // not discard their failure counts; reads still report stale health unknown.
    state
        .service_health
        .entries
        .lock()
        .unwrap()
        .retain(|id, _| seen.contains(id));
}

pub fn spawn_monitor(
    state: Arc<ServerState>,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = interval.tick() => {
                    tokio::select! {
                        _ = shutdown.changed() => break,
                        () = scan(&state) => {},
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(readiness: bool) -> ServiceEndpoint {
        ServiceEndpoint {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "service".to_string(),
                ..Default::default()
            }),
            target_port: 4500,
            readiness_check: readiness.then(|| HttpReadinessCheck {
                path: "/readyz".to_string(),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn peer_target_refusal_fails_but_infrastructure_errors_are_unknown() {
        let refusal = openshell_core::rpc_error::failed_precondition(
            "RELAY_TARGET_FAILED",
            "connection refused",
        );
        assert!(matches!(relay_failure(&refusal), ProbeResult::Failed(_)));
        for status in [
            Status::unavailable("peer offline"),
            Status::failed_precondition("peer TLS configuration unavailable"),
        ] {
            assert!(matches!(relay_failure(&status), ProbeResult::Unknown(_)));
        }
        // Older supervisors omit the marker and continue logging normal relays.
        assert!(
            !RelayOpen::decode(&[0x0a, 1, b'x'][..])
                .unwrap()
                .health_check
        );
    }

    #[test]
    fn validates_origin_paths() {
        for path in ["", "/", "/readyz", "/health/ready"] {
            assert!(
                validate_readiness_check(Some(&HttpReadinessCheck {
                    path: path.to_string()
                }))
                .is_ok()
            );
        }
        for path in [
            "readyz",
            "//other-host/",
            "http://other/",
            "/x?token=secret",
            "/x#fragment",
            "/x\r\n",
            "/a b",
        ] {
            assert!(
                validate_readiness_check(Some(&HttpReadinessCheck {
                    path: path.to_string()
                }))
                .is_err(),
                "{path}"
            );
        }
    }

    #[test]
    fn legacy_wire_payloads_default_to_responsiveness_and_unknown_health() {
        // Old endpoints contained target_port at field 5 and no readiness field.
        let endpoint = ServiceEndpoint::decode(&[0x28, 0x90, 0x3f][..]).unwrap();
        assert_eq!(endpoint.target_port, 8080);
        assert!(endpoint.readiness_check.is_none());
        assert_eq!(probe_path(&endpoint), "/");
        let response =
            openshell_core::proto::ServiceEndpointResponse::decode(&[0x12, 1, b'/'][..]).unwrap();
        assert!(response.health.is_none());
    }

    #[test]
    fn thresholds_recovery_and_runtime_invalidation() {
        let cache = ServiceHealthCache::default();
        let endpoint = endpoint(true);
        let generation = vec![1];
        assert_eq!(
            cache.read(&endpoint, &generation).state,
            ServiceHealthState::Unknown as i32
        );
        cache.record(
            &endpoint,
            generation.clone(),
            ProbeResult::Http(StatusCode::OK),
        );
        for _ in 0..2 {
            cache.record(
                &endpoint,
                generation.clone(),
                ProbeResult::Http(StatusCode::SERVICE_UNAVAILABLE),
            );
            assert_eq!(
                cache.read(&endpoint, &generation).state,
                ServiceHealthState::Healthy as i32
            );
        }
        cache.record(
            &endpoint,
            generation.clone(),
            ProbeResult::Http(StatusCode::FOUND),
        );
        assert_eq!(
            cache.read(&endpoint, &generation).state,
            ServiceHealthState::Unhealthy as i32
        );
        cache.record(
            &endpoint,
            generation.clone(),
            ProbeResult::Http(StatusCode::NO_CONTENT),
        );
        assert_eq!(
            cache.read(&endpoint, &generation).state,
            ServiceHealthState::Healthy as i32
        );
        assert_eq!(
            cache.read(&endpoint, &[2]).state,
            ServiceHealthState::Unknown as i32
        );
        cache.record(&endpoint, vec![2], ProbeResult::Failed("Connection failed"));
        assert_eq!(
            cache.read(&endpoint, &[2]).state,
            ServiceHealthState::Unknown as i32
        );
        cache.record(
            &endpoint,
            vec![2],
            ProbeResult::Unknown("Relay unavailable"),
        );
        assert_eq!(
            cache.read(&endpoint, &[2]).state,
            ServiceHealthState::Unknown as i32
        );
    }

    #[test]
    fn delayed_scans_preserve_failures_without_reusing_stale_readiness() {
        let cache = ServiceHealthCache::default();
        let endpoint = endpoint(true);
        for attempt in 1..=3 {
            cache.record(
                &endpoint,
                vec![1],
                ProbeResult::Failed("HTTP response timed out"),
            );
            let expected = if attempt == 3 {
                ServiceHealthState::Unhealthy
            } else {
                ServiceHealthState::Unknown
            };
            assert_eq!(cache.read(&endpoint, &[1]).state, expected as i32);
            cache
                .entries
                .lock()
                .unwrap()
                .get_mut("service")
                .unwrap()
                .observed_at -= STALE_AFTER;
            assert_eq!(
                cache.read(&endpoint, &[1]).state,
                ServiceHealthState::Unknown as i32
            );
        }
    }

    #[test]
    fn responsiveness_accepts_errors_and_stale_checks_expire() {
        let cache = ServiceHealthCache::default();
        let endpoint = endpoint(false);
        cache.record(
            &endpoint,
            vec![1],
            ProbeResult::Http(StatusCode::INTERNAL_SERVER_ERROR),
        );
        let health = cache.read(&endpoint, &[1]);
        assert_eq!(health.state, ServiceHealthState::Healthy as i32);
        assert_eq!(health.http_status_code, Some(500));
        cache
            .entries
            .lock()
            .unwrap()
            .get_mut("service")
            .unwrap()
            .observed_at -= STALE_AFTER;
        assert_eq!(
            cache.read(&endpoint, &[1]).state,
            ServiceHealthState::Unknown as i32
        );
    }

    #[tokio::test]
    async fn health_reads_reject_restarted_stopped_and_reconfigured_services() {
        let state = crate::grpc::test_support::test_server_state().await;
        let mut endpoint = endpoint(true);
        endpoint.sandbox_id = "sandbox".to_string();
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sandbox".to_string(),
                name: "sandbox".to_string(),
                workspace: "default".to_string(),
                ..Default::default()
            }),
            status: Some(openshell_core::proto::SandboxStatus {
                phase: SandboxPhase::Ready as i32,
                main_process_instance_id: "first-runtime".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        state.store.put_message(&sandbox).await.unwrap();
        state.service_health.record(
            &endpoint,
            generation(&state, &endpoint, &sandbox),
            ProbeResult::Http(StatusCode::OK),
        );
        assert_eq!(
            endpoint_health(&state, &endpoint).await.state,
            ServiceHealthState::Healthy as i32
        );

        endpoint.metadata.as_mut().unwrap().resource_version += 1;
        assert_eq!(
            endpoint_health(&state, &endpoint).await.state,
            ServiceHealthState::Unknown as i32
        );
        endpoint.metadata.as_mut().unwrap().resource_version -= 1;
        sandbox.status.as_mut().unwrap().main_process_instance_id =
            "replacement-runtime".to_string();
        state.store.put_message(&sandbox).await.unwrap();
        assert_eq!(
            endpoint_health(&state, &endpoint).await.state,
            ServiceHealthState::Unknown as i32
        );
        state.service_health.record(
            &endpoint,
            generation(&state, &endpoint, &sandbox),
            ProbeResult::Http(StatusCode::OK),
        );
        sandbox.set_phase(SandboxPhase::Stopped as i32);
        state.store.put_message(&sandbox).await.unwrap();
        assert_eq!(
            endpoint_health(&state, &endpoint).await.state,
            ServiceHealthState::Unknown as i32
        );
    }

    #[tokio::test]
    async fn http_probe_uses_path_no_credentials_and_stops_at_headers() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, mut server) = tokio::io::duplex(4096);
        let application = tokio::spawn(async move {
            let mut bytes = vec![0; 4096];
            let count = server.read(&mut bytes).await.unwrap();
            let request = String::from_utf8_lossy(&bytes[..count]);
            assert!(request.starts_with("GET /readyz HTTP/1.1\r\n"));
            assert!(!request.to_lowercase().contains("authorization:"));
            server
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 1000000\r\n\r\n")
                .await
                .unwrap();
            // No body follows. The check must finish without waiting for it.
            let _ = server.read(&mut bytes).await;
        });
        let result = tokio::time::timeout(TIMEOUT, http_check(client, 4500, "/readyz"))
            .await
            .unwrap();
        assert!(matches!(
            result,
            ProbeResult::Http(StatusCode::SERVICE_UNAVAILABLE)
        ));
        application.await.unwrap();
    }
}
