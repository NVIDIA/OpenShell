// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Read-only web dashboard for developers and operators (demo scaffolding).
//!
//! Serves a single-file SPA at `/ui` plus a small JSON/SSE API under
//! `/ui/api/*` that adapts existing gRPC handler logic for browser
//! consumption. The whole surface is disabled unless the
//! `OPENSHELL_WEB_UI` environment variable is set to `1` or `true`,
//! because these routes intentionally bypass gRPC bearer authentication
//! and are only suitable for trusted local/dev gateways.

use std::convert::Infallible;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Json};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use tokio_stream::wrappers::ReceiverStream;
use tonic::Request;

use openshell_core::proto::{
    GetSandboxLogsRequest, GetSandboxPolicyStatusRequest, GetSandboxRequest,
    ListSandboxPoliciesRequest, ListSandboxesRequest, Sandbox, SandboxLogLine, SandboxPhase,
    sandbox_stream_event,
};

use crate::ServerState;
use crate::grpc::{policy, sandbox};

/// Returns true when the web UI surface is enabled for this process.
pub fn enabled() -> bool {
    matches!(
        std::env::var("OPENSHELL_WEB_UI").as_deref(),
        Ok("1" | "true")
    )
}

/// Build the `/ui` router. Returns an empty router when disabled.
pub fn router(state: Arc<ServerState>) -> Router {
    if !enabled() {
        return Router::new();
    }
    Router::new()
        .route("/ui", get(index))
        .route("/ui/", get(index))
        .route("/ui/api/overview", get(overview))
        .route("/ui/api/sandboxes", get(list_sandboxes))
        .route("/ui/api/sandboxes/{name}", get(sandbox_detail))
        .route("/ui/api/sandboxes/{name}/logs", get(sandbox_logs))
        .route("/ui/api/sandboxes/{name}/stream", get(sandbox_stream))
        .with_state(state)
}

async fn index() -> impl IntoResponse {
    Html(include_str!("../assets/ui.html"))
}

// ---------------------------------------------------------------------------
// JSON shapes (stable UI contract, decoupled from proto)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct OverviewJson {
    version: String,
    sandbox_count: usize,
    ready_count: usize,
}

#[derive(Serialize)]
struct SandboxJson {
    id: String,
    name: String,
    phase: String,
    created_at_ms: i64,
    image: String,
    providers: Vec<String>,
    active_policy_version: u32,
    conditions: Vec<ConditionJson>,
}

#[derive(Serialize)]
struct ConditionJson {
    r#type: String,
    status: String,
    reason: String,
    message: String,
}

#[derive(Serialize)]
struct PolicyRevisionJson {
    version: u32,
    hash: String,
    status: String,
    load_error: String,
    created_at_ms: i64,
    loaded_at_ms: i64,
}

#[derive(Serialize)]
struct SandboxDetailJson {
    sandbox: SandboxJson,
    revisions: Vec<PolicyRevisionJson>,
    policy_yaml: String,
}

#[derive(Serialize)]
struct LogLineJson {
    timestamp_ms: i64,
    level: String,
    target: String,
    message: String,
    source: String,
    fields: std::collections::HashMap<String, String>,
}

fn phase_name(phase: i32) -> String {
    match SandboxPhase::try_from(phase) {
        Ok(SandboxPhase::Provisioning) => "Provisioning",
        Ok(SandboxPhase::Ready) => "Ready",
        Ok(SandboxPhase::Error) => "Error",
        Ok(SandboxPhase::Deleting) => "Deleting",
        _ => "Unknown",
    }
    .to_string()
}

fn sandbox_json(sb: &Sandbox) -> SandboxJson {
    let meta = sb.metadata.clone().unwrap_or_default();
    let spec = sb.spec.clone().unwrap_or_default();
    let status = sb.status.clone().unwrap_or_default();
    let image = spec
        .template
        .as_ref()
        .map(|t| t.image.clone())
        .unwrap_or_default();
    SandboxJson {
        id: meta.id,
        name: meta.name,
        phase: phase_name(status.phase),
        created_at_ms: meta.created_at_ms,
        image,
        providers: spec.providers,
        active_policy_version: status.current_policy_version,
        conditions: status
            .conditions
            .iter()
            .map(|c| ConditionJson {
                r#type: c.r#type.clone(),
                status: c.status.clone(),
                reason: c.reason.clone(),
                message: c.message.clone(),
            })
            .collect(),
    }
}

fn log_line_json(line: &SandboxLogLine) -> LogLineJson {
    LogLineJson {
        timestamp_ms: line.timestamp_ms,
        level: line.level.clone(),
        target: line.target.clone(),
        message: line.message.clone(),
        source: line.source.clone(),
        fields: line.fields.clone(),
    }
}

fn status_error(status: tonic::Status) -> (StatusCode, String) {
    let code = match status.code() {
        tonic::Code::NotFound => StatusCode::NOT_FOUND,
        tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (code, status.message().to_string())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn overview(
    State(state): State<Arc<ServerState>>,
) -> Result<Json<OverviewJson>, (StatusCode, String)> {
    let resp = sandbox::handle_list_sandboxes(
        &state,
        Request::new(ListSandboxesRequest {
            limit: 500,
            ..Default::default()
        }),
    )
    .await
    .map_err(status_error)?
    .into_inner();

    let ready_count = resp
        .sandboxes
        .iter()
        .filter(|sb| sb.status.as_ref().map(|s| s.phase) == Some(SandboxPhase::Ready as i32))
        .count();

    Ok(Json(OverviewJson {
        version: openshell_core::VERSION.to_string(),
        sandbox_count: resp.sandboxes.len(),
        ready_count,
    }))
}

async fn list_sandboxes(
    State(state): State<Arc<ServerState>>,
) -> Result<Json<Vec<SandboxJson>>, (StatusCode, String)> {
    let resp = sandbox::handle_list_sandboxes(
        &state,
        Request::new(ListSandboxesRequest {
            limit: 500,
            ..Default::default()
        }),
    )
    .await
    .map_err(status_error)?
    .into_inner();
    Ok(Json(resp.sandboxes.iter().map(sandbox_json).collect()))
}

async fn sandbox_detail(
    State(state): State<Arc<ServerState>>,
    Path(name): Path<String>,
) -> Result<Json<SandboxDetailJson>, (StatusCode, String)> {
    let sb = sandbox::handle_get_sandbox(
        &state,
        Request::new(GetSandboxRequest { name: name.clone() }),
    )
    .await
    .map_err(status_error)?
    .into_inner()
    .sandbox
    .ok_or_else(|| (StatusCode::NOT_FOUND, "sandbox not found".to_string()))?;

    let revisions = policy::handle_list_sandbox_policies(
        &state,
        Request::new(ListSandboxPoliciesRequest {
            name: name.clone(),
            limit: 50,
            ..Default::default()
        }),
    )
    .await
    .map_err(status_error)?
    .into_inner()
    .revisions
    .iter()
    .map(|r| PolicyRevisionJson {
        version: r.version,
        hash: r.policy_hash.clone(),
        status: format!("{:?}", r.status()),
        load_error: r.load_error.clone(),
        created_at_ms: r.created_at_ms,
        loaded_at_ms: r.loaded_at_ms,
    })
    .collect();

    // Latest revision with full policy payload for the YAML pane.
    let policy_yaml = policy::handle_get_sandbox_policy_status(
        &state,
        Request::new(GetSandboxPolicyStatusRequest {
            name: name.clone(),
            ..Default::default()
        }),
    )
    .await
    .ok()
    .and_then(|resp| resp.into_inner().revision)
    .and_then(|rev| rev.policy)
    .and_then(|p| openshell_policy::serialize_sandbox_policy(&p).ok())
    .unwrap_or_default();

    Ok(Json(SandboxDetailJson {
        sandbox: sandbox_json(&sb),
        revisions,
        policy_yaml,
    }))
}

#[derive(Deserialize)]
struct LogsQuery {
    #[serde(default)]
    lines: u32,
}

async fn sandbox_logs(
    State(state): State<Arc<ServerState>>,
    Path(name): Path<String>,
    Query(q): Query<LogsQuery>,
) -> Result<Json<Vec<LogLineJson>>, (StatusCode, String)> {
    let id = resolve_sandbox_id(&state, &name).await?;
    let resp = policy::handle_get_sandbox_logs(
        &state,
        Request::new(GetSandboxLogsRequest {
            sandbox_id: id,
            lines: if q.lines == 0 { 300 } else { q.lines },
            ..Default::default()
        }),
    )
    .await
    .map_err(status_error)?
    .into_inner();
    Ok(Json(resp.logs.iter().map(log_line_json).collect()))
}

/// Live event stream: forwards the sandbox's tracing bus to the browser as
/// SSE messages, one JSON-encoded log line per event.
async fn sandbox_stream(
    State(state): State<Arc<ServerState>>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let id = resolve_sandbox_id(&state, &name).await?;
    let mut rx = state.tracing_log_bus.subscribe(&id);
    let (tx, out_rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(256);

    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    let Some(sandbox_stream_event::Payload::Log(line)) = event.payload else {
                        continue;
                    };
                    let Ok(json) = serde_json::to_string(&log_line_json(&line)) else {
                        continue;
                    };
                    if tx.send(Ok(Event::default().data(json))).await.is_err() {
                        break; // client went away
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    Ok(Sse::new(ReceiverStream::new(out_rx)).keep_alive(KeepAlive::default()))
}

async fn resolve_sandbox_id(
    state: &Arc<ServerState>,
    name: &str,
) -> Result<String, (StatusCode, String)> {
    let sb = sandbox::handle_get_sandbox(
        state,
        Request::new(GetSandboxRequest {
            name: name.to_string(),
        }),
    )
    .await
    .map_err(status_error)?
    .into_inner()
    .sandbox
    .ok_or_else(|| (StatusCode::NOT_FOUND, "sandbox not found".to_string()))?;
    Ok(sb.metadata.unwrap_or_default().id)
}
