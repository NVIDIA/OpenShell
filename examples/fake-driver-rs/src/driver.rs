// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::result_large_err)] // gRPC handlers return Result<_, tonic::Status>

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::Stream;
use openshell_core::proto::compute::v1::{
    CreateSandboxRequest, CreateSandboxResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    DriverSandbox, DriverSandboxStatus, GetCapabilitiesRequest, GetCapabilitiesResponse,
    GetSandboxRequest, GetSandboxResponse, ListSandboxesRequest, ListSandboxesResponse,
    StopSandboxRequest, StopSandboxResponse, ValidateSandboxCreateRequest,
    ValidateSandboxCreateResponse, WatchSandboxesDeletedEvent, WatchSandboxesEvent,
    WatchSandboxesRequest, WatchSandboxesSandboxEvent, compute_driver_server::ComputeDriver,
    watch_sandboxes_event::Payload,
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::config::{Config, SandboxConfig, WatchSandboxesConfig};
use crate::sequence::Sequence;

pub struct FakeDriver {
    state: Arc<Mutex<DriverState>>,
    watch_config: WatchSandboxesConfig,
}

struct DriverState {
    validate_sandbox_create: Sequence<crate::config::ValidateSandboxCreateEntry>,
    create_sandbox: Sequence<crate::config::SimpleEntry>,
    get_sandbox: Sequence<crate::config::GetSandboxEntry>,
    list_sandboxes: Sequence<crate::config::ListSandboxesEntry>,
    stop_sandbox: Sequence<crate::config::SimpleEntry>,
    delete_sandbox: Sequence<crate::config::DeleteSandboxEntry>,
}

impl FakeDriver {
    pub fn new(config: Config) -> Self {
        let Config {
            validate_sandbox_create,
            create_sandbox,
            get_sandbox,
            list_sandboxes,
            stop_sandbox,
            delete_sandbox,
            watch_sandboxes,
        } = config;

        Self {
            state: Arc::new(Mutex::new(DriverState {
                validate_sandbox_create: Sequence::new(
                    "validate_sandbox_create",
                    validate_sandbox_create,
                ),
                create_sandbox: Sequence::new("create_sandbox", create_sandbox),
                get_sandbox: Sequence::new("get_sandbox", get_sandbox),
                list_sandboxes: Sequence::new("list_sandboxes", list_sandboxes),
                stop_sandbox: Sequence::new("stop_sandbox", stop_sandbox),
                delete_sandbox: Sequence::new("delete_sandbox", delete_sandbox),
            })),
            watch_config: watch_sandboxes,
        }
    }
}

fn sandbox_to_proto(cfg: &SandboxConfig) -> DriverSandbox {
    DriverSandbox {
        id: cfg.id.clone(),
        name: cfg.name.clone(),
        namespace: cfg.namespace.clone(),
        status: cfg.status.as_ref().map(|s| DriverSandboxStatus {
            sandbox_name: s.sandbox_name.clone(),
            instance_id: s.instance_id.clone(),
            agent_fd: s.agent_fd.clone(),
            sandbox_fd: s.sandbox_fd.clone(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[tonic::async_trait]
impl ComputeDriver for FakeDriver {
    async fn get_capabilities(
        &self,
        _request: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<GetCapabilitiesResponse>, Status> {
        Ok(Response::new(GetCapabilitiesResponse {
            driver_name: "fake-driver-rs".to_string(),
            driver_version: env!("CARGO_PKG_VERSION").to_string(),
            default_image: "ghcr.io/nvidia/openshell-sandbox:latest".to_string(),
        }))
    }

    async fn validate_sandbox_create(
        &self,
        request: Request<ValidateSandboxCreateRequest>,
    ) -> Result<Response<ValidateSandboxCreateResponse>, Status> {
        let sandbox_id = request
            .into_inner()
            .sandbox
            .as_ref()
            .map_or_else(String::new, |s| s.id.clone());
        let mut state = self.state.lock().expect("state lock poisoned");
        let entry = state.validate_sandbox_create.next().ok_or_else(|| {
            Status::unimplemented("no validate_sandbox_create entries configured")
        })?;
        tracing::info!(
            sandbox_id,
            rpc = "validate_sandbox_create",
            "handling request"
        );
        if let Some(err) = &entry.error {
            return Err(err.to_status());
        }
        Ok(Response::new(ValidateSandboxCreateResponse {}))
    }

    async fn create_sandbox(
        &self,
        request: Request<CreateSandboxRequest>,
    ) -> Result<Response<CreateSandboxResponse>, Status> {
        let sandbox_id = request
            .into_inner()
            .sandbox
            .as_ref()
            .map_or_else(String::new, |s| s.id.clone());
        let mut state = self.state.lock().expect("state lock poisoned");
        let entry = state
            .create_sandbox
            .next()
            .ok_or_else(|| Status::unimplemented("no create_sandbox entries configured"))?;
        tracing::info!(sandbox_id, rpc = "create_sandbox", "handling request");
        if let Some(err) = &entry.error {
            return Err(err.to_status());
        }
        Ok(Response::new(CreateSandboxResponse {}))
    }

    async fn get_sandbox(
        &self,
        request: Request<GetSandboxRequest>,
    ) -> Result<Response<GetSandboxResponse>, Status> {
        let req = request.into_inner();
        tracing::info!(
            sandbox_id = req.sandbox_id,
            sandbox_name = req.sandbox_name,
            rpc = "get_sandbox",
            "handling request"
        );
        let mut state = self.state.lock().expect("state lock poisoned");
        let entry = state
            .get_sandbox
            .next()
            .ok_or_else(|| Status::unimplemented("no get_sandbox entries configured"))?;
        if let Some(err) = &entry.error {
            return Err(err.to_status());
        }
        let sandbox = entry
            .sandbox
            .as_ref()
            .map(sandbox_to_proto)
            .ok_or_else(|| Status::not_found("no sandbox in scripted entry"))?;
        Ok(Response::new(GetSandboxResponse {
            sandbox: Some(sandbox),
        }))
    }

    async fn list_sandboxes(
        &self,
        _request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        tracing::info!(rpc = "list_sandboxes", "handling request");
        let mut state = self.state.lock().expect("state lock poisoned");
        let entry = state
            .list_sandboxes
            .next()
            .ok_or_else(|| Status::unimplemented("no list_sandboxes entries configured"))?;
        if let Some(err) = &entry.error {
            return Err(err.to_status());
        }
        let sandboxes = entry.sandboxes.iter().map(sandbox_to_proto).collect();
        Ok(Response::new(ListSandboxesResponse { sandboxes }))
    }

    async fn stop_sandbox(
        &self,
        request: Request<StopSandboxRequest>,
    ) -> Result<Response<StopSandboxResponse>, Status> {
        let req = request.into_inner();
        tracing::info!(
            sandbox_id = req.sandbox_id,
            sandbox_name = req.sandbox_name,
            rpc = "stop_sandbox",
            "handling request"
        );
        let mut state = self.state.lock().expect("state lock poisoned");
        let entry = state
            .stop_sandbox
            .next()
            .ok_or_else(|| Status::unimplemented("no stop_sandbox entries configured"))?;
        if let Some(err) = &entry.error {
            return Err(err.to_status());
        }
        Ok(Response::new(StopSandboxResponse {}))
    }

    async fn delete_sandbox(
        &self,
        request: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        let req = request.into_inner();
        tracing::info!(
            sandbox_id = req.sandbox_id,
            sandbox_name = req.sandbox_name,
            rpc = "delete_sandbox",
            "handling request"
        );
        let mut state = self.state.lock().expect("state lock poisoned");
        let entry = state
            .delete_sandbox
            .next()
            .ok_or_else(|| Status::unimplemented("no delete_sandbox entries configured"))?;
        if let Some(err) = &entry.error {
            return Err(err.to_status());
        }
        Ok(Response::new(DeleteSandboxResponse {
            deleted: entry.deleted,
        }))
    }

    type WatchSandboxesStream =
        Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, Status>> + Send + 'static>>;

    async fn watch_sandboxes(
        &self,
        _request: Request<WatchSandboxesRequest>,
    ) -> Result<Response<Self::WatchSandboxesStream>, Status> {
        tracing::info!(rpc = "watch_sandboxes", "starting stream");

        // Convert config events to proto eagerly so config errors are caught before streaming.
        let mut proto_events: Vec<WatchSandboxesEvent> = Vec::new();
        for e in &self.watch_config.events {
            let event = if let Some(sandbox) = &e.sandbox {
                WatchSandboxesEvent {
                    payload: Some(Payload::Sandbox(WatchSandboxesSandboxEvent {
                        sandbox: Some(sandbox_to_proto(sandbox)),
                    })),
                }
            } else if let Some(deleted) = &e.deleted {
                WatchSandboxesEvent {
                    payload: Some(Payload::Deleted(WatchSandboxesDeletedEvent {
                        sandbox_id: deleted.sandbox_id.clone(),
                    })),
                }
            } else {
                return Err(Status::internal(
                    "watch_sandboxes event has neither `sandbox` nor `deleted` payload",
                ));
            };
            proto_events.push(event);
        }

        let delay = Duration::from_millis(self.watch_config.delay_ms);
        let (tx, rx) = tokio::sync::mpsc::channel(16);

        tokio::spawn(async move {
            for event in proto_events {
                tokio::time::sleep(delay).await;
                if tx.send(Ok(event)).await.is_err() {
                    return; // receiver dropped; gateway disconnected
                }
            }
            tracing::info!(rpc = "watch_sandboxes", "stream exhausted; closing");
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}
