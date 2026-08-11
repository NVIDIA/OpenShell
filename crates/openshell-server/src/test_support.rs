// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Test fixtures for exercising gateway integration points.

use futures::{Stream, stream};
#[cfg(unix)]
use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriverServer;
use openshell_core::proto::compute::v1::{
    CreateSandboxRequest, CreateSandboxResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    DriverSandbox, GatewayListenerRequirement, GetCapabilitiesRequest, GetCapabilitiesResponse,
    GetGatewayListenerRequirementsRequest, GetGatewayListenerRequirementsResponse,
    GetSandboxRequest, GetSandboxResponse, ListSandboxesRequest, ListSandboxesResponse,
    StartSandboxRequest, StartSandboxResponse, StopSandboxRequest, StopSandboxResponse,
    ValidateSandboxCreateRequest, ValidateSandboxCreateResponse, WatchSandboxesEvent,
    WatchSandboxesRequest, compute_driver_server::ComputeDriver,
    gateway_listener_requirement::Selector,
};
use std::collections::HashMap;
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
#[cfg(unix)]
use std::task::{Context, Poll};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
#[cfg(unix)]
use tokio::task::JoinHandle;
use tonic::{Request, Response, Status};

type WatchStream = Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, Status>> + Send>>;

#[derive(Debug, Clone, PartialEq)]
pub enum FakeComputeDriverCall {
    GetCapabilities,
    GetGatewayListenerRequirements,
    ValidateSandboxCreate {
        sandbox: Option<DriverSandbox>,
    },
    GetSandbox {
        sandbox_id: String,
        sandbox_name: String,
    },
    ListSandboxes,
    CreateSandbox {
        sandbox: Option<DriverSandbox>,
    },
    StopSandbox {
        sandbox_id: String,
        sandbox_name: String,
    },
    StartSandbox {
        sandbox_id: String,
        sandbox_name: String,
    },
    DeleteSandbox {
        sandbox_id: String,
        sandbox_name: String,
    },
    WatchSandboxes,
}

#[derive(Debug, Clone)]
pub struct FakeComputeDriver {
    state: Arc<Mutex<FakeComputeDriverState>>,
}

#[derive(Debug)]
struct FakeComputeDriverState {
    driver_name: String,
    driver_version: String,
    default_image: String,
    gateway_listener_requirements: Vec<GatewayListenerRequirement>,
    gateway_listener_requirements_supported: bool,
    sandboxes: HashMap<String, DriverSandbox>,
    calls: Vec<FakeComputeDriverCall>,
    traceparents: Vec<String>,
}

impl Default for FakeComputeDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeComputeDriver {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(FakeComputeDriverState {
                driver_name: "fake-compute-driver".to_string(),
                driver_version: "test".to_string(),
                default_image: "openshell/sandbox:test".to_string(),
                gateway_listener_requirements: Vec::new(),
                gateway_listener_requirements_supported: true,
                sandboxes: HashMap::new(),
                calls: Vec::new(),
                traceparents: Vec::new(),
            })),
        }
    }

    #[must_use]
    pub fn with_driver_name(self, driver_name: impl Into<String>) -> Self {
        self.with_state(|state| state.driver_name = driver_name.into());
        self
    }

    #[must_use]
    pub fn with_driver_version(self, driver_version: impl Into<String>) -> Self {
        self.with_state(|state| state.driver_version = driver_version.into());
        self
    }

    #[must_use]
    pub fn with_default_image(self, default_image: impl Into<String>) -> Self {
        self.with_state(|state| state.default_image = default_image.into());
        self
    }

    #[must_use]
    pub fn with_gateway_listener_requirement(
        self,
        bind_address: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        self.with_state(|state| {
            state
                .gateway_listener_requirements
                .push(GatewayListenerRequirement {
                    reason: reason.into(),
                    selector: Some(Selector::ExactBindAddress(bind_address.into())),
                });
        });
        self
    }

    #[must_use]
    pub fn without_gateway_listener_requirements_api(self) -> Self {
        self.with_state(|state| state.gateway_listener_requirements_supported = false);
        self
    }

    #[must_use]
    pub fn calls(&self) -> Vec<FakeComputeDriverCall> {
        self.with_state(|state| state.calls.clone())
    }

    #[must_use]
    pub fn traceparents(&self) -> Vec<String> {
        self.with_state(|state| state.traceparents.clone())
    }

    pub fn clear_calls(&self) {
        self.with_state(|state| state.calls.clear());
    }

    #[cfg(unix)]
    pub fn serve_uds(
        &self,
        socket_path: impl AsRef<Path>,
    ) -> io::Result<FakeComputeDriverServerHandle> {
        let socket_path = socket_path.as_ref().to_path_buf();
        let listener = UnixListener::bind(&socket_path)?;
        let driver = self.clone();
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(ComputeDriverServer::new(driver))
                .serve_with_incoming(UnixIncoming { listener })
                .await
        });
        Ok(FakeComputeDriverServerHandle { socket_path, task })
    }

    fn with_state<R>(&self, f: impl FnOnce(&mut FakeComputeDriverState) -> R) -> R {
        let mut state = self
            .state
            .lock()
            .expect("fake compute driver state poisoned");
        f(&mut state)
    }

    fn record_traceparent(&self, metadata: &tonic::metadata::MetadataMap) {
        let traceparent = metadata
            .get("traceparent")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        self.with_state(|state| state.traceparents.extend(traceparent));
    }
}

#[cfg(unix)]
#[derive(Debug)]
pub struct FakeComputeDriverServerHandle {
    socket_path: PathBuf,
    task: JoinHandle<Result<(), tonic::transport::Error>>,
}

#[cfg(unix)]
impl Drop for FakeComputeDriverServerHandle {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[cfg(unix)]
struct UnixIncoming {
    listener: UnixListener,
}

#[cfg(unix)]
impl Stream for UnixIncoming {
    type Item = io::Result<UnixStream>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.get_mut().listener.poll_accept(cx) {
            Poll::Ready(Ok((stream, _addr))) => Poll::Ready(Some(Ok(stream))),
            Poll::Ready(Err(err)) => Poll::Ready(Some(Err(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[tonic::async_trait]
impl ComputeDriver for FakeComputeDriver {
    type WatchSandboxesStream = WatchStream;

    async fn get_capabilities(
        &self,
        request: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<GetCapabilitiesResponse>, Status> {
        self.record_traceparent(request.metadata());
        let response = self.with_state(|state| {
            state.calls.push(FakeComputeDriverCall::GetCapabilities);
            GetCapabilitiesResponse {
                driver_name: state.driver_name.clone(),
                driver_version: state.driver_version.clone(),
                default_image: state.default_image.clone(),
            }
        });
        Ok(Response::new(response))
    }

    async fn get_gateway_listener_requirements(
        &self,
        request: Request<GetGatewayListenerRequirementsRequest>,
    ) -> Result<Response<GetGatewayListenerRequirementsResponse>, Status> {
        self.record_traceparent(request.metadata());
        self.with_state(|state| {
            state
                .calls
                .push(FakeComputeDriverCall::GetGatewayListenerRequirements);
            state
                .gateway_listener_requirements_supported
                .then(|| GetGatewayListenerRequirementsResponse {
                    requirements: state.gateway_listener_requirements.clone(),
                })
                .map(Response::new)
                .ok_or_else(|| Status::unimplemented("listener requirements unsupported"))
        })
    }

    async fn validate_sandbox_create(
        &self,
        request: Request<ValidateSandboxCreateRequest>,
    ) -> Result<Response<ValidateSandboxCreateResponse>, Status> {
        self.record_traceparent(request.metadata());
        let sandbox = request.into_inner().sandbox;
        self.with_state(|state| {
            state
                .calls
                .push(FakeComputeDriverCall::ValidateSandboxCreate { sandbox });
        });
        Ok(Response::new(ValidateSandboxCreateResponse {}))
    }

    async fn get_sandbox(
        &self,
        request: Request<GetSandboxRequest>,
    ) -> Result<Response<GetSandboxResponse>, Status> {
        self.record_traceparent(request.metadata());
        let request = request.into_inner();
        let sandbox = self.with_state(|state| {
            state.calls.push(FakeComputeDriverCall::GetSandbox {
                sandbox_id: request.sandbox_id.clone(),
                sandbox_name: request.sandbox_name.clone(),
            });
            state
                .sandboxes
                .values()
                .find(|sandbox| {
                    (!request.sandbox_id.is_empty() && sandbox.id == request.sandbox_id)
                        || (!request.sandbox_name.is_empty()
                            && sandbox.name == request.sandbox_name)
                })
                .cloned()
        });
        let sandbox = sandbox.ok_or_else(|| Status::not_found("sandbox not found"))?;
        Ok(Response::new(GetSandboxResponse {
            sandbox: Some(sandbox),
        }))
    }

    async fn list_sandboxes(
        &self,
        request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        self.record_traceparent(request.metadata());
        let sandboxes = self.with_state(|state| {
            state.calls.push(FakeComputeDriverCall::ListSandboxes);
            state.sandboxes.values().cloned().collect()
        });
        Ok(Response::new(ListSandboxesResponse { sandboxes }))
    }

    async fn create_sandbox(
        &self,
        request: Request<CreateSandboxRequest>,
    ) -> Result<Response<CreateSandboxResponse>, Status> {
        self.record_traceparent(request.metadata());
        let sandbox = request.into_inner().sandbox;
        self.with_state(|state| {
            if let Some(sandbox) = sandbox.as_ref() {
                state.sandboxes.insert(sandbox.id.clone(), sandbox.clone());
            }
            state
                .calls
                .push(FakeComputeDriverCall::CreateSandbox { sandbox });
        });
        Ok(Response::new(CreateSandboxResponse {}))
    }

    async fn stop_sandbox(
        &self,
        request: Request<StopSandboxRequest>,
    ) -> Result<Response<StopSandboxResponse>, Status> {
        self.record_traceparent(request.metadata());
        let request = request.into_inner();
        self.with_state(|state| {
            state.calls.push(FakeComputeDriverCall::StopSandbox {
                sandbox_id: request.sandbox_id,
                sandbox_name: request.sandbox_name,
            });
        });
        Ok(Response::new(StopSandboxResponse {}))
    }

    async fn start_sandbox(
        &self,
        request: Request<StartSandboxRequest>,
    ) -> Result<Response<StartSandboxResponse>, Status> {
        self.record_traceparent(request.metadata());
        let request = request.into_inner();
        self.with_state(|state| {
            state.calls.push(FakeComputeDriverCall::StartSandbox {
                sandbox_id: request.sandbox_id,
                sandbox_name: request.sandbox_name,
            });
        });
        Ok(Response::new(StartSandboxResponse {}))
    }

    async fn delete_sandbox(
        &self,
        request: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        self.record_traceparent(request.metadata());
        let request = request.into_inner();
        let deleted = self.with_state(|state| {
            state.calls.push(FakeComputeDriverCall::DeleteSandbox {
                sandbox_id: request.sandbox_id.clone(),
                sandbox_name: request.sandbox_name.clone(),
            });
            if request.sandbox_id.is_empty() {
                let Some(id) = state
                    .sandboxes
                    .iter()
                    .find(|(_, sandbox)| sandbox.name == request.sandbox_name)
                    .map(|(id, _)| id.clone())
                else {
                    return false;
                };
                state.sandboxes.remove(&id).is_some()
            } else {
                state.sandboxes.remove(&request.sandbox_id).is_some()
            }
        });
        Ok(Response::new(DeleteSandboxResponse { deleted }))
    }

    async fn watch_sandboxes(
        &self,
        request: Request<WatchSandboxesRequest>,
    ) -> Result<Response<Self::WatchSandboxesStream>, Status> {
        self.record_traceparent(request.metadata());
        self.with_state(|state| state.calls.push(FakeComputeDriverCall::WatchSandboxes));
        Ok(Response::new(Box::pin(stream::empty())))
    }
}
