// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Fixed baseline server source fixture from 6546691d5e493343c7877573252e835d28bf9e23.
//! It deliberately implements only the original generated `ComputeDriver` methods,
//! including its concrete streaming associated type, with no image-update method
//! or in-process extension trait. New optional RPCs must not break this source.

use openshell_core::proto::compute::v1::{
    AuthenticateSandboxRequest, AuthenticateSandboxResponse, CreateSandboxRequest,
    CreateSandboxResponse, DeleteSandboxRequest, DeleteSandboxResponse, DeleteWorkspaceRequest,
    DeleteWorkspaceResponse, EnsureWorkspaceRequest, EnsureWorkspaceResponse,
    GetCapabilitiesRequest, GetCapabilitiesResponse, GetSandboxRequest, GetSandboxResponse,
    ListSandboxesRequest, ListSandboxesResponse, StartSandboxRequest, StartSandboxResponse,
    StopSandboxRequest, StopSandboxResponse, UpdateSandboxImageRequest, UpdateSandboxImageResponse,
    ValidateSandboxCreateRequest, ValidateSandboxCreateResponse, WatchSandboxesEvent,
    WatchSandboxesRequest,
    compute_driver_client::ComputeDriverClient,
    compute_driver_image_updates_client::ComputeDriverImageUpdatesClient,
    compute_driver_image_updates_server::{
        ComputeDriverImageUpdates, ComputeDriverImageUpdatesServer,
    },
    compute_driver_server::{ComputeDriver, ComputeDriverServer},
};
use prost::Message;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

#[derive(Debug)]
struct BaselineDriver;

#[tonic::async_trait]
impl ComputeDriver for BaselineDriver {
    async fn get_capabilities(
        &self,
        _request: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<GetCapabilitiesResponse>, Status> {
        Ok(Response::new(GetCapabilitiesResponse {
            driver_name: "baseline-source-fixture".into(),
            ..Default::default()
        }))
    }

    async fn authenticate_sandbox(
        &self,
        _request: Request<AuthenticateSandboxRequest>,
    ) -> Result<Response<AuthenticateSandboxResponse>, Status> {
        Err(Status::unimplemented("fixture"))
    }

    async fn validate_sandbox_create(
        &self,
        _request: Request<ValidateSandboxCreateRequest>,
    ) -> Result<Response<ValidateSandboxCreateResponse>, Status> {
        Err(Status::unimplemented("fixture"))
    }

    async fn get_sandbox(
        &self,
        _request: Request<GetSandboxRequest>,
    ) -> Result<Response<GetSandboxResponse>, Status> {
        Err(Status::unimplemented("fixture"))
    }

    async fn list_sandboxes(
        &self,
        _request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        Ok(Response::new(ListSandboxesResponse { sandboxes: vec![] }))
    }

    async fn create_sandbox(
        &self,
        _request: Request<CreateSandboxRequest>,
    ) -> Result<Response<CreateSandboxResponse>, Status> {
        Err(Status::unimplemented("fixture"))
    }

    async fn stop_sandbox(
        &self,
        _request: Request<StopSandboxRequest>,
    ) -> Result<Response<StopSandboxResponse>, Status> {
        Err(Status::unimplemented("fixture"))
    }

    async fn start_sandbox(
        &self,
        _request: Request<StartSandboxRequest>,
    ) -> Result<Response<StartSandboxResponse>, Status> {
        Err(Status::unimplemented("fixture"))
    }

    async fn delete_sandbox(
        &self,
        _request: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        Err(Status::unimplemented("fixture"))
    }

    type WatchSandboxesStream = tokio_stream::Empty<Result<WatchSandboxesEvent, Status>>;

    async fn watch_sandboxes(
        &self,
        _request: Request<WatchSandboxesRequest>,
    ) -> Result<Response<Self::WatchSandboxesStream>, Status> {
        Ok(Response::new(tokio_stream::empty()))
    }

    async fn ensure_workspace(
        &self,
        _request: Request<EnsureWorkspaceRequest>,
    ) -> Result<Response<EnsureWorkspaceResponse>, Status> {
        Err(Status::unimplemented("fixture"))
    }

    async fn delete_workspace(
        &self,
        _request: Request<DeleteWorkspaceRequest>,
    ) -> Result<Response<DeleteWorkspaceResponse>, Status> {
        Err(Status::unimplemented("fixture"))
    }
}

#[derive(Debug, Clone, Default)]
struct ImageUpdates {
    calls: Arc<Mutex<Vec<UpdateSandboxImageRequest>>>,
}

#[tonic::async_trait]
impl ComputeDriverImageUpdates for ImageUpdates {
    async fn update_sandbox_image(
        &self,
        request: Request<UpdateSandboxImageRequest>,
    ) -> Result<Response<UpdateSandboxImageResponse>, Status> {
        self.calls.lock().unwrap().push(request.into_inner());
        Ok(Response::new(UpdateSandboxImageResponse {}))
    }
}

struct TcpIncoming(TcpListener);

impl Stream for TcpIncoming {
    type Item = std::io::Result<TcpStream>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_accept(cx).map(|result| {
            Some(result.map(|(stream, _)| {
                openshell_core::net::set_tcp_nodelay_best_effort(&stream);
                stream
            }))
        })
    }
}

async fn roundtrip(serve_image_updates: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let extension = ImageUpdates::default();
    let optional_service =
        serve_image_updates.then(|| ComputeDriverImageUpdatesServer::new(extension.clone()));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(ComputeDriverServer::new(BaselineDriver))
            .add_optional_service(optional_service)
            .serve_with_incoming_shutdown(TcpIncoming(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut baseline = ComputeDriverClient::new(channel.clone());
    assert_eq!(
        baseline
            .get_capabilities(GetCapabilitiesRequest::default())
            .await
            .unwrap()
            .into_inner()
            .driver_name,
        "baseline-source-fixture"
    );
    assert!(
        baseline
            .list_sandboxes(ListSandboxesRequest {})
            .await
            .unwrap()
            .into_inner()
            .sandboxes
            .is_empty()
    );
    assert!(
        baseline
            .watch_sandboxes(WatchSandboxesRequest {})
            .await
            .unwrap()
            .into_inner()
            .message()
            .await
            .unwrap()
            .is_none()
    );

    let request = UpdateSandboxImageRequest {
        sandbox_id: "sandbox-id".into(),
        image: "example/workload:v2".into(),
        ..Default::default()
    };
    let result = ComputeDriverImageUpdatesClient::new(channel)
        .update_sandbox_image(request.clone())
        .await;
    if serve_image_updates {
        result.unwrap();
        assert_eq!(*extension.calls.lock().unwrap(), vec![request]);
    } else {
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unimplemented);
        assert!(extension.calls.lock().unwrap().is_empty());
    }
    // Absence of the optional service must not impair the original service.
    baseline
        .list_sandboxes(ListSandboxesRequest {})
        .await
        .unwrap();
    drop(baseline);
    shutdown_tx.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn baseline_generated_server_source_and_transport_remain_compatible() {
    roundtrip(false).await;
}

#[tokio::test]
async fn optional_image_service_shares_the_baseline_channel() {
    roundtrip(true).await;
}

#[test]
fn baseline_compute_service_methods_are_frozen() {
    let descriptor =
        prost_types::FileDescriptorSet::decode(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
    let compute = descriptor
        .file
        .iter()
        .find(|file| file.package.as_deref() == Some("openshell.compute.v1"))
        .unwrap();
    let baseline = compute
        .service
        .iter()
        .find(|service| service.name.as_deref() == Some("ComputeDriver"))
        .unwrap();
    assert_eq!(
        baseline
            .method
            .iter()
            .map(|method| method.name.as_deref().unwrap())
            .collect::<Vec<_>>(),
        vec![
            "GetCapabilities",
            "AuthenticateSandbox",
            "ValidateSandboxCreate",
            "GetSandbox",
            "ListSandboxes",
            "CreateSandbox",
            "StopSandbox",
            "StartSandbox",
            "DeleteSandbox",
            "WatchSandboxes",
            "EnsureWorkspace",
            "DeleteWorkspace",
        ]
    );
    let image_updates = compute
        .service
        .iter()
        .find(|service| service.name.as_deref() == Some("ComputeDriverImageUpdates"))
        .unwrap();
    assert_eq!(image_updates.method.len(), 1);
    assert_eq!(
        image_updates.method[0].name.as_deref(),
        Some("UpdateSandboxImage")
    );
}
