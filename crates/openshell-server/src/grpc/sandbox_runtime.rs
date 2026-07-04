// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway bridge for SandboxRuntime CRD management.
//!
//! Implements the `SandboxRuntimeManager` gRPC service, bridging gateway
//! API calls to Kubernetes CRD operations on `SandboxRuntime` custom
//! resources. This allows the gateway CLI/API to manage operator-controlled
//! workloads without direct K8s access from clients.

use kube::api::{Api, ListParams, PostParams};
use kube::Client;
use tonic::{Request, Response, Status};

use openshell_core::proto::runtime::v1::{
    sandbox_runtime_manager_server::SandboxRuntimeManager, CreateSandboxRuntimeRequest,
    DeleteSandboxRuntimeRequest, DeleteSandboxRuntimeResponse, GetSandboxRuntimeRequest,
    ListSandboxRuntimesRequest, ListSandboxRuntimesResponse, SandboxRuntimeMessage,
    SandboxRuntimeResponse,
};
use openshell_operator::crd::{SandboxRuntime, SandboxRuntimeSpec, ServicePort, TargetRef};

/// Bridge service that proxies gRPC calls to Kubernetes CRD operations.
#[derive(Clone)]
pub struct SandboxRuntimeManagerService {
    client: Client,
}

impl SandboxRuntimeManagerService {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    fn api(&self, namespace: &str) -> Api<SandboxRuntime> {
        Api::namespaced(self.client.clone(), namespace)
    }
}

#[tonic::async_trait]
impl SandboxRuntimeManager for SandboxRuntimeManagerService {
    async fn create_sandbox_runtime(
        &self,
        request: Request<CreateSandboxRuntimeRequest>,
    ) -> Result<Response<SandboxRuntimeResponse>, Status> {
        let req = request.into_inner();
        let api = self.api(&req.namespace);

        let runtime = SandboxRuntime::new(
            &req.name,
            SandboxRuntimeSpec {
                runtime_type: if req.runtime_type.is_empty() {
                    "agent".to_string()
                } else {
                    req.runtime_type
                },
                target_ref: TargetRef {
                    api_version: "apps/v1".to_string(),
                    kind: if req.target_kind.is_empty() {
                        "Deployment".to_string()
                    } else {
                        req.target_kind
                    },
                    name: req.name.clone(),
                },
                image: req.image,
                replicas: if req.replicas == 0 { 1 } else { req.replicas },
                env: Vec::new(),
                resources: None,
                service_ports: vec![ServicePort {
                    name: "http".to_string(),
                    port: 8080,
                    target_port: 8000,
                    protocol: "TCP".to_string(),
                }],
                description: req.description,
            },
        );

        let created = api
            .create(&PostParams::default(), &runtime)
            .await
            .map_err(|e| match &e {
                kube::Error::Api(api_err) if api_err.code == 409 => {
                    Status::already_exists(format!(
                        "SandboxRuntime '{}' already exists",
                        req.name
                    ))
                }
                _ => Status::internal(e.to_string()),
            })?;

        Ok(Response::new(SandboxRuntimeResponse {
            runtime: Some(runtime_to_message(&created)),
        }))
    }

    async fn get_sandbox_runtime(
        &self,
        request: Request<GetSandboxRuntimeRequest>,
    ) -> Result<Response<SandboxRuntimeResponse>, Status> {
        let req = request.into_inner();
        let api = self.api(&req.namespace);

        let runtime = api.get(&req.name).await.map_err(|e| match &e {
            kube::Error::Api(api_err) if api_err.code == 404 => {
                Status::not_found(format!("SandboxRuntime '{}' not found", req.name))
            }
            _ => Status::internal(e.to_string()),
        })?;

        Ok(Response::new(SandboxRuntimeResponse {
            runtime: Some(runtime_to_message(&runtime)),
        }))
    }

    async fn list_sandbox_runtimes(
        &self,
        request: Request<ListSandboxRuntimesRequest>,
    ) -> Result<Response<ListSandboxRuntimesResponse>, Status> {
        let req = request.into_inner();
        let api = self.api(&req.namespace);

        let list = api
            .list(&ListParams::default())
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let runtimes = list
            .items
            .into_iter()
            .map(|r| runtime_to_message(&r))
            .collect();

        Ok(Response::new(ListSandboxRuntimesResponse { runtimes }))
    }

    async fn delete_sandbox_runtime(
        &self,
        request: Request<DeleteSandboxRuntimeRequest>,
    ) -> Result<Response<DeleteSandboxRuntimeResponse>, Status> {
        let req = request.into_inner();
        let api = self.api(&req.namespace);

        match api.delete(&req.name, &Default::default()).await {
            Ok(_) => Ok(Response::new(DeleteSandboxRuntimeResponse { deleted: true })),
            Err(kube::Error::Api(ref api_err)) if api_err.code == 404 => {
                Ok(Response::new(DeleteSandboxRuntimeResponse { deleted: false }))
            }
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }
}

fn runtime_to_message(runtime: &SandboxRuntime) -> SandboxRuntimeMessage {
    let status = runtime.status.as_ref();
    SandboxRuntimeMessage {
        name: runtime.metadata.name.clone().unwrap_or_default(),
        namespace: runtime.metadata.namespace.clone().unwrap_or_default(),
        runtime_type: runtime.spec.runtime_type.clone(),
        image: runtime.spec.image.clone(),
        replicas: runtime.spec.replicas,
        target_kind: runtime.spec.target_ref.kind.clone(),
        phase: status.map_or_else(String::new, |s| s.phase.clone()),
        message: status.map_or_else(String::new, |s| s.message.clone()),
        description: runtime.spec.description.clone(),
    }
}
