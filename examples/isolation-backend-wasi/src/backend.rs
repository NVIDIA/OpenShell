// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Partial loopback service. Reserving a boundary never executes guest code.
use std::{pin::Pin, sync::Mutex};

use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

use crate::protocol::{BACKEND, boundary::*, control::*, metadata};

/// Trusted provisioning, independent of request claims. Paths never arrive over RPC.
pub struct Provisioned {
    pub sandbox_id: String,
    pub session_id: String,
    pub generation_id: String,
    token: String,
    pub descriptor: Vec<u8>,
}

impl Provisioned {
    pub fn new(
        sandbox_id: String,
        session_id: String,
        generation_id: String,
        token: String,
        module: &[u8],
    ) -> Result<Self> {
        ensure!(
            !sandbox_id.is_empty() && !session_id.is_empty() && !generation_id.is_empty(),
            "launch identities must not be empty"
        );
        ensure!(
            token.len() >= 32 && !token.chars().any(char::is_whitespace),
            "credential must contain at least 32 non-whitespace characters"
        );
        let digest = format!("{:x}", Sha256::digest(module));
        Ok(Self {
            sandbox_id,
            session_id,
            generation_id,
            token,
            descriptor: serde_json::to_vec(&serde_json::json!({"module_sha256": digest}))?,
        })
    }
}

pub struct Backend {
    provisioned: Provisioned,
    boundary_id: Mutex<Option<String>>,
}

impl Backend {
    pub fn new(provisioned: Provisioned) -> Self {
        Self {
            provisioned,
            boundary_id: Mutex::new(None),
        }
    }

    fn authenticate<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let mut values = request.metadata().get_all("authorization").iter();
        let valid = values.next().is_some_and(|value| {
            bool::from(
                value
                    .as_bytes()
                    .ct_eq(format!("Bearer {}", self.provisioned.token).as_bytes()),
            )
        });
        if !valid || values.next().is_some() {
            return Err(Status::unauthenticated("invalid prototype credential"));
        }
        Ok(())
    }

    async fn route(&self, mut request: Request<Streaming<BoundaryChunk>>) -> Result<(), Status> {
        self.authenticate(&request)?;
        let first = request.get_mut().message().await?;
        let Some(BoundaryChunk {
            payload: Some(boundary_chunk::Payload::BoundaryId(id)),
        }) = first
        else {
            return Err(Status::invalid_argument(
                "first frame must identify a boundary",
            ));
        };
        if id.is_empty() {
            return Err(Status::invalid_argument(
                "first frame must identify a boundary",
            ));
        }
        let expected = self
            .boundary_id
            .lock()
            .map_err(|_| Status::internal("binding lock poisoned"))?;
        if !expected
            .as_ref()
            .is_some_and(|expected| bool::from(id.as_bytes().ct_eq(expected.as_bytes())))
        {
            return Err(Status::permission_denied("unknown boundary handle"));
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl sandbox_backend_server::SandboxBackend for Backend {
    async fn describe(
        &self,
        request: Request<DescribeSandboxBackendRequest>,
    ) -> Result<Response<DescribeSandboxBackendResponse>, Status> {
        let local = metadata();
        let remote = request
            .into_inner()
            .supervisor
            .ok_or_else(|| Status::failed_precondition("missing peer metadata"))?;
        if remote.protocol_version.as_ref().map(|v| v.major) != Some(1)
            || !local
                .required_capabilities
                .iter()
                .all(|c| remote.supported_capabilities.contains(c))
            || !remote
                .required_capabilities
                .iter()
                .all(|c| local.supported_capabilities.contains(c))
        {
            return Err(Status::failed_precondition(
                "partial WASI prototype does not implement the base sandbox contract",
            ));
        }
        Ok(Response::new(DescribeSandboxBackendResponse {
            backend: Some(local),
        }))
    }

    async fn open_boundary(
        &self,
        request: Request<OpenBoundaryRequest>,
    ) -> Result<Response<OpenBoundaryResponse>, Status> {
        self.authenticate(&request)?;
        let launch = request.into_inner();
        let p = &self.provisioned;
        if launch.sandbox_id != p.sandbox_id
            || launch.session_id != p.session_id
            || launch.generation_id != p.generation_id
            || launch.backend_name != BACKEND
        {
            return Err(Status::permission_denied("launch identity mismatch"));
        }
        if launch.driver_descriptor != p.descriptor {
            return Err(Status::permission_denied("provisioned module mismatch"));
        }
        let mut id = self
            .boundary_id
            .lock()
            .map_err(|_| Status::internal("binding lock poisoned"))?;
        Ok(Response::new(OpenBoundaryResponse {
            boundary_id: id
                .get_or_insert_with(|| uuid::Uuid::new_v4().to_string())
                .clone(),
            outcome: open_boundary_response::LaunchOutcome::Fresh.into(),
        }))
    }

    async fn suspend_boundary(
        &self,
        request: Request<SuspendBoundaryRequest>,
    ) -> Result<Response<SuspendBoundaryResponse>, Status> {
        self.authenticate(&request)?;
        Err(Status::unimplemented(
            "WASI memory snapshots are not implemented",
        ))
    }

    async fn resume_boundary(
        &self,
        request: Request<ResumeBoundaryRequest>,
    ) -> Result<Response<OpenBoundaryResponse>, Status> {
        self.authenticate(&request)?;
        Err(Status::unimplemented(
            "WASI memory restoration is not implemented",
        ))
    }
}

type Chunks = Pin<Box<dyn Stream<Item = Result<BoundaryChunk, Status>> + Send>>;

#[tonic::async_trait]
impl sandbox_boundary_server::SandboxBoundary for Backend {
    type ExchangeStream = Chunks;
    type MediateStream = Chunks;

    async fn exchange(
        &self,
        request: Request<Streaming<BoundaryChunk>>,
    ) -> Result<Response<Chunks>, Status> {
        self.route(request).await?;
        Err(Status::unimplemented(
            "attach/confirm/start are not implemented; no guest was run",
        ))
    }

    async fn mediate(
        &self,
        request: Request<Streaming<BoundaryChunk>>,
    ) -> Result<Response<Chunks>, Status> {
        self.route(request).await?;
        Err(Status::unimplemented(
            "TCP/DNS mediation is not implemented",
        ))
    }
}
