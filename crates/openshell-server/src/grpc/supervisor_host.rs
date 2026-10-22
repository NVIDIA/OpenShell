// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The private `openshell.supervisor.host.v1` service: the gateway end of the
//! shared supervisor's assignment stream.
//!
//! The router admits only requests bearing a verified supervisor token, so
//! the handler sees a [`Principal::Supervisor`] and hands the stream to the
//! controller the in-process compute driver installed.

use std::pin::Pin;
use std::sync::Arc;

use openshell_core::proto::supervisor_host::v1::supervisor_host_server::SupervisorHost;
use openshell_core::proto::supervisor_host::v1::{HostGatewayMessage, HostMessage};
use tonic::{Request, Response, Status, Streaming};

use crate::ServerState;
use crate::auth::principal::Principal;

/// gRPC path prefix of the supervisor host service.
pub const SUPERVISOR_HOST_PATH_PREFIX: &str = "/openshell.supervisor.host.v1.SupervisorHost/";

#[derive(Clone)]
pub struct SupervisorHostService {
    state: Arc<ServerState>,
}

impl SupervisorHostService {
    #[must_use]
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl SupervisorHost for SupervisorHostService {
    type AttachStream = Pin<
        Box<dyn tokio_stream::Stream<Item = Result<HostGatewayMessage, Status>> + Send + 'static>,
    >;

    async fn attach(
        &self,
        request: Request<Streaming<HostMessage>>,
    ) -> Result<Response<Self::AttachStream>, Status> {
        let identity = match request.extensions().get::<Principal>() {
            Some(Principal::Supervisor(supervisor)) => supervisor.identity.clone(),
            _ => {
                return Err(Status::permission_denied(
                    "the supervisor assignment stream requires a supervisor token",
                ));
            }
        };
        let controller = self
            .state
            .compute
            .supervisor_host()
            .ok_or_else(|| {
                Status::failed_precondition("this gateway does not host a shared supervisor")
            })?
            .clone();
        let outbound = controller.attach(identity, request.into_inner()).await?;
        Ok(Response::new(Box::pin(outbound)))
    }
}
