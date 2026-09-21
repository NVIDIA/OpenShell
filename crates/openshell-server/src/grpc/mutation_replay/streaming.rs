// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Launch admission only: output and interactive input are never replayed.

#[cfg(test)]
mod tests;

use std::sync::Arc;

use openshell_core::proto::{
    ExecSandboxEvent, ExecSandboxInput, ExecSandboxRequest, WorkspaceSelector, exec_sandbox_input,
};
use openshell_core::rpc_error;
use openshell_core::{ObjectId, ObjectWorkspace};
use prost_reflect::DynamicMessage;
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use super::{Mutation, Scope, Success, decode_request_message, named_scope, uncertain};
use crate::ServerState;
use crate::auth::principal::Principal;
use crate::grpc::sandbox;
use crate::persistence::Store;

pub(in crate::grpc) type ExecStream = ReceiverStream<Result<ExecSandboxEvent, Status>>;

/// Private, one-owner transport handoff. The fingerprint includes only Start.
#[derive(Clone)]
pub(in crate::grpc) struct InteractiveInput(
    pub Arc<Mutex<Option<tonic::Streaming<ExecSandboxInput>>>>,
);

pub(in crate::grpc) fn start(input: &ExecSandboxInput) -> Result<&ExecSandboxRequest, Status> {
    match input.payload.as_ref() {
        Some(exec_sandbox_input::Payload::Start(request)) => Ok(request),
        _ => Err(rpc_error::invalid_argument(
            "start",
            "first message must be a start payload",
        )),
    }
}

async fn authorize(
    state: &ServerState,
    principal: &Principal,
    request: &ExecSandboxRequest,
) -> Result<Scope, Status> {
    sandbox::validate_exec_start(request)?;
    let sandbox = sandbox::resolve_and_authorize_sandbox_name(
        state,
        principal,
        &request.sandbox,
        crate::auth::workspace_authz::selected_workspace_name(request.workspace_scope.as_ref())?,
        crate::auth::workspace_authz::MinWorkspaceRole::User,
    )
    .await?;
    let mut scope = named_scope(state, sandbox.object_workspace()).await?;
    scope.target_id = Some(sandbox.object_id().into());
    Ok(scope)
}

fn stream_unavailable(success: Success) -> Status {
    if !matches!(success, Success::StreamTerminal) {
        return super::replay_unavailable();
    }
    rpc_error::failed_precondition(
        "REQUEST_STREAM_UNAVAILABLE",
        "execution terminated, but its output stream is not stored; this request was not launched again",
    )
}

#[tonic::async_trait]
impl Mutation for ExecSandboxRequest {
    type Output = ExecStream;
    const METHOD: &'static str = "ExecSandbox";
    const PROTECTED: bool = true;
    const DEFERRED: bool = true;

    fn request_id(&self) -> &str {
        &self.request_id
    }

    fn target_selector(&self) -> Option<(&str, &WorkspaceSelector)> {
        self.workspace_scope
            .as_ref()
            .map(|workspace| (self.sandbox.as_str(), workspace))
    }

    async fn authorize(&self, state: &ServerState, principal: &Principal) -> Result<Scope, Status> {
        authorize(state, principal, self).await
    }

    async fn execute(
        state: &Arc<ServerState>,
        request: Request<Self>,
    ) -> Result<Response<Self::Output>, Status> {
        sandbox::handle_exec_sandbox(state, request).await
    }

    fn capture(_: &Response<Self::Output>) -> Result<Success, Status> {
        Err(uncertain())
    }

    async fn restore(_: &Store, success: Success) -> Result<Self::Output, Status> {
        Err(stream_unavailable(success))
    }
}

#[tonic::async_trait]
impl Mutation for ExecSandboxInput {
    type Output = ExecStream;
    const METHOD: &'static str = "ExecSandboxInteractive";
    const PROTECTED: bool = true;
    const DEFERRED: bool = true;

    fn request_id(&self) -> &str {
        start(self).map_or("", |request| request.request_id.as_str())
    }

    fn target_selector(&self) -> Option<(&str, &WorkspaceSelector)> {
        start(self).ok().and_then(Mutation::target_selector)
    }

    fn canonical_message(&self) -> Result<DynamicMessage, Status> {
        decode_request_message("ExecSandboxRequest", start(self)?)
    }

    async fn authorize(&self, state: &ServerState, principal: &Principal) -> Result<Scope, Status> {
        authorize(state, principal, start(self)?).await
    }

    async fn execute(
        state: &Arc<ServerState>,
        request: Request<Self>,
    ) -> Result<Response<Self::Output>, Status> {
        sandbox::handle_exec_sandbox_interactive_start(state, request).await
    }

    fn capture(_: &Response<Self::Output>) -> Result<Success, Status> {
        Err(uncertain())
    }

    async fn restore(_: &Store, success: Success) -> Result<Self::Output, Status> {
        Err(stream_unavailable(success))
    }
}
