// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! One SSH transport gets one grant. The issuing client retains ownership
//! until the proxy opens `ForwardTcp`, disconnects, or the SSH command exits.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
use unix as ipc;
#[cfg(windows)]
use windows as ipc;

use crate::forward::{build_proxy_command, validate_ssh_session_response};
use crate::proto::{
    CreateSshSessionRequest, CreateSshSessionResponse, RevokeSshSessionRequest,
    open_shell_client::OpenShellClient, workspace_selector,
};
use miette::{IntoDiagnostic, Result};
use prost::Message;
use std::{future::Future, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::oneshot;
use tonic::{
    service::{Interceptor, interceptor::InterceptedService},
    transport::Channel,
};
use uuid::Uuid;

type Client<I> = OpenShellClient<InterceptedService<Channel, I>>;

#[derive(Clone, Debug)]
pub struct SshTarget {
    pub endpoint: String,
    pub profile: String,
    pub name: String,
    pub workspace: String,
    pub id: String,
    pub replica: Option<String>,
}

#[derive(Message)]
pub struct RelayGrant {
    #[prost(message, required, tag = "1")]
    pub session: CreateSshSessionResponse,
    #[prost(string, tag = "2")]
    pub endpoint: String,
    #[prost(string, tag = "3")]
    pub profile: String,
    #[prost(string, optional, tag = "4")]
    pub replica: Option<String>,
}

pub struct PreparedProxy {
    command: String,
    cancel: oneshot::Sender<()>,
    cleanup: tokio::task::JoinHandle<()>,
}

impl SshTarget {
    pub async fn prepare<I: Interceptor + Clone + Send + Sync + 'static>(
        &self,
        mut client: Client<I>,
        registration_timeout: Option<Duration>,
    ) -> Result<PreparedProxy> {
        let id = Uuid::new_v4();
        let listener = ipc::Listener::bind(id).into_diagnostic()?;
        let handle = format!("{}-{id}", std::process::id());
        let command = build_proxy_command(&handle, &self.name, &self.workspace)?;
        let request = CreateSshSessionRequest {
            sandbox: self.name.clone(),
            workspace_scope: Some(workspace_selector(self.workspace.clone())),
        };
        let deadline = registration_timeout.map(|timeout| tokio::time::Instant::now() + timeout);
        let session = loop {
            match client.create_ssh_session(request.clone()).await {
                Ok(response) => break response.into_inner(),
                Err(status)
                    if status.code() == tonic::Code::FailedPrecondition
                        && deadline.is_some_and(|end| tokio::time::Instant::now() < end) =>
                {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(status) => return Err(status).into_diagnostic(),
            }
        };
        let validation = validate_ssh_session_response(&session)
            .map_err(|err| miette::miette!("gateway returned invalid SSH session response: {err}"))
            .and_then(|()| {
                if session.sandbox_id == self.id {
                    Ok(())
                } else {
                    Err(miette::miette!(
                        "sandbox was replaced before opening the SSH relay"
                    ))
                }
            });
        let token = session.token.clone();
        let revoke = async move {
            let request = RevokeSshSessionRequest {
                token,
                allow_missing: true,
            };
            if !matches!(
                tokio::time::timeout(Duration::from_secs(2), client.revoke_ssh_session(request))
                    .await,
                Ok(Ok(_))
            ) {
                eprintln!("Warning: could not revoke the SSH session token");
            }
        };
        if let Err(error) = validation {
            revoke.await;
            return Err(error);
        }
        let payload = RelayGrant {
            session,
            endpoint: self.endpoint.clone(),
            profile: self.profile.clone(),
            replica: self.replica.clone(),
        }
        .encode_to_vec();
        let (cancel, cancelled) = oneshot::channel();
        let cleanup = tokio::spawn(async move {
            let serve = async {
                let mut peer = listener.accept().await?;
                peer.write_u32(u32::try_from(payload.len()).map_err(std::io::Error::other)?)
                    .await?;
                peer.write_all(&payload).await?;
                peer.read_u8().await?;
                Ok::<_, std::io::Error>(peer)
            };
            // Keep the peer until the issuing client has attempted revocation.
            let peer = tokio::select! {
                result = serve => result.ok(),
                _ = cancelled => None,
            };
            revoke.await;
            if let Some(mut peer) = peer {
                let _ = peer.write_u8(1).await;
            }
        });
        Ok(PreparedProxy {
            command,
            cancel,
            cleanup,
        })
    }
}

impl PreparedProxy {
    pub fn command(&self) -> &str {
        &self.command
    }

    pub async fn run<T>(self, operation: impl Future<Output = Result<T>>) -> Result<T> {
        let result = operation.await;
        drop(self.cancel);
        self.cleanup.await.into_diagnostic()?;
        result
    }
}

pub async fn receive(handle: &str) -> Result<(RelayGrant, impl AsyncRead + AsyncWrite + Unpin)> {
    let (pid, id) = handle
        .split_once('-')
        .ok_or_else(|| miette::miette!("invalid SSH handoff"))?;
    let pid = pid.parse::<u32>().into_diagnostic()?;
    let id = Uuid::parse_str(id).into_diagnostic()?;
    #[cfg(unix)]
    let mut peer = ipc::connect(id, pid).await.into_diagnostic()?;
    #[cfg(windows)]
    let mut peer = ipc::connect(id, pid).into_diagnostic()?;
    let size = peer.read_u32().await.into_diagnostic()? as usize;
    // The session response comes from a unary gRPC call; allow its default
    // message limit plus room for the endpoint, profile and routing hint.
    if size > 5 * 1024 * 1024 {
        return Err(miette::miette!("SSH handoff exceeds the size limit"));
    }
    let mut payload = vec![0; size];
    peer.read_exact(&mut payload).await.into_diagnostic()?;
    Ok((
        RelayGrant::decode(&payload[..])
            .map_err(|_| miette::miette!("invalid SSH handoff message"))?,
        peer,
    ))
}
