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
    pub gateway_name: String,
    pub name: String,
    pub workspace: String,
    pub id: String,
    pub replica: Option<String>,
    pub cleanup: SshCleanup,
}

#[derive(Message)]
pub struct RelayGrant {
    #[prost(message, required, tag = "1")]
    pub session: CreateSshSessionResponse,
    #[prost(string, tag = "2")]
    pub endpoint: String,
    #[prost(string, tag = "3")]
    pub gateway_name: String,
    #[prost(string, optional, tag = "4")]
    pub replica: Option<String>,
}

pub struct PreparedProxy {
    command: String,
    cancel: oneshot::Sender<()>,
    cleanup: tokio::task::JoinHandle<Option<Duration>>,
}

/// Work that must finish before an SSH command or TUI releases its runtime.
#[derive(Clone, Debug, Default)]
pub struct SshCleanup(tokio_util::task::TaskTracker);

impl SshCleanup {
    pub fn spawn<T: Send + 'static>(
        &self,
        future: impl Future<Output = T> + Send + 'static,
    ) -> tokio::task::JoinHandle<T> {
        self.0.spawn(future)
    }

    pub async fn drain(&self) {
        self.0.close();
        self.0.wait().await;
    }
}

impl SshTarget {
    pub fn new(endpoint: &str, gateway_name: &str, name: &str, workspace: &str, id: &str) -> Self {
        Self {
            endpoint: endpoint.into(),
            gateway_name: gateway_name.into(),
            name: name.into(),
            workspace: workspace.into(),
            id: id.into(),
            replica: None,
            cleanup: SshCleanup::default(),
        }
    }

    pub async fn prepare<I: Interceptor + Clone + Send + Sync + 'static>(
        &self,
        mut client: Client<I>,
        registration_timeout: Option<Duration>,
    ) -> Result<PreparedProxy> {
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
        let revoke = revoke_grant(client, session.token.clone());
        let setup = || {
            validate_ssh_session_response(&session).map_err(|err| {
                miette::miette!("gateway returned invalid SSH session response: {err}")
            })?;
            if session.sandbox_id != self.id {
                return Err(miette::miette!(
                    "sandbox was replaced before opening the SSH relay"
                ));
            }
            let id = Uuid::new_v4();
            let listener = ipc::Listener::bind(id).into_diagnostic()?;
            let handle = format!("{}-{id}", std::process::id());
            let command = build_proxy_command(&handle, &self.name, &self.workspace)?;
            Ok((listener, command))
        };
        let (listener, command) = match setup() {
            Ok(parts) => parts,
            Err(error) => {
                self.cleanup.spawn(revoke).await.into_diagnostic()?;
                return Err(error);
            }
        };
        let payload = RelayGrant {
            session,
            endpoint: self.endpoint.clone(),
            gateway_name: self.gateway_name.clone(),
            replica: self.replica.clone(),
        }
        .encode_to_vec();
        let (cancel, cancelled) = oneshot::channel();
        let cleanup = self.cleanup.spawn(async move {
            let serve = async {
                let mut peer = listener.accept().await?;
                peer.write_u32(u32::try_from(payload.len()).map_err(std::io::Error::other)?)
                    .await?;
                peer.write_all(&payload).await?;
                if peer.read_u8().await? != 1 {
                    return Err(std::io::ErrorKind::InvalidData.into());
                }
                Ok::<_, std::io::Error>(peer)
            };
            // Keep the peer until the issuing client has attempted revocation.
            let peer = tokio::select! {
                result = serve => result.ok(),
                _ = cancelled => None,
            };
            let started = std::time::Instant::now();
            revoke.await;
            if let Some(mut peer) = peer {
                let _ = peer.write_u8(1).await;
                Some(started.elapsed())
            } else {
                None
            }
        });
        Ok(PreparedProxy {
            command,
            cancel,
            cleanup,
        })
    }
}

pub async fn revoke_grant<I: Interceptor + Clone>(mut client: Client<I>, token: String) {
    let request = RevokeSshSessionRequest {
        token,
        allow_missing: true,
    };
    if !matches!(
        tokio::time::timeout(Duration::from_secs(2), client.revoke_ssh_session(request)).await,
        Ok(Ok(_))
    ) {
        eprintln!("Warning: could not revoke the SSH session token");
    }
}

impl PreparedProxy {
    pub fn command(&self) -> &str {
        &self.command
    }

    pub async fn run<T>(self, operation: impl Future<Output = Result<T>>) -> Result<T> {
        self.run_with_admission(operation)
            .await
            .map(|(value, _)| value)
    }

    /// An admitted proxy waits for revocation before it can carry SSH bytes.
    /// Return that interval so it does not count as time attached to a sandbox.
    pub async fn run_with_admission<T>(
        self,
        operation: impl Future<Output = Result<T>>,
    ) -> Result<(T, Option<Duration>)> {
        let result = operation.await;
        drop(self.cancel);
        let revocation_wait = self.cleanup.await.into_diagnostic()?;
        Ok((result?, revocation_wait))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn proxy_rejects_a_different_issuer_pid_before_reading_a_grant() {
        let id = Uuid::new_v4();
        let listener = ipc::Listener::bind(id).unwrap();
        let handle = format!("{}-{id}", std::process::id() + 1);
        // Leave the server alive without writing a frame. A client that trusts
        // the handle alone would hang waiting for credentials.
        let result = tokio::time::timeout(Duration::from_secs(2), receive(&handle))
            .await
            .unwrap();
        let Err(error) = result else {
            panic!("accepted an unrelated issuer")
        };
        assert!(
            error
                .to_string()
                .contains(&std::io::Error::from(std::io::ErrorKind::PermissionDenied).to_string())
        );
        drop(listener);
    }
}
