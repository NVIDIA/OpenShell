// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Extracted credential-driver implementation.

#[cfg(unix)]
use super::CredentialDriver;
use super::driver_config::{BuiltCredentialDriver, ConfiguredCredentialDriver};
#[cfg(unix)]
use async_trait::async_trait;
#[cfg(unix)]
use hyper_util::rt::TokioIo;
#[cfg(unix)]
use openshell_core::extension_protocol::{
    ExtensionFamily, NegotiatedExtension, gateway_metadata, negotiate,
};
#[cfg(unix)]
use openshell_core::proto::CredentialHandle;
#[cfg(unix)]
use openshell_core::proto::credentials::v1::{
    DeleteCredentialRequest, GetCredentialDriverCapabilitiesRequest,
    GetCredentialDriverCapabilitiesResponse, ResolveCredentialRequest, ResolveCredentialsRequest,
    ResolvedCredential, StoreCredentialRequest, credential_driver_client::CredentialDriverClient,
};
use openshell_core::{Error, Result as CoreResult};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::{
    future::Future,
    io::ErrorKind,
    os::unix::fs::{FileTypeExt, MetadataExt},
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};
#[cfg(unix)]
use tokio::{net::UnixStream, process::Command};
#[cfg(unix)]
use tonic::{
    Request, Status,
    transport::{Channel, Endpoint},
};
#[cfg(unix)]
use tower::service_fn;
#[cfg(unix)]
const DEFAULT_CREDENTIAL_DRIVER_RPC_TIMEOUT_SECS: u64 = 30;
#[cfg(unix)]
const CREDENTIAL_DRIVER_CONNECT_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone)]
#[cfg(unix)]
pub(super) struct RemoteCredentialDriver {
    channel: Channel,
}

#[cfg(unix)]
impl RemoteCredentialDriver {
    pub(super) fn new(channel: Channel) -> Self {
        Self { channel }
    }

    fn client(&self) -> CredentialDriverClient<Channel> {
        CredentialDriverClient::new(self.channel.clone())
    }
}

#[cfg(unix)]
#[async_trait]
impl CredentialDriver for RemoteCredentialDriver {
    async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        let mut client = self.client();
        let mut grpc_request = Request::new(request);
        grpc_request.set_timeout(Duration::from_secs(
            DEFAULT_CREDENTIAL_DRIVER_RPC_TIMEOUT_SECS,
        ));

        let timeout_duration = Duration::from_secs(DEFAULT_CREDENTIAL_DRIVER_RPC_TIMEOUT_SECS);
        let response =
            tokio::time::timeout(timeout_duration, client.store_credential(grpc_request))
                .await
                .map_err(|_| {
                    Status::deadline_exceeded("credential driver StoreCredential timed out")
                })??;

        response
            .into_inner()
            .handle
            .ok_or_else(|| Status::internal("credential driver returned no stored handle"))
    }

    async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status> {
        let mut client = self.client();
        let mut grpc_request = Request::new(request);
        grpc_request.set_timeout(Duration::from_secs(
            DEFAULT_CREDENTIAL_DRIVER_RPC_TIMEOUT_SECS,
        ));

        let timeout_duration = Duration::from_secs(DEFAULT_CREDENTIAL_DRIVER_RPC_TIMEOUT_SECS);
        tokio::time::timeout(timeout_duration, client.delete_credential(grpc_request))
            .await
            .map_err(|_| {
                Status::deadline_exceeded("credential driver DeleteCredential timed out")
            })??;
        Ok(())
    }

    async fn resolve_credentials(
        &self,
        requests: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        let mut client = self.client();
        let mut grpc_request = Request::new(ResolveCredentialsRequest {
            credentials: requests,
        });
        grpc_request.set_timeout(Duration::from_secs(
            DEFAULT_CREDENTIAL_DRIVER_RPC_TIMEOUT_SECS,
        ));

        let timeout_duration = Duration::from_secs(DEFAULT_CREDENTIAL_DRIVER_RPC_TIMEOUT_SECS);
        let response =
            tokio::time::timeout(timeout_duration, client.resolve_credentials(grpc_request))
                .await
                .map_err(|_| {
                    Status::deadline_exceeded("credential driver ResolveCredentials timed out")
                })??;
        Ok(response.into_inner().credentials)
    }
}

#[derive(Debug)]
pub(super) struct ManagedCredentialDriverProcess {
    child: std::sync::Mutex<Option<tokio::process::Child>>,
    socket_path: PathBuf,
}

#[cfg(unix)]
impl ManagedCredentialDriverProcess {
    fn new(child: tokio::process::Child, socket_path: PathBuf) -> Self {
        Self {
            child: std::sync::Mutex::new(Some(child)),
            socket_path,
        }
    }
}

impl Drop for ManagedCredentialDriverProcess {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.take();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[cfg(unix)]
pub(super) async fn connect_uds_driver(
    driver_name: &str,
    config: ConfiguredCredentialDriver,
    socket_path: &Path,
) -> CoreResult<BuiltCredentialDriver> {
    if config.command.is_some() {
        spawn_uds_driver(driver_name, config, socket_path).await
    } else {
        let (channel, negotiated_extension) =
            connect_ready_credential_driver(driver_name, socket_path)
                .await
                .map_err(CredentialDriverReadinessError::into_error)?;
        Ok(BuiltCredentialDriver {
            driver: Arc::new(RemoteCredentialDriver::new(channel)),
            process: None,
            negotiated_extension,
        })
    }
}

#[cfg(not(unix))]
pub(super) async fn connect_uds_driver(
    driver_name: &str,
    _config: ConfiguredCredentialDriver,
    _socket_path: &Path,
) -> CoreResult<BuiltCredentialDriver> {
    Err(Error::config(format!(
        "credential driver '{driver_name}' uses transport = 'uds', but this platform does not support Unix domain sockets"
    )))
}

#[cfg(unix)]
pub(super) async fn spawn_uds_driver(
    driver_name: &str,
    config: ConfiguredCredentialDriver,
    socket_path: &Path,
) -> CoreResult<BuiltCredentialDriver> {
    let command_path = config
        .command
        .expect("UDS command exists when spawning credential driver");
    let parent = socket_path.parent().ok_or_else(|| {
        Error::execution(format!(
            "credential driver '{driver_name}' socket path '{}' has no parent directory",
            socket_path.display()
        ))
    })?;
    std::fs::create_dir_all(parent).map_err(|err| {
        Error::execution(format!(
            "failed to create credential driver '{driver_name}' socket dir '{}': {err}",
            parent.display()
        ))
    })?;
    remove_stale_launched_driver_socket(driver_name, socket_path)?;

    let mut command = Command::new(&command_path);
    command.kill_on_drop(true);
    command.stdin(Stdio::null());
    command.stdout(Stdio::inherit());
    command.stderr(Stdio::inherit());
    command.args(&config.args);
    command.arg("--bind-socket").arg(socket_path);

    let mut child = command.spawn().map_err(|err| {
        Error::execution(format!(
            "failed to launch credential driver '{driver_name}' '{}': {err}",
            command_path.display()
        ))
    })?;
    let (channel, negotiated_extension) = wait_for_launched_credential_driver(
        driver_name,
        socket_path,
        &mut child,
        Duration::from_secs(config.startup_timeout_secs),
    )
    .await?;
    let process = Arc::new(ManagedCredentialDriverProcess::new(
        child,
        socket_path.to_path_buf(),
    ));
    Ok(BuiltCredentialDriver {
        driver: Arc::new(RemoteCredentialDriver::new(channel)),
        process: Some(process),
        negotiated_extension,
    })
}

#[cfg(unix)]
pub(super) fn remove_stale_launched_driver_socket(
    driver_name: &str,
    socket_path: &Path,
) -> CoreResult<()> {
    let metadata = match std::fs::symlink_metadata(socket_path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(Error::execution(format!(
                "failed to stat credential driver '{driver_name}' socket '{}': {err}",
                socket_path.display()
            )));
        }
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(Error::execution(format!(
            "credential driver '{driver_name}' socket '{}' is a symlink; refusing to remove it",
            socket_path.display()
        )));
    }
    if !file_type.is_socket() {
        return Err(Error::execution(format!(
            "credential driver '{driver_name}' socket path '{}' exists but is not a Unix socket",
            socket_path.display()
        )));
    }
    let expected_uid = rustix::process::geteuid().as_raw();
    if metadata.uid() != expected_uid {
        return Err(Error::execution(format!(
            "credential driver '{driver_name}' socket '{}' is owned by uid {} but current euid is {}",
            socket_path.display(),
            metadata.uid(),
            expected_uid
        )));
    }
    std::fs::remove_file(socket_path).map_err(|err| {
        Error::execution(format!(
            "failed to remove stale credential driver '{driver_name}' socket '{}': {err}",
            socket_path.display()
        ))
    })
}

#[cfg(unix)]
pub(super) async fn wait_for_launched_credential_driver(
    driver_name: &str,
    socket_path: &Path,
    child: &mut tokio::process::Child,
    timeout: Duration,
) -> CoreResult<(Channel, NegotiatedExtension)> {
    wait_for_launched_credential_driver_with(driver_name, socket_path, child, timeout, || {
        connect_ready_credential_driver(driver_name, socket_path)
    })
    .await
}

#[cfg(unix)]
pub(super) async fn wait_for_launched_credential_driver_with<F, Fut>(
    driver_name: &str,
    socket_path: &Path,
    child: &mut tokio::process::Child,
    timeout: Duration,
    mut connect: F,
) -> CoreResult<(Channel, NegotiatedExtension)>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<(Channel, NegotiatedExtension), CredentialDriverReadinessError>>,
{
    let deadline = Instant::now() + timeout;
    let mut last_error: Option<String> = None;

    loop {
        let try_wait_result = child.try_wait().map_err(|err| {
            Error::execution(format!(
                "failed to poll credential driver '{driver_name}' process: {err}"
            ))
        })?;
        if let Some(status) = try_wait_result {
            return Err(Error::execution(format!(
                "credential driver '{driver_name}' exited before becoming ready with status {status}"
            )));
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Error::execution(format!(
                "timed out waiting for credential driver '{driver_name}' socket '{}': {}",
                socket_path.display(),
                last_error.unwrap_or_else(|| "unknown error".to_string())
            )));
        }

        match tokio::time::timeout(remaining, connect()).await {
            Ok(Ok(connected)) => return Ok(connected),
            Ok(Err(error)) if error.is_retryable() => {
                last_error = Some(error.into_error().to_string());
            }
            Ok(Err(error)) => return Err(error.into_error()),
            Err(_) => {
                return Err(Error::execution(format!(
                    "timed out waiting for credential driver '{driver_name}' to respond to GetCapabilities"
                )));
            }
        }

        if Instant::now() >= deadline {
            return Err(Error::execution(format!(
                "timed out waiting for credential driver '{driver_name}' socket '{}': {}",
                socket_path.display(),
                last_error.unwrap_or_else(|| "unknown error".to_string())
            )));
        }

        tokio::time::sleep(CREDENTIAL_DRIVER_CONNECT_INTERVAL).await;
    }
}

#[cfg(unix)]
#[derive(Debug)]
pub(super) enum CredentialDriverReadinessError {
    Retryable(Error),
    RpcStatus { driver_name: String, status: Status },
    Terminal(Error),
}

#[cfg(unix)]
impl CredentialDriverReadinessError {
    pub(super) fn rpc_status(driver_name: &str, status: Status) -> Self {
        Self::RpcStatus {
            driver_name: driver_name.to_string(),
            status,
        }
    }

    pub(super) fn is_retryable(&self) -> bool {
        match self {
            Self::Retryable(_) => true,
            Self::RpcStatus { status, .. } => matches!(
                status.code(),
                tonic::Code::Unavailable
                    | tonic::Code::DeadlineExceeded
                    | tonic::Code::ResourceExhausted
                    | tonic::Code::Aborted
                    | tonic::Code::Internal
                    | tonic::Code::Unknown
            ),
            Self::Terminal(_) => false,
        }
    }

    pub(super) fn into_error(self) -> Error {
        match self {
            Self::Retryable(error) | Self::Terminal(error) => error,
            Self::RpcStatus {
                driver_name,
                status,
            } => Error::config(format!(
                "credential driver '{driver_name}' GetCapabilities failed: {status}"
            )),
        }
    }
}

#[cfg(unix)]
pub(super) async fn connect_ready_credential_driver(
    driver_name: &str,
    socket_path: &Path,
) -> Result<(Channel, NegotiatedExtension), CredentialDriverReadinessError> {
    let channel = connect_credential_driver_socket(driver_name, socket_path)
        .await
        .map_err(CredentialDriverReadinessError::Retryable)?;
    let mut client = CredentialDriverClient::new(channel.clone());
    let gateway = gateway_metadata(ExtensionFamily::Credentials);
    let mut request = Request::new(GetCredentialDriverCapabilitiesRequest {
        gateway: Some(gateway.clone()),
    });
    let timeout = Duration::from_secs(DEFAULT_CREDENTIAL_DRIVER_RPC_TIMEOUT_SECS);
    request.set_timeout(timeout);
    let capabilities = await_credential_driver_capabilities(
        driver_name,
        timeout,
        client.get_capabilities(request),
    )
    .await?;
    let negotiated_extension = negotiate(
        ExtensionFamily::Credentials,
        driver_name,
        &gateway,
        capabilities.extension,
    )
    .map_err(|error| CredentialDriverReadinessError::Terminal(Error::config(error.to_string())))?;
    Ok((channel, negotiated_extension))
}

#[cfg(unix)]
pub(super) async fn await_credential_driver_capabilities(
    driver_name: &str,
    timeout: Duration,
    response: impl Future<
        Output = Result<tonic::Response<GetCredentialDriverCapabilitiesResponse>, Status>,
    >,
) -> Result<GetCredentialDriverCapabilitiesResponse, CredentialDriverReadinessError> {
    tokio::time::timeout(timeout, response)
        .await
        .map_err(|_| {
            CredentialDriverReadinessError::Retryable(Error::config(format!(
                "credential driver '{driver_name}' GetCapabilities timed out"
            )))
        })?
        .map_err(|status| CredentialDriverReadinessError::rpc_status(driver_name, status))
        .map(tonic::Response::into_inner)
}

#[cfg(unix)]
pub(super) async fn connect_credential_driver_socket(
    driver_name: &str,
    socket_path: &Path,
) -> CoreResult<Channel> {
    let socket_path = socket_path.to_path_buf();
    let display_path = socket_path.clone();
    Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(service_fn(move |_: tonic::transport::Uri| {
            let socket_path = socket_path.clone();
            async move { UnixStream::connect(socket_path).await.map(TokioIo::new) }
        }))
        .await
        .map_err(|err| {
            Error::transport(format!(
                "failed to connect to credential driver '{driver_name}' socket '{}': {err}",
                display_path.display()
            ))
        })
}
