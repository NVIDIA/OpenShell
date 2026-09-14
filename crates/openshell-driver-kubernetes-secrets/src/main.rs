// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use clap::Parser;
use futures::Stream;
use miette::{IntoDiagnostic, Result, miette};
use openshell_core::VERSION;
use openshell_core::proto::credentials::v1::credential_driver_server::CredentialDriverServer;
use openshell_driver_kubernetes_secrets::{
    CredentialDriverService, KubernetesSecretsCredentialDriver,
};
use tokio::net::{UnixListener, UnixStream};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "openshell-driver-kubernetes-secrets")]
#[command(version = VERSION)]
struct Args {
    #[arg(long, env = "OPENSHELL_CREDENTIAL_DRIVER_SOCKET")]
    bind_socket: PathBuf,

    #[arg(long, env = "OPENSHELL_LOG_LEVEL", default_value = "info")]
    log_level: String,

    #[arg(long, env = "OPENSHELL_KUBERNETES_SECRETS_NAMESPACE")]
    namespace: Option<String>,

    #[arg(
        long,
        env = "OPENSHELL_KUBERNETES_SECRETS_ALLOW_REFERENCE_NAMESPACE",
        default_value_t = false
    )]
    allow_reference_namespace: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
        )
        .init();

    let driver = KubernetesSecretsCredentialDriver::from_config(&driver_config(&args))
        .await
        .into_diagnostic()?;

    prepare_socket(&args.bind_socket)?;
    let listener = UnixListener::bind(&args.bind_socket).into_diagnostic()?;
    restrict_socket_permissions(&args.bind_socket)?;

    info!(
        socket = %args.bind_socket.display(),
        "Starting Kubernetes Secrets credential driver"
    );
    let result = tonic::transport::Server::builder()
        .add_service(CredentialDriverServer::new(CredentialDriverService::new(
            driver,
        )))
        .serve_with_incoming(UnixIncoming::new(listener))
        .await
        .into_diagnostic();
    let _ = std::fs::remove_file(&args.bind_socket);
    result
}

fn driver_config(args: &Args) -> toml::Table {
    let mut config = toml::Table::new();
    if let Some(namespace) = args.namespace.as_ref() {
        config.insert(
            "namespace".to_string(),
            toml::Value::String(namespace.clone()),
        );
    }
    if args.allow_reference_namespace {
        config.insert(
            "allow_reference_namespace".to_string(),
            toml::Value::Boolean(true),
        );
    }
    config
}

fn prepare_socket(socket_path: &Path) -> Result<()> {
    let parent = socket_path.parent().ok_or_else(|| {
        miette!(
            "credential driver socket path '{}' has no parent directory",
            socket_path.display()
        )
    })?;
    std::fs::create_dir_all(parent).into_diagnostic()?;

    match std::fs::symlink_metadata(socket_path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            std::fs::remove_file(socket_path).into_diagnostic()?;
        }
        Ok(_) => {
            return Err(miette!(
                "credential driver socket path '{}' exists but is not a Unix socket",
                socket_path.display()
            ));
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).into_diagnostic(),
    }
    Ok(())
}

fn restrict_socket_permissions(socket_path: &Path) -> Result<()> {
    let mut permissions = std::fs::metadata(socket_path)
        .into_diagnostic()?
        .permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(socket_path, permissions).into_diagnostic()
}

struct UnixIncoming {
    listener: UnixListener,
}

impl UnixIncoming {
    fn new(listener: UnixListener) -> Self {
        Self { listener }
    }
}

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
