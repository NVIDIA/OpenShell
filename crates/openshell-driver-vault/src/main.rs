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
use openshell_driver_vault::{CredentialDriverService, VaultCredentialDriver};
use tokio::net::{UnixListener, UnixStream};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "openshell-driver-vault")]
#[command(version = VERSION)]
struct Args {
    #[arg(long, env = "OPENSHELL_CREDENTIAL_DRIVER_SOCKET")]
    bind_socket: PathBuf,

    #[arg(long, env = "OPENSHELL_LOG_LEVEL", default_value = "info")]
    log_level: String,

    #[arg(long, env = "OPENSHELL_VAULT_ADDRESS")]
    address: Option<String>,

    #[arg(long, env = "OPENSHELL_VAULT_MOUNT")]
    mount: Option<String>,

    #[arg(long, env = "OPENSHELL_VAULT_KV_VERSION")]
    kv_version: Option<String>,

    #[arg(long, env = "OPENSHELL_VAULT_AUTH_METHOD")]
    auth_method: Option<String>,

    #[arg(long, env = "OPENSHELL_VAULT_ROLE")]
    role: Option<String>,

    #[arg(long, env = "OPENSHELL_VAULT_KUBERNETES_AUTH_MOUNT")]
    kubernetes_auth_mount: Option<String>,

    #[arg(long, env = "OPENSHELL_VAULT_SERVICE_ACCOUNT_TOKEN_PATH")]
    service_account_token_path: Option<PathBuf>,

    #[arg(long, env = "OPENSHELL_VAULT_TOKEN_PATH")]
    token_path: Option<PathBuf>,

    #[arg(long, env = "OPENSHELL_VAULT_TIMEOUT_SECS")]
    timeout_secs: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
        )
        .init();

    let driver = VaultCredentialDriver::from_config(&driver_config(&args)).into_diagnostic()?;

    prepare_socket(&args.bind_socket)?;
    let listener = UnixListener::bind(&args.bind_socket).into_diagnostic()?;
    restrict_socket_permissions(&args.bind_socket)?;

    info!(socket = %args.bind_socket.display(), "Starting Vault credential driver");
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
    insert_string(&mut config, "address", args.address.as_ref());
    insert_string(&mut config, "mount", args.mount.as_ref());
    insert_string(&mut config, "kv_version", args.kv_version.as_ref());
    insert_string(&mut config, "auth_method", args.auth_method.as_ref());
    insert_string(&mut config, "role", args.role.as_ref());
    insert_string(
        &mut config,
        "kubernetes_auth_mount",
        args.kubernetes_auth_mount.as_ref(),
    );
    insert_path(
        &mut config,
        "service_account_token_path",
        args.service_account_token_path.as_ref(),
    );
    insert_path(&mut config, "token_path", args.token_path.as_ref());
    if let Some(timeout_secs) = args.timeout_secs {
        config.insert(
            "timeout_secs".to_string(),
            toml::Value::Integer(i64::try_from(timeout_secs).unwrap_or(i64::MAX)),
        );
    }
    config
}

fn insert_string(config: &mut toml::Table, key: &str, value: Option<&String>) {
    if let Some(value) = value {
        config.insert(key.to_string(), toml::Value::String(value.clone()));
    }
}

fn insert_path(config: &mut toml::Table, key: &str, value: Option<&PathBuf>) {
    if let Some(value) = value {
        config.insert(
            key.to_string(),
            toml::Value::String(value.display().to_string()),
        );
    }
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
