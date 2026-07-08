// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Local control channel for Kubernetes sidecar topology.
//!
//! The network sidecar owns gateway credentials. The process supervisor in the
//! agent container connects over this Unix socket to receive policy/provider
//! state without mounting gateway credentials into the agent container.

use miette::{IntoDiagnostic, Result, WrapErr};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::{Mutex, broadcast, mpsc};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct BootstrapData {
    pub policy_proto: openshell_core::proto::SandboxPolicy,
    pub provider_env_revision: u64,
    pub provider_child_env: HashMap<String, String>,
    pub proxy_ca_cert_path: Option<PathBuf>,
    pub proxy_ca_bundle_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct EntrypointStarted {
    pub pid: u32,
    pub ssh_socket_path: PathBuf,
    pub start_session: bool,
}

#[derive(Debug, Clone)]
pub enum ControlUpdate {
    ProviderEnvUpdated {
        revision: u64,
        provider_child_env: HashMap<String, String>,
    },
    PolicyUpdated {
        policy_proto: openshell_core::proto::SandboxPolicy,
        policy_hash: String,
        config_revision: u64,
    },
}

#[derive(Clone)]
pub struct Publisher {
    state: Arc<RwLock<BootstrapData>>,
    updates: broadcast::Sender<WireServerMessage>,
}

impl Publisher {
    pub fn publish_provider_env(&self, revision: u64, provider_child_env: HashMap<String, String>) {
        {
            let mut state = self.state.write().expect("sidecar control state poisoned");
            if revision <= state.provider_env_revision {
                return;
            }
            state.provider_env_revision = revision;
            state.provider_child_env.clone_from(&provider_child_env);
        }

        let _ = self.updates.send(WireServerMessage::ProviderEnvUpdated {
            revision,
            provider_child_env,
        });
    }

    pub fn publish_policy(
        &self,
        policy_proto: openshell_core::proto::SandboxPolicy,
        policy_hash: String,
        config_revision: u64,
    ) {
        {
            let mut state = self.state.write().expect("sidecar control state poisoned");
            state.policy_proto = policy_proto.clone();
        }

        let _ = self.updates.send(WireServerMessage::PolicyUpdated {
            policy_proto: policy_proto.encode_to_vec(),
            policy_hash,
            config_revision,
        });
    }
}

pub struct ServerHandle {
    publisher: Publisher,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    entrypoint_rx: mpsc::UnboundedReceiver<EntrypointStarted>,
}

impl ServerHandle {
    pub fn publisher(&self) -> Publisher {
        self.publisher.clone()
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn into_entrypoint_receiver(self) -> mpsc::UnboundedReceiver<EntrypointStarted> {
        self.entrypoint_rx
    }
}

pub struct ProcessConnection {
    pub writer: Arc<Mutex<OwnedWriteHalf>>,
    pub updates: mpsc::UnboundedReceiver<ControlUpdate>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WireClientMessage {
    BootstrapRequest { supervisor_pid: Option<u32> },
    EntrypointStarted { pid: u32, ssh_socket_path: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WireServerMessage {
    BootstrapResponse {
        policy_proto: Vec<u8>,
        provider_env_revision: u64,
        provider_child_env: HashMap<String, String>,
        proxy_ca_cert_path: Option<String>,
        proxy_ca_bundle_path: Option<String>,
    },
    ProviderEnvUpdated {
        revision: u64,
        provider_child_env: HashMap<String, String>,
    },
    PolicyUpdated {
        policy_proto: Vec<u8>,
        policy_hash: String,
        config_revision: u64,
    },
}

impl BootstrapData {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn to_wire(&self) -> WireServerMessage {
        WireServerMessage::BootstrapResponse {
            policy_proto: self.policy_proto.encode_to_vec(),
            provider_env_revision: self.provider_env_revision,
            provider_child_env: self.provider_child_env.clone(),
            proxy_ca_cert_path: self
                .proxy_ca_cert_path
                .as_ref()
                .map(|path| path.display().to_string()),
            proxy_ca_bundle_path: self
                .proxy_ca_bundle_path
                .as_ref()
                .map(|path| path.display().to_string()),
        }
    }
}

impl TryFrom<WireServerMessage> for BootstrapData {
    type Error = miette::Report;

    fn try_from(message: WireServerMessage) -> Result<Self> {
        let WireServerMessage::BootstrapResponse {
            policy_proto,
            provider_env_revision,
            provider_child_env,
            proxy_ca_cert_path,
            proxy_ca_bundle_path,
        } = message
        else {
            return Err(miette::miette!(
                "expected sidecar bootstrap response, received update message"
            ));
        };

        let policy_proto = openshell_core::proto::SandboxPolicy::decode(policy_proto.as_slice())
            .into_diagnostic()
            .wrap_err("failed to decode sidecar bootstrap policy")?;

        Ok(Self {
            policy_proto,
            provider_env_revision,
            provider_child_env,
            proxy_ca_cert_path: proxy_ca_cert_path.map(PathBuf::from),
            proxy_ca_bundle_path: proxy_ca_bundle_path.map(PathBuf::from),
        })
    }
}

impl TryFrom<WireServerMessage> for ControlUpdate {
    type Error = miette::Report;

    fn try_from(message: WireServerMessage) -> Result<Self> {
        match message {
            WireServerMessage::ProviderEnvUpdated {
                revision,
                provider_child_env,
            } => Ok(Self::ProviderEnvUpdated {
                revision,
                provider_child_env,
            }),
            WireServerMessage::PolicyUpdated {
                policy_proto,
                policy_hash,
                config_revision,
            } => {
                let policy_proto =
                    openshell_core::proto::SandboxPolicy::decode(policy_proto.as_slice())
                        .into_diagnostic()
                        .wrap_err("failed to decode sidecar policy update")?;
                Ok(Self::PolicyUpdated {
                    policy_proto,
                    policy_hash,
                    config_revision,
                })
            }
            WireServerMessage::BootstrapResponse { .. } => Err(miette::miette!(
                "unexpected sidecar bootstrap response after initial handshake"
            )),
        }
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn spawn_server(path: &Path, bootstrap: BootstrapData) -> Result<ServerHandle> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to create sidecar control socket dir {}",
                    parent.display()
                )
            })?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).into_diagnostic().wrap_err_with(|| {
                format!(
                    "failed to remove stale sidecar control socket {}",
                    path.display()
                )
            });
        }
    }

    let listener = UnixListener::bind(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to bind sidecar control socket {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to set permissions on sidecar control socket {}",
                    path.display()
                )
            })?;
    }

    let state = Arc::new(RwLock::new(bootstrap));
    let (updates, _) = broadcast::channel(32);
    let (entrypoint_tx, entrypoint_rx) = mpsc::unbounded_channel();
    let publisher = Publisher {
        state: state.clone(),
        updates: updates.clone(),
    };

    tokio::spawn(accept_loop(listener, state, updates, entrypoint_tx));
    info!(path = %path.display(), "Sidecar control socket listening");

    Ok(ServerHandle {
        publisher,
        entrypoint_rx,
    })
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
async fn accept_loop(
    listener: UnixListener,
    state: Arc<RwLock<BootstrapData>>,
    updates: broadcast::Sender<WireServerMessage>,
    entrypoint_tx: mpsc::UnboundedSender<EntrypointStarted>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let state = state.clone();
                let updates = updates.clone();
                let entrypoint_tx = entrypoint_tx.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(stream, state, updates, entrypoint_tx).await
                    {
                        debug!(error = %err, "Sidecar control connection closed");
                    }
                });
            }
            Err(err) => {
                warn!(error = %err, "Failed to accept sidecar control connection");
            }
        }
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
async fn handle_connection(
    stream: tokio::net::UnixStream,
    state: Arc<RwLock<BootstrapData>>,
    updates: broadcast::Sender<WireServerMessage>,
    entrypoint_tx: mpsc::UnboundedSender<EntrypointStarted>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    let first_line =
        lines.next_line().await.into_diagnostic()?.ok_or_else(|| {
            miette::miette!("sidecar control client disconnected before bootstrap")
        })?;
    match decode_client_message(&first_line)? {
        WireClientMessage::BootstrapRequest { supervisor_pid } => {
            if let Some(pid) = supervisor_pid.filter(|pid| *pid != 0) {
                let _ = entrypoint_tx.send(EntrypointStarted {
                    pid,
                    ssh_socket_path: PathBuf::new(),
                    start_session: false,
                });
            }
        }
        WireClientMessage::EntrypointStarted { .. } => {
            return Err(miette::miette!(
                "sidecar control client sent entrypoint event before bootstrap"
            ));
        }
    }

    let bootstrap = {
        let state = state.read().expect("sidecar control state poisoned");
        state.to_wire()
    };
    write_json_line(&mut writer, &bootstrap).await?;

    let mut update_rx = updates.subscribe();
    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Some(line) = line.into_diagnostic()? else {
                    return Ok(());
                };
                match decode_client_message(&line)? {
                    WireClientMessage::BootstrapRequest { .. } => {
                        debug!("Ignoring duplicate sidecar bootstrap request");
                    }
                    WireClientMessage::EntrypointStarted { pid, ssh_socket_path } => {
                        if pid == 0 {
                            warn!("Ignoring sidecar entrypoint event with pid=0");
                            continue;
                        }
                        let _ = entrypoint_tx.send(EntrypointStarted {
                            pid,
                            ssh_socket_path: PathBuf::from(ssh_socket_path),
                            start_session: true,
                        });
                    }
                }
            }
            update = update_rx.recv() => {
                match update {
                    Ok(message) => write_json_line(&mut writer, &message).await?,
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(skipped, "Sidecar control client lagged behind updates");
                    }
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
    }
}

pub async fn connect_process_client(
    path: &Path,
    timeout: Duration,
) -> Result<(BootstrapData, ProcessConnection)> {
    let stream = connect_with_retry(path, timeout).await?;
    let (reader, mut writer) = stream.into_split();
    write_json_line(
        &mut writer,
        &WireClientMessage::BootstrapRequest {
            supervisor_pid: Some(std::process::id()),
        },
    )
    .await?;

    let mut lines = BufReader::new(reader).lines();
    let first_line = lines
        .next_line()
        .await
        .into_diagnostic()?
        .ok_or_else(|| miette::miette!("sidecar control closed before bootstrap response"))?;
    let bootstrap = BootstrapData::try_from(decode_server_message(&first_line)?)?;

    let (update_tx, updates) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            match decode_server_message(&line).and_then(ControlUpdate::try_from) {
                Ok(update) => {
                    if update_tx.send(update).is_err() {
                        return;
                    }
                }
                Err(err) => {
                    warn!(error = %err, "Ignoring invalid sidecar control update");
                }
            }
        }
    });

    Ok((
        bootstrap,
        ProcessConnection {
            writer: Arc::new(Mutex::new(writer)),
            updates,
        },
    ))
}

async fn connect_with_retry(path: &Path, timeout: Duration) -> Result<tokio::net::UnixStream> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio::net::UnixStream::connect(path).await {
            Ok(stream) => return Ok(stream),
            Err(err) if tokio::time::Instant::now() < deadline => {
                debug!(
                    path = %path.display(),
                    error = %err,
                    "Waiting for sidecar control socket"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(err) => {
                return Err(err).into_diagnostic().wrap_err_with(|| {
                    format!(
                        "timed out waiting for sidecar control socket {}",
                        path.display()
                    )
                });
            }
        }
    }
}

pub async fn send_entrypoint_started(
    writer: &Arc<Mutex<OwnedWriteHalf>>,
    pid: u32,
    ssh_socket_path: &Path,
) -> Result<()> {
    let message = WireClientMessage::EntrypointStarted {
        pid,
        ssh_socket_path: ssh_socket_path.display().to_string(),
    };
    let mut writer = writer.lock().await;
    write_json_line(&mut *writer, &message).await
}

async fn write_json_line<W, T>(writer: &mut W, value: &T) -> Result<()>
where
    W: AsyncWrite + Unpin + Send,
    T: Serialize + Sync,
{
    let bytes = serde_json::to_vec(value).into_diagnostic()?;
    writer.write_all(&bytes).await.into_diagnostic()?;
    writer.write_all(b"\n").await.into_diagnostic()?;
    writer.flush().await.into_diagnostic()?;
    Ok(())
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn decode_client_message(line: &str) -> Result<WireClientMessage> {
    serde_json::from_str(line)
        .into_diagnostic()
        .wrap_err("failed to decode sidecar client message")
}

fn decode_server_message(line: &str) -> Result<WireServerMessage> {
    serde_json::from_str(line)
        .into_diagnostic()
        .wrap_err("failed to decode sidecar server message")
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::SandboxPolicy;

    #[tokio::test]
    async fn bootstrap_round_trips_policy_and_provider_env() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let mut env = HashMap::new();
        env.insert("GITHUB_TOKEN".to_string(), "secret".to_string());
        let bootstrap = BootstrapData {
            policy_proto: SandboxPolicy {
                version: 7,
                ..SandboxPolicy::default()
            },
            provider_env_revision: 3,
            provider_child_env: env.clone(),
            proxy_ca_cert_path: Some(PathBuf::from("/tmp/ca.pem")),
            proxy_ca_bundle_path: Some(PathBuf::from("/tmp/bundle.pem")),
        };

        let _server = spawn_server(&socket, bootstrap).unwrap();
        let (received, _connection) = connect_process_client(&socket, Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(received.policy_proto.version, 7);
        assert_eq!(received.provider_env_revision, 3);
        assert_eq!(received.provider_child_env, env);
        assert_eq!(
            received.proxy_ca_cert_path,
            Some(PathBuf::from("/tmp/ca.pem"))
        );
        assert_eq!(
            received.proxy_ca_bundle_path,
            Some(PathBuf::from("/tmp/bundle.pem"))
        );
    }

    #[tokio::test]
    async fn entrypoint_started_is_delivered_to_server() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let server = spawn_server(
            &socket,
            BootstrapData {
                policy_proto: SandboxPolicy::default(),
                provider_env_revision: 0,
                provider_child_env: HashMap::new(),
                proxy_ca_cert_path: None,
                proxy_ca_bundle_path: None,
            },
        )
        .unwrap();
        let mut entrypoint_rx = server.into_entrypoint_receiver();
        let (_bootstrap, connection) = connect_process_client(&socket, Duration::from_secs(1))
            .await
            .unwrap();

        let anchor = tokio::time::timeout(Duration::from_secs(1), entrypoint_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(anchor.pid, std::process::id());
        assert!(!anchor.start_session);

        send_entrypoint_started(
            &connection.writer,
            4242,
            Path::new("/run/openshell-sidecar/ssh.sock"),
        )
        .await
        .unwrap();

        let started = tokio::time::timeout(Duration::from_secs(1), entrypoint_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(started.pid, 4242);
        assert_eq!(
            started.ssh_socket_path,
            PathBuf::from("/run/openshell-sidecar/ssh.sock")
        );
        assert!(started.start_session);
    }

    #[test]
    fn malformed_client_message_is_rejected() {
        let err = decode_client_message("not-json").unwrap_err();
        assert!(
            err.to_string()
                .contains("failed to decode sidecar client message")
        );
    }
}
