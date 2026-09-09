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
    pub provider_env_generation: u64,
    pub provider_child_env: HashMap<String, String>,
    pub agent_proposals_enabled: bool,
    pub proxy_ca_cert_path: Option<PathBuf>,
    pub proxy_ca_bundle_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct EntrypointStarted {
    pub pid: u32,
    pub start_session: bool,
    pub instance_id: String,
    pub exit_code: Option<i32>,
    pub finalized: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct ExpectedPeer {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone)]
pub enum ControlUpdate {
    ProviderEnv {
        revision: u64,
        generation: u64,
        provider_child_env: HashMap<String, String>,
    },
    Policy {
        policy_proto: Box<openshell_core::proto::SandboxPolicy>,
        policy_hash: String,
        config_revision: u64,
    },
    AgentProposals {
        enabled: bool,
        config_revision: u64,
    },
    MainProcessExitAck {
        instance_id: String,
    },
}

#[derive(Clone)]
pub struct Publisher {
    state: Arc<RwLock<BootstrapData>>,
    updates: broadcast::Sender<WireServerMessage>,
}

impl Publisher {
    pub fn publish_provider_env(&self, revision: u64, provider_child_env: HashMap<String, String>) {
        let mut state = self.state.write().expect("sidecar control state poisoned");
        if revision == state.provider_env_revision {
            return;
        }
        state.provider_env_revision = revision;
        state.provider_env_generation = state
            .provider_env_generation
            .checked_add(1)
            .expect("sidecar provider environment generation overflow");
        state.provider_child_env.clone_from(&provider_child_env);

        // Keep generation assignment, bootstrap state, and publication under
        // one lock so cloned publishers cannot emit generations out of order.
        let _ = self.updates.send(WireServerMessage::ProviderEnvUpdated {
            revision,
            generation: state.provider_env_generation,
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

    pub fn publish_agent_proposals(&self, enabled: bool, config_revision: u64) {
        {
            let mut state = self.state.write().expect("sidecar control state poisoned");
            if state.agent_proposals_enabled == enabled {
                return;
            }
            state.agent_proposals_enabled = enabled;
        }

        let _ = self.updates.send(WireServerMessage::AgentProposalsUpdated {
            enabled,
            config_revision,
        });
    }

    #[cfg(any(target_os = "linux", test))]
    pub fn publish_main_process_exit_ack(&self, instance_id: String) {
        let _ = self
            .updates
            .send(WireServerMessage::MainProcessExitAck { instance_id });
    }
}

pub struct ServerHandle {
    publisher: Publisher,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    entrypoint_rx: mpsc::Receiver<EntrypointStarted>,
    connection_task: tokio::task::JoinHandle<()>,
}

impl ServerHandle {
    pub fn publisher(&self) -> Publisher {
        self.publisher.clone()
    }

    #[cfg(test)]
    pub fn into_entrypoint_receiver(self) -> mpsc::Receiver<EntrypointStarted> {
        self.entrypoint_rx
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn into_runtime_parts(
        self,
    ) -> (
        mpsc::Receiver<EntrypointStarted>,
        tokio::task::JoinHandle<()>,
    ) {
        (self.entrypoint_rx, self.connection_task)
    }
}

pub struct ProcessConnection {
    pub writer: Arc<Mutex<OwnedWriteHalf>>,
    pub updates: mpsc::UnboundedReceiver<ControlUpdate>,
    pub closed: tokio::sync::oneshot::Receiver<()>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WireClientMessage {
    BootstrapRequest { supervisor_pid: u32 },
    EntrypointStarted { pid: u32, instance_id: String },
    MainProcessExited { instance_id: String, exit_code: i32 },
    MainProcessFinalized { instance_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WireServerMessage {
    BootstrapResponse {
        policy_proto: Vec<u8>,
        provider_env_revision: u64,
        provider_env_generation: u64,
        provider_child_env: HashMap<String, String>,
        agent_proposals_enabled: bool,
        proxy_ca_cert_path: Option<String>,
        proxy_ca_bundle_path: Option<String>,
    },
    ProviderEnvUpdated {
        revision: u64,
        generation: u64,
        provider_child_env: HashMap<String, String>,
    },
    PolicyUpdated {
        policy_proto: Vec<u8>,
        policy_hash: String,
        config_revision: u64,
    },
    AgentProposalsUpdated {
        enabled: bool,
        config_revision: u64,
    },
    MainProcessExitAck {
        instance_id: String,
    },
}

impl BootstrapData {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn to_wire(&self) -> WireServerMessage {
        WireServerMessage::BootstrapResponse {
            policy_proto: self.policy_proto.encode_to_vec(),
            provider_env_revision: self.provider_env_revision,
            provider_env_generation: self.provider_env_generation,
            provider_child_env: self.provider_child_env.clone(),
            agent_proposals_enabled: self.agent_proposals_enabled,
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
            provider_env_generation,
            provider_child_env,
            agent_proposals_enabled,
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
        let policy_proto = canonicalize_sidecar_policy(
            policy_proto,
            "sidecar bootstrap policy failed validation",
        )?;

        Ok(Self {
            policy_proto,
            provider_env_revision,
            provider_env_generation,
            provider_child_env,
            agent_proposals_enabled,
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
                generation,
                provider_child_env,
            } => Ok(Self::ProviderEnv {
                revision,
                generation,
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
                let policy_proto = canonicalize_sidecar_policy(
                    policy_proto,
                    "sidecar policy update failed validation",
                )?;
                Ok(Self::Policy {
                    policy_proto: Box::new(policy_proto),
                    policy_hash,
                    config_revision,
                })
            }
            WireServerMessage::AgentProposalsUpdated {
                enabled,
                config_revision,
            } => Ok(Self::AgentProposals {
                enabled,
                config_revision,
            }),
            WireServerMessage::MainProcessExitAck { instance_id } => {
                Ok(Self::MainProcessExitAck { instance_id })
            }
            WireServerMessage::BootstrapResponse { .. } => Err(miette::miette!(
                "unexpected sidecar bootstrap response after initial handshake"
            )),
        }
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn spawn_server(
    path: &Path,
    bootstrap: BootstrapData,
    expected_peer: ExpectedPeer,
) -> Result<ServerHandle> {
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
    let (entrypoint_tx, entrypoint_rx) = mpsc::channel(8);
    let publisher = Publisher {
        state: state.clone(),
        updates: updates.clone(),
    };

    let connection_task = tokio::spawn(accept_authoritative_connection(
        listener,
        path.to_path_buf(),
        expected_peer,
        state,
        updates,
        entrypoint_tx,
    ));
    info!(path = %path.display(), "Sidecar control socket listening");

    Ok(ServerHandle {
        publisher,
        entrypoint_rx,
        connection_task,
    })
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
async fn accept_authoritative_connection(
    listener: UnixListener,
    socket_path: PathBuf,
    expected_peer: ExpectedPeer,
    state: Arc<RwLock<BootstrapData>>,
    updates: broadcast::Sender<WireServerMessage>,
    entrypoint_tx: mpsc::Sender<EntrypointStarted>,
) {
    let stream = match listener.accept().await {
        Ok((stream, _addr)) => stream,
        Err(err) => {
            warn!(error = %err, "Failed to accept authoritative sidecar control connection");
            return;
        }
    };

    // The process supervisor connects before it launches the workload. Drop
    // the listener and unlink its pathname after that first accept so workload
    // processes can neither open a second control channel nor impersonate a
    // restarted server at the trusted path.
    drop(listener);
    if let Err(err) = std::fs::remove_file(&socket_path)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        warn!(
            path = %socket_path.display(),
            error = %err,
            "Failed to unlink accepted sidecar control socket"
        );
    }

    if let Err(err) = handle_connection(stream, expected_peer, state, updates, entrypoint_tx).await
    {
        warn!(error = %err, "Authoritative sidecar control connection closed");
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
async fn handle_connection(
    stream: tokio::net::UnixStream,
    expected_peer: ExpectedPeer,
    state: Arc<RwLock<BootstrapData>>,
    updates: broadcast::Sender<WireServerMessage>,
    entrypoint_tx: mpsc::Sender<EntrypointStarted>,
) -> Result<()> {
    let credentials = stream
        .peer_cred()
        .into_diagnostic()
        .wrap_err("failed to read sidecar control peer credentials")?;
    if credentials.uid() != expected_peer.uid || credentials.gid() != expected_peer.gid {
        return Err(miette::miette!(
            "sidecar control peer identity mismatch: expected uid:gid {}:{}, got {}:{}",
            expected_peer.uid,
            expected_peer.gid,
            credentials.uid(),
            credentials.gid(),
        ));
    }
    let peer_pid = credentials
        .pid()
        .and_then(|pid| u32::try_from(pid).ok())
        .ok_or_else(|| miette::miette!("sidecar control peer PID is unavailable"))?;

    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    let first_line =
        lines.next_line().await.into_diagnostic()?.ok_or_else(|| {
            miette::miette!("sidecar control client disconnected before bootstrap")
        })?;
    match decode_client_message(&first_line)? {
        WireClientMessage::BootstrapRequest { supervisor_pid } => {
            if supervisor_pid == 0 || supervisor_pid != peer_pid {
                return Err(miette::miette!(
                    "sidecar bootstrap PID mismatch: peer PID {peer_pid}, claimed PID {supervisor_pid}"
                ));
            }
            entrypoint_tx
                .send(EntrypointStarted {
                    pid: supervisor_pid,
                    start_session: false,
                    instance_id: String::new(),
                    exit_code: None,
                    finalized: false,
                })
                .await
                .map_err(|_| miette::miette!("sidecar entrypoint receiver closed"))?;
        }
        WireClientMessage::EntrypointStarted { .. }
        | WireClientMessage::MainProcessExited { .. }
        | WireClientMessage::MainProcessFinalized { .. } => {
            return Err(miette::miette!(
                "sidecar control client sent entrypoint event before bootstrap"
            ));
        }
    }

    // Subscribe before taking the bootstrap snapshot so an update can neither
    // be missed between the snapshot and the live update stream nor omitted
    // from the snapshot itself.
    let mut update_rx = updates.subscribe();
    let bootstrap = {
        let state = state.read().expect("sidecar control state poisoned");
        state.to_wire()
    };
    write_json_line(&mut writer, &bootstrap).await?;

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
                    WireClientMessage::EntrypointStarted { pid, instance_id } => {
                        if pid == 0 {
                            warn!("Ignoring sidecar entrypoint event with pid=0");
                            continue;
                        }
                        entrypoint_tx
                            .send(EntrypointStarted {
                                pid,
                                start_session: true,
                                instance_id,
                                exit_code: None,
                                finalized: false,
                            })
                            .await
                            .map_err(|_| miette::miette!("sidecar entrypoint receiver closed"))?;
                    }
                    WireClientMessage::MainProcessExited {
                        instance_id,
                        exit_code,
                    } => {
                        entrypoint_tx
                            .send(EntrypointStarted {
                                pid: 0,
                                start_session: false,
                                instance_id,
                                exit_code: Some(exit_code),
                                finalized: false,
                            })
                            .await
                            .map_err(|_| miette::miette!("sidecar entrypoint receiver closed"))?;
                    }
                    WireClientMessage::MainProcessFinalized { instance_id } => {
                        entrypoint_tx
                            .send(EntrypointStarted {
                                pid: 0,
                                start_session: false,
                                instance_id,
                                exit_code: None,
                                finalized: true,
                            })
                            .await
                            .map_err(|_| miette::miette!("sidecar entrypoint receiver closed"))?;
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
            supervisor_pid: std::process::id(),
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
    let (closed_tx, closed) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            match decode_server_message(&line).and_then(ControlUpdate::try_from) {
                Ok(update) => {
                    if update_tx.send(update).is_err() {
                        break;
                    }
                }
                Err(err) => {
                    warn!(error = %err, "Ignoring invalid sidecar control update");
                }
            }
        }
        let _ = closed_tx.send(());
    });

    Ok((
        bootstrap,
        ProcessConnection {
            writer: Arc::new(Mutex::new(writer)),
            updates,
            closed,
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
    instance_id: String,
) -> Result<()> {
    let message = WireClientMessage::EntrypointStarted { pid, instance_id };
    let mut writer = writer.lock().await;
    write_json_line(&mut *writer, &message).await
}

pub async fn send_main_process_exited(
    writer: &Arc<Mutex<OwnedWriteHalf>>,
    instance_id: String,
    exit_code: i32,
) -> Result<()> {
    let message = WireClientMessage::MainProcessExited {
        instance_id,
        exit_code,
    };
    let mut writer = writer.lock().await;
    write_json_line(&mut *writer, &message).await
}

pub async fn send_main_process_finalized(
    writer: &Arc<Mutex<OwnedWriteHalf>>,
    instance_id: String,
) -> Result<()> {
    let message = WireClientMessage::MainProcessFinalized { instance_id };
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

fn canonicalize_sidecar_policy(
    policy: openshell_core::proto::SandboxPolicy,
    error_message: &'static str,
) -> Result<openshell_core::proto::SandboxPolicy> {
    // Bootstrap and update messages must expose the same canonical typed
    // policy to every process-supervisor consumer. Keep validation details
    // out of this channel error because they can contain authored values.
    openshell_policy::validate_and_canonicalize_sandbox_policy(policy)
        .map_err(|_| miette::miette!(error_message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{McpOptions, NetworkEndpoint, NetworkPolicyRule, SandboxPolicy};

    fn defaultable_mcp_policy(mcp: Option<McpOptions>) -> SandboxPolicy {
        let mut policy = openshell_policy::restrictive_default_policy();
        policy.network_policies.insert(
            "mcp".to_string(),
            NetworkPolicyRule {
                name: "mcp".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "mcp.example.com".to_string(),
                    port: 443,
                    protocol: "mcp".to_string(),
                    mcp,
                    rules: vec![openshell_core::proto::L7Rule {
                        allow: Some(openshell_core::proto::L7Allow {
                            method: "tools/list".to_string(),
                            ..Default::default()
                        }),
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        policy
    }

    fn mcp_versions(policy: &SandboxPolicy) -> &[String] {
        policy.network_policies["mcp"].endpoints[0]
            .mcp
            .as_ref()
            .expect("canonical MCP options")
            .versions
            .as_slice()
    }

    fn bootstrap_message(policy: &SandboxPolicy) -> WireServerMessage {
        WireServerMessage::BootstrapResponse {
            policy_proto: policy.encode_to_vec(),
            provider_env_revision: 0,
            provider_env_generation: 0,
            provider_child_env: HashMap::new(),
            agent_proposals_enabled: false,
            proxy_ca_cert_path: None,
            proxy_ca_bundle_path: None,
        }
    }

    fn policy_update_message(policy: &SandboxPolicy) -> WireServerMessage {
        WireServerMessage::PolicyUpdated {
            policy_proto: policy.encode_to_vec(),
            policy_hash: "hash".to_string(),
            config_revision: 1,
        }
    }

    fn current_peer() -> ExpectedPeer {
        ExpectedPeer {
            uid: nix::unistd::Uid::current().as_raw(),
            gid: nix::unistd::Gid::current().as_raw(),
        }
    }

    #[test]
    fn policy_messages_canonicalize_defaultable_mcp_versions() {
        for raw in [
            defaultable_mcp_policy(None),
            defaultable_mcp_policy(Some(McpOptions::default())),
        ] {
            let bootstrap = BootstrapData::try_from(bootstrap_message(&raw))
                .expect("defaultable MCP policy must pass bootstrap ingress");
            assert_eq!(mcp_versions(&bootstrap.policy_proto), ["2025-11-25"]);

            let update = ControlUpdate::try_from(policy_update_message(&raw))
                .expect("defaultable MCP policy must pass update ingress");
            let ControlUpdate::Policy { policy_proto, .. } = update else {
                panic!("expected policy update");
            };
            assert_eq!(mcp_versions(&policy_proto), ["2025-11-25"]);
        }
    }

    #[test]
    fn policy_messages_reject_invalid_mcp_versions_without_echoing_values() {
        let invalid = defaultable_mcp_policy(Some(McpOptions {
            versions: vec!["latest".to_string()],
            ..Default::default()
        }));

        let bootstrap_error = BootstrapData::try_from(bootstrap_message(&invalid))
            .expect_err("invalid MCP policy must not pass bootstrap ingress")
            .to_string();
        assert_eq!(
            bootstrap_error,
            "sidecar bootstrap policy failed validation"
        );
        assert!(!bootstrap_error.contains("latest"));

        let update_error = ControlUpdate::try_from(policy_update_message(&invalid))
            .expect_err("invalid MCP policy must not pass update ingress")
            .to_string();
        assert_eq!(update_error, "sidecar policy update failed validation");
        assert!(!update_error.contains("latest"));
    }

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
            provider_env_generation: 0,
            provider_child_env: env.clone(),
            agent_proposals_enabled: true,
            proxy_ca_cert_path: Some(PathBuf::from("/tmp/ca.pem")),
            proxy_ca_bundle_path: Some(PathBuf::from("/tmp/bundle.pem")),
        };

        let _server = spawn_server(&socket, bootstrap, current_peer()).unwrap();
        let (received, _connection) = connect_process_client(&socket, Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(received.policy_proto.version, 7);
        assert_eq!(received.provider_env_revision, 3);
        assert_eq!(received.provider_env_generation, 0);
        assert_eq!(received.provider_child_env, env);
        assert!(received.agent_proposals_enabled);
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
    async fn provider_env_updates_use_generation_not_fingerprint_order() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let server = spawn_server(
            &socket,
            BootstrapData {
                policy_proto: SandboxPolicy::default(),
                provider_env_revision: u64::MAX,
                provider_env_generation: 7,
                provider_child_env: HashMap::from([("TOKEN".to_string(), "first".to_string())]),
                agent_proposals_enabled: false,
                proxy_ca_cert_path: None,
                proxy_ca_bundle_path: None,
            },
            current_peer(),
        )
        .unwrap();
        let publisher = server.publisher();
        let (_bootstrap, mut connection) = connect_process_client(&socket, Duration::from_secs(1))
            .await
            .unwrap();

        publisher.publish_provider_env(
            1,
            HashMap::from([("TOKEN".to_string(), "second".to_string())]),
        );

        let update = tokio::time::timeout(Duration::from_secs(1), connection.updates.recv())
            .await
            .unwrap()
            .unwrap();
        match update {
            ControlUpdate::ProviderEnv {
                revision,
                generation,
                provider_child_env,
            } => {
                assert_eq!(revision, 1);
                assert_eq!(generation, 8);
                assert_eq!(
                    provider_child_env.get("TOKEN").map(String::as_str),
                    Some("second")
                );
            }
            other => panic!("unexpected sidecar update: {other:?}"),
        }

        publisher.publish_provider_env(
            1,
            HashMap::from([("TOKEN".to_string(), "duplicate".to_string())]),
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), connection.updates.recv())
                .await
                .is_err(),
            "an identical fingerprint must remain a no-op"
        );

        publisher.publish_provider_env(
            u64::MAX,
            HashMap::from([("TOKEN".to_string(), "third".to_string())]),
        );
        let update = tokio::time::timeout(Duration::from_secs(1), connection.updates.recv())
            .await
            .unwrap()
            .unwrap();
        match update {
            ControlUpdate::ProviderEnv {
                revision,
                generation,
                provider_child_env,
            } => {
                assert_eq!(revision, u64::MAX);
                assert_eq!(generation, 9);
                assert_eq!(
                    provider_child_env.get("TOKEN").map(String::as_str),
                    Some("third")
                );
            }
            other => panic!("unexpected sidecar update: {other:?}"),
        }
    }

    #[tokio::test]
    async fn agent_proposals_update_is_delivered_to_process_client() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let server = spawn_server(
            &socket,
            BootstrapData {
                policy_proto: SandboxPolicy::default(),
                provider_env_revision: 0,
                provider_env_generation: 0,
                provider_child_env: HashMap::new(),
                agent_proposals_enabled: false,
                proxy_ca_cert_path: None,
                proxy_ca_bundle_path: None,
            },
            current_peer(),
        )
        .unwrap();
        let publisher = server.publisher();
        let (_bootstrap, mut connection) = connect_process_client(&socket, Duration::from_secs(1))
            .await
            .unwrap();

        publisher.publish_agent_proposals(true, 9);

        let update = tokio::time::timeout(Duration::from_secs(1), connection.updates.recv())
            .await
            .unwrap()
            .unwrap();
        match update {
            ControlUpdate::AgentProposals {
                enabled,
                config_revision,
            } => {
                assert!(enabled);
                assert_eq!(config_revision, 9);
            }
            other => panic!("unexpected sidecar update: {other:?}"),
        }
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
                provider_env_generation: 0,
                provider_child_env: HashMap::new(),
                agent_proposals_enabled: false,
                proxy_ca_cert_path: None,
                proxy_ca_bundle_path: None,
            },
            current_peer(),
        )
        .unwrap();
        let publisher = server.publisher();
        let mut entrypoint_rx = server.into_entrypoint_receiver();
        let (_bootstrap, mut connection) = connect_process_client(&socket, Duration::from_secs(1))
            .await
            .unwrap();

        let anchor = tokio::time::timeout(Duration::from_secs(1), entrypoint_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(anchor.pid, std::process::id());
        assert!(!anchor.start_session);

        send_entrypoint_started(&connection.writer, 4242, "instance-1".to_string())
            .await
            .unwrap();

        let started = tokio::time::timeout(Duration::from_secs(1), entrypoint_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(started.pid, 4242);
        assert!(started.start_session);
        assert_eq!(started.instance_id, "instance-1");
        assert!(started.exit_code.is_none());

        send_main_process_exited(&connection.writer, "instance-1".to_string(), 0)
            .await
            .unwrap();
        let terminal = tokio::time::timeout(Duration::from_secs(1), entrypoint_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(terminal.exit_code, Some(0));
        assert!(!terminal.finalized);

        assert!(
            tokio::time::timeout(Duration::from_millis(20), connection.updates.recv())
                .await
                .is_err(),
            "process side must not observe a durable ACK before gateway persistence"
        );
        publisher.publish_main_process_exit_ack("instance-1".to_string());
        let ack = tokio::time::timeout(Duration::from_secs(1), connection.updates.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            ack,
            ControlUpdate::MainProcessExitAck { instance_id } if instance_id == "instance-1"
        ));

        send_main_process_finalized(&connection.writer, "instance-1".to_string())
            .await
            .unwrap();
        let delivered = tokio::time::timeout(Duration::from_secs(1), entrypoint_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(delivered.exit_code.is_none());
        assert!(delivered.finalized);
    }

    #[tokio::test]
    async fn second_control_client_is_rejected_after_authoritative_bootstrap() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let _server = spawn_server(
            &socket,
            BootstrapData {
                policy_proto: SandboxPolicy::default(),
                provider_env_revision: 0,
                provider_env_generation: 0,
                provider_child_env: HashMap::new(),
                agent_proposals_enabled: false,
                proxy_ca_cert_path: None,
                proxy_ca_bundle_path: None,
            },
            current_peer(),
        )
        .unwrap();

        let (_bootstrap, _connection) = connect_process_client(&socket, Duration::from_secs(1))
            .await
            .unwrap();

        let err = tokio::net::UnixStream::connect(&socket)
            .await
            .expect_err("control listener must be removed after the first bootstrap");
        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ),
            "unexpected second-client error: {err}"
        );
    }

    #[tokio::test]
    async fn authoritative_connection_task_ends_when_process_supervisor_disconnects() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let server = spawn_server(
            &socket,
            BootstrapData {
                policy_proto: SandboxPolicy::default(),
                provider_env_revision: 0,
                provider_env_generation: 0,
                provider_child_env: HashMap::new(),
                agent_proposals_enabled: false,
                proxy_ca_cert_path: None,
                proxy_ca_bundle_path: None,
            },
            current_peer(),
        )
        .unwrap();
        let (_entrypoint_rx, connection_task) = server.into_runtime_parts();
        let (_bootstrap, connection) = connect_process_client(&socket, Duration::from_secs(1))
            .await
            .unwrap();

        drop(connection);
        tokio::time::timeout(Duration::from_secs(1), connection_task)
            .await
            .expect("server must observe authoritative client disconnect")
            .expect("control task must not panic");
    }

    #[tokio::test]
    async fn process_client_reports_network_sidecar_restart() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let server = spawn_server(
            &socket,
            BootstrapData {
                policy_proto: SandboxPolicy::default(),
                provider_env_revision: 0,
                provider_env_generation: 0,
                provider_child_env: HashMap::new(),
                agent_proposals_enabled: false,
                proxy_ca_cert_path: None,
                proxy_ca_bundle_path: None,
            },
            current_peer(),
        )
        .unwrap();
        let (_entrypoint_rx, connection_task) = server.into_runtime_parts();
        let (_bootstrap, connection) = connect_process_client(&socket, Duration::from_secs(1))
            .await
            .unwrap();

        connection_task.abort();
        let _ = connection_task.await;
        tokio::time::timeout(Duration::from_secs(1), connection.closed)
            .await
            .expect("process supervisor must observe network sidecar disconnect")
            .expect("disconnect notifier must remain live");
    }

    #[tokio::test]
    async fn bootstrap_rejects_claimed_pid_that_does_not_match_peer_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let server = spawn_server(
            &socket,
            BootstrapData {
                policy_proto: SandboxPolicy::default(),
                provider_env_revision: 0,
                provider_env_generation: 0,
                provider_child_env: HashMap::new(),
                agent_proposals_enabled: false,
                proxy_ca_cert_path: None,
                proxy_ca_bundle_path: None,
            },
            current_peer(),
        )
        .unwrap();
        let mut entrypoint_rx = server.into_entrypoint_receiver();

        let mut stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
        write_json_line(
            &mut stream,
            &WireClientMessage::BootstrapRequest {
                supervisor_pid: std::process::id().saturating_add(1),
            },
        )
        .await
        .unwrap();

        assert!(
            tokio::time::timeout(Duration::from_secs(1), entrypoint_rx.recv())
                .await
                .unwrap()
                .is_none(),
            "mismatched bootstrap must not publish a process anchor"
        );
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
