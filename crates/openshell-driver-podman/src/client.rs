// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Thin async HTTP client for the Podman REST API over a Unix socket.

use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tracing::debug;

/// Podman libpod API version prefix.
const API_VERSION: &str = "v5.0.0";

/// Timeout for individual Podman API calls.
const API_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum allowed size for the event stream line buffer (1 MB).
const MAX_EVENT_BUFFER: usize = 1_048_576;

#[derive(Debug, thiserror::Error)]
pub enum PodmanApiError {
    #[error("podman API not found (404): {0}")]
    NotFound(String),
    #[error("podman API conflict (409): {0}")]
    Conflict(String),
    #[error("podman API error ({status}): {message}")]
    Api { status: u16, message: String },
    #[error("connection error: {0}")]
    Connection(String),
    #[error("timeout after {0:?}")]
    Timeout(Duration),
    #[error("JSON error: {0}")]
    Json(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

/// Maximum resource name length. Podman container names become directory
/// names in the storage driver, so we cap at 255 to stay within ext4/xfs
/// filename limits.
const MAX_NAME_LEN: usize = 255;

/// Validate that a resource name is safe for URL path interpolation.
///
/// Valid names start with an alphanumeric character and contain only
/// alphanumerics, dots, underscores, and hyphens — matching Podman's
/// own naming rules. Names longer than [`MAX_NAME_LEN`] are rejected.
pub fn validate_name(name: &str) -> Result<(), PodmanApiError> {
    // Regex-equivalent: ^[a-zA-Z0-9][a-zA-Z0-9._-]*$
    if name.is_empty() {
        return Err(PodmanApiError::InvalidInput(
            "name must not be empty".to_string(),
        ));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(PodmanApiError::InvalidInput(format!(
            "name exceeds maximum length of {MAX_NAME_LEN} characters (got {})",
            name.len()
        )));
    }
    let bytes = name.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        return Err(PodmanApiError::InvalidInput(format!(
            "name must start with an alphanumeric character: {name:?}"
        )));
    }
    if !bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
    {
        return Err(PodmanApiError::InvalidInput(format!(
            "name contains invalid characters: {name:?}"
        )));
    }
    Ok(())
}

/// A container state snapshot returned by inspect APIs.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerInspect {
    pub id: String,
    pub name: String,
    pub state: ContainerState,
    #[serde(default)]
    #[allow(dead_code)] // kept for podman API compat
    pub network_settings: NetworkSettings,
    #[serde(default)]
    pub config: ContainerConfig,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerState {
    pub status: String,
    #[allow(dead_code)] // kept for podman API compat
    pub running: bool,
    #[serde(default)]
    pub exit_code: i64,
    #[serde(rename = "OOMKilled")]
    #[serde(default)]
    pub oom_killed: bool,
    #[serde(default)]
    pub health: Option<HealthState>,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HealthState {
    pub status: String,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkSettings {
    #[serde(default)]
    #[allow(dead_code)] // kept for podman API compat
    pub networks: HashMap<String, NetworkInfo>,
    #[serde(default)]
    #[allow(dead_code)] // kept for podman API compat
    pub ports: HashMap<String, Option<Vec<PortBinding>>>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkInfo {
    #[serde(rename = "IPAddress")]
    #[serde(default)]
    #[allow(dead_code)] // kept for podman API compat
    pub ip_address: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PortBinding {
    #[serde(default)]
    #[allow(dead_code)] // kept for podman API compat
    pub host_port: String,
    #[serde(rename = "HostIp")]
    #[serde(default)]
    #[allow(dead_code)] // kept for podman API compat
    pub host_ip: String,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerConfig {
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

/// A container summary returned by the list API.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerListEntry {
    pub id: String,
    #[serde(default)]
    pub names: Vec<String>,
    pub state: String,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    #[allow(dead_code)] // kept for podman API compat
    pub ports: Option<Vec<PortMappingEntry>>,
    #[serde(default)]
    #[allow(dead_code)] // kept for podman API compat
    pub networks: Option<Vec<String>>,
    #[serde(default)]
    #[allow(dead_code)] // kept for podman API compat
    pub exit_code: i64,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct PortMappingEntry {
    #[allow(dead_code)] // kept for podman API compat
    pub host_port: u16,
    #[allow(dead_code)] // kept for podman API compat
    pub container_port: u16,
    #[allow(dead_code)] // kept for podman API compat
    pub protocol: String,
    #[serde(default)]
    #[allow(dead_code)] // kept for podman API compat
    pub host_ip: String,
}

/// A Podman event from the events stream.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PodmanEvent {
    #[serde(rename = "Type")]
    #[allow(dead_code)] // kept for podman API compat
    pub event_type: String,
    pub action: String,
    #[serde(default)]
    pub actor: EventActor,
    #[serde(rename = "timeNano", default)]
    #[allow(dead_code)] // kept for podman API compat
    pub time_nano: i64,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EventActor {
    #[serde(rename = "ID")]
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub attributes: HashMap<String, String>,
}

/// System info response (subset of fields we care about).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SystemInfo {
    pub host: HostInfo,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostInfo {
    #[serde(default)]
    pub cgroup_version: String,
    #[serde(default)]
    pub network_backend: String,
    #[serde(default)]
    pub security: SecurityInfo,
}

/// Security-related fields from the Podman system info response.
///
/// Podman returns `host.security.rootless: true` when the daemon is
/// running without root privileges (rootless mode).
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct SecurityInfo {
    #[serde(default)]
    pub rootless: bool,
}

// ── Client ───────────────────────────────────────────────────────────────

/// Async Podman REST API client communicating over a Unix socket.
#[derive(Debug, Clone)]
pub struct PodmanClient {
    socket_path: PathBuf,
}

impl PodmanClient {
    /// Create a new client targeting the given socket path.
    #[must_use]
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// Open a new HTTP/1.1 connection to the Podman socket.
    async fn connect(
        &self,
    ) -> Result<hyper::client::conn::http1::SendRequest<Full<Bytes>>, PodmanApiError> {
        let stream = UnixStream::connect(&self.socket_path).await.map_err(|e| {
            PodmanApiError::Connection(format!("{}: {e}", self.socket_path.display()))
        })?;

        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| PodmanApiError::Connection(e.to_string()))?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!(error = %e, "Podman API connection closed");
            }
        });

        Ok(sender)
    }

    // ── Request infrastructure ───────────────────────────────────────────

    /// Build an HTTP request from components.
    fn build_request(
        method: hyper::Method,
        path: &str,
        body: Full<Bytes>,
        content_type: Option<&str>,
    ) -> Request<Full<Bytes>> {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("http://localhost{path}"))
            .header("Host", "localhost");
        if let Some(ct) = content_type {
            builder = builder.header("Content-Type", ct);
        }
        builder.body(body).expect("valid request")
    }

    /// Send a pre-built HTTP request and return status + body bytes.
    async fn send_request(
        &self,
        req: Request<Full<Bytes>>,
        timeout: Duration,
    ) -> Result<(hyper::StatusCode, Bytes), PodmanApiError> {
        let mut sender = self.connect().await?;
        let response = tokio::time::timeout(timeout, sender.send_request(req))
            .await
            .map_err(|_| PodmanApiError::Timeout(timeout))?
            .map_err(|e| PodmanApiError::Connection(e.to_string()))?;
        let status = response.status();
        let bytes = tokio::time::timeout(timeout, response.into_body().collect())
            .await
            .map_err(|_| PodmanApiError::Timeout(timeout))?
            .map_err(|e| PodmanApiError::Connection(e.to_string()))?
            .to_bytes();
        Ok((status, bytes))
    }

    /// Perform a versioned HTTP request and return status + body bytes.
    async fn request(
        &self,
        method: hyper::Method,
        path: &str,
        body: Option<&Value>,
        timeout: Duration,
    ) -> Result<(hyper::StatusCode, Bytes), PodmanApiError> {
        let (full_body, content_type) = match body {
            Some(json) => {
                let payload =
                    serde_json::to_vec(json).map_err(|e| PodmanApiError::Json(e.to_string()))?;
                (Full::new(Bytes::from(payload)), Some("application/json"))
            }
            None => (Full::new(Bytes::new()), None),
        };
        let req = Self::build_request(
            method,
            &format!("/{API_VERSION}{path}"),
            full_body,
            content_type,
        );
        self.send_request(req, timeout).await
    }

    /// Perform a request and deserialize the JSON response.
    async fn request_json<T: DeserializeOwned>(
        &self,
        method: hyper::Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<T, PodmanApiError> {
        let (status, bytes) = self.request(method, path, body, API_TIMEOUT).await?;
        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(|e| {
                PodmanApiError::Json(format!("{e}: {}", String::from_utf8_lossy(&bytes)))
            })
        } else {
            Err(error_from_response(status.as_u16(), &bytes))
        }
    }

    /// Perform a request that returns no meaningful body.
    async fn request_ok(
        &self,
        method: hyper::Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(), PodmanApiError> {
        let (status, bytes) = self.request(method, path, body, API_TIMEOUT).await?;
        let code = status.as_u16();
        if status.is_success() || code == 304 {
            Ok(())
        } else {
            Err(error_from_response(code, &bytes))
        }
    }

    /// Perform a versioned HTTP request with a raw byte body (not JSON).
    async fn request_raw(
        &self,
        method: hyper::Method,
        path: &str,
        content_type: &str,
        body: Bytes,
    ) -> Result<(hyper::StatusCode, Bytes), PodmanApiError> {
        let req = Self::build_request(
            method,
            &format!("/{API_VERSION}{path}"),
            Full::new(body),
            Some(content_type),
        );
        self.send_request(req, API_TIMEOUT).await
    }

    /// POST a JSON body and ignore 409 Conflict (resource already exists).
    async fn create_ignore_conflict(&self, path: &str, body: &Value) -> Result<(), PodmanApiError> {
        match self
            .request_json::<Value>(hyper::Method::POST, path, Some(body))
            .await
        {
            Ok(_) | Err(PodmanApiError::Conflict(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    // ── Container operations ─────────────────────────────────────────────

    /// Create a container from a JSON spec.
    pub async fn create_container(&self, spec: &Value) -> Result<Value, PodmanApiError> {
        self.request_json(hyper::Method::POST, "/libpod/containers/create", Some(spec))
            .await
    }

    /// Start a container by name or ID.
    pub async fn start_container(&self, name: &str) -> Result<(), PodmanApiError> {
        validate_name(name)?;
        self.request_ok(
            hyper::Method::POST,
            &format!("/libpod/containers/{name}/start"),
            None,
        )
        .await
    }

    /// Stop a container with a grace period in seconds.
    pub async fn stop_container(
        &self,
        name: &str,
        timeout_secs: u32,
    ) -> Result<(), PodmanApiError> {
        validate_name(name)?;
        let http_timeout = Duration::from_secs(u64::from(timeout_secs) + 5);
        let (status, bytes) = self
            .request(
                hyper::Method::POST,
                &format!("/libpod/containers/{name}/stop?timeout={timeout_secs}"),
                None,
                http_timeout,
            )
            .await?;
        let code = status.as_u16();
        if status.is_success() || code == 304 {
            Ok(())
        } else {
            Err(error_from_response(code, &bytes))
        }
    }

    /// Force-remove a container and its anonymous volumes.
    pub async fn remove_container(&self, name: &str) -> Result<(), PodmanApiError> {
        validate_name(name)?;
        self.request_ok(
            hyper::Method::DELETE,
            &format!("/libpod/containers/{name}?force=true&v=true"),
            None,
        )
        .await
    }

    /// Inspect a container by name or ID.
    pub async fn inspect_container(&self, name: &str) -> Result<ContainerInspect, PodmanApiError> {
        validate_name(name)?;
        self.request_json(
            hyper::Method::GET,
            &format!("/libpod/containers/{name}/json"),
            None,
        )
        .await
    }

    /// List containers matching a label filter (e.g. `"openshell.managed=true"`).
    pub async fn list_containers(
        &self,
        label_filter: &str,
    ) -> Result<Vec<ContainerListEntry>, PodmanApiError> {
        let filters = serde_json::json!({"label": [label_filter]});
        let encoded = url_encode(&filters.to_string());
        self.request_json(
            hyper::Method::GET,
            &format!("/libpod/containers/json?all=true&filters={encoded}"),
            None,
        )
        .await
    }

    // ── Volume operations ────────────────────────────────────────────────

    /// Create a named volume. Idempotent (conflict is ignored).
    pub async fn create_volume(&self, name: &str) -> Result<(), PodmanApiError> {
        validate_name(name)?;
        self.create_ignore_conflict("/libpod/volumes/create", &serde_json::json!({"Name": name}))
            .await
    }

    /// Remove a named volume. Idempotent (not-found is ignored).
    pub async fn remove_volume(&self, name: &str) -> Result<(), PodmanApiError> {
        validate_name(name)?;
        match self
            .request_ok(
                hyper::Method::DELETE,
                &format!("/libpod/volumes/{name}"),
                None,
            )
            .await
        {
            Ok(()) | Err(PodmanApiError::NotFound(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    // ── Network operations ───────────────────────────────────────────────

    /// Create a bridge network with DNS enabled. Idempotent.
    pub async fn ensure_network(&self, name: &str) -> Result<(), PodmanApiError> {
        validate_name(name)?;
        self.create_ignore_conflict(
            "/libpod/networks/create",
            &serde_json::json!({
                "name": name,
                "driver": "bridge",
                "dns_enabled": true,
            }),
        )
        .await
    }

    /// Inspect a network and return the gateway IP of its first subnet.
    ///
    /// The gateway IP is the host's address on the bridge network, used by
    /// sandbox containers to call back to the gateway server.
    pub async fn network_gateway_ip(&self, name: &str) -> Result<Option<String>, PodmanApiError> {
        validate_name(name)?;
        let encoded = url_encode(name);
        let path = format!("/libpod/networks/{encoded}/json");
        let resp: Value = self.request_json(hyper::Method::GET, &path, None).await?;
        // The response has "subnets": [{"gateway": "10.89.1.1", "subnet": "..."}]
        let gateway = resp
            .get("subnets")
            .and_then(|s| s.as_array())
            .and_then(|arr| arr.first())
            .and_then(|sub| sub.get("gateway"))
            .and_then(|g| g.as_str())
            .map(String::from);
        Ok(gateway)
    }

    // ── Secret operations ────────────────────────────────────────────────

    /// Create a Podman secret with the given name and raw value.
    ///
    /// Idempotent: if a secret with the same name already exists it is
    /// replaced (delete + recreate) so the value is always up-to-date.
    pub async fn create_secret(&self, name: &str, value: &[u8]) -> Result<(), PodmanApiError> {
        validate_name(name)?;
        let encoded_name = url_encode(name);
        let path = format!("/libpod/secrets/create?name={encoded_name}");
        let (status, bytes) = self
            .request_raw(
                hyper::Method::POST,
                &path,
                "application/octet-stream",
                Bytes::copy_from_slice(value),
            )
            .await?;

        match status.as_u16() {
            200 | 201 => Ok(()),
            409 => {
                // Secret already exists — replace it.
                self.remove_secret(name).await?;
                let (status2, bytes2) = self
                    .request_raw(
                        hyper::Method::POST,
                        &path,
                        "application/octet-stream",
                        Bytes::copy_from_slice(value),
                    )
                    .await?;
                if status2.is_success() {
                    Ok(())
                } else {
                    Err(error_from_response(status2.as_u16(), &bytes2))
                }
            }
            _ => Err(error_from_response(status.as_u16(), &bytes)),
        }
    }

    /// Remove a Podman secret by name. Idempotent (not-found is ignored).
    pub async fn remove_secret(&self, name: &str) -> Result<(), PodmanApiError> {
        validate_name(name)?;
        match self
            .request_ok(
                hyper::Method::DELETE,
                &format!("/libpod/secrets/{name}"),
                None,
            )
            .await
        {
            Ok(()) | Err(PodmanApiError::NotFound(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    // ── Image operations ────────────────────────────────────────────────

    /// Pull an image if it is not already present locally.
    ///
    /// Uses the `policy` parameter to decide whether to pull:
    /// - `"always"` — always pull, even if a local copy exists
    /// - `"missing"` — pull only when no local copy exists (default)
    /// - `"never"` — never pull, fail if not local
    /// - `"newer"` — pull only if the remote image is newer
    ///
    /// The pull `policy` is passed directly to Podman's API so that
    /// Podman handles local-image resolution and registry fallback
    /// natively. This avoids name-resolution mismatches between the
    /// exists API and the local image store (e.g. `openshell/supervisor:dev`
    /// vs `localhost/openshell/supervisor:dev`).
    ///
    /// The Podman pull endpoint streams NDJSON progress. We consume the
    /// entire stream and check for an `error` field in the final object.
    pub async fn pull_image(&self, reference: &str, policy: &str) -> Result<(), PodmanApiError> {
        let path = format!(
            "/libpod/images/pull?reference={}&policy={}",
            url_encode(reference),
            url_encode(policy),
        );
        // Image pulls can be slow — use a generous timeout.
        let pull_timeout = Duration::from_secs(600);
        let (status, bytes) = self
            .request(hyper::Method::POST, &path, None, pull_timeout)
            .await?;
        if !status.is_success() {
            return Err(error_from_response(status.as_u16(), &bytes));
        }
        // The response is NDJSON. Check the last line for an error field.
        let body = String::from_utf8_lossy(&bytes);
        if let Some(last_line) = body.lines().rfind(|l| !l.is_empty())
            && let Ok(obj) = serde_json::from_str::<Value>(last_line)
            && let Some(err) = obj.get("error").and_then(|v| v.as_str())
            && !err.is_empty()
        {
            return Err(PodmanApiError::Api {
                status: 500,
                message: format!("image pull failed: {err}"),
            });
        }
        Ok(())
    }

    // ── System operations ────────────────────────────────────────────────

    /// Ping the Podman API to verify connectivity.
    pub async fn ping(&self) -> Result<(), PodmanApiError> {
        // _ping is outside the versioned API path.
        let req = Self::build_request(hyper::Method::GET, "/_ping", Full::new(Bytes::new()), None);
        let (status, _) = self.send_request(req, API_TIMEOUT).await?;
        if status.is_success() {
            Ok(())
        } else {
            Err(PodmanApiError::Api {
                status: status.as_u16(),
                message: "ping failed".to_string(),
            })
        }
    }

    /// Get system info.
    pub async fn system_info(&self) -> Result<SystemInfo, PodmanApiError> {
        self.request_json(hyper::Method::GET, "/libpod/info", None)
            .await
    }

    // ── Event streaming ──────────────────────────────────────────────────

    /// Start streaming container events filtered by label.
    ///
    /// Events are sent to the returned receiver. The background task runs
    /// until the receiver is dropped.
    pub async fn events_stream(
        &self,
        label_filter: &str,
    ) -> Result<mpsc::Receiver<Result<PodmanEvent, PodmanApiError>>, PodmanApiError> {
        let filters = serde_json::json!({
            "label": [label_filter],
            "type": ["container"],
        });
        let encoded = url_encode(&filters.to_string());
        let path =
            format!("http://localhost/{API_VERSION}/libpod/events?stream=true&filters={encoded}");

        let mut sender = self.connect().await?;

        let req = Request::builder()
            .method(hyper::Method::GET)
            .uri(&path)
            .header("Host", "localhost")
            .body(Full::new(Bytes::new()))
            .map_err(|e| PodmanApiError::Connection(e.to_string()))?;

        let response = tokio::time::timeout(API_TIMEOUT, sender.send_request(req))
            .await
            .map_err(|_| PodmanApiError::Timeout(API_TIMEOUT))?
            .map_err(|e| PodmanApiError::Connection(e.to_string()))?;

        if !response.status().is_success() {
            return Err(PodmanApiError::Api {
                status: response.status().as_u16(),
                message: "events stream request failed".to_string(),
            });
        }

        let (tx, rx) = mpsc::channel(256);
        let body = response.into_body();

        tokio::spawn(async move {
            let mut buffer = Vec::new();
            let mut body = body;

            loop {
                use hyper::body::Body;

                let frame =
                    match std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
                        Some(Ok(frame)) => frame,
                        Some(Err(e)) => {
                            let _ = tx
                                .send(Err(PodmanApiError::Connection(e.to_string())))
                                .await;
                            break;
                        }
                        None => break,
                    };

                if let Some(data) = frame.data_ref() {
                    buffer.extend_from_slice(data);
                }

                if buffer.len() > MAX_EVENT_BUFFER {
                    tracing::error!("event stream buffer exceeded maximum size, disconnecting");
                    let _ = tx
                        .send(Err(PodmanApiError::Connection(
                            "event buffer exceeded 1 MB limit".to_string(),
                        )))
                        .await;
                    break;
                }

                // Parse complete newline-delimited JSON lines.
                while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = buffer.drain(..=pos).collect();
                    let trimmed = line.strip_suffix(b"\n").unwrap_or(&line);
                    if trimmed.is_empty() {
                        continue;
                    }
                    let event = serde_json::from_slice::<PodmanEvent>(trimmed).map_err(|e| {
                        PodmanApiError::Json(format!("{e}: {}", String::from_utf8_lossy(trimmed)))
                    });
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }
        });

        Ok(rx)
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn error_from_response(status: u16, bytes: &Bytes) -> PodmanApiError {
    let message = serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|v| {
            v.get("message")
                .or_else(|| v.get("cause"))
                .and_then(Value::as_str)
                .map(String::from)
        })
        .unwrap_or_else(|| String::from_utf8_lossy(bytes).to_string());

    match status {
        404 => PodmanApiError::NotFound(message),
        409 => PodmanApiError::Conflict(message),
        _ => PodmanApiError::Api { status, message },
    }
}

/// Minimal percent-encoding for query parameter values.
///
/// Note: `percent-encoding` is available as a transitive dependency but is not
/// a direct dependency of this crate. Rather than adding a new dep for one
/// call site, we keep this self-contained implementation.
fn url_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                String::from(b as char)
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encode_encodes_special_characters() {
        assert_eq!(url_encode("hello world"), "hello%20world");
        assert_eq!(url_encode("a=b&c=d"), "a%3Db%26c%3Dd");
        assert_eq!(url_encode("safe-_.~chars"), "safe-_.~chars");
    }

    #[test]
    fn validate_name_accepts_valid_names() {
        // alphanumeric, dots, hyphens, underscores
        assert!(validate_name("my-container").is_ok());
        assert!(validate_name("my_container.v2").is_ok());
        assert!(validate_name("a").is_ok());
        assert!(validate_name("Container123").is_ok());
    }

    #[test]
    fn validate_name_rejects_invalid_names() {
        assert!(validate_name("").is_err()); // empty
        assert!(validate_name("-leading").is_err()); // starts with dash
        assert!(validate_name(".leading").is_err()); // starts with dot
        assert!(validate_name("has/slash").is_err()); // path traversal
        assert!(validate_name("../etc").is_err()); // path traversal
        assert!(validate_name("has space").is_err()); // space
        assert!(validate_name("has%20encoded").is_err()); // percent
        assert!(validate_name("has?query").is_err()); // query char
    }

    #[test]
    fn validate_name_rejects_names_exceeding_max_length() {
        let long_name = format!("a{}", "b".repeat(MAX_NAME_LEN));
        assert!(long_name.len() > MAX_NAME_LEN);
        assert!(validate_name(&long_name).is_err());

        // Exactly at the limit should be accepted.
        let exact_name = "a".repeat(MAX_NAME_LEN);
        assert!(validate_name(&exact_name).is_ok());
    }
}
