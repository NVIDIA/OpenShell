// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! BoxLite VM-based sandbox backend via REST API.
//!
//! Communicates with a running BoxLite server (`boxlite serve` or
//! `boxlite-server coordinator`) over HTTP to create and manage VMs.
//!
//! This backend provides:
//! - Hardware-level memory isolation (VM boundary)
//! - Independent kernel (guest cannot attack host kernel)
//! - Network isolation via VM boundary
//! - Cross-platform support (Linux + macOS ARM64)
//!
//! No `boxlite` library is linked — all interaction is via REST API,
//! avoiding native dependency conflicts (e.g., sqlite version mismatches).

use miette::{IntoDiagnostic, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

use super::{SandboxedProcess, SpawnConfig};
use crate::process::ProcessStatus;

/// Default BoxLite server URL.
const DEFAULT_BOXLITE_URL: &str = "http://127.0.0.1:8100";

/// Default API namespace.
const DEFAULT_NAMESPACE: &str = "default";

/// Environment variable for BoxLite server URL.
const BOXLITE_URL_ENV: &str = "BOXLITE_URL";

/// Default VM resources for sandbox workloads.
const DEFAULT_CPUS: u8 = 2;
const DEFAULT_MEMORY_MIB: u32 = 512;

// ============================================================================
// REST API request/response types (subset of BoxLite's OpenAPI schema)
// ============================================================================

#[derive(Debug, Serialize)]
struct CreateBoxRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpus: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    memory_mib: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    working_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    env: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auto_remove: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct BoxResponse {
    box_id: String,
    #[allow(dead_code)]
    status: String,
}

#[derive(Debug, Serialize)]
struct ExecRequest {
    command: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    env: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    working_dir: Option<String>,
    #[serde(default)]
    tty: bool,
}

#[derive(Debug, Deserialize)]
struct ExecResponse {
    execution_id: String,
}

#[derive(Debug, Serialize)]
struct SignalRequest {
    signal: i32,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: ErrorModel,
}

#[derive(Debug, Deserialize)]
struct ErrorModel {
    message: String,
}

#[derive(Debug, Deserialize)]
struct SseExitData {
    exit_code: i32,
}

// ============================================================================
// Backend implementation
// ============================================================================

/// BoxLite VM-based sandbox backend.
///
/// Talks to a BoxLite REST server to create VMs and run commands.
pub struct BoxliteBackend {
    client: Client,
    base_url: String,
    namespace: String,
}

impl BoxliteBackend {
    /// Create a new BoxLite REST backend.
    ///
    /// Reads the server URL from `BOXLITE_URL` env var, or defaults
    /// to `http://127.0.0.1:8100`.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client fails to initialize.
    pub fn new() -> Result<Self> {
        let base_url =
            std::env::var(BOXLITE_URL_ENV).unwrap_or_else(|_| DEFAULT_BOXLITE_URL.to_string());

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .into_diagnostic()?;

        info!(url = %base_url, "BoxLite REST backend initialized");

        Ok(Self {
            client,
            base_url,
            namespace: DEFAULT_NAMESPACE.to_string(),
        })
    }

    fn boxes_url(&self) -> String {
        format!("{}/v1/{}/boxes", self.base_url, self.namespace)
    }

    /// Spawn an agent process inside a BoxLite VM via REST API.
    ///
    /// 1. Creates a VM from the specified container image
    /// 2. Executes the agent command inside the VM
    /// 3. Returns a handle to wait for completion
    ///
    /// # Errors
    ///
    /// Returns an error if the BoxLite server is unreachable or rejects the request.
    pub async fn spawn(&self, config: &SpawnConfig) -> Result<SandboxedProcess> {
        let image = config.image.as_deref().unwrap_or("alpine:latest");

        let env = if config.env.is_empty() {
            None
        } else {
            Some(config.env.clone())
        };

        // Step 1: Create box
        let create_req = CreateBoxRequest {
            image: Some(image.to_string()),
            cpus: Some(DEFAULT_CPUS),
            memory_mib: Some(DEFAULT_MEMORY_MIB),
            working_dir: config.workdir.clone(),
            env: env.clone(),
            auto_remove: Some(true),
        };

        let resp = self
            .client
            .post(self.boxes_url())
            .json(&create_req)
            .send()
            .await
            .into_diagnostic()?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            let msg = serde_json::from_str::<ErrorResponse>(&body)
                .map(|e| e.error.message)
                .unwrap_or(body);
            return Err(miette::miette!(
                "BoxLite create failed ({}): {}",
                status,
                msg
            ));
        }

        let box_resp: BoxResponse = resp.json().await.into_diagnostic()?;
        let box_id = box_resp.box_id;
        info!(box_id = %box_id, image = %image, "BoxLite VM created");

        // Step 2: Execute command
        let exec_req = ExecRequest {
            command: config.program.clone(),
            args: config.args.clone(),
            env,
            working_dir: config.workdir.clone(),
            tty: config.interactive,
        };

        let exec_url = format!("{}/{}/exec", self.boxes_url(), box_id);
        let resp = self
            .client
            .post(&exec_url)
            .json(&exec_req)
            .send()
            .await
            .into_diagnostic()?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            let msg = serde_json::from_str::<ErrorResponse>(&body)
                .map(|e| e.error.message)
                .unwrap_or(body);
            return Err(miette::miette!("BoxLite exec failed ({}): {}", status, msg));
        }

        let exec_resp: ExecResponse = resp.json().await.into_diagnostic()?;
        debug!(
            box_id = %box_id,
            execution_id = %exec_resp.execution_id,
            "Command started in BoxLite VM"
        );

        Ok(SandboxedProcess::Boxlite(BoxliteProcess {
            client: self.client.clone(),
            boxes_url: self.boxes_url(),
            box_id,
            execution_id: exec_resp.execution_id,
        }))
    }
}

/// Handle to a process running inside a BoxLite VM.
pub struct BoxliteProcess {
    client: Client,
    boxes_url: String,
    box_id: String,
    execution_id: String,
}

impl BoxliteProcess {
    /// Get the box identifier (hashed to u32 for PID-based API compat).
    #[must_use]
    pub fn id(&self) -> u32 {
        let bytes = self.box_id.as_bytes();
        let mut hash: u32 = 0;
        for &b in bytes {
            hash = hash.wrapping_mul(31).wrapping_add(u32::from(b));
        }
        // PIDs are always > 0
        if hash == 0 { 1 } else { hash }
    }

    /// Wait for the VM process to exit by streaming SSE output.
    ///
    /// Connects to the BoxLite execution output SSE endpoint and waits
    /// for the `exit` event containing the exit code.
    ///
    /// # Errors
    ///
    /// Returns an error if the SSE connection fails.
    pub async fn wait(&mut self) -> std::io::Result<ProcessStatus> {
        let output_url = format!(
            "{}/{}/executions/{}/output",
            self.boxes_url, self.box_id, self.execution_id
        );

        let resp = self
            .client
            .get(&output_url)
            .header("Accept", "text/event-stream")
            .send()
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(std::io::Error::other(format!(
                "BoxLite output stream failed: {}",
                resp.status()
            )));
        }

        // Parse SSE stream for the exit event
        let body = resp
            .text()
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let exit_code = parse_sse_exit_code(&body).unwrap_or(-1);

        info!(box_id = %self.box_id, exit_code, "BoxLite VM process exited");

        // Stop the VM
        let stop_url = format!("{}/{}/stop", self.boxes_url, self.box_id);
        if let Err(e) = self.client.post(&stop_url).send().await {
            warn!(box_id = %self.box_id, error = %e, "Failed to stop BoxLite VM");
        }

        Ok(ProcessStatus::from_code(exit_code))
    }

    /// Send a signal to the process inside the VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the signal cannot be sent.
    pub fn signal(&self, sig: nix::sys::signal::Signal) -> Result<()> {
        let sig_num = sig as i32;
        let signal_url = format!(
            "{}/{}/executions/{}/signal",
            self.boxes_url, self.box_id, self.execution_id
        );
        let client = self.client.clone();
        let box_id = self.box_id.clone();

        let handle = tokio::runtime::Handle::current();
        handle.block_on(async {
            let req = SignalRequest { signal: sig_num };
            if let Err(e) = client.post(&signal_url).json(&req).send().await {
                warn!(box_id = %box_id, error = %e, "Failed to signal BoxLite VM");
            }
        });
        Ok(())
    }

    /// Kill the VM and its processes.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be stopped.
    pub fn kill(&mut self) -> Result<()> {
        let stop_url = format!("{}/{}/stop", self.boxes_url, self.box_id);
        let client = self.client.clone();
        let box_id = self.box_id.clone();

        let handle = tokio::runtime::Handle::current();
        handle.block_on(async {
            if let Err(e) = client.post(&stop_url).send().await {
                warn!(box_id = %box_id, error = %e, "Failed to stop BoxLite VM on kill");
            }
        });
        Ok(())
    }
}

/// Parse the exit code from an SSE response body.
///
/// Looks for lines like:
/// ```text
/// event: exit
/// data: {"exit_code": 0}
/// ```
fn parse_sse_exit_code(body: &str) -> Option<i32> {
    let mut in_exit_event = false;
    for line in body.lines() {
        if line.starts_with("event:") {
            let event_type = line.trim_start_matches("event:").trim();
            in_exit_event = event_type == "exit";
        } else if in_exit_event && line.starts_with("data:") {
            let data = line.trim_start_matches("data:").trim();
            if let Ok(exit_data) = serde_json::from_str::<SseExitData>(data) {
                return Some(exit_data.exit_code);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sse_exit_code_found() {
        let body = "event: stdout\ndata: {\"data\":\"aGVsbG8=\"}\n\nevent: exit\ndata: {\"exit_code\": 0}\n\n";
        assert_eq!(parse_sse_exit_code(body), Some(0));
    }

    #[test]
    fn parse_sse_exit_code_nonzero() {
        let body = "event: exit\ndata: {\"exit_code\": 137}\n\n";
        assert_eq!(parse_sse_exit_code(body), Some(137));
    }

    #[test]
    fn parse_sse_exit_code_missing() {
        let body = "event: stdout\ndata: {\"data\":\"aGVsbG8=\"}\n\n";
        assert_eq!(parse_sse_exit_code(body), None);
    }

    #[test]
    fn parse_sse_exit_code_malformed() {
        let body = "event: exit\ndata: not-json\n\n";
        assert_eq!(parse_sse_exit_code(body), None);
    }

    #[test]
    fn boxlite_process_id_is_nonzero() {
        let process = BoxliteProcess {
            client: Client::new(),
            boxes_url: String::new(),
            box_id: "abc123".to_string(),
            execution_id: String::new(),
        };
        assert_ne!(process.id(), 0);
    }

    #[test]
    fn boxlite_process_id_deterministic() {
        let make = |id: &str| BoxliteProcess {
            client: Client::new(),
            boxes_url: String::new(),
            box_id: id.to_string(),
            execution_id: String::new(),
        };
        assert_eq!(make("abc123").id(), make("abc123").id());
        assert_ne!(make("abc123").id(), make("xyz789").id());
    }

    #[test]
    fn create_box_request_serialization() {
        let req = CreateBoxRequest {
            image: Some("python:3.11".into()),
            cpus: Some(2),
            memory_mib: Some(512),
            working_dir: None,
            env: None,
            auto_remove: Some(true),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"image\":\"python:3.11\""));
        assert!(json.contains("\"cpus\":2"));
        assert!(!json.contains("working_dir"));
    }

    #[test]
    fn exec_request_serialization() {
        let req = ExecRequest {
            command: "echo".into(),
            args: vec!["hello".into()],
            env: None,
            working_dir: Some("/app".into()),
            tty: false,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"command\":\"echo\""));
        assert!(json.contains("\"working_dir\":\"/app\""));
    }
}
