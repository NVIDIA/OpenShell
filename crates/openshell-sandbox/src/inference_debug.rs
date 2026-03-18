// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use base64::Engine;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

pub(crate) const INFERENCE_DEBUG_LOG_ENV: &str = "OPENSHELL_INFERENCE_DEBUG_LOG";
const BODY_CAPTURE_LIMIT_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub(crate) struct InferenceDebugLogger {
    path: PathBuf,
    file: Mutex<File>,
}

impl InferenceDebugLogger {
    pub(crate) fn from_env() -> Option<Self> {
        let path = std::env::var_os(INFERENCE_DEBUG_LOG_ENV)?;
        let path = PathBuf::from(path);
        match Self::new(&path) {
            Ok(logger) => {
                info!(path = %logger.path.display(), "Inference debug logging enabled");
                Some(logger)
            }
            Err(error) => {
                warn!(
                    path = %path.display(),
                    error = %error,
                    "Failed to enable inference debug logging"
                );
                None
            }
        }
    }

    pub(crate) fn new(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            file: Mutex::new(file),
        })
    }

    pub(crate) fn write_record(&self, record: &InferenceDebugRecord) {
        let mut line = match serde_json::to_vec(record) {
            Ok(line) => line,
            Err(error) => {
                warn!(error = %error, "Failed to serialize inference debug record");
                return;
            }
        };
        line.push(b'\n');

        let write = |file: &mut File| -> std::io::Result<()> {
            file.write_all(&line)?;
            file.flush()
        };

        match self.file.lock() {
            Ok(mut file) => {
                if let Err(error) = write(&mut file) {
                    warn!(
                        path = %self.path.display(),
                        error = %error,
                        "Failed to append inference debug record"
                    );
                }
            }
            Err(poisoned) => {
                let mut file = poisoned.into_inner();
                if let Err(error) = write(&mut file) {
                    warn!(
                        path = %self.path.display(),
                        error = %error,
                        "Failed to append inference debug record after mutex poison"
                    );
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct LoggedHeader {
    pub name: String,
    pub value: String,
}

pub(crate) fn logged_headers(headers: &[(String, String)]) -> Vec<LoggedHeader> {
    headers
        .iter()
        .map(|(name, value)| LoggedHeader {
            name: name.clone(),
            value: value.clone(),
        })
        .collect()
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InferenceDebugOutcome {
    Routed,
    Denied,
    UpstreamError,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InferenceDebugRecord {
    pub timestamp_ms: u64,
    pub source_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_path: Option<String>,
    pub ancestor_binaries: Vec<String>,
    pub cmdline_paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_error: Option<String>,
    pub method: String,
    pub raw_path: String,
    pub normalized_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_route: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_model: Option<String>,
    pub request_headers: Vec<LoggedHeader>,
    pub request_body_bytes: usize,
    pub request_body_capture_bytes: usize,
    pub request_body_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body_b64: Option<String>,
    pub response_status: u16,
    pub response_headers: Vec<LoggedHeader>,
    pub response_body_bytes: usize,
    pub response_body_capture_bytes: usize,
    pub response_body_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body_b64: Option<String>,
    pub streaming: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_to_first_chunk_ms: Option<u64>,
    pub total_duration_ms: u64,
    pub outcome: InferenceDebugOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub router_error: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BodyCaptureBuffer {
    captured: Vec<u8>,
    total_bytes: usize,
    truncated: bool,
}

impl BodyCaptureBuffer {
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        let mut capture = Self::default();
        capture.push(bytes);
        capture
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) {
        self.total_bytes += bytes.len();

        let remaining = BODY_CAPTURE_LIMIT_BYTES.saturating_sub(self.captured.len());
        let take = remaining.min(bytes.len());
        self.captured.extend_from_slice(&bytes[..take]);
        if take < bytes.len() {
            self.truncated = true;
        }
    }

    pub(crate) const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub(crate) fn captured_bytes(&self) -> usize {
        self.captured.len()
    }

    pub(crate) const fn truncated(&self) -> bool {
        self.truncated
    }

    pub(crate) fn encoded_body(&self) -> Option<String> {
        (!self.captured.is_empty())
            .then(|| base64::engine::general_purpose::STANDARD.encode(&self.captured))
    }
}

pub(crate) fn timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64)
}

pub(crate) fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_capture_truncates_and_encodes() {
        let data = vec![b'a'; BODY_CAPTURE_LIMIT_BYTES + 32];
        let capture = BodyCaptureBuffer::from_slice(&data);

        assert_eq!(capture.total_bytes(), BODY_CAPTURE_LIMIT_BYTES + 32);
        assert_eq!(capture.captured_bytes(), BODY_CAPTURE_LIMIT_BYTES);
        assert!(capture.truncated());
        assert_eq!(
            capture.encoded_body().unwrap(),
            base64::engine::general_purpose::STANDARD.encode(vec![b'a'; BODY_CAPTURE_LIMIT_BYTES])
        );
    }

    #[test]
    fn logger_writes_jsonl_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inference-debug.jsonl");
        let logger = InferenceDebugLogger::new(&path).unwrap();

        logger.write_record(&InferenceDebugRecord {
            timestamp_ms: 1234,
            source_port: 4567,
            pid: Some(42),
            binary_path: Some("/usr/bin/test".to_string()),
            ancestor_binaries: vec!["/usr/bin/parent".to_string()],
            cmdline_paths: vec!["/workspace/app".to_string()],
            identity_error: None,
            method: "POST".to_string(),
            raw_path: "/v1/messages".to_string(),
            normalized_path: "/v1/messages".to_string(),
            protocol: Some("anthropic_messages".to_string()),
            kind: Some("messages".to_string()),
            selected_route: Some("inference.local".to_string()),
            selected_provider: Some("anthropic".to_string()),
            selected_model: Some("claude-sonnet".to_string()),
            request_headers: vec![LoggedHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            request_body_bytes: 2,
            request_body_capture_bytes: 2,
            request_body_truncated: false,
            request_body_b64: Some("e30=".to_string()),
            response_status: 200,
            response_headers: vec![LoggedHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            response_body_bytes: 2,
            response_body_capture_bytes: 2,
            response_body_truncated: false,
            response_body_b64: Some("e30=".to_string()),
            streaming: false,
            time_to_first_chunk_ms: None,
            total_duration_ms: 10,
            outcome: InferenceDebugOutcome::Routed,
            deny_reason: None,
            router_error: None,
        });

        let content = std::fs::read_to_string(path).unwrap();
        let line = content.lines().next().unwrap();
        let json: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(json["source_port"], 4567);
        assert_eq!(json["selected_provider"], "anthropic");
        assert_eq!(json["outcome"], "routed");
    }
}
