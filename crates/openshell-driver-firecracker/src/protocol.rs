// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driver-private, length-delimited JSON protocol carried over virtio-vsock.

use std::fmt;
use std::io::{self, Read, Write};

use openshell_core::policy::{
    FilesystemPolicy, LandlockCompatibility, LandlockPolicy, NetworkMode, NetworkPolicy,
    ProcessPolicy, ProxyPolicy, SandboxPolicy,
};
use openshell_isolation::AgentSpec;
use openshell_isolation::contract::{BoundaryExitStatus, BoundarySignal};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub const MAX_CONTROL_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub request_id: u64,
    pub boundary_id: String,
    pub bootstrap_token: String,
    pub request: Request,
}

impl fmt::Debug for RequestEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestEnvelope")
            .field("request_id", &self.request_id)
            .field("boundary_id", &self.boundary_id)
            .field("bootstrap_token", &"<redacted>")
            .field("request", &self.request)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Request {
    Attach,
    Confirm,
    StartAgent {
        sandbox_id: String,
        spec: AgentSpecWire,
        policy: Box<SandboxPolicyWire>,
    },
    Wait {
        process_id: String,
    },
    Signal {
        process_id: String,
        signal: SignalWire,
    },
    Terminate {
        process_id: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub request_id: u64,
    pub response: Response,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Attached,
    Confirmed,
    Started { process_id: String },
    Exited { status: ExitStatusWire },
    Signaled,
    Terminated,
    Error { kind: String, message: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSpecWire {
    pub program: String,
    pub args: Vec<String>,
    pub workdir: Option<String>,
    pub timeout_secs: u64,
    pub interactive: bool,
}

impl From<AgentSpec> for AgentSpecWire {
    fn from(spec: AgentSpec) -> Self {
        Self {
            program: spec.program,
            args: spec.args,
            workdir: spec.workdir,
            timeout_secs: spec.timeout_secs,
            interactive: spec.interactive,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPolicyWire {
    pub version: u32,
    pub read_only: Vec<std::path::PathBuf>,
    pub read_write: Vec<std::path::PathBuf>,
    pub include_workdir: bool,
    pub network: NetworkModeWire,
    pub proxy_addr: Option<std::net::SocketAddr>,
    pub landlock: LandlockCompatibilityWire,
    pub run_as_user: Option<String>,
    pub run_as_group: Option<String>,
}

impl From<SandboxPolicy> for SandboxPolicyWire {
    fn from(policy: SandboxPolicy) -> Self {
        Self {
            version: policy.version,
            read_only: policy.filesystem.read_only,
            read_write: policy.filesystem.read_write,
            include_workdir: policy.filesystem.include_workdir,
            network: NetworkModeWire::from(policy.network.mode),
            proxy_addr: policy.network.proxy.and_then(|proxy| proxy.http_addr),
            landlock: LandlockCompatibilityWire::from(policy.landlock.compatibility),
            run_as_user: policy.process.run_as_user,
            run_as_group: policy.process.run_as_group,
        }
    }
}

impl From<SandboxPolicyWire> for SandboxPolicy {
    fn from(policy: SandboxPolicyWire) -> Self {
        let proxy = matches!(policy.network, NetworkModeWire::Proxy).then_some(ProxyPolicy {
            http_addr: policy.proxy_addr,
        });
        Self {
            version: policy.version,
            filesystem: FilesystemPolicy {
                read_only: policy.read_only,
                read_write: policy.read_write,
                include_workdir: policy.include_workdir,
            },
            network: NetworkPolicy {
                mode: policy.network.into(),
                proxy,
            },
            landlock: LandlockPolicy {
                compatibility: policy.landlock.into(),
            },
            process: ProcessPolicy {
                run_as_user: policy.run_as_user,
                run_as_group: policy.run_as_group,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkModeWire {
    Block,
    Proxy,
    Allow,
}

impl From<NetworkMode> for NetworkModeWire {
    fn from(mode: NetworkMode) -> Self {
        match mode {
            NetworkMode::Block => Self::Block,
            NetworkMode::Proxy => Self::Proxy,
            NetworkMode::Allow => Self::Allow,
        }
    }
}

impl From<NetworkModeWire> for NetworkMode {
    fn from(mode: NetworkModeWire) -> Self {
        match mode {
            NetworkModeWire::Block => Self::Block,
            NetworkModeWire::Proxy => Self::Proxy,
            NetworkModeWire::Allow => Self::Allow,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LandlockCompatibilityWire {
    BestEffort,
    HardRequirement,
}

impl From<LandlockCompatibility> for LandlockCompatibilityWire {
    fn from(compatibility: LandlockCompatibility) -> Self {
        match compatibility {
            LandlockCompatibility::BestEffort => Self::BestEffort,
            LandlockCompatibility::HardRequirement => Self::HardRequirement,
        }
    }
}

impl From<LandlockCompatibilityWire> for LandlockCompatibility {
    fn from(compatibility: LandlockCompatibilityWire) -> Self {
        match compatibility {
            LandlockCompatibilityWire::BestEffort => Self::BestEffort,
            LandlockCompatibilityWire::HardRequirement => Self::HardRequirement,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalWire {
    Term,
    Kill,
    Int,
    Hup,
}

impl From<BoundarySignal> for SignalWire {
    fn from(signal: BoundarySignal) -> Self {
        match signal {
            BoundarySignal::Term => Self::Term,
            BoundarySignal::Kill => Self::Kill,
            BoundarySignal::Int => Self::Int,
            BoundarySignal::Hup => Self::Hup,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ExitStatusWire {
    Exited(i32),
    Signaled(i32),
}

impl From<ExitStatusWire> for BoundaryExitStatus {
    fn from(status: ExitStatusWire) -> Self {
        match status {
            ExitStatusWire::Exited(code) => Self::Exited(code),
            ExitStatusWire::Signaled(signal) => Self::Signaled(signal),
        }
    }
}

pub fn encode_frame<T: Serialize>(message: &T) -> Result<Vec<u8>, FrameError> {
    let payload = serde_json::to_vec(message).map_err(FrameError::Serialize)?;
    if payload.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(FrameError::TooLarge(payload.len()));
    }
    let length = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge(payload.len()))?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<T, FrameError> {
    let header: [u8; 4] = frame
        .get(..4)
        .ok_or(FrameError::Truncated)?
        .try_into()
        .map_err(|_| FrameError::Truncated)?;
    let declared = u32::from_be_bytes(header) as usize;
    if declared > MAX_CONTROL_FRAME_BYTES {
        return Err(FrameError::TooLarge(declared));
    }
    let payload = frame.get(4..).ok_or(FrameError::Truncated)?;
    if payload.len() != declared {
        return Err(FrameError::LengthMismatch {
            declared,
            actual: payload.len(),
        });
    }
    serde_json::from_slice(payload).map_err(FrameError::Deserialize)
}

pub fn read_frame<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T, FrameError> {
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header)?;
    let declared = u32::from_be_bytes(header) as usize;
    if declared > MAX_CONTROL_FRAME_BYTES {
        return Err(FrameError::TooLarge(declared));
    }
    let mut frame = Vec::with_capacity(4 + declared);
    frame.extend_from_slice(&header);
    frame.resize(4 + declared, 0);
    reader.read_exact(&mut frame[4..])?;
    decode_frame(&frame)
}

pub fn write_frame<T: Serialize>(writer: &mut impl Write, message: &T) -> Result<(), FrameError> {
    let frame = encode_frame(message)?;
    writer.write_all(&frame)?;
    writer.flush()?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("control frame is truncated")]
    Truncated,
    #[error("control frame is too large: {0} bytes")]
    TooLarge(usize),
    #[error("control frame declared {declared} bytes but contained {actual}")]
    LengthMismatch { declared: usize, actual: usize },
    #[error("serialize control frame: {0}")]
    Serialize(serde_json::Error),
    #[error("deserialize control frame: {0}")]
    Deserialize(serde_json::Error),
    #[error("read or write control frame: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_and_redacts_token() {
        let request = RequestEnvelope {
            request_id: 7,
            boundary_id: "sandbox-1".to_string(),
            bootstrap_token: "never-log-this".to_string(),
            request: Request::StartAgent {
                sandbox_id: "sandbox-1".to_string(),
                spec: AgentSpecWire {
                    program: "/bin/true".to_string(),
                    args: Vec::new(),
                    workdir: Some("/sandbox".to_string()),
                    timeout_secs: 5,
                    interactive: false,
                },
                policy: Box::new(SandboxPolicyWire::from(SandboxPolicy {
                    version: 1,
                    filesystem: FilesystemPolicy::default(),
                    network: NetworkPolicy::default(),
                    landlock: LandlockPolicy::default(),
                    process: ProcessPolicy::default(),
                })),
            },
        };
        let frame = encode_frame(&request).expect("encode request");
        let decoded: RequestEnvelope = decode_frame(&frame).expect("decode request");
        assert_eq!(decoded, request);
        let debug = format!("{request:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("never-log-this"));
    }

    #[test]
    fn rejects_declared_oversize() {
        let oversized = u32::try_from(MAX_CONTROL_FRAME_BYTES + 1).expect("test size fits u32");
        let mut frame = Vec::from(oversized.to_be_bytes());
        frame.extend_from_slice(b"{}");
        assert!(matches!(
            decode_frame::<RequestEnvelope>(&frame),
            Err(FrameError::TooLarge(_))
        ));
    }
}
