// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Private native process plumbing behind the Sandbox Protocol server.

use async_trait::async_trait;
use openshell_isolation_interface::contract::{
    BackendError, BoundaryDuplexStream, BoundaryExitStatus, BoundaryInput, BoundaryOutput,
    BoundarySignal, ExecSpec, LoopbackTarget,
};
use std::sync::Arc;

#[async_trait]
pub trait BoundaryProcess: Send + Sync {
    /// Attach to the admitted process's retained standard I/O. The boundary
    /// remains the process owner and may permit only one control attachment.
    async fn attach(&self) -> Result<ProcessAttachment, BackendError> {
        Err(BackendError::Unsupported(
            "process attachment is not supported".to_string(),
        ))
    }
    /// Await terminal status (stable across repeated calls).
    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError>;
    /// Deliver a signal to the process or its group.
    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError>;
    /// Terminate the process and its backend-owned process group.
    async fn terminate(&self) -> Result<(), BackendError>;
}

pub struct ProcessAttachment {
    /// Stdin writer.
    pub stdin: BoundaryInput,
    /// Stdout reader, or the PTY-merged output stream.
    pub stdout: BoundaryOutput,
    /// Stderr reader, distinct from stdout for non-PTY processes.
    pub stderr: Option<BoundaryOutput>,
    /// PTY control, present when the admitted process owns a terminal.
    pub terminal: Option<Arc<dyn BoundaryTerminal>>,
}

#[async_trait]
pub trait BoundaryTerminal: Send + Sync {
    /// Resize the terminal.
    async fn resize(&self, cols: u16, rows: u16) -> Result<(), BackendError>;
}

pub struct ExecSession {
    /// The spawned process.
    pub process: Arc<dyn BoundaryProcess>,
    /// Stdin writer, if not a PTY-merged stream.
    pub stdin: Option<BoundaryInput>,
    /// Stdout reader.
    pub stdout: BoundaryOutput,
    /// Stderr reader, distinct from stdout for non-PTY exec.
    pub stderr: Option<BoundaryOutput>,
    /// PTY control, present when a terminal was requested.
    pub terminal: Option<Arc<dyn BoundaryTerminal>>,
}

#[async_trait]
pub trait BoundaryExec: Send + Sync {
    /// Spawn `spec` inside the boundary, returning an owned session.
    async fn exec(&self, spec: ExecSpec) -> Result<ExecSession, BackendError>;
}

#[async_trait]
pub trait BoundaryLoopbackConnector: Send + Sync {
    /// Connect to `target` inside the boundary.
    async fn connect(&self, target: LoopbackTarget) -> Result<BoundaryDuplexStream, BackendError>;
}
