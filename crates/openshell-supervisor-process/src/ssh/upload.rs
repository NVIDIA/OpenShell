// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Upload input credit follows boundary consumption, independently of russh's
//! receive window. The SSH callback only decodes and queues bounded input.

use super::input::{InputProgress, InputSender, InputState, InputTask, SendError};
use openshell_core::upload::{
    DESTINATION_CHANGED_EXIT_CODE, Decoder, FailureCode, Frame, MAX_DATA_BYTES,
    MAX_DIAGNOSTIC_BYTES, UploadFailure, UploadPlan, UploadSummary, WINDOW_BYTES,
    build_extract_command,
};
use openshell_isolation_interface::contract::{
    BoundaryExec, BoundaryExitStatus, BoundaryProcess, ExecSession, ExecSpec, ShellSpec,
};
use russh::ChannelId;
use russh::server::Handle;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::{Notify, oneshot, watch};
use tokio::task::JoinHandle;

const ACK_INTERVAL: u64 = 256 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    AwaitBegin,
    Starting,
    Receiving,
    Draining,
    Finished,
}

struct State {
    phase: Phase,
    plan: Option<UploadPlan>,
    sender: Option<InputSender>,
    input_task: Option<InputTask>,
    progress: Option<watch::Receiver<InputProgress>>,
    process: Option<Arc<dyn BoundaryProcess>>,
    received: u64,
    digest: Sha256,
    summary: Option<UploadSummary>,
    failure: Option<UploadFailure>,
}

struct Shared {
    state: Mutex<State>,
    changed: Notify,
}

pub(super) struct UploadChannel {
    decoder: Decoder,
    shared: Arc<Shared>,
    owner: JoinHandle<()>,
}

impl UploadChannel {
    pub(super) fn spawn(
        channel: ChannelId,
        handle: Handle,
        boundary_exec: Arc<dyn BoundaryExec>,
        login: bool,
    ) -> Self {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                phase: Phase::AwaitBegin,
                plan: None,
                sender: None,
                input_task: None,
                progress: None,
                process: None,
                received: 0,
                digest: Sha256::new(),
                summary: None,
                failure: None,
            }),
            changed: Notify::new(),
        });
        let owner_shared = shared.clone();
        let owner = tokio::spawn(async move {
            run(owner_shared, channel, handle, boundary_exec, login).await;
        });
        Self {
            decoder: Decoder::default(),
            shared,
            owner,
        }
    }

    pub(super) fn data(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            match self.decoder.decode(&mut bytes) {
                Ok(Some(frame)) => {
                    if let Err(failure) = self.accept(frame) {
                        self.fail(failure);
                        return;
                    }
                }
                Ok(None) => return,
                Err(error) => {
                    self.fail(failure(FailureCode::Protocol, error.to_string()));
                    return;
                }
            }
        }
    }

    pub(super) fn eof(&self) {
        let valid = self.decoder.is_empty()
            && self
                .shared
                .state
                .lock()
                .is_ok_and(|state| matches!(state.phase, Phase::Draining | Phase::Finished));
        if !valid {
            self.fail(failure(
                FailureCode::Protocol,
                "upload stream ended before a complete END frame",
            ));
        }
    }

    pub(super) fn reject_extended_data(&self) {
        self.fail(failure(
            FailureCode::Protocol,
            "extended data is not supported by the upload subsystem",
        ));
    }

    pub(super) fn process(&self) -> Option<Arc<dyn BoundaryProcess>> {
        self.shared.state.lock().ok()?.process.clone()
    }

    fn fail(&self, failure: UploadFailure) {
        if let Ok(mut state) = self.shared.state.lock()
            && state.phase != Phase::Finished
            && state.failure.is_none()
        {
            state.failure = Some(failure);
            // Stop a stalled write immediately. The owner reports the typed
            // failure and terminates the process outside the session callback.
            state.sender.take();
            state.input_task.take();
        }
        self.shared.changed.notify_one();
    }

    fn accept(&self, frame: Frame) -> Result<(), UploadFailure> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| failure(FailureCode::Internal, "upload state unavailable"))?;
        if state.failure.is_some() || state.phase == Phase::Finished {
            return Ok(());
        }
        match frame {
            Frame::Begin(plan) if state.phase == Phase::AwaitBegin => {
                plan.validate()
                    .map_err(|error| failure(FailureCode::Protocol, error.to_string()))?;
                state.phase = Phase::Starting;
                state.plan = Some(plan);
            }
            Frame::Data(data) if state.phase == Phase::Receiving => {
                let consumed = state
                    .progress
                    .as_ref()
                    .map_or(0, |progress| progress.borrow().consumed);
                let received = state
                    .received
                    .checked_add(data.len() as u64)
                    .ok_or_else(|| failure(FailureCode::Protocol, "upload length overflow"))?;
                if received - consumed > u64::from(WINDOW_BYTES) {
                    return Err(failure(
                        FailureCode::Protocol,
                        "upload input credit exceeded",
                    ));
                }
                let sender = state.sender.as_ref().ok_or_else(|| {
                    failure(
                        FailureCode::InputWrite,
                        "extraction process stdin is closed",
                    )
                })?;
                sender.send(&data).map_err(|error| match error {
                    SendError::Full => {
                        failure(FailureCode::Internal, "upload input budget exceeded")
                    }
                    SendError::Closed => failure(
                        FailureCode::InputWrite,
                        "extraction process stdin is closed",
                    ),
                })?;
                state.received = received;
                state.digest.update(data);
            }
            Frame::End(summary) if state.phase == Phase::Receiving => {
                let actual = UploadSummary {
                    bytes: state.received,
                    sha256: state.digest.clone().finalize().into(),
                };
                if summary != actual {
                    return Err(failure(
                        FailureCode::Protocol,
                        "upload count or digest mismatch",
                    ));
                }
                state.summary = Some(summary);
                state.phase = Phase::Draining;
                // EOF drains accepted bytes before closing boundary stdin.
                state.sender.take();
            }
            Frame::Cancel => {
                return Err(failure(FailureCode::Protocol, "upload cancelled by client"));
            }
            _ => {
                return Err(failure(FailureCode::Protocol, "unexpected upload frame"));
            }
        }
        drop(state);
        self.shared.changed.notify_one();
        Ok(())
    }
}

impl Drop for UploadChannel {
    fn drop(&mut self) {
        self.owner.abort();
        let process = self.shared.state.lock().ok().and_then(|mut state| {
            state.phase = Phase::Finished;
            state.sender.take();
            state.input_task.take();
            state.process.take()
        });
        if let Some(process) = process {
            tokio::spawn(async move {
                let _ = process.terminate().await;
            });
        }
    }
}

fn failure(code: FailureCode, message: impl Into<String>) -> UploadFailure {
    let mut message = message.into();
    // Error formatting and backend diagnostics can be large. Bound the UTF-8
    // string before it enters a queued protocol frame.
    if message.len() > MAX_DIAGNOSTIC_BYTES {
        let mut end = MAX_DIAGNOSTIC_BYTES;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
    }
    UploadFailure { code, message }
}

async fn send(handle: &Handle, channel: ChannelId, frame: Frame) -> bool {
    match frame.encode() {
        Ok(bytes) => handle.data(channel, bytes).await.is_ok(),
        Err(_) => false,
    }
}

async fn finish(
    shared: &Shared,
    channel: ChannelId,
    handle: &Handle,
    result: Result<UploadSummary, UploadFailure>,
) {
    let (result, process) = shared.state.lock().map_or_else(
        |_| {
            (
                Err(failure(FailureCode::Internal, "upload state unavailable")),
                None,
            )
        },
        |mut state| {
            // Commit the result under the same lock that records protocol failure.
            let result = state.failure.take().map_or(result, Err);
            state.phase = Phase::Finished;
            state.sender.take();
            state.input_task.take();
            (result, state.process.take())
        },
    );
    let failed = result.is_err();
    if failed && let Some(process) = process {
        tokio::spawn(async move {
            let _ = process.terminate().await;
        });
    }
    let frame = match result {
        Ok(summary) => Frame::Result(summary),
        Err(error) => Frame::Error(error),
    };
    let _ = send(handle, channel, frame).await;
    let _ = handle
        .exit_status_request(channel, if failed { 74 } else { 0 })
        .await;
    let _ = handle.eof(channel).await;
    let _ = handle.close(channel).await;
}

async fn run(
    shared: Arc<Shared>,
    channel: ChannelId,
    handle: Handle,
    boundary_exec: Arc<dyn BoundaryExec>,
    login: bool,
) {
    let result = drive(&shared, channel, &handle, boundary_exec, login).await;
    finish(&shared, channel, &handle, result).await;
}

async fn drive(
    shared: &Shared,
    channel: ChannelId,
    handle: &Handle,
    boundary_exec: Arc<dyn BoundaryExec>,
    login: bool,
) -> Result<UploadSummary, UploadFailure> {
    if !send(
        handle,
        channel,
        Frame::Hello {
            window_bytes: WINDOW_BYTES,
            max_data_bytes: u32::try_from(MAX_DATA_BYTES).expect("bounded data frame"),
        },
    )
    .await
    {
        return Err(failure(
            FailureCode::Internal,
            "upload reply delivery failed",
        ));
    }
    let plan = loop {
        let changed = shared.changed.notified();
        {
            let mut state = shared
                .state
                .lock()
                .map_err(|_| failure(FailureCode::Internal, "upload state unavailable"))?;
            if let Some(error) = state.failure.take() {
                return Err(error);
            }
            if let Some(plan) = state.plan.take() {
                break plan;
            }
        }
        changed.await;
    };
    let extraction = async {
        let command = build_extract_command(&plan)
            .map_err(|error| failure(FailureCode::Protocol, error.to_string()))?;
        // Remote backends may admit a process before returning its attachment.
        // Keep startup owned independently of this channel: cancellation must
        // terminate even a result delivered after the upload owner is dropped.
        let (started_tx, started_rx) = oneshot::channel();
        tokio::spawn(async move {
            let result = boundary_exec
                .exec(ExecSpec {
                    program: String::new(),
                    args: Vec::new(),
                    shell: Some(ShellSpec {
                        command: Some(command),
                        login,
                    }),
                    runtime_helper: None,
                    env: Vec::new(),
                    workdir: None,
                    pty: false,
                })
                .await
                .map(|exec| PendingExec(Some(exec)));
            // A queued PendingExec also terminates on drop if the receiver was
            // cancelled after send succeeded but before receiving the attachment.
            let _ = started_tx.send(result);
        });
        let mut pending = started_rx
            .await
            .map_err(|_| failure(FailureCode::Internal, "extraction startup stopped"))?
            .map_err(|error| failure(FailureCode::Extract, error.to_string()))?;
        {
            let mut state = shared
                .state
                .lock()
                .map_err(|_| failure(FailureCode::Internal, "upload state unavailable"))?;
            // Channel drop can run on another worker after the receive completes.
            // Keep the startup guard armed until ownership is registered under the
            // same lock that cancellation uses to mark the channel finished.
            if state.phase == Phase::Finished || state.failure.is_some() {
                return Err(failure(
                    FailureCode::Protocol,
                    "upload cancelled during startup",
                ));
            }
            state.process = Some(
                pending
                    .0
                    .as_ref()
                    .expect("owned startup result")
                    .process
                    .clone(),
            );
        }
        let mut exec = pending.0.take().expect("registered startup result");
        let stdin = exec
            .stdin
            .take()
            .ok_or_else(|| failure(FailureCode::Internal, "extraction process has no stdin"))?;
        let (sender, input_task, mut progress) = InputTask::spawn_with_progress(stdin);
        {
            let mut state = shared
                .state
                .lock()
                .map_err(|_| failure(FailureCode::Internal, "upload state unavailable"))?;
            if state.phase == Phase::Finished {
                return Err(failure(
                    FailureCode::Protocol,
                    "upload cancelled during startup",
                ));
            }
            if let Some(error) = state.failure.take() {
                return Err(error);
            }
            state.sender = Some(sender);
            state.input_task = Some(input_task);
            state.progress = Some(progress.clone());
            state.phase = Phase::Receiving;
        }
        let diagnostic = Arc::new(Mutex::new(Vec::new()));
        let stdout = DrainTask::spawn(exec.stdout, diagnostic.clone());
        let stderr = exec
            .stderr
            .map(|stderr| DrainTask::spawn(stderr, diagnostic.clone()));
        let mut exit = Box::pin(exec.process.wait());
        if !send(handle, channel, Frame::Ready).await {
            return Err(failure(
                FailureCode::Internal,
                "upload reply delivery failed",
            ));
        }
        let mut acknowledged = 0;
        let status = loop {
            let latest = *progress.borrow_and_update();
            if latest.state == InputState::Failed {
                return Err(failure(
                    FailureCode::InputWrite,
                    diagnostic_message(&diagnostic, "failed to write extraction stdin"),
                ));
            }
            if latest.consumed - acknowledged >= ACK_INTERVAL
                || (latest.state == InputState::Drained && latest.consumed != acknowledged)
            {
                if !send(handle, channel, Frame::Ack(latest.consumed)).await {
                    return Err(failure(
                        FailureCode::Internal,
                        "upload reply delivery failed",
                    ));
                }
                acknowledged = latest.consumed;
            }
            tokio::select! {
                status = &mut exit => {
                    let status = status.map_err(|error| failure(FailureCode::Extract, error.to_string()))?;
                    let final_progress = *progress.borrow();
                    let (final_summary, final_received) = shared.state.lock().map(|state| (state.summary, state.received)).map_err(|_| failure(FailureCode::Internal, "upload state unavailable"))?;
                    if final_summary.is_none() || final_progress.consumed != final_received {
                        return Err(extract_failure(status, &diagnostic_message(&diagnostic, "extraction process exited before upload completed")));
                    }
                    // A pipe shutdown can wake the child just before the writer
                    // publishes Drained. Await that final watch update rather than
                    // treating the successful EOF race as an early extraction exit.
                    while progress.borrow().state == InputState::Writing {
                        progress.changed().await.map_err(|_| failure(FailureCode::InputWrite, "extraction stdin writer stopped"))?;
                    }
                    if progress.borrow().state != InputState::Drained {
                        return Err(failure(FailureCode::InputWrite, diagnostic_message(&diagnostic, "failed to close extraction stdin")));
                    }
                    if final_received != acknowledged && !send(handle, channel, Frame::Ack(final_received)).await {
                        return Err(failure(FailureCode::Internal, "upload reply delivery failed"));
                    }
                    break status;
                }
                result = progress.changed() => {
                    if result.is_err() {
                        return Err(failure(FailureCode::InputWrite, "extraction stdin writer stopped"));
                    }
                }
            }
        };
        stdout
            .join()
            .await
            .map_err(|error| failure(FailureCode::Extract, error.to_string()))?;
        if let Some(stderr) = stderr {
            stderr
                .join()
                .await
                .map_err(|error| failure(FailureCode::Extract, error.to_string()))?;
        }
        let status = if let Some(output_status) = exec.output_status {
            output_status
                .await
                .map_err(|_| failure(FailureCode::Extract, "extraction output delivery failed"))?
        } else {
            status
        };
        if status != BoundaryExitStatus::Exited(0) {
            let diagnostic = diagnostic_message(&diagnostic, "extraction process failed");
            return Err(extract_failure(status, &diagnostic));
        }
        shared
            .state
            .lock()
            .ok()
            .and_then(|state| state.summary)
            .ok_or_else(|| failure(FailureCode::Internal, "upload summary unavailable"))
    };
    tokio::pin!(extraction);
    loop {
        let changed = shared.changed.notified();
        let error = shared
            .state
            .lock()
            .map_err(|_| failure(FailureCode::Internal, "upload state unavailable"))?
            .failure
            .clone();
        if let Some(error) = error {
            return Err(error);
        }
        tokio::select! {
            result = &mut extraction => return result,
            () = changed => {}
        }
    }
}

fn diagnostic_message(diagnostic: &Mutex<Vec<u8>>, fallback: &str) -> String {
    diagnostic
        .lock()
        .ok()
        .filter(|bytes| !bytes.is_empty())
        .map_or_else(
            || fallback.to_string(),
            |bytes| String::from_utf8_lossy(&bytes).into_owned(),
        )
}

fn extract_failure(status: BoundaryExitStatus, diagnostic: &str) -> UploadFailure {
    if status == BoundaryExitStatus::Exited(DESTINATION_CHANGED_EXIT_CODE) {
        failure(FailureCode::DestinationChanged, diagnostic)
    } else {
        failure(
            FailureCode::Extract,
            format!("extraction failed ({status:?}): {diagnostic}"),
        )
    }
}

/// Own a late startup result until the channel registers process ownership.
struct PendingExec(Option<ExecSession>);

impl Drop for PendingExec {
    fn drop(&mut self) {
        if let Some(exec) = self.0.take() {
            tokio::spawn(async move {
                let _ = exec.process.terminate().await;
            });
        }
    }
}

/// Aborting the owner also aborts output drains; dropping `JoinHandle` alone
/// would detach a pipe reader and retain the boundary streams after close.
struct DrainTask(JoinHandle<std::io::Result<()>>);

impl DrainTask {
    fn spawn(
        mut stream: Box<dyn AsyncRead + Send + Unpin>,
        diagnostic: Arc<Mutex<Vec<u8>>>,
    ) -> Self {
        Self(tokio::spawn(async move {
            let mut bytes = [0; 4096];
            loop {
                match stream.read(&mut bytes).await {
                    Ok(0) => return Ok(()),
                    Err(error) => return Err(error),
                    Ok(size) => {
                        if let Ok(mut diagnostic) = diagnostic.lock() {
                            let retain = size.min(MAX_DIAGNOSTIC_BYTES - diagnostic.len());
                            diagnostic.extend_from_slice(&bytes[..retain]);
                        }
                    }
                }
            }
        }))
    }

    async fn join(mut self) -> std::io::Result<()> {
        (&mut self.0).await.map_err(std::io::Error::other)?
    }
}

impl Drop for DrainTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
