// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded tar upload over the supervisor's credited SSH subsystem.

use std::io::{self, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

use miette::Diagnostic;
use openshell_core::upload::{
    Frame, MAX_DIAGNOSTIC_BYTES, ProtocolError, UploadPlan, UploadSummary, read_frame, write_frame,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, Command as TokioCommand};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(10);
const CHILD_EXIT_TIMEOUT: Duration = Duration::from_secs(5);
/// The producer can hold at most two chunks in addition to its current buffer
/// and the chunk held by the driver. It cannot build an entire archive in RAM.
const PRODUCER_QUEUE_CHUNKS: usize = 2;

#[derive(Debug, Error, Diagnostic)]
pub(super) enum UploadError {
    #[error("upload SSH transport failed: {0}")]
    Transport(String),
    #[error(
        "this sandbox supervisor does not support openshell-upload-v1; upgrade the sandbox supervisor before uploading"
    )]
    Unsupported,
    #[error("upload protocol failed: {0}")]
    Protocol(String),
    #[error("sandbox upload failed: {0}")]
    Remote(String),
    #[error("failed to create upload archive: {0}")]
    Archive(String),
    #[error("upload cancelled")]
    Cancelled,
}

impl UploadError {
    pub(super) fn is_retryable(&self) -> bool {
        matches!(self, Self::Transport(_))
    }
}

/// Own the SSH child through cancellation as well as ordinary error paths.
/// Tokio's kill-on-drop handles termination; the detached waiter also reaps it
/// when an enclosing command future is dropped by its caller.
struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn child(&mut self) -> &mut Child {
        self.0.as_mut().expect("SSH child is still owned")
    }

    async fn finish(&mut self, terminate: bool) -> io::Result<ExitStatus> {
        let child = self.child();
        if terminate {
            child.start_kill()?;
        }
        let status = child.wait().await?;
        self.0.take();
        Ok(status)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.start_kill();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    let _ = child.wait().await;
                });
            }
        }
    }
}

struct AbortTasks(Vec<AbortHandle>);

impl Drop for AbortTasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

/// Start the producer only after the subsystem has accepted the destination.
/// The archive callback uses the existing tar builder unchanged.
pub(super) async fn run<P>(
    mut command: Command,
    plan: UploadPlan,
    producer: P,
) -> Result<(), UploadError>
where
    P: FnOnce(&mut dyn Write) -> miette::Result<()> + Send + 'static,
{
    plan.validate()
        .map_err(|error| UploadError::Protocol(error.to_string()))?;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = TokioCommand::from(command)
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| UploadError::Transport(error.to_string()))?;
    let mut child = ChildGuard(Some(child));
    let stdin = child.child().stdin.take().expect("piped SSH stdin");
    let stdout = child.child().stdout.take().expect("piped SSH stdout");
    let stderr = child.child().stderr.take().expect("piped SSH stderr");
    let diagnostics = tokio::spawn(read_diagnostic(stderr));
    let diagnostic_guard = AbortTasks(vec![diagnostics.abort_handle()]);

    let result = transfer(stdout, stdin, plan, producer).await;

    let status = if result.is_err() {
        child.finish(true).await
    } else if let Ok(status) = tokio::time::timeout(CHILD_EXIT_TIMEOUT, child.finish(false)).await {
        status
    } else {
        let _ = child.finish(true).await;
        return Err(UploadError::Protocol(
            "SSH did not exit after the upload result".to_string(),
        ));
    };
    let diagnostic = tokio::time::timeout(CHILD_EXIT_TIMEOUT, diagnostics)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    drop(diagnostic_guard);
    // OpenSSH reports subsystem rejection as status 255, like other SSH
    // failures. Its explicit request diagnostic distinguishes an old server
    // from a transient connection failure, without sending any archive bytes.
    if matches!(result, Err(UploadError::Transport(_)))
        && diagnostic.contains("subsystem request failed")
    {
        return Err(UploadError::Unsupported);
    }
    match result {
        Err(UploadError::Transport(message)) if !diagnostic.trim().is_empty() => {
            return Err(UploadError::Transport(format!("{message}: {diagnostic}")));
        }
        result => result?,
    }
    let status = status.map_err(|error| UploadError::Transport(error.to_string()))?;
    if !status.success() {
        if status.code() == Some(super::SSH_TRANSPORT_FAILURE_EXIT_CODE) {
            return Err(UploadError::Transport(format!("{status}: {diagnostic}")));
        }
        return Err(UploadError::Protocol(format!(
            "SSH exited with {status} after a successful result: {diagnostic}"
        )));
    }
    Ok(())
}

async fn read_diagnostic<R: AsyncRead + Unpin>(mut reader: R) -> String {
    let mut diagnostic = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(bytes) => {
                diagnostic.extend_from_slice(&chunk[..bytes]);
                if diagnostic.len() > MAX_DIAGNOSTIC_BYTES {
                    diagnostic.drain(..diagnostic.len() - MAX_DIAGNOSTIC_BYTES);
                }
            }
        }
    }
    String::from_utf8_lossy(&diagnostic).into_owned()
}

fn protocol_error(error: ProtocolError) -> UploadError {
    // ProtocolError preserves I/O errors separately from invalid frames.
    match error {
        ProtocolError::Io(error) => UploadError::Transport(error.to_string()),
        error => UploadError::Protocol(error.to_string()),
    }
}

async fn negotiate<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    plan: UploadPlan,
) -> Result<(u64, usize), UploadError> {
    let hello = read_frame(reader).await.map_err(protocol_error)?;
    let Frame::Hello {
        window_bytes,
        max_data_bytes,
    } = hello
    else {
        return Err(server_failure(hello, "expected HELLO"));
    };
    write_frame(writer, &Frame::Begin(plan))
        .await
        .map_err(protocol_error)?;
    match read_frame(reader).await.map_err(protocol_error)? {
        Frame::Ready => Ok((u64::from(window_bytes), max_data_bytes as usize)),
        frame => Err(server_failure(frame, "expected READY")),
    }
}

fn server_failure(frame: Frame, expected: &str) -> UploadError {
    match frame {
        Frame::Error(failure) => {
            UploadError::Remote(format!("{:?}: {}", failure.code, failure.message))
        }
        _ => UploadError::Protocol(expected.to_string()),
    }
}

enum ProducerEvent {
    Data(Vec<u8>),
    Finished(Result<(), UploadError>),
}

struct ChunkWriter {
    sender: mpsc::Sender<ProducerEvent>,
    buffer: Vec<u8>,
    max_chunk: usize,
}

impl ChunkWriter {
    fn flush_chunk(&mut self) -> io::Result<()> {
        if !self.buffer.is_empty() {
            let buffer = std::mem::replace(&mut self.buffer, Vec::with_capacity(self.max_chunk));
            self.sender
                .blocking_send(ProducerEvent::Data(buffer))
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "upload stopped"))?;
        }
        Ok(())
    }
}

impl Write for ChunkWriter {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let original_len = bytes.len();
        while !bytes.is_empty() {
            let length = bytes.len().min(self.max_chunk - self.buffer.len());
            self.buffer.extend_from_slice(&bytes[..length]);
            bytes = &bytes[length..];
            if self.buffer.len() == self.max_chunk {
                self.flush_chunk()?;
            }
        }
        Ok(original_len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_chunk()
    }
}

fn spawn_producer<P>(producer: P, max_chunk: usize) -> mpsc::Receiver<ProducerEvent>
where
    P: FnOnce(&mut dyn Write) -> miette::Result<()> + Send + 'static,
{
    let (sender, receiver) = mpsc::channel(PRODUCER_QUEUE_CHUNKS);
    tokio::task::spawn_blocking(move || {
        let mut writer = ChunkWriter {
            sender: sender.clone(),
            buffer: Vec::with_capacity(max_chunk),
            max_chunk,
        };
        let result = producer(&mut writer)
            .map_err(|error| UploadError::Archive(error.to_string()))
            .and_then(|()| {
                writer
                    .flush()
                    .map_err(|error| UploadError::Archive(error.to_string()))
            });
        let _ = sender.blocking_send(ProducerEvent::Finished(result));
    });
    receiver
}

/// Dedicated readers and writers let remote failure interrupt a blocked local
/// SSH pipe write. The frame reader is never cancelled between partial reads.
async fn transfer<R, W, P>(
    mut reader: R,
    mut writer: W,
    plan: UploadPlan,
    producer: P,
) -> Result<(), UploadError>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    P: FnOnce(&mut dyn Write) -> miette::Result<()> + Send + 'static,
{
    let (window, max_chunk) = tokio::time::timeout(
        NEGOTIATION_TIMEOUT,
        negotiate(&mut reader, &mut writer, plan),
    )
    .await
    .map_err(|_| UploadError::Transport("upload negotiation timed out".to_string()))??;
    let mut events = spawn_producer(producer, max_chunk);
    let (incoming, mut frames) = mpsc::channel(4);
    let reader_task = tokio::spawn(async move {
        loop {
            let frame = read_frame(&mut reader).await.map_err(protocol_error);
            let terminal = frame.is_err();
            if incoming.send(frame).await.is_err() || terminal {
                break;
            }
        }
    });
    let (outgoing, mut queued) = mpsc::channel::<Frame>(1);
    let (completed, mut completions) = mpsc::channel(1);
    let writer_task = tokio::spawn(async move {
        while let Some(frame) = queued.recv().await {
            let is_end = matches!(frame, Frame::End(_));
            let result = write_frame(&mut writer, &frame)
                .await
                .map_err(protocol_error);
            let result = if result.is_ok() && is_end {
                writer
                    .shutdown()
                    .await
                    .map_err(|error| UploadError::Transport(error.to_string()))
            } else {
                result
            };
            let terminal = result.is_err() || is_end;
            if completed.send(result).await.is_err() || terminal {
                break;
            }
        }
    });
    let _tasks = AbortTasks(vec![reader_task.abort_handle(), writer_task.abort_handle()]);
    let mut sent = 0_u64;
    let mut acknowledged = 0_u64;
    let mut digest = Sha256::new();
    let mut pending = None;
    let mut producer_finished = false;
    let mut writing = false;
    let mut end = None;
    loop {
        if !writing && end.is_none() {
            if pending.as_ref().is_some_and(|data: &Vec<u8>| {
                (sent - acknowledged)
                    .checked_add(data.len() as u64)
                    .is_some_and(|pending| pending <= window)
            }) {
                let data = pending.take().expect("pending upload data");
                sent = sent.checked_add(data.len() as u64).ok_or_else(|| {
                    UploadError::Protocol("upload byte count overflow".to_string())
                })?;
                digest.update(&data);
                outgoing
                    .send(Frame::Data(data))
                    .await
                    .map_err(|_| UploadError::Transport("upload writer stopped".to_string()))?;
                writing = true;
            } else if producer_finished && pending.is_none() {
                let summary = UploadSummary {
                    bytes: sent,
                    sha256: digest.clone().finalize().into(),
                };
                outgoing
                    .send(Frame::End(summary))
                    .await
                    .map_err(|_| UploadError::Transport("upload writer stopped".to_string()))?;
                end = Some(summary);
                writing = true;
            }
        }
        tokio::select! {
            frame = frames.recv() => {
                match frame.ok_or_else(|| UploadError::Transport("upload reader stopped".to_string()))?? {
                    Frame::Ack(bytes) => {
                        if bytes < acknowledged || bytes > sent {
                            return Err(UploadError::Protocol("invalid cumulative upload ACK".to_string()));
                        }
                        acknowledged = bytes;
                    }
                    Frame::Result(summary) => {
                        if end != Some(summary) {
                            return Err(UploadError::Protocol("upload result count or digest does not match END".to_string()));
                        }
                        return Ok(());
                    }
                    frame => return Err(server_failure(frame, "unexpected frame during upload")),
                }
            }
            result = completions.recv(), if writing => {
                result.ok_or_else(|| UploadError::Transport("upload writer stopped".to_string()))??;
                writing = false;
            }
            event = events.recv(), if pending.is_none() && !producer_finished => {
                match event.ok_or_else(|| UploadError::Archive("archive producer stopped".to_string()))? {
                    ProducerEvent::Data(data) => pending = Some(data),
                    ProducerEvent::Finished(result) => {
                        result?;
                        producer_finished = true;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::upload::{FailureCode, MAX_DATA_BYTES, UploadFailure, WINDOW_BYTES};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{DuplexStream, ReadHalf, WriteHalf};

    fn plan() -> UploadPlan {
        UploadPlan {
            destination_directory: "/tmp/upload".to_string(),
            expected_destination: None,
        }
    }

    async fn accept(stream: DuplexStream) -> (ReadHalf<DuplexStream>, WriteHalf<DuplexStream>) {
        let (mut read, mut write) = tokio::io::split(stream);
        write_frame(
            &mut write,
            &Frame::Hello {
                window_bytes: WINDOW_BYTES,
                max_data_bytes: u32::try_from(MAX_DATA_BYTES).unwrap(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_frame(&mut read).await.unwrap(),
            Frame::Begin(_)
        ));
        write_frame(&mut write, &Frame::Ready).await.unwrap();
        (read, write)
    }

    fn payload(bytes: usize) -> Vec<u8> {
        (0..bytes)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect()
    }

    async fn complete(
        read: &mut ReadHalf<DuplexStream>,
        write: &mut WriteHalf<DuplexStream>,
        mut received: Vec<u8>,
    ) -> Vec<u8> {
        loop {
            match read_frame(read).await.unwrap() {
                Frame::Data(data) => {
                    assert!(data.len() <= MAX_DATA_BYTES);
                    received.extend_from_slice(&data);
                    write_frame(write, &Frame::Ack(received.len() as u64))
                        .await
                        .unwrap();
                }
                Frame::End(summary) => {
                    assert_eq!(summary.bytes, received.len() as u64);
                    assert_eq!(summary.sha256, <[u8; 32]>::from(Sha256::digest(&received)));
                    write_frame(write, &Frame::Result(summary)).await.unwrap();
                    return received;
                }
                frame => panic!("unexpected client frame: {frame:?}"),
            }
        }
    }

    #[tokio::test]
    async fn stalled_consumer_blocks_at_credit_limit_then_resumes_with_exact_data() {
        let expected = payload(6 * WINDOW_BYTES as usize + 123);
        let bytes = expected.clone();
        let (client, server) = tokio::io::duplex(4096);
        let (read, write) = tokio::io::split(client);
        let client = tokio::spawn(transfer(read, write, plan(), move |writer| {
            writer.write_all(&bytes).map_err(miette::Report::from_err)?;
            Ok(())
        }));
        let (mut read, mut write) = accept(server).await;
        let mut received = Vec::new();
        while received.len() < WINDOW_BYTES as usize {
            match read_frame(&mut read).await.unwrap() {
                Frame::Data(data) => received.extend_from_slice(&data),
                frame => panic!("unexpected client frame: {frame:?}"),
            }
        }
        assert_eq!(received.len(), WINDOW_BYTES as usize);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), read_frame(&mut read))
                .await
                .is_err(),
            "client exceeded credit while the extractor was stalled"
        );
        assert!(!client.is_finished());
        write_frame(&mut write, &Frame::Ack(received.len() as u64))
            .await
            .unwrap();
        assert_eq!(complete(&mut read, &mut write, received).await, expected);
        client.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn cancelling_stalled_transfer_stops_blocking_producer_and_closes_pipes() {
        struct ProducerExit(Arc<AtomicBool>);
        impl Drop for ProducerExit {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let finished = Arc::new(AtomicBool::new(false));
        let producer_finished = finished.clone();
        let (client, server) = tokio::io::duplex(4096);
        let (read, write) = tokio::io::split(client);
        let client = tokio::spawn(transfer(read, write, plan(), move |writer| {
            let _finished = ProducerExit(producer_finished);
            writer
                .write_all(&payload(8 * WINDOW_BYTES as usize))
                .map_err(miette::Report::from_err)?;
            Ok(())
        }));
        let (mut read, _write) = accept(server).await;
        let mut received = 0;
        while received < WINDOW_BYTES as usize {
            let Frame::Data(data) = read_frame(&mut read).await.unwrap() else {
                panic!("expected data before credit is exhausted");
            };
            received += data.len();
        }
        assert_eq!(received, WINDOW_BYTES as usize);
        assert!(!finished.load(Ordering::SeqCst));
        client.abort();
        assert!(client.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(2), async {
            while !finished.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled transfer must stop its blocking archive producer");
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), read.read(&mut byte))
                .await
                .expect("cancelled transfer must release its protocol pipes")
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn impossible_ack_is_rejected_without_retry() {
        let (client, server) = tokio::io::duplex(4096);
        let (read, write) = tokio::io::split(client);
        let client = tokio::spawn(transfer(read, write, plan(), |writer| {
            writer
                .write_all(&payload(2 * WINDOW_BYTES as usize))
                .map_err(miette::Report::from_err)?;
            Ok(())
        }));
        let (_read, mut write) = accept(server).await;
        write_frame(&mut write, &Frame::Ack(u64::MAX))
            .await
            .unwrap();
        let error = client.await.unwrap().unwrap_err();
        assert!(matches!(error, UploadError::Protocol(_)));
        assert!(!error.is_retryable());
    }

    #[tokio::test]
    async fn regressing_ack_is_rejected() {
        let (client, server) = tokio::io::duplex(4096);
        let (read, write) = tokio::io::split(client);
        let client = tokio::spawn(transfer(read, write, plan(), |writer| {
            writer
                .write_all(&payload(2 * WINDOW_BYTES as usize))
                .map_err(miette::Report::from_err)?;
            Ok(())
        }));
        let (mut read, mut write) = accept(server).await;
        let Frame::Data(data) = read_frame(&mut read).await.unwrap() else {
            panic!("expected data");
        };
        write_frame(&mut write, &Frame::Ack(data.len() as u64))
            .await
            .unwrap();
        write_frame(&mut write, &Frame::Ack(data.len() as u64 - 1))
            .await
            .unwrap();
        assert!(matches!(
            client.await.unwrap().unwrap_err(),
            UploadError::Protocol(_)
        ));
    }

    #[tokio::test]
    async fn terminal_error_interrupts_blocked_pipe_write() {
        let (client, server) = tokio::io::duplex(64);
        let (read, write) = tokio::io::split(client);
        let client = tokio::spawn(transfer(read, write, plan(), |writer| {
            writer
                .write_all(&payload(2 * WINDOW_BYTES as usize))
                .map_err(miette::Report::from_err)?;
            Ok(())
        }));
        let (_read, mut write) = accept(server).await;
        write_frame(
            &mut write,
            &Frame::Error(UploadFailure {
                code: FailureCode::InputWrite,
                message: "extractor closed stdin: connection is unavailable".to_string(),
            }),
        )
        .await
        .unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), client)
            .await
            .expect("remote failure must interrupt a blocked writer")
            .unwrap()
            .unwrap_err();
        assert!(matches!(error, UploadError::Remote(_)));
        assert!(!error.is_retryable());
    }

    #[tokio::test]
    async fn successful_exit_cannot_replace_terminal_result() {
        let (client, server) = tokio::io::duplex(4096);
        let (read, write) = tokio::io::split(client);
        let client = tokio::spawn(transfer(read, write, plan(), |_| Ok(())));
        let (mut read, write) = accept(server).await;
        assert!(matches!(
            read_frame(&mut read).await.unwrap(),
            Frame::End(_)
        ));
        drop(write);
        drop(read);
        assert!(client.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn mismatched_terminal_digest_is_rejected() {
        let (client, server) = tokio::io::duplex(4096);
        let (read, write) = tokio::io::split(client);
        let client = tokio::spawn(transfer(read, write, plan(), |_| Ok(())));
        let (mut read, mut write) = accept(server).await;
        let Frame::End(mut summary) = read_frame(&mut read).await.unwrap() else {
            panic!("expected end");
        };
        summary.sha256[0] ^= 1;
        write_frame(&mut write, &Frame::Result(summary))
            .await
            .unwrap();
        assert!(matches!(
            client.await.unwrap().unwrap_err(),
            UploadError::Protocol(_)
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unavailable_subsystem_never_starts_archive_producer() {
        let started = Arc::new(AtomicBool::new(false));
        let producer_started = started.clone();
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "printf 'subsystem request failed on channel 0\\n' >&2; exit 255",
        ]);
        let error = run(command, plan(), move |_| {
            producer_started.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap_err();
        assert!(matches!(error, UploadError::Unsupported));
        assert!(!started.load(Ordering::SeqCst));
        assert!(!error.is_retryable());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn early_ssh_exit_never_starts_archive_producer() {
        let started = Arc::new(AtomicBool::new(false));
        let producer_started = started.clone();
        let mut command = Command::new("sh");
        command.args(["-c", "exit 255"]);
        let error = run(command, plan(), move |_| {
            producer_started.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap_err();
        assert!(matches!(error, UploadError::Transport(_)));
        assert!(!started.load(Ordering::SeqCst));
        assert!(error.is_retryable());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dropping_upload_future_terminates_and_reaps_ssh_child() {
        let temporary = tempfile::tempdir().unwrap();
        let pid_file = temporary.path().join("pid");
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "printf '%s' \"$$\" > \"$1\"; exec sleep 60",
            "upload-test",
        ]);
        command.arg(&pid_file);
        let upload = tokio::spawn(run(command, plan(), |_| Ok(())));
        let pid = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(pid) = tokio::fs::read_to_string(&pid_file).await
                    && let Ok(pid) = pid.parse::<i32>()
                {
                    break pid;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        upload.abort();
        assert!(upload.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(2), async {
            while nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("SSH child must be terminated and reaped on cancellation");
    }
}
