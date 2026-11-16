// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded tar upload over the supervisor's credited SSH subsystem.

use std::io::{self, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

use miette::Diagnostic;
use openshell_core::upload::{
    ACK_INTERVAL_BYTES, DESTINATION_CHANGED_EXIT_CODE, UploadPlan, WINDOW_BYTES,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, Command as TokioCommand};
use tokio::sync::{mpsc, watch};
use tokio::task::{AbortHandle, JoinHandle};

const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(10);
const CHILD_EXIT_TIMEOUT: Duration = Duration::from_secs(5);
const CHUNK_BYTES: usize = 64 * 1024;
// A larger chunk could wait forever for credit the supervisor never reports.
const _: () = assert!(CHUNK_BYTES as u64 <= WINDOW_BYTES - ACK_INTERVAL_BYTES);
const MAX_DIAGNOSTIC_BYTES: usize = 16 * 1024;
/// The producer can hold at most two chunks in addition to its current buffer
/// and the chunk held by the sender. It cannot build an entire archive in RAM.
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

struct AbortOnDrop(AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// How a transfer ended before every archive byte was acknowledged.
#[derive(Debug)]
enum Stopped {
    /// The SSH stream closed or failed; the exit status explains why.
    Stream(String),
    /// A local or protocol failure; the SSH child must be terminated.
    Local(UploadError),
}

/// Archive bytes sent and the final total the supervisor acknowledged.
#[derive(Debug)]
struct Sent {
    bytes: u64,
    acknowledged: u64,
}

/// Start the producer only after the subsystem has started extraction.
/// The archive callback uses the existing tar builder unchanged.
pub(super) async fn run<P>(
    mut command: Command,
    plan: UploadPlan,
    producer: P,
) -> Result<(), UploadError>
where
    P: FnOnce(&mut dyn Write) -> miette::Result<()> + Send + 'static,
{
    let plan = plan
        .encode()
        .map_err(|error| UploadError::Protocol(error.to_string()))?;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = TokioCommand::from(command)
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| UploadError::Transport(error.to_string()))?;
    // EOF marks the end of the archive, so a failed or cancelled transfer must
    // stop SSH before its stdin closes. The transfer closes stdin only on
    // success, and declaring stdin first drops the guard, killing SSH, first.
    let mut stdin = Some(child.stdin.take().expect("piped SSH stdin"));
    let stdout = child.stdout.take().expect("piped SSH stdout");
    let stderr = child.stderr.take().expect("piped SSH stderr");
    let mut child = ChildGuard(Some(child));
    let diagnostics = tokio::spawn(read_diagnostic(stderr));
    let _diagnostics = AbortOnDrop(diagnostics.abort_handle());

    let transfer = match transfer(stdout, &mut stdin, plan, producer).await {
        Ok(sent) => Ok(sent),
        Err(Stopped::Stream(message)) => Err(message),
        Err(Stopped::Local(error)) => {
            let _ = child.finish(true).await;
            drop(stdin);
            return Err(match error {
                UploadError::Transport(message) => UploadError::Transport(format!(
                    "{message}: {}",
                    finish_diagnostic(diagnostics).await
                )),
                error => error,
            });
        }
    };
    drop(stdin);
    let Ok(status) = tokio::time::timeout(CHILD_EXIT_TIMEOUT, child.finish(false)).await else {
        let _ = child.finish(true).await;
        return Err(UploadError::Transport(
            "SSH did not exit after the upload stream ended".to_string(),
        ));
    };
    let status = status.map_err(|error| UploadError::Transport(error.to_string()))?;
    let diagnostic = finish_diagnostic(diagnostics).await;
    match status.code() {
        Some(0) => match transfer {
            Ok(sent) if sent.acknowledged == sent.bytes => Ok(()),
            Ok(sent) => Err(UploadError::Protocol(format!(
                "sandbox acknowledged {} of {} upload bytes",
                sent.acknowledged, sent.bytes
            ))),
            Err(message) => Err(UploadError::Protocol(format!(
                "upload stream ended before completion: {message}"
            ))),
        },
        // OpenSSH reports subsystem rejection as status 255, like other SSH
        // failures. Its explicit request diagnostic distinguishes an old server
        // from a transient connection failure, without sending any archive bytes.
        Some(super::SSH_TRANSPORT_FAILURE_EXIT_CODE)
            if diagnostic.contains("subsystem request failed") =>
        {
            Err(UploadError::Unsupported)
        }
        Some(super::SSH_TRANSPORT_FAILURE_EXIT_CODE) | None => Err(UploadError::Transport(
            format!("SSH exited with {status}: {diagnostic}"),
        )),
        Some(DESTINATION_CHANGED_EXIT_CODE) => Err(UploadError::Remote(format!(
            "upload destination changed type before extraction; retry the upload: {diagnostic}"
        ))),
        Some(code) => Err(UploadError::Remote(format!(
            "extraction exited with status {code}: {diagnostic}"
        ))),
    }
}

/// The tail of SSH stderr, which includes extraction output.
async fn finish_diagnostic(task: JoinHandle<String>) -> String {
    tokio::time::timeout(CHILD_EXIT_TIMEOUT, task)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default()
        .trim()
        .to_string()
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

enum ProducerEvent {
    Data(Vec<u8>),
    Finished(Result<(), UploadError>),
}

struct ChunkWriter {
    sender: mpsc::Sender<ProducerEvent>,
    buffer: Vec<u8>,
}

impl ChunkWriter {
    fn flush_chunk(&mut self) -> io::Result<()> {
        if !self.buffer.is_empty() {
            let buffer = std::mem::replace(&mut self.buffer, Vec::with_capacity(CHUNK_BYTES));
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
            let length = bytes.len().min(CHUNK_BYTES - self.buffer.len());
            self.buffer.extend_from_slice(&bytes[..length]);
            bytes = &bytes[length..];
            if self.buffer.len() == CHUNK_BYTES {
                self.flush_chunk()?;
            }
        }
        Ok(original_len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_chunk()
    }
}

fn spawn_producer<P>(producer: P) -> mpsc::Receiver<ProducerEvent>
where
    P: FnOnce(&mut dyn Write) -> miette::Result<()> + Send + 'static,
{
    let (sender, receiver) = mpsc::channel(PRODUCER_QUEUE_CHUNKS);
    tokio::task::spawn_blocking(move || {
        let mut writer = ChunkWriter {
            sender: sender.clone(),
            buffer: Vec::with_capacity(CHUNK_BYTES),
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

/// Send the plan, wait for extraction to start, then stream the archive while
/// at most `WINDOW_BYTES` remain unacknowledged. Takes `stdin` only after the
/// archive is complete, so failures leave the caller to stop SSH first.
async fn transfer<R, W, P>(
    mut reader: R,
    stdin: &mut Option<W>,
    plan: Vec<u8>,
    producer: P,
) -> Result<Sent, Stopped>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send,
    P: FnOnce(&mut dyn Write) -> miette::Result<()> + Send + 'static,
{
    let stream = |error: io::Error| Stopped::Stream(error.to_string());
    let writer = stdin.as_mut().expect("upload stdin is open");
    writer.write_all(&plan).await.map_err(stream)?;
    writer.flush().await.map_err(stream)?;
    match tokio::time::timeout(NEGOTIATION_TIMEOUT, reader.read_u64()).await {
        Err(_) => {
            return Err(Stopped::Local(UploadError::Transport(
                "upload negotiation timed out".to_string(),
            )));
        }
        Ok(Err(error)) => return Err(stream(error)),
        Ok(Ok(0)) => {}
        Ok(Ok(_)) => {
            return Err(Stopped::Local(UploadError::Protocol(
                "upload did not start at offset zero".to_string(),
            )));
        }
    }
    // The reader is never cancelled between partial records.
    let (totals, mut acknowledged) = watch::channel(0_u64);
    let acks = tokio::spawn(async move {
        while let Ok(total) = reader.read_u64().await {
            if total < *totals.borrow() {
                return Err(UploadError::Protocol(
                    "upload acknowledgment moved backwards".to_string(),
                ));
            }
            totals.send_replace(total);
        }
        Ok(())
    });
    let _acks = AbortOnDrop(acks.abort_handle());
    let mut chunks = spawn_producer(producer);
    let mut sent = 0_u64;
    loop {
        let chunk = match chunks.recv().await {
            Some(ProducerEvent::Data(chunk)) => chunk,
            Some(ProducerEvent::Finished(result)) => {
                result.map_err(Stopped::Local)?;
                break;
            }
            None => {
                return Err(Stopped::Local(UploadError::Archive(
                    "archive producer stopped".to_string(),
                )));
            }
        };
        let length = chunk.len() as u64;
        loop {
            let total = *acknowledged.borrow_and_update();
            if total > sent {
                return Err(Stopped::Local(UploadError::Protocol(
                    "upload acknowledged unsent bytes".to_string(),
                )));
            }
            if sent + length - total <= WINDOW_BYTES {
                break;
            }
            if acknowledged.changed().await.is_err() {
                return Err(match acks.await {
                    Ok(Err(error)) => Stopped::Local(error),
                    _ => Stopped::Stream("upload acknowledgments ended".to_string()),
                });
            }
        }
        sent += length;
        writer.write_all(&chunk).await.map_err(stream)?;
    }
    // Closing stdin sends SSH EOF; the final total arrives before exit status.
    writer.shutdown().await.map_err(stream)?;
    stdin.take();
    if let Ok(Err(error)) = acks.await {
        return Err(Stopped::Local(error));
    }
    let acknowledged = *acknowledged.borrow();
    if acknowledged > sent {
        return Err(Stopped::Local(UploadError::Protocol(
            "upload acknowledged unsent bytes".to_string(),
        )));
    }
    Ok(Sent {
        bytes: sent,
        acknowledged,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncBufReadExt, BufReader, DuplexStream, ReadHalf, WriteHalf};

    #[allow(clippy::cast_possible_truncation)]
    const WINDOW: usize = WINDOW_BYTES as usize;
    type Check = fn(&Result<(), UploadError>) -> bool;

    fn plan() -> UploadPlan {
        UploadPlan {
            destination_directory: "/tmp/upload".to_string(),
            expected_destination: None,
        }
    }

    fn start(
        producer: impl FnOnce(&mut dyn Write) -> miette::Result<()> + Send + 'static,
        buffer: usize,
    ) -> (JoinHandle<Result<Sent, Stopped>>, DuplexStream) {
        let (client, server) = tokio::io::duplex(buffer);
        let (read, write) = tokio::io::split(client);
        let plan = plan().encode().unwrap();
        let transfer = tokio::spawn(async move {
            let mut write = Some(write);
            transfer(read, &mut write, plan, producer).await
        });
        (transfer, server)
    }

    /// Read the plan line and grant the zero acknowledgment.
    async fn accept(
        server: DuplexStream,
    ) -> (BufReader<ReadHalf<DuplexStream>>, WriteHalf<DuplexStream>) {
        let (read, mut write) = tokio::io::split(server);
        let mut read = BufReader::new(read);
        let mut line = Vec::new();
        read.read_until(b'\n', &mut line).await.unwrap();
        assert_eq!(line, plan().encode().unwrap());
        write.write_u64(0).await.unwrap();
        (read, write)
    }

    fn payload(bytes: usize) -> Vec<u8> {
        (0..bytes)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect()
    }

    fn produce(bytes: Vec<u8>) -> impl FnOnce(&mut dyn Write) -> miette::Result<()> {
        move |writer| writer.write_all(&bytes).map_err(miette::Report::from_err)
    }

    #[tokio::test]
    async fn stalled_consumer_blocks_at_credit_limit_then_resumes_with_exact_data() {
        let expected = payload(6 * WINDOW + 123);
        let (client, server) = start(produce(expected.clone()), 4096);
        let (mut read, mut write) = accept(server).await;
        let mut received = vec![0; WINDOW];
        read.read_exact(&mut received).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), read.read_u8())
                .await
                .is_err(),
            "client exceeded credit while the extractor was stalled"
        );
        assert!(!client.is_finished());
        // Acknowledge in ordinary-sized steps until the client sends EOF.
        let mut chunk = vec![0; 256 * 1024];
        loop {
            write.write_u64(received.len() as u64).await.unwrap();
            let size = read.read(&mut chunk).await.unwrap();
            if size == 0 {
                break;
            }
            received.extend_from_slice(&chunk[..size]);
        }
        write.shutdown().await.unwrap();
        let sent = client.await.unwrap().unwrap();
        assert_eq!(received, expected);
        assert_eq!(sent.bytes, expected.len() as u64);
        assert_eq!(sent.acknowledged, sent.bytes);
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
        let (client, server) = start(
            move |writer| {
                let _finished = ProducerExit(producer_finished);
                writer
                    .write_all(&payload(8 * WINDOW))
                    .map_err(miette::Report::from_err)
            },
            4096,
        );
        let (mut read, _write) = accept(server).await;
        let mut received = vec![0; WINDOW];
        read.read_exact(&mut received).await.unwrap();
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
    async fn impossible_and_regressing_acks_are_rejected_without_retry() {
        for regress in [false, true] {
            let (client, server) = start(produce(payload(4 * WINDOW)), 4096);
            let (mut read, mut write) = accept(server).await;
            if regress {
                let mut chunk = vec![0; CHUNK_BYTES];
                read.read_exact(&mut chunk).await.unwrap();
                write.write_u64(CHUNK_BYTES as u64).await.unwrap();
                write.write_u64(CHUNK_BYTES as u64 - 1).await.unwrap();
            } else {
                write.write_u64(u64::MAX).await.unwrap();
            }
            // Keep consuming so the client reaches its next credit decision.
            let drain = tokio::spawn(async move {
                let _ = tokio::io::copy(&mut read, &mut tokio::io::sink()).await;
            });
            let Err(Stopped::Local(error)) = client.await.unwrap() else {
                panic!("invalid acknowledgment was accepted");
            };
            assert!(matches!(error, UploadError::Protocol(_)));
            assert!(!error.is_retryable());
            drop(write);
            drain.await.unwrap();
        }
    }

    #[tokio::test]
    async fn failed_archive_leaves_stdin_open_for_the_caller_to_stop_ssh() {
        let (client, server) = tokio::io::duplex(4096);
        let (read, write) = tokio::io::split(client);
        let mut stdin = Some(write);
        let server = tokio::spawn(async move {
            let (mut read, write) = accept(server).await;
            let mut partial = [0; 7];
            read.read_exact(&mut partial).await.unwrap();
            (read, write)
        });
        let result = transfer(read, &mut stdin, plan().encode().unwrap(), |writer| {
            writer
                .write_all(b"partial")
                .map_err(miette::Report::from_err)?;
            writer.flush().map_err(miette::Report::from_err)?;
            Err(miette::miette!("source file vanished"))
        })
        .await;
        assert!(matches!(
            result,
            Err(Stopped::Local(UploadError::Archive(_)))
        ));
        // EOF would mark a truncated archive as complete.
        assert!(stdin.is_some());
        let (mut read, _write) = server.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), read.read_u8())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn closed_stream_interrupts_blocked_pipe_write() {
        let (client, server) = start(produce(payload(2 * WINDOW)), 64);
        let (read, write) = accept(server).await;
        drop((read, write));
        let result = tokio::time::timeout(Duration::from_secs(1), client)
            .await
            .expect("remote closure must interrupt a blocked writer")
            .unwrap();
        assert!(matches!(result, Err(Stopped::Stream(_))));
    }

    #[cfg(unix)]
    async fn run_script(script: &str, started: Arc<AtomicBool>) -> Result<(), UploadError> {
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        run(command, plan(), move |writer| {
            started.store(true, Ordering::SeqCst);
            writer
                .write_all(b"archive")
                .map_err(miette::Report::from_err)
        })
        .await
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exit_status_and_final_total_decide_the_result() {
        // Each script reads the plan line, grants zero credit, then drains the
        // archive before reporting. `\0\0\0\0\0\0\0\a` is a total of seven bytes.
        const ZERO: &str = r"printf '\0\0\0\0\0\0\0\0'";
        const SEVEN: &str = r"printf '\0\0\0\0\0\0\0\a'";
        let cases: [(String, Check); 4] = [
            (
                format!("read -r plan; {ZERO}; cat >/dev/null; {SEVEN}"),
                |result| result.is_ok(),
            ),
            (format!("read -r plan; {ZERO}; cat >/dev/null"), |result| {
                matches!(result, Err(UploadError::Protocol(_)))
            }),
            (
                format!("read -r plan; {ZERO}; cat >/dev/null; echo 'tar: boom' >&2; exit 2"),
                |result| matches!(result, Err(UploadError::Remote(message)) if message.contains("tar: boom")),
            ),
            (
                format!("read -r plan; {ZERO}; cat >/dev/null; exit 73"),
                |result| matches!(result, Err(UploadError::Remote(message)) if message.contains("retry the upload")),
            ),
        ];
        for (script, check) in cases {
            let started = Arc::new(AtomicBool::new(false));
            let result = run_script(&script, started.clone()).await;
            assert!(check(&result), "{script}: {result:?}");
            assert!(started.load(Ordering::SeqCst));
            if let Err(error) = result {
                assert!(!error.is_retryable());
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failure_before_extraction_starts_never_starts_archive_producer() {
        for (script, retryable) in [
            (
                "printf 'subsystem request failed on channel 0\\n' >&2; exit 255",
                false,
            ),
            ("exit 255", true),
            ("read -r plan; echo 'mkdir: denied' >&2; exit 1", false),
        ] {
            let started = Arc::new(AtomicBool::new(false));
            let error = run_script(script, started.clone()).await.unwrap_err();
            assert!(!started.load(Ordering::SeqCst), "{script}");
            assert_eq!(error.is_retryable(), retryable, "{script}: {error:?}");
            if script.contains("subsystem") {
                assert!(matches!(error, UploadError::Unsupported));
            }
        }
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
