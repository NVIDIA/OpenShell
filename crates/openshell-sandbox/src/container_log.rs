// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Container stdout/stderr shared by the agent's output and launcher log lines.

use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

const AGENT_OUTPUT_QUEUE_CHUNKS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentStream {
    Stdout,
    Stderr,
}

struct StderrState {
    writer: Box<dyn Write + Send>,
    mid_line: bool,
}

pub struct ContainerLog {
    stdout: Mutex<Box<dyn Write + Send>>,
    stderr: Mutex<StderrState>,
}

impl ContainerLog {
    #[must_use]
    pub fn new(stdout: Box<dyn Write + Send>, stderr: Box<dyn Write + Send>) -> Arc<Self> {
        Arc::new(Self {
            stdout: Mutex::new(stdout),
            stderr: Mutex::new(StderrState {
                writer: stderr,
                mid_line: false,
            }),
        })
    }

    /// The process's own stdout and stderr.
    pub fn process() -> &'static Arc<Self> {
        static LOG: OnceLock<Arc<ContainerLog>> = OnceLock::new();
        LOG.get_or_init(|| Self::new(Box::new(std::io::stdout()), Box::new(std::io::stderr())))
    }

    /// The agent output forwarder for the process's own stdout and stderr.
    pub fn process_agent_output() -> AgentOutputSink {
        static SINK: OnceLock<AgentOutputSink> = OnceLock::new();
        SINK.get_or_init(|| Self::process().agent_output()).clone()
    }

    fn write_agent(&self, stream: AgentStream, data: &[u8]) {
        match stream {
            AgentStream::Stdout => {
                let mut stdout = self.stdout.lock().expect("container stdout lock poisoned");
                let _ = stdout.write_all(data);
                let _ = stdout.flush();
            }
            AgentStream::Stderr => {
                let mut stderr = self.stderr.lock().expect("container stderr lock poisoned");
                if let Some(last) = data.last() {
                    stderr.mid_line = *last != b'\n';
                }
                let _ = stderr.writer.write_all(data);
                let _ = stderr.writer.flush();
            }
        }
    }

    fn write_launcher_line(&self, line: &[u8]) {
        let mut stderr = self.stderr.lock().expect("container stderr lock poisoned");
        let mut record = Vec::with_capacity(line.len() + 1);
        if stderr.mid_line {
            record.push(b'\n');
            stderr.mid_line = false;
        }
        record.extend_from_slice(line);
        let _ = stderr.writer.write_all(&record);
        let _ = stderr.writer.flush();
    }

    /// A writer for launcher log output that emits whole lines.
    #[must_use]
    pub fn launcher_writer(self: &Arc<Self>) -> LauncherLogWriter {
        LauncherLogWriter {
            log: Arc::clone(self),
            pending: Vec::new(),
        }
    }

    /// Forward agent output with a dedicated thread per stream.
    #[must_use]
    pub fn agent_output(self: &Arc<Self>) -> AgentOutputSink {
        AgentOutputSink {
            stdout: self.forwarder(AgentStream::Stdout, "openshell-agent-stdout"),
            stderr: self.forwarder(AgentStream::Stderr, "openshell-agent-stderr"),
        }
    }

    fn forwarder(self: &Arc<Self>, stream: AgentStream, name: &str) -> mpsc::Sender<AgentOutput> {
        let (sender, mut receiver) = mpsc::channel(AGENT_OUTPUT_QUEUE_CHUNKS);
        let log = Arc::clone(self);
        std::thread::Builder::new()
            .name(name.to_string())
            .spawn(move || {
                while let Some(message) = receiver.blocking_recv() {
                    match message {
                        AgentOutput::Data(data) => log.write_agent(stream, &data),
                        AgentOutput::Drained(done) => {
                            let _ = done.send(());
                        }
                    }
                }
            })
            .expect("spawn agent output forwarder");
        sender
    }
}

pub struct LauncherLogWriter {
    log: Arc<ContainerLog>,
    pending: Vec<u8>,
}

impl Write for LauncherLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.pending.extend_from_slice(buf);
        while let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=end).collect();
            self.log.write_launcher_line(&line);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

enum AgentOutput {
    Data(Bytes),
    Drained(oneshot::Sender<()>),
}

#[derive(Clone)]
pub struct AgentOutputSink {
    stdout: mpsc::Sender<AgentOutput>,
    stderr: mpsc::Sender<AgentOutput>,
}

impl AgentOutputSink {
    /// Waits while the container log is not keeping up with this stream.
    pub async fn send(&self, stream: AgentStream, data: Bytes) {
        let _ = self.sender(stream).send(AgentOutput::Data(data)).await;
    }

    /// Waits until previously sent output has been written.
    pub async fn drain(&self) {
        tokio::join!(drain(&self.stdout), drain(&self.stderr));
    }

    const fn sender(&self, stream: AgentStream) -> &mpsc::Sender<AgentOutput> {
        match stream {
            AgentStream::Stdout => &self.stdout,
            AgentStream::Stderr => &self.stderr,
        }
    }
}

async fn drain(sender: &mpsc::Sender<AgentOutput>) {
    let (done, drained) = oneshot::channel();
    if sender.send(AgentOutput::Drained(done)).await.is_ok() {
        let _ = drained.await;
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    #[derive(Clone, Default)]
    pub struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Capture {
        pub fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }

        pub async fn wait_for(&self, expected: &str) -> String {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while self.contents() != expected {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
            .await;
            self.contents()
        }
    }

    impl Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    pub fn capture_log() -> (Arc<ContainerLog>, Capture, Capture) {
        let stdout = Capture::default();
        let stderr = Capture::default();
        let log = ContainerLog::new(Box::new(stdout.clone()), Box::new(stderr.clone()));
        (log, stdout, stderr)
    }

    /// Holds container stdout writes until opened.
    #[derive(Clone, Default)]
    pub struct Gate(Arc<(Mutex<bool>, std::sync::Condvar)>);

    impl Gate {
        pub fn open(&self) {
            *self.0.0.lock().unwrap() = true;
            self.0.1.notify_all();
        }

        fn wait(&self) {
            let mut open = self.0.0.lock().unwrap();
            while !*open {
                open = self.0.1.wait(open).unwrap();
            }
        }
    }

    struct Gated(Gate, Capture);

    impl Write for Gated {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.wait();
            self.1.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    pub fn gated_capture_log(gate: &Gate) -> (Arc<ContainerLog>, Capture, Capture) {
        let stdout = Capture::default();
        let stderr = Capture::default();
        let log = ContainerLog::new(
            Box::new(Gated(gate.clone(), stdout.clone())),
            Box::new(stderr.clone()),
        );
        (log, stdout, stderr)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{Gate, capture_log, gated_capture_log};
    use super::*;

    #[test]
    fn agent_output_is_written_unmodified() {
        let (log, stdout, stderr) = capture_log();
        log.write_agent(AgentStream::Stdout, b"{\"msg\":\"out\"}\n");
        log.write_agent(AgentStream::Stderr, b"err\n");
        assert_eq!(stdout.contents(), "{\"msg\":\"out\"}\n");
        assert_eq!(stderr.contents(), "err\n");
    }

    #[test]
    fn launcher_lines_follow_complete_agent_lines() {
        let (log, stdout, stderr) = capture_log();
        log.write_agent(AgentStream::Stderr, b"agent line\n");
        log.write_launcher_line(b"WARN denied\n");
        assert_eq!(stderr.contents(), "agent line\nWARN denied\n");
        assert_eq!(stdout.contents(), "");
    }

    #[test]
    fn launcher_line_starts_on_a_new_line_after_partial_agent_stderr() {
        let (log, _stdout, stderr) = capture_log();
        log.write_agent(AgentStream::Stderr, b"partial");
        log.write_launcher_line(b"WARN denied\n");
        log.write_agent(AgentStream::Stderr, b" rest\n");
        assert_eq!(stderr.contents(), "partial\nWARN denied\n rest\n");
    }

    #[test]
    fn partial_agent_stdout_does_not_split_launcher_lines() {
        let (log, stdout, stderr) = capture_log();
        log.write_agent(AgentStream::Stdout, b"prompt> ");
        log.write_launcher_line(b"WARN denied\n");
        assert_eq!(stdout.contents(), "prompt> ");
        assert_eq!(stderr.contents(), "WARN denied\n");
    }

    #[test]
    fn launcher_writer_joins_fragmented_writes_into_lines() {
        let (log, _stdout, stderr) = capture_log();
        let mut writer = log.launcher_writer();
        write!(writer, "2026-01-01T00:00:00.000Z ").unwrap();
        write!(writer, "WARN target: one\nWARN target: ").unwrap();
        assert_eq!(
            stderr.contents(),
            "2026-01-01T00:00:00.000Z WARN target: one\n"
        );
        writeln!(writer, "two").unwrap();
        assert_eq!(
            stderr.contents(),
            "2026-01-01T00:00:00.000Z WARN target: one\nWARN target: two\n"
        );
    }

    #[tokio::test]
    async fn agent_output_sink_waits_for_a_stalled_log_without_dropping() {
        let gate = Gate::default();
        let (log, stdout, _stderr) = gated_capture_log(&gate);
        let sink = log.agent_output();
        let chunks = AGENT_OUTPUT_QUEUE_CHUNKS * 4;
        let sender = tokio::spawn(async move {
            for _ in 0..chunks {
                sink.send(AgentStream::Stdout, Bytes::from_static(b"x\n"))
                    .await;
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(!sender.is_finished());

        gate.open();
        sender.await.unwrap();
        let expected = "x\n".repeat(chunks);
        assert_eq!(stdout.wait_for(&expected).await, expected);
    }

    #[tokio::test]
    async fn stalled_stdout_does_not_block_stderr() {
        let gate = Gate::default();
        let (log, _stdout, stderr) = gated_capture_log(&gate);
        let sink = log.agent_output();
        let stdout_sink = sink.clone();
        let stdout_sender = tokio::spawn(async move {
            for _ in 0..AGENT_OUTPUT_QUEUE_CHUNKS * 4 {
                stdout_sink
                    .send(AgentStream::Stdout, Bytes::from_static(b"x\n"))
                    .await;
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(!stdout_sender.is_finished());

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            sink.send(AgentStream::Stderr, Bytes::from_static(b"still flowing\n")),
        )
        .await
        .expect("stderr send waited on stalled stdout");
        assert_eq!(stderr.wait_for("still flowing\n").await, "still flowing\n");
        gate.open();
    }

    #[tokio::test]
    async fn drain_waits_for_queued_output_to_be_written() {
        let gate = Gate::default();
        let (log, stdout, _stderr) = gated_capture_log(&gate);
        let sink = log.agent_output();
        sink.send(AgentStream::Stdout, Bytes::from_static(b"last words\n"))
            .await;
        let drain = tokio::spawn({
            let sink = sink.clone();
            async move { sink.drain().await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(!drain.is_finished());

        gate.open();
        drain.await.unwrap();
        assert_eq!(stdout.contents(), "last words\n");
    }

    #[tokio::test]
    async fn agent_output_sink_forwards_in_order() {
        let (log, stdout, stderr) = capture_log();
        let sink = log.agent_output();
        sink.send(AgentStream::Stdout, Bytes::from_static(b"one\n"))
            .await;
        sink.send(AgentStream::Stderr, Bytes::from_static(b"two\n"))
            .await;
        sink.send(AgentStream::Stdout, Bytes::from_static(b"three\n"))
            .await;
        assert_eq!(stdout.wait_for("one\nthree\n").await, "one\nthree\n");
        assert_eq!(stderr.wait_for("two\n").await, "two\n");
    }
}
