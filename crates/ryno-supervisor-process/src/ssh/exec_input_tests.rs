// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Real SSH sessions with controlled boundary I/O, including stalled stdin.

use super::input::MAX_PENDING_INPUT;
use super::tests::test_client;
use russh::ChannelMsg;
use ryno_isolation_interface::contract::{
    BackendError, BoundaryExec, BoundaryExitStatus, BoundaryProcess, BoundarySignal, ExecSession,
    ExecSpec,
};
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot, watch};

const DEADLINE: Duration = Duration::from_secs(5);

struct TrackedInput {
    stream: DuplexStream,
    dropped: Option<oneshot::Sender<()>>,
}

impl AsyncWrite for TrackedInput {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl Drop for TrackedInput {
    fn drop(&mut self) {
        if let Some(dropped) = self.dropped.take() {
            let _ = dropped.send(());
        }
    }
}

struct TestProcess {
    status: watch::Sender<Option<BoundaryExitStatus>>,
    signals: mpsc::UnboundedSender<BoundarySignal>,
    terminated: watch::Sender<bool>,
}

#[async_trait::async_trait]
impl BoundaryProcess for TestProcess {
    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
        let mut status = self.status.subscribe();
        Ok(*status
            .wait_for(Option::is_some)
            .await
            .unwrap()
            .as_ref()
            .unwrap())
    }

    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError> {
        self.signals.send(signal).unwrap();
        Ok(())
    }

    async fn terminate(&self) -> Result<(), BackendError> {
        self.terminated.send_replace(true);
        self.status
            .send_replace(Some(BoundaryExitStatus::Exited(0)));
        Ok(())
    }
}

struct TestExec(Mutex<VecDeque<ExecSession>>);

#[async_trait::async_trait]
impl BoundaryExec for TestExec {
    async fn exec(&self, _spec: ExecSpec) -> Result<ExecSession, BackendError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .pop_front()
            .expect("test exec session"))
    }
}

struct Control {
    stdin: DuplexStream,
    stdout: DuplexStream,
    stderr: DuplexStream,
    dropped: oneshot::Receiver<()>,
    process: Arc<TestProcess>,
    signals: mpsc::UnboundedReceiver<BoundarySignal>,
}

fn exec_session() -> (ExecSession, Control) {
    exec_session_with_capacity(1)
}

fn exec_session_with_capacity(capacity: usize) -> (ExecSession, Control) {
    // A one-byte sink makes every ordinary SSH packet stall in write_all until
    // the test starts reading. Retain the read end to distinguish cancellation
    // from a broken pipe caused by the fixture closing its own input.
    let (stdin, stdin_reader) = tokio::io::duplex(capacity);
    let (stdout, stdout_writer) = tokio::io::duplex(64 * 1024);
    let (stderr, stderr_writer) = tokio::io::duplex(64 * 1024);
    let (dropped_tx, dropped) = oneshot::channel();
    let (signals_tx, signals) = mpsc::unbounded_channel();
    let process = Arc::new(TestProcess {
        status: watch::channel(None).0,
        signals: signals_tx,
        terminated: watch::channel(false).0,
    });
    (
        ExecSession {
            process: process.clone(),
            stdin: Some(Box::new(TrackedInput {
                stream: stdin,
                dropped: Some(dropped_tx),
            })),
            stdout: Box::new(stdout),
            stderr: Some(Box::new(stderr)),
            terminal: None,
            output_status: None,
        },
        Control {
            stdin: stdin_reader,
            stdout: stdout_writer,
            stderr: stderr_writer,
            dropped,
            process,
            signals,
        },
    )
}

async fn start_exec(
    client: &russh::client::Handle<super::tests::AcceptAnyServerKey>,
) -> russh::Channel<russh::client::Msg> {
    let mut channel = client.channel_open_session().await.unwrap();
    channel.exec(true, "cat").await.unwrap();
    assert!(matches!(channel.wait().await, Some(ChannelMsg::Success)));
    channel
}

#[tokio::test]
async fn full_input_allows_output_signals_and_channel_close() {
    tokio::time::timeout(DEADLINE, async {
        let (session, mut control) = exec_session();
        let client = test_client(
            None,
            Arc::new(TestExec(Mutex::new([session].into()))),
            russh::client::Config::default(),
        )
        .await;
        let mut channel = start_exec(&client).await;
        channel
            .data(vec![7; MAX_PENDING_INPUT].as_slice())
            .await
            .unwrap();
        // The signal follows all input packets on the wire and acts as a
        // barrier proving that the handler accepted the full pending budget.
        channel.signal(russh::Sig::INT).await.unwrap();
        assert_eq!(control.signals.recv().await, Some(BoundarySignal::Int));
        // Exceed the default SSH output window so this also requires incoming
        // window adjustments while stdin remains full.
        let output = tokio::spawn(async move {
            control
                .stdout
                .write_all(&vec![9; 3 * 1024 * 1024])
                .await
                .unwrap();
        });
        control
            .stderr
            .write_all(b"stderr while stdin is full")
            .await
            .unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        while stdout.len() < 3 * 1024 * 1024 || stderr.len() < 26 {
            match channel.wait().await.unwrap() {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
                ChannelMsg::WindowAdjusted { .. } => {}
                message => panic!("unexpected message: {message:?}"),
            }
        }
        assert_eq!(stdout, vec![9; 3 * 1024 * 1024]);
        assert_eq!(stderr, b"stderr while stdin is full");
        output.await.unwrap();
        channel.close().await.unwrap();
        control.dropped.await.expect("close releases blocked stdin");
        control
            .process
            .terminated
            .subscribe()
            .wait_for(|done| *done)
            .await
            .unwrap();
    })
    .await
    .expect("full stdin blocked output, signal, or close");
}

#[tokio::test]
async fn disconnect_cancels_stalled_input_without_main_session() {
    tokio::time::timeout(DEADLINE, async {
        let (session, mut control) = exec_session();
        let client = test_client(
            None,
            Arc::new(TestExec(Mutex::new([session].into()))),
            russh::client::Config::default(),
        )
        .await;
        let channel = start_exec(&client).await;
        channel
            .data(vec![7; MAX_PENDING_INPUT].as_slice())
            .await
            .unwrap();
        channel.signal(russh::Sig::INT).await.unwrap();
        control.signals.recv().await.unwrap();
        client
            .disconnect(russh::Disconnect::ByApplication, "test disconnect", "")
            .await
            .unwrap();
        control
            .dropped
            .await
            .expect("disconnect releases blocked stdin");
    })
    .await
    .expect("disconnect retained a blocked stdin writer");
}

#[tokio::test]
async fn process_exit_cancels_stalled_input() {
    tokio::time::timeout(DEADLINE, async {
        let (session, mut control) = exec_session();
        let client = test_client(
            None,
            Arc::new(TestExec(Mutex::new([session].into()))),
            russh::client::Config::default(),
        )
        .await;
        let mut channel = start_exec(&client).await;
        channel
            .data(vec![7; MAX_PENDING_INPUT].as_slice())
            .await
            .unwrap();
        channel.signal(russh::Sig::INT).await.unwrap();
        control.signals.recv().await.unwrap();
        control
            .process
            .status
            .send_replace(Some(BoundaryExitStatus::Exited(0)));
        drop(control.stdout);
        drop(control.stderr);
        control
            .dropped
            .await
            .expect("process exit releases blocked stdin");
        while let Some(message) = channel.wait().await {
            if let ChannelMsg::ExitStatus { exit_status } = message {
                assert_eq!(exit_status, 0);
                return;
            }
        }
        panic!("missing process exit status");
    })
    .await
    .expect("process exit retained a blocked stdin writer");
}

#[tokio::test]
async fn overflow_reports_failure_and_preserves_sibling_channel() {
    tokio::time::timeout(DEADLINE, async {
        let (first, mut a) = exec_session();
        let (second, mut b) = exec_session();
        let client = test_client(
            None,
            Arc::new(TestExec(Mutex::new([first, second].into()))),
            russh::client::Config::default(),
        )
        .await;
        let mut channel = start_exec(&client).await;
        let sibling = start_exec(&client).await;
        channel
            .data(vec![7; MAX_PENDING_INPUT].as_slice())
            .await
            .unwrap();
        channel.signal(russh::Sig::INT).await.unwrap();
        a.signals.recv().await.unwrap();
        channel.data(&b"overflow"[..]).await.unwrap();
        a.dropped.await.expect("overflow releases blocked stdin");
        a.process
            .terminated
            .subscribe()
            .wait_for(|done| *done)
            .await
            .unwrap();
        // Termination reports success in this fixture; the SSH result must
        // still report rejected input, with no later successful exit status.
        drop(a.stdout);
        drop(a.stderr);
        let mut statuses = Vec::new();
        let mut stderr = Vec::new();
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::ExitStatus { exit_status } => statuses.push(exit_status),
                ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        assert_eq!(statuses, [74]);
        assert!(stderr.is_empty());
        sibling.data(&b"still usable"[..]).await.unwrap();
        sibling.eof().await.unwrap();
        let mut received = Vec::new();
        b.stdin.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"still usable");
        sibling.close().await.unwrap();
    })
    .await
    .expect("overflow blocked cleanup or a sibling channel");
}

#[tokio::test]
async fn eof_drains_accepted_input_and_allows_larger_total_transfers() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (session, mut control) = exec_session_with_capacity(64 * 1024);
        let client = test_client(
            None,
            Arc::new(TestExec(Mutex::new([session].into()))),
            russh::client::Config::default(),
        )
        .await;
        let mut channel = start_exec(&client).await;
        // Consume each batch before sending the next, allowing a transfer
        // larger than the pending-byte budget without relying on scheduling.
        let payload = vec![42; 64 * 1024];
        let (read_tx, mut read_rx) = mpsc::channel(1);
        let reader = tokio::spawn(async move {
            let mut total = 0;
            let mut received = vec![0; 64 * 1024];
            for _ in 0..80 {
                control.stdin.read_exact(&mut received).await.unwrap();
                assert!(received.iter().all(|byte| *byte == 42));
                total += received.len();
                read_tx.send(()).await.unwrap();
            }
            let mut tail = Vec::new();
            control.stdin.read_to_end(&mut tail).await.unwrap();
            assert_eq!(tail, b"accepted before EOF");
            total
        });
        for _ in 0..80 {
            channel.data(payload.as_slice()).await.unwrap();
            read_rx.recv().await.unwrap();
        }
        channel.data(&b"accepted before EOF"[..]).await.unwrap();
        channel.eof().await.unwrap();
        assert_eq!(reader.await.unwrap(), 5 * 1024 * 1024);
        control.stdout.write_all(b"complete").await.unwrap();
        drop(control.stdout);
        drop(control.stderr);
        control
            .process
            .status
            .send_replace(Some(BoundaryExitStatus::Exited(0)));
        let mut output = Vec::new();
        let mut statuses = Vec::new();
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => output.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => statuses.push(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        assert_eq!(output, b"complete");
        assert_eq!(statuses, [0]);
    })
    .await
    .expect("EOF did not drain accepted input");
}

#[tokio::test]
async fn eof_preserves_queued_input_until_the_child_reads() {
    tokio::time::timeout(DEADLINE, async {
        let (session, mut control) = exec_session();
        let client = test_client(
            None,
            Arc::new(TestExec(Mutex::new([session].into()))),
            russh::client::Config::default(),
        )
        .await;
        let channel = start_exec(&client).await;
        channel.data(vec![42; 64 * 1024].as_slice()).await.unwrap();
        channel.eof().await.unwrap();
        channel.signal(russh::Sig::INT).await.unwrap();
        control.signals.recv().await.unwrap();
        // EOF has reached the handler while write_all is still blocked. Only
        // now let the child consume the accepted input and observe stdin EOF.
        let mut received = Vec::new();
        control.stdin.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, vec![42; 64 * 1024]);
        channel.close().await.unwrap();
    })
    .await
    .expect("EOF discarded or retained queued input");
}

#[tokio::test]
async fn overflow_reports_failure_without_output_window_credit() {
    tokio::time::timeout(DEADLINE, async {
        let (session, mut control) = exec_session();
        let (second, sibling_control) = exec_session();
        let client = test_client(
            None,
            Arc::new(TestExec(Mutex::new([session, second].into()))),
            russh::client::Config {
                window_size: 0,
                ..Default::default()
            },
        )
        .await;
        let mut channel = start_exec(&client).await;
        let mut sibling = start_exec(&client).await;
        channel
            .data(vec![7; MAX_PENDING_INPUT].as_slice())
            .await
            .unwrap();
        channel.signal(russh::Sig::INT).await.unwrap();
        control.signals.recv().await.unwrap();
        // Overflow must not queue a diagnostic behind the zero output window.
        // That would block Handle messages, including the sibling's status.
        channel.data(&b"overflow"[..]).await.unwrap();
        control.dropped.await.unwrap();
        loop {
            match channel.wait().await {
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(ChannelMsg::ExitStatus { exit_status: 74 }) => break,
                message => panic!("expected failure before output credit: {message:?}"),
            }
        }
        control
            .process
            .terminated
            .subscribe()
            .wait_for(|done| *done)
            .await
            .unwrap();
        sibling_control
            .process
            .status
            .send_replace(Some(BoundaryExitStatus::Exited(0)));
        drop(sibling_control.stdout);
        drop(sibling_control.stderr);
        loop {
            match sibling.wait().await {
                Some(ChannelMsg::ExitStatus { exit_status: 0 }) => break,
                Some(ChannelMsg::Eof | ChannelMsg::WindowAdjusted { .. }) => {}
                message => panic!("sibling did not complete: {message:?}"),
            }
        }
        client
            .disconnect(russh::Disconnect::ByApplication, "done", "")
            .await
            .unwrap();
    })
    .await
    .expect("overflow waited for output credit before reporting failure");
}
