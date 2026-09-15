// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Exercise the gateway's actual SSH input/output bridge with a controllable peer.

use super::*;
use openshell_core::proto::{exec_sandbox_event, exec_sandbox_input};
use russh::server::{Auth, ChannelOpenHandle, Handler, Msg, Session};
use std::time::Duration;

struct ExecPeer {
    echo: bool,
    input: Arc<std::sync::Mutex<Vec<u8>>>,
    eof: Arc<AtomicBool>,
    release_output: Arc<tokio::sync::Notify>,
    output_task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for ExecPeer {
    fn drop(&mut self) {
        if let Some(task) = self.output_task.take() {
            task.abort();
        }
    }
}

impl Handler for ExecPeer {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        self.echo = data == b"duplex";
        if data == b"early" {
            session.exit_status_request(channel, 0)?;
            session.close(channel)?;
            return Ok(());
        }
        // Signal that SSH setup is complete without depending on input EOF.
        session.data(channel, b"ready".to_vec())?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.input.lock().unwrap().extend_from_slice(data);
        if self.echo {
            session.data(channel, data.to_vec())?;
            session.extended_data(channel, 1, data.to_vec())?;
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: russh::ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.eof.store(true, Ordering::SeqCst);
        let release = self.release_output.clone();
        let handle = session.handle();
        self.output_task = Some(tokio::spawn(async move {
            release.notified().await;
            if handle.data(channel, b"after eof".to_vec()).await.is_err() {
                return;
            }
            let _ = handle
                .extended_data(channel, 1, b"stderr after eof".to_vec())
                .await;
            let _ = handle.exit_status_request(channel, 7).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        }));
        Ok(())
    }

    async fn channel_close(
        &mut self,
        _channel: russh::ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // A client CLOSE before release must really prevent later output.
        if let Some(task) = self.output_task.take() {
            task.abort();
        }
        Ok(())
    }
}

struct Fixture {
    port: u16,
    input: Arc<std::sync::Mutex<Vec<u8>>>,
    eof: Arc<AtomicBool>,
    release_output: Arc<tokio::sync::Notify>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Fixture {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut config = russh::server::Config::default();
        config
            .keys
            .push(russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&rand::random()).into());
        let input = Arc::new(std::sync::Mutex::new(Vec::new()));
        let eof = Arc::new(AtomicBool::new(false));
        let release_output = Arc::new(tokio::sync::Notify::new());
        let handler = ExecPeer {
            echo: false,
            input: input.clone(),
            eof: eof.clone(),
            release_output: release_output.clone(),
            output_task: None,
        };
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            set_tcp_nodelay_best_effort(&socket);
            if let Ok(session) = russh::server::run_stream(Arc::new(config), socket, handler).await
            {
                let _ = session.await;
            }
        });
        Self {
            port,
            input,
            eof,
            release_output,
            server,
        }
    }
}

async fn ready(rx: &mut mpsc::Receiver<Result<ExecSandboxEvent, Status>>) {
    let event = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        matches!(event.payload, Some(exec_sandbox_event::Payload::Stdout(s)) if s.data == b"ready")
    );
}

#[tokio::test]
async fn interactive_exec_drains_stdout_and_stderr_after_input_eof() {
    let fixture = Fixture::new().await;
    let (input_tx, input_rx) = mpsc::channel(2);
    let (output_tx, mut output_rx) = mpsc::channel(2);
    let exec = run_interactive_exec_with_russh(
        fixture.port,
        "test",
        ReceiverStream::new(input_rx),
        false,
        false,
        0,
        0,
        output_tx,
    );
    let exercise = async {
        ready(&mut output_rx).await;
        input_tx
            .send(Ok(ExecSandboxInput {
                payload: Some(exec_sandbox_input::Payload::Stdin(b"input".to_vec())),
            }))
            .await
            .unwrap();
        drop(input_tx);
        while !fixture.eof.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        // Keep the peer silent briefly after EOF so a premature SSH CLOSE is
        // processed before output is released.
        tokio::time::sleep(Duration::from_millis(50)).await;
        fixture.release_output.notify_one();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        while let Some(event) = output_rx.recv().await {
            match event.unwrap().payload.unwrap() {
                exec_sandbox_event::Payload::Stdout(s) => stdout.extend(s.data),
                exec_sandbox_event::Payload::Stderr(s) => stderr.extend(s.data),
                other @ exec_sandbox_event::Payload::Exit(_) => {
                    panic!("unexpected event: {other:?}")
                }
            }
        }
        assert_eq!(stdout, b"after eof");
        assert_eq!(stderr, b"stderr after eof");
        assert_eq!(*fixture.input.lock().unwrap(), b"input");
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(exec, exercise)
    })
    .await
    .unwrap();
    assert_eq!(result.unwrap(), 7);
}

#[tokio::test]
async fn interactive_exec_makes_progress_in_both_directions_before_eof() {
    const CHUNKS: usize = 128;
    const CHUNK_SIZE: usize = 64 * 1024;
    let fixture = Fixture::new().await;
    let (input_tx, input_rx) = mpsc::channel(16);
    let (output_tx, mut output_rx) = mpsc::channel(2);
    let drained = tokio::sync::Notify::new();
    let exec = run_interactive_exec_with_russh(
        fixture.port,
        "duplex",
        ReceiverStream::new(input_rx),
        false,
        false,
        0,
        0,
        output_tx,
    );
    let writer = async {
        for _ in 0..CHUNKS {
            input_tx
                .send(Ok(ExecSandboxInput {
                    payload: Some(exec_sandbox_input::Payload::Stdin(vec![b'x'; CHUNK_SIZE])),
                }))
                .await
                .unwrap();
        }
        // Keep the request stream open until BOTH output streams have drained.
        // The payload exceeds SSH windows and all bridge queues, so buffering
        // the entire exchange cannot masquerade as concurrent progress.
        drained.notified().await;
        drop(input_tx);
    };
    let reader = async {
        ready(&mut output_rx).await;
        let mut stdout = 0;
        let mut stderr = 0;
        while stdout < CHUNKS * CHUNK_SIZE || stderr < CHUNKS * CHUNK_SIZE {
            let bytes = match output_rx.recv().await.unwrap().unwrap().payload.unwrap() {
                exec_sandbox_event::Payload::Stdout(s) => {
                    stdout += s.data.len();
                    s.data
                }
                exec_sandbox_event::Payload::Stderr(s) => {
                    stderr += s.data.len();
                    s.data
                }
                event => panic!("unexpected event: {event:?}"),
            };
            assert!(bytes.iter().all(|b| *b == b'x'));
            assert!(!fixture.eof.load(Ordering::SeqCst));
        }
        assert_eq!(stdout, CHUNKS * CHUNK_SIZE);
        assert_eq!(stderr, CHUNKS * CHUNK_SIZE);
        drained.notify_one();
        fixture.release_output.notify_one();
        while output_rx.recv().await.is_some() {}
    };
    let (result, (), ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(exec, writer, reader)
    })
    .await
    .expect("stdin and stdout/stderr must make progress without request EOF");
    assert_eq!(result.unwrap(), 7);
    assert_eq!(fixture.input.lock().unwrap().len(), CHUNKS * CHUNK_SIZE);
}

#[tokio::test]
async fn interactive_exec_input_error_is_not_graceful_eof() {
    for message in [
        Err(Status::cancelled("input cancelled")),
        Ok(ExecSandboxInput { payload: None }),
        Ok(ExecSandboxInput {
            payload: Some(exec_sandbox_input::Payload::Start(
                ExecSandboxRequest::default(),
            )),
        }),
    ] {
        let expected = message
            .as_ref()
            .err()
            .map_or(tonic::Code::InvalidArgument, Status::code);
        let fixture = Fixture::new().await;
        let (input_tx, input_rx) = mpsc::channel(1);
        let (output_tx, mut output_rx) = mpsc::channel(1);
        let exec = run_interactive_exec_with_russh(
            fixture.port,
            "test",
            ReceiverStream::new(input_rx),
            false,
            false,
            0,
            0,
            output_tx,
        );
        let exercise = async {
            ready(&mut output_rx).await;
            input_tx.send(message).await.unwrap();
            while output_rx.recv().await.is_some() {}
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(exec, exercise)
        })
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().code(), expected);
        assert!(!fixture.eof.load(Ordering::SeqCst));
    }
}

#[tokio::test]
async fn interactive_exec_response_drop_cancels_idle_input() {
    let fixture = Fixture::new().await;
    let (input_tx, input_rx) = mpsc::channel(1);
    let (output_tx, mut output_rx) = mpsc::channel(1);
    let exec = run_interactive_exec_with_russh(
        fixture.port,
        "test",
        ReceiverStream::new(input_rx),
        false,
        false,
        0,
        0,
        output_tx,
    );
    let exercise = async {
        ready(&mut output_rx).await;
        drop(output_rx);
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(exec, exercise)
    })
    .await
    .unwrap();
    assert_eq!(result.unwrap_err().code(), tonic::Code::Cancelled);
    assert!(input_tx.is_closed(), "stdin receiver must not outlive exec");
    assert!(!fixture.eof.load(Ordering::SeqCst));
}

#[tokio::test]
async fn interactive_exec_parent_abort_drops_input_receiver() {
    let fixture = Fixture::new().await;
    let (input_tx, input_rx) = mpsc::channel(1);
    let (output_tx, mut output_rx) = mpsc::channel(1);
    let exec = tokio::spawn(run_interactive_exec_with_russh(
        fixture.port,
        "test",
        ReceiverStream::new(input_rx),
        false,
        false,
        0,
        0,
        output_tx,
    ));
    ready(&mut output_rx).await;
    // An operation timeout drops the same future as this task abort.
    exec.abort();
    assert!(exec.await.unwrap_err().is_cancelled());
    assert!(
        input_tx.is_closed(),
        "aborted exec must not leave a stdin task alive"
    );
}

#[tokio::test]
async fn interactive_exec_response_drop_unblocks_full_output_queue() {
    let fixture = Fixture::new().await;
    let (input_tx, input_rx) = mpsc::channel(1);
    let (output_tx, mut output_rx) = mpsc::channel(1);
    // Use an empty request stream: EOF releases the peer's output once notified.
    drop(input_tx);
    let exec = run_interactive_exec_with_russh(
        fixture.port,
        "test",
        ReceiverStream::new(input_rx),
        false,
        false,
        0,
        0,
        output_tx,
    );
    let exercise = async {
        ready(&mut output_rx).await;
        fixture.release_output.notify_one();
        while output_rx.is_empty() {
            tokio::task::yield_now().await;
        }
        // stdout fills the one-slot queue while stderr still needs delivery.
        drop(output_rx);
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(exec, exercise)
    })
    .await
    .unwrap();
    assert_eq!(result.unwrap_err().code(), tonic::Code::Cancelled);
}

#[tokio::test]
async fn interactive_exec_early_exit_does_not_wait_for_stdin() {
    let fixture = Fixture::new().await;
    let (input_tx, input_rx) = mpsc::channel(1);
    input_tx
        .send(Ok(ExecSandboxInput {
            payload: Some(exec_sandbox_input::Payload::Stdin(vec![
                b'x';
                4 * 1024 * 1024
            ])),
        }))
        .await
        .unwrap();
    let (output_tx, _output_rx) = mpsc::channel(1);
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        run_interactive_exec_with_russh(
            fixture.port,
            "early",
            ReceiverStream::new(input_rx),
            false,
            false,
            0,
            0,
            output_tx,
        ),
    )
    .await
    .unwrap();
    assert_eq!(result.unwrap(), 0);
    assert!(input_tx.is_closed());
}
