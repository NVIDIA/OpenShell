// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Exercise the production upload handler over a real SSH session.

use super::tests::{AcceptAnyServerKey, test_client};
use openshell_core::upload::{
    Decoder, FailureCode, Frame, MAX_DATA_BYTES, SUBSYSTEM, UploadPlan, UploadSummary, WINDOW_BYTES,
};
use openshell_isolation_interface::contract::{
    BackendError, BoundaryExec, BoundaryExitStatus, BoundaryProcess, BoundarySignal, ExecSession,
    ExecSpec,
};
use russh::ChannelMsg;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot, watch};

const DEADLINE: Duration = Duration::from_secs(10);

struct Process {
    status: watch::Sender<Option<BoundaryExitStatus>>,
    terminated: watch::Sender<bool>,
    signals: mpsc::UnboundedSender<BoundarySignal>,
}

#[async_trait::async_trait]
impl BoundaryProcess for Process {
    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
        let mut status = self.status.subscribe();
        Ok(status
            .wait_for(Option::is_some)
            .await
            .unwrap()
            .as_ref()
            .copied()
            .unwrap())
    }

    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError> {
        let _ = self.signals.send(signal);
        Ok(())
    }

    async fn terminate(&self) -> Result<(), BackendError> {
        self.terminated.send_replace(true);
        self.status
            .send_replace(Some(BoundaryExitStatus::Exited(0)));
        Ok(())
    }
}

struct Exec(Mutex<VecDeque<ExecSession>>);

#[async_trait::async_trait]
impl BoundaryExec for Exec {
    async fn exec(&self, spec: ExecSpec) -> Result<ExecSession, BackendError> {
        assert!(!spec.pty);
        assert!(spec.runtime_helper.is_none());
        if spec.shell.as_ref().unwrap().command.as_deref() != Some("cat") {
            assert!(spec.shell.as_ref().unwrap().login);
        }
        Ok(self.0.lock().unwrap().pop_front().unwrap())
    }
}

struct Control {
    stdin: DuplexStream,
    stdout: DuplexStream,
    stderr: DuplexStream,
    process: Arc<Process>,
    signals: mpsc::UnboundedReceiver<BoundarySignal>,
}

fn exec_session() -> (ExecSession, Control) {
    let (stdin, reader) = tokio::io::duplex(1024);
    let (stdout, writer) = tokio::io::duplex(4096);
    let (stderr, errors) = tokio::io::duplex(4096);
    let (signal_tx, signals) = mpsc::unbounded_channel();
    let process = Arc::new(Process {
        status: watch::channel(None).0,
        terminated: watch::channel(false).0,
        signals: signal_tx,
    });
    (
        ExecSession {
            process: process.clone(),
            stdin: Some(Box::new(stdin)),
            stdout: Box::new(stdout),
            stderr: Some(Box::new(stderr)),
            terminal: None,
            output_status: None,
        },
        Control {
            stdin: reader,
            stdout: writer,
            stderr: errors,
            process,
            signals,
        },
    )
}

type Channel = russh::Channel<russh::client::Msg>;

struct Reader {
    decoder: Decoder,
    frames: VecDeque<Frame>,
    statuses: Vec<u32>,
}

impl Reader {
    fn new() -> Self {
        Self {
            decoder: Decoder::default(),
            frames: VecDeque::new(),
            statuses: Vec::new(),
        }
    }

    async fn frame(&mut self, channel: &mut Channel) -> Frame {
        loop {
            if let Some(frame) = self.frames.pop_front() {
                return frame;
            }
            match channel.wait().await.expect("channel closed before frame") {
                ChannelMsg::Data { data } => {
                    let mut bytes = data.as_ref();
                    while !bytes.is_empty() {
                        if let Some(frame) = self.decoder.decode(&mut bytes).unwrap() {
                            self.frames.push_back(frame);
                        }
                    }
                }
                ChannelMsg::ExitStatus { exit_status } => self.statuses.push(exit_status),
                ChannelMsg::WindowAdjusted { .. } | ChannelMsg::Success | ChannelMsg::Eof => {}
                message => panic!("unexpected SSH message: {message:?}"),
            }
        }
    }
}

async fn send(channel: &Channel, frame: Frame) {
    channel
        .data(frame.encode().unwrap().as_slice())
        .await
        .unwrap();
}

async fn start(client: &russh::client::Handle<AcceptAnyServerKey>) -> (Channel, Reader) {
    let mut channel = client.channel_open_session().await.unwrap();
    channel.request_subsystem(true, SUBSYSTEM).await.unwrap();
    assert!(matches!(channel.wait().await, Some(ChannelMsg::Success)));
    let mut reader = Reader::new();
    assert_eq!(
        reader.frame(&mut channel).await,
        Frame::Hello {
            window_bytes: WINDOW_BYTES,
            max_data_bytes: u32::try_from(MAX_DATA_BYTES).unwrap(),
        }
    );
    send(
        &channel,
        Frame::Begin(UploadPlan {
            destination_directory: "/tmp/upload".to_string(),
            expected_destination: None,
        }),
    )
    .await;
    assert_eq!(reader.frame(&mut channel).await, Frame::Ready);
    (channel, reader)
}

#[tokio::test]
async fn stalled_upload_preserves_controls_then_resumes_beyond_four_mib() {
    tokio::time::timeout(DEADLINE, async {
        let (upload, mut control) = exec_session();
        let (sibling, mut other) = exec_session();
        let client = test_client(
            None,
            Arc::new(Exec(Mutex::new([upload, sibling].into()))),
            russh::client::Config::default(),
        )
        .await;
        let (mut channel, mut reader) = start(&client).await;
        let payload = vec![42; MAX_DATA_BYTES];
        let mut sent = 0_u64;
        while sent < u64::from(WINDOW_BYTES) {
            send(&channel, Frame::Data(payload.clone())).await;
            sent += payload.len() as u64;
        }
        channel.signal(russh::Sig::INT).await.unwrap();
        assert_eq!(control.signals.recv().await, Some(BoundarySignal::Int));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), reader.frame(&mut channel))
                .await
                .is_err()
        );
        // Stalled upload input must leave sibling channel requests responsive.
        let mut sibling = client.channel_open_session().await.unwrap();
        sibling.exec(true, "cat").await.unwrap();
        assert!(matches!(sibling.wait().await, Some(ChannelMsg::Success)));
        sibling.data(&b"sibling"[..]).await.unwrap();
        sibling.eof().await.unwrap();
        let mut sibling_input = Vec::new();
        other.stdin.read_to_end(&mut sibling_input).await.unwrap();
        assert_eq!(sibling_input, b"sibling");
        sibling.close().await.unwrap();
        // Output is drained into a bounded diagnostic, never exposed as forged
        // protocol stdout or allowed to block extraction on a full pipe.
        let forged = Frame::Ack(u64::MAX).encode().unwrap();
        control.stdout.write_all(&forged).await.unwrap();
        let noisy = tokio::spawn(async move {
            control
                .stderr
                .write_all(&vec![9; 1024 * 1024])
                .await
                .unwrap();
            drop(control.stderr);
        });
        let consumed = tokio::spawn(async move {
            let mut bytes = Vec::new();
            control.stdin.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, vec![42; 5 * 1024 * 1024]);
            drop(control.stdout);
            control
                .process
                .status
                .send_replace(Some(BoundaryExitStatus::Exited(0)));
        });
        let mut ack = 0;
        while sent < 5 * 1024 * 1024 {
            if sent + MAX_DATA_BYTES as u64 > ack + u64::from(WINDOW_BYTES) {
                match reader.frame(&mut channel).await {
                    Frame::Ack(consumed) => {
                        assert!(consumed >= ack && consumed <= sent);
                        ack = consumed;
                    }
                    frame => panic!("unexpected transfer reply: {frame:?}"),
                }
            } else {
                send(&channel, Frame::Data(payload.clone())).await;
                sent += payload.len() as u64;
            }
        }
        let summary = UploadSummary {
            bytes: sent,
            sha256: Sha256::digest(vec![42; usize::try_from(sent).unwrap()]).into(),
        };
        send(&channel, Frame::End(summary)).await;
        channel.eof().await.unwrap();
        loop {
            match reader.frame(&mut channel).await {
                Frame::Ack(consumed) => assert!(consumed <= sent),
                Frame::Result(actual) => {
                    assert_eq!(actual, summary);
                    break;
                }
                frame => panic!("unexpected terminal reply: {frame:?}"),
            }
        }
        let mut statuses = Vec::new();
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::ExitStatus { exit_status } => statuses.push(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        assert_eq!(statuses, [0]);
        consumed.await.unwrap();
        noisy.await.unwrap();
    })
    .await
    .expect("upload did not resume or blocked SSH control traffic");
}

#[tokio::test]
async fn credit_violation_and_truncated_eof_are_typed_and_terminate() {
    for truncated in [false, true] {
        tokio::time::timeout(DEADLINE, async {
            let (session, control) = exec_session();
            let client = test_client(
                None,
                Arc::new(Exec(Mutex::new([session].into()))),
                russh::client::Config::default(),
            )
            .await;
            let (mut channel, mut reader) = start(&client).await;
            if truncated {
                channel.eof().await.unwrap();
            } else {
                for _ in 0..=WINDOW_BYTES as usize / MAX_DATA_BYTES {
                    send(&channel, Frame::Data(vec![7; MAX_DATA_BYTES])).await;
                }
            }
            assert!(matches!(reader.frame(&mut channel).await, Frame::Error(error) if error.code == FailureCode::Protocol));
            control.process.terminated.subscribe().wait_for(|terminated| *terminated).await.unwrap();
            let mut eof = Vec::new();
            let _ = control.stdin.take(2).read_to_end(&mut eof).await;
        })
        .await
        .expect("protocol failure retained a stalled input or process");
    }
}

#[tokio::test]
async fn broken_stdin_and_early_exit_wake_credit_waiter() {
    for early_exit in [false, true] {
        tokio::time::timeout(DEADLINE, async {
            let (session, control) = exec_session();
            let client = test_client(
                None,
                Arc::new(Exec(Mutex::new([session].into()))),
                russh::client::Config::default(),
            )
            .await;
            let (mut channel, mut reader) = start(&client).await;
            if early_exit {
                control.process.status.send_replace(Some(BoundaryExitStatus::Exited(1)));
            } else {
                drop(control.stdin);
                send(&channel, Frame::Data(vec![7; MAX_DATA_BYTES])).await;
            }
            let expected = if early_exit { FailureCode::Extract } else { FailureCode::InputWrite };
            assert!(matches!(reader.frame(&mut channel).await, Frame::Error(error) if error.code == expected));
            control.process.terminated.subscribe().wait_for(|terminated| *terminated).await.unwrap();
        })
        .await
        .expect("terminal failure did not wake upload sender");
    }
}

#[tokio::test]
async fn close_and_disconnect_cancel_stalled_boundary_input() {
    for disconnect in [false, true] {
        tokio::time::timeout(DEADLINE, async {
            let (session, mut control) = exec_session();
            let client = test_client(
                None,
                Arc::new(Exec(Mutex::new([session].into()))),
                russh::client::Config::default(),
            )
            .await;
            let (channel, _) = start(&client).await;
            send(&channel, Frame::Data(vec![7; MAX_DATA_BYTES])).await;
            channel.signal(russh::Sig::INT).await.unwrap();
            control.signals.recv().await.unwrap();
            if disconnect {
                client
                    .disconnect(russh::Disconnect::ByApplication, "test", "")
                    .await
                    .unwrap();
            } else {
                channel.close().await.unwrap();
            }
            control
                .process
                .terminated
                .subscribe()
                .wait_for(|terminated| *terminated)
                .await
                .unwrap();
            let mut received = Vec::new();
            control.stdin.read_to_end(&mut received).await.unwrap();
            assert!(received.len() <= 1024);
        })
        .await
        .expect("close or disconnect stranded upload input");
    }
}

#[tokio::test]
async fn upload_rejects_pty_and_duplicate_channel_requests() {
    tokio::time::timeout(DEADLINE, async {
        let client = test_client(
            None,
            Arc::new(super::tests::RejectingExec),
            russh::client::Config::default(),
        )
        .await;
        let mut pty = client.channel_open_session().await.unwrap();
        pty.request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        assert!(matches!(pty.wait().await, Some(ChannelMsg::Success)));
        pty.request_subsystem(true, SUBSYSTEM).await.unwrap();
        assert!(matches!(pty.wait().await, Some(ChannelMsg::Failure)));
        let mut upload = client.channel_open_session().await.unwrap();
        upload.request_subsystem(true, SUBSYSTEM).await.unwrap();
        assert!(matches!(upload.wait().await, Some(ChannelMsg::Success)));
        let mut reader = Reader::new();
        assert!(matches!(
            reader.frame(&mut upload).await,
            Frame::Hello { .. }
        ));
        upload.exec(true, "cat").await.unwrap();
        assert!(matches!(upload.wait().await, Some(ChannelMsg::Failure)));
        upload.request_shell(true).await.unwrap();
        assert!(matches!(upload.wait().await, Some(ChannelMsg::Failure)));
        upload.request_subsystem(true, "sftp").await.unwrap();
        assert!(matches!(upload.wait().await, Some(ChannelMsg::Failure)));
        upload
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        assert!(matches!(upload.wait().await, Some(ChannelMsg::Failure)));
        upload.close().await.unwrap();
    })
    .await
    .expect("duplicate upload request disrupted SSH session");
}

struct DelayedExec {
    session: Mutex<Option<ExecSession>>,
    started: watch::Sender<bool>,
    release: Mutex<Option<oneshot::Receiver<()>>>,
}

#[async_trait::async_trait]
impl BoundaryExec for DelayedExec {
    async fn exec(&self, _: ExecSpec) -> Result<ExecSession, BackendError> {
        let release = self.release.lock().unwrap().take().unwrap();
        self.started.send_replace(true);
        release.await.unwrap();
        Ok(self.session.lock().unwrap().take().unwrap())
    }
}

#[tokio::test]
async fn cancellation_during_remote_startup_terminates_late_process() {
    for disconnect in [false, true] {
        tokio::time::timeout(DEADLINE, async {
            let (session, control) = exec_session();
            let (release, receiver) = oneshot::channel();
            let started = watch::channel(false).0;
            let client = test_client(
                None,
                Arc::new(DelayedExec {
                    session: Mutex::new(Some(session)),
                    started: started.clone(),
                    release: Mutex::new(Some(receiver)),
                }),
                russh::client::Config::default(),
            )
            .await;
            let mut channel = client.channel_open_session().await.unwrap();
            channel.request_subsystem(true, SUBSYSTEM).await.unwrap();
            assert!(matches!(channel.wait().await, Some(ChannelMsg::Success)));
            let mut reader = Reader::new();
            assert!(matches!(
                reader.frame(&mut channel).await,
                Frame::Hello { .. }
            ));
            send(
                &channel,
                Frame::Begin(UploadPlan {
                    destination_directory: "/tmp/upload".into(),
                    expected_destination: None,
                }),
            )
            .await;
            started
                .subscribe()
                .wait_for(|started| *started)
                .await
                .unwrap();
            if disconnect {
                client
                    .disconnect(russh::Disconnect::ByApplication, "test", "")
                    .await
                    .unwrap();
            } else {
                channel.close().await.unwrap();
            }
            // A signal on another channel is a session-loop barrier proving
            // that the close was handled while startup is still pending.
            // Disconnect has no surviving channel, so wait for client closure.
            if disconnect {
                let _ = client.await;
            } else {
                let mut sibling = client.channel_open_session().await.unwrap();
                sibling
                    .request_subsystem(true, "unsupported")
                    .await
                    .unwrap();
                assert!(matches!(sibling.wait().await, Some(ChannelMsg::Failure)));
            }
            release.send(()).unwrap();
            control
                .process
                .terminated
                .subscribe()
                .wait_for(|terminated| *terminated)
                .await
                .unwrap();
        })
        .await
        .expect("cancelled startup stranded a late extractor");
    }
}

#[tokio::test]
async fn mismatched_end_and_extended_data_fail_without_result() {
    for extended in [false, true] {
        tokio::time::timeout(DEADLINE, async {
            let (session, control) = exec_session();
            let client = test_client(None, Arc::new(Exec(Mutex::new([session].into()))), russh::client::Config::default()).await;
            let (mut channel, mut reader) = start(&client).await;
            if extended {
                channel.extended_data(1, b"unexpected".as_slice()).await.unwrap();
            } else {
                send(&channel, Frame::End(UploadSummary {bytes: 1, sha256: [0;32]})).await;
            }
            assert!(matches!(reader.frame(&mut channel).await, Frame::Error(failure) if failure.code == FailureCode::Protocol));
            control.process.terminated.subscribe().wait_for(|terminated| *terminated).await.unwrap();
        }).await.expect("invalid upload input did not terminate");
    }
}

struct LoginProbe(watch::Sender<Option<bool>>);

#[async_trait::async_trait]
impl BoundaryExec for LoginProbe {
    async fn exec(&self, spec: ExecSpec) -> Result<ExecSession, BackendError> {
        self.0.send_replace(Some(spec.shell.unwrap().login));
        Err(BackendError::Process("login selection observed".into()))
    }
}

#[tokio::test]
async fn upload_preserves_login_shell_selection() {
    for no_login in [false, true] {
        tokio::time::timeout(DEADLINE, async {
            let login = watch::channel(None).0;
            let client = test_client(
                None,
                Arc::new(LoginProbe(login.clone())),
                russh::client::Config::default(),
            )
            .await;
            let mut channel = client.channel_open_session().await.unwrap();
            if no_login {
                channel
                    .set_env(true, "OPENSHELL_NO_LOGIN_SHELL", "1")
                    .await
                    .unwrap();
                assert!(matches!(channel.wait().await, Some(ChannelMsg::Success)));
            }
            channel.request_subsystem(true, SUBSYSTEM).await.unwrap();
            assert!(matches!(channel.wait().await, Some(ChannelMsg::Success)));
            let mut reader = Reader::new();
            assert!(matches!(
                reader.frame(&mut channel).await,
                Frame::Hello { .. }
            ));
            send(
                &channel,
                Frame::Begin(UploadPlan {
                    destination_directory: "/tmp/upload".into(),
                    expected_destination: None,
                }),
            )
            .await;
            assert!(matches!(reader.frame(&mut channel).await, Frame::Error(_)));
            assert_eq!(*login.borrow(), Some(!no_login));
        })
        .await
        .expect("login shell selection not applied to upload");
    }
}
