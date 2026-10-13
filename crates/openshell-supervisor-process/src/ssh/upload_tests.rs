// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Exercise the production upload handler over a real SSH session.

use super::tests::{AcceptAnyServerKey, RejectingExec, test_client};
use openshell_core::upload::{SUBSYSTEM, UploadPlan, WINDOW_BYTES};
use openshell_isolation_interface::contract::{
    BackendError, BoundaryExec, BoundaryExitStatus, BoundaryProcess, BoundarySignal, ExecSession,
    ExecSpec,
};
use russh::ChannelMsg;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot, watch};

const DEADLINE: Duration = Duration::from_secs(10);
const CHUNK: usize = 64 * 1024;
#[allow(clippy::cast_possible_truncation)]
const WINDOW: usize = WINDOW_BYTES as usize;

struct Process {
    status: watch::Sender<Option<BoundaryExitStatus>>,
    waited: watch::Sender<bool>,
    terminated: watch::Sender<bool>,
    signals: mpsc::UnboundedSender<BoundarySignal>,
}

#[async_trait::async_trait]
impl BoundaryProcess for Process {
    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
        let mut status = self.status.subscribe();
        let result = status
            .wait_for(Option::is_some)
            .await
            .unwrap()
            .as_ref()
            .copied()
            .unwrap();
        self.waited.send_replace(true);
        Ok(result)
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

impl Process {
    async fn terminated(&self) {
        self.terminated
            .subscribe()
            .wait_for(|terminated| *terminated)
            .await
            .unwrap();
    }
}

fn exec_session() -> (ExecSession, Control) {
    let (stdin, reader) = tokio::io::duplex(1024);
    let (stdout, writer) = tokio::io::duplex(4096);
    let (stderr, errors) = tokio::io::duplex(4096);
    let (signal_tx, signals) = mpsc::unbounded_channel();
    let process = Arc::new(Process {
        status: watch::channel(None).0,
        waited: watch::channel(false).0,
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

async fn client_for(sessions: Vec<ExecSession>) -> russh::client::Handle<AcceptAnyServerKey> {
    test_client(
        None,
        Arc::new(Exec(Mutex::new(sessions.into()))),
        russh::client::Config::default(),
    )
    .await
}

type Channel = russh::Channel<russh::client::Msg>;

/// Collects acknowledgment totals from stdout, stderr and exit statuses.
#[derive(Default)]
struct Reader {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    statuses: Vec<u32>,
}

impl Reader {
    /// Next acknowledged total, or `None` once the channel closes.
    async fn next(&mut self, channel: &mut Channel) -> Option<u64> {
        loop {
            if self.stdout.len() >= 8 {
                let total = self.stdout.drain(..8).collect::<Vec<_>>();
                return Some(u64::from_be_bytes(total.try_into().unwrap()));
            }
            match channel.wait().await? {
                ChannelMsg::Data { data } => self.stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => self.stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => self.statuses.push(exit_status),
                ChannelMsg::Close => return None,
                ChannelMsg::WindowAdjusted { .. } | ChannelMsg::Success | ChannelMsg::Eof => {}
                message => panic!("unexpected SSH message: {message:?}"),
            }
        }
    }

    /// Remaining totals through channel close; no partial total may remain.
    async fn close(&mut self, channel: &mut Channel) -> Vec<u64> {
        let mut totals = Vec::new();
        while let Some(total) = self.next(channel).await {
            totals.push(total);
        }
        assert!(self.stdout.is_empty(), "partial acknowledgment");
        totals
    }
}

fn plan_line() -> Vec<u8> {
    UploadPlan {
        destination_directory: "/tmp/upload".to_string(),
        expected_destination: None,
    }
    .encode()
    .unwrap()
}

async fn open(client: &russh::client::Handle<AcceptAnyServerKey>) -> Channel {
    let mut channel = client.channel_open_session().await.unwrap();
    channel.request_subsystem(true, SUBSYSTEM).await.unwrap();
    assert!(matches!(channel.wait().await, Some(ChannelMsg::Success)));
    channel
}

async fn start(client: &russh::client::Handle<AcceptAnyServerKey>) -> (Channel, Reader) {
    let mut channel = open(client).await;
    channel.data(plan_line().as_slice()).await.unwrap();
    let mut reader = Reader::default();
    assert_eq!(reader.next(&mut channel).await, Some(0));
    (channel, reader)
}

#[tokio::test]
async fn stalled_upload_preserves_controls_then_resumes_beyond_four_mib() {
    tokio::time::timeout(DEADLINE, async {
        let (upload, mut control) = exec_session();
        let (sibling, mut other) = exec_session();
        let client = client_for(vec![upload, sibling]).await;
        let (mut channel, mut reader) = start(&client).await;
        let chunk = vec![42; CHUNK];
        let mut sent = 0;
        while sent < WINDOW {
            channel.data(chunk.as_slice()).await.unwrap();
            sent += CHUNK;
        }
        channel.signal(russh::Sig::INT).await.unwrap();
        assert_eq!(control.signals.recv().await, Some(BoundarySignal::Int));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), reader.next(&mut channel))
                .await
                .is_err(),
            "credit returned before the extractor consumed input"
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
        // Extractor stdout is delivered as stderr, so it cannot forge credit.
        let forged = u64::MAX.to_be_bytes();
        control.stdout.write_all(&forged).await.unwrap();
        let noisy = tokio::spawn(async move {
            control
                .stderr
                .write_all(&vec![9; 1024 * 1024])
                .await
                .unwrap();
        });
        let consumed = tokio::spawn(async move {
            let mut bytes = Vec::new();
            control.stdin.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, vec![42; 5 * WINDOW]);
            drop(control.stdout);
            control
                .process
                .status
                .send_replace(Some(BoundaryExitStatus::Exited(0)));
        });
        let mut acknowledged = 0;
        while sent < 5 * WINDOW {
            if sent + CHUNK > acknowledged + WINDOW {
                let total = reader.next(&mut channel).await.unwrap();
                assert!(total >= acknowledged as u64 && total <= sent as u64);
                acknowledged = usize::try_from(total).unwrap();
            } else {
                channel.data(chunk.as_slice()).await.unwrap();
                sent += CHUNK;
            }
        }
        channel.eof().await.unwrap();
        noisy.await.unwrap();
        let totals = reader.close(&mut channel).await;
        assert_eq!(totals.last(), Some(&(sent as u64)));
        assert_eq!(reader.statuses, [0]);
        assert_eq!(reader.stderr.len(), forged.len() + 1024 * 1024);
        assert!(reader.stderr.windows(8).any(|bytes| bytes == forged));
        consumed.await.unwrap();
    })
    .await
    .expect("upload did not resume or blocked SSH control traffic");
}

#[tokio::test]
async fn small_upload_in_one_packet_reports_final_total() {
    tokio::time::timeout(DEADLINE, async {
        let (session, mut control) = exec_session();
        let client = client_for(vec![session]).await;
        let mut channel = open(&client).await;
        // The plan and archive share one packet; the tail stays below the
        // progress interval, so only the final total covers it.
        let mut packet = plan_line();
        packet.push(b'x');
        channel.data(packet.as_slice()).await.unwrap();
        channel.eof().await.unwrap();
        let mut bytes = Vec::new();
        control.stdin.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"x");
        control
            .process
            .status
            .send_replace(Some(BoundaryExitStatus::Exited(0)));
        drop((control.stdout, control.stderr));
        let mut reader = Reader::default();
        assert_eq!(reader.close(&mut channel).await, [0, 1]);
        assert_eq!(reader.statuses, [0]);
    })
    .await
    .expect("small upload did not report its final total");
}

#[tokio::test]
async fn invalid_plans_and_credit_violations_exit_74() {
    for case in ["credit", "eof", "plan"] {
        tokio::time::timeout(DEADLINE, async {
            let (session, control) = exec_session();
            let client = client_for(vec![session]).await;
            let (mut channel, mut reader) = if case == "credit" {
                start(&client).await
            } else {
                (open(&client).await, Reader::default())
            };
            match case {
                "credit" => {
                    for _ in 0..=WINDOW / CHUNK {
                        channel.data(vec![7; CHUNK].as_slice()).await.unwrap();
                    }
                }
                "eof" => {
                    channel.data(&b"{"[..]).await.unwrap();
                    channel.eof().await.unwrap();
                }
                _ => {
                    let plan = br#"{"destination_directory":"/tmp","expected_destination":null,"command":"id"}
"#;
                    channel.data(&plan[..]).await.unwrap();
                }
            }
            reader.close(&mut channel).await;
            assert_eq!(reader.statuses, [74]);
            if case == "credit" {
                control.process.terminated().await;
            } else {
                let stderr = String::from_utf8_lossy(&reader.stderr);
                assert!(stderr.contains("openshell: "), "{stderr}");
                assert!(!*control.process.terminated.borrow());
            }
        })
        .await
        .expect("rejected upload did not close");
    }
}

#[tokio::test]
async fn extractor_failures_report_status_and_output() {
    for early_exit in [true, false] {
        tokio::time::timeout(DEADLINE, async {
            let (session, mut control) = exec_session();
            let client = client_for(vec![session]).await;
            let (mut channel, mut reader) = start(&client).await;
            let diagnostic = "mkdir: /tmp/existing-file/child: Not a directory";
            if early_exit {
                control
                    .stderr
                    .write_all(diagnostic.as_bytes())
                    .await
                    .unwrap();
                control
                    .process
                    .status
                    .send_replace(Some(BoundaryExitStatus::Exited(2)));
            } else {
                // Broken stdin wakes no credit; the extractor is stopped.
                drop(control.stdin);
                channel.data(vec![7; CHUNK].as_slice()).await.unwrap();
                control.process.terminated().await;
            }
            drop((control.stdout, control.stderr));
            reader.close(&mut channel).await;
            if early_exit {
                assert_eq!(reader.statuses, [2]);
                assert_eq!(reader.stderr, diagnostic.as_bytes());
            } else {
                assert_eq!(reader.statuses, [74]);
            }
        })
        .await
        .expect("extractor failure did not close the upload");
    }
}

#[tokio::test]
async fn close_and_disconnect_cancel_stalled_boundary_input() {
    for disconnect in [false, true] {
        tokio::time::timeout(DEADLINE, async {
            let (session, mut control) = exec_session();
            let client = client_for(vec![session]).await;
            let (channel, _) = start(&client).await;
            channel.data(vec![7; CHUNK].as_slice()).await.unwrap();
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
            control.process.terminated().await;
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
            Arc::new(RejectingExec),
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
        let mut upload = open(&client).await;
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
            let channel = open(&client).await;
            channel.data(plan_line().as_slice()).await.unwrap();
            started
                .subscribe()
                .wait_for(|started| *started)
                .await
                .unwrap();
            // Startup holds the session loop, as for exec requests, so the
            // close or disconnect is handled after the process is registered.
            if disconnect {
                client
                    .disconnect(russh::Disconnect::ByApplication, "test", "")
                    .await
                    .unwrap();
            } else {
                channel.close().await.unwrap();
            }
            release.send(()).unwrap();
            control.process.terminated().await;
        })
        .await
        .expect("cancelled startup stranded a late extractor");
    }
}

#[tokio::test]
async fn late_rejection_wins_until_the_result_is_reported() {
    for (after_exit, pending_output_status) in [(false, false), (true, false), (true, true)] {
        tokio::time::timeout(DEADLINE, async {
            let (mut session, mut control) = exec_session();
            let (output_status, receiver) = oneshot::channel();
            if pending_output_status {
                session.output_status = Some(receiver);
            }
            let client = client_for(vec![session]).await;
            let (mut channel, mut reader) = start(&client).await;
            if after_exit {
                channel.data(&b"x"[..]).await.unwrap();
                channel.eof().await.unwrap();
                let mut bytes = Vec::new();
                control.stdin.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, b"x");
                if pending_output_status {
                    // Output EOF leaves the exit task waiting for the backend's
                    // final status; dropped readers prove both drains finished.
                    control.stdout.shutdown().await.unwrap();
                    control.stderr.shutdown().await.unwrap();
                    assert_eq!(control.stdout.read(&mut [0]).await.unwrap(), 0);
                    assert_eq!(control.stderr.read(&mut [0]).await.unwrap(), 0);
                } else {
                    control
                        .process
                        .status
                        .send_replace(Some(BoundaryExitStatus::Exited(0)));
                    control
                        .process
                        .waited
                        .subscribe()
                        .wait_for(|waited| *waited)
                        .await
                        .unwrap();
                }
            }
            // The exit task is still waiting for output EOF or its final
            // status, so the rejection must report without waiting for it.
            channel
                .extended_data(1, b"unexpected".as_slice())
                .await
                .unwrap();
            assert!(reader.close(&mut channel).await.is_empty());
            assert_eq!(reader.statuses, [74]);
            control.process.terminated().await;
            drop((control.stdout, control.stderr, output_status));
        })
        .await
        .expect("invalid upload input did not terminate");
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
            channel.data(plan_line().as_slice()).await.unwrap();
            let mut reader = Reader::default();
            assert!(reader.close(&mut channel).await.is_empty());
            assert_eq!(reader.statuses, [74]);
            let stderr = String::from_utf8_lossy(&reader.stderr);
            assert!(stderr.contains("login selection observed"), "{stderr}");
            assert_eq!(*login.borrow(), Some(!no_login));
        })
        .await
        .expect("login shell selection not applied to upload");
    }
}
