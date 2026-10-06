// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Exercise a half-open gateway path through the production supervisor frame bridge.

use super::tests::{AcceptAnyServerKey, RejectingExec, TestLoopbackConnector};
use super::*;
use openshell_core::proto::{RelayFrame, relay_frame};
use openshell_isolation_interface::contract::{
    BackendError, BoundaryExitStatus, BoundaryProcess, BoundarySignal, ProcessAttachment,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};

const TEST_INTERVAL: Duration = Duration::from_millis(50);
const WAIT: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, PartialEq)]
enum RelayMode {
    Forward,
    Discard,
    Stalled,
}

#[derive(Default)]
struct RetainedProcess(AtomicUsize);

#[async_trait::async_trait]
impl BoundaryProcess for RetainedProcess {
    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
        std::future::pending().await
    }

    async fn signal(&self, _: BoundarySignal) -> Result<(), BackendError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn terminate(&self) -> Result<(), BackendError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct CanonicalProcess {
    session: Arc<MainSession>,
    process: Arc<RetainedProcess>,
    input: tokio::io::DuplexStream,
    output: Option<tokio::io::DuplexStream>,
}

impl CanonicalProcess {
    fn new() -> Self {
        let (stdin, input) = tokio::io::duplex(64 * 1024);
        let (stdout, output) = tokio::io::duplex(64 * 1024);
        let process = Arc::new(RetainedProcess::default());
        let session = MainSession::from_boundary(
            ProcessAttachment {
                stdin: Box::new(stdin),
                stdout: Box::new(stdout),
                stderr: None,
                terminal: None,
            },
            process.clone(),
        );
        Self {
            session,
            process,
            input,
            output: Some(output),
        }
    }

    async fn assert_input(&mut self, channel: &russh::Channel<russh::client::Msg>) {
        channel.data(&b"typing restored\n"[..]).await.unwrap();
        self.expect_input().await;
    }

    async fn expect_input(&mut self) {
        let mut received = [0; 16];
        tokio::time::timeout(WAIT, self.input.read_exact(&mut received))
            .await
            .expect("attachment must deliver input to the retained process")
            .unwrap();
        assert_eq!(&received, b"typing restored\n");
        assert!(!self.session.finished());
        assert_eq!(self.process.0.load(Ordering::SeqCst), 0);
    }
}

struct Connection {
    client: russh::client::Handle<AcceptAnyServerKey>,
    mode: watch::Sender<RelayMode>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Connection {
    async fn new(main: Arc<MainSession>) -> Self {
        Self::with_window(main, None).await
    }

    async fn with_window(main: Arc<MainSession>, window: Option<u32>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("ssh.sock");
        let (listener, mut config, _) = ssh_server_init(&socket, &None, false).unwrap();
        // Preserve whether production enables probes. Only shorten the interval.
        let config_mut = Arc::get_mut(&mut config).unwrap();
        config_mut.keepalive_interval = config_mut.keepalive_interval.map(|_| TEST_INTERVAL);
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_connection(
                stream,
                config,
                Arc::new(TestLoopbackConnector),
                Arc::new(RejectingExec),
                Some(main),
                TEST_INTERVAL * 4,
            )
            .await;
        });
        let target = tokio::net::UnixStream::connect(&socket).await.unwrap();
        let (to_supervisor, inbound) = mpsc::channel(16);
        let (outbound, mut from_supervisor) = mpsc::channel::<RelayFrame>(16);
        let relay = tokio::spawn(crate::supervisor_session::test_bridge_ssh_relay(
            target, inbound, outbound,
        ));
        let (client_stream, gateway_stream) = tokio::io::duplex(64 * 1024);
        let (mut gateway_read, mut gateway_write) = tokio::io::split(gateway_stream);
        let (mode, mut input_mode) = watch::channel(RelayMode::Forward);
        let mut output_mode = input_mode.clone();
        let inbound_pump = tokio::spawn(async move {
            let mut bytes = [0; 16 * 1024];
            loop {
                if *input_mode.borrow() == RelayMode::Stalled {
                    if input_mode.changed().await.is_err() {
                        break;
                    }
                    continue;
                }
                tokio::select! {
                    changed = input_mode.changed() => {
                        if changed.is_err() { break; }
                    }
                    read = gateway_read.read(&mut bytes) => {
                        let Ok(size) = read else { break; };
                        if size == 0 { break; }
                        if *input_mode.borrow() == RelayMode::Forward {
                            let frame = RelayFrame {
                                payload: Some(relay_frame::Payload::Data(bytes[..size].to_vec())),
                            };
                            if to_supervisor.send(Ok(frame)).await.is_err() { break; }
                        }
                    }
                }
            }
        });
        let outbound_pump = tokio::spawn(async move {
            loop {
                if *output_mode.borrow() == RelayMode::Stalled {
                    if output_mode.changed().await.is_err() {
                        break;
                    }
                    continue;
                }
                tokio::select! {
                    changed = output_mode.changed() => {
                        if changed.is_err() { break; }
                    }
                    frame = from_supervisor.recv() => {
                        let Some(frame) = frame else { break; };
                        if let Some(relay_frame::Payload::Data(data)) = frame.payload
                            && *output_mode.borrow() == RelayMode::Forward
                            && gateway_write.write_all(&data).await.is_err()
                        {
                            break;
                        }
                    }
                }
            }
        });
        let mut client_config = russh::client::Config::default();
        if let Some(window) = window {
            client_config.window_size = window;
        }
        let mut client = russh::client::connect_stream(
            Arc::new(client_config),
            client_stream,
            AcceptAnyServerKey,
        )
        .await
        .unwrap();
        assert!(matches!(
            client.authenticate_none("sandbox").await.unwrap(),
            russh::client::AuthResult::Success
        ));
        Self {
            client,
            mode,
            tasks: vec![server_task, relay, inbound_pump, outbound_pump],
        }
    }

    async fn attach(&self) -> russh::Channel<russh::client::Msg> {
        let mut channel = self.client.channel_open_session().await.unwrap();
        channel
            .request_subsystem(true, "openshell-main")
            .await
            .unwrap();
        assert!(matches!(
            next_event(&mut channel).await,
            russh::ChannelMsg::Success
        ));
        channel
    }
}

async fn next_event(channel: &mut russh::Channel<russh::client::Msg>) -> russh::ChannelMsg {
    tokio::time::timeout(WAIT, channel.wait())
        .await
        .unwrap()
        .unwrap()
}

async fn assert_read_only(channel: &mut russh::Channel<russh::client::Msg>) {
    loop {
        match next_event(channel).await {
            russh::ChannelMsg::ExtendedData { data, ext: 1 } => {
                assert!(String::from_utf8_lossy(&data).contains("attached read-only"));
                break;
            }
            russh::ChannelMsg::Data { .. } => {}
            other => panic!("expected read-only diagnostic, got {other:?}"),
        }
    }
}

async fn wait_for_release(main: &MainSession) {
    tokio::time::timeout(WAIT, async {
        loop {
            if let Ok((owner, _)) = main.acquire_input() {
                main.release_input(owner);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("dead relay must release stdin within the liveness bound");
}

async fn reconnect_after_cut(mode: RelayMode, producing: bool) {
    let mut main = CanonicalProcess::new();
    let original = Connection::new(main.session.clone()).await;
    let original_channel = original.attach().await;
    main.assert_input(&original_channel).await;
    let mut early = Connection::new(main.session.clone()).await;
    let mut early_channel = early.attach().await;
    assert_read_only(&mut early_channel).await;
    let (mut early_read, early_write) = early_channel.split();
    let (notice_tx, mut notice_rx) = mpsc::channel(1);
    early.tasks.push(tokio::spawn(async move {
        // The replacement remains a healthy output consumer while the old
        // path is cut. Its own SSH receive window must not become the fault.
        while let Some(event) = early_read.wait().await {
            if let russh::ChannelMsg::ExtendedData { data, ext: 1 } = event {
                let _ = notice_tx.send(data).await;
            }
        }
    }));
    original.mode.send_replace(mode);

    let output_task = producing.then(|| {
        let mut output = main.output.take().unwrap();
        tokio::spawn(async move {
            // Faster than the stalled relay can drain, but below the retained
            // output budget until the SSH event queue has applied backpressure.
            let chunk = [b'x'; 16 * 1024];
            loop {
                if output.write_all(&chunk).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
    });
    wait_for_release(&main.session).await;
    if let Some(task) = output_task {
        task.abort();
    }
    // The already reconnected writer can acquire the freed lease on new input.
    // Keystrokes ignored while the previous owner was alive are never replayed.
    early_write.data(&b"typing restored\n"[..]).await.unwrap();
    main.expect_input().await;
    let notice = tokio::time::timeout(WAIT, notice_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&notice[..], b"openshell: input enabled\r\n");
    early_write.close().await.unwrap();
    wait_for_release(&main.session).await;
    // A fresh connection after cleanup can also attach to that same process.
    let mut recovered = Connection::new(main.session.clone()).await;
    let recovered_channel = recovered.attach().await;
    let (mut recovered_read, recovered_write) = recovered_channel.split();
    recovered.tasks.push(tokio::spawn(async move {
        while recovered_read.wait().await.is_some() {}
    }));
    recovered_write
        .data(&b"typing restored\n"[..])
        .await
        .unwrap();
    main.expect_input().await;
    assert!(main.session.acquire_input().is_err());
}

#[tokio::test]
async fn silent_half_open_relay_releases_canonical_input() {
    reconnect_after_cut(RelayMode::Discard, false).await;
}

#[tokio::test]
async fn output_does_not_keep_a_half_open_relay_alive() {
    reconnect_after_cut(RelayMode::Discard, true).await;
}

#[tokio::test]
async fn stalled_relay_writes_release_canonical_input() {
    reconnect_after_cut(RelayMode::Stalled, true).await;
}

#[tokio::test]
async fn healthy_idle_owner_survives_probes_and_cannot_be_displaced() {
    let mut main = CanonicalProcess::new();
    let owner = Connection::new(main.session.clone()).await;
    let channel = owner.attach().await;
    main.assert_input(&channel).await;
    tokio::time::sleep(TEST_INTERVAL * 12).await;
    let viewer = Connection::new(main.session.clone()).await;
    let mut viewer_channel = viewer.attach().await;
    assert_read_only(&mut viewer_channel).await;
    viewer_channel.data(&b"ignored\n"[..]).await.unwrap();
    viewer_channel.eof().await.unwrap();
    viewer_channel.close().await.unwrap();
    main.assert_input(&channel).await;
    assert!(main.session.acquire_input().is_err());
}

#[tokio::test]
async fn explicit_viewer_does_not_acquire_released_input() {
    let mut main = CanonicalProcess::new();
    let owner = Connection::new(main.session.clone()).await;
    let owner_channel = owner.attach().await;
    let viewer = Connection::new(main.session.clone()).await;
    let mut channel = viewer.client.channel_open_session().await.unwrap();
    channel
        .set_env(true, "OPENSHELL_MAIN_READ_ONLY", "1")
        .await
        .unwrap();
    assert!(matches!(
        next_event(&mut channel).await,
        russh::ChannelMsg::Success
    ));
    channel
        .request_subsystem(true, "openshell-main")
        .await
        .unwrap();
    assert!(matches!(
        next_event(&mut channel).await,
        russh::ChannelMsg::Success
    ));
    owner_channel.close().await.unwrap();
    wait_for_release(&main.session).await;
    channel.data(&b"ignored\n"[..]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    let fresh = Connection::new(main.session.clone()).await;
    let fresh_channel = fresh.attach().await;
    main.assert_input(&fresh_channel).await;
}

#[tokio::test]
async fn waiting_writer_eof_cancels_acquisition() {
    let mut main = CanonicalProcess::new();
    let owner = Connection::new(main.session.clone()).await;
    let owner_channel = owner.attach().await;
    let waiting = Connection::new(main.session.clone()).await;
    let mut channel = waiting.attach().await;
    assert_read_only(&mut channel).await;
    channel.eof().await.unwrap();
    owner_channel.close().await.unwrap();
    wait_for_release(&main.session).await;
    channel.data(&b"ignored\n"[..]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    let fresh = Connection::new(main.session.clone()).await;
    let fresh_channel = fresh.attach().await;
    main.assert_input(&fresh_channel).await;
}

#[tokio::test]
async fn production_config_probes_before_the_receive_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let (_, config, _) = ssh_server_init(&dir.path().join("ssh.sock"), &None, false).unwrap();
    assert_eq!(config.keepalive_interval, Some(Duration::from_secs(15)));
    assert_eq!(config.keepalive_max, 3);
    assert_eq!(SSH_PEER_TIMEOUT, Duration::from_mins(1));
}

#[tokio::test]
async fn waiting_writer_detach_keys_do_not_acquire_released_input() {
    for key in [b"\x03".as_slice(), b"\x04", b"\x10\x11"] {
        let main = CanonicalProcess::new();
        let owner = Connection::new(main.session.clone()).await;
        let owner_channel = owner.attach().await;
        let waiting = Connection::new(main.session.clone()).await;
        let mut channel = waiting.attach().await;
        assert_read_only(&mut channel).await;
        owner_channel.close().await.unwrap();
        wait_for_release(&main.session).await;
        channel.data(key).await.unwrap();
        loop {
            if matches!(next_event(&mut channel).await, russh::ChannelMsg::Close) {
                break;
            }
        }
        wait_for_release(&main.session).await;
        assert_eq!(main.process.0.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn competing_waiting_writers_preserve_exclusive_ownership() {
    let mut main = CanonicalProcess::new();
    let owner = Connection::new(main.session.clone()).await;
    let owner_channel = owner.attach().await;
    let first = Connection::new(main.session.clone()).await;
    let mut first_channel = first.attach().await;
    assert_read_only(&mut first_channel).await;
    let second = Connection::new(main.session.clone()).await;
    let mut second_channel = second.attach().await;
    assert_read_only(&mut second_channel).await;
    owner_channel.close().await.unwrap();
    wait_for_release(&main.session).await;
    let (a, b) = tokio::join!(
        first_channel.data(&b"a"[..]),
        second_channel.data(&b"b"[..])
    );
    a.unwrap();
    b.unwrap();
    let mut winner = [0];
    tokio::time::timeout(WAIT, main.input.read_exact(&mut winner))
        .await
        .unwrap()
        .unwrap();
    let mut extra = [0];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), main.input.read(&mut extra))
            .await
            .is_err()
    );
    let winning_channel = match winner[0] {
        b'a' => {
            second_channel.close().await.unwrap();
            first_channel
        }
        b'b' => {
            first_channel.close().await.unwrap();
            second_channel
        }
        other => panic!("unexpected input: {other}"),
    };
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(main.session.acquire_input().is_err());
    main.assert_input(&winning_channel).await;
}

#[tokio::test]
async fn detached_waiting_writer_cannot_reacquire_with_pending_output() {
    let mut main = CanonicalProcess::new();
    let owner = Connection::new(main.session.clone()).await;
    let owner_channel = owner.attach().await;
    // The read-only diagnostic exhausts this channel's output window, so
    // russh retains the channel while the detach close waits behind output.
    let waiting = Connection::with_window(main.session.clone(), Some(0)).await;
    let channel = waiting.attach().await;
    owner_channel.close().await.unwrap();
    wait_for_release(&main.session).await;
    channel.data(&b"\x04"[..]).await.unwrap();
    channel.data(&b"after detach"[..]).await.unwrap();
    let mut received = [0];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), main.input.read(&mut received))
            .await
            .is_err(),
        "detached channel forwarded input: {received:?}"
    );
    let (lease, _) = main
        .session
        .acquire_input()
        .expect("detach must cancel pending ownership");
    main.session.release_input(lease);
    channel.close().await.unwrap();
    wait_for_release(&main.session).await;
}

#[tokio::test]
async fn retry_does_not_forward_prefix_typed_before_owner_release() {
    let mut main = CanonicalProcess::new();
    let owner = Connection::new(main.session.clone()).await;
    let owner_channel = owner.attach().await;
    let waiting = Connection::new(main.session.clone()).await;
    let mut channel = waiting.attach().await;
    assert_read_only(&mut channel).await;
    channel.data(&b"\x10"[..]).await.unwrap();
    // A request response on the same SSH channel proves the prefix was
    // processed before the original owner releases its lease.
    channel.set_env(true, "REVIEW_BARRIER", "1").await.unwrap();
    assert!(matches!(
        next_event(&mut channel).await,
        russh::ChannelMsg::Success
    ));
    owner_channel.close().await.unwrap();
    wait_for_release(&main.session).await;
    channel.data(&b"z"[..]).await.unwrap();
    let mut received = [0];
    tokio::time::timeout(WAIT, main.input.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        received,
        [b'z'],
        "retry replayed a prefix typed while stdin was denied"
    );
}

#[tokio::test]
async fn waiting_writer_split_detach_survives_owner_release() {
    let main = CanonicalProcess::new();
    let owner = Connection::new(main.session.clone()).await;
    let owner_channel = owner.attach().await;
    let waiting = Connection::new(main.session.clone()).await;
    let mut channel = waiting.attach().await;
    assert_read_only(&mut channel).await;
    channel.data(&b"\x10"[..]).await.unwrap();
    channel.set_env(true, "TEST_BARRIER", "1").await.unwrap();
    assert!(matches!(
        next_event(&mut channel).await,
        russh::ChannelMsg::Success
    ));
    owner_channel.close().await.unwrap();
    wait_for_release(&main.session).await;
    channel.data(&b"\x11"[..]).await.unwrap();
    loop {
        if matches!(next_event(&mut channel).await, russh::ChannelMsg::Close) {
            break;
        }
    }
    wait_for_release(&main.session).await;
    assert_eq!(main.process.0.load(Ordering::SeqCst), 0);
}
