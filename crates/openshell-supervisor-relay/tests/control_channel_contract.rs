// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Black-box integration coverage for `openshell-supervisor-relay`'s
//! control-channel wire contract (see `src/imp.rs`'s module docs for the
//! protocol itself).
//!
//! Each test spawns the real compiled `openshell-supervisor-relay.exe`
//! (via `CARGO_BIN_EXE_...`) as an ordinary child process -- no `wxc-exec`,
//! no `AppContainer`, no MXC involved -- and drives it over its actual
//! stdin/stdout JSON protocol, exactly as `openshell-driver-mxc`'s
//! `driver.rs` and `control_channel.rs` do in production. This exercises
//! the real launch handshake, target-ready ordering, shutdown semantics,
//! and the relay-auth/forward bridging protocol end to end, without
//! requiring a live Windows `AppContainer` host.
//!
//! What this file deliberately does NOT cover: the `ProcessContainer`
//! stop/delete lifecycle as driven by `openshell-driver-mxc`'s
//! `driver.rs` (that needs a real `wxc-exec`/`AppContainer`, or a much
//! larger mock of the whole MXC invoker -- exercised today by
//! `run-openclaw-forward-test.ps1` / `run-ws-agent-test.ps1` against real
//! hardware instead) and the relay-listener half of the auth handshake
//! (`openshell-driver-mxc/src/relay.rs`'s `relay_task`, which has its own
//! unit-testable pieces but isn't exercised here). This file only tests
//! `openshell-supervisor-relay`'s side of the contract, standing in for
//! the relay listener with a small hand-rolled WS server per test.
//!
//! Windows-only, like the binary under test: gated on the whole file via
//! `#![cfg(windows)]` so nothing here (including the dev-dependencies
//! pulled in for it) affects non-Windows builds at all.

#![cfg(windows)]

use base64::Engine;
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

const TIMEOUT: Duration = Duration::from_secs(10);

/// A running `openshell-supervisor-relay.exe`, with its stdin/stdout wired
/// up as a JSON control channel the same way the driver uses them.
struct RelayProcess {
    child: Child,
    stdin: ChildStdin,
    lines: Lines<BufReader<ChildStdout>>,
    // `None` for `spawn()` (stderr is discarded there -- see its doc
    // comment). `spawn_capturing_stderr()` populates this so a test can
    // deterministically wait for a specific diagnostic line instead of
    // guessing a sleep duration.
    stderr_lines: Option<tokio::sync::mpsc::UnboundedReceiver<String>>,
}

impl RelayProcess {
    /// Spawn the real binary. `target_port` is the CLI arg the binary
    /// expects (its own liveness-check port for whatever `launch` later
    /// starts) -- irrelevant to tests that never send `launch`.
    async fn spawn(target_port: u16) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_openshell-supervisor-relay"))
            .arg(target_port.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Not read by these tests -- null rather than piped-and-ignored
            // so the child can never block on a full stderr pipe buffer.
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn openshell-supervisor-relay.exe (build it first: cargo build -p openshell-supervisor-relay)");
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        Self {
            child,
            stdin,
            lines: BufReader::new(stdout).lines(),
            stderr_lines: None,
        }
    }

    /// Like `spawn`, but pipes stderr instead of discarding it, so a test
    /// can wait for a specific diagnostic line via `wait_for_stderr_line`.
    /// A background task drains it continuously for the process's entire
    /// lifetime (forwarding every line over an unbounded channel) -- reading
    /// only until the sought-after line arrives and then stopping (as an
    /// earlier version of this helper did) leaves the pipe unread from then
    /// on; this process's own ongoing diagnostic output (plus anything the
    /// launched target itself prints, forwarded through it) then fills the
    /// OS pipe buffer and makes its *next* `eprintln!` block synchronously
    /// forever -- including ones on the exact shutdown path a test wants to
    /// observe. Confirmed by hand: without continuous draining, this
    /// deadlocks the relay process itself, not just this test.
    async fn spawn_capturing_stderr(target_port: u16) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_openshell-supervisor-relay"))
            .arg(target_port.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn openshell-supervisor-relay.exe (build it first: cargo build -p openshell-supervisor-relay)");
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            lines: BufReader::new(stdout).lines(),
            stderr_lines: Some(rx),
        }
    }

    /// Consume forwarded stderr lines (discarding non-matching ones) until
    /// one contains `pattern`, or `timeout` elapses. `timeout` is
    /// deliberately a caller argument, not the shared `TIMEOUT` constant --
    /// spawning a real OS process for this to wait on can occasionally take
    /// far longer than this file's other, purely protocol-level waits
    /// (observed on this host: real-time AV scanning stalling
    /// `CreateProcess` well past 10s, unrelated to anything this binary
    /// controls).
    async fn wait_for_stderr_line(&mut self, pattern: &str, timeout: Duration) {
        let rx = self
            .stderr_lines
            .as_mut()
            .expect("wait_for_stderr_line requires spawn_capturing_stderr");
        tokio::time::timeout(timeout, async {
            loop {
                match rx.recv().await {
                    Some(line) if line.contains(pattern) => return,
                    Some(_) => {}
                    None => {
                        panic!("relay stderr closed before printing a line containing {pattern:?}")
                    }
                }
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!("timed out after {timeout:?} waiting for a stderr line containing {pattern:?}")
        });
    }

    async fn next_line(&mut self) -> String {
        tokio::time::timeout(TIMEOUT, self.lines.next_line())
            .await
            .expect("timed out waiting for a control-channel line")
            .expect("stdout read error")
            .expect("relay exited before producing the expected line")
    }

    async fn next_json(&mut self) -> Value {
        let line = self.next_line().await;
        serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("non-JSON control-channel line {line:?}: {e}"))
    }

    async fn send(&mut self, value: Value) {
        let mut line = serde_json::to_string(&value).expect("serialize request");
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .await
            .expect("write control-channel request");
        self.stdin
            .flush()
            .await
            .expect("flush control-channel request");
    }

    /// Consume and validate the startup handshake event -- see
    /// `control_channel::try_route_ready` on the driver side, which this
    /// mirrors.
    async fn expect_ready(&mut self) {
        let v = self.next_json().await;
        assert_eq!(v["event"], "ready");
        assert_eq!(v["protocol_version"], 4);
    }

    async fn launch(&mut self, id: u64, command: &[&str]) -> Value {
        self.send(json!({
            "id": id,
            "op": "launch",
            "data": {"command": command, "env": []},
        }))
        .await;
        self.next_json().await
    }

    async fn confirm_target_ready(&mut self, id: u64) -> Value {
        self.send(json!({"id": id, "op": "target_ready"})).await;
        self.next_json().await
    }
}

/// Spawn an in-process TCP echo server (a stand-in for whatever real
/// `agent_command` target would be bound to a port in production) and
/// return the port it bound. Handles concurrent connections -- each
/// accepted connection gets its own task -- so it doubles as the shared
/// target for the concurrent-forwards test.
async fn spawn_echo_target() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

/// Stand-in for `openshell-driver-mxc/src/relay.rs`'s Phase A listener:
/// accept one TCP connection, complete the WS upgrade, and require the
/// first message to be exactly `AUTH:<nonce>` -- matching what
/// `run_relay_bridge` in `imp.rs` sends. Panics (failing the test) if
/// anything else arrives first, same as a real relay would just silently
/// distrust and drop the connection.
async fn accept_and_authenticate(
    listener: &TcpListener,
    expected_nonce: &str,
) -> WebSocketStream<TcpStream> {
    let (stream, _addr) = tokio::time::timeout(TIMEOUT, listener.accept())
        .await
        .expect("timed out waiting for the relay's Phase A connection")
        .expect("accept failed");
    let mut ws = tokio_tungstenite::accept_async(stream)
        .await
        .expect("WS upgrade failed");
    let msg = tokio::time::timeout(TIMEOUT, ws.next())
        .await
        .expect("timed out waiting for the AUTH message")
        .expect("relay closed before sending AUTH")
        .expect("WS read error");
    let expected = format!("AUTH:{expected_nonce}");
    match msg {
        Message::Text(t) if t == expected => {}
        other => panic!("expected {expected:?} as the first message, got {other:?}"),
    }
    ws
}

// ── Startup handshake ────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn ready_event_reports_protocol_version() {
    let mut relay = RelayProcess::spawn(0).await;
    relay.expect_ready().await;
}

// ── ping / echo (protocol sanity, no launch required) ──────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn ping_and_echo_round_trip() {
    let mut relay = RelayProcess::spawn(0).await;
    relay.expect_ready().await;

    relay.send(json!({"id": 1, "op": "ping"})).await;
    assert_eq!(
        relay.next_json().await,
        json!({"id": 1, "ok": true, "data": "pong"})
    );

    relay
        .send(json!({"id": 2, "op": "echo", "data": {"x": 1, "y": "two"}}))
        .await;
    let resp = relay.next_json().await;
    assert_eq!(resp["id"], 2);
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["data"], json!({"x": 1, "y": "two"}));
}

// ── launch: success and failure ─────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn launch_fails_fast_when_command_is_empty() {
    let mut relay = RelayProcess::spawn(0).await;
    relay.expect_ready().await;

    let resp = relay.launch(1, &[]).await;
    assert_eq!(resp["id"], 1);
    assert_eq!(resp["ok"], false);
    assert!(
        resp["error"].as_str().unwrap().contains("non-empty array"),
        "unexpected error message: {resp}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn launch_success_then_target_ready_ordering() {
    // Reserve a free port, then launch a target that binds exactly it --
    // small a-priori race (something else could steal the port between the
    // bind-and-drop below and the launch), acceptable for a test.
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    let script = format!(
        "Start-Sleep -Milliseconds 800; \
         $l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback,{port}); \
         $l.Start(); Start-Sleep -Seconds 30"
    );

    let mut relay = RelayProcess::spawn(port).await;
    relay.expect_ready().await;

    let ack = relay
        .launch(
            1,
            &[
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &script,
            ],
        )
        .await;
    assert_eq!(ack["id"], 1);
    assert_eq!(ack["ok"], true, "launch ack: {ack}");

    // Production performs this observation in the host driver, where the TCP
    // table is accessible. Stand in for that driver by waiting until the
    // delayed target listener is visible, then explicitly confirm it.
    tokio::time::timeout(TIMEOUT, async {
        loop {
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("delayed target did not bind");
    let confirmation = relay.confirm_target_ready(2).await;
    assert_eq!(confirmation, json!({"id": 2, "ok": true}));

    // The correlated confirmation response precedes the relay's unsolicited
    // event, which remains the driver's final race-safe startup signal.
    let target_ready = relay.next_json().await;
    assert_eq!(target_ready["event"], "target_ready");
    assert!(
        target_ready.get("id").is_none(),
        "target_ready must not carry a correlation id"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn early_child_crash_is_reported_promptly_with_its_stderr() {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };
    let mut relay = RelayProcess::spawn(port).await;
    relay.expect_ready().await;

    let ack = relay
        .launch(
            1,
            &[
                "cmd",
                "/d",
                "/c",
                "echo early-child-crash-sentinel 1>&2 & exit /b 23",
            ],
        )
        .await;
    assert_eq!(ack["ok"], true, "launch ack: {ack}");

    let failed = relay.next_json().await;
    assert_eq!(failed["event"], "target_failed", "failure event: {failed}");
    let error = failed["error"]
        .as_str()
        .expect("target_failed error string");
    assert!(error.contains("23"), "exit status missing from: {error}");
    assert!(
        error.contains("early-child-crash-sentinel"),
        "target stderr missing from: {error}"
    );

    tokio::time::timeout(TIMEOUT, relay.child.wait())
        .await
        .expect("relay must exit promptly after reporting an early target crash")
        .expect("wait() failed");
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_is_acked_and_the_process_exits() {
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    let script = format!(
        "$l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback,{port}); \
         $l.Start(); Start-Sleep -Seconds 30"
    );

    let mut relay = RelayProcess::spawn(port).await;
    relay.expect_ready().await;
    let ack = relay
        .launch(
            1,
            &[
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &script,
            ],
        )
        .await;
    assert_eq!(ack["ok"], true);
    let confirmation = relay.confirm_target_ready(2).await;
    assert_eq!(confirmation, json!({"id": 2, "ok": true}));
    let target_ready = relay.next_json().await;
    assert_eq!(target_ready["event"], "target_ready");

    relay.send(json!({"id": 3, "op": "shutdown"})).await;
    let ack = relay.next_json().await;
    assert_eq!(ack, json!({"id": 3, "ok": true}));

    let status = tokio::time::timeout(TIMEOUT, relay.child.wait())
        .await
        .expect("relay did not exit within the timeout after shutdown")
        .expect("wait() failed");
    assert!(status.success(), "expected a clean exit, got {status:?}");
}

/// Reproduces the reported race: a "shutdown" request arriving while the
/// target is still coming up (here, one the host never confirms as ready)
/// must stop this process promptly instead of leaving it waiting for host
/// confirmation after `run_control_channel` already acknowledged shutdown.
/// Without racing that wait against shutdown, the final
/// `child.wait()` below would time out instead of completing within
/// `SHUTDOWN_TIMEOUT`.
///
/// Waits for the relay's own "waiting for target on ..." stderr line
/// before sending shutdown, rather than sending it right after the launch
/// ack -- the ack fires as soon as the request is parsed, before this
/// process's own `spawn_target()` (a plain `CreateProcess` call) has
/// necessarily completed, and *that* call is a separate, pre-existing
/// source of multi-second-to-multi-minute stalls on this host (real-time
/// AV scanning a freshly-launched process) that this fix does not -- and is
/// not meant to -- address. Anchoring on that line instead isolates the
/// assertion to the one thing this fix actually changed: how promptly a
/// shutdown arriving *during the port-readiness poll itself* is observed
/// and acted on.
///
/// Does not close `stdin` before waiting on process exit -- on purpose,
/// matching driver.rs, which never closes its end of the control channel
/// before observing the relay exit either. An earlier version of this
/// fix returned normally from `run()` on this path instead of calling
/// `std::process::exit`; `run_control_channel` loops on
/// `stdin.next_line()` for the process's entire lifetime, so with `stdin`
/// still open (as it always is against a real driver) that task -- and so
/// the whole process -- stayed alive indefinitely even after `run()` had
/// already returned. Confirmed by hand with internal timestamps: the fix
/// fired and `run()` returned within single-digit milliseconds while the
/// process, observed externally, never exited. This test would have
/// caught that.
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_while_waiting_for_host_readiness_stops_promptly() {
    // Generous: covers this host's observed CreateProcess stalls (up to
    // ~60s) plus real margin, not just the fast path.
    const SPAWN_TIMEOUT: Duration = Duration::from_mins(2);
    // Generous only relative to `TIMEOUT`, since a bare
    // `std::process::exit` completes in well under a second.
    const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);

    let port = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };

    let mut relay = RelayProcess::spawn_capturing_stderr(port).await;
    relay.expect_ready().await;
    // A real target the host never confirms as ready. Do not use `timeout.exe`
    // here: it exits immediately
    // when its stdin is not attached to a console, which is precisely how the
    // relay launches targets.
    let ack = relay
        .launch(1, &["cmd", "/d", "/c", "ping -n 301 127.0.0.1 >nul"])
        .await;
    assert_eq!(ack["ok"], true, "launch ack: {ack}");

    // Confirms spawn_target() has returned and the host-confirmation wait has
    // started -- only from this point on is the fix under test in play.
    relay
        .wait_for_stderr_line("waiting for host-confirmed target readiness", SPAWN_TIMEOUT)
        .await;

    relay.send(json!({"id": 2, "op": "shutdown"})).await;
    let ack = relay.next_json().await;
    assert_eq!(ack, json!({"id": 2, "ok": true}));

    let status = tokio::time::timeout(SHUTDOWN_TIMEOUT, relay.child.wait())
        .await
        .expect(
            "relay did not exit promptly after shutdown during port-wait \
             (see imp.rs's host-readiness/shutdown race)",
        )
        .expect("wait() failed");
    assert!(status.success(), "expected a clean exit, got {status:?}");
}

// ── forward: authenticated relay association + byte bridging ───────────────

#[tokio::test(flavor = "multi_thread")]
async fn control_channel_forward_round_trips_bytes_without_host_callback_networking() {
    let target_port = spawn_echo_target().await;
    let mut relay = RelayProcess::spawn(0).await;
    relay.expect_ready().await;
    let session_id = "a".repeat(64);

    relay
        .send(json!({
            "id": 1, "op": "forward_open",
            "data": {"session_id": session_id, "target_port": target_port},
        }))
        .await;
    assert_eq!(relay.next_json().await, json!({"id": 1, "ok": true}));

    let payload = b"stdio-forward-round-trip";
    relay
        .send(json!({
            "id": 2, "op": "forward_write",
            "data": {
                "session_id": session_id,
                "bytes": base64::engine::general_purpose::STANDARD.encode(payload),
            },
        }))
        .await;
    assert_eq!(relay.next_json().await, json!({"id": 2, "ok": true}));

    let echoed = loop {
        relay
            .send(json!({
                "id": 3, "op": "forward_read", "data": {"session_id": session_id},
            }))
            .await;
        let response = relay.next_json().await;
        let encoded = response["data"]["bytes"].as_str().unwrap();
        if !encoded.is_empty() {
            break base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap();
        }
    };
    assert_eq!(echoed, payload);

    relay
        .send(json!({
            "id": 4, "op": "forward_close", "data": {"session_id": session_id},
        }))
        .await;
    assert_eq!(relay.next_json().await, json!({"id": 4, "ok": true}));
}

#[tokio::test(flavor = "multi_thread")]
async fn forward_with_correct_auth_bridges_bytes_both_directions() {
    let target_port = spawn_echo_target().await;
    let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();

    let mut relay = RelayProcess::spawn(0).await;
    relay.expect_ready().await;

    let nonce = "test-nonce-abc123";
    relay
        .send(json!({
            "id": 5,
            "op": "forward",
            "data": {"relay_addr": relay_addr.to_string(), "target_port": target_port, "nonce": nonce},
        }))
        .await;

    // Both sides of the handshake only make progress if driven
    // concurrently: the relay's forward ack doesn't arrive until its WS
    // client connection to us completes, which needs us to actually
    // accept it.
    let (mut ws, ack) = tokio::join!(
        accept_and_authenticate(&relay_listener, nonce),
        relay.next_json()
    );
    assert_eq!(ack["id"], 5);
    assert_eq!(ack["ok"], true, "forward ack: {ack}");

    ws.send(Message::Text("SESSION_START".into()))
        .await
        .unwrap();
    let payload = b"hello over the bridge".to_vec();
    ws.send(Message::Binary(payload.clone().into()))
        .await
        .unwrap();

    let echoed = tokio::time::timeout(TIMEOUT, ws.next())
        .await
        .expect("timed out waiting for the echoed bytes")
        .expect("WS closed before echoing")
        .expect("WS read error");
    match echoed {
        Message::Binary(b) => assert_eq!(b.as_ref(), payload.as_slice()),
        other => panic!("expected a Binary echo, got {other:?}"),
    }

    ws.send(Message::Text("SESSION_END".into())).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_forwards_do_not_cross_talk() {
    let target_port = spawn_echo_target().await;
    let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_a = listener_a.local_addr().unwrap();
    let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_b = listener_b.local_addr().unwrap();

    let mut relay = RelayProcess::spawn(0).await;
    relay.expect_ready().await;

    relay
        .send(json!({
            "id": 1, "op": "forward",
            "data": {"relay_addr": addr_a.to_string(), "target_port": target_port, "nonce": "nonce-a"},
        }))
        .await;
    relay
        .send(json!({
            "id": 2, "op": "forward",
            "data": {"relay_addr": addr_b.to_string(), "target_port": target_port, "nonce": "nonce-b"},
        }))
        .await;

    let (ws_a, ws_b) = tokio::join!(
        accept_and_authenticate(&listener_a, "nonce-a"),
        accept_and_authenticate(&listener_b, "nonce-b"),
    );
    let (mut ws_a, mut ws_b) = (ws_a, ws_b);

    let ack1 = relay.next_json().await;
    let ack2 = relay.next_json().await;
    assert!(
        ack1["ok"] == true && ack2["ok"] == true,
        "acks: {ack1} / {ack2}"
    );
    let ids: HashSet<_> = [ack1["id"].as_u64(), ack2["id"].as_u64()]
        .into_iter()
        .collect();
    assert_eq!(
        ids,
        HashSet::from([Some(1), Some(2)]),
        "both forward requests must be acked exactly once"
    );

    ws_a.send(Message::Text("SESSION_START".into()))
        .await
        .unwrap();
    ws_b.send(Message::Text("SESSION_START".into()))
        .await
        .unwrap();
    ws_a.send(Message::Binary(b"payload-A".to_vec().into()))
        .await
        .unwrap();
    ws_b.send(Message::Binary(b"payload-B".to_vec().into()))
        .await
        .unwrap();

    let (echo_a, echo_b) = tokio::join!(
        tokio::time::timeout(TIMEOUT, ws_a.next()),
        tokio::time::timeout(TIMEOUT, ws_b.next()),
    );
    match echo_a
        .expect("timeout on A")
        .expect("closed on A")
        .expect("read error on A")
    {
        Message::Binary(b) => assert_eq!(
            b.as_ref(),
            b"payload-A",
            "session A must not see session B's bytes"
        ),
        other => panic!("unexpected message on A: {other:?}"),
    }
    match echo_b
        .expect("timeout on B")
        .expect("closed on B")
        .expect("read error on B")
    {
        Message::Binary(b) => assert_eq!(
            b.as_ref(),
            b"payload-B",
            "session B must not see session A's bytes"
        ),
        other => panic!("unexpected message on B: {other:?}"),
    }
}
