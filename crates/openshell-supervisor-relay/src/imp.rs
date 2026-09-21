// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generic process spawner + WebSocket relay bridge for `OpenShell` MXC
//! `ProcessContainer` sandboxes.
//!
//! Unlike `mxc-ws-agent.rs` (a self-contained echo-server test harness), this
//! binary has exactly one job: launch an arbitrary command inside the
//! `AppContainer` and, on request, expose one of its TCP ports to the host
//! through a gateway relay, without requiring any changes to the launched
//! command itself. It is the `agent_command` the mxc driver spawns in place
//! of the target application directly, whenever a sandbox config asks for
//! relay bridging (see `driver.rs`'s handling of `pc_relay_spawner_path` /
//! `pc_relay_target_port`).
//!
//! There is no bridge at startup — relay bridging is entirely on-demand,
//! driven by `forward` requests over the control channel below (used for
//! `openshell forward service`). Each bridge is independent, short-lived, and
//! parameterized per-request (relay address + target port supplied in the
//! request), not declared anywhere in the gateway TOML.
//!
//! ```text
//! Host TCP client (via `openshell forward service`)
//!      |
//!      v
//! Gateway relay (127.0.0.1:<ephemeral>)   <-- driver binds one per forward
//!      ^                                      request, tells us the address
//!      | outbound WS (via egress_proxy)        over the control channel
//!      |
//!  openshell-supervisor-relay  <-- dials out on "forward", proxies traffic
//!      |               for the lifetime of that one request
//!      | loopback WS (AppContainer-internal)
//!      v
//!  <target process>   <-- launched from the "launch" control-channel
//!                          request (see below), no relay knowledge required
//! ```
//!
//! Usage: `openshell-supervisor-relay.exe <target-port>` -- `<target-port>`
//! is the TCP port the launched command is expected to bind. The host MXC
//! driver observes that listener and confirms it over the control channel;
//! the relay races that confirmation against target exit and shutdown.
//! This binary uses no `share_dir` files
//! at all -- command/env and shutdown both travel over the control channel.
//!
//! Shutdown: driver sends a `"shutdown"` request over the control channel
//! (see below) and separately kills the wxc-exec process (`AppContainer`
//! teardown) as a backstop regardless of whether that message gets through.
//! This binary's `run_lifecycle` reacts to the request by killing the
//! target cleanly if it's still running.
//!
//! ## Control channel (this process's own stdin/stdout)
//!
//! `wxc-exec` runs this process with STDIO passthrough, which forwards its
//! own stdin/stdout down from the driver -- the driver pipes them (see
//! `mxc.rs`'s `run_oneshot`) instead of the usual `null`/`piped`-for-logging
//! split, giving the gateway a write channel straight into the `AppContainer`.
//! This needs **no `AppContainer` network capability at all**: it's inherited
//! process handles, not network traffic, so none of `egress_proxy` /
//! `network.proxy` / `privateNetworkClientServer` are involved.
//!
//! Protocol: newline-delimited JSON, mirroring MXC's own `pipe_server` tool:
//!   Request:  `{"id": <N>, "op": "<op>", "data": <any>}`
//!   Response: `{"id": <N>, "ok": true,  "data": <any>}`
//!          or `{"id": <N>, "ok": false, "error": "<msg>"}`
//!   Event (unsolicited, no id): `{"event": "<name>"}` (startup also emits
//!          either `target_ready` or `target_failed`; the latter includes an
//!          `error` string with the target's exit and bounded stderr detail)
//!
//! Startup handshake: before spawning anything, this process emits
//! `{"event":"ready","protocol_version":N}` on stdout (`N` = `PROTOCOL_VERSION`
//! below -- the driver rejects a mismatched/missing version immediately,
//! so an independently staged, out-of-sync binary fails fast instead of
//! hanging or misbehaving later), then blocks waiting for a `"launch"`
//! request carrying `data: {"command": [...], "env": [...]}` (one arg per
//! `command` element, first is the executable; `env` is `"KEY=VALUE"`
//! strings, replacing the inherited environment entirely when non-empty --
//! lets runtimes that choke on an unrecognized host env, e.g. node.js
//! `STATUS_DLL_INIT_FAILED`, get a curated one instead). The driver sends
//! this once its stdout-reader observes the ready event (see driver.rs).
//! Command/env travel over this channel rather than as `agent-cmd.txt`/
//! `agent-env.txt` files in `share_dir` -- keeps them (which can carry
//! secrets) off disk, and avoids the file ever going stale.
//!
//! Ops: `launch` (see above), `shutdown` (no data; acked, then wakes
//! `run_lifecycle` to kill the target and exit -- see Shutdown above),
//! `target_ready` (host listener confirmation), `ping`, `echo`, and `forward`
//! -- `forward` opens a new, independent relay
//! bridge for the target port and relay address given in the request (see
//! `handle_control_request`'s doc comment for the full shape).
//!
//! Because this channel owns our stdout exclusively, the target process's own
//! stdout/stderr are piped (not inherited) and forwarded to *our* stderr with
//! a `[target stdout]`/`[target stderr]` tag instead, so they stay visible in
//! the gateway log without colliding with control-channel responses.

use base64::Engine;
use futures::{SinkExt, StreamExt};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::Message;

/// Wire protocol version reported in the startup `"ready"` event (see
/// `run_control_channel`). Must match `openshell-driver-mxc`'s
/// `REQUIRED_SUPERVISOR_RELAY_PROTOCOL_VERSION` constant -- duplicated
/// rather than shared via a common crate, matching how the rest of this
/// wire protocol is already duplicated across the two sides. Bump both
/// together whenever the control-channel protocol changes in a way an
/// out-of-sync peer can't safely ignore, so an independently staged, stale
/// binary on either side fails fast with a clear version-mismatch error
/// instead of hanging or misbehaving against a field/event it predates.
const PROTOCOL_VERSION: u64 = 4;

const TARGET_STDERR_TAIL_LINES: usize = 20;
const TARGET_STDERR_LINE_CHARS: usize = 1024;

struct SpawnedTarget {
    child: tokio::process::Child,
    stderr_tail: Arc<StdMutex<VecDeque<String>>>,
    stderr_forwarder: Option<tokio::task::JoinHandle<()>>,
}

enum StartupOutcome {
    Ready,
    Exited(std::io::Result<std::process::ExitStatus>),
    Shutdown,
}

struct ForwardSession {
    reader: tokio::sync::Mutex<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::sync::Mutex<tokio::net::tcp::OwnedWriteHalf>,
}

type ForwardSessions = tokio::sync::Mutex<HashMap<String, Arc<ForwardSession>>>;

pub async fn run() -> anyhow::Result<()> {
    let port: u16 = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: openshell-supervisor-relay <target-port>"))?
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid <target-port>: {e}"))?;

    // Wait for the driver's "launch" request (see module docs' startup
    // handshake) before spawning anything -- command/env arrive over the
    // control channel, not as files read from share_dir. Shutdown notice
    // arrives the same way (a later "shutdown" request) -- no share_dir
    // files are used by this process at all.
    let (launch_tx, launch_rx) = oneshot::channel::<(Vec<String>, Vec<String>)>();
    let launch_slot = Arc::new(tokio::sync::Mutex::new(Some(launch_tx)));
    let (target_ready_tx, target_ready_rx) = oneshot::channel::<()>();
    let target_ready_slot = Arc::new(tokio::sync::Mutex::new(Some(target_ready_tx)));
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let shutdown_slot = Arc::new(tokio::sync::Mutex::new(Some(shutdown_tx)));
    let forward_sessions = Arc::new(ForwardSessions::new(HashMap::new()));
    // Lets main() ask run_control_channel's task to announce either
    // "target_ready" or "target_failed" on stdout. The acknowledgement makes
    // failure delivery deterministic: do not let this process exit until the
    // real target diagnostic has been flushed into the pipe to the driver.
    let (target_status_tx, target_status_rx) = oneshot::channel::<Result<(), String>>();
    let (target_status_ack_tx, target_status_ack_rx) = oneshot::channel::<()>();
    tokio::spawn(run_control_channel(
        launch_slot,
        target_ready_slot,
        shutdown_slot,
        forward_sessions,
        target_status_rx,
        target_status_ack_tx,
    ));

    eprintln!("[openshell-supervisor-relay] waiting for launch request from driver...");
    let (command, env) = launch_rx
        .await
        .map_err(|_| anyhow::anyhow!("control channel closed before a launch request arrived"))?;

    let mut target = match spawn_target(command, env) {
        Ok(target) => target,
        Err(error) => {
            let message = format!("target process failed to start: {error:#}");
            announce_target_status(target_status_tx, target_status_ack_rx, Err(message.clone()))
                .await;
            eprintln!("[openshell-supervisor-relay] {message}");
            std::process::exit(1);
        }
    };

    eprintln!(
        "[openshell-supervisor-relay] waiting for host-confirmed target readiness on port {port} ..."
    );
    // The AppContainer cannot reliably connect to a not-yet-listening
    // loopback port or inspect the Windows TCP table. The host driver can
    // observe that table, so it sends `target_ready` after the listener
    // appears. Race that confirmation against target exit and shutdown so a
    // failed target still reports its real status/stderr immediately.
    let mut shutdown_rx = shutdown_rx;
    let startup = tokio::select! {
        biased;
        // If the target exits at the same instant the host confirms its
        // listener, preserve the real exit/stderr diagnostic instead of
        // briefly publishing a stale Ready state.
        status = target.child.wait() => StartupOutcome::Exited(status),
        _ = &mut shutdown_rx => StartupOutcome::Shutdown,
        result = target_ready_rx => match result {
            Ok(()) => StartupOutcome::Ready,
            Err(_) => StartupOutcome::Exited(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "control channel closed before target readiness was confirmed",
            ))),
        },
    };
    match startup {
        StartupOutcome::Ready => {}
        StartupOutcome::Exited(status) => {
            let message = target_failure_message(&mut target, port, status).await;
            announce_target_status(target_status_tx, target_status_ack_rx, Err(message.clone()))
                .await;
            eprintln!("[openshell-supervisor-relay] {message}");
            std::process::exit(1);
        }
        StartupOutcome::Shutdown => {
            eprintln!(
                "[openshell-supervisor-relay] shutdown request -- stopping before target became ready"
            );
            let _ = target.child.kill().await;
            let _ = target.child.wait().await;
            eprintln!("[openshell-supervisor-relay] done");
            // Not `return Ok(())`: run_control_channel loops on
            // stdin.next_line() for this process's entire lifetime and
            // only sees EOF once the driver closes its end, which it has
            // no reason to do before observing this process actually exit
            // -- returning normally here would leave that task (and so
            // this whole process) alive indefinitely, exactly the
            // "acknowledged but still alive" symptom this fix exists to
            // close. std::process::exit terminates unconditionally,
            // matching run_lifecycle's own shutdown branch below.
            std::process::exit(0);
        }
    }
    eprintln!("[openshell-supervisor-relay] host confirmed target listener on port {port}");
    // Unsolicited event, distinct from the "launch" control-channel
    // response (which only confirmed the command/env arrived, not that the
    // target is actually reachable) -- driver.rs awaits this before
    // publishing the sandbox Ready=True. A send failure just means the
    // control-channel task already exited; nothing to do about that here.
    announce_target_status(target_status_tx, target_status_ack_rx, Ok(())).await;

    // No bridge at startup -- relay bridging is entirely on-demand via the
    // control channel's "forward" op (see module docs). Just run the target
    // process's lifecycle from here.
    run_lifecycle(target, shutdown_rx).await;

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Render the first `n` bytes of `data` as a printable-ASCII preview
/// (non-printable bytes shown as `.`), for hop-by-hop diagnostic logging.
/// Not a general-purpose formatter -- just enough to eyeball whether e.g. an
/// HTTP/WS handshake looks intact versus corrupted or empty.
///
/// Not called anywhere: forwarded traffic can carry auth headers, cookies, or
/// other sensitive payload, and helper stderr is forwarded into gateway logs,
/// so no byte preview is ever logged. Kept only so a future opt-in diagnostic
/// mode has a ready-made (still-redaction-worthy) formatter to start from.
#[allow(dead_code)]
fn byte_preview(data: &[u8]) -> String {
    const MAX: usize = 120;
    let n = data.len().min(MAX);
    let mut s: String = data[..n]
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect();
    if data.len() > MAX {
        s.push_str("...");
    }
    s
}

// ── Target process ────────────────────────────────────────────────────────────

/// Spawn `command` (first element is the executable, rest are args) with
/// `env` (`"KEY=VALUE"` strings) as its entire environment when non-empty --
/// both arrive over the control channel's `"launch"` request (see module
/// docs), not read from `share_dir` files. The child's stdout/stderr are piped
/// and forwarded (tagged) to our own stderr — not inherited directly —
/// because our stdout is reserved exclusively for the control-channel
/// protocol with the driver. The child's stdin is closed; it isn't part of
/// this channel.
fn spawn_target(command: Vec<String>, env: Vec<String>) -> anyhow::Result<SpawnedTarget> {
    if command.is_empty() {
        anyhow::bail!("launch command must not be empty");
    }

    let mut cmd = tokio::process::Command::new(&command[0]);
    cmd.args(&command[1..]);
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    if !env.is_empty() {
        let child_env: Vec<(String, String)> = env
            .iter()
            .filter(|l| l.contains('='))
            .filter_map(|l| {
                let pos = l.find('=')?;
                Some((l[..pos].to_string(), l[pos + 1..].to_string()))
            })
            .collect();
        eprintln!(
            "[openshell-supervisor-relay] using {} child env vars from launch request",
            child_env.len()
        );
        cmd.env_clear().envs(child_env);
    }

    // Not the full command line: it's a control-channel payload (see the
    // "launch" handshake in this module's docs) and can carry secrets in
    // its arguments (e.g. a token passed via CLI flag) -- log only the
    // executable and an argument count, matching how the driver side
    // avoids writing agent_command/env to disk for the same reason.
    eprintln!(
        "[openshell-supervisor-relay] starting program {:?} with {} arg(s)",
        command[0],
        command.len().saturating_sub(1)
    );
    let mut child = cmd.spawn()?;

    if let Some(stdout) = child.stdout.take() {
        tokio::spawn(forward_tagged_lines(stdout, "target stdout", None));
    }
    let stderr_tail = Arc::new(StdMutex::new(VecDeque::new()));
    let stderr_forwarder = child.stderr.take().map(|stderr| {
        tokio::spawn(forward_tagged_lines(
            stderr,
            "target stderr",
            Some(stderr_tail.clone()),
        ))
    });

    Ok(SpawnedTarget {
        child,
        stderr_tail,
        stderr_forwarder,
    })
}

/// Read lines from `reader` and re-emit them on our own stderr, tagged, so
/// the target's output stays visible in the gateway log without touching our
/// stdout (reserved for the control channel).
async fn forward_tagged_lines(
    reader: impl tokio::io::AsyncRead + Unpin,
    label: &'static str,
    capture_tail: Option<Arc<StdMutex<VecDeque<String>>>>,
) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if let Some(tail) = &capture_tail {
            let mut chars = line.chars();
            let mut captured: String = chars.by_ref().take(TARGET_STDERR_LINE_CHARS).collect();
            if chars.next().is_some() {
                captured.push_str("...");
            }
            if let Ok(mut tail) = tail.lock() {
                if tail.len() == TARGET_STDERR_TAIL_LINES {
                    tail.pop_front();
                }
                tail.push_back(captured);
            }
        }
        eprintln!("[{label}] {line}");
    }
}

async fn announce_target_status(
    sender: oneshot::Sender<Result<(), String>>,
    announced: oneshot::Receiver<()>,
    status: Result<(), String>,
) {
    if sender.send(status).is_err() {
        return;
    }
    if tokio::time::timeout(Duration::from_secs(5), announced)
        .await
        .is_err()
    {
        eprintln!("[openshell-supervisor-relay] control channel did not flush target status");
    }
}

async fn target_failure_message(
    target: &mut SpawnedTarget,
    port: u16,
    status: std::io::Result<std::process::ExitStatus>,
) -> String {
    if let Some(forwarder) = target.stderr_forwarder.take() {
        let _ = tokio::time::timeout(Duration::from_secs(2), forwarder).await;
    }
    let status = status.map_or_else(
        |error| format!("status unavailable: {error}"),
        |status| status.to_string(),
    );
    let stderr = target
        .stderr_tail
        .lock()
        .map(|tail| tail.iter().cloned().collect::<Vec<_>>().join(" | "))
        .unwrap_or_default();
    let stderr = if stderr.is_empty() {
        String::new()
    } else {
        format!("; stderr: {stderr}")
    };
    format!("target process exited before port {port} came up: {status}{stderr}")
}

// ── Control channel ───────────────────────────────────────────────────────────
//
// See module docs for the protocol and why this is safe to run with no
// AppContainer network capability. Runs for the lifetime of the process,
// independent of target/relay state.

/// Holds the one-shot sender the `"launch"` op fires, carrying `(command,
/// env)` to `main()`. `None` after the first successful launch (or if
/// `main()` already gave up on it) -- a second `"launch"` is rejected.
type LaunchSlot = tokio::sync::Mutex<Option<oneshot::Sender<(Vec<String>, Vec<String>)>>>;
/// Holds the one-shot sender the driver's host-side listener observation
/// fires. Startup does not become ready until this confirmation arrives.
type TargetReadySlot = tokio::sync::Mutex<Option<oneshot::Sender<()>>>;
/// Holds the one-shot sender the `"shutdown"` op fires, waking
/// `run_lifecycle`'s select so it can kill the target and exit. `None`
/// after the first shutdown request -- a second one is a no-op ack.
type ShutdownSlot = tokio::sync::Mutex<Option<oneshot::Sender<()>>>;

async fn run_control_channel(
    launch: Arc<LaunchSlot>,
    target_ready: Arc<TargetReadySlot>,
    shutdown: Arc<ShutdownSlot>,
    forward_sessions: Arc<ForwardSessions>,
    target_status_rx: oneshot::Receiver<Result<(), String>>,
    target_status_ack: oneshot::Sender<()>,
) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();

    // Announce readiness before entering the request loop: this is the
    // signal driver.rs's stdout-reader waits for to know it's safe to send
    // "launch" (see module docs' startup handshake). Unsolicited -- no
    // correlation id, since it isn't a reply to anything the driver sent.
    let ready = serde_json::json!({"event": "ready", "protocol_version": PROTOCOL_VERSION})
        .to_string()
        + "\n";
    if stdout.write_all(ready.as_bytes()).await.is_err() || stdout.flush().await.is_err() {
        eprintln!("[openshell-supervisor-relay] control channel: failed to announce ready");
        return;
    }
    eprintln!("[openshell-supervisor-relay] control channel ready (stdin/stdout)");

    // `None` once fired (or once main()'s sender is dropped without firing) --
    // the `if` guard below then disables that select arm instead of it firing
    // repeatedly on every subsequent poll of an already-resolved oneshot.
    let mut target_status_rx = Some(target_status_rx);
    let mut target_status_ack = Some(target_status_ack);

    loop {
        tokio::select! {
            line_result = lines.next_line() => {
                let line = match line_result {
                    Ok(Some(l)) => l,
                    Ok(None) => {
                        eprintln!("[openshell-supervisor-relay] control channel: stdin closed");
                        break;
                    }
                    Err(e) => {
                        eprintln!("[openshell-supervisor-relay] control channel read error: {e}");
                        break;
                    }
                };
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                // Log only the operation and correlation id, never the raw request --
                // "launch" carries the target's complete environment (e.g.
                // OPENCLAW_GATEWAY_TOKEN) and this process's stderr is forwarded
                // verbatim into the gateway's own logs, so printing `trimmed` here
                // would expose it even when MXC's own --debug flag is off.
                eprintln!(
                    "[openshell-supervisor-relay] control request: {}",
                    describe_control_request(trimmed)
                );
                let response = handle_control_request(
                    trimmed,
                    &launch,
                    &target_ready,
                    &shutdown,
                    &forward_sessions,
                )
                .await;
                let mut out = response.to_string();
                out.push('\n');
                if stdout.write_all(out.as_bytes()).await.is_err() || stdout.flush().await.is_err() {
                    eprintln!("[openshell-supervisor-relay] control channel write failed");
                    break;
                }
            }
            // See module docs' startup handshake -- distinct from the
            // "launch" response, which only confirms the command/env
            // arrived. Unsolicited, like "ready" above.
            result = async { target_status_rx.as_mut().unwrap().await }, if target_status_rx.is_some() => {
                target_status_rx = None;
                let event = match result {
                    Ok(Ok(())) => Some(serde_json::json!({"event": "target_ready"})),
                    Ok(Err(error)) => Some(serde_json::json!({"event": "target_failed", "error": error})),
                    Err(_) => None,
                };
                if let Some(event) = event {
                    let out = event.to_string() + "\n";
                    if stdout.write_all(out.as_bytes()).await.is_err() || stdout.flush().await.is_err() {
                        eprintln!("[openshell-supervisor-relay] control channel: failed to announce target status");
                    }
                    if let Some(ack) = target_status_ack.take() {
                        let _ = ack.send(());
                    }
                }
                // A dropped sender means main() exited before announcing
                // target status. There is nothing to write in that case;
                // driver.rs will observe control-channel EOF.
            }
        }
    }
}

/// `forward` opens a new, independent relay bridge for a target port, e.g.
/// for `openshell forward service`.
///
/// `data`: `{"relay_addr": "<host:port>", "target_port": <u16>}` -- the
/// caller (the driver) has already started a fresh relay listener on the
/// gateway side for this one request and tells us its address here; we dial
/// out to it (Phase A). Replies once Phase A actually connects (or on
/// failure/timeout), so the caller knows whether the bridge is really usable
/// before it starts sending Phase B clients at the relay address it created.
///
/// No explicit "stop" for this bridge: it runs until Phase A closes, which
/// happens when the caller drops its relay listener (the gRPC forward
/// stream ending) -- see the driver-side `ForwardSink::open_dynamic_forward`.
/// Summarizes an inbound control-channel request for logging as `op=... id=...`
/// -- deliberately never includes `data`, since `launch` (and, in principle,
/// `echo`) can carry secrets. Falls back to a fixed placeholder rather than
/// printing anything from `line` if it doesn't even parse, so a malformed
/// request can't smuggle sensitive-looking text into the log via a JSON
/// parse failure either.
fn describe_control_request(line: &str) -> String {
    serde_json::from_str::<serde_json::Value>(line).map_or_else(
        |_| "<unparseable request>".to_string(),
        |v| {
            let op = v.get("op").and_then(|x| x.as_str()).unwrap_or("<missing>");
            let id = v.get("id").cloned().unwrap_or(serde_json::Value::Null);
            format!("op={op} id={id}")
        },
    )
}

async fn handle_control_request(
    line: &str,
    launch: &LaunchSlot,
    target_ready: &TargetReadySlot,
    shutdown: &ShutdownSlot,
    forward_sessions: &ForwardSessions,
) -> serde_json::Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let req: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return serde_json::json!({"id": null, "ok": false, "error": format!("parse error: {e}")});
        }
    };
    let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
    let op = req.get("op").and_then(|v| v.as_str()).unwrap_or("");

    match op {
        // The host MXC driver can observe the AppContainer listener without
        // the AppContainer's own network/table restrictions. It sends this
        // only after the configured target port appears in the host TCP
        // table; main races this signal against target exit and shutdown.
        "target_ready" => {
            let slot = target_ready.lock().await.take();
            slot.map_or_else(
                || {
                    serde_json::json!({
                        "id": id,
                        "ok": false,
                        "error": "target readiness already confirmed"
                    })
                },
                |tx| {
                    if tx.send(()).is_ok() {
                        serde_json::json!({"id": id, "ok": true})
                    } else {
                        serde_json::json!({
                            "id": id,
                            "ok": false,
                            "error": "target readiness receiver is unavailable"
                        })
                    }
                },
            )
        }
        // Driver sends this on sandbox delete instead of writing a
        // openshell-shutdown.signal file -- wakes run_lifecycle's select so
        // it can kill the target and exit. Acked even on a repeat (the
        // slot's already empty by then), since the driver's request has a
        // short timeout and shouldn't be left hanging either way.
        "shutdown" => {
            let slot = shutdown.lock().await.take();
            if let Some(tx) = slot {
                let _ = tx.send(());
            }
            serde_json::json!({"id": id, "ok": true})
        }
        // See module docs' startup handshake: sent once, right after the
        // "ready" event, carrying the real command/env instead of them
        // being written to share_dir as agent-cmd.txt/agent-env.txt.
        "launch" => {
            let data = req.get("data").cloned().unwrap_or(serde_json::Value::Null);
            let command: Vec<String> = data
                .get("command")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            if command.is_empty() {
                return serde_json::json!({
                    "id": id, "ok": false,
                    "error": "launch requires data.command (non-empty array of strings)"
                });
            }
            let env: Vec<String> = data
                .get("env")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();

            let slot = launch.lock().await.take();
            slot.map_or_else(
                || serde_json::json!({"id": id, "ok": false, "error": "launch already requested"}),
                |tx| {
                    let _ = tx.send((command, env));
                    serde_json::json!({"id": id, "ok": true})
                },
            )
        }
        "ping" => serde_json::json!({"id": id, "ok": true, "data": "pong"}),
        "echo" => {
            let data = req.get("data").cloned().unwrap_or(serde_json::Value::Null);
            serde_json::json!({"id": id, "ok": true, "data": data})
        }
        "forward_open" => {
            let data = req.get("data").cloned().unwrap_or(serde_json::Value::Null);
            let session_id = data
                .get("session_id")
                .and_then(|v| v.as_str())
                .filter(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
                .map(str::to_string);
            let target_port = data
                .get("target_port")
                .and_then(serde_json::Value::as_u64)
                .and_then(|n| u16::try_from(n).ok());
            let (Some(session_id), Some(target_port)) = (session_id, target_port) else {
                return serde_json::json!({
                    "id": id, "ok": false,
                    "error": "forward_open requires a 64-character hexadecimal session_id and target_port (u16)"
                });
            };
            if forward_sessions.lock().await.contains_key(&session_id) {
                return serde_json::json!({
                    "id": id, "ok": false, "error": "forward session already exists"
                });
            }
            let stream = match connect_forward_target(|| {
                tokio::net::TcpStream::connect(("127.0.0.1", target_port))
            })
            .await
            {
                Ok(stream) => stream,
                Err(error) => {
                    return serde_json::json!({
                        "id": id, "ok": false,
                        "error": format!("target connect failed: {error}")
                    });
                }
            };
            if let Err(error) = stream.set_nodelay(true) {
                eprintln!(
                    "[openshell-supervisor-relay] failed to set TCP_NODELAY on target connection: {error}"
                );
            }
            let (reader, writer) = stream.into_split();
            forward_sessions.lock().await.insert(
                session_id,
                Arc::new(ForwardSession {
                    reader: tokio::sync::Mutex::new(reader),
                    writer: tokio::sync::Mutex::new(writer),
                }),
            );
            serde_json::json!({"id": id, "ok": true})
        }
        "forward_write" => {
            let data = req.get("data").cloned().unwrap_or(serde_json::Value::Null);
            let session_id = data.get("session_id").and_then(|v| v.as_str());
            let encoded = data.get("bytes").and_then(|v| v.as_str());
            let (Some(session_id), Some(encoded)) = (session_id, encoded) else {
                return serde_json::json!({
                    "id": id, "ok": false,
                    "error": "forward_write requires session_id and base64 bytes"
                });
            };
            if encoded.len() > 16_384 {
                return serde_json::json!({"id": id, "ok": false, "error": "forward_write chunk is too large"});
            }
            let bytes = match base64::engine::general_purpose::STANDARD.decode(encoded) {
                Ok(bytes) => bytes,
                Err(error) => {
                    return serde_json::json!({
                        "id": id, "ok": false, "error": format!("invalid forward bytes: {error}")
                    });
                }
            };
            let session = forward_sessions.lock().await.get(session_id).cloned();
            let Some(session) = session else {
                return serde_json::json!({"id": id, "ok": false, "error": "forward session not found"});
            };
            match session.writer.lock().await.write_all(&bytes).await {
                Ok(()) => serde_json::json!({"id": id, "ok": true}),
                Err(error) => {
                    serde_json::json!({"id": id, "ok": false, "error": format!("target write failed: {error}")})
                }
            }
        }
        "forward_read" => {
            let data = req.get("data").cloned().unwrap_or(serde_json::Value::Null);
            let Some(session_id) = data.get("session_id").and_then(|v| v.as_str()) else {
                return serde_json::json!({"id": id, "ok": false, "error": "forward_read requires session_id"});
            };
            let session = forward_sessions.lock().await.get(session_id).cloned();
            let Some(session) = session else {
                return serde_json::json!({"id": id, "ok": false, "error": "forward session not found"});
            };
            let mut bytes = vec![0_u8; 8192];
            match tokio::time::timeout(
                Duration::from_millis(100),
                session.reader.lock().await.read(&mut bytes),
            )
            .await
            {
                Ok(Ok(0)) => {
                    serde_json::json!({"id": id, "ok": true, "data": {"bytes": "", "eof": true}})
                }
                Ok(Ok(n)) => {
                    let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes[..n]);
                    serde_json::json!({"id": id, "ok": true, "data": {"bytes": encoded, "eof": false}})
                }
                Ok(Err(error)) => {
                    serde_json::json!({"id": id, "ok": false, "error": format!("target read failed: {error}")})
                }
                Err(_) => {
                    serde_json::json!({"id": id, "ok": true, "data": {"bytes": "", "eof": false}})
                }
            }
        }
        "forward_close" => {
            let data = req.get("data").cloned().unwrap_or(serde_json::Value::Null);
            let Some(session_id) = data.get("session_id").and_then(|v| v.as_str()) else {
                return serde_json::json!({"id": id, "ok": false, "error": "forward_close requires session_id"});
            };
            forward_sessions.lock().await.remove(session_id);
            serde_json::json!({"id": id, "ok": true})
        }
        "forward" => {
            let data = req.get("data").cloned().unwrap_or(serde_json::Value::Null);
            let relay_addr = data
                .get("relay_addr")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let target_port = data
                .get("target_port")
                .and_then(serde_json::Value::as_u64)
                .and_then(|n| u16::try_from(n).ok());
            // Proves to the relay (a loopback-bound listener any other local
            // process could otherwise race to connect to first) that this
            // is the real Phase A peer -- see openshell-driver-mxc's
            // relay.rs module docs. Sent verbatim as the WS auth message
            // below, not decoded here; the driver and the relay agree on
            // the hex encoding independently.
            let nonce = data
                .get("nonce")
                .and_then(|v| v.as_str())
                .map(str::to_string);

            let (Some(relay_addr), Some(target_port), Some(nonce)) =
                (relay_addr, target_port, nonce)
            else {
                return serde_json::json!({
                    "id": id, "ok": false,
                    "error": "forward requires data.relay_addr (string), data.target_port (u16), and data.nonce (string)"
                });
            };

            let (ready_tx, ready_rx) = oneshot::channel::<Result<(), String>>();

            eprintln!(
                "[openshell-supervisor-relay] forward: dynamic bridge ws://{relay_addr} <-> 127.0.0.1:{target_port}"
            );
            tokio::spawn(run_relay_bridge(relay_addr, target_port, nonce, ready_tx));

            match tokio::time::timeout(Duration::from_secs(5), ready_rx).await {
                Ok(Ok(Ok(()))) => {
                    serde_json::json!({"id": id, "ok": true, "data": {"target_port": target_port}})
                }
                Ok(Ok(Err(e))) => serde_json::json!({"id": id, "ok": false, "error": e}),
                Ok(Err(_)) => {
                    serde_json::json!({"id": id, "ok": false, "error": "relay bridge task dropped"})
                }
                Err(_) => serde_json::json!({
                    "id": id, "ok": false, "error": "timed out waiting for relay connection"
                }),
            }
        }
        _ => serde_json::json!({"id": id, "ok": false, "error": format!("unknown op: {op}")}),
    }
}

/// Bound session opening below the driver's 10-second control-request timeout.
/// Five one-second attempts plus four 300ms retry delays take at most 6.2s
/// of timer budget. A stuck connect is cancelled before another is attempted.
async fn connect_forward_target<T, F, Fut>(mut connect: F) -> std::io::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = std::io::Result<T>>,
{
    let mut last_error = std::io::Error::from(std::io::ErrorKind::TimedOut);
    for attempt in 1..=5 {
        match tokio::time::timeout(Duration::from_secs(1), connect()).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => last_error = error,
            Err(_) => last_error = std::io::Error::from(std::io::ErrorKind::TimedOut),
        }
        if attempt < 5 {
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }
    Err(last_error)
}

// ── Relay bridge ──────────────────────────────────────────────────────────────
//
// Implements the sandbox side of relay.rs's Phase A protocol exactly:
//
//   TEXT  "SESSION_START" — relay opened a new Phase B TCP connection; open a
//                           FRESH raw TCP connection to the target and start
//                           forwarding its bytes back as BINARY frames.
//   BINARY <bytes>        — bytes from the Phase B TCP stream; write them
//                           as-is to the active target connection.
//   TEXT  "SESSION_END"   — Phase B TCP connection closed; drop the target
//                           connection.
//   WS Close               — relay shutting down.
//
// This is a raw byte tunnel, not a WS-to-WS message bridge: each session gets
// its own genuine TCP connection to the target with bytes passed through
// untouched, so the host's own protocol (e.g. a real WS handshake it performs
// against the tunnel) reaches the target exactly as sent. A single persistent
// connection re-used across sessions, forwarding opaque message payloads,
// would not preserve that — the target would never see a valid handshake.

async fn run_relay_bridge(
    relay_addr: String,
    port: u16,
    nonce: String,
    ready_tx: oneshot::Sender<Result<(), String>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let relay_url = format!("ws://{relay_addr}");

    // The gateway already bound this listener before sending us the
    // "forward" request, so it's expected to be immediately reachable --
    // single attempt, no retry needed here.
    //
    // Connect the raw TCP socket ourselves rather than letting
    // tokio_tungstenite::connect_async do it internally, so TCP_NODELAY can
    // be set before the WS handshake: this is a latency-sensitive
    // request/response tunnel, including on loopback, and small WS frames
    // can otherwise stall behind delayed ACK behavior. Best-effort --
    // failure to set it doesn't fail the connection, just costs a bit of
    // latency.
    let tcp = match tokio::net::TcpStream::connect(&relay_addr).await {
        Ok(stream) => {
            if let Err(e) = stream.set_nodelay(true) {
                eprintln!(
                    "[openshell-supervisor-relay] failed to set TCP_NODELAY on relay connection: {e}"
                );
            }
            stream
        }
        Err(e) => {
            let msg = format!("relay connect failed: {e}");
            eprintln!("[openshell-supervisor-relay] {msg}");
            let _ = ready_tx.send(Err(msg));
            return;
        }
    };
    let relay_ws = match tokio_tungstenite::client_async(&relay_url, tcp).await {
        Ok((ws, _)) => {
            eprintln!("[openshell-supervisor-relay] relay connected: {relay_url}");
            ws
        }
        Err(e) => {
            let msg = format!("relay handshake failed: {e}");
            eprintln!("[openshell-supervisor-relay] {msg}");
            let _ = ready_tx.send(Err(msg));
            return;
        }
    };
    let (mut relay_write, mut relay_read) = relay_ws.split();

    // Must be the very first message: the relay won't trust anything else
    // from this connection (including SESSION_START/BINARY frames) until
    // this matches -- see relay.rs module docs.
    if let Err(e) = relay_write
        .send(Message::Text(format!("AUTH:{nonce}").into()))
        .await
    {
        let msg = format!("relay auth send failed: {e}");
        eprintln!("[openshell-supervisor-relay] {msg}");
        let _ = ready_tx.send(Err(msg));
        return;
    }

    eprintln!("[openshell-supervisor-relay] relay bridge active");
    let _ = ready_tx.send(Ok(()));

    let mut session: Option<tokio::net::TcpStream> = None;
    let mut read_buf = vec![0u8; 8192];
    // Byte counters, reset per session -- mirror the instrumentation in
    // relay.rs. Together the two sides let a hung request be localized to a
    // specific hop instead of just "the client timed out": relay.rs's
    // host_to_sandbox_* should match this session's phase_a_to_target_*
    // (same bytes, different name each side of the WS tunnel), and
    // target_to_phase_a_* should match relay.rs's sandbox_to_host_*. A
    // mismatch or a stuck-at-zero counter on one side pinpoints exactly
    // where bytes stop moving. No payload content is ever logged -- see the
    // module-level note on `byte_preview`.
    let mut phase_a_to_target_bytes: u64 = 0;
    let mut phase_a_to_target_chunks: u64 = 0;
    let mut target_to_phase_a_bytes: u64 = 0;
    let mut target_to_phase_a_chunks: u64 = 0;

    loop {
        let session_read =
            futures::future::OptionFuture::from(session.as_mut().map(|s| s.read(&mut read_buf)));

        tokio::select! {
            msg = relay_read.next() => match msg {
                Some(Ok(Message::Text(t))) => {
                    if t == "SESSION_START" {
                        // Retry briefly: the host driver's TCP-table observation
                        // confirms a listener exists, but does not guarantee it
                        // stays continuously accept-ready under a freshly-started
                        // process (observed as a genuine, reproducible ~500ms
                        // startup race elsewhere in this codebase -- see
                        // mxc-ws-agent.rs's local-connect retry). A session-open
                        // failure here would otherwise silently drop the host's
                        // connection attempt.
                        match connect_forward_target(|| tokio::net::TcpStream::connect(("127.0.0.1", port))).await {
                          Ok(s) => {
                            // Latency-sensitive request/response tunnel --
                            // see the matching comment on the relay
                            // connection above. Best-effort.
                            if let Err(e) = s.set_nodelay(true) {
                                eprintln!("[openshell-supervisor-relay] failed to set TCP_NODELAY on target connection: {e}");
                            }
                            eprintln!("[openshell-supervisor-relay] session start -- connected to target 127.0.0.1:{port}");
                            session = Some(s);
                            phase_a_to_target_bytes = 0;
                            phase_a_to_target_chunks = 0;
                            target_to_phase_a_bytes = 0;
                            target_to_phase_a_chunks = 0;
                          }
                          Err(last_err) => {
                            eprintln!("[openshell-supervisor-relay] session start -- target connect failed: {last_err}");
                            // Tell the relay so it can close the host's
                            // TCP connection promptly instead of leaving
                            // it hanging until the client's own timeout.
                            let _ = relay_write
                                .send(Message::Text(format!("SESSION_FAILED:{last_err}").into()))
                                .await;
                          }
                        }
                    } else if t == "SESSION_END" {
                        eprintln!("[openshell-supervisor-relay] session end phase_a_to_target_bytes={phase_a_to_target_bytes} phase_a_to_target_chunks={phase_a_to_target_chunks} target_to_phase_a_bytes={target_to_phase_a_bytes} target_to_phase_a_chunks={target_to_phase_a_chunks}");
                        session = None;
                    }
                }
                Some(Ok(Message::Binary(b))) => {
                    if let Some(s) = session.as_mut() {
                        phase_a_to_target_chunks += 1;
                        phase_a_to_target_bytes += b.len() as u64;
                        if phase_a_to_target_chunks == 1 {
                            eprintln!("[openshell-supervisor-relay] first phase-A->target chunk: {} bytes", b.len());
                        }
                        if s.write_all(&b).await.is_err() {
                            eprintln!("[openshell-supervisor-relay] target write failed");
                            session = None;
                        }
                    } else {
                        eprintln!("[openshell-supervisor-relay] BINARY with no active session (dropped {} bytes)", b.len());
                    }
                }
                Some(Ok(Message::Close(_))) | None => {
                    eprintln!("[openshell-supervisor-relay] relay closed");
                    break;
                }
                Some(Ok(_)) => {} // ping/pong handled by tungstenite
                Some(Err(e)) => {
                    eprintln!("[openshell-supervisor-relay] relay read error: {e}");
                    break;
                }
            },
            Some(result) = session_read => {
                match result {
                    Ok(0) => {
                        eprintln!("[openshell-supervisor-relay] target connection closed phase_a_to_target_bytes={phase_a_to_target_bytes} phase_a_to_target_chunks={phase_a_to_target_chunks} target_to_phase_a_bytes={target_to_phase_a_bytes} target_to_phase_a_chunks={target_to_phase_a_chunks}");
                        session = None;
                        // Tell the relay so it can close the host's Phase B
                        // TCP connection promptly (see relay.rs's handling
                        // of this message) instead of leaving the host
                        // client waiting for more bytes until its own
                        // timeout -- the target won't send any more.
                        let _ = relay_write.send(Message::Text("SESSION_END".into())).await;
                    }
                    Ok(n) => {
                        target_to_phase_a_chunks += 1;
                        target_to_phase_a_bytes += n as u64;
                        if target_to_phase_a_chunks == 1 {
                            eprintln!("[openshell-supervisor-relay] first target->phase-A chunk: {n} bytes");
                        }
                        if relay_write.send(Message::Binary(read_buf[..n].to_vec().into())).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("[openshell-supervisor-relay] target read error: {e}");
                        session = None;
                    }
                }
            }
        }
    }
    eprintln!(
        "[openshell-supervisor-relay] relay bridge stopped phase_a_to_target_bytes={phase_a_to_target_bytes} phase_a_to_target_chunks={phase_a_to_target_chunks} target_to_phase_a_bytes={target_to_phase_a_bytes} target_to_phase_a_chunks={target_to_phase_a_chunks}"
    );
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

/// Wait for the target process to exit or a "shutdown" control-channel
/// request to arrive (see `handle_control_request`), whichever comes first.
/// Any active dynamic relay bridges are tokio tasks in this same process, so
/// `std::process::exit` below tears them down too -- no separate stop signal
/// needed.
async fn run_lifecycle(mut target: SpawnedTarget, shutdown_rx: oneshot::Receiver<()>) {
    tokio::select! {
        status = target.child.wait() => {
            let code = status.map_or(1, |s| s.code().unwrap_or(1));
            eprintln!("[openshell-supervisor-relay] target exited with code {code}");
            std::process::exit(code);
        }
        _ = shutdown_rx => {
            eprintln!("[openshell-supervisor-relay] shutdown request -- stopping");
            let _ = target.child.kill().await;
            let _ = target.child.wait().await;
            eprintln!("[openshell-supervisor-relay] done");
            std::process::exit(0);
        }
    }
}

#[cfg(test)]
mod forward_connect_tests {
    use super::connect_forward_target;
    use std::io::{Error, ErrorKind};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test(start_paused = true)]
    async fn forward_connect_returns_success_without_retry_delay() {
        let start = tokio::time::Instant::now();
        let result = connect_forward_target(|| std::future::ready(Ok(42))).await;
        assert_eq!(result.unwrap(), 42);
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn forward_connect_retries_refused_connections_and_preserves_last_error() {
        let mut attempts = 0;
        let start = tokio::time::Instant::now();
        let result = connect_forward_target(|| {
            attempts += 1;
            std::future::ready(Err::<(), _>(Error::new(
                ErrorKind::ConnectionRefused,
                attempts.to_string(),
            )))
        })
        .await;
        assert_eq!(attempts, 5);
        assert_eq!(result.unwrap_err().kind(), ErrorKind::ConnectionRefused);
        assert_eq!(start.elapsed(), Duration::from_millis(1200));
    }

    #[tokio::test(start_paused = true)]
    async fn forward_connect_cancels_stuck_attempts_before_driver_timeout() {
        struct Cancelled(Arc<AtomicUsize>);
        impl Drop for Cancelled {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let cancelled = Arc::new(AtomicUsize::new(0));
        let start = tokio::time::Instant::now();
        let result = connect_forward_target(|| {
            let guard = Cancelled(cancelled.clone());
            async move {
                let _guard = guard;
                std::future::pending::<std::io::Result<()>>().await
            }
        })
        .await;
        assert_eq!(result.unwrap_err().kind(), ErrorKind::TimedOut);
        assert_eq!(cancelled.load(Ordering::SeqCst), 5);
        assert_eq!(start.elapsed(), Duration::from_millis(6200));
        assert!(start.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test(start_paused = true)]
    async fn forward_connect_recovers_after_a_stuck_attempt() {
        let mut attempts = 0;
        let start = tokio::time::Instant::now();
        let result = connect_forward_target(|| {
            attempts += 1;
            let attempt = attempts;
            async move {
                if attempt == 1 {
                    std::future::pending::<()>().await;
                }
                Ok(42)
            }
        })
        .await;
        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts, 2);
        assert_eq!(start.elapsed(), Duration::from_millis(1300));
    }
}
