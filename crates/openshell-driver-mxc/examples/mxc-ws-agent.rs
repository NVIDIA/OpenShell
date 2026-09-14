// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! WebSocket demo agent for `OpenShell` MXC `ProcessContainer`.
//!
//! **Active role: `server`** — a plain WebSocket echo server on port 22000,
//! used by `run-ws-agent-test.ps1` as the target application. It is launched
//! directly as `agent_command` and wrapped by `openshell-supervisor-relay.exe`
//! (see `mxc-ws-gateway.toml`'s `pc_relay_spawner_path`/`pc_relay_target_port`)
//! for connectivity, exactly like the `OpenClaw` scenario wraps `node.exe` --
//! `openshell forward service --target-port 22000` opens an on-demand relay
//! for a host client to reach it. `server` has no relay awareness at all.
//!
//! **Legacy roles: `spawner` and `proxy-for`** — implement an older,
//! *removed* static-relay protocol (`pc_relay_port` config field + a
//! `reverse-relay-addr.txt` file the driver would write into `share_dir`
//! before sandbox creation). The driver no longer supports this: `mxc.rs`/
//! `driver.rs` have no code path that binds `pc_relay_port` or writes that
//! file, so these modes cannot work against the current driver -- kept in
//! this file only as a historical reference for the pre-dynamic-forward
//! design, not exercised by any current test.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::Message;

const WS_PORT: u16 = 22000;

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mode = std::env::args().nth(1).unwrap_or_default();
    match mode.as_str() {
        "spawner" => spawner().await,
        "server" => server().await,
        "proxy-for" => {
            // proxy-for <port>: start the command in agent-cmd.txt as a child
            // process, wait for it to bind <port>, connect outward to the
            // gateway relay, and bridge bidirectionally.  Used to expose an
            // arbitrary WebSocket server (e.g. openclaw gateway) to host
            // clients via the OpenShell relay without modifying that server.
            let port = std::env::args()
                .nth(2)
                .and_then(|s| s.parse::<u16>().ok())
                .expect("Usage: mxc-ws-agent proxy-for <port>");
            proxy_for(port).await
        }
        other => {
            eprintln!("mxc-ws-agent: unknown mode {other:?}. Use 'spawner' or 'server'.");
            std::process::exit(2);
        }
    }
}

// ── AppContainer SID (Windows only) ──────────────────────────────────────────

/// Returns the `AppContainer` SID string of the current process, or `None` if
/// not running in an `AppContainer`.  Written to `appcontainer-sid.txt` in the
/// share dir as a diagnostic aid.
#[cfg(windows)]
#[allow(unsafe_code)] // Windows token-query FFI is confined to this diagnostic helper.
fn appcontainer_sid() -> Option<String> {
    use std::ptr;

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenProcessToken(process: isize, access: u32, token: *mut isize) -> i32;
        fn GetTokenInformation(
            token: isize,
            class: i32,
            info: *mut u8,
            len: u32,
            ret_len: *mut u32,
        ) -> i32;
        fn ConvertSidToStringSidW(sid: *const u8, str_sid: *mut *mut u16) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> isize;
        fn LocalFree(mem: *mut u8) -> *mut u8;
        fn CloseHandle(handle: isize) -> i32;
    }

    // SAFETY: output buffers remain alive through each call; successful token
    // information contains a SID pointer into that buffer. The SID conversion
    // returns a NUL-terminated allocation freed with LocalFree, and the owned
    // token handle is closed on every return path.
    unsafe {
        let proc = GetCurrentProcess();
        let mut token: isize = 0;
        if OpenProcessToken(proc, 0x0008, &raw mut token) == 0 {
            return None;
        }
        let mut buf = [0u8; 256];
        let mut ret_len: u32 = 0;
        let ok = GetTokenInformation(token, 31, buf.as_mut_ptr(), 256, &raw mut ret_len);
        if ok == 0 {
            CloseHandle(token);
            return None;
        }
        let sid_ptr = ptr::read_unaligned(buf.as_ptr().cast::<*const u8>());
        if sid_ptr.is_null() {
            CloseHandle(token);
            return None;
        }
        let mut wide_ptr: *mut u16 = ptr::null_mut();
        if ConvertSidToStringSidW(sid_ptr, &raw mut wide_ptr) == 0 || wide_ptr.is_null() {
            CloseHandle(token);
            return None;
        }
        let mut len = 0;
        while *wide_ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(wide_ptr, len);
        let result = String::from_utf16_lossy(slice);
        LocalFree(wide_ptr.cast());
        CloseHandle(token);
        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }
}

#[cfg(not(windows))]
fn appcontainer_sid() -> Option<String> {
    None
}

// ── Signal / relay address helpers ────────────────────────────────────────────

fn exe_dir() -> anyhow::Result<std::path::PathBuf> {
    Ok(std::env::current_exe()?
        .parent()
        .ok_or_else(|| anyhow::anyhow!("exe has no parent dir"))?
        .to_path_buf())
}

fn signal_file_path() -> anyhow::Result<std::path::PathBuf> {
    Ok(exe_dir()?.join("openshell-shutdown.signal"))
}

/// Read a file written by the host (ASCII, possibly with UTF-8 BOM from
/// `PowerShell` Set-Content -Encoding UTF8) and return the trimmed string.
fn read_host_file(path: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim_start_matches('\u{FEFF}').trim().to_string())
        .filter(|s| !s.is_empty())
}

// ── Spawner ───────────────────────────────────────────────────────────────────

/// Process #1 — the sandbox `agent_command`.
///
/// Responsibilities:
///   1. Spawns the server subprocess and holds its stdin pipe.
///   2. Waits for the server to bind its port (ws-server-started.txt).
///   3. Reads reverse-relay-addr.txt and starts the relay proxy bridge.
///   4. Polls for the shutdown signal file; on detection kills the server and exits.
///
/// The server is a plain WebSocket application with no relay knowledge.
async fn spawner() -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let dir = exe_dir()?;
    let signal = signal_file_path()?;

    // Remove stale files from a previous run. ws-server-started.txt in
    // particular must go too: it encodes the server's port, and a stale copy
    // would let the readiness wait below observe an old run's port instead
    // of actually waiting for this run's server to (re)bind.
    let _ = std::fs::remove_file(&signal);
    if let Ok(dir) = exe_dir() {
        let _ = std::fs::remove_file(dir.join("relay-ready.txt"));
        let _ = std::fs::remove_file(dir.join("ws-server-started.txt"));
    }

    // Write AppContainer SID for diagnostic use.
    if let Some(sid) = appcontainer_sid() {
        let _ = std::fs::write(dir.join("appcontainer-sid.txt"), &sid);
        eprintln!("[spawner] AppContainer SID: {sid}");
    } else {
        eprintln!("[spawner] not running in an AppContainer (no SID)");
    }

    // Spawn the server.
    let mut cmd = tokio::process::Command::new(&exe);
    cmd.arg("server")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    let mut child = cmd.spawn()?;
    let _pipe = child.stdin.take(); // keep write-end alive
    eprintln!("[spawner] server started (pid {:?})", child.id());

    // Wait up to 30 s for the server to write its startup marker, then start
    // the relay proxy.  We launch the proxy in a background task so the main
    // lifecycle loop can still react to shutdown signals and server exit.
    let relay_addr_file = dir.join("reverse-relay-addr.txt");
    let server_marker = dir.join("ws-server-started.txt");

    let server_ready_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if server_marker.exists() {
            break;
        }
        if tokio::time::Instant::now() >= server_ready_deadline {
            eprintln!("[spawner] server did not start within 30 s; relay proxy skipped");
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Read the local server port from ws-server-started.txt ("port=<N>").
    let local_ws_port = read_host_file(&server_marker)
        .and_then(|s| s.strip_prefix("port=").and_then(|n| n.parse::<u16>().ok()))
        .unwrap_or(WS_PORT);

    // Start the relay proxy bridge if the gateway relay address is available.
    let mut relay_task = read_host_file(&relay_addr_file).map_or_else(
        || {
            eprintln!("[spawner] no reverse-relay-addr.txt; relay proxy disabled");
            None
        },
        |relay_addr| {
            let local_url = format!("ws://127.0.0.1:{local_ws_port}");
            let relay_url = format!("ws://{relay_addr}");
            eprintln!("[spawner] starting relay proxy: {relay_url} <-> {local_url}");

            let (bridge_stop_tx, bridge_stop_rx) = oneshot::channel::<()>();
            tokio::spawn(run_relay_proxy(relay_url, local_url, bridge_stop_rx));
            Some(bridge_stop_tx)
        },
    );

    // Main lifecycle loop: server exit or shutdown signal.
    loop {
        tokio::select! {
            status = child.wait() => {
                let code = status.map_or(1, |s| s.code().unwrap_or(1));
                eprintln!("[spawner] server exited with code {code}");
                let _ = std::fs::remove_file(&signal);
                std::process::exit(code);
            }
            () = tokio::time::sleep(Duration::from_millis(500)) => {
                if signal.exists() {
                    eprintln!("[spawner] shutdown signal -- killing server");
                    // Stop the relay proxy first so the relay connection closes
                    // cleanly before we tear down the server.
                    if let Some(tx) = relay_task.take() { let _ = tx.send(()); }
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    let _ = std::fs::remove_file(&signal);
                    eprintln!("[spawner] done");
                    std::process::exit(0);
                }
            }
        }
    }
}

// ── Relay proxy bridge ────────────────────────────────────────────────────────

/// Connect outward to the gateway relay and inward to the local server, then
/// bridge WebSocket messages bidirectionally until either side closes or the
/// shutdown signal fires.
///
/// The local server is a plain WebSocket application.  The spawner acts as a
/// transparent proxy between the gateway relay and the local server, so the
/// server needs no knowledge of the relay.
async fn run_relay_proxy(relay_url: String, local_url: String, mut stop_rx: oneshot::Receiver<()>) {
    const LOCAL_CONNECT_ATTEMPTS: u32 = 15;
    const LOCAL_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
    const LOCAL_CONNECT_BACKOFF: Duration = Duration::from_millis(300);
    // Connect to the gateway relay (outbound via egress_proxy).
    let relay_ws = match tokio_tungstenite::connect_async(&relay_url).await {
        Ok((ws, _)) => {
            eprintln!("[spawner] relay connected: {relay_url}");
            ws
        }
        Err(e) => {
            let msg = format!("relay connect failed: {e}");
            eprintln!("[spawner] {msg}");
            if let Ok(dir) = exe_dir() {
                let _ = std::fs::write(dir.join("relay-debug.txt"), &msg);
            }
            return;
        }
    };

    // Connect to the local server (AppContainer-internal loopback), with
    // retries. The in-sandbox server and the spawner's own AppContainer
    // network-permission state can still be settling when this fires, so the
    // first attempt can race the server's listen() call or a brief
    // AppContainer network-policy warmup window. Without retry, a lost race
    // manifests as a ~20s OS-level connect timeout (os error 10060) rather
    // than an instant refusal, because the SYN is silently dropped, not
    // rejected -- so each retry attempt uses a short timeout instead of
    // waiting out that OS timeout on every try.
    let mut local_ws = None;
    let mut last_err = String::new();
    for attempt in 1..=LOCAL_CONNECT_ATTEMPTS {
        match tokio::time::timeout(
            LOCAL_CONNECT_TIMEOUT,
            tokio_tungstenite::connect_async(&local_url),
        )
        .await
        {
            Ok(Ok((ws, _))) => {
                eprintln!(
                    "[spawner] local server connected: {local_url} (attempt {attempt}/{LOCAL_CONNECT_ATTEMPTS})"
                );
                local_ws = Some(ws);
                break;
            }
            Ok(Err(e)) => last_err = e.to_string(),
            Err(_) => last_err = format!("timed out after {LOCAL_CONNECT_TIMEOUT:?}"),
        }
        eprintln!(
            "[spawner] local server connect attempt {attempt}/{LOCAL_CONNECT_ATTEMPTS} failed ({last_err}); retrying"
        );
        if attempt < LOCAL_CONNECT_ATTEMPTS {
            tokio::time::sleep(LOCAL_CONNECT_BACKOFF).await;
        }
    }
    let Some(local_ws) = local_ws else {
        let msg = format!(
            "local server connect failed after {LOCAL_CONNECT_ATTEMPTS} attempts ({local_url}): {last_err}"
        );
        eprintln!("[spawner] {msg}");
        if let Ok(dir) = exe_dir() {
            let _ = std::fs::write(dir.join("relay-debug.txt"), &msg);
        }
        return;
    };

    let (mut relay_write, mut relay_read) = relay_ws.split();
    let (mut local_write, mut local_read) = local_ws.split();

    eprintln!("[spawner] relay proxy bridge active");

    // Write a marker so the host can wait until the bridge is fully connected
    // before sending the first message.
    if let Ok(dir) = exe_dir() {
        let _ = std::fs::write(dir.join("relay-ready.txt"), b"ok");
    }

    loop {
        tokio::select! {
            // Relay -> local server
            msg = relay_read.next() => match msg {
                Some(Ok(Message::Text(t))) => {
                    if local_write.send(Message::Text(t)).await.is_err() { break; }
                }
                Some(Ok(Message::Binary(b))) => {
                    if local_write.send(Message::Binary(b)).await.is_err() { break; }
                }
                Some(Ok(Message::Close(_))) | None => {
                    eprintln!("[spawner] relay closed");
                    break;
                }
                Some(Ok(_)) => {} // ping/pong
                Some(Err(e)) => {
                    eprintln!("[spawner] relay read error: {e}");
                    break;
                }
            },
            // Local server -> relay
            msg = local_read.next() => match msg {
                Some(Ok(Message::Text(t))) => {
                    if relay_write.send(Message::Text(t)).await.is_err() { break; }
                }
                Some(Ok(Message::Binary(b))) => {
                    if relay_write.send(Message::Binary(b)).await.is_err() { break; }
                }
                Some(Ok(Message::Close(_))) | None => {
                    eprintln!("[spawner] local server closed");
                    break;
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => {
                    eprintln!("[spawner] local server read error: {e}");
                    break;
                }
            },
            _ = &mut stop_rx => {
                eprintln!("[spawner] relay proxy stopped by shutdown");
                break;
            }
        }
    }

    eprintln!("[spawner] relay proxy bridge exited");
}

// ── Server ────────────────────────────────────────────────────────────────────

/// Process #2 — a plain WebSocket echo server.
///
/// This is a stand-in for any real application. It has no knowledge of any
/// relay -- launched directly as the `agent_command` `openshell-supervisor-
/// relay.exe` wraps (see mxc-ws-gateway.toml's `pc_relay_spawner_path`/
/// `pc_relay_target_port`), the same way `OpenClaw`'s gateway is. Runs until
/// killed; there is no cooperative shutdown protocol to implement (the
/// generic spawner just kills its target on shutdown, same as any other
/// wrapped process), so this loops on `listener.accept()` alone.
async fn server() -> anyhow::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", WS_PORT)).await?;
    eprintln!("[server] WebSocket listening on 0.0.0.0:{WS_PORT}");

    let active = Arc::new(AtomicUsize::new(0));

    loop {
        let (stream, addr) = listener.accept().await?;
        let active2 = active.clone();
        active2.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            handle_connection(stream, addr).await;
            active2.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

// ── WebSocket connection handler ──────────────────────────────────────────────

async fn handle_connection(stream: TcpStream, addr: SocketAddr) {
    eprintln!("[server] new connection from {addr}");

    let ws = match tokio_tungstenite::accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            eprintln!("[server] handshake failed from {addr}: {e}");
            return;
        }
    };

    let (mut write, mut read) = ws.split();

    while let Some(msg) = read.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                eprintln!("[server] {addr} recv: {text}");
                if write.send(Message::Text(text)).await.is_err() {
                    break;
                }
            }
            Ok(Message::Binary(bin)) => {
                if write.send(Message::Binary(bin)).await.is_err() {
                    break;
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => {}
            Err(e) => {
                eprintln!("[server] {addr} error: {e}");
                break;
            }
        }
    }

    eprintln!("[server] connection from {addr} ended");
}

// ── proxy-for mode ────────────────────────────────────────────────────────────

/// Start the command listed in `agent-cmd.txt` in the share dir as a child
/// process, wait for it to accept TCP on `port`, then connect outward to the
/// gateway relay and bridge all WebSocket traffic to/from the local server.
///
/// This lets any WebSocket server (e.g. openclaw gateway) be exposed to host
/// clients via the `OpenShell` relay without any changes to that server.
async fn proxy_for(port: u16) -> anyhow::Result<()> {
    // Early sentinel: write to exe_dir so it works in any container directory.
    if let Ok(exe) = std::env::current_exe()
        && let Some(d) = exe.parent()
    {
        let _ = std::fs::write(
            d.join("proxy-for-started.txt"),
            format!("port={port} exe={}", exe.display()),
        );
    }

    let dir = match exe_dir() {
        Ok(d) => d,
        Err(e) => {
            let _ = std::fs::write(
                "C:\\work\\openshell-mxc-openclaw\\proxy-for-error.txt",
                format!("exe_dir failed: {e}"),
            );
            return Err(e);
        }
    };
    let signal = signal_file_path()?;
    let _ = std::fs::remove_file(&signal);
    if let Ok(d) = exe_dir() {
        let _ = std::fs::remove_file(d.join("relay-ready.txt"));
    }

    // Read the command to launch from agent-cmd.txt in the share dir.
    // Each line is one argument; the first line is the executable.
    let cmd_file = dir.join("agent-cmd.txt");
    let mut child = if cmd_file.exists() {
        let lines: Vec<String> = std::fs::read_to_string(&cmd_file)?
            .lines()
            .map(|l| l.trim_start_matches('\u{FEFF}').trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        if lines.is_empty() {
            anyhow::bail!("agent-cmd.txt is empty");
        }
        let stdout_file = std::fs::File::create(dir.join("agent-stdout.txt")).ok();
        let stderr_file = std::fs::File::create(dir.join("agent-stderr.txt")).ok();
        // If agent-env.txt exists in the share dir, set the child process env
        // explicitly (clear parent env, then set only those vars).  This allows
        // running runtimes like node.js that fail with STATUS_DLL_INIT_FAILED
        // when presented with the full host env, while mxc-ws-agent itself
        // (the parent) still runs with the full env it needs.
        // agent-env.txt format: one KEY=VALUE per line.
        let env_file = dir.join("agent-env.txt");
        let mut cmd = tokio::process::Command::new(&lines[0]);
        cmd.args(&lines[1..]);
        if env_file.exists()
            && let Ok(content) = std::fs::read_to_string(&env_file)
        {
            let child_env: Vec<(String, String)> = content
                .lines()
                .map(|l| l.trim_start_matches('\u{FEFF}').trim().to_string())
                .filter(|l| !l.is_empty() && l.contains('='))
                .filter_map(|l| {
                    let pos = l.find('=')?;
                    Some((l[..pos].to_string(), l[pos + 1..].to_string()))
                })
                .collect();
            eprintln!(
                "[proxy-for] using {} child env vars from agent-env.txt",
                child_env.len()
            );
            cmd.env_clear().envs(child_env);
        }
        cmd.stdout(
            stdout_file.map_or_else(std::process::Stdio::inherit, std::process::Stdio::from),
        )
        .stderr(stderr_file.map_or_else(std::process::Stdio::inherit, std::process::Stdio::from));
        eprintln!("[proxy-for] starting: {}", lines.join(" "));
        Some(cmd.spawn()?)
    } else {
        eprintln!("[proxy-for] no agent-cmd.txt; assuming server already running on port {port}");
        None
    };

    // Wait up to 60 s for the server to accept TCP on `port`.
    eprintln!("[proxy-for] waiting for server on 127.0.0.1:{port} ...");
    let deadline = tokio::time::Instant::now() + Duration::from_mins(1);
    loop {
        if TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .is_ok()
        {
            eprintln!("[proxy-for] server is up on port {port}");
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("[proxy-for] timeout waiting for server on port {port}");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        // Also check for early child exit
        if let Some(ref mut c) = child
            && let Ok(Some(status)) = c.try_wait()
        {
            anyhow::bail!("[proxy-for] child exited early: {status}");
        }
    }

    // Connect relay and run bridge.
    let relay_addr_file = dir.join("reverse-relay-addr.txt");
    if let Some(relay_addr) = read_host_file(&relay_addr_file) {
        let relay_url = format!("ws://{relay_addr}");
        let local_url = format!("ws://127.0.0.1:{port}");
        eprintln!("[proxy-for] relay bridge: {relay_url} <-> {local_url}");
        let (bridge_stop_tx, bridge_stop_rx) = oneshot::channel::<()>();
        tokio::spawn(run_relay_proxy(relay_url, local_url, bridge_stop_rx));

        // Main lifecycle: child exit or shutdown signal.
        loop {
            tokio::select! {
                status = async {
                    if let Some(ref mut c) = child { c.wait().await.ok() } else { std::future::pending().await }
                } => {
                    eprintln!("[proxy-for] child exited: {status:?}");
                    let _ = std::fs::remove_file(&signal);
                    break;
                }
                () = tokio::time::sleep(Duration::from_millis(500)) => {
                    if signal.exists() {
                        eprintln!("[proxy-for] shutdown signal -- stopping");
                        let _ = bridge_stop_tx.send(());
                        if let Some(ref mut c) = child { let _ = c.kill().await; let _ = c.wait().await; }
                        let _ = std::fs::remove_file(&signal);
                        break;
                    }
                }
            }
        }
    } else {
        eprintln!("[proxy-for] no reverse-relay-addr.txt; relay bridge disabled");
        // Still manage child lifecycle.
        if let Some(mut c) = child {
            let _ = c.wait().await;
        }
    }
    Ok(())
}
