// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Proxy-peer helper started by the OpenShell MXC driver under a per-sandbox
//! `AppContainer` profile (the sandbox's `processContainer.network.
//! allowedProxyPeer`). See `src/peer.rs` in this crate for the architecture and
//! the control protocol; this process is the other side of it.
//!
//! Usage: `openshell-mxc-peer.exe <token> <egress|none> [log-file]`
//!
//! 1. Bind a proxy listener on `127.0.0.1:0`. It is the sandbox's
//!    `networkProxy` endpoint. In `egress` mode every connection the sandbox
//!    opens to it is tunnelled, byte for byte, through the gateway's
//!    `<prefix>-egress` pipe to the sandbox's host egress proxy, which applies
//!    the OpenShell network policy. In `none` mode (no egress policy) every
//!    request gets `403 Forbidden`, so the sandbox has no network egress.
//! 2. Connect to the gateway's control pipe and send `READY <proxy-port>`.
//! 3. For every `OPEN <id> <target-port>` line, connect to the data pipe for
//!    `<id>`, dial `127.0.0.1:<target-port>` (admitted because this process
//!    runs as the sandbox's peer identity), report `OK` or `ERR <message>` and
//!    pump bytes in both directions.
//!
//! The process exits when the control pipe closes.

#[cfg(not(windows))]
fn main() {
    eprintln!("openshell-mxc-peer is only supported on Windows");
    std::process::exit(2);
}

#[cfg(windows)]
mod imp {
    use std::io::Write;
    use std::sync::Mutex;
    use std::time::Duration;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ClientOptions;
    use tokio::net::{TcpListener, TcpStream};

    static LOG: Mutex<Option<std::fs::File>> = Mutex::new(None);

    fn log(message: &str) {
        if let Ok(mut guard) = LOG.lock() {
            if let Some(file) = guard.as_mut() {
                let _ = writeln!(file, "{message}");
            }
        }
    }

    fn ctl_pipe_name(token: &str) -> String {
        format!(r"\\.\pipe\openshell-mxc-{token}-ctl")
    }

    fn data_pipe_name(token: &str, id: u64) -> String {
        format!(r"\\.\pipe\openshell-mxc-{token}-d{id}")
    }

    fn egress_pipe_name(token: &str) -> String {
        format!(r"\\.\pipe\openshell-mxc-{token}-egress")
    }

    /// `ERROR_PIPE_BUSY`: every instance is connected; the gateway is creating the
    /// next one, so retry shortly.
    const ERROR_PIPE_BUSY: i32 = 231;

    async fn open_egress_pipe(
        token: &str,
    ) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
        let name = egress_pipe_name(token);
        let mut attempts = 0;
        loop {
            match ClientOptions::new().open(&name) {
                Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempts < 250 => {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                other => return other,
            }
        }
    }

    /// Tunnel one sandbox connection to the gateway's host egress proxy.
    async fn tunnel_egress(token: String, mut tcp: TcpStream) {
        let mut pipe = match open_egress_pipe(&token).await {
            Ok(pipe) => pipe,
            Err(error) => {
                log(&format!("egress pipe open failed: {error}"));
                let _ = tcp
                    .write_all(
                        b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                return;
            }
        };
        // Tell the gateway which sandbox socket this is, so the host proxy can
        // resolve the real client process (see `ForwardedClients` in the driver).
        let client_port = tcp.peer_addr().map_or(0, |addr| addr.port());
        if pipe
            .write_all(format!("CLIENT {client_port}\n").as_bytes())
            .await
            .is_err()
        {
            return;
        }
        match tokio::io::copy_bidirectional(&mut tcp, &mut pipe).await {
            Ok((from_sandbox, to_sandbox)) => log(&format!(
                "egress done: {from_sandbox} bytes sandbox->gateway, {to_sandbox} bytes gateway->sandbox"
            )),
            Err(error) => log(&format!("egress tunnel ended: {error}")),
        }
    }

    /// Parse `OPEN <id> <port>`.
    fn parse_open(line: &str) -> Option<(u64, u16)> {
        let mut parts = line.strip_prefix("OPEN ")?.split_whitespace();
        let id = parts.next()?.parse().ok()?;
        let port = parts.next()?.parse().ok()?;
        parts.next().is_none().then_some((id, port))
    }

    async fn serve_proxy(listener: TcpListener, token: String, egress: bool) {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            if egress {
                let _ = stream.set_nodelay(true);
                tokio::spawn(tunnel_egress(token.clone(), stream));
                continue;
            }
            tokio::spawn(async move {
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            });
        }
    }

    async fn handle_open(token: String, id: u64, port: u16) {
        let mut pipe = match ClientOptions::new().open(data_pipe_name(&token, id)) {
            Ok(pipe) => pipe,
            Err(error) => {
                log(&format!("[{id}] data pipe open failed: {error}"));
                return;
            }
        };
        let dial = tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(("127.0.0.1", port)),
        )
        .await;
        let mut tcp = match dial {
            Ok(Ok(tcp)) => tcp,
            Ok(Err(error)) => {
                log(&format!("[{id}] dial 127.0.0.1:{port} failed: {error}"));
                let _ = pipe.write_all(format!("ERR {error}\n").as_bytes()).await;
                return;
            }
            Err(_) => {
                log(&format!("[{id}] dial 127.0.0.1:{port} timed out"));
                let _ = pipe.write_all(b"ERR connect timed out\n").await;
                return;
            }
        };
        let _ = tcp.set_nodelay(true);
        if pipe.write_all(b"OK\n").await.is_err() {
            return;
        }
        log(&format!("[{id}] relaying to 127.0.0.1:{port}"));
        match tokio::io::copy_bidirectional(&mut pipe, &mut tcp).await {
            Ok((to_target, from_target)) => log(&format!(
                "[{id}] done: {to_target} bytes pipe->tcp, {from_target} bytes tcp->pipe"
            )),
            Err(error) => log(&format!("[{id}] relay ended: {error}")),
        }
    }

    pub async fn run() -> i32 {
        let mut args = std::env::args().skip(1);
        let (Some(token), Some(mode)) = (args.next(), args.next()) else {
            eprintln!("usage: openshell-mxc-peer <token> <egress|none> [log-file]");
            return 2;
        };
        let egress = match mode.as_str() {
            "egress" => true,
            "none" => false,
            other => {
                eprintln!("unknown mode '{other}' (expected egress or none)");
                return 2;
            }
        };
        if let Some(path) = args.next() {
            if let Ok(file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                if let Ok(mut guard) = LOG.lock() {
                    *guard = Some(file);
                }
            }
        }

        let proxy = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => {
                log(&format!("proxy bind failed: {error}"));
                return 1;
            }
        };
        let proxy_port = proxy.local_addr().map(|addr| addr.port()).unwrap_or(0);
        tokio::spawn(serve_proxy(proxy, token.clone(), egress));

        let mut control = None;
        for _ in 0..100 {
            match ClientOptions::new().open(ctl_pipe_name(&token)) {
                Ok(pipe) => {
                    control = Some(pipe);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
        let Some(mut control) = control else {
            log("control pipe unavailable");
            return 1;
        };
        if control
            .write_all(format!("READY {proxy_port}\n").as_bytes())
            .await
            .is_err()
        {
            return 1;
        }
        log(&format!("ready: proxy 127.0.0.1:{proxy_port} (egress tunnel: {egress})"));

        let mut lines = BufReader::new(control).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            match parse_open(&line) {
                Some((id, port)) => {
                    tokio::spawn(handle_open(token.clone(), id, port));
                }
                None => log(&format!("ignoring malformed control line: {line}")),
            }
        }
        log("control pipe closed; exiting");
        0
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn open_lines_parse_strictly() {
            assert_eq!(parse_open("OPEN 3 18889"), Some((3, 18889)));
            assert_eq!(parse_open("OPEN 3"), None);
            assert_eq!(parse_open("OPEN 3 70000"), None);
            assert_eq!(parse_open("OPEN 3 1 extra"), None);
            assert_eq!(parse_open("READY 1"), None);
        }

        #[test]
        fn pipe_names_match_the_driver() {
            assert_eq!(ctl_pipe_name("t"), r"\\.\pipe\openshell-mxc-t-ctl");
            assert_eq!(data_pipe_name("t", 9), r"\\.\pipe\openshell-mxc-t-d9");
            assert_eq!(egress_pipe_name("t"), r"\\.\pipe\openshell-mxc-t-egress");
        }
    }
}

#[cfg(windows)]
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    std::process::exit(imp::run().await);
}
