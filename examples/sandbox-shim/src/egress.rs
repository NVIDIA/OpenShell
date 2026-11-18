// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Guest-local HTTP CONNECT proxy. The guest has no network route, so this is
//! the only egress path. Every tunnel is resolved through supervisor policy
//! DNS and opened only after the supervisor's TCP open decision.
use crate::{dns, protocol::boundary};
use anyhow::{Context, Result, bail};
use openshell_binary_identity::ProcfsIdentityResolver;
use openshell_isolation_interface::contract::{BinaryIdentity, ResolveError};
use openshell_sandbox_backend::boundary_protocol::NetworkModeWire;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc, oneshot, watch},
};

const MAX_HEAD: usize = 16 * 1024;
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);
const HANDOFF_TIMEOUT: Duration = Duration::from_secs(30);
const DNS_TIMEOUT: Duration = Duration::from_secs(15);

pub type Identity = Result<BinaryIdentity, ResolveError>;

/// A tunnel waiting for the supervisor to accept and decide it.
pub struct PendingOpen {
    pub identity: Identity,
    pub destination: SocketAddr,
    pub client: TcpStream,
    /// Bytes the client sent after the CONNECT header.
    pub early: Vec<u8>,
}

pub struct DnsRequest {
    pub message: Vec<u8>,
    pub identity: boundary::BinaryIdentity,
    pub reply: oneshot::Sender<Result<Vec<u8>, String>>,
}

pub struct Egress {
    opens_tx: mpsc::Sender<PendingOpen>,
    pub opens: Mutex<mpsc::Receiver<PendingOpen>>,
    dns_tx: mpsc::Sender<DnsRequest>,
    pub dns: Mutex<mpsc::Receiver<DnsRequest>>,
    /// Network mode bound at Attach; `None` until then.
    pub mode: watch::Sender<Option<NetworkModeWire>>,
    resolver: ProcfsIdentityResolver,
    next_dns_id: AtomicU16,
}

impl Default for Egress {
    fn default() -> Self {
        let (opens_tx, opens) = mpsc::channel(64);
        let (dns_tx, dns) = mpsc::channel(64);
        Self {
            opens_tx,
            opens: Mutex::new(opens),
            dns_tx,
            dns: Mutex::new(dns),
            mode: watch::channel(None).0,
            resolver: ProcfsIdentityResolver::for_pid_namespace(),
            next_dns_id: AtomicU16::new(1),
        }
    }
}

async fn respond(client: &mut TcpStream, status: &str, reason: &str) {
    let body = format!("{reason}\n");
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = client.write_all(response.as_bytes()).await;
    let _ = client.shutdown().await;
}

pub async fn deny(mut client: TcpStream, reason: &str) {
    respond(&mut client, "403 Forbidden", reason).await;
}

impl Egress {
    pub async fn serve(self: std::sync::Arc<Self>, address: &str) -> Result<()> {
        let listener = TcpListener::bind(address)
            .await
            .with_context(|| format!("bind egress proxy {address}"))?;
        loop {
            let (stream, peer) = listener.accept().await?;
            openshell_core::net::set_tcp_nodelay_best_effort(&stream);
            let egress = self.clone();
            tokio::spawn(async move {
                if let Err(error) = egress.handle(stream, peer).await {
                    eprintln!("sandbox-shim: egress {peer}: {error:#}");
                }
            });
        }
    }

    async fn handle(&self, mut client: TcpStream, peer: SocketAddr) -> Result<()> {
        let (head, early) = match tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut client)).await {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => {
                respond(&mut client, "400 Bad Request", "malformed proxy request").await;
                return Err(error);
            }
            Err(_) => return Ok(()),
        };
        let (host, port) = match parse_connect(&head) {
            Ok(target) => target,
            Err(error) => {
                respond(
                    &mut client,
                    "501 Not Implemented",
                    "this sandbox proxy supports only HTTP CONNECT tunnels",
                )
                .await;
                return Err(error);
            }
        };
        let mode = *self.mode.borrow();
        match mode {
            Some(NetworkModeWire::Proxy) => {}
            _ => {
                deny(client, "network access is disabled by sandbox policy").await;
                bail!("denied {host}:{port}: policy network mode is not proxy");
            }
        }
        let identity = {
            let resolver = self.resolver.clone();
            tokio::task::spawn_blocking(move || peer_identity(&resolver, peer)).await?
        };
        let address = match host.parse::<IpAddr>() {
            Ok(address) => address,
            Err(_) => match self.resolve(&host, &identity).await {
                Ok(address) => address,
                Err(error) => {
                    respond(
                        &mut client,
                        "502 Bad Gateway",
                        "name resolution denied or failed",
                    )
                    .await;
                    bail!("resolve {host}: {error:#}");
                }
            },
        };
        let open = PendingOpen {
            identity,
            destination: SocketAddr::new(address, port),
            client,
            early,
        };
        match self.opens_tx.send_timeout(open, HANDOFF_TIMEOUT).await {
            Ok(()) => Ok(()),
            Err(error) => {
                let open = match error {
                    mpsc::error::SendTimeoutError::Timeout(open)
                    | mpsc::error::SendTimeoutError::Closed(open) => open,
                };
                let mut client = open.client;
                respond(
                    &mut client,
                    "503 Service Unavailable",
                    "supervisor mediation unavailable",
                )
                .await;
                bail!("no supervisor accepted {host}:{port}")
            }
        }
    }

    /// Resolve through the supervisor's policy DNS on the Mediate stream.
    async fn resolve(&self, host: &str, identity: &Identity) -> Result<IpAddr> {
        let mut last_error = None;
        for qtype in [dns::TYPE_A, dns::TYPE_AAAA] {
            let id = self.next_dns_id.fetch_add(1, Ordering::Relaxed);
            let (reply, response) = oneshot::channel();
            self.dns_tx
                .send(DnsRequest {
                    message: dns::query(id, host, qtype)?,
                    identity: crate::protocol::binary_identity(identity),
                    reply,
                })
                .await
                .map_err(|_| anyhow::anyhow!("DNS mediation closed"))?;
            let response = tokio::time::timeout(DNS_TIMEOUT, response)
                .await
                .context("DNS mediation timed out")?
                .context("DNS mediation dropped")?
                .map_err(|error| anyhow::anyhow!(error))?;
            match dns::answers(&response, id) {
                Ok(addresses) if !addresses.is_empty() => return Ok(addresses[0]),
                Ok(_) => last_error = Some(anyhow::anyhow!("no address records")),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no address records")))
    }
}

async fn read_head(client: &mut TcpStream) -> Result<(String, Vec<u8>)> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        let read = client.read(&mut chunk).await?;
        if read == 0 {
            bail!("client closed before request header");
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            let early = buffer[end + 4..].to_vec();
            let head = String::from_utf8(buffer[..end].to_vec()).context("non-UTF-8 header")?;
            return Ok((head, early));
        }
        if buffer.len() > MAX_HEAD {
            bail!("request header too large");
        }
    }
}

/// Parse `CONNECT host:port HTTP/1.x`.
pub fn parse_connect(head: &str) -> Result<(String, u16)> {
    let line = head.lines().next().unwrap_or_default();
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        bail!("malformed request line");
    };
    if method != "CONNECT" || !version.starts_with("HTTP/1.") {
        bail!("unsupported proxy method {method}");
    }
    let (host, port) = if let Some(rest) = target.strip_prefix('[') {
        let (host, port) = rest.split_once("]:").context("malformed IPv6 authority")?;
        (host, port)
    } else {
        target
            .rsplit_once(':')
            .context("CONNECT target needs a port")?
    };
    let port: u16 = port.parse().context("invalid port")?;
    if host.is_empty() || port == 0 {
        bail!("invalid CONNECT target");
    }
    Ok((host.to_ascii_lowercase(), port))
}

/// Executable identity of the guest process holding the proxy client socket.
/// Failure is reported as such; the supervisor then denies the open.
fn peer_identity(resolver: &ProcfsIdentityResolver, peer: SocketAddr) -> Identity {
    let failed = |message: String| ResolveError::Failed(message);
    let inode = socket_inode(peer).map_err(|error| failed(format!("{error:#}")))?;
    let owners = socket_owners(inode);
    match owners.as_slice() {
        [pid] => resolver.resolve(*pid).map(workload_view),
        [] => Err(failed("no process holds the proxy client socket".into())),
        _ => Err(failed(
            "the proxy client socket is shared by several processes".into(),
        )),
    }
}

/// The shim reads `/proc/<pid>/exe` from its own root, where workload files
/// appear under the workload rootfs mount. Report the path the workload uses.
/// Shim-side ancestors (the shim itself) keep their shim-root paths.
fn workload_view(mut identity: BinaryIdentity) -> BinaryIdentity {
    let strip = |path: &mut std::path::PathBuf| {
        if let Ok(inner) = path.strip_prefix(crate::launch::WORKLOAD_ROOT) {
            *path = std::path::Path::new("/").join(inner);
        }
    };
    strip(&mut identity.executable.path);
    for ancestor in &mut identity.ancestors {
        strip(&mut ancestor.path);
    }
    identity
}

fn socket_inode(peer: SocketAddr) -> Result<u64> {
    let SocketAddr::V4(peer) = peer else {
        bail!("proxy peer is not IPv4 loopback");
    };
    let table = std::fs::read_to_string("/proc/net/tcp").context("read /proc/net/tcp")?;
    let proxy_port = crate::launch::PROXY_ADDR
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .expect("valid proxy address");
    find_inode(&table, *peer.ip(), peer.port(), proxy_port)
        .context("proxy client socket is not in /proc/net/tcp")
}

pub fn find_inode(table: &str, ip: Ipv4Addr, port: u16, remote_port: u16) -> Option<u64> {
    let local = format!("{:08X}:{port:04X}", u32::from_le_bytes(ip.octets()));
    let remote = format!(
        "{:08X}:{remote_port:04X}",
        u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets())
    );
    table.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        (fields.len() > 9
            && fields[1].eq_ignore_ascii_case(&local)
            && fields[2].eq_ignore_ascii_case(&remote))
        .then(|| fields[9].parse().ok())
        .flatten()
    })
}

fn socket_owners(inode: u64) -> Vec<u32> {
    let target = format!("socket:[{inode}]");
    let me = std::process::id();
    let mut owners = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return owners;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == me {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        if fds.flatten().any(|fd| {
            std::fs::read_link(fd.path()).is_ok_and(|link| link.as_os_str() == target.as_str())
        }) {
            owners.push(pid);
        }
    }
    owners
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_workload_paths() {
        use openshell_isolation_interface::contract::ExecutableIdentity;
        let exe = |path: &str| ExecutableIdentity {
            path: path.into(),
            digest: None,
        };
        let identity = workload_view(BinaryIdentity {
            executable: exe("/run/openshell/workload/usr/bin/curl"),
            ancestors: vec![exe("/run/openshell/workload/usr/bin/bash"), exe("/init")],
            cmdline_paths: vec![],
        });
        assert_eq!(
            identity.executable.path,
            std::path::Path::new("/usr/bin/curl")
        );
        assert_eq!(
            identity.ancestors[0].path,
            std::path::Path::new("/usr/bin/bash")
        );
        assert_eq!(identity.ancestors[1].path, std::path::Path::new("/init"));
    }

    #[test]
    fn parses_connect_targets() {
        assert_eq!(
            parse_connect("CONNECT Example.com:443 HTTP/1.1\r\nHost: x").unwrap(),
            ("example.com".into(), 443)
        );
        assert_eq!(
            parse_connect("CONNECT [::1]:8443 HTTP/1.1").unwrap(),
            ("::1".into(), 8443)
        );
        assert!(parse_connect("GET http://example.com/ HTTP/1.1").is_err());
        assert!(parse_connect("CONNECT example.com HTTP/1.1").is_err());
        assert!(parse_connect("CONNECT example.com:0 HTTP/1.1").is_err());
    }

    #[test]
    fn finds_loopback_socket_inode() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0C38 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0 100 0 0 10 0\n   1: 0100007F:D2A4 0100007F:0C38 01 00000000:00000000 00:00000000 00000000 10001        0 4242 1 0 20 4 30 10 -1\n";
        assert_eq!(
            find_inode(table, Ipv4Addr::LOCALHOST, 0xD2A4, 3128),
            Some(4242)
        );
        assert_eq!(find_inode(table, Ipv4Addr::LOCALHOST, 0xD2A5, 3128), None);
    }
}
