//! Embedded SSH server for sandbox access.

use crate::policy::SandboxPolicy;
use crate::process::drop_privileges;
use crate::sandbox;
use miette::{IntoDiagnostic, Result};
use nix::pty::{Winsize, openpty};
use nix::unistd::setsid;
use rand_core::OsRng;
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, Handle, Session};
use russh::{ChannelId, CryptoVec};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::process::Command;
use std::sync::{Arc, mpsc};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

const PREFACE_MAGIC: &str = "NSSH1";

pub async fn run_ssh_server(
    listen_addr: SocketAddr,
    policy: SandboxPolicy,
    workdir: Option<String>,
    handshake_secret: String,
    handshake_skew_secs: u64,
    netns_fd: Option<RawFd>,
    proxy_url: Option<String>,
) -> Result<()> {
    let mut rng = OsRng;
    let host_key = PrivateKey::random(&mut rng, Algorithm::Ed25519).into_diagnostic()?;

    let mut config = russh::server::Config {
        auth_rejection_time: std::time::Duration::from_secs(1),
        ..Default::default()
    };
    config.keys.push(host_key);

    let config = Arc::new(config);
    let listener = TcpListener::bind(listen_addr).await.into_diagnostic()?;
    info!(addr = %listen_addr, "SSH server listening");

    loop {
        let (stream, peer) = listener.accept().await.into_diagnostic()?;
        stream.set_nodelay(true).into_diagnostic()?;
        let config = config.clone();
        let policy = policy.clone();
        let workdir = workdir.clone();
        let secret = handshake_secret.clone();
        let proxy_url = proxy_url.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_connection(
                stream,
                peer,
                config,
                policy,
                workdir,
                &secret,
                handshake_skew_secs,
                netns_fd,
                proxy_url,
            )
            .await
            {
                warn!(error = %err, "SSH connection failed");
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
    config: Arc<russh::server::Config>,
    policy: SandboxPolicy,
    workdir: Option<String>,
    secret: &str,
    handshake_skew_secs: u64,
    netns_fd: Option<RawFd>,
    proxy_url: Option<String>,
) -> Result<()> {
    let mut line = String::new();
    read_line(&mut stream, &mut line).await?;
    if !verify_preface(&line, secret, handshake_skew_secs)? {
        let _ = stream.write_all(b"ERR\n").await;
        return Ok(());
    }
    stream.write_all(b"OK\n").await.into_diagnostic()?;
    info!(peer = %peer, "SSH handshake accepted");

    let handler = SshHandler::new(policy, workdir, netns_fd, proxy_url);
    russh::server::run_stream(config, stream, handler)
        .await
        .map_err(|err| miette::miette!("ssh stream error: {err}"))?;
    Ok(())
}

async fn read_line(stream: &mut tokio::net::TcpStream, buf: &mut String) -> Result<()> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let n = stream.read(&mut byte).await.into_diagnostic()?;
        if n == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        bytes.push(byte[0]);
        if bytes.len() > 1024 {
            break;
        }
    }
    *buf = String::from_utf8_lossy(&bytes).to_string();
    Ok(())
}

fn verify_preface(line: &str, secret: &str, handshake_skew_secs: u64) -> Result<bool> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() != 5 || parts[0] != PREFACE_MAGIC {
        return Ok(false);
    }
    let token = parts[1];
    let timestamp: i64 = parts[2].parse().unwrap_or(0);
    let nonce = parts[3];
    let signature = parts[4];

    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .into_diagnostic()?
            .as_secs(),
    )
    .into_diagnostic()?;
    let skew = (now - timestamp).unsigned_abs();
    if skew > handshake_skew_secs {
        return Ok(false);
    }

    let payload = format!("{token}|{timestamp}|{nonce}");
    let expected = hmac_sha256(secret.as_bytes(), payload.as_bytes());
    Ok(signature == expected)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    hex::encode(result)
}

struct SshHandler {
    policy: SandboxPolicy,
    workdir: Option<String>,
    netns_fd: Option<RawFd>,
    proxy_url: Option<String>,
    input_sender: Option<mpsc::Sender<Vec<u8>>>,
    pty_master: Option<std::fs::File>,
    pty_request: Option<PtyRequest>,
}

impl SshHandler {
    fn new(
        policy: SandboxPolicy,
        workdir: Option<String>,
        netns_fd: Option<RawFd>,
        proxy_url: Option<String>,
    ) -> Self {
        Self {
            policy,
            workdir,
            netns_fd,
            proxy_url,
            input_sender: None,
            pty_master: None,
            pty_request: None,
        }
    }
}

impl russh::server::Handler for SshHandler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.pty_request = Some(PtyRequest {
            term: term.to_string(),
            col_width,
            row_height,
            pixel_width: 0,
            pixel_height: 0,
        });
        session.channel_success(channel)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        _channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pixel_width: u32,
        pixel_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(master) = self.pty_master.as_ref() {
            let winsize = Winsize {
                ws_row: to_u16(row_height.max(1)),
                ws_col: to_u16(col_width.max(1)),
                ws_xpixel: to_u16(pixel_width),
                ws_ypixel: to_u16(pixel_height),
            };
            let _ = unsafe_pty::set_winsize(master.as_raw_fd(), winsize);
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        self.start_shell(channel, session.handle(), None)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let command = String::from_utf8_lossy(data).trim().to_string();
        if command.is_empty() {
            return Ok(());
        }
        self.start_shell(channel, session.handle(), Some(command))?;
        Ok(())
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(sender) = self.input_sender.as_ref() {
            let _ = sender.send(data.to_vec());
        }
        Ok(())
    }
}

impl SshHandler {
    fn start_shell(
        &mut self,
        channel: ChannelId,
        handle: Handle,
        command: Option<String>,
    ) -> anyhow::Result<()> {
        let pty = self.pty_request.take().unwrap_or_default();
        let (pty_master, input_sender) = spawn_pty_shell(
            &self.policy,
            self.workdir.clone(),
            command,
            &pty,
            handle,
            channel,
            self.netns_fd,
            self.proxy_url.clone(),
        )?;
        self.pty_master = Some(pty_master);
        self.input_sender = Some(input_sender);
        Ok(())
    }
}

#[derive(Clone)]
struct PtyRequest {
    term: String,
    col_width: u32,
    row_height: u32,
    pixel_width: u32,
    pixel_height: u32,
}

impl Default for PtyRequest {
    fn default() -> Self {
        Self {
            term: "xterm-256color".to_string(),
            col_width: 80,
            row_height: 24,
            pixel_width: 0,
            pixel_height: 0,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_pty_shell(
    policy: &SandboxPolicy,
    workdir: Option<String>,
    command: Option<String>,
    pty: &PtyRequest,
    handle: Handle,
    channel: ChannelId,
    netns_fd: Option<RawFd>,
    proxy_url: Option<String>,
) -> anyhow::Result<(std::fs::File, mpsc::Sender<Vec<u8>>)> {
    let winsize = Winsize {
        ws_row: to_u16(pty.row_height.max(1)),
        ws_col: to_u16(pty.col_width.max(1)),
        ws_xpixel: to_u16(pty.pixel_width),
        ws_ypixel: to_u16(pty.pixel_height),
    };
    let openpty = openpty(Some(&winsize), None)?;
    let master = std::fs::File::from(openpty.master);
    let slave = std::fs::File::from(openpty.slave);
    let slave_fd = slave.as_raw_fd();

    let stdin = slave.try_clone()?;
    let stdout = slave.try_clone()?;
    let stderr = slave;
    let mut reader = master.try_clone()?;
    let mut writer = master.try_clone()?;

    let mut cmd = command.map_or_else(
        || {
            let mut c = Command::new("/bin/bash");
            c.arg("-i");
            c
        },
        |command| {
            let mut c = Command::new("/bin/bash");
            c.arg("-lc").arg(command);
            c
        },
    );

    let term = if pty.term.is_empty() {
        "xterm-256color"
    } else {
        pty.term.as_str()
    };

    cmd.stdin(stdin)
        .stdout(stdout)
        .stderr(stderr)
        .env("NAVIGATOR_SANDBOX", "1")
        .env("HOME", "/sandbox")
        .env("USER", "sandbox")
        .env("TERM", term);

    // Set proxy environment variables so cooperative tools (curl, wget, etc.)
    // route traffic through the CONNECT proxy for OPA policy evaluation.
    // Both uppercase and lowercase variants are needed: curl/wget use uppercase,
    // gRPC C-core (libgrpc) checks lowercase http_proxy/https_proxy first.
    if let Some(ref url) = proxy_url {
        cmd.env("HTTP_PROXY", url)
            .env("HTTPS_PROXY", url)
            .env("ALL_PROXY", url)
            .env("http_proxy", url)
            .env("https_proxy", url)
            .env("grpc_proxy", url);
    }

    if let Some(dir) = workdir.as_deref() {
        cmd.current_dir(dir);
    }

    #[cfg(unix)]
    {
        unsafe_pty::install_pre_exec(
            &mut cmd,
            policy.clone(),
            workdir.clone(),
            slave_fd,
            netns_fd,
        );
    }

    let mut child = cmd.spawn()?;
    let master_file = master;

    let (sender, receiver) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        while let Ok(bytes) = receiver.recv() {
            if writer.write_all(&bytes).is_err() {
                break;
            }
            let _ = writer.flush();
        }
    });

    let runtime = tokio::runtime::Handle::current();
    let runtime_reader = runtime.clone();
    let handle_clone = handle.clone();
    // Signal from the reader thread to the exit thread that all output has
    // been forwarded.  The exit thread waits for this before sending the
    // exit-status and closing the channel, ensuring the correct SSH protocol
    // ordering: data → EOF → exit-status → close.
    let (reader_done_tx, reader_done_rx) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let data = CryptoVec::from_slice(&buf[..n]);
                    let handle_clone = handle_clone.clone();
                    drop(runtime_reader.spawn(async move {
                        let _ = handle_clone.data(channel, data).await;
                    }));
                }
            }
        }
        // Send EOF to indicate no more data will be sent on this channel.
        let eof_handle = handle_clone.clone();
        drop(runtime_reader.spawn(async move {
            let _ = eof_handle.eof(channel).await;
        }));
        // Notify the exit thread that all output has been forwarded.
        let _ = reader_done_tx.send(());
    });

    let handle_exit = handle;
    let runtime_exit = runtime;
    std::thread::spawn(move || {
        let status = child.wait().ok();
        let code = status.and_then(|s| s.code()).unwrap_or(1).unsigned_abs();
        // Wait for the reader thread to finish forwarding all output before
        // sending exit-status and closing the channel.  This prevents the
        // race where close() was called before exit_status_request().
        let _ = reader_done_rx.recv();
        drop(runtime_exit.spawn(async move {
            let _ = handle_exit.exit_status_request(channel, code).await;
            let _ = handle_exit.close(channel).await;
        }));
    });

    Ok((master_file, sender))
}

mod unsafe_pty {
    use super::{Command, RawFd, SandboxPolicy, Winsize, drop_privileges, sandbox, setsid};
    #[cfg(unix)]
    use std::os::unix::process::CommandExt;

    #[allow(unsafe_code)]
    pub fn set_winsize(fd: RawFd, winsize: Winsize) -> std::io::Result<()> {
        let rc = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, winsize) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    fn set_controlling_tty(fd: RawFd) -> std::io::Result<()> {
        let rc = unsafe { libc::ioctl(fd, libc::TIOCSCTTY.into(), 0) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    pub fn install_pre_exec(
        cmd: &mut Command,
        policy: SandboxPolicy,
        workdir: Option<String>,
        slave_fd: RawFd,
        netns_fd: Option<RawFd>,
    ) {
        unsafe {
            cmd.pre_exec(move || {
                setsid().map_err(|err| std::io::Error::other(err.to_string()))?;
                set_controlling_tty(slave_fd)?;

                // Enter network namespace before dropping privileges.
                // This ensures SSH shell processes are isolated to the same
                // network namespace as the entrypoint, forcing all traffic
                // through the veth pair and CONNECT proxy.
                #[cfg(target_os = "linux")]
                if let Some(fd) = netns_fd {
                    let result = libc::setns(fd, libc::CLONE_NEWNET);
                    if result != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }

                #[cfg(not(target_os = "linux"))]
                let _ = netns_fd;

                // Drop privileges before applying sandbox restrictions.
                // initgroups/setgid/setuid need access to /etc/group and /etc/passwd
                // which may be blocked by Landlock.
                drop_privileges(&policy).map_err(|err| std::io::Error::other(err.to_string()))?;
                sandbox::apply(&policy, workdir.as_deref())
                    .map_err(|err| std::io::Error::other(err.to_string()))?;
                Ok(())
            });
        }
    }
}

fn to_u16(value: u32) -> u16 {
    u16::try_from(value.min(u32::from(u16::MAX))).unwrap_or(u16::MAX)
}
