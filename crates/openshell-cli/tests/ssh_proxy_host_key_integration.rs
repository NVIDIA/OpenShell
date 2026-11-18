// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use openshell_core::proto::{
    CreateSshSessionResponse, Sandbox, SandboxResponse, TcpForwardFrame, tcp_forward_frame,
};
use prost::Message;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::{HashAlg, PrivateKey};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Output, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_stream::wrappers::ReceiverStream;

const SANDBOX: &str = "my-sb";
const WORKSPACE: &str = "team-a";
const ALLOW_UNVERIFIED: &str = "OPENSHELL_SSH_ALLOW_UNVERIFIED_HOST_KEY";
const PIN_HEADER: &str =
    "# Managed by OpenShell. Rewritten from the gateway-published fingerprint; do not edit.\n";

type GrpcFrames = tokio::sync::mpsc::Sender<Result<Frame<Bytes>, Infallible>>;
type GrpcBody = StreamBody<ReceiverStream<Result<Frame<Bytes>, Infallible>>>;

fn host_key(seed: u8) -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
}

fn fingerprint(key: &PrivateKey) -> String {
    key.public_key().fingerprint(HashAlg::Sha256).to_string()
}

/// The pin file `ssh-proxy` leaves behind: holding `key`, or no key at all.
fn pin_content(key: Option<&PrivateKey>) -> String {
    key.map_or_else(
        || PIN_HEADER.to_string(),
        |key| {
            format!(
                "{PIN_HEADER}openshell-{SANDBOX}.{WORKSPACE} {}\n",
                key.public_key().to_openssh().unwrap()
            )
        },
    )
}

/// A gateway that publishes one host-key fingerprint for the sandbox and
/// relays every SSH connection to `sandbox`.
struct Gateway {
    published: String,
    sandbox: Box<dyn Fn(DuplexStream) + Send + Sync>,
}

impl Gateway {
    async fn serve(self) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let gateway = Arc::new(self);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                openshell_core::net::set_tcp_nodelay_best_effort(&socket);
                let gateway = gateway.clone();
                let service = service_fn(move |request| {
                    let gateway = gateway.clone();
                    async move { Ok::<_, Infallible>(gateway.respond(request, address).await) }
                });
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(socket), service)
                        .await;
                });
            }
        });
        address
    }

    async fn respond(
        &self,
        request: hyper::Request<Incoming>,
        address: SocketAddr,
    ) -> hyper::Response<GrpcBody> {
        let (frames, body) = tokio::sync::mpsc::channel(16);
        match request.uri().path() {
            "/openshell.v1.OpenShell/GetSandbox" => {
                let found = SandboxResponse {
                    sandbox: Some(Sandbox::default()),
                    ..Default::default()
                };
                respond_once(&frames, &found).await;
            }
            "/openshell.v1.OpenShell/CreateSshSession" => {
                let session = CreateSshSessionResponse {
                    sandbox_id: "sandbox-1".to_string(),
                    token: "test-token".to_string(),
                    gateway_host: address.ip().to_string(),
                    gateway_port: u32::from(address.port()),
                    gateway_scheme: "http".to_string(),
                    host_key_fingerprint: self.published.clone(),
                    ..Default::default()
                };
                respond_once(&frames, &session).await;
            }
            "/openshell.v1.OpenShell/ForwardTcp" => {
                let (relay_end, sandbox_end) = tokio::io::duplex(64 * 1024);
                (self.sandbox)(sandbox_end);
                tokio::spawn(relay(request.into_body(), relay_end, frames));
            }
            _ => {}
        }
        let mut response = hyper::Response::new(StreamBody::new(ReceiverStream::new(body)));
        response
            .headers_mut()
            .insert("content-type", "application/grpc".parse().unwrap());
        response
    }
}

fn grpc_message(message: &impl Message) -> Frame<Bytes> {
    let encoded = message.encode_to_vec();
    let mut framed = vec![0];
    framed.extend_from_slice(&u32::try_from(encoded.len()).unwrap().to_be_bytes());
    framed.extend_from_slice(&encoded);
    Frame::data(framed.into())
}

fn grpc_status(status: tonic::Status) -> Frame<Bytes> {
    Frame::trailers(status.into_http::<()>().into_parts().0.headers)
}

async fn respond_once(frames: &GrpcFrames, message: &impl Message) {
    let _ = frames.send(Ok(grpc_message(message))).await;
    let _ = frames.send(Ok(grpc_status(tonic::Status::ok("")))).await;
}

/// Copies `ForwardTcp` data frames to the sandbox and the sandbox's bytes back.
async fn relay(mut inbound: Incoming, sandbox: DuplexStream, frames: GrpcFrames) {
    let (mut from_sandbox, mut to_sandbox) = tokio::io::split(sandbox);
    let to_sandbox = tokio::spawn(async move {
        let mut pending = Vec::new();
        while let Some(Ok(frame)) = inbound.frame().await {
            let Ok(data) = frame.into_data() else {
                continue;
            };
            pending.extend_from_slice(&data);
            while let Some(length) = pending
                .get(1..5)
                .map(|length| u32::from_be_bytes(length.try_into().unwrap()) as usize)
                .filter(|length| pending.len() >= 5 + length)
            {
                let frame = TcpForwardFrame::decode(&pending[5..5 + length]).unwrap();
                pending.drain(..5 + length);
                if let Some(tcp_forward_frame::Payload::Data(data)) = frame.payload
                    && to_sandbox.write_all(&data).await.is_err()
                {
                    return;
                }
            }
        }
        let _ = to_sandbox.shutdown().await;
    });
    // Smaller than any key exchange packet, so the proxy has to reassemble
    // each one.
    let mut chunk = [0_u8; 97];
    while let Ok(read @ 1..) = from_sandbox.read(&mut chunk).await {
        let frame = TcpForwardFrame {
            payload: Some(tcp_forward_frame::Payload::Data(chunk[..read].to_vec())),
        };
        if frames.send(Ok(grpc_message(&frame))).await.is_err() {
            break;
        }
    }
    let _ = frames.send(Ok(grpc_status(tonic::Status::ok("")))).await;
    to_sandbox.abort();
}

/// The `ssh-proxy` arguments of a generated config entry.
fn name_mode(gateway: SocketAddr, known_hosts: &Path) -> String {
    let known_hosts = known_hosts.display();
    format!("{} --known-hosts {known_hosts}", old_name_mode(gateway))
}

/// The same, as releases before host-key verification generated them.
fn old_name_mode(gateway: SocketAddr) -> String {
    format!("ssh-proxy --server http://{gateway} --name {SANDBOX} --workspace {WORKSPACE}")
}

/// Runs `command` to completion. `allow_unverified` is the value of the
/// variable that permits a sandbox with no published fingerprint.
async fn finished(
    mut command: tokio::process::Command,
    config: &Path,
    allow_unverified: Option<&str>,
) -> Output {
    match allow_unverified {
        Some(value) => command.env(ALLOW_UNVERIFIED, value),
        None => command.env_remove(ALLOW_UNVERIFIED),
    };
    let run = command
        .env("XDG_CONFIG_HOME", config)
        .env("OPENSHELL_TELEMETRY_ENABLED", "false")
        .env_remove("OPENSHELL_GATEWAY")
        .env_remove("OPENSHELL_GATEWAY_ENDPOINT")
        .env_remove("OPENSHELL_WORKSPACE")
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output();
    tokio::time::timeout(Duration::from_secs(30), run)
        .await
        .expect("the command must exit")
        .unwrap()
}

/// Runs `openshell` with `args`, which are separated by single spaces.
async fn openshell(args: &str, config: &Path, allow_unverified: Option<&str>) -> Output {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_openshell"));
    command.args(args.split(' '));
    finished(command, config, allow_unverified).await
}

fn mismatch_message(published: &PrivateKey, presented: &PrivateKey) -> String {
    format!(
        "openshell: SSH host key mismatch for sandbox '{SANDBOX}' (workspace '{WORKSPACE}')\n  \
         gateway published: {}\n  \
         server presented:  {}\n\
         The SSH server reached through the gateway is not this sandbox's. The handshake was not forwarded.\n\
         Do not connect. Compare the published value with `openshell --workspace {WORKSPACE} sandbox get {SANDBOX} --output json`, then stop and start the sandbox.\n\
         If the mismatch persists, contact the gateway operator.\n",
        fingerprint(published),
        fingerprint(presented)
    )
}

/// What an SSH server presenting `key` sends: up to its key exchange reply,
/// then from the reply to its first encrypted bytes. The proxy does not check
/// block alignment, so every packet has four bytes of padding.
fn handshake(key: &PrivateKey) -> [Vec<u8>; 2] {
    let packet = |payload: &[u8]| {
        let length = u32::try_from(payload.len() + 5).unwrap().to_be_bytes();
        [&length[..], &[4], payload, &[0; 4]].concat()
    };
    let key = key.public_key().to_bytes().unwrap();
    let key_length = u32::try_from(key.len()).unwrap().to_be_bytes();
    let reply = [&[31][..], &key_length, &key, &[0; 127]].concat();
    [
        [
            &b"SSH-2.0-OpenShell_test\r\n"[..],
            &packet(&[&[20][..], &[0; 61]].concat()),
        ]
        .concat(),
        [packet(&reply), packet(&[21]), vec![0xff; 48]].concat(),
    ]
}

/// A sandbox whose SSH server sends `bytes` and hangs up.
fn sending(bytes: Vec<u8>) -> Box<dyn Fn(DuplexStream) + Send + Sync> {
    Box::new(move |mut stream| {
        let bytes = bytes.clone();
        tokio::spawn(async move {
            let _ = stream.write_all(&bytes).await;
        });
    })
}

#[tokio::test]
async fn name_mode_proxy_withholds_a_key_the_gateway_did_not_publish() {
    let published = host_key(1);
    let presented = host_key(2);
    let [before_reply, reply_onward] = handshake(&presented);
    let gateway = Gateway {
        published: fingerprint(&published),
        sandbox: sending([before_reply.clone(), reply_onward].concat()),
    }
    .serve()
    .await;
    let scratch = tempfile::tempdir().unwrap();
    let pin = scratch.path().join("known_hosts/pin");

    let proxy = openshell(&name_mode(gateway, &pin), scratch.path(), None).await;

    let stderr = String::from_utf8_lossy(&proxy.stderr);
    assert_eq!(proxy.status.code(), Some(1), "{stderr}");
    assert!(
        before_reply.starts_with(&proxy.stdout),
        "no byte of the key exchange reply may reach ssh"
    );
    assert!(
        stderr.contains(&mismatch_message(&published, &presented)),
        "{stderr}"
    );
    assert_eq!(std::fs::read_to_string(&pin).unwrap(), pin_content(None));
}

#[tokio::test]
async fn name_mode_proxy_reaches_a_sandbox_with_no_published_key_only_when_allowed() {
    let key = host_key(1);
    let transcript = handshake(&key).concat();
    let gateway = Gateway {
        published: String::new(),
        sandbox: sending(transcript.clone()),
    }
    .serve()
    .await;
    let scratch = tempfile::tempdir().unwrap();
    let pin = scratch.path().join("known_hosts/pin");
    let args = name_mode(gateway, &pin);

    let refused = openshell(&args, scratch.path(), None).await;

    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(!refused.status.success());
    assert_eq!(refused.stdout, b"");
    assert!(
        stderr.contains("sandbox 'my-sb' has no published SSH host key"),
        "{stderr}"
    );
    assert!(!pin.exists());

    let allowed = openshell(&args, scratch.path(), Some("1")).await;

    let stderr = String::from_utf8_lossy(&allowed.stderr);
    assert!(allowed.status.success(), "{stderr}");
    assert_eq!(allowed.stdout, transcript);
    assert!(
        stderr.contains("warning: SSH host key of sandbox 'my-sb' is NOT verified"),
        "{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(&pin).unwrap(),
        pin_content(Some(&key))
    );
}

/// An `ssh` started by a client or a config entry from before host-key
/// verification accepts any key, so its proxy must not relay.
#[tokio::test]
async fn proxy_refuses_a_caller_that_predates_host_key_verification() {
    let gateway = Gateway {
        published: fingerprint(&host_key(1)),
        sandbox: sending(handshake(&host_key(1)).concat()),
    }
    .serve()
    .await;
    let scratch = tempfile::tempdir().unwrap();
    let old_client = format!(
        "ssh-proxy --gateway http://{gateway}/proxy/connect --sandbox {SANDBOX} --workspace {WORKSPACE} --token test-token"
    );

    for (args, refused) in [
        (old_client, "started by an OpenShell client that predates"),
        (
            old_name_mode(gateway),
            "SSH config entry for sandbox 'my-sb'",
        ),
    ] {
        let proxy = openshell(&args, scratch.path(), None).await;

        let stderr = String::from_utf8_lossy(&proxy.stderr);
        assert_eq!(proxy.status.code(), Some(1), "{stderr}");
        assert_eq!(proxy.stdout, b"");
        assert!(stderr.contains(refused), "{stderr}");
        assert!(stderr.contains("and is refused"), "{stderr}");
    }
}

/// The real `ssh` client against a real SSH server, with `ssh-proxy` as its
/// `ProxyCommand`.
#[cfg(unix)]
mod openssh {
    use super::*;
    use openshell_core::forward::{sandbox_proxy_command, sandbox_ssh_args};
    use openshell_core::ssh_host_key::{HostKeyCheck, KnownHostsPin, SandboxSshTarget};
    use russh::server::{Auth, ChannelOpenHandle, Msg, Session};
    use russh::{Channel, ChannelId};

    const COMMAND: &str = "report-ready";
    const COMMAND_OUTPUT: &str = "ready\n";
    const GATEWAY: &str = "test-gateway";

    fn write_pin(pin: &Path, content: &str) {
        std::fs::create_dir_all(pin.parent().unwrap()).unwrap();
        std::fs::write(pin, content).unwrap();
    }

    /// Accepts every login and answers every command with [`COMMAND_OUTPUT`].
    struct Shell;

    impl russh::server::Handler for Shell {
        type Error = russh::Error;

        async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
            Ok(Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _channel: Channel<Msg>,
            reply: ChannelOpenHandle,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn exec_request(
            &mut self,
            channel: ChannelId,
            _data: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            session.data(channel, COMMAND_OUTPUT)?;
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
            Ok(())
        }
    }

    /// The gateway in front of a sandbox whose SSH server presents `key`.
    async fn sandbox_presenting(key: &PrivateKey) -> SocketAddr {
        // The supervisor's server also keeps the default algorithms.
        let config = Arc::new(russh::server::Config {
            keys: vec![key.clone()],
            ..Default::default()
        });
        Gateway {
            published: fingerprint(key),
            sandbox: Box::new(move |stream| {
                let config = config.clone();
                tokio::spawn(async move {
                    if let Ok(session) = russh::server::run_stream(config, stream, Shell).await {
                        let _ = session.await;
                    }
                });
            }),
        }
        .serve()
        .await
    }

    /// Runs [`COMMAND`] with the `ssh` arguments the CLI and TUI build for
    /// a session whose published fingerprint is `published`. `ssh` takes
    /// the first value of an option, so `overrides` win.
    async fn ssh_as_client(
        gateway: SocketAddr,
        published: &str,
        pin: &Path,
        config: &Path,
        overrides: &[String],
    ) -> Output {
        let target = SandboxSshTarget {
            gateway: GATEWAY,
            workspace: WORKSPACE,
            sandbox: SANDBOX,
        };
        let pin = KnownHostsPin::at(pin.to_path_buf(), SANDBOX, WORKSPACE).unwrap();
        let host_key = HostKeyCheck::for_relay(published.parse().unwrap(), pin).unwrap();
        let proxy_command = sandbox_proxy_command(
            env!("CARGO_BIN_EXE_openshell"),
            &format!("http://{gateway}"),
            &target,
            "test-token",
            host_key,
        );
        let mut ssh = tokio::process::Command::new("ssh");
        ssh.args(["-F", "/dev/null", "-o", "BatchMode=yes"])
            .args(overrides.iter().flat_map(|option| ["-o", option]))
            .args(sandbox_ssh_args(&proxy_command, "ERROR"))
            .args(["sandbox", COMMAND]);
        finished(ssh, config, None).await
    }

    /// Runs [`COMMAND`] through the config entry `sandbox ssh-config`
    /// prints, with no other configuration and no options of its own.
    async fn ssh_through_config_entry(gateway: SocketAddr, config: &Path) -> Output {
        let gateway_dir = config.join("openshell/gateways").join(GATEWAY);
        std::fs::create_dir_all(&gateway_dir).unwrap();
        let metadata = serde_json::json!({
            "name": GATEWAY,
            "gateway_endpoint": format!("http://{gateway}"),
            "gateway_port": gateway.port(),
            "is_remote": false,
            "auth_mode": "plaintext",
        });
        std::fs::write(gateway_dir.join("metadata.json"), metadata.to_string()).unwrap();

        let print_entry =
            format!("--gateway {GATEWAY} --workspace {WORKSPACE} sandbox ssh-config {SANDBOX}");
        let printed = openshell(&print_entry, config, None).await;
        assert!(
            printed.status.success(),
            "{}",
            String::from_utf8_lossy(&printed.stderr)
        );
        let entry = config.join("ssh_config_entry");
        std::fs::write(&entry, printed.stdout).unwrap();

        let mut ssh = tokio::process::Command::new("ssh");
        ssh.arg("-F")
            .arg(entry)
            .args(["-o", "BatchMode=yes"])
            .args([format!("openshell-{SANDBOX}.{WORKSPACE}").as_str(), COMMAND]);
        finished(ssh, config, None).await
    }

    /// The proxy accepts and forwards any key here, so the refusal is `ssh`'s
    /// own strict check against a file the proxy does not write.
    #[tokio::test]
    async fn ssh_refuses_a_key_missing_from_its_own_known_hosts_file() {
        let key = host_key(1);
        let gateway = sandbox_presenting(&key).await;
        let scratch = tempfile::tempdir().unwrap();
        let proxy_pin = scratch.path().join("known_hosts/proxy");
        let ssh_pin = scratch.path().join("known_hosts/ssh");
        let another_key = pin_content(Some(&host_key(2)));
        write_pin(&ssh_pin, &another_key);

        let ssh = ssh_as_client(
            gateway,
            "unverified",
            &proxy_pin,
            scratch.path(),
            &[format!("UserKnownHostsFile=\"{}\"", ssh_pin.display())],
        )
        .await;

        let stderr = String::from_utf8_lossy(&ssh.stderr);
        assert_eq!(ssh.status.code(), Some(255), "{stderr}");
        assert!(stderr.contains("Host key verification failed"), "{stderr}");
        assert_eq!(ssh.stdout, b"");
        assert_eq!(
            std::fs::read_to_string(&proxy_pin).unwrap(),
            pin_content(Some(&key)),
            "the proxy forwarded the key exchange reply"
        );
        assert_eq!(std::fs::read_to_string(&ssh_pin).unwrap(), another_key);
    }

    /// `ssh` is already running when the proxy pins the key, so this holds
    /// only because `ssh` reads its known-hosts file when it processes the key
    /// exchange reply, not when it starts. Host-key verification rests on it.
    #[tokio::test]
    async fn ssh_with_the_client_arguments_reaches_the_published_sandbox() {
        let key = host_key(1);
        let gateway = sandbox_presenting(&key).await;
        let scratch = tempfile::tempdir().unwrap();
        let pin = scratch.path().join("known_hosts/pin");

        let ssh = ssh_as_client(gateway, &fingerprint(&key), &pin, scratch.path(), &[]).await;

        let stderr = String::from_utf8_lossy(&ssh.stderr);
        assert!(ssh.status.success(), "{stderr}");
        assert_eq!(String::from_utf8_lossy(&ssh.stdout), COMMAND_OUTPUT);
        assert_eq!(
            std::fs::read_to_string(&pin).unwrap(),
            pin_content(Some(&key))
        );
    }

    #[tokio::test]
    async fn ssh_with_the_client_arguments_never_reaches_another_server() {
        let presented = host_key(1);
        let published = host_key(2);
        let gateway = sandbox_presenting(&presented).await;
        let scratch = tempfile::tempdir().unwrap();
        let pin = scratch.path().join("known_hosts/pin");

        let ssh = ssh_as_client(gateway, &fingerprint(&published), &pin, scratch.path(), &[]).await;

        let stderr = String::from_utf8_lossy(&ssh.stderr);
        assert_eq!(ssh.status.code(), Some(255), "{stderr}");
        assert!(
            stderr.contains(&mismatch_message(&published, &presented)),
            "{stderr}"
        );
        assert_eq!(ssh.stdout, b"");
        assert_eq!(std::fs::read_to_string(&pin).unwrap(), pin_content(None));
    }

    /// The pin still holds the stale key when `ssh` starts, so this holds only
    /// because the proxy replaces it before `ssh` reads the file.
    #[tokio::test]
    async fn ssh_connects_through_the_generated_config_entry_despite_a_stale_pin() {
        let key = host_key(1);
        let gateway = sandbox_presenting(&key).await;
        let scratch = tempfile::tempdir().unwrap();
        let pin = scratch
            .path()
            .join("openshell/known_hosts")
            .join(GATEWAY)
            .join(format!("openshell-{SANDBOX}.{WORKSPACE}"));
        write_pin(&pin, &pin_content(Some(&host_key(2))));

        let ssh = ssh_through_config_entry(gateway, scratch.path()).await;

        let stderr = String::from_utf8_lossy(&ssh.stderr);
        assert!(ssh.status.success(), "{stderr}");
        assert_eq!(String::from_utf8_lossy(&ssh.stdout), COMMAND_OUTPUT);
        assert_eq!(
            std::fs::read_to_string(&pin).unwrap(),
            pin_content(Some(&key))
        );
    }
}
