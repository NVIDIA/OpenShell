// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-pod CLI clients, bounded retries, and one function per operation class
//! of the HA operation inventory: continuity (C), exec through every pod (E1),
//! streamed-stdin exec (E2), upload and download (F1), `forward start` (F2),
//! `forward service` (F3), policy update (P), provider attach or detach (V),
//! and a fresh sandbox across pods (N).

use std::collections::HashMap;
use std::fs;
use std::io::Write as _;
use std::net::TcpListener;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::port::find_free_port;
use openshell_e2e::harness::sandbox::E2E_WORKLOAD_IMAGE;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::Child;

use crate::kube::{KubeTarget, PortForward};

const OP_DEADLINE: Duration = Duration::from_secs(60);
/// Policy and provider waits run the CLI's own `--wait --timeout 120`.
const SLOW_OP_DEADLINE: Duration = Duration::from_secs(150);
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(45);
/// Collecting a timed-out CLI's output after its process group is killed.
const KILLED_OUTPUT_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_SLEEP: Duration = Duration::from_secs(2);
/// Non-`--wait` ops: C, E1, E2, F1, F2, F3.
const OP_MAX_ATTEMPTS: u32 = 5;
/// P and V.
const WAIT_OP_MAX_ATTEMPTS: u32 = 2;
/// The fresh create in N.
const N_MAX_ATTEMPTS: u32 = 3;
const SETUP_CREATE_TIMEOUT: Duration = Duration::from_secs(300);
const SETUP_READY_DEADLINE: Duration = Duration::from_secs(120);
/// Connections tried, [`RETRY_SLEEP`] apart, while a forward comes up.
const ECHO_TRIES: u32 = 15;
/// Over the CLI's 1 MiB request limit, so exec uses `ExecSandboxInteractive`.
const STREAM_STDIN_BYTES: usize = 2 * 1024 * 1024;
const TRANSFER_BYTES: usize = 1024 * 1024;
const ROOT: &str = "/sandbox/ha-ops";
const TLS_GATEWAY_NAME: &str = "ha-ops-pod-tls";

/// Output that marks a failed attempt as retryable (matched case-insensitively).
const TRANSIENT_MARKERS: [&str; 10] = [
    "unavailable",
    "transport error",
    "connection refused",
    "connection reset",
    "broken pipe",
    "timed out",
    "deadline exceeded",
    "sandbox is not ready",
    "supervisor session not connected",
    "error trying to connect",
];

/// Local peer transport policy refusals; the lane must never trigger them, so
/// they fail the op even next to a transient marker.
const HARD_FAIL_MARKERS: [&str; 2] = ["gateway peer transport refused", "OPENSHELL_PEER_"];

/// Minimal policy with no network rules (`e2e/rust/tests/live_policy_update.rs`).
const SANDBOX_POLICY: &str = r"version: 1

filesystem_policy:
  include_workdir: true
  read_only:
    - /bin
    - /usr
    - /lib
    - /proc
    - /dev/urandom
    - /app
    - /etc
    - /var/log
  read_write:
    - /sandbox
    - /tmp
    - /dev/null

landlock:
  compatibility: best_effort

network_policies: {}
";

/// Echo server main command. It never exits and records its pid plus a
/// per-start nonce, so C can prove the workload was never restarted: `/sandbox`
/// is a PVC that outlives the pod, and a restarted server can reuse the pid.
fn echo_server_script(port: u16) -> String {
    format!(
        r#"import os, socketserver
class H(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"echo:" + self.rfile.readline())
class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
srv = S(("127.0.0.1", {port}), H)
os.makedirs("{ROOT}", exist_ok=True)
open("{ROOT}/echo.pid", "w").write("%d-%s" % (os.getpid(), os.urandom(8).hex()))
srv.serve_forever()
"#
    )
}

pub fn run_id() -> String {
    const BASE36: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let pick = || char::from(BASE36[rand::random_range(0..BASE36.len())]);
    (0..6).map(|_| pick()).collect()
}

pub fn sandbox_name(run: &str) -> String {
    format!("ha-ops-{run}")
}

/// `ha-n-<run>-p<d>a<k>`: `<d>` is the phase digit and `<k>` counts this
/// phase's names already `tried` (attempts and the owner-stability rerun),
/// so every create uses a name never used before.
pub fn fresh_name(run: &str, phase: &str, tried: &[String]) -> String {
    let prefix = format!("ha-n-{run}-{}a", &phase[..2]);
    let k = 1 + tried
        .iter()
        .filter(|name| name.starts_with(&prefix))
        .count();
    format!("{prefix}{k}")
}

/// The echo port, free now and below the default Linux ephemeral range
/// (32768-60999), so no port-0 bind (a port-forward, F3's local listener)
/// takes it between F2 runs; `forward start` listens on the same port.
fn pick_echo_port() -> u16 {
    let free = |port: &u16| TcpListener::bind(("127.0.0.1", *port)).is_ok();
    let mut candidates = (0..64).map(|_| rand::random_range(20_000..32_768));
    candidates.find(free).unwrap_or_else(find_free_port)
}

fn sha256_file(path: &Path) -> String {
    let data = fs::read(path);
    data.map_or_else(
        |err| err.to_string(),
        |data| hex::encode(Sha256::digest(data)),
    )
}

fn words(line: &str) -> Vec<&str> {
    line.split_whitespace().collect()
}

fn left(until: Instant) -> Duration {
    until.saturating_duration_since(Instant::now())
}

/// True when a failed attempt may be retried: it timed out or its output
/// carries a transient marker, and it carries no hard-fail marker.
pub fn is_transient(output: &str, timed_out: bool) -> bool {
    let lower = strip_ansi(output).to_ascii_lowercase();
    let has = |marker: &str| lower.contains(&marker.to_ascii_lowercase());
    !HARD_FAIL_MARKERS.into_iter().any(has) && (timed_out || TRANSIENT_MARKERS.into_iter().any(has))
}

/// A failed attempt; only a transient one is retried.
pub struct Fail {
    pub msg: String,
    pub transient: bool,
}

impl Fail {
    pub fn fatal(msg: impl Into<String>) -> Self {
        let msg = msg.into();
        Self {
            msg,
            transient: false,
        }
    }

    pub fn transient(msg: impl Into<String>) -> Self {
        let msg = msg.into();
        Self {
            msg,
            transient: true,
        }
    }

    fn classify(msg: String, timed_out: bool) -> Self {
        let transient = is_transient(&msg, timed_out);
        Self { msg, transient }
    }
}

fn check(ok: bool, msg: impl FnOnce() -> String) -> Result<(), Fail> {
    if ok { Ok(()) } else { Err(Fail::fatal(msg())) }
}

pub type Outcome = (u32, Result<(), String>);

/// Run `attempt` with bounded retries: a transient failure is retried after
/// [`RETRY_SLEEP`] until `max` attempts or `deadline` run out; anything else
/// fails at once. `attempt` gets its number and the time left.
async fn run_op<T>(
    label: &str,
    max: u32,
    deadline: Duration,
    mut attempt: impl AsyncFnMut(u32, Duration) -> Result<T, Fail>,
) -> (u32, Result<T, String>) {
    let started = Instant::now();
    let mut attempts = 0;
    let mut last = String::from("no attempt fit in the deadline");
    while attempts < max && started.elapsed() < deadline {
        attempts += 1;
        match attempt(attempts, deadline.saturating_sub(started.elapsed())).await {
            Ok(value) => return (attempts, Ok(value)),
            Err(fail) if fail.transient => last = fail.msg,
            Err(fail) => {
                last = fail.msg;
                break;
            }
        }
        if attempts < max {
            tokio::time::sleep(RETRY_SLEEP).await;
        }
    }
    let secs = started.elapsed().as_secs();
    let err = format!("{label} failed after {attempts} attempts ({secs}s): {last}");
    (attempts, Err(err))
}

/// Poll `probe` until it succeeds, fails fatally, or `deadline` passes. Only
/// for setup and recovery gates, where a pending state is expected.
pub async fn poll<T>(
    what: &str,
    deadline: Duration,
    mut probe: impl AsyncFnMut() -> Result<T, Fail>,
) -> Result<T, String> {
    run_op(what, u32::MAX, deadline, async |_, _| probe().await)
        .await
        .1
}

#[derive(Default)]
pub struct CliOutput {
    ok: bool,
    pub timed_out: bool,
    pub stdout: String,
    /// stdout and stderr, ANSI-stripped.
    pub text: String,
}

async fn drain(pipe: Option<impl AsyncRead + Unpin>) -> Vec<u8> {
    let mut bytes = Vec::new();
    if let Some(mut pipe) = pipe {
        let _ = pipe.read_to_end(&mut bytes).await;
    }
    bytes
}

/// Wait up to `timeout` for `child` and collect its output. On timeout the
/// child's process group is killed and what it wrote is still returned, so a
/// hard-fail marker printed before a hang is classified and reported.
pub async fn output(mut child: Child, timeout: Duration) -> CliOutput {
    // Taken first: `wait` reaps the child, and a grandchild may still hold
    // the pipes.
    let group = Group::of(&child);
    let stdout = tokio::spawn(drain(child.stdout.take()));
    let stderr = tokio::spawn(drain(child.stderr.take()));
    let aborts = [stdout.abort_handle(), stderr.abort_handle()];
    // One future for the whole run keeps every branch that finished before
    // the timeout, so resuming it after the kill polls only what is pending.
    let mut all = std::pin::pin!(async {
        tokio::join!(child.wait(), async { tokio::join!(stdout, stderr) })
    });
    let finished = tokio::time::timeout(timeout, all.as_mut()).await;
    let (status, (stdout, stderr)) = if let Ok((status, pipes)) = finished {
        (Some(status), pipes)
    } else {
        drop(group);
        // The pipes close once the whole group is dead.
        let pipes = tokio::time::timeout(KILLED_OUTPUT_TIMEOUT, all.as_mut()).await;
        for abort in aborts {
            abort.abort();
        }
        let pipes = pipes.map_or_else(|_| (Ok(Vec::new()), Ok(Vec::new())), |(_, pipes)| pipes);
        (None, pipes)
    };
    let stdout = String::from_utf8_lossy(&stdout.unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&stderr.unwrap_or_default()).into_owned();
    let text = strip_ansi(&format!("{stdout}{stderr}"));
    match status {
        Some(Err(err)) => CliOutput {
            text: err.to_string(),
            ..CliOutput::default()
        },
        status => CliOutput {
            timed_out: status.is_none(),
            ok: status.is_some_and(|status| status.is_ok_and(|status| status.success())),
            stdout,
            text,
        },
    }
}

/// Kills a CLI's process group when dropped, including the `ssh` that
/// upload, download, and `forward start` spawn.
struct Group(Option<Pid>);

impl Group {
    /// The group a child spawned with `process_group(0)` leads.
    fn of(child: &Child) -> Self {
        let pid = child.id().and_then(|id| i32::try_from(id).ok());
        Self(pid.map(Pid::from_raw))
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        if let Some(group) = self.0 {
            let _ = killpg(group, Signal::SIGKILL);
        }
    }
}

fn exited(child: &mut Child) -> bool {
    !matches!(child.try_wait(), Ok(None))
}

/// Runs the CLI against one gateway pod through a `kubectl port-forward` per
/// pod, over TLS when the pods serve it.
pub struct Client {
    kube: KubeTarget,
    /// Config home holding the client TLS files for [`TLS_GATEWAY_NAME`].
    tls_home: Option<TempDir>,
    forwards: HashMap<String, PortForward>,
}

impl Client {
    pub async fn new(kube: KubeTarget, tls: bool) -> Result<Self, String> {
        let mut tls_home = None;
        if tls {
            tls_home = Some(tls_home_dir(&kube).await?);
        }
        let forwards = HashMap::new();
        Ok(Self {
            kube,
            tls_home,
            forwards,
        })
    }

    pub fn retain(&mut self, pods: &[String]) {
        self.forwards.retain(|pod, _| pods.contains(pod));
    }

    /// Start `openshell <args>` against `pod` in its own process group.
    async fn spawn(
        &mut self,
        pod: &str,
        args: &[&str],
        stdin: Option<Vec<u8>>,
    ) -> Result<(Child, Group), Fail> {
        if !self
            .forwards
            .get_mut(pod)
            .is_some_and(PortForward::is_alive)
        {
            let forward = PortForward::start(&self.kube, pod)
                .await
                .map_err(Fail::transient)?;
            self.forwards.insert(pod.to_string(), forward);
        }
        let port = self.forwards[pod].port;
        let mut cmd = openshell_cmd();
        if let Some(home) = &self.tls_home {
            // `localhost` is a server certificate SAN in both chart PKI modes.
            // `ssh-proxy` (upload, download, `forward start`) inherits this
            // environment, so it finds the same client identity.
            cmd.env("XDG_CONFIG_HOME", home.path())
                .env("OPENSHELL_GATEWAY", TLS_GATEWAY_NAME);
            cmd.args(["--gateway-endpoint", &format!("https://localhost:{port}")]);
        } else {
            cmd.args(["--gateway-endpoint", &format!("http://127.0.0.1:{port}")]);
        }
        let input = if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        };
        cmd.args(args).process_group(0).stdin(input);
        let child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn();
        let mut child = child.map_err(|err| Fail::fatal(format!("spawn openshell: {err}")))?;
        let group = Group::of(&child);
        if let (Some(bytes), Some(mut pipe)) = (stdin, child.stdin.take()) {
            tokio::spawn(async move { pipe.write_all(&bytes).await });
        }
        Ok((child, group))
    }

    /// Run `openshell <args>` against `pod` within `timeout`; a failure is
    /// classified.
    pub async fn exec(
        &mut self,
        pod: &str,
        args: &[&str],
        stdin: Option<Vec<u8>>,
        timeout: Duration,
    ) -> Result<CliOutput, Fail> {
        let (child, _group) = self.spawn(pod, args, stdin).await?;
        let out = output(child, timeout).await;
        if out.ok {
            return Ok(out);
        }
        // Only the subcommand: other arguments may carry a credential.
        let what = args.get(..2).unwrap_or(args).join(" ");
        let how = if out.timed_out { "timed out" } else { "failed" };
        let msg = format!("openshell {what} via {pod} {how}: {}", out.text.trim());
        self.fail(pod, Fail::classify(msg, out.timed_out))
    }

    /// A failed attempt; a transient one drops the pod's port-forward so the
    /// next attempt opens a new one.
    fn fail<T>(&mut self, pod: &str, fail: Fail) -> Result<T, Fail> {
        if fail.transient {
            self.forwards.remove(pod);
        }
        Err(fail)
    }

    pub async fn run(
        &mut self,
        pod: &str,
        line: &str,
        timeout: Duration,
    ) -> Result<CliOutput, Fail> {
        self.exec(pod, &words(line), None, timeout).await
    }

    /// [`Client::run`] of a `-o json` command, parsed. The CLI logs to stdout,
    /// so log lines before the document are skipped.
    pub async fn json(&mut self, pod: &str, line: &str, timeout: Duration) -> Result<Value, Fail> {
        let text = strip_ansi(&self.run(pod, line, timeout).await?.stdout);
        let start = if text.trim_start().starts_with('{') {
            Some(0)
        } else {
            text.find("\n{")
        };
        let value = start.and_then(|start| serde_json::from_str(&text[start..]).ok());
        value.ok_or_else(|| Fail::fatal(format!("expected JSON from {line}, got: {}", text.trim())))
    }

    /// `sandbox exec --name <sandbox> <args>` through `pod`, requiring `want`
    /// in its stdout.
    async fn expect(
        &mut self,
        pod: &str,
        sandbox: &str,
        args: &str,
        want: &str,
        until: Instant,
    ) -> Result<(), Fail> {
        let exec = format!("sandbox exec --name {sandbox} {args}");
        let out = self.run(pod, &exec, left(until)).await?;
        let msg = || format!("exec via {pod} lacks {want:?}: {:?}", out.text);
        check(out.stdout.contains(want), msg)
    }

    /// Run a forward, echo `messages` through its local `port`, stop it, and
    /// classify a failure together with the forward's output.
    async fn forward(
        &mut self,
        pod: &str,
        line: &str,
        port: u16,
        messages: &[&str],
        until: Instant,
    ) -> Result<(), Fail> {
        let (mut child, group) = self.spawn(pod, &words(line), None).await?;
        let echoed = echo(&mut child, port, messages, until).await;
        drop(group);
        let out = output(child, Duration::from_secs(5)).await;
        let Err((err, timed_out)) = echoed else {
            return Ok(());
        };
        self.fail(
            pod,
            Fail::classify(format!("{err}\n{}", out.text.trim()), timed_out),
        )
    }
}

/// A private config home with the client TLS files for [`TLS_GATEWAY_NAME`]:
/// the CLI reads an https endpoint's CA and client identity from the gateway
/// name's `mtls` directory (`crates/openshell-cli/src/tls.rs`). The files come
/// from the harness-registered gateway (`$OPENSHELL_GATEWAY`), or from the
/// chart-default Secrets when the harness registered none. Never print them.
async fn tls_home_dir(kube: &KubeTarget) -> Result<TempDir, String> {
    let home = std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config"));
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or(home);
    let gateway = std::env::var("OPENSHELL_GATEWAY")
        .ok()
        .filter(|name| !name.is_empty());
    let harness = config
        .zip(gateway)
        .map(|(config, name)| config.join("openshell/gateways").join(name).join("mtls"));
    let harness = harness.filter(|dir| dir.is_dir());
    let home = tempfile::tempdir().map_err(|err| format!("create CLI config home: {err}"))?;
    let dir = home
        .path()
        .join("openshell/gateways")
        .join(TLS_GATEWAY_NAME);
    let dir = dir.join("mtls");
    fs::create_dir_all(&dir).map_err(|err| format!("create {}: {err}", dir.display()))?;
    // Chart defaults of `server.tls.certSecretName` and `server.tls.clientTlsSecretName`.
    let (server, client) = ("openshell-server-tls", "openshell-client-tls");
    for (file, secret) in [("ca.crt", server), ("tls.crt", client), ("tls.key", client)] {
        let bytes = match &harness {
            Some(src) => fs::read(src.join(file)).map_err(|err| format!("read {file}: {err}"))?,
            None => kube.secret(secret, file).await?,
        };
        let mut open = fs::OpenOptions::new();
        let out = open
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join(file));
        let written = out.and_then(|mut out| out.write_all(&bytes));
        written.map_err(|err| format!("write {file}: {err}"))?;
    }
    Ok(home)
}

/// A failed echo, and whether the attempt ran out of time.
type Echoed = Result<(), (String, bool)>;

/// Send each message on a new connection to `127.0.0.1:port` and expect
/// `echo:<message>`, retrying while the forward comes up.
async fn echo(child: &mut Child, port: u16, messages: &[&str], until: Instant) -> Echoed {
    for message in messages {
        let want = format!("echo:{message}");
        for tries in 1..=ECHO_TRIES {
            match echo_once(port, message, until).await {
                Ok(reply) if reply.starts_with(&want) => break,
                Ok(reply) => return Err((format!("expected {want:?}, got {reply:?}"), false)),
                Err(err) if exited(child) || tries == ECHO_TRIES || left(until) <= RETRY_SLEEP => {
                    let err = format!("no echo through 127.0.0.1:{port}: {err}");
                    return Err((err, left(until) <= RETRY_SLEEP));
                }
                Err(_) => tokio::time::sleep(RETRY_SLEEP).await,
            }
        }
    }
    Ok(())
}

async fn echo_once(port: u16, message: &str, until: Instant) -> Result<String, String> {
    let connect = TcpStream::connect(("127.0.0.1", port)).await;
    let mut stream = connect.map_err(|err| format!("connect: {err}"))?;
    let write = stream.write_all(format!("{message}\n").as_bytes()).await;
    write.map_err(|err| format!("write: {err}"))?;
    let mut reply = String::new();
    let mut reader = BufReader::new(stream);
    let read = reader.read_line(&mut reply);
    match tokio::time::timeout(left(until).min(Duration::from_secs(10)), read).await {
        Ok(Ok(0)) => Err("connection closed before a reply".to_string()),
        Ok(Ok(_)) => Ok(reply.trim_end().to_string()),
        Ok(Err(err)) => Err(format!("read: {err}")),
        Err(_) => Err("read timed out".to_string()),
    }
}

/// `(state, wait_outcome, attached)` of the single target of a provider
/// mutation or status output; `attached` is the saved desired state.
fn provider_target(body: &Value) -> Result<(String, String, bool), Fail> {
    let targets = body["targets"].as_array().map_or(&[][..], Vec::as_slice);
    let [target] = targets else {
        return Err(Fail::fatal(format!("want one provider target: {body}")));
    };
    let field = |name: &str| target[name].as_str().unwrap_or_default().to_string();
    let attached = target["receipt"]["desired"]["provider_id"].as_str();
    let attached = attached.is_some_and(|id| !id.is_empty());
    Ok((field("state"), field("wait_outcome"), attached))
}

/// `ha_ops_<phase_key>`: the phase id with `-` replaced by `_`.
pub fn policy_key(phase: &str) -> String {
    format!("ha_ops_{}", phase.replace('-', "_"))
}

/// The rule a P op adds: `ha_ops_<phase_key>` with this block's host.
struct PolicyRule<'a> {
    sandbox: &'a str,
    key: String,
    host: String,
}

impl PolicyRule<'_> {
    /// Through `pod`: the latest policy version, whether it holds this rule,
    /// and (only then) that revision's status. The effective view without
    /// `--rev` always reports `effective`.
    async fn state(
        &self,
        client: &mut Client,
        pod: &str,
        until: Instant,
    ) -> Result<(u64, bool, String), Fail> {
        let get = format!("policy get {} --full -o json", self.sandbox);
        let snapshot = client.json(pod, &get, left(until)).await?;
        let Some(version) = snapshot["version"].as_u64() else {
            return Err(Fail::fatal(format!(
                "policy get returned no version: {snapshot}"
            )));
        };
        let rule = &snapshot["policy"]["network_policies"][&self.key];
        if !rule.is_object() || !rule.to_string().contains(&format!("\"{}\"", self.host)) {
            return Ok((version, false, String::new()));
        }
        let rev = format!("policy get {} --rev {version} -o json", self.sandbox);
        let revision = client.json(pod, &rev, left(until)).await?;
        Ok((
            version,
            true,
            revision["status"].as_str().unwrap_or_default().to_string(),
        ))
    }

    /// Poll through `pod` until the rule is saved above version `before` and
    /// its revision is loaded.
    async fn loaded(
        &self,
        client: &mut Client,
        pod: &str,
        before: u64,
        until: Instant,
    ) -> Result<(), Fail> {
        loop {
            let (version, saved, status) = self.state(client, pod, until).await?;
            if !saved || version <= before {
                let (key, host) = (&self.key, &self.host);
                let msg = format!("policy v{version} via {pod} lacks {key}/{host} above v{before}");
                return Err(Fail::fatal(msg));
            }
            if status == "loaded" {
                return Ok(());
            }
            if status != "pending" || left(until) <= RETRY_SLEEP {
                let msg = format!("policy revision {version} via {pod} is {status:?}");
                return Err(Fail {
                    msg,
                    transient: status == "pending",
                });
            }
            tokio::time::sleep(RETRY_SLEEP).await;
        }
    }
}

/// Where one op runs: `via` does not own the session, `other` is a second
/// Ready pod (P's cross-check, N's second pod).
pub struct Target<'a> {
    pub phase: &'static str,
    pub pods: &'a [String],
    pub via: &'a str,
    pub other: &'a str,
    pub rerun: bool,
}

/// The long-lived sandbox and the state every operation shares.
pub struct Ops {
    pub client: Client,
    run: String,
    pub sandbox: String,
    provider: String,
    /// Sandbox listener port, and the local port of `forward start`.
    echo_port: u16,
    /// Continuity token written once in setup, and the echo server's
    /// `<pid>-<nonce>` start identity.
    token: String,
    echo_pid: String,
    python3: String,
    scratch: TempDir,
    payload_sha: String,
    /// P's policy version before its first attempt.
    policy_before: Option<u64>,
    /// Every fresh sandbox name tried, recorded before its create for cleanup.
    fresh: Vec<String>,
}

impl Ops {
    pub fn new(client: Client) -> Result<Self, String> {
        let run = run_id();
        let scratch = tempfile::tempdir().map_err(|err| format!("create scratch dir: {err}"))?;
        let payload = (0..TRANSFER_BYTES).map(|i| u8::try_from(i % 251).unwrap_or_default());
        let path = scratch.path().join("payload.bin");
        let written = fs::write(&path, payload.collect::<Vec<_>>());
        written.map_err(|err| format!("write payload: {err}"))?;
        Ok(Self {
            client,
            sandbox: sandbox_name(&run),
            provider: format!("ha-ops-{run}-openai"),
            echo_port: pick_echo_port(),
            token: format!("ha-ops-{run}-{:016x}", rand::random::<u64>()),
            echo_pid: String::new(),
            python3: String::new(),
            payload_sha: sha256_file(&path),
            scratch,
            policy_before: None,
            fresh: Vec::new(),
            run,
        })
    }

    /// Through `pod`: create the long-lived sandbox running the echo server,
    /// wait for it, write the continuity token, create the provider, and
    /// return the sandbox id.
    pub async fn setup(&mut self, pod: &str) -> Result<String, String> {
        let policy = self.scratch.path().join("policy.yaml");
        fs::write(&policy, SANDBOX_POLICY).map_err(|err| format!("write policy: {err}"))?;
        let (policy, script) = (policy.to_string_lossy(), echo_server_script(self.echo_port));
        let create = format!(
            "sandbox create --detach --name {} --from {E2E_WORKLOAD_IMAGE}",
            self.sandbox
        );
        let mut create = words(&create);
        create.extend(["--policy", &policy, "--", "python3", "-c", &script]);
        let client = &mut self.client;
        let created = client.exec(pod, &create, None, SETUP_CREATE_TIMEOUT).await;
        created.map_err(|fail| fail.msg)?;

        // `cat` fails until the echo server listens and writes its pid, so
        // any failure is polled here.
        let probe = format!(
            "set -e; pid=$(cat {ROOT}/echo.pid); printf %s {} > {ROOT}/marker; \
             echo \"$pid\" \"$(readlink -f \"$(command -v python3)\")\"",
            self.token
        );
        let exec = format!("sandbox exec --name {} --no-tty -- sh -c", self.sandbox);
        let mut exec = words(&exec);
        exec.push(&probe);
        let out = poll("echo server start", SETUP_READY_DEADLINE, async || {
            let out = client.exec(pod, &exec, None, ATTEMPT_TIMEOUT).await;
            out.map_err(|fail| Fail::transient(fail.msg))
        })
        .await?;
        let [pid, python3] = words(&out.stdout)[..] else {
            return Err(format!("echo server probe printed {:?}", out.stdout));
        };
        let start = pid.split_once('-');
        let start_ok =
            start.is_some_and(|(pid, nonce)| pid.parse::<u32>().is_ok() && nonce.len() == 16);
        if !start_ok || !python3.starts_with('/') {
            return Err(format!("echo server probe printed {:?}", out.stdout));
        }
        (self.echo_pid, self.python3) = (pid.to_string(), python3.to_string());

        let get = format!("sandbox get {} -o json", self.sandbox);
        let sandbox = client
            .json(pod, &get, ATTEMPT_TIMEOUT)
            .await
            .map_err(|fail| fail.msg)?;
        // The key is only an argument; failures print the output, never it.
        let key = format!("OPENAI_API_KEY=sk-ha-ops-{:016x}", rand::random::<u64>());
        let provider = format!("provider create --name {} --type openai", self.provider);
        let provider = format!("{provider} --credential {key}");
        client
            .run(pod, &provider, ATTEMPT_TIMEOUT)
            .await
            .map_err(|fail| fail.msg)?;
        let id = sandbox["id"].as_str().filter(|id| !id.is_empty());
        id.map(str::to_string)
            .ok_or_else(|| format!("sandbox get returned no id: {sandbox}"))
    }

    /// Run op `id` through `at` within its retry bounds. `V+` attaches the
    /// provider and `V-` detaches it.
    pub async fn run(&mut self, id: &str, at: &Target<'_>) -> Outcome {
        let (max, deadline) = match id {
            "P" | "V+" | "V-" => (WAIT_OP_MAX_ATTEMPTS, SLOW_OP_DEADLINE),
            "N" => (N_MAX_ATTEMPTS, SLOW_OP_DEADLINE),
            _ => (OP_MAX_ATTEMPTS, OP_DEADLINE),
        };
        // Non-`--wait` attempts are capped; the others run the CLI's own wait.
        let cap = if max == OP_MAX_ATTEMPTS {
            ATTEMPT_TIMEOUT
        } else {
            deadline
        };
        let label = format!(
            "{}/{} via {}",
            at.phase,
            id.trim_end_matches(['+', '-']),
            at.via
        );
        self.policy_before = None;
        run_op(&label, max, deadline, async |attempt, time| {
            let until = Instant::now() + cap.min(time);
            match id {
                "C" => self.continuity(at.via, until).await,
                "E1" => self.exec_every_pod(at, until).await,
                "E2" => self.streamed_exec(at.via, until).await,
                "F1" => self.transfer(at, attempt, until).await,
                "F2" => self.forward_start(at.via, until).await,
                "F3" => self.forward_service(at.via, until).await,
                "P" => self.policy(at, until).await,
                "N" => self.fresh_sandbox(at, until).await,
                "V+" | "V-" => self.provider(at.via, id == "V+", attempt, until).await,
                _ => Err(Fail::fatal(format!("unknown op {id}"))),
            }
        })
        .await
    }

    /// C: the sandbox is Ready and still runs the same echo server with the
    /// setup token, so the workload was never restarted.
    async fn continuity(&mut self, via: &str, until: Instant) -> Result<(), Fail> {
        let get = format!("sandbox get {} -o json", self.sandbox);
        let phase = &self.client.json(via, &get, left(until)).await?["phase"];
        if phase != "Ready" {
            // The gateway reports this condition as "sandbox is not ready".
            return Err(Fail::transient(format!("sandbox is not ready ({phase})")));
        }
        let want = format!("{}{}", self.token, self.echo_pid);
        let cat = format!("--no-tty -- cat {ROOT}/marker {ROOT}/echo.pid");
        self.client
            .expect(via, &self.sandbox, &cat, &want, until)
            .await
    }

    /// E1: non-interactive exec through every Ready pod; the owner runs it
    /// locally and every other pod relays it to the owner.
    async fn exec_every_pod(&mut self, at: &Target<'_>, until: Instant) -> Result<(), Fail> {
        for pod in at.pods {
            let marker = format!("ha-ops-{}-{pod}", at.phase);
            let printf = format!("--no-tty -- printf %s {marker}");
            self.client
                .expect(pod, &self.sandbox, &printf, &marker, until)
                .await?;
        }
        Ok(())
    }

    /// E2: exec with 2 MiB of piped stdin and no TTY, which the CLI sends
    /// through `ExecSandboxInteractive`.
    async fn streamed_exec(&mut self, via: &str, until: Instant) -> Result<(), Fail> {
        let exec = format!(
            "sandbox exec --name {} --no-tty --no-login-shell",
            self.sandbox
        );
        let exec = format!("{exec} -- wc -c");
        let stdin = Some(vec![b'x'; STREAM_STDIN_BYTES]);
        let out = self
            .client
            .exec(via, &words(&exec), stdin, left(until))
            .await?;
        let counted = out.stdout.trim();
        let msg = || format!("streamed exec counted {counted:?} bytes");
        check(counted == STREAM_STDIN_BYTES.to_string(), msg)
    }

    /// F1: upload and download of a 1 MiB payload over SSH through `via`.
    async fn transfer(
        &mut self,
        at: &Target<'_>,
        attempt: u32,
        until: Instant,
    ) -> Result<(), Fail> {
        let (phase, scratch) = (at.phase, self.scratch.path());
        let upload = scratch.join(format!("ha-ops-{phase}"));
        let payload = (scratch.join("payload.bin"), upload.join("payload.bin"));
        let copied = fs::create_dir_all(&upload).and_then(|()| fs::copy(payload.0, payload.1));
        copied.map_err(|err| Fail::fatal(format!("prepare the upload: {err}")))?;
        let (upload, xfer) = (upload.to_string_lossy(), format!("{ROOT}/xfer"));
        let mut args = words("sandbox upload --no-git-ignore");
        args.extend([&self.sandbox, &*upload, &xfer]);
        self.client.exec(at.via, &args, None, left(until)).await?;
        let download = scratch.join(format!("dl-{phase}-{attempt}"));
        let _ = fs::remove_dir_all(&download);
        fs::create_dir_all(&download).map_err(|err| Fail::fatal(err.to_string()))?;
        let (remote, local) = (format!("{xfer}/ha-ops-{phase}"), download.to_string_lossy());
        let args = ["sandbox", "download", &self.sandbox, &remote, &local];
        self.client.exec(at.via, &args, None, left(until)).await?;
        let (got, sha) = (
            sha256_file(&download.join("payload.bin")),
            &self.payload_sha,
        );
        check(got == *sha, || {
            format!("downloaded SHA-256 {got}, uploaded {sha}")
        })
    }

    /// F2: `forward start` (SSH `-L` over `ForwardTcp`) from the local echo
    /// port to the sandbox echo server.
    async fn forward_start(&mut self, via: &str, until: Instant) -> Result<(), Fail> {
        let line = format!("forward start {} {}", self.echo_port, self.sandbox);
        self.client
            .forward(via, &line, self.echo_port, &["hello"], until)
            .await
    }

    /// F3: `forward service` (`ForwardTcp` with a TCP target, the relay target
    /// of service URLs). The second connection opens a new relay stream.
    async fn forward_service(&mut self, via: &str, until: Instant) -> Result<(), Fail> {
        let local = find_free_port();
        let line = format!(
            "forward service {} --target-port {}",
            self.sandbox, self.echo_port
        );
        let line = format!("{line} --local 127.0.0.1:{local}");
        let messages = ["ha-ops-f3-first", "ha-ops-f3-second"];
        self.client
            .forward(via, &line, local, &messages, until)
            .await
    }

    /// P: `policy update --wait` through `via`, checked through `other`. Each
    /// attempt reads the policy first, so an update that committed before a
    /// failed attempt is not sent again.
    async fn policy(&mut self, at: &Target<'_>, until: Instant) -> Result<(), Fail> {
        let (phase, suffix) = (at.phase, if at.rerun { "-r1" } else { "" });
        let key = policy_key(phase);
        let host = format!("ha-ops-{phase}{suffix}.example.test");
        let rule = PolicyRule {
            sandbox: &self.sandbox,
            key,
            host,
        };
        let (version, saved, _) = rule.state(&mut self.client, at.via, until).await?;
        let before = *self.policy_before.get_or_insert(version);
        if !saved {
            let (key, host, python3) = (&rule.key, &rule.host, &self.python3);
            let update = format!("policy update {} --rule-name {key}", self.sandbox);
            let update = format!(
                "{update} --binary {python3} --add-endpoint {host}:443:read-only:rest:enforce \
                 --wait --timeout 120"
            );
            self.client.run(at.via, &update, left(until)).await?;
        }
        rule.loaded(&mut self.client, at.other, before, until).await
    }

    /// V: provider attach or detach with `--wait` through `via`. A retry
    /// first reads the status, since the last attempt may have saved the
    /// change before it failed.
    async fn provider(
        &mut self,
        via: &str,
        attach: bool,
        attempt: u32,
        until: Instant,
    ) -> Result<(), Fail> {
        let (verb, done) = if attach {
            ("attach", "ready")
        } else {
            ("detach", "revoked")
        };
        let names = format!("{} {}", self.sandbox, self.provider);
        let status = format!("sandbox provider status {names} -o json");
        let mut line = format!("sandbox provider {verb} {names} --wait --timeout 120 -o json");
        if attempt > 1 {
            let current = self.client.json(via, &status, left(until)).await?;
            let (state, _, attached) = provider_target(&current)?;
            if state == done {
                return Ok(());
            }
            if attached == attach {
                line = format!("{status} --wait --timeout 120");
            }
        }
        let body = self.client.json(via, &line, left(until)).await?;
        let (state, outcome, _) = provider_target(&body)?;
        let msg = || format!("provider {verb} ended {state:?}/{outcome:?}, want {done:?}/complete");
        check(state == done && outcome == "complete", msg)
    }

    /// N: create a new sandbox through `via` (watched until Ready), exec in it
    /// and delete it through `other`, then see it gone through `via`. Each
    /// attempt uses a new name.
    async fn fresh_sandbox(&mut self, at: &Target<'_>, until: Instant) -> Result<(), Fail> {
        let name = fresh_name(&self.run, at.phase, &self.fresh);
        self.fresh.push(name.clone());
        let create = format!("sandbox create --detach --name {name} --from {E2E_WORKLOAD_IMAGE}");
        self.client.run(at.via, &create, left(until)).await?;
        let (printf, marker) = (
            format!("--no-tty -- printf %s {name}-ok"),
            format!("{name}-ok"),
        );
        self.client
            .expect(at.other, &name, &printf, &marker, until)
            .await?;
        let delete = format!("sandbox delete {name}");
        self.client.run(at.other, &delete, left(until)).await?;
        let get = format!("sandbox get {name} -o json");
        loop {
            let fail = match self.client.run(at.via, &get, left(until)).await {
                Ok(_) => Fail::transient(format!("{name} still visible after delete")),
                Err(fail) if fail.msg.to_ascii_lowercase().contains("not found") => return Ok(()),
                Err(fail) => fail,
            };
            if !fail.transient || left(until) <= RETRY_SLEEP {
                return Err(fail);
            }
            tokio::time::sleep(RETRY_SLEEP).await;
        }
    }

    /// Delete everything this test may have created through the first pod
    /// that completes each delete; return what could not be deleted.
    ///
    /// The provider is detached first: a deleted sandbox keeps its record,
    /// providers included, until the driver finishes, and the gateway refuses
    /// to delete a provider that any sandbox record lists.
    pub async fn cleanup(&mut self, pods: &[String]) -> Vec<String> {
        let detach = format!("sandbox provider detach {} {}", self.sandbox, self.provider);
        let sandboxes = std::iter::once(&self.sandbox).chain(&self.fresh);
        let mut deletes = vec![detach];
        deletes.extend(sandboxes.map(|name| format!("sandbox delete {name}")));
        deletes.push(format!("provider delete {}", self.provider));
        let mut failed = Vec::new();
        for line in deletes {
            let mut done = false;
            for pod in pods {
                done = match self.client.run(pod, &line, ATTEMPT_TIMEOUT).await {
                    Ok(_) => true,
                    Err(fail) => fail.msg.to_ascii_lowercase().contains("not found"),
                };
                if done {
                    break;
                }
            }
            if !done {
                failed.push(line);
            }
        }
        failed
    }
}
