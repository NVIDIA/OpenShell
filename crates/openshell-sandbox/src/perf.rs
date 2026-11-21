// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in microbenchmarks for the production seccomp network listener.

use std::fmt;
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::linux::workload_launcher;
use anyhow::{Context as _, bail};
use clap::ValueEnum;
use openshell_isolation_interface::contract::{TcpOpenDecision, TcpOpenDenial};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Socket, Type};

use crate::network_broker::NetworkBroker;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Layer {
    Native,
    Filtered,
}

impl Layer {
    pub fn selection(value: &str) -> anyhow::Result<Vec<Self>> {
        match value {
            "all" => Ok(vec![Self::Native, Self::Filtered]),
            "native" => Ok(vec![Self::Native]),
            "filtered" => Ok(vec![Self::Filtered]),
            _ => bail!("unknown layer {value}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    TcpConnect,
    TcpStream,
    FileOpen,
}

impl Protocol {
    pub fn selection(value: &str) -> anyhow::Result<Vec<Self>> {
        match value {
            "all" => Ok(vec![Self::TcpConnect, Self::TcpStream, Self::FileOpen]),
            _ => Ok(vec![
                Self::from_str(value, true).map_err(|error| anyhow::anyhow!("{error}"))?,
            ]),
        }
    }
}

/// Where a benchmark worker directs its measured operation: a socket address
/// for the socket protocols, or a file path for file-open.
#[derive(Clone, Debug)]
pub enum Target {
    Tcp(SocketAddr),
    File(PathBuf),
}

impl Target {
    /// Parse the worker `--target` value for `protocol`.
    pub fn parse(protocol: Protocol, value: &str) -> anyhow::Result<Self> {
        match protocol {
            Protocol::FileOpen => Ok(Self::File(PathBuf::from(value))),
            Protocol::TcpConnect | Protocol::TcpStream => {
                Ok(Self::Tcp(value.parse().with_context(|| {
                    format!("parse socket address {value}")
                })?))
            }
        }
    }

    fn tcp(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Tcp(address) => Ok(*address),
            Self::File(_) => Err(target_mismatch()),
        }
    }

    fn file(&self) -> io::Result<&Path> {
        match self {
            Self::File(path) => Ok(path),
            Self::Tcp(_) => Err(target_mismatch()),
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(address) => write!(formatter, "{address}"),
            Self::File(path) => write!(formatter, "{}", path.display()),
        }
    }
}

fn target_mismatch() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "benchmark target does not match the protocol",
    )
}

#[derive(Debug)]
pub struct BenchmarkOptions {
    pub layers: Vec<Layer>,
    pub protocols: Vec<Protocol>,
    pub iterations: u64,
    pub warmup: u64,
    pub concurrency: usize,
    pub payload_bytes: usize,
    /// Filtered-only background load: cold external connects whose
    /// connect-time identity resolution contends with the measured mediation
    /// path (serialized on the broker thread before the worker move, on
    /// per-connect workers after). Zero disables the load.
    pub background_cold_connects: usize,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BenchmarkReport {
    pub layer: Layer,
    pub protocol: Protocol,
    pub iterations: u64,
    pub concurrency: usize,
    pub payload_bytes: usize,
    /// Cold-connect rounds of the background load that completed while the
    /// measured worker process ran, including its startup and warmup: the
    /// parent cannot see the worker's internal timed-window boundary. Zero
    /// when no load was requested.
    pub background_cold_connect_rounds: u64,
    pub capability_scope: String,
    pub elapsed_ms: f64,
    pub operations_per_second: f64,
    pub throughput_mbit_per_second: f64,
    pub latency_ns_p50: u64,
    pub latency_ns_p95: u64,
    pub latency_ns_p99: u64,
}

pub fn run(options: BenchmarkOptions) -> anyhow::Result<Vec<BenchmarkReport>> {
    if options.iterations == 0 || options.concurrency == 0 {
        bail!("iterations and concurrency must be greater than zero");
    }
    if options.payload_bytes == 0 || options.payload_bytes > 65_507 {
        bail!("payload-bytes must be between 1 and 65507");
    }
    let background_cold_connects =
        u64::try_from(options.background_cold_connects).unwrap_or(u64::MAX);
    if background_cold_connects > 0
        && !options
            .layers
            .iter()
            .any(|layer| matches!(layer, Layer::Filtered))
    {
        bail!("background cold connects require the filtered layer");
    }

    let executable = std::env::current_exe().context("resolve benchmark executable")?;
    let mut reports = Vec::new();
    let mut filtered_runtime = None;
    for layer in options.layers {
        if matches!(layer, Layer::Filtered) && filtered_runtime.is_none() {
            let (launcher, listener) = workload_launcher::start()?;
            // Bound identity resolution to this harness process so the
            // cold-connect load's digest-cache misses actually hash on any
            // host: with the production namespace scope the ancestry walk can
            // fail on an unreadable host ancestor (a nondumpable daemon under
            // init) before the cold hash runs, and the load would not load.
            let broker = NetworkBroker::start_with_identity_root(
                listener,
                crate::network_broker::NETWORK_DECISION_TIMEOUT,
                std::process::id(),
            )?;
            broker.confirm_healthy()?;
            filtered_runtime = Some((launcher, broker));
        }
        for protocol in &options.protocols {
            let fixture = Fixture::start(*protocol, filtered_runtime.as_ref().map(|(_, b)| b))?;
            let mut command = Command::new(&executable);
            command
                .arg("worker")
                .arg("--protocol")
                .arg(
                    protocol
                        .to_possible_value()
                        .expect("protocol value")
                        .get_name(),
                )
                .arg("--target")
                .arg(fixture.target.to_string())
                .arg("--iterations")
                .arg(options.iterations.to_string())
                .arg("--warmup")
                .arg(options.warmup.to_string())
                .arg("--concurrency")
                .arg(options.concurrency.to_string())
                .arg("--payload-bytes")
                .arg(options.payload_bytes.to_string())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit());
            // The load only applies to the filtered layer: its purpose is to
            // put the broker's connect-time identity resolution behind the
            // measured mediation path.
            let load = if background_cold_connects > 0 && matches!(layer, Layer::Filtered) {
                let (launcher, broker) = filtered_runtime.as_ref().expect("filtered runtime");
                Some(ColdConnectLoad::start(
                    launcher,
                    broker,
                    &executable,
                    background_cold_connects,
                )?)
            } else {
                None
            };
            let baseline_rounds = load.as_ref().map_or(0, ColdConnectLoad::rounds_completed);
            // Capture the worker result without unwrapping it: neither a
            // launcher failure nor a worker failure may skip the load
            // teardown below.
            let output = match layer {
                Layer::Native => command.output().map_err(anyhow::Error::from),
                Layer::Filtered => filtered_runtime
                    .as_ref()
                    .expect("filtered runtime")
                    .0
                    .execute(move || command.output())
                    .and_then(|output| output)
                    .map_err(anyhow::Error::from),
            };
            let overlapped_rounds = load
                .as_ref()
                .map_or(0, |load| load.rounds_completed() - baseline_rounds);
            // Stop the load before inspecting the worker result so both of
            // its threads are joined on every exit path after it was started.
            if let Some(load) = load {
                load.stop()?;
            }
            let output = output.context("run benchmark worker")?;
            if !output.status.success() {
                bail!("benchmark worker exited with {}", output.status);
            }
            let mut report: BenchmarkReport =
                serde_json::from_slice(&output.stdout).context("decode worker report")?;
            report.layer = layer;
            report.background_cold_connect_rounds = overlapped_rounds;
            reports.push(report);
        }
    }
    Ok(reports)
}

struct Fixture {
    target: Target,
    /// Keeps the file-open fixture alive until its worker finishes; the
    /// socket fixtures own a listener thread instead.
    _file: Option<tempfile::NamedTempFile>,
}

const OPERATION_TIMEOUT: Duration = Duration::from_secs(10);
const START_TIMEOUT: Duration = Duration::from_secs(30);

impl Fixture {
    fn start(protocol: Protocol, _broker: Option<&NetworkBroker>) -> io::Result<Self> {
        match protocol {
            Protocol::TcpConnect => start_tcp_fixture(false),
            Protocol::TcpStream => start_tcp_fixture(true),
            Protocol::FileOpen => start_file_fixture(),
        }
    }
}

fn start_file_fixture() -> io::Result<Fixture> {
    // The measured operation opens and closes an ordinary file, so the
    // filtered layer exercises the broker's open mediation (the provider
    // prefix probe and continue); the fixture only needs to exist.
    let file = tempfile::NamedTempFile::new()?;
    Ok(Fixture {
        target: Target::File(file.path().to_path_buf()),
        _file: Some(file),
    })
}

fn start_tcp_fixture(echo: bool) -> io::Result<Fixture> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    socket.set_reuse_address(true)?;
    socket.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).into())?;
    socket.listen(4_096)?;
    let listener: TcpListener = socket.into();
    let target = listener.local_addr()?;
    thread::Builder::new()
        .name("seccomp-perf-tcp-fixture".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let _ = stream.set_nodelay(true);
                if echo {
                    let _ = thread::Builder::new()
                        .name("seccomp-perf-tcp-echo".into())
                        .spawn(move || {
                            let mut buffer = vec![0_u8; 65_507];
                            while let Ok(length) = stream.read(&mut buffer) {
                                if length == 0 || stream.write_all(&buffer[..length]).is_err() {
                                    break;
                                }
                            }
                        });
                }
            }
        })?;
    Ok(Fixture {
        target: Target::Tcp(target),
        _file: None,
    })
}

/// RFC 5737 TEST-NET-1 endpoint targeted by the background cold-connect load.
/// The address is external to the broker (not loopback, not the metadata
/// service) and reserved, so a connect there can never reach a real network.
/// The filter intercepts the syscall before execution and the load's drain
/// denies it, so no packet is ever sent.
const COLD_CONNECT_TARGET: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 443));

/// How long the decision drain waits between shutdown checks.
const COLD_CONNECT_DRAIN_POLL: Duration = Duration::from_millis(100);

/// State shared by the load driver, the decision drain, and the harness
/// thread that starts and stops them.
#[derive(Default)]
struct ColdConnectState {
    /// When set, the driver stops taking new rounds.
    stop: AtomicBool,
    /// When set, the driver thread has been joined and the drain may exit
    /// once the queue is idle.
    driver_finished: AtomicBool,
    rounds: AtomicU64,
    failure: Mutex<Option<String>>,
}

impl ColdConnectState {
    /// Record the first failure and request shutdown.
    fn fail(&self, message: String) {
        self.stop.store(true, Ordering::Release);
        let mut failure = self
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        failure.get_or_insert(message);
    }
}

/// Filtered-only background load: a sequence of cold external TCP connects
/// whose connect-time identity resolution (a full SHA-256 of a fresh
/// executable copy) contends with the measured mediation path exactly as a
/// real cold connect would (serialized on the broker thread before the
/// worker move, on per-connect workers after).
struct ColdConnectLoad {
    state: Arc<ColdConnectState>,
    driver: thread::JoinHandle<()>,
    drain: thread::JoinHandle<()>,
}

impl ColdConnectLoad {
    /// Start the load. The driver thread is spawned from a launcher job that
    /// returns immediately, so the launcher thread stays free to run the
    /// measurement child concurrently: a thread spawned by the filtered
    /// launcher thread inherits the seccomp filter, and so does every child
    /// the driver execs.
    fn start(
        launcher: &workload_launcher::WorkloadLauncher,
        broker: &NetworkBroker,
        executable: &Path,
        rounds: u64,
    ) -> io::Result<Self> {
        let state = Arc::new(ColdConnectState::default());
        let driver_state = Arc::clone(&state);
        let driver_executable = executable.to_path_buf();
        let driver = launcher.execute(move || {
            thread::Builder::new()
                .name("seccomp-perf-cold-connect".into())
                .spawn(move || drive_cold_connects(driver_executable, rounds, driver_state))
        })??;
        let drain_state = Arc::clone(&state);
        let drain_broker = broker.clone();
        let drain = match thread::Builder::new()
            .name("seccomp-perf-cold-drain".into())
            .spawn(move || drain_pending_opens(drain_broker, drain_state))
        {
            Ok(drain) => drain,
            Err(error) => {
                // The driver would keep connecting with nobody answering its
                // queued opens, holding each out to the broker's decision
                // timeout; stop it and join before surfacing the failure.
                state.stop.store(true, Ordering::Release);
                let _ = driver.join();
                return Err(error);
            }
        };
        Ok(Self {
            state,
            driver,
            drain,
        })
    }

    /// Cold-connect rounds the driver has completed so far.
    fn rounds_completed(&self) -> u64 {
        self.state.rounds.load(Ordering::Acquire)
    }

    /// Stop the load and join both of its threads. The drain keeps answering
    /// while the driver finishes its in-flight round, so the driver's last
    /// probe is never left waiting out the broker's decision timeout.
    fn stop(self) -> anyhow::Result<()> {
        self.state.stop.store(true, Ordering::Release);
        let driver = self.driver.join();
        // The drain only exits once the driver has finished, so mark it even
        // when the join failed. The drain is joined before the driver failure
        // is surfaced: returning early would abandon it, leaving a drain panic
        // unobserved and the thread detached.
        self.state.driver_finished.store(true, Ordering::Release);
        let drain = self.drain.join();
        driver.map_err(|_| anyhow::anyhow!("cold-connect load driver panicked"))?;
        drain.map_err(|_| anyhow::anyhow!("cold-connect decision drain panicked"))?;
        let failure = self
            .state
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        match failure {
            Some(failure) => bail!("background cold-connect load failed: {failure}"),
            None => Ok(()),
        }
    }
}

/// Run cold-connect rounds until the budget is exhausted or the load is
/// stopped. Runs on a filtered thread, so every probe child it execs makes
/// the broker resolve (and cold hash) a fresh executable.
fn drive_cold_connects(executable: PathBuf, budget: u64, state: Arc<ColdConnectState>) {
    while !state.stop.load(Ordering::Acquire) && state.rounds.load(Ordering::Acquire) < budget {
        if let Err(error) = one_cold_connect_round(&executable) {
            state.fail(format!("{error}"));
            return;
        }
        state.rounds.fetch_add(1, Ordering::AcqRel);
    }
}

fn one_cold_connect_round(executable: &Path) -> io::Result<()> {
    // A fresh inode per round forces a digest-cache miss, so the broker
    // cold-hashes the connecting binary every time. fs::copy preserves the
    // executable's permission bits, and the copy lives in tmpfs, so repeated
    // rounds never touch real disk.
    let copy = tempfile::NamedTempFile::new()?;
    std::fs::copy(executable, copy.path())?;
    // exec refuses a file that is open for writing (ETXTBSY), so release the
    // temp file's own handle and keep only its path; the copy is deleted when
    // the child has exited and this round ends.
    let copy = copy.into_temp_path();
    let mut child = Command::new(&*copy)
        .arg("cold-connect")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()?;
    let status = child.wait()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "cold-connect probe exited with {status}"
        )));
    }
    Ok(())
}

/// Answer every queued external TCP open with a fast denial, so each load
/// round returns promptly instead of holding the broker's decision timeout.
/// Runs unfiltered on its own thread, like a supervisor would.
fn drain_pending_opens(broker: NetworkBroker, state: Arc<ColdConnectState>) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            state.fail(format!("build cold-connect drain runtime: {error}"));
            return;
        }
    };
    loop {
        // Poll for shutdown instead of blocking forever; a queued open still
        // wakes the accept immediately.
        let pending = match runtime.block_on(async {
            tokio::time::timeout(COLD_CONNECT_DRAIN_POLL, broker.accept()).await
        }) {
            Ok(Ok(pending)) => pending,
            Ok(Err(error)) => {
                state.fail(format!("accept queued TCP open: {error}"));
                break;
            }
            Err(_) => {
                if state.stop.load(Ordering::Acquire)
                    && state.driver_finished.load(Ordering::Acquire)
                {
                    break;
                }
                continue;
            }
        };
        if let Err(error) = pending.decide(TcpOpenDecision::Denied(TcpOpenDenial::PolicyDenied)) {
            state.fail(format!("deny queued TCP open: {error}"));
            break;
        }
    }
}

/// Perform one mediated external connect for the background load.
///
/// The drain answers the queued open with a policy denial, which reaches the
/// blocked syscall as EACCES; any other outcome means the load is not being
/// mediated as designed.
pub fn run_cold_connect_probe() -> anyhow::Result<()> {
    match TcpStream::connect_timeout(&COLD_CONNECT_TARGET, OPERATION_TIMEOUT) {
        Err(error) if error.raw_os_error() == Some(libc::EACCES) => Ok(()),
        Err(error) => bail!("cold-connect probe to {COLD_CONNECT_TARGET} failed: {error}"),
        Ok(stream) => {
            drop(stream);
            bail!("cold-connect probe to {COLD_CONNECT_TARGET} completed");
        }
    }
}

#[allow(clippy::cast_precision_loss)]
pub fn run_worker(
    protocol: Protocol,
    target: Target,
    iterations: u64,
    warmup: u64,
    concurrency: usize,
    payload_bytes: usize,
) -> anyhow::Result<BenchmarkReport> {
    let preparation_deadline = Instant::now() + START_TIMEOUT;
    let (sender, receiver) = mpsc::channel();
    let mut threads = Vec::with_capacity(concurrency);
    let mut starters = Vec::with_capacity(concurrency);
    let mut readiness = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let sender = sender.clone();
        let target = target.clone();
        let (start_tx, start_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel();
        starters.push(start_tx);
        readiness.push(ready_rx);
        threads.push(thread::spawn(move || {
            let result = worker_loop(
                WorkerOptions {
                    protocol,
                    target,
                    iterations,
                    warmup,
                    payload_bytes,
                    preparation_deadline,
                },
                start_rx,
                ready_tx,
            );
            let _ = sender.send(result);
        }));
    }
    drop(sender);
    let preparation = readiness.into_iter().try_for_each(|ready| {
        ready
            .recv_timeout(preparation_deadline.saturating_duration_since(Instant::now()))
            .context("benchmark worker did not finish preparation")?
            .map_err(anyhow::Error::msg)
    });
    if let Err(error) = preparation {
        // Releasing the senders wakes workers that completed preparation while
        // a peer failed, so every thread can be joined without hanging.
        drop(starters);
        for worker in threads {
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("worker panicked"))?;
        }
        return Err(error);
    }
    let started = Instant::now();
    for starter in starters {
        starter
            .send(())
            .context("benchmark worker exited before measurement")?;
    }
    let mut samples = Vec::new();
    for result in receiver {
        samples.extend(result?);
    }
    let elapsed = started.elapsed();
    for worker in threads {
        worker
            .join()
            .map_err(|_| anyhow::anyhow!("worker panicked"))?;
    }
    samples.sort_unstable();
    let operations = iterations.saturating_mul(concurrency as u64);
    let seconds = elapsed.as_secs_f64();
    Ok(BenchmarkReport {
        layer: Layer::Native,
        protocol,
        iterations: operations,
        concurrency,
        payload_bytes,
        background_cold_connect_rounds: 0,
        capability_scope: protocol.capability_scope().to_string(),
        elapsed_ms: seconds * 1_000.0,
        operations_per_second: operations as f64 / seconds,
        throughput_mbit_per_second: throughput_mbit_per_second(
            protocol,
            operations,
            payload_bytes,
            seconds,
        ),
        latency_ns_p50: percentile(&samples, 50),
        latency_ns_p95: percentile(&samples, 95),
        latency_ns_p99: percentile(&samples, 99),
    })
}

/// Report application bytes transferred by the measured operation. A TCP
/// stream operation writes one payload and reads its echo, so both directions
/// count. A connect-only or file-open operation transfers no application
/// payload.
#[allow(clippy::cast_precision_loss)]
fn throughput_mbit_per_second(
    protocol: Protocol,
    operations: u64,
    payload_bytes: usize,
    seconds: f64,
) -> f64 {
    let bytes_per_operation = match protocol {
        Protocol::TcpConnect | Protocol::FileOpen => 0,
        Protocol::TcpStream => payload_bytes.saturating_mul(2),
    };
    operations as f64 * bytes_per_operation as f64 * 8.0 / seconds / 1_000_000.0
}

impl Protocol {
    const fn capability_scope(self) -> &'static str {
        match self {
            Self::TcpConnect => "implemented local TCP socket/connect interception",
            Self::TcpStream => "implemented established TCP fast path",
            Self::FileOpen => "implemented ordinary file open mediation",
        }
    }
}

#[derive(Clone)]
struct WorkerOptions {
    protocol: Protocol,
    target: Target,
    iterations: u64,
    warmup: u64,
    payload_bytes: usize,
    preparation_deadline: Instant,
}

fn worker_loop(
    options: WorkerOptions,
    start: mpsc::Receiver<()>,
    ready: mpsc::Sender<Result<(), String>>,
) -> anyhow::Result<Vec<u64>> {
    let WorkerOptions {
        protocol,
        target,
        iterations,
        warmup,
        payload_bytes,
        preparation_deadline,
    } = options;
    let prepared = (|| -> anyhow::Result<_> {
        let payload = vec![0x5a; payload_bytes];
        let mut tcp = if matches!(protocol, Protocol::TcpStream) {
            Some(connect(&target)?)
        } else {
            None
        };
        let mut response = vec![0_u8; payload_bytes];
        for _ in 0..warmup {
            if Instant::now() >= preparation_deadline {
                bail!("benchmark warmup exceeded preparation deadline");
            }
            one_operation(protocol, &target, &payload, &mut response, tcp.as_mut())?;
        }
        Ok((payload, response, tcp))
    })();
    let (payload, mut response, mut tcp) = match prepared {
        Ok(prepared) => {
            ready
                .send(Ok(()))
                .context("benchmark coordinator exited during preparation")?;
            prepared
        }
        Err(error) => {
            let message = format!("{error:#}");
            let _ = ready.send(Err(message));
            return Err(error);
        }
    };
    start.recv().context("benchmark measurement cancelled")?;
    let mut samples = Vec::with_capacity(usize::try_from(iterations).unwrap_or(0));
    for _ in 0..iterations {
        let started = Instant::now();
        one_operation(protocol, &target, &payload, &mut response, tcp.as_mut())?;
        samples.push(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
    }
    Ok(samples)
}

fn one_operation(
    protocol: Protocol,
    target: &Target,
    payload: &[u8],
    response: &mut [u8],
    tcp: Option<&mut TcpStream>,
) -> io::Result<()> {
    match protocol {
        Protocol::TcpConnect => {
            connect(target)?;
        }
        Protocol::TcpStream => {
            let stream = tcp.expect("TCP stream initialized");
            stream.write_all(payload)?;
            stream.read_exact(response)?;
        }
        Protocol::FileOpen => {
            // Open and close an ordinary file. Under the filter this measures
            // the broker's open mediation: the provider prefix probe and the
            // continue response, with no supervisor decision involved.
            drop(File::open(target.file()?)?);
        }
    }
    Ok(())
}

fn connect(target: &Target) -> io::Result<TcpStream> {
    let address = target.tcp()?;
    let stream = TcpStream::connect_timeout(&address, OPERATION_TIMEOUT)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(OPERATION_TIMEOUT))?;
    stream.set_write_timeout(Some(OPERATION_TIMEOUT))?;
    Ok(stream)
}

fn percentile(samples: &[u64], percentile: usize) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let index = (samples.len() - 1) * percentile / 100;
    samples[index]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_are_stable() {
        let samples = (1..=100).collect::<Vec<_>>();
        assert_eq!(percentile(&samples, 50), 50);
        assert_eq!(percentile(&samples, 95), 95);
        assert_eq!(percentile(&samples, 99), 99);
    }

    #[test]
    fn tcp_connect_never_reports_payload_throughput() {
        let small_payload = throughput_mbit_per_second(Protocol::TcpConnect, 1_000, 64, 1.0);
        let large_payload = throughput_mbit_per_second(Protocol::TcpConnect, 1_000, 65_507, 1.0);
        assert!(small_payload.abs() < f64::EPSILON);
        assert!(large_payload.abs() < f64::EPSILON);
    }

    #[test]
    fn tcp_stream_counts_request_and_echo_bytes() {
        let throughput = throughput_mbit_per_second(Protocol::TcpStream, 1_000, 64, 1.0);
        assert!((throughput - 1.024).abs() < f64::EPSILON);
    }

    #[test]
    fn file_open_never_reports_payload_throughput() {
        let small_payload = throughput_mbit_per_second(Protocol::FileOpen, 1_000, 64, 1.0);
        let large_payload = throughput_mbit_per_second(Protocol::FileOpen, 1_000, 65_507, 1.0);
        assert!(small_payload.abs() < f64::EPSILON);
        assert!(large_payload.abs() < f64::EPSILON);
    }

    #[test]
    fn targets_parse_per_protocol() {
        let target = Target::parse(Protocol::FileOpen, "/tmp/seccomp-perf-fixture")
            .expect("parse file-open target");
        assert!(
            matches!(target, Target::File(ref path) if path == Path::new("/tmp/seccomp-perf-fixture"))
        );

        let target =
            Target::parse(Protocol::TcpConnect, "127.0.0.1:8080").expect("parse tcp target");
        assert!(matches!(target, Target::Tcp(address) if address.port() == 8080));

        assert!(Target::parse(Protocol::TcpStream, "not a socket address").is_err());
    }

    #[test]
    fn file_open_worker_measures_operations() {
        let file = tempfile::NamedTempFile::new().expect("create fixture file");
        let report = run_worker(
            Protocol::FileOpen,
            Target::File(file.path().to_path_buf()),
            4,
            1,
            2,
            8,
        )
        .expect("run file-open worker");
        assert_eq!(report.protocol, Protocol::FileOpen);
        assert_eq!(report.iterations, 8);
        assert_eq!(report.concurrency, 2);
    }

    #[test]
    fn preparation_failure_does_not_wait_for_other_workers() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("test listener address");
        drop(listener);

        assert!(run_worker(Protocol::TcpStream, Target::Tcp(address), 1, 1, 2, 8).is_err());
    }

    #[test]
    fn background_cold_connects_require_the_filtered_layer() {
        let options = BenchmarkOptions {
            layers: vec![Layer::Native],
            protocols: vec![Protocol::FileOpen],
            iterations: 1,
            warmup: 0,
            concurrency: 1,
            payload_bytes: 8,
            background_cold_connects: 1,
        };
        let error = run(options).expect_err("native layer cannot carry the load");
        assert!(format!("{error:#}").contains("filtered layer"));
    }

    #[test]
    fn driver_panic_still_joins_the_drain() {
        let state = Arc::new(ColdConnectState::default());
        state.stop.store(true, Ordering::Release);
        // A drain shaped like the real one: it exits only once the driver has
        // been joined and marked finished, then records its completion where
        // the test can see it.
        let drain_state = Arc::clone(&state);
        let drained = Arc::new(AtomicBool::new(false));
        let drained_drain = Arc::clone(&drained);
        let drain = thread::Builder::new()
            .name("seccomp-perf-cold-drain".into())
            .spawn(move || {
                while !drain_state.driver_finished.load(Ordering::Acquire) {
                    thread::sleep(COLD_CONNECT_DRAIN_POLL);
                }
                // The buggy stop returns the driver failure without joining
                // the drain; only a stop still blocked in its join is
                // guaranteed to observe this.
                thread::sleep(2 * COLD_CONNECT_DRAIN_POLL);
                drained_drain.store(true, Ordering::Release);
            })
            .expect("spawn cold-connect drain");
        let driver = thread::Builder::new()
            .name("seccomp-perf-cold-connect".into())
            .spawn(|| panic!("forced driver panic"))
            .expect("spawn cold-connect driver");
        let load = ColdConnectLoad {
            state,
            driver,
            drain,
        };
        let error = load.stop().expect_err("driver panic must surface");
        assert!(format!("{error:#}").contains("driver panicked"));
        assert!(
            drained.load(Ordering::Acquire),
            "stop returned before the decision drain was joined"
        );
    }

    #[test]
    fn cold_connect_load_without_rounds_stops_cleanly() {
        let (launcher, listener) = workload_launcher::start().expect("start workload launcher");
        let broker = NetworkBroker::start_for_test(listener).expect("start network broker");
        broker.confirm_healthy().expect("confirm broker health");
        let executable = std::env::current_exe().expect("resolve test executable");
        let load = ColdConnectLoad::start(&launcher, &broker, &executable, 0).expect("start load");
        assert_eq!(load.rounds_completed(), 0);
        load.stop().expect("stop load");
    }
}
