// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in microbenchmarks for the production seccomp network listener.

use std::fmt;
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::linux::workload_launcher;
use anyhow::{Context as _, bail};
use clap::ValueEnum;
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
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BenchmarkReport {
    pub layer: Layer,
    pub protocol: Protocol,
    pub iterations: u64,
    pub concurrency: usize,
    pub payload_bytes: usize,
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

    let executable = std::env::current_exe().context("resolve benchmark executable")?;
    let mut reports = Vec::new();
    let mut filtered_runtime = None;
    for layer in options.layers {
        if matches!(layer, Layer::Filtered) && filtered_runtime.is_none() {
            let (launcher, listener) = workload_launcher::start()?;
            let broker = NetworkBroker::start_for_test(listener)?;
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
            let output = match layer {
                Layer::Native => command.output(),
                Layer::Filtered => filtered_runtime
                    .as_ref()
                    .expect("filtered runtime")
                    .0
                    .execute(move || command.output())?,
            }
            .context("run benchmark worker")?;
            if !output.status.success() {
                bail!("benchmark worker exited with {}", output.status);
            }
            let mut report: BenchmarkReport =
                serde_json::from_slice(&output.stdout).context("decode worker report")?;
            report.layer = layer;
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
}
