// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in microbenchmarks for the production seccomp network listener.
//!
//! Besides the production broker, one harness-only layer attributes the cost
//! of a workload file open. It exists only under this feature and adds no
//! switch to the production runtime: `notify-only` installs the production
//! filter and answers every notification with "continue" from a loop that
//! reads no workload memory. Against `filtered`, it separates the
//! notification round trip from the broker's path-prefix copy.
//!
//! `--landlock` additionally confines the worker with a Landlock domain, to
//! show what the filesystem hook adds to an open in any layer.
//!
//! `--provider-file` makes the file protocols open a managed provider file,
//! which the `filtered` layer's broker serves by injection, instead of an
//! ordinary file the kernel opens. The `mixed-*` protocols run file opens and
//! TCP operations at the same time and report each class separately.

use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
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
    /// No seccomp filter.
    Native,
    /// The production listener and broker; every file open notifies.
    Filtered,
    /// Harness only: the production filter answered by a loop that continues
    /// every notification without reading workload memory.
    NotifyOnly,
}

impl Layer {
    /// `all` is the original native/filtered pair, so existing invocations
    /// keep measuring what they measured. `attribution` adds the layer that
    /// separates the parts of a file open.
    pub fn selection(value: &str) -> anyhow::Result<Vec<Self>> {
        match value {
            "all" => Ok(vec![Self::Native, Self::Filtered]),
            "attribution" => Ok(vec![Self::Native, Self::NotifyOnly, Self::Filtered]),
            "native" => Ok(vec![Self::Native]),
            "filtered" => Ok(vec![Self::Filtered]),
            "notify-only" => Ok(vec![Self::NotifyOnly]),
            _ => bail!("unknown layer {value}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    TcpConnect,
    TcpStream,
    /// Open a file read-only and close it.
    FileOpenClose,
    /// Open a file read-only, read `payload-bytes` from it, and close it.
    FileOpenRead,
    /// Read `payload-bytes` from one descriptor opened before measurement.
    FileRead,
    /// `stat` a file by path; the broker answers a provider path.
    FileStat,
    /// `file-open-read` and `tcp-connect` workers running at the same time.
    MixedFileTcpConnect,
    /// `file-open-read` and `tcp-stream` workers running at the same time.
    MixedFileTcpStream,
}

impl Protocol {
    /// `all` is the original TCP pair; `file` is the file-open attribution
    /// set; `mixed` is the two contention workloads.
    pub fn selection(value: &str) -> anyhow::Result<Vec<Self>> {
        match value {
            "all" => Ok(vec![Self::TcpConnect, Self::TcpStream]),
            "mixed" => Ok(vec![Self::MixedFileTcpConnect, Self::MixedFileTcpStream]),
            "file" => Ok(vec![
                Self::FileOpenClose,
                Self::FileOpenRead,
                Self::FileRead,
                Self::FileStat,
            ]),
            _ => Ok(vec![
                Self::from_str(value, true).map_err(|error| anyhow::anyhow!("{error}"))?,
            ]),
        }
    }
}

#[derive(Debug)]
pub struct BenchmarkOptions {
    pub layers: Vec<Layer>,
    pub protocols: Vec<Protocol>,
    pub iterations: u64,
    pub warmup: u64,
    pub concurrency: usize,
    pub payload_bytes: usize,
    /// Confine each worker with a Landlock domain before it measures.
    pub landlock: bool,
    /// File the file protocols open.
    pub file_path: PathBuf,
    /// Request the kernel's synchronous-wakeup hint on each filtered layer's
    /// listener. Fails where the kernel does not support it.
    pub sync_wakeup: bool,
    /// Threads answering notifications in the notify-only layer.
    pub notify_receivers: usize,
    /// Open a managed provider file of this many bytes instead of
    /// `file_path`. Only the filtered layer's virtual delivery serves one.
    pub provider_file_bytes: Option<usize>,
}

/// The managed provider file `--provider-file` publishes and opens.
pub const PROVIDER_FILE_PATH: &str = "/run/openshell/providers/perf/config.toml";
/// The largest provider file the broker accepts.
const MAX_PROVIDER_FILE_BYTES: usize = 65_536;

/// The content of the synthetic provider file: the same for every run of a
/// given size, so a worker can check what it reads without being told.
fn synthetic_provider_file(bytes: usize) -> String {
    use std::fmt::Write as _;
    let mut content = String::with_capacity(bytes + 64);
    let mut line = 0_usize;
    while content.len() < bytes {
        let _ = writeln!(content, "setting_{line:06} = \"openshell-perf-{line:06}\"");
        line += 1;
    }
    // ASCII only, so any byte offset is a character boundary.
    content.truncate(bytes);
    content
}

/// Task-memory copies the broker made while one worker ran, by the backend
/// that served them.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct TaskMemoryReads {
    /// Copies `process_vm_readv` completed.
    pub process_vm: u64,
    /// Copies that fell back to `/proc/<tid>/mem`.
    pub proc_mem_fallback: u64,
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
    #[serde(default)]
    pub latency_ns_max: u64,
    /// Whether the worker ran inside a Landlock domain.
    #[serde(default)]
    pub landlock: bool,
    /// Broker task-memory copies during this run. Absent for layers without
    /// the production broker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_memory_reads: Option<TaskMemoryReads>,
    /// Whether the layer's listener used the synchronous-wakeup hint.
    #[serde(default)]
    pub sync_wakeup: bool,
    /// Threads that answered notifications, for the notify-only layer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_receivers: Option<usize>,
    /// The file a file operation opened. Absent for TCP operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<PathBuf>,
    /// Size of the managed provider file the broker served by injection.
    /// Absent when the file was an ordinary one the kernel opened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_file_bytes: Option<usize>,
    /// For a mixed protocol: the class of operation this report covers.
    /// Every other field then describes that class alone, measured while
    /// the other class ran. `iterations` is what the class completed in the
    /// shared window, not a requested count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<Protocol>,
    /// For a mixed protocol: threads that ran this class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class_workers: Option<usize>,
}

/// A launcher whose children inherit one layer's filter, with whatever
/// answers its notifications.
struct LayerRuntime {
    launcher: workload_launcher::WorkloadLauncher,
    /// Present when the production broker serves the layer.
    broker: Option<NetworkBroker>,
}

impl LayerRuntime {
    fn start(
        layer: Layer,
        sync_wakeup: bool,
        notify_receivers: usize,
    ) -> anyhow::Result<Option<Self>> {
        let prepare = |listener: &crate::linux::seccomp_notify::NotificationListener| {
            if sync_wakeup {
                listener
                    .enable_sync_wakeup()
                    .context("request synchronous listener wakeup")?;
            }
            anyhow::Ok(())
        };
        match layer {
            Layer::Native => Ok(None),
            Layer::Filtered => {
                let (launcher, listener) = workload_launcher::start()?;
                prepare(&listener)?;
                let broker = NetworkBroker::start_for_test(listener)?;
                broker.confirm_healthy()?;
                Ok(Some(Self {
                    launcher,
                    broker: Some(broker),
                }))
            }
            Layer::NotifyOnly => {
                let (launcher, listener) = workload_launcher::start()?;
                prepare(&listener)?;
                let listener = Arc::new(listener);
                // The kernel hands each notification to one receiver.
                for _ in 0..notify_receivers {
                    let listener = Arc::clone(&listener);
                    thread::Builder::new()
                        .name("seccomp-perf-notify-only".into())
                        .spawn(move || {
                            loop {
                                match listener.receive() {
                                    Ok(notification) => {
                                        // The notifying task may have died.
                                        let _ = listener.respond_continue(notification.id);
                                    }
                                    Err(error)
                                        if error.kind() == io::ErrorKind::Interrupted
                                            || error.raw_os_error() == Some(libc::ENOENT) => {}
                                    Err(_) => break,
                                }
                            }
                        })
                        .context("start notify-only responder")?;
                }
                Ok(Some(Self {
                    launcher,
                    broker: None,
                }))
            }
        }
    }
}

fn task_memory_reads() -> TaskMemoryReads {
    let (process_vm, proc_mem_fallback) = crate::linux::task_memory::read_backend_counts();
    TaskMemoryReads {
        process_vm,
        proc_mem_fallback,
    }
}

pub fn run(options: BenchmarkOptions) -> anyhow::Result<Vec<BenchmarkReport>> {
    if options.iterations == 0 || options.concurrency == 0 || options.notify_receivers == 0 {
        bail!("iterations, concurrency, and notify-receivers must be greater than zero");
    }
    if options.payload_bytes == 0 || options.payload_bytes > 65_507 {
        bail!("payload-bytes must be between 1 and 65507");
    }
    if let Some(bytes) = options.provider_file_bytes {
        // Refuse rather than measure an ordinary file under another name:
        // no other layer serves a provider path by injection.
        if bytes == 0 || bytes > MAX_PROVIDER_FILE_BYTES {
            bail!("provider-file-bytes must be between 1 and {MAX_PROVIDER_FILE_BYTES}");
        }
        if !options
            .layers
            .iter()
            .all(|layer| matches!(layer, Layer::Filtered))
        {
            bail!(
                "--provider-file measures virtual provider-file delivery, which only the filtered layer has; pass --layer filtered"
            );
        }
        if !options
            .protocols
            .iter()
            .all(|protocol| protocol.opens_file())
        {
            bail!("--provider-file applies to the file and mixed protocols only");
        }
    }
    let file_path = options
        .provider_file_bytes
        .map_or(options.file_path, |_| PathBuf::from(PROVIDER_FILE_PATH));

    let executable = std::env::current_exe().context("resolve benchmark executable")?;
    let mut reports = Vec::new();
    for layer in options.layers {
        // Each layer has its own launcher thread and filter.
        let runtime = LayerRuntime::start(layer, options.sync_wakeup, options.notify_receivers)?;
        if let Some(bytes) = options.provider_file_bytes {
            runtime
                .as_ref()
                .and_then(|runtime| runtime.broker.as_ref())
                .context("the layer has no broker to serve a provider file")?
                .provider_files()
                .replace(std::collections::HashMap::from([(
                    PROVIDER_FILE_PATH.to_string(),
                    synthetic_provider_file(bytes),
                )]))
                .context("publish the synthetic provider file")?;
        }
        for protocol in &options.protocols {
            if matches!(layer, Layer::NotifyOnly) && !protocol.is_file() {
                bail!(
                    "the notify-only layer continues every syscall and measures file protocols only"
                );
            }
            let fixture = Fixture::start(*protocol)?;
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
                .arg("--file-path")
                .arg(&file_path)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit());
            if let Some(bytes) = options.provider_file_bytes {
                command.arg("--provider-file-bytes").arg(bytes.to_string());
            }
            if options.landlock {
                command.arg("--landlock");
            }
            let before = task_memory_reads();
            let output = match &runtime {
                None => command.output(),
                Some(runtime) => runtime.launcher.execute(move || command.output())?,
            }
            .context("run benchmark worker")?;
            if !output.status.success() {
                bail!("benchmark worker exited with {}", output.status);
            }
            let after = task_memory_reads();
            // One report, or one per class of a mixed protocol. The
            // task-memory copies are those of the whole worker run.
            let worker_reports = output
                .stdout
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .map(serde_json::from_slice::<BenchmarkReport>)
                .collect::<Result<Vec<_>, _>>()
                .context("decode worker report")?;
            if worker_reports.is_empty() {
                bail!("benchmark worker reported nothing");
            }
            for mut report in worker_reports {
                report.layer = layer;
                report.sync_wakeup = options.sync_wakeup && runtime.is_some();
                report.notify_receivers =
                    matches!(layer, Layer::NotifyOnly).then_some(options.notify_receivers);
                report.task_memory_reads = runtime
                    .as_ref()
                    .and_then(|runtime| runtime.broker.as_ref())
                    .map(|_| TaskMemoryReads {
                        process_vm: after.process_vm - before.process_vm,
                        proc_mem_fallback: after.proc_mem_fallback - before.proc_mem_fallback,
                    });
                reports.push(report);
            }
        }
    }
    Ok(reports)
}

struct Fixture {
    target: SocketAddr,
}

const OPERATION_TIMEOUT: Duration = Duration::from_secs(10);
const START_TIMEOUT: Duration = Duration::from_secs(30);

impl Fixture {
    fn start(protocol: Protocol) -> io::Result<Self> {
        match protocol {
            Protocol::TcpConnect | Protocol::MixedFileTcpConnect => start_tcp_fixture(false),
            Protocol::TcpStream | Protocol::MixedFileTcpStream => start_tcp_fixture(true),
            // File protocols need no peer; the worker ignores the target.
            Protocol::FileOpenClose
            | Protocol::FileOpenRead
            | Protocol::FileRead
            | Protocol::FileStat => Ok(Self {
                target: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            }),
        }
    }
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
    Ok(Fixture { target })
}

/// What one worker process measures.
#[derive(Clone, Debug)]
pub struct WorkerRun {
    pub protocol: Protocol,
    pub target: SocketAddr,
    pub iterations: u64,
    pub warmup: u64,
    pub concurrency: usize,
    pub payload_bytes: usize,
    pub landlock: bool,
    pub file_path: PathBuf,
    /// `file_path` is the synthetic provider file of this size; verify it.
    pub provider_file_bytes: Option<usize>,
}

/// Confine the calling process with a Landlock domain that handles every
/// ABI v3 filesystem right and allows them all beneath `/`.
///
/// Nothing is denied, so the worker behaves as before; each open now runs
/// the Landlock hook, which is what this measures. The production baseline
/// allows each root entry separately instead, which walks the same
/// hierarchy.
fn confine_with_landlock() -> anyhow::Result<()> {
    use landlock::{
        ABI, Access as _, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr as _,
        RulesetCreatedAttr as _, RulesetStatus,
    };
    let access = AccessFs::from_all(ABI::V3);
    let status = Ruleset::default()
        .handle_access(access)
        .context("handle Landlock filesystem access")?
        .create()
        .context("create Landlock ruleset")?
        .add_rule(PathBeneath::new(
            PathFd::new("/").context("open filesystem root")?,
            access,
        ))
        .context("allow the root hierarchy")?
        .restrict_self()
        .context("enter Landlock domain")?;
    if status.ruleset != RulesetStatus::FullyEnforced {
        bail!("Landlock ABI v3 is not fully enforced on this kernel");
    }
    Ok(())
}

/// What the workers of a mixed protocol share: every worker keeps operating
/// until the last one has measured its `iterations`, so each class is
/// measured only while the other is running.
struct MixedRun {
    /// Workers that have not yet measured `iterations` operations.
    below_quota: AtomicUsize,
    stop: AtomicBool,
}

/// Ends a mixed run when its worker stops for any reason. A worker that
/// failed or panicked never reaches its quota; without this its peers would
/// wait for it forever.
struct StopMixedRun<'a>(&'a MixedRun);

impl Drop for StopMixedRun<'_> {
    fn drop(&mut self) {
        self.0.stop.store(true, Ordering::Release);
    }
}

/// Latency samples a mixed worker keeps. It keeps operating, and counting,
/// past this many while a slower class finishes.
const MIXED_SAMPLE_LIMIT: usize = 1_000_000;

/// What one worker thread measured.
struct Measured {
    operations: u64,
    samples: Vec<u64>,
}

/// The bytes a read of `payload_bytes` from the benchmark file must return,
/// for runs that check them.
fn expected_read(run: &WorkerRun) -> anyhow::Result<Option<Arc<[u8]>>> {
    let reference = if let Some(bytes) = run.provider_file_bytes {
        // The whole file, against content this worker derives itself.
        let expected = synthetic_provider_file(bytes).into_bytes();
        let served = std::fs::read(&run.file_path).context("read provider file")?;
        if served != expected {
            bail!(
                "provider file {} does not hold the synthetic content",
                run.file_path.display()
            );
        }
        expected
    } else if run.protocol.is_mixed() {
        std::fs::read(&run.file_path).context("read benchmark file")?
    } else {
        // The original protocols on an ordinary file check nothing.
        return Ok(None);
    };
    let length = reference.len().min(run.payload_bytes);
    Ok(Some(Arc::from(&reference[..length])))
}

pub fn run_worker(run: &WorkerRun) -> anyhow::Result<Vec<BenchmarkReport>> {
    let WorkerRun {
        protocol,
        target,
        iterations,
        warmup,
        concurrency,
        payload_bytes,
        landlock,
        ..
    } = *run;
    if landlock {
        confine_with_landlock()?;
    }
    let file_path: Arc<Path> = Arc::from(run.file_path.as_path());
    let expected = expected_read(run)?;
    let classes = protocol.classes();
    let workers = classes.len() * concurrency;
    let mixed = protocol.is_mixed().then(|| {
        Arc::new(MixedRun {
            below_quota: AtomicUsize::new(workers),
            stop: AtomicBool::new(false),
        })
    });
    let preparation_deadline = Instant::now() + START_TIMEOUT;
    let (sender, receiver) = mpsc::channel();
    let mut threads = Vec::with_capacity(workers);
    let mut starters = Vec::with_capacity(workers);
    let mut readiness = Vec::with_capacity(workers);
    for (class, class_protocol) in classes.iter().copied().enumerate() {
        for _ in 0..concurrency {
            let sender = sender.clone();
            let (start_tx, start_rx) = mpsc::channel();
            let (ready_tx, ready_rx) = mpsc::channel();
            starters.push(start_tx);
            readiness.push(ready_rx);
            let options = WorkerOptions {
                protocol: class_protocol,
                target,
                iterations,
                warmup,
                payload_bytes,
                preparation_deadline,
                file_path: Arc::clone(&file_path),
                expected: expected.clone(),
                mixed: mixed.clone(),
            };
            threads.push(thread::spawn(move || {
                let result = worker_loop(&options, start_rx, ready_tx);
                let _ = sender.send((class, result));
            }));
        }
    }
    drop(sender);
    let join = |threads: Vec<thread::JoinHandle<()>>| {
        threads.into_iter().try_for_each(|worker| {
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("worker panicked"))
        })
    };
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
        join(threads)?;
        return Err(error);
    }
    let started = Instant::now();
    for starter in starters {
        starter
            .send(())
            .context("benchmark worker exited before measurement")?;
    }
    // The channel closes once every worker has reported or died. A worker
    // that fails ends a mixed run for its peers, so this never waits on a
    // worker that cannot finish.
    let outcomes = receiver.into_iter().collect::<Vec<_>>();
    let seconds = started.elapsed().as_secs_f64();
    join(threads)?;
    let mut measured = classes
        .iter()
        .map(|_| Measured {
            operations: 0,
            samples: Vec::new(),
        })
        .collect::<Vec<_>>();
    for (class, outcome) in outcomes {
        let worker = outcome?;
        measured[class].operations += worker.operations;
        measured[class].samples.extend(worker.samples);
    }
    Ok(classes
        .iter()
        .zip(measured)
        .map(|(class, measured)| class_report(run, *class, measured, seconds))
        .collect())
}

/// The report of one class of operation: the whole run, or one class of a
/// mixed protocol.
#[allow(clippy::cast_precision_loss)]
fn class_report(
    run: &WorkerRun,
    class: Protocol,
    mut measured: Measured,
    seconds: f64,
) -> BenchmarkReport {
    measured.samples.sort_unstable();
    let samples = &measured.samples;
    let mixed = run.protocol.is_mixed();
    BenchmarkReport {
        layer: Layer::Native,
        protocol: run.protocol,
        iterations: measured.operations,
        concurrency: run.concurrency,
        payload_bytes: run.payload_bytes,
        capability_scope: class.capability_scope().to_string(),
        elapsed_ms: seconds * 1_000.0,
        operations_per_second: measured.operations as f64 / seconds,
        throughput_mbit_per_second: throughput_mbit_per_second(
            class,
            measured.operations,
            run.payload_bytes,
            seconds,
        ),
        latency_ns_p50: percentile(samples, 50),
        latency_ns_p95: percentile(samples, 95),
        latency_ns_p99: percentile(samples, 99),
        latency_ns_max: samples.last().copied().unwrap_or(0),
        landlock: run.landlock,
        task_memory_reads: None,
        sync_wakeup: false,
        notify_receivers: None,
        file_path: class.is_file().then(|| run.file_path.clone()),
        provider_file_bytes: run.provider_file_bytes.filter(|_| class.is_file()),
        class: mixed.then_some(class),
        class_workers: mixed.then_some(run.concurrency),
    }
}

/// Report application bytes transferred by the measured operation. A TCP
/// stream operation writes one payload and reads its echo, so both directions
/// count. A connect-only operation transfers no application payload.
#[allow(clippy::cast_precision_loss)]
fn throughput_mbit_per_second(
    protocol: Protocol,
    operations: u64,
    payload_bytes: usize,
    seconds: f64,
) -> f64 {
    let bytes_per_operation = match protocol {
        // A mixed protocol is reported per class, never as a whole.
        Protocol::TcpConnect
        | Protocol::FileOpenClose
        | Protocol::FileStat
        | Protocol::MixedFileTcpConnect
        | Protocol::MixedFileTcpStream => 0,
        Protocol::TcpStream => payload_bytes.saturating_mul(2),
        Protocol::FileOpenRead | Protocol::FileRead => payload_bytes,
    };
    operations as f64 * bytes_per_operation as f64 * 8.0 / seconds / 1_000_000.0
}

impl Protocol {
    const fn capability_scope(self) -> &'static str {
        match self {
            Self::TcpConnect => "implemented local TCP socket/connect interception",
            Self::TcpStream => "implemented established TCP fast path",
            Self::FileOpenClose => "read-only file open and close",
            Self::FileOpenRead => "read-only file open, one read, and close",
            Self::FileRead => "read on an already-open descriptor; no open is measured",
            Self::FileStat => "stat by path; no descriptor is created",
            Self::MixedFileTcpConnect | Self::MixedFileTcpStream => {
                "file opens and TCP operations at the same time"
            }
        }
    }

    const fn is_mixed(self) -> bool {
        matches!(self, Self::MixedFileTcpConnect | Self::MixedFileTcpStream)
    }

    /// Whether the protocol opens the benchmark file.
    const fn opens_file(self) -> bool {
        self.is_file() || self.is_mixed()
    }

    /// The operations worker threads run: the protocol itself, or the two
    /// classes of a mixed protocol, each on `concurrency` threads.
    fn classes(self) -> Vec<Self> {
        match self {
            Self::MixedFileTcpConnect => vec![Self::FileOpenRead, Self::TcpConnect],
            Self::MixedFileTcpStream => vec![Self::FileOpenRead, Self::TcpStream],
            single => vec![single],
        }
    }

    const fn is_file(self) -> bool {
        matches!(
            self,
            Self::FileOpenClose | Self::FileOpenRead | Self::FileRead | Self::FileStat
        )
    }
}

struct WorkerOptions {
    protocol: Protocol,
    target: SocketAddr,
    iterations: u64,
    warmup: u64,
    payload_bytes: usize,
    preparation_deadline: Instant,
    file_path: Arc<Path>,
    /// What a read of the benchmark file must return, when checked.
    expected: Option<Arc<[u8]>>,
    /// Present for a class of a mixed protocol.
    mixed: Option<Arc<MixedRun>>,
}

/// What one worker thread keeps across operations.
struct Prepared {
    payload: Vec<u8>,
    response: Vec<u8>,
    tcp: Option<TcpStream>,
    /// Opened before measurement for [`Protocol::FileRead`].
    file: Option<File>,
    /// What a file read must return, when checked.
    expected: Option<Arc<[u8]>>,
    /// Whether a TCP echo must equal its request.
    check_echo: bool,
}

fn worker_loop(
    options: &WorkerOptions,
    start: mpsc::Receiver<()>,
    ready: mpsc::Sender<Result<(), String>>,
) -> anyhow::Result<Measured> {
    let WorkerOptions {
        protocol,
        target,
        iterations,
        warmup,
        payload_bytes,
        preparation_deadline,
        ref file_path,
        ref expected,
        ref mixed,
    } = *options;
    let prepared = (|| -> anyhow::Result<_> {
        let mut prepared = Prepared {
            payload: vec![0x5a; payload_bytes],
            response: vec![0_u8; payload_bytes],
            tcp: if matches!(protocol, Protocol::TcpStream) {
                Some(connect(target)?)
            } else {
                None
            },
            file: if matches!(protocol, Protocol::FileRead) {
                Some(File::open(file_path).context("open benchmark file")?)
            } else {
                None
            },
            expected: expected.clone(),
            check_echo: mixed.is_some(),
        };
        for _ in 0..warmup {
            if Instant::now() >= preparation_deadline {
                bail!("benchmark warmup exceeded preparation deadline");
            }
            one_operation(protocol, target, file_path, &mut prepared)?;
        }
        Ok(prepared)
    })();
    let mut prepared = match prepared {
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
    let Some(mixed) = mixed else {
        for _ in 0..iterations {
            let started = Instant::now();
            one_operation(protocol, target, file_path, &mut prepared)?;
            samples.push(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
        }
        return Ok(Measured {
            operations: iterations,
            samples,
        });
    };
    // Keep operating until every worker of both classes has its quota, so
    // no class is measured after the other went idle.
    let _stop = StopMixedRun(mixed);
    let mut operations = 0_u64;
    while !mixed.stop.load(Ordering::Acquire) {
        let started = Instant::now();
        one_operation(protocol, target, file_path, &mut prepared)?;
        if samples.len() < MIXED_SAMPLE_LIMIT {
            samples.push(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
        }
        operations += 1;
        if operations == iterations && mixed.below_quota.fetch_sub(1, Ordering::AcqRel) == 1 {
            mixed.stop.store(true, Ordering::Release);
        }
    }
    Ok(Measured {
        operations,
        samples,
    })
}

fn one_operation(
    protocol: Protocol,
    target: SocketAddr,
    file_path: &Path,
    prepared: &mut Prepared,
) -> io::Result<()> {
    match protocol {
        Protocol::TcpConnect => {
            connect(target)?;
        }
        Protocol::TcpStream => {
            let stream = prepared.tcp.as_mut().expect("TCP stream initialized");
            stream.write_all(&prepared.payload)?;
            stream.read_exact(&mut prepared.response)?;
            if prepared.check_echo && prepared.response != prepared.payload {
                return Err(content_mismatch("TCP echo differs from its request"));
            }
        }
        Protocol::FileOpenClose => {
            drop(File::open(file_path)?);
        }
        Protocol::FileOpenRead => {
            let mut file = File::open(file_path)?;
            let read = file.read(&mut prepared.response)?;
            require_data(read)?;
            require_expected(&prepared.response[..read], prepared.expected.as_deref())?;
        }
        Protocol::FileRead => {
            let file = prepared.file.as_ref().expect("benchmark file opened");
            let read = file.read_at(&mut prepared.response, 0)?;
            require_data(read)?;
            require_expected(&prepared.response[..read], prepared.expected.as_deref())?;
        }
        Protocol::FileStat => {
            let metadata = std::fs::metadata(file_path)?;
            if let Some(expected) = prepared.expected.as_deref()
                && metadata.len() < expected.len() as u64
            {
                return Err(content_mismatch(
                    "stat reports a shorter file than expected",
                ));
            }
        }
        Protocol::MixedFileTcpConnect | Protocol::MixedFileTcpStream => {
            unreachable!("a mixed protocol runs as its classes")
        }
    }
    Ok(())
}

fn content_mismatch(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Fail a read whose bytes are not the ones the run established, where it
/// established any.
fn require_expected(read: &[u8], expected: Option<&[u8]>) -> io::Result<()> {
    match expected {
        Some(expected) if read != expected => Err(content_mismatch(
            "benchmark file content changed or is not the expected file",
        )),
        _ => Ok(()),
    }
}

/// A file shorter than the payload still yields a valid operation; an empty
/// one measures nothing.
fn require_data(read: usize) -> io::Result<()> {
    if read == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "benchmark file is empty",
        ));
    }
    Ok(())
}

fn connect(target: SocketAddr) -> io::Result<TcpStream> {
    let stream = TcpStream::connect_timeout(&target, OPERATION_TIMEOUT)?;
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
    fn preparation_failure_does_not_wait_for_other_workers() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("test listener address");
        drop(listener);

        assert!(run_worker(&worker_run(Protocol::TcpStream, address)).is_err());
    }

    fn worker_run(protocol: Protocol, target: SocketAddr) -> WorkerRun {
        WorkerRun {
            protocol,
            target,
            iterations: 1,
            warmup: 1,
            concurrency: 2,
            payload_bytes: 8,
            landlock: false,
            file_path: PathBuf::from("/etc/passwd"),
            provider_file_bytes: None,
        }
    }

    /// The single report of a protocol that is not mixed.
    fn one_report(run: &WorkerRun) -> BenchmarkReport {
        let mut reports = run_worker(run).unwrap();
        assert_eq!(reports.len(), 1);
        reports.pop().unwrap()
    }

    fn options(
        layers: &str,
        protocols: &str,
        provider_file_bytes: Option<usize>,
    ) -> BenchmarkOptions {
        BenchmarkOptions {
            layers: Layer::selection(layers).unwrap(),
            protocols: Protocol::selection(protocols).unwrap(),
            iterations: 1,
            warmup: 0,
            concurrency: 1,
            payload_bytes: 64,
            landlock: false,
            file_path: PathBuf::from("/etc/passwd"),
            sync_wakeup: false,
            notify_receivers: 1,
            provider_file_bytes,
        }
    }

    #[test]
    fn provider_file_runs_refuse_what_cannot_serve_or_open_one() {
        for (layers, protocols, bytes) in [
            // Only the filtered layer injects a provider file.
            ("native", "file", 4_096),
            ("all", "file", 4_096),
            ("attribution", "file", 4_096),
            ("notify-only", "file-open-read", 4_096),
            // Only file operations open one.
            ("filtered", "all", 4_096),
            ("filtered", "tcp-connect", 4_096),
            // The broker's own bounds.
            ("filtered", "file", 0),
            ("filtered", "file", 65_537),
        ] {
            let error = run(options(layers, protocols, Some(bytes)))
                .expect_err("an incompatible provider-file run must be refused");
            assert!(
                error.to_string().contains("provider-file"),
                "{layers} {protocols} {bytes}: {error}"
            );
        }
    }

    #[test]
    fn provider_file_workers_verify_what_they_read() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(&path, synthetic_provider_file(256)).unwrap();
        for protocol in [Protocol::FileOpenRead, Protocol::FileRead] {
            let run = WorkerRun {
                provider_file_bytes: Some(256),
                ..file_run(protocol, &path)
            };
            let report = one_report(&run);
            assert_eq!(report.provider_file_bytes, Some(256));
            assert_eq!(report.file_path.as_deref(), Some(path.as_path()));
            // Any other content is an error, not a measurement.
            let wrong = WorkerRun {
                provider_file_bytes: Some(255),
                ..run
            };
            assert!(run_worker(&wrong).is_err());
        }
    }

    #[test]
    fn mixed_protocols_report_each_class_measured_together() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("data");
        std::fs::write(&path, b"0123456789abcdef").unwrap();
        for (protocol, tcp_class, echo) in [
            (Protocol::MixedFileTcpConnect, Protocol::TcpConnect, false),
            (Protocol::MixedFileTcpStream, Protocol::TcpStream, true),
        ] {
            let fixture = start_tcp_fixture(echo).unwrap();
            let run = WorkerRun {
                iterations: 32,
                warmup: 2,
                concurrency: 2,
                file_path: path.clone(),
                ..worker_run(protocol, fixture.target)
            };
            let reports = run_worker(&run).unwrap();
            assert_eq!(reports.len(), 2, "{protocol:?}");
            let classes = [Protocol::FileOpenRead, tcp_class];
            for (report, class) in reports.iter().zip(classes) {
                assert_eq!(
                    serde_json::to_value(report.protocol).unwrap(),
                    serde_json::to_value(protocol).unwrap()
                );
                assert_eq!(
                    serde_json::to_value(report.class).unwrap(),
                    serde_json::to_value(class).unwrap()
                );
                assert_eq!(report.class_workers, Some(2));
                // Every worker of the class met its quota; a class that
                // finished first kept running until the other did.
                assert!(report.iterations >= 64, "{class:?}: {}", report.iterations);
                assert!(report.operations_per_second > 0.0);
                assert!(report.latency_ns_p50 > 0, "{class:?}");
                assert!(report.latency_ns_p50 <= report.latency_ns_p99);
                assert!(report.latency_ns_p99 <= report.latency_ns_max);
                assert_eq!(report.file_path.is_some(), class.is_file());
            }
            // Both classes were measured over the same window.
            assert!((reports[0].elapsed_ms - reports[1].elapsed_ms).abs() < f64::EPSILON);
        }
    }

    #[test]
    fn a_failing_class_ends_a_mixed_run_instead_of_hanging_it() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("data");
        std::fs::write(&path, b"0123456789abcdef").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let closed = listener.local_addr().expect("test listener address");
        drop(listener);
        // No warmup: the connects fail during measurement, while the file
        // workers, which could never be told to stop otherwise, are running.
        let run = WorkerRun {
            iterations: u64::MAX,
            warmup: 0,
            concurrency: 2,
            file_path: path,
            ..worker_run(Protocol::MixedFileTcpConnect, closed)
        };
        assert!(run_worker(&run).is_err());

        // A worker that panics ends the run the same way.
        let mixed = Arc::new(MixedRun {
            below_quota: AtomicUsize::new(2),
            stop: AtomicBool::new(false),
        });
        let panicking = {
            let mixed = Arc::clone(&mixed);
            thread::spawn(move || {
                let _stop = StopMixedRun(&mixed);
                panic!("worker failure");
            })
        };
        assert!(panicking.join().is_err());
        assert!(mixed.stop.load(Ordering::Acquire));
    }

    fn file_run(protocol: Protocol, path: &Path) -> WorkerRun {
        WorkerRun {
            iterations: 64,
            file_path: path.to_path_buf(),
            ..worker_run(
                protocol,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            )
        }
    }

    #[test]
    fn file_protocols_measure_every_requested_operation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("data");
        std::fs::write(&path, b"0123456789abcdef").unwrap();
        for protocol in [
            Protocol::FileOpenClose,
            Protocol::FileOpenRead,
            Protocol::FileRead,
            Protocol::FileStat,
        ] {
            let report = one_report(&file_run(protocol, &path));
            // Two threads, 64 iterations each.
            assert_eq!(report.iterations, 128, "{protocol:?}");
            assert!(report.latency_ns_p50 > 0, "{protocol:?}");
            assert!(report.latency_ns_p50 <= report.latency_ns_p99);
            assert!(report.latency_ns_p99 <= report.latency_ns_max);
            assert!(!report.landlock);
        }
        // Only a read transfers payload.
        let open_only = throughput_mbit_per_second(Protocol::FileOpenClose, 1_000, 64, 1.0);
        assert!(open_only.abs() < f64::EPSILON);
        assert!(throughput_mbit_per_second(Protocol::FileRead, 1_000, 64, 1.0) > 0.0);

        // A missing file fails every operation; an empty one fails the reads.
        let missing = directory.path().join("missing");
        let empty = directory.path().join("empty");
        std::fs::write(&empty, b"").unwrap();
        for protocol in [
            Protocol::FileOpenClose,
            Protocol::FileOpenRead,
            Protocol::FileRead,
            Protocol::FileStat,
        ] {
            assert!(run_worker(&file_run(protocol, &missing)).is_err());
        }
        for protocol in [Protocol::FileOpenRead, Protocol::FileRead] {
            assert!(run_worker(&file_run(protocol, &empty)).is_err());
        }
    }
}
