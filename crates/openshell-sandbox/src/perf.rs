// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in microbenchmarks for the production seccomp network listener.

use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::Instant;

use anyhow::{Context as _, bail};
use clap::ValueEnum;
use openshell_isolation_interface::linux::workload_launcher;
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

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    TcpConnect,
    TcpStream,
}

impl Protocol {
    pub fn selection(value: &str) -> anyhow::Result<Vec<Self>> {
        match value {
            "all" => Ok(vec![Self::TcpConnect, Self::TcpStream]),
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
    target: SocketAddr,
}

impl Fixture {
    fn start(protocol: Protocol, _broker: Option<&NetworkBroker>) -> io::Result<Self> {
        match protocol {
            Protocol::TcpConnect => start_tcp_fixture(false),
            Protocol::TcpStream => start_tcp_fixture(true),
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

#[allow(clippy::cast_precision_loss)]
pub fn run_worker(
    protocol: Protocol,
    target: SocketAddr,
    iterations: u64,
    warmup: u64,
    concurrency: usize,
    payload_bytes: usize,
) -> anyhow::Result<BenchmarkReport> {
    let barrier = Arc::new(Barrier::new(concurrency + 1));
    let (sender, receiver) = mpsc::channel();
    let mut threads = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let barrier = Arc::clone(&barrier);
        let sender = sender.clone();
        threads.push(thread::spawn(move || {
            let result = worker_loop(
                protocol,
                target,
                iterations,
                warmup,
                payload_bytes,
                &barrier,
            );
            let _ = sender.send(result);
        }));
    }
    drop(sender);
    barrier.wait();
    let started = Instant::now();
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
        throughput_mbit_per_second: operations as f64 * payload_bytes as f64 * 8.0
            / seconds
            / 1_000_000.0,
        latency_ns_p50: percentile(&samples, 50),
        latency_ns_p95: percentile(&samples, 95),
        latency_ns_p99: percentile(&samples, 99),
    })
}

impl Protocol {
    const fn capability_scope(self) -> &'static str {
        match self {
            Self::TcpConnect => "implemented local TCP socket/connect interception",
            Self::TcpStream => "implemented established TCP fast path",
        }
    }
}

fn worker_loop(
    protocol: Protocol,
    target: SocketAddr,
    iterations: u64,
    warmup: u64,
    payload_bytes: usize,
    barrier: &Barrier,
) -> anyhow::Result<Vec<u64>> {
    let payload = vec![0x5a; payload_bytes];
    let mut tcp = if matches!(protocol, Protocol::TcpStream) {
        let stream = TcpStream::connect(target)?;
        let _ = stream.set_nodelay(true);
        Some(stream)
    } else {
        None
    };
    let mut response = vec![0_u8; payload_bytes];
    for _ in 0..warmup {
        one_operation(protocol, target, &payload, &mut response, tcp.as_mut())?;
    }
    barrier.wait();
    let mut samples = Vec::with_capacity(usize::try_from(iterations).unwrap_or(0));
    for _ in 0..iterations {
        let started = Instant::now();
        one_operation(protocol, target, &payload, &mut response, tcp.as_mut())?;
        samples.push(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
    }
    Ok(samples)
}

fn one_operation(
    protocol: Protocol,
    target: SocketAddr,
    payload: &[u8],
    response: &mut [u8],
    tcp: Option<&mut TcpStream>,
) -> io::Result<()> {
    match protocol {
        Protocol::TcpConnect => {
            let stream = TcpStream::connect(target)?;
            let _ = stream.set_nodelay(true);
        }
        Protocol::TcpStream => {
            let stream = tcp.expect("TCP stream initialized");
            stream.write_all(payload)?;
            stream.read_exact(response)?;
        }
    }
    Ok(())
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
}
