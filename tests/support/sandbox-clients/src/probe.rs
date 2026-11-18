// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runs [`scripts::TCP_PROBE`] in a sandbox and turns its JSON line into
//! typed results.

use std::time::Duration;

use serde::Deserialize;
use testkit::{Result, ResultExt as _, Sandbox};

use crate::message::{Http, Request};
use crate::scripts;

/// How long a connect may take, as the clients the probes replace allowed.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long reading a reply may take in all.
const READ_TIMEOUT: Duration = Duration::from_secs(15);
/// How long [`http_raw`] waits for more bytes before it stops reading. Raw
/// bytes may leave the server waiting for more, so the connection may never
/// close.
const RAW_IDLE_TIMEOUT: Duration = Duration::from_secs(2);

const EPERM: i32 = 1;
const EACCES: i32 = 13;

/// How a connect ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectOutcome {
    Connected,
    /// The connect failed with `errno`, or none for an error without one.
    /// `error` is Python's description of it.
    Failed {
        errno: Option<i32>,
        error: String,
    },
    TimedOut,
}

impl ConnectOutcome {
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected)
    }

    /// The errno a failed connect reported.
    pub fn errno(&self) -> Option<i32> {
        match self {
            Self::Failed { errno, .. } => *errno,
            Self::Connected | Self::TimedOut => None,
        }
    }

    /// Whether the connect failed with `EACCES` or `EPERM`, as the sandbox
    /// denies a connection.
    pub fn is_permission_denied(&self) -> bool {
        matches!(self.errno(), Some(EACCES | EPERM))
    }
}

/// The result of [`connect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connect {
    pub outcome: ConnectOutcome,
    /// How long the connect took, until it connected, failed, or timed out.
    pub elapsed: Duration,
}

/// How reading a reply ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadEnd {
    /// The peer closed the connection.
    Closed,
    /// The peer reset the connection (`ECONNRESET`).
    Reset,
    /// No bytes arrived for the idle timeout of [`http_raw`].
    Idle,
    /// The read timeout ran out before the connection ended.
    TimedOut,
    /// Sending or reading failed some other way.
    Failed { errno: Option<i32>, error: String },
}

/// Open a TCP connection from `sandbox` to `host:port`, then close it.
/// A connect that fails or times out is a result, not an error.
pub async fn connect(sandbox: &Sandbox, host: &str, port: u16) -> Result<Connect> {
    let probe = run(sandbox, host, port, None, Duration::ZERO).await?;
    Ok(Connect {
        outcome: probe.connect,
        elapsed: probe.connect_elapsed,
    })
}

/// Send `request` from `sandbox` to `host:port` and read the reply until the
/// server closes the connection. The request asks it to, with
/// `Connection: close`, unless it sets its own `Connection` header.
pub async fn http(sandbox: &Sandbox, host: &str, port: u16, request: &Request) -> Result<Http> {
    let bytes = request.encode(host, port);
    let probe = run(sandbox, host, port, Some(&bytes), Duration::ZERO).await?;
    Ok(Http::from_probe(probe, request.is_head()))
}

/// Send `bytes` as they are from `sandbox` to `host:port`, and read the reply
/// until the connection ends or goes quiet for two seconds. Use it for
/// requests [`Request`] can't make, or bytes that aren't HTTP at all.
pub async fn http_raw(sandbox: &Sandbox, host: &str, port: u16, bytes: &[u8]) -> Result<Http> {
    let probe = run(sandbox, host, port, Some(bytes), RAW_IDLE_TIMEOUT).await?;
    Ok(Http::from_probe(probe, false))
}

/// What the probe script reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Probe {
    pub(crate) connect: ConnectOutcome,
    pub(crate) connect_elapsed: Duration,
    pub(crate) read_end: Option<ReadEnd>,
    pub(crate) received: Vec<u8>,
}

async fn run(
    sandbox: &Sandbox,
    host: &str,
    port: u16,
    payload: Option<&[u8]>,
    idle_timeout: Duration,
) -> Result<Probe> {
    let payload = payload.map_or_else(|| "-".to_string(), to_hex);
    let args = [
        host.to_string(),
        port.to_string(),
        payload,
        CONNECT_TIMEOUT.as_secs_f64().to_string(),
        READ_TIMEOUT.as_secs_f64().to_string(),
        idle_timeout.as_secs_f64().to_string(),
    ];
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = sandbox
        .run_python(scripts::TCP_PROBE, &args)
        .await
        .context(format!(
            "probe {host}:{port} from sandbox {}",
            sandbox.name()
        ))?;
    parse_probe(output.last_json()?)
}

#[derive(Deserialize)]
struct ProbeJson {
    connect: ConnectJson,
    errno: Option<i32>,
    error: Option<String>,
    connect_ms: u64,
    read_end: Option<ReadEndJson>,
    read_errno: Option<i32>,
    read_error: Option<String>,
    received_hex: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ConnectJson {
    Ok,
    Failed,
    Timeout,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ReadEndJson {
    Closed,
    Reset,
    Idle,
    Timeout,
    Failed,
}

fn parse_probe(value: serde_json::Value) -> Result<Probe> {
    let json: ProbeJson = serde_json::from_value(value.clone())
        .context(format!("read the probe's result {value}"))?;
    let connect = match json.connect {
        ConnectJson::Ok => ConnectOutcome::Connected,
        ConnectJson::Failed => ConnectOutcome::Failed {
            errno: json.errno,
            error: json.error.unwrap_or_default(),
        },
        ConnectJson::Timeout => ConnectOutcome::TimedOut,
    };
    let read_end = json.read_end.map(|end| match end {
        ReadEndJson::Closed => ReadEnd::Closed,
        ReadEndJson::Reset => ReadEnd::Reset,
        ReadEndJson::Idle => ReadEnd::Idle,
        ReadEndJson::Timeout => ReadEnd::TimedOut,
        ReadEndJson::Failed => ReadEnd::Failed {
            errno: json.read_errno,
            error: json.read_error.clone().unwrap_or_default(),
        },
    });
    Ok(Probe {
        connect,
        connect_elapsed: Duration::from_millis(json.connect_ms),
        read_end,
        received: from_hex(&json.received_hex)?,
    })
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut hex, byte| {
        let _ = write!(hex, "{byte:02x}");
        hex
    })
}

fn from_hex(hex: &str) -> Result<Vec<u8>> {
    testkit::ensure!(
        hex.len().is_multiple_of(2),
        "the probe's received_hex has odd length"
    );
    (0..hex.len())
        .step_by(2)
        .map(|at| {
            hex.get(at..at + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| {
                    testkit::Error::msg(format!("the probe's received_hex {hex:?} isn't hex"))
                })
        })
        .collect()
}
