// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Support for the provider rotation tests: two TLS servers that check the
//! credential a sandbox sends, and the probes that drive a long-running
//! client in the sandbox.
//!
//! The servers run on the test host with a certificate signed by the
//! environment's additional CA ([`TestCa::from_env`]), so supervisors trust
//! them only through `additional_ca_bundle`. Sandboxes reach them by
//! [`TEST_HOST`], and by the host's primary IPv4 address for the wrong-host
//! checks. That address differs from the one [`TEST_HOST`] leads to: Docker's
//! bridge gateway, or the supervisor's loopback with Podman.
//!
//! Only the servers and the provider CLI see the keys. A client reports
//! status fields only, and the helpers here fail without echoing any output
//! that contains a key, an issued reference, or a bearer header.

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use host_server_support::{HttpRecorder, Request, Response, TEST_HOST, TestCa};
use serde_json::{Value, json};
use testkit::sdk::raw::proto::SandboxPolicy;
use testkit::{Context, Error, PYTHON_BINARIES, Poll, Result, Sandbox, policy, poll_until};

/// The provider credential's environment variable.
pub const TOKEN_ENV: &str = "PROVIDER_ROTATION_TOKEN";
/// The header the external caller assertion travels in.
pub const ASSERTION_HEADER: &str = "x-openshell-sandbox-assertion";
/// How long `--wait` waits for a provider change to be acknowledged.
pub const READINESS_TIMEOUT_SECONDS: &str = "90";
/// How long a client has to answer a probe once it is running.
const PROBE_TIMEOUT: Duration = Duration::from_secs(20);

/// Two random keys: the provider's first credential and its replacement.
pub fn keys() -> [String; 2] {
    [
        format!("test-{:032x}", rand::random::<u128>()),
        format!("test-{:032x}", rand::random::<u128>()),
    ]
}

/// Fail, without echoing `text`, if it contains a key, an issued reference,
/// or a bearer header.
pub fn ensure_no_credentials(text: &str, keys: &[String; 2], what: &str) -> Result {
    if keys.iter().any(|key| text.contains(key.as_str()))
        || text.contains("openshell:resolve:")
        || text.contains("Bearer ")
    {
        return Err(Error::msg(format!(
            "{what} contained credential material; output withheld"
        )));
    }
    Ok(())
}

/// Run the CLI with `env` and `args` and parse its JSON output. Fails if the
/// command fails or its output contains credential material, and reports the
/// output only when it contains none.
pub async fn cli_json(
    cx: &Context,
    env: &[(&str, &str)],
    args: &[&str],
    keys: &[String; 2],
) -> Result<Value> {
    let output = cx.cli_with_env(env, args).await?;
    let what = format!("`{}`", output.command);
    if output.exit_code != 0 {
        let report = format!("{}\n{}", output.stdout, output.stderr);
        ensure_no_credentials(&report, keys, &what)?;
        return Err(Error::msg(format!(
            "{what} exited {}: {report}",
            output.exit_code
        )));
    }
    ensure_no_credentials(&output.stdout, keys, &what)?;
    serde_json::from_str(&output.stdout)
        .map_err(|_| Error::msg(format!("{what} printed invalid JSON")))
}

/// How the servers read the credential from a request.
#[derive(Clone, Copy, Debug)]
pub enum Credential {
    /// `Authorization: Bearer <key>`, for any POST.
    Bearer,
    /// [`ASSERTION_HEADER`] with the key, for a JSON-RPC `tools/call` of
    /// `local_hello` that [`tool_call`] describes.
    Assertion,
}

/// The JSON-RPC request an assertion client sends.
pub fn tool_call() -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "local_hello", "arguments": {"name": "rotation-proof"}}})
}

/// What the servers have seen, across both. They hold no header or key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// The key the servers accept: 0 until [`Backends::rotate`], then 1.
    pub phase: usize,
    pub total: u64,
    /// Accepted requests by the phase they arrived in.
    pub accepted: [u64; 2],
    pub rejected: u64,
    /// Requests carrying the first or the replacement key.
    pub received: [u64; 2],
    /// Requests carrying no credential.
    pub missing: u64,
    /// Requests carrying something other than a key.
    pub unknown: u64,
    /// Requests whose body wasn't the expected tool call.
    pub invalid_tool_calls: u64,
}

/// Two TLS servers on the test host that accept the current key and count
/// what they see. [`Backends::port`] is the provider's endpoint, and
/// [`Backends::other_port`] and [`Backends::other_host`] are the wrong-port
/// and wrong-host checks.
pub struct Backends {
    servers: [HttpRecorder; 2],
    counts: Arc<Mutex<Counts>>,
    other_host: String,
}

impl Backends {
    pub async fn start(credential: Credential, keys: &[String; 2]) -> Result<Self> {
        let other_host = primary_ipv4()?;
        let identity = TestCa::from_env()?.leaf(&[TEST_HOST, &other_host])?;
        let counts = Arc::new(Mutex::new(Counts::default()));
        let keys = Arc::new(keys.clone());
        let server = async || {
            let counts = Arc::clone(&counts);
            let keys = Arc::clone(&keys);
            HttpRecorder::serve_tls(&identity, move |request| {
                respond(credential, &keys, &counts, request)
            })
            .await
        };
        let servers = [server().await?, server().await?];
        Ok(Self {
            servers,
            counts,
            other_host,
        })
    }

    pub fn port(&self) -> u16 {
        self.servers[0].port
    }

    pub fn other_port(&self) -> u16 {
        self.servers[1].port
    }

    /// The test host's primary IPv4 address.
    pub fn other_host(&self) -> &str {
        &self.other_host
    }

    /// Accept only the replacement key from now on.
    pub fn rotate(&self) {
        self.counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .phase = 1;
    }

    pub fn counts(&self) -> Counts {
        self.counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Fail unless the requests so far reached the servers on an address
    /// other than [`Backends::other_host`], so the wrong-host checks really
    /// name a different host. Call it before any wrong-host request.
    pub fn ensure_distinct_hosts(&self) -> Result {
        let arrivals: Vec<IpAddr> = self
            .servers
            .iter()
            .flat_map(HttpRecorder::requests)
            .filter_map(|request| request.local_addr.map(|address| address.ip()))
            .collect();
        testkit::ensure!(
            !arrivals.is_empty(),
            "no request to {TEST_HOST} reached the servers"
        );
        testkit::ensure!(
            arrivals
                .iter()
                .all(|address| address.to_string() != self.other_host),
            "requests to {TEST_HOST} arrived on {arrivals:?}, which includes the wrong-host \
             address {}",
            self.other_host
        );
        Ok(())
    }

    /// A policy that lets Python reach the provider's endpoint and the
    /// wrong-host and wrong-port addresses, so only the credential binding
    /// keeps a credential from them. Other binaries, such as curl, can't
    /// connect.
    pub fn policy(&self) -> Result<SandboxPolicy> {
        let endpoints: String = [
            (TEST_HOST, self.port()),
            (TEST_HOST, self.other_port()),
            (self.other_host.as_str(), self.port()),
        ]
        .iter()
        .map(|(host, port)| {
            format!(
                "      - {{host: \"{host}\", port: {port}, path: \"/**\", protocol: rest, access: full, enforcement: enforce}}\n"
            )
        })
        .collect();
        policy::base_with(&format!(
            "network_policies:
  rotation_backends:
    name: rotation_backends
    endpoints:
{endpoints}    binaries: {binaries}
",
            binaries = policy::binaries_yaml(PYTHON_BINARIES),
        ))
    }
}

fn respond(
    credential: Credential,
    keys: &[String; 2],
    counts: &Mutex<Counts>,
    request: &Request,
) -> Response {
    let body: Value = serde_json::from_str(&request.body).unwrap_or(Value::Null);
    let (presented, is_tool_call) = match credential {
        Credential::Bearer => (
            request
                .header("authorization")
                .and_then(|value| value.strip_prefix("Bearer ").map(str::to_string)),
            true,
        ),
        Credential::Assertion => (
            request.header(ASSERTION_HEADER),
            body["jsonrpc"] == "2.0"
                && body["method"] == "tools/call"
                && body["params"] == tool_call()["params"],
        ),
    };
    let generation = presented
        .as_deref()
        .map(|value| keys.iter().position(|key| key == value));
    let mut counts = counts.lock().unwrap_or_else(PoisonError::into_inner);
    let phase = counts.phase;
    let generation = match generation {
        None => {
            counts.missing += 1;
            "missing"
        }
        Some(None) => {
            counts.unknown += 1;
            "unknown"
        }
        Some(Some(index)) => {
            counts.received[index] += 1;
            if index == 0 { "A" } else { "B" }
        }
    };
    if !is_tool_call {
        counts.invalid_tool_calls += 1;
    }
    let valid = is_tool_call && presented.as_deref() == Some(keys[phase].as_str());
    counts.total += 1;
    if valid {
        counts.accepted[phase] += 1;
    } else {
        counts.rejected += 1;
    }
    drop(counts);
    let reply = match credential {
        Credential::Bearer => json!({"authorized": valid, "phase": phase}),
        Credential::Assertion => {
            let mut reply = json!({"jsonrpc": "2.0", "id": body["id"],
                "fixture": {"authorized": valid, "phase": phase,
                    "credential_generation": generation, "tool_call": is_tool_call}});
            if valid {
                reply["result"] =
                    json!({"content": [{"type": "text", "text": "Hello rotation-proof"}]});
            } else {
                reply["error"] = json!({"code": -32001, "message": "Unauthorized"});
            }
            reply
        }
    };
    Response::json(&reply).status(if valid { 200 } else { 401 })
}

/// The address this host sends from on its default route.
fn primary_ipv4() -> Result<String> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    // Connecting a UDP socket sends nothing; it only picks the route.
    socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9))?;
    let address = socket.local_addr()?.ip();
    testkit::ensure!(
        matches!(address, IpAddr::V4(v4) if v4.is_private()),
        "the test host's primary address {address} isn't a private IPv4 address"
    );
    Ok(address.to_string())
}

/// Ask the client called `client` in `sandbox` to run `phase` and return its
/// result. A client watches `/sandbox/rotation-probe-<client>` and writes its
/// result to `/sandbox/rotation-result-<client>`. Allow `timeout` for a
/// client that may still be starting, [`PROBE_TIMEOUT`] otherwise.
pub async fn probe(
    sandbox: &Sandbox,
    client: &str,
    phase: &str,
    timeout: Option<Duration>,
) -> Result<Value> {
    let control = format!("/sandbox/rotation-probe-{client}");
    let result = format!("/sandbox/rotation-result-{client}");
    // The client takes the control file as soon as it appears, so write it
    // whole and rename it into place.
    sandbox
        .exec([
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "rm -f {result} && printf '%s' '{phase}' > {control}.tmp && mv {control}.tmp {control}"
            ),
        ])
        .await?
        .success()?;
    let response = poll_until(
        &format!("client {client} to answer {phase}"),
        timeout.unwrap_or(PROBE_TIMEOUT),
        Duration::from_millis(100),
        async || {
            let output = sandbox.exec(["cat", result.as_str()]).await?;
            if output.exit_code != 0 || output.stdout.trim().is_empty() {
                return Ok(Poll::Pending("no result yet".to_string()));
            }
            serde_json::from_str::<Value>(output.stdout.trim())
                .map(Poll::Ready)
                .map_err(|_| Error::msg(format!("client {client} wrote an invalid result")))
        },
    )
    .await?;
    testkit::ensure!(
        response["phase"] == phase && response["same_reference"] == true,
        "client {client} answered {phase} with phase {} and same_reference {}",
        response["phase"],
        response["same_reference"]
    );
    Ok(response)
}

/// Fail unless `response` came from the process `pid` and its request
/// succeeded exactly when `success` says. With `backend_phase`, the server
/// must also have accepted it in that phase.
pub fn check(response: &Value, pid: u64, success: bool, backend_phase: Option<u64>) -> Result {
    // Report typed status fields only, never error text, which can carry
    // headers.
    testkit::ensure!(
        response["pid"].as_u64() == Some(pid) && response["ok"].as_bool() == Some(success),
        "probe {} failed: pid_matches={}, expected_ok={success}, actual_ok={:?}, status={:?}, \
         error_kind={:?}, reason_kind={:?}",
        response["phase"],
        response["pid"].as_u64() == Some(pid),
        response["ok"].as_bool(),
        response["status"].as_u64(),
        response["error_kind"].as_str(),
        response["reason_kind"].as_str(),
    );
    if let Some(phase) = backend_phase {
        testkit::ensure!(
            response["backend_phase"].as_u64() == Some(phase) && response["status"] == 200,
            "probe {} was not accepted with key {phase}: backend_phase={}, status={}",
            response["phase"],
            response["backend_phase"],
            response["status"]
        );
    }
    Ok(())
}

/// Send the credential from curl, which the policy doesn't allow, with
/// `header` (such as `Authorization: Bearer `) before it and `data` as the
/// body. Fails unless the request is denied.
///
/// curl runs as a sibling of the clients, so no allowed ancestor authorizes
/// it, and it reads the header from a pipe, so the credential isn't in its
/// arguments.
pub async fn probe_disallowed_binary(
    sandbox: &Sandbox,
    header: &str,
    url: &str,
    data: &str,
) -> Result {
    let script = format!(
        r#"token=$(printenv {TOKEN_ENV}) || exit 64
command -v curl >/dev/null 2>&1 || exit 65
if printf '%s%s\n' "$1" "$token" | \
    curl --silent --fail --max-time 5 --output /dev/null --header @- --data "$2" "$3" 2>/dev/null
then
    printf unexpected-success
else
    printf denied
fi"#
    );
    let output = sandbox
        .exec(["sh", "-c", &script, "binary-probe", header, data, url])
        .await?;
    testkit::ensure!(
        output.exit_code == 0 && output.stdout.trim() == "denied",
        "curl's request to {url} wasn't denied: exit {}, stdout {:?}",
        output.exit_code,
        output.stdout.trim()
    );
    Ok(())
}
